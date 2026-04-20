# SIEM Integration Framework — Architecture Reference

This document is designed for LLM context. It specifies the complete architecture that every integration must follow.

---

## Four-layer architecture

### Layer 1: Shell wrapper (`run.sh`)
- Sets environment variables (API URLs, feature flags, debug level)
- Resolves the Python interpreter: `command -v python3` first, falls back to Wazuh's bundled `/var/ossec/framework/python/bin/python3`; emits a JSON `PYTHON_VERSION_ERROR` and exits 1 if neither is found
- Resolves script directory with `SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"`
- Execs Python entry point: `exec "${PYTHON}" "$SCRIPT_DIR/{vendor}.py" "$@"`
- Uses `#!/usr/bin/env bash` and `set -euo pipefail`
- Never contains credentials (those go in `.secrets`)
- The `exec` replaces the shell process — no parent lingers

### Layer 2: Orchestrator (`{vendor}.py`)
- Parses CLI arguments with `argparse`
- Loads config by merging env vars with CLI overrides (CLI takes precedence)
- Loads secrets file via `load_secrets_file()`
- Builds credential dict via `get_secret()` calls
- Loads state via `load_state()`
- Calls each domain module in sequence, wrapped in try/except
- On module failure: calls `emit_error()`, does NOT re-raise
- Saves state via `save_state()` (skipped in `--all` mode)
- Main function structure:

```python
def main():
    args = parse_args()
    config = load_config(args)
    secrets = load_secrets_file(config["secrets_file"])
    credentials = {"key": get_secret("key_name", "ENV_VAR", secrets)}
    state = load_state(config["state_file"])

    if should_run("module_a", config):
        try:
            state["module_a_cursor"] = fetch_module_a(credentials, state.get("module_a_cursor"), config)
        except Exception as e:
            emit_error("module_a", str(e))

    if not config["all_mode"]:
        save_state(config["state_file"], state)
```

### Layer 3: Domain modules (`{vendor}_{surface}.py`)
- One module per logical API surface
- Each module exports one main function: `fetch_{surface}(credentials, cursor, config) -> updated_cursor`
- Internal structure:
  1. Determine start position (cursor from state or lookback timestamp)
  2. Pagination loop: request → extract events → transform → emit → update cursor
  3. Return updated cursor to orchestrator
- Never imports from other domain modules
- Never imports from the orchestrator
- Only imports from utils

### Layer 4: Shared utilities (`{vendor}_utils.py`)
- Module-level constants: `INTEGRATION_NAME`, `NAMESPACE`, `DEBUG_LEVEL`
- Functions (implement in this order):
  1. `log(level, msg, *args)` — stderr, lazy formatting
  2. `emit(event)` — stdout, compact JSON, flush
  3. `emit_error(source, message, code=None)` — structured error event
  4. `load_secrets_file(path)` — parse KEY=VALUE file
  5. `get_secret(cred_name, env_var, secrets)` — three-tier credential chain
  6. `load_state(path)` — JSON file → dict (empty dict if missing)
  7. `save_state(path, state)` — atomic write via tempfile + os.replace
  8. `http_get(url, headers, timeout=30)` — GET with error handling
  9. `http_post(url, headers, body, timeout=30)` — POST with JSON body
  10. `http_with_retry(request_fn, max_wait=60)` — 429 retry wrapper
  11. Auth header helpers: `bearer_auth_headers()`, `basic_auth_headers()`, etc.

---

## Data flow

```
Vendor API → Domain module fetches via HTTP
  → Response parsed, events extracted
  → Each event transformed: wrapped in namespace, metadata added
  → emit() writes one JSON line to stdout
  → Wazuh wodle manager captures stdout
  → Decoder matches program_name → activates JSON_Decoder
  → Rules evaluate fields → assign rule ID, level, description, groups
  → Event indexed in OpenSearch under data.*
  → Dashboard visualizations query data.{namespace}.*
```

## Event emission format

```json
{
  "integration": "vendorname",
  "{namespace}": {
    "event_type": "signin",
    "field_a": "value",
    "nested_obj": {
      "subfield": "preserved"
    }
  }
}
```

- `integration` is always a top-level key
- All vendor data nests under the namespace key
- Nested objects are preserved as-is (never flattened)
- Output uses `json.dumps(event, separators=(",", ":"))` for compactness
- One object per line, explicit `sys.stdout.flush()` after each

## Error event format

```json
{
  "integration": "vendorname",
  "{namespace}": {
    "event_type": "error",
    "error_source": "module_name",
    "error_message": "descriptive message",
    "error_code": 401
  }
}
```

## State file format

```json
{
  "module_a_cursor": "opaque-value",
  "module_a_last_poll": "2026-03-22T10:00:00Z"
}
```

- Atomic writes only (tempfile + os.replace)
- Contains cursors/timestamps only — never cached credentials or event data
- Delete to reset; next run starts from lookback window

## Credential chain (per key)

```
$CREDENTIALS_DIRECTORY/{cred_name}  →  .secrets file (KEY=VALUE)  →  $ENV_VAR
         (systemd, most secure)         (file, recommended)         (env, testing only)
```

## Decoder pattern

```xml
<decoder name="{vendor}">
  <program_name>{vendor}</program_name>
</decoder>
<decoder name="{vendor}_json">
  <parent>{vendor}</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

## Rule hierarchy

```
Level 0: Base rule (decoded_as + integration field match)
  └─ Level 3-5: Event type rules (field match on event_type)
       └─ Level 6-8: Conditional rules (field match on outcome, severity, etc.)
Level 8-10: Error rules (event_type = error)
```

## Rule ID allocation (100-ID block per integration)

- xx00: Base rule (level 0)
- xx01–xx49: Event type rules
- xx50–xx79: Conditional/elevated rules
- xx90–xx99: Error and health rules
