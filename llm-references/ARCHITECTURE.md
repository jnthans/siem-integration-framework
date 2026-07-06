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
  8. `HttpError(RuntimeError)` — exception with `.status` (int or None for network failures) and `.headers` (dict); raised by both HTTP functions
  9. `http_get(url, headers, timeout=30)` — GET; raises `HttpError` on HTTP error status, `urllib.error.URLError`, or timeout (all normalized to the same message format); adds a default `{INTEGRATION_NAME}/1.0` User-Agent; caps response reads at 50 MB
  10. `http_post(url, headers, body, timeout=30)` — POST with JSON body; same error handling, User-Agent, and response cap as `http_get`
  11. `http_with_retry(request_fn, max_wait=60)` — one retry on 429 (honors `Retry-After` from `e.headers`, capped at `max_wait`, default 30s) and on 502/503/504 (5s wait); checks `e.status == 429`, never string-matches the message
  12. Auth header helpers: `bearer_auth_headers()`, `basic_auth_headers()`, etc.

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

---

## Push ingestion model (HEC receiver)

Everything above describes the **pull model** (scheduled wodle poller +
cursor state) — the default. The framework also supports a **push model**
for sources that cannot be polled and only emit events (HEC senders,
webhook forwarders). Templates live in `templates/receiver/`.

### Architecture

```
Push source → edge (Cloudflare Tunnel / Tailscale: TLS, WAF, access policy)
  → outbound-only tunnel → hec_receiver.py on 127.0.0.1:8088 (loopback ONLY)
  → spool file (framework-format JSON lines, e.g. /var/ossec/logs/hec/spool.jsonl)
  → Wazuh <localfile log_format="json"> tails the spool
  → decoder (prematch, no program_name) → rules → OpenSearch
```

### Receiver contract (`hec_receiver.py` — concrete and runnable, no placeholders)

- stdlib only; `ThreadingHTTPServer` bound to `127.0.0.1:8088` (configurable, keep loopback)
- Endpoints: `POST /services/collector` and `/services/collector/event`;
  `GET /services/collector/health` → `{"text":"HEC is healthy","code":17}` (no auth)
- Auth: `Authorization: Splunk <token>` or `Bearer <token>`; multiple tokens, each
  mapped to `source` + `namespace` (per-source revocation); tokens via the same
  three-tier credential chain, key `HEC_TOKENS` = `token:source:namespace` triplets
- HEC batches are CONCATENATED JSON objects, not an array — parse with a
  `json.JSONDecoder().raw_decode()` loop, never `json.loads()` on the whole body
- `Content-Encoding: gzip` supported with a decompression cap; body cap ~1 MB → 413
- Transform per envelope: `{"integration": "<source>", "<ns>": {<event payload>,
  "hec_host":..., "hec_source":..., "hec_sourcetype":..., "hec_time":...}}` —
  HEC metadata is preserved under `hec_*` keys; success response `{"text":"Success","code":0}`
- Spool: line-buffered append; size-based rotation (keep one `.1` generation);
  disk quota → 503 `{"text":"Server is busy","code":9}` (sender backpressure)
- Receiver health events (auth_failure, malformed_batch, spool_error,
  quota_exceeded, receiver_started) are spooled under `integration=hec_receiver`,
  namespace `hecr`; diagnostics to stderr via the same `log()` pattern

### Decoder pattern (push)

Spool lines arrive via localfile, not a wodle, so there is no program_name.
Prematch on the stable line prefix (the receiver always writes `integration` first):

```xml
<decoder name="hec_spool">
  <prematch>^{"integration":</prematch>
</decoder>
<decoder name="hec_spool_json">
  <parent>hec_spool</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

One decoder covers all spool traffic; each source gets its own rule file whose
base rule matches `<decoded_as>hec_spool</decoded_as>` + `<field name="integration">`.
Receiver health/error rules occupy the xx90–xx99 block as usual.

### Model differences that change design decisions

- No cursor/state file — there is no position to track; the spool is the durability boundary
- Dedup is the SENDER's job; the receiver accepts what arrives (retries after a
  lost 200 produce duplicates)
- Long-running systemd service (wazuh user, hardening directives, LoadCredential),
  not a scheduled wodle
- Classes are acceptable in the receiver (`BaseHTTPRequestHandler` requires one);
  wodle code style otherwise applies (stdlib only, no print, log() to stderr)
- `http.server` is acceptable only because the bind is loopback behind a hardened
  tunnel edge; for high volume, use Vector/Fluent Bit native HEC sources instead
  (zero-deps governs wodle code on the manager; the receiver is a separate
  deployment component)
