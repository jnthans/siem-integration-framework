# Phase 2: Building

Build in this order: utils first (foundation), then domain modules (vendor logic), then entry point (orchestration), then shell wrapper, then decoder/rules. Each layer builds on the one below it.

---

## Step 1: Build utils (`{vendor}_utils.py`)

Start here because every other file depends on it. Implement these functions in order:

### `log(level, message, *args)`
Write diagnostic output to stderr at configurable verbosity. Never stdout.
```python
def log(level, msg, *args):
    if level <= DEBUG_LEVEL:
        text = msg.format(*args) if args else msg
        sys.stderr.write(f"[vendorname] {text}\n")
        sys.stderr.flush()
```

### `load_secrets_file(path)`
Parse the `KEY=VALUE` secrets file. Handle comments, blank lines, optional quotes.

### `get_secret(key, env_var, secrets, credentials_dir)`
Implement the three-tier credential chain. Log which source was used (at debug level 2), never log the value.

### `emit(event)`
Write one JSON line to stdout. Use `separators=(",", ":")` for compact output. Always `flush()`.

### `load_state(path)` and `save_state(path, state)`
Load from JSON file (return empty dict if missing). Save via tempfile + `os.replace()`.

### HTTP function
Choose based on vendor auth:
- Bearer token → `http_post(url, headers, body)` or `http_get(url, headers)`
- Basic auth → similar, with base64 encoding
- HMAC → `api_post(url, key_id, key, body)` with hash computation

Include timeout handling, HTTP error code inspection, and 429 retry logic with `Retry-After` header support.

### Test utils independently
Before moving on, test each function:
```bash
# Test credential loading
python3 -c "from vendorname_utils import get_secret; print(get_secret(...))"

# Test HTTP (if you have credentials)
python3 -c "from vendorname_utils import http_get; print(http_get(test_url, headers))"
```

---

## Step 2: Build domain modules

Implement one module at a time. Each module follows this internal structure:

### Function signature
```python
def fetch_events(credentials, cursor, config):
    """Fetch events from vendor API. Returns updated cursor."""
```

### Request construction
Build the API request from the cursor/timestamp and config. This is where vendor-specific logic lives — URL construction, query parameters, POST body formatting.

### Pagination loop
```python
while has_more:
    response = http_function(url, headers, body)
    events = extract_events(response)
    
    for event in events:
        enriched = transform(event)
        emit(enriched)
    
    cursor = extract_cursor(response)
    has_more = check_more(response)

return cursor
```

### Event transformation
Map vendor fields into the namespaced output format:
```python
def transform(raw_event):
    return {
        "integration": "vendorname",
        "vn": {
            "event_type": determine_type(raw_event),
            # Map vendor fields explicitly — preserve nesting
            "actor": raw_event.get("actor"),
            "target": raw_event.get("target"),
            "action": raw_event.get("action"),
            "timestamp": raw_event.get("timestamp"),
            # ... map remaining vendor-specific fields
        }
    }
```

**Key decisions during transformation**:
- Preserve all vendor fields — do not drop data
- Preserve nested objects — do not flatten
- Add `event_type` if the API does not include one
- Add any computed fields (e.g., MITRE tactic mappings)

### Error handling
Wrap the entire fetch in a try/except. On failure, emit an error event and return the unchanged cursor (so the next run retries from the same position).

---

## Step 3: Build the entry point (`{vendor}.py`)

The orchestrator follows a rigid template:

```python
def main():
    args = parse_args()                    # argparse with --source, --all, --debug, --lookback
    config = load_config(args)             # Merge env vars + CLI overrides
    secrets = load_secrets_file(config)    # Load .secrets
    credentials = build_credentials(secrets, config)  # Apply credential chain
    state = load_state(config.state_file)  # Load persisted cursors
    
    # Call each module
    if should_run("module_a", config):
        try:
            state["module_a_cursor"] = fetch_module_a(credentials, state.get("module_a_cursor"), config)
        except Exception as e:
            emit_error("module_a", str(e))
    
    if should_run("module_b", config):
        try:
            state["module_b_cursor"] = fetch_module_b(credentials, state.get("module_b_cursor"), config)
        except Exception as e:
            emit_error("module_b", str(e))
    
    # Save state (skip in --all mode)
    if not config.all_mode:
        save_state(config.state_file, state)
```

### CLI arguments
Every integration supports these standard flags:
- `--source` — which modules to run (e.g., `siem`, `people`, `all`)
- `--all` / `-a` — test/backfill mode: ignore and do not update state
- `--lookback` / `-l` — hours to look back (for first run or `--all` mode)
- `--debug` / `-d` — verbosity level (0-3)

### Config loading
Merge environment variables with CLI overrides. CLI takes precedence:
```python
config.debug = args.debug if args.debug is not None else int(os.environ.get("VN_DEBUG", "0"))
```

---

## Step 4: Build the shell wrapper (`run.sh`)

```bash
#!/usr/bin/env bash
set -euo pipefail

# ── Runtime configuration ──
export VN_BASE_URL="https://api.vendor.com"
export VN_STATE_FILE="/var/ossec/wodles/vendorname/state.json"
export VN_SECRETS_FILE="/var/ossec/wodles/vendorname/.secrets"
export VN_DEBUG="0"

# ── Execute ──
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$SCRIPT_DIR/vendorname.py" "$@"
```

Key points:
- `set -euo pipefail` — fail fast on errors
- `exec` — replaces the shell process with Python (no lingering parent)
- `"$@"` — forwards CLI arguments from ossec.conf
- All config is environment variables — no hardcoded paths in Python

---

## Step 5: Build decoder and rules

### Decoder (`{vendor}_decoder.xml`)

The decoder's `<program_name>` must match the `<tag>` value from the ossec.conf wodle stanza — Wazuh uses the tag, not the script filename, as the program name.

```xml
<decoder name="vendorname">
  <program_name>vendorname</program_name>
</decoder>

<decoder name="vendorname_json">
  <parent>vendorname</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

### Rules (`{vendor}_rules.xml`)
Build rules in this order:
1. **Base rule** — matches on integration field, sets group
2. **Event type rules** — one per event type, sets severity and description
3. **Conditional rules** — elevated severity for specific conditions (failed auth, high-risk actions)
4. **Error rule** — matches error events at high severity

```xml
<!-- Base rule -->
<rule id="100800" level="0">
  <decoded_as>vendorname</decoded_as>
  <field name="integration">vendorname</field>
  <description>Vendor integration event.</description>
  <group>vendorname,</group>
</rule>

<!-- Event type rule -->
<rule id="100801" level="3">
  <if_sid>100800</if_sid>
  <field name="vn.event_type">signin</field>
  <description>Vendor: sign-in by $(vn.user.email).</description>
  <group>vendorname,authentication,</group>
</rule>

<!-- Error rule -->
<rule id="100890" level="8">
  <if_sid>100800</if_sid>
  <field name="vn.event_type">error</field>
  <description>Vendor integration error: $(vn.error_message).</description>
  <group>vendorname,integration_error,</group>
</rule>
```

---

## Building checklist

- [ ] Utils: `log()`, `emit()`, `load_secrets_file()`, `get_secret()`
- [ ] Utils: `load_state()`, `save_state()` with atomic writes
- [ ] Utils: HTTP function with timeout, error handling, 429 retry
- [ ] Domain module 1: fetch, paginate, transform, emit
- [ ] Domain module 2 (if needed): same pattern
- [ ] Entry point: args, config, credential chain, module calls, state save
- [ ] Shell wrapper: env vars, exec Python
- [ ] Decoder XML: program name match, JSON decoder
- [ ] Rules XML: base rule, event type rules, error rule
- [ ] All functions tested independently before integration
