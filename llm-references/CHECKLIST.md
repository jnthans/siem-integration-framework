# SIEM Integration Framework — Build Checklist

Step-by-step checklist for building a complete integration. Follow in order.

---

## Phase 1: Planning (do this before writing code)

- [ ] Read vendor API documentation completely
- [ ] Document auth method: bearer | basic | HMAC | OAuth
- [ ] List endpoints: URL, HTTP method, request format, response format
- [ ] Identify pagination model: cursor | time-window | offset
- [ ] List all event types with their field structures
- [ ] Note rate limits: requests per minute/hour/day, per endpoint
- [ ] Calculate rate limit budget: requests_per_interval × intervals_per_day ≤ daily_limit
- [ ] Reserve rule ID range: 100-ID block (e.g., 100800–100899)
- [ ] Choose namespace prefix: 2-4 chars (e.g., `op`, `pp`, `xdr`)
- [ ] Decide module split: how many domain modules, what each covers
- [ ] Map event types to severity levels and rule families

## Phase 2: Building (build in this order)

### Step 1: Utils (`{vendor}_utils.py`)
- [ ] Set module constants: `INTEGRATION_NAME`, `NAMESPACE`, `DEBUG_LEVEL`
- [ ] Implement `log(level, msg, *args)` → stderr
- [ ] Implement `emit(event)` → stdout, compact JSON, flush
- [ ] Implement `emit_error(source, message, code)` → structured error event
- [ ] Implement `load_secrets_file(path)` → parse KEY=VALUE
- [ ] Implement `get_secret(cred_name, env_var, secrets)` → three-tier chain
- [ ] Implement `load_state(path)` → JSON to dict, empty dict if missing
- [ ] Implement `save_state(path, state)` → tempfile + os.replace (ATOMIC)
- [ ] Implement HTTP function(s): `http_get()`, `http_post()`, or `api_post()`
  - [ ] Includes timeout parameter (default 30s)
  - [ ] Reads response body on error for diagnostic message
  - [ ] Truncates error body to 200 chars
- [ ] Implement `http_with_retry()` → 429 handling with Retry-After
- [ ] Implement auth header builder(s): `bearer_auth_headers()`, `basic_auth_headers()`, etc.
- [ ] Verify: no `print()` anywhere
- [ ] Verify: no external imports

### Step 2: Domain module(s) (`{vendor}_{module}.py`)
- [ ] Export `fetch_{module}(credentials, cursor, config) -> cursor`
- [ ] Determine start position from cursor or lookback
- [ ] Implement pagination loop:
  - [ ] Build request (URL, headers, body)
  - [ ] Execute via HTTP function
  - [ ] Extract events from response
  - [ ] Transform each event (namespace, event_type, preserve nesting)
  - [ ] Call `emit()` for each event
  - [ ] Extract next cursor from response
  - [ ] Check has_more / pagination end condition
- [ ] Log page count and event count at debug level 1
- [ ] Return updated cursor
- [ ] Verify: no imports from other domain modules
- [ ] Verify: no imports from orchestrator
- [ ] Verify: all vendor fields preserved in output

### Step 3: Orchestrator (`{vendor}.py`)
- [ ] `parse_args()` with `--source`, `--all`, `--lookback`, `--debug`
- [ ] `load_config()` merging env vars + CLI overrides (CLI wins)
- [ ] Set `DEBUG_LEVEL` in utils module
- [ ] Load secrets file
- [ ] Build credentials dict via `get_secret()` calls
- [ ] Load state
- [ ] For each module: `if should_run()` → try/except → call module → update state
- [ ] On exception: `emit_error()` + `log()` — do NOT re-raise
- [ ] Save state (skip if `--all` mode)
- [ ] Add `if __name__ == "__main__": main()`

### Step 4: Shell wrapper (`run.sh`)
- [ ] `#!/usr/bin/env bash`
- [ ] `set -euo pipefail`
- [ ] Export config env vars (base URL, paths, debug level)
- [ ] `SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"`
- [ ] `exec "$SCRIPT_DIR/{vendor}.py" "$@"`
- [ ] No credentials in this file
- [ ] Make executable: `chmod +x run.sh`

### Step 5: Credentials template (`.secrets.example`)
- [ ] Comment header explaining the file
- [ ] Placeholder values for each credential variable
- [ ] Notes about file permissions (chmod 640, chown root:wazuh)

### Step 6: Decoder (`{vendor}_decoder.xml`)
- [ ] Parent decoder matching `<program_name>{vendor}</program_name>` (must match the `<tag>` in ossec.conf)
- [ ] Child decoder with `<plugin_decoder>JSON_Decoder</plugin_decoder>`

### Step 7: Rules (`{vendor}_rules.xml`)
- [ ] Base rule (level 0): `<decoded_as>` + `<field name="integration">`
- [ ] Event type rules (level 3-5): one per event type, chain from base
- [ ] Conditional rules (level 6-8): elevated severity for specific conditions
- [ ] Error rule (level 8+): matches `event_type` = `error`
- [ ] All rules have `<group>` with trailing comma
- [ ] Descriptions use `$(field.path)` interpolation
- [ ] Rule IDs within reserved range

### Step 8: ossec.conf stanza
- [ ] `<wodle name="command">` block with tag, command, interval, timeout
- [ ] `<ignore_output>no</ignore_output>` — required for events to enter pipeline
- [ ] `<run_on_start>yes</run_on_start>` — immediate first execution

## Phase 3: Testing

- [ ] Standalone: `./run.sh --all --lookback 1 --debug 1` produces JSON on stdout
- [ ] Standalone: output piped through `jq` validates as proper JSON
- [ ] Standalone: error handling tested (break credentials, verify error event)
- [ ] Standalone: pagination tested (24h+ lookback produces multiple pages)
- [ ] Standalone: state file created and updated after normal run
- [ ] Standalone: state file survives `kill -9` during execution
- [ ] Integrated: events appear in Wazuh alerts log with correct rule IDs
- [ ] Integrated: `wazuh-logtest` matches decoder and rules for sample events
- [ ] Integrated: events visible in OpenSearch with queryable nested fields
- [ ] Integrated: error rule fires when credentials are invalid

## Phase 4: Deploying

- [ ] Files copied to `/var/ossec/wodles/{vendor}/`
- [ ] `.secrets` created with real credentials, `chmod 640`, `chown root:wazuh`
- [ ] Decoder copied to `/var/ossec/etc/decoders/`
- [ ] Rules copied to `/var/ossec/etc/rules/`
- [ ] ossec.conf stanza added
- [ ] Wazuh manager restarted
- [ ] Events appearing in dashboard within one polling interval

## Phase 5: Documenting

- [ ] README.md with dashboard screenshots, features, installation, structure, flow diagram
- [ ] `artifacts/guides/configuration.md` — every env var and CLI flag
- [ ] `artifacts/guides/rules-reference.md` — every rule ID with description
- [ ] `artifacts/guides/troubleshooting.md` — symptom → cause → fix table
- [ ] `.gitignore` excludes `.secrets`, `state.json`, `__pycache__/`
