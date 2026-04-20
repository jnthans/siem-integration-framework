# SIEM Integration Framework — Coding Standards

Machine-readable coding standards for LLM-assisted integration development.

---

## Python requirements

- Python 3.8+ compatibility
- Standard library only — NEVER use third-party packages
- Allowed imports: `json`, `sys`, `os`, `urllib.request`, `urllib.error`, `urllib.parse`, `datetime`, `argparse`, `tempfile`, `time`, `hashlib`, `hmac`, `base64`, `ssl`
- Forbidden: `requests`, `httpx`, `aiohttp`, `click`, `pydantic`, `dataclasses` (3.7+, but we prefer dicts)

## Naming

| Element | Convention | Example |
|---|---|---|
| Functions | `snake_case` | `load_state()`, `fetch_events()` |
| Constants | `UPPER_SNAKE_CASE` | `DEBUG_LEVEL`, `NAMESPACE` |
| Variables | `snake_case` | `state_file`, `page_count` |
| Module files | `{vendor}_{purpose}.py` | `proofpoint_siem.py` |
| Namespace prefix | 2-4 lowercase chars | `op`, `pp`, `xdr` |
| Integration name | lowercase, no hyphens | `onepassword`, `proofpoint` |

## Function patterns

### emit() — ALWAYS use this, NEVER print()
```python
def emit(event):
    sys.stdout.write(json.dumps(event, separators=(",", ":")) + "\n")
    sys.stdout.flush()
```

### log() — ALWAYS to stderr, NEVER stdout
```python
def log(level, msg, *args):
    if level <= DEBUG_LEVEL:
        text = msg.format(*args) if args else msg
        sys.stderr.write("[{}] {}\n".format(INTEGRATION_NAME, text))
        sys.stderr.flush()
```

### save_state() — ALWAYS atomic
```python
def save_state(path, state):
    dir_name = os.path.dirname(path) or "."
    with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, suffix=".tmp") as tmp:
        json.dump(state, tmp, indent=2)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name
    os.replace(tmp_path, path)
```

### load_state() — handle missing gracefully
```python
def load_state(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
```

### get_secret() — three-tier chain
```python
def get_secret(cred_name, env_var, secrets):
    # Tier 1: systemd
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        cred_path = os.path.join(cred_dir, cred_name)
        if os.path.isfile(cred_path):
            with open(cred_path, "r") as f:
                value = f.read().strip()
            if value:
                log(2, "Credential '{}' from systemd", cred_name)
                return value
    # Tier 2: secrets file
    if env_var in secrets:
        log(2, "Credential '{}' from secrets file", cred_name)
        return secrets[env_var]
    # Tier 3: environment
    value = os.environ.get(env_var)
    if value:
        log(2, "Credential '{}' from environment", cred_name)
        return value
    raise RuntimeError("Credential '{}' not found".format(cred_name))
```

### HTTP with 429 retry
```python
def http_with_retry(request_fn, max_wait=60):
    try:
        return request_fn()
    except urllib.error.HTTPError as e:
        if e.code == 429:
            retry_after = int(e.headers.get("Retry-After", "30"))
            wait = min(retry_after, max_wait)
            log(1, "Rate limited. Waiting {}s", wait)
            time.sleep(wait)
            return request_fn()
        raise
```

## Error handling rules

1. Catch specific exceptions: `urllib.error.HTTPError`, `json.JSONDecodeError`, `RuntimeError`
2. Never bare `except:` or `except Exception: pass`
3. Every caught exception either emits an error event or re-raises
4. In the orchestrator: catch per module, emit error, continue to next module
5. In domain modules: let exceptions propagate to the orchestrator
6. Error messages must never contain credential values

## Event transformation rules

1. Add `"integration": INTEGRATION_NAME` at the top level
2. Nest all vendor data under the `NAMESPACE` key
3. Add `"event_type"` inside the namespace if the API does not provide one
4. Preserve nested objects — do not flatten with dot notation
5. Preserve all vendor fields — do not drop data
6. Truncate error messages to 500 chars to prevent huge error events

## Shell script rules

1. `#!/usr/bin/env bash`
2. `set -euo pipefail`
3. Resolve Python explicitly — prefer `command -v python3`, fall back to `/var/ossec/framework/python/bin/python3`; on failure emit a JSON `PYTHON_VERSION_ERROR` to stdout and `exit 1`
4. `SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"` — resolve absolute path (use `${BASH_SOURCE[0]}`, not `$0`)
5. `exec "${PYTHON}" "$SCRIPT_DIR/{vendor}.py" "$@"` — replace shell, forward args
6. No credentials in run.sh — only in .secrets
7. All config via `export VAR="value"`

## Decoder rules

1. First decoder matches on `<program_name>{vendor}</program_name>` (must match the `<tag>` in ossec.conf)
2. Child decoder uses `<plugin_decoder>JSON_Decoder</plugin_decoder>`
3. Decoder name matches the integration name (lowercase)

## Rule rules

1. Base rule at level 0 with `<decoded_as>` and `<field name="integration">`
2. Event type rules chain via `<if_sid>` from base rule
3. Conditional rules chain from event type rules
4. Error rules at level 8+ chain from base rule
5. Groups always have trailing comma: `<group>vendorname,authentication,</group>`
6. Descriptions use `$(field.path)` interpolation
7. Rule IDs in a reserved 100-ID block starting at 100000+

## Documentation rules

1. Every integration ships four documents: README + three guides
2. Configuration reference: table for every env var and CLI flag
3. Rules reference: row for every rule ID
4. Troubleshooting: symptom → cause → fix format
5. All commands are copy-paste ready with `sudo -u wazuh`
6. README includes ASCII flow diagram and dashboard screenshots
