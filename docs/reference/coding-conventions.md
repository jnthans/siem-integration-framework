# Coding Conventions

These conventions are enforced across all integrations. They exist to ensure consistency, security, and maintainability.

---

## Python style

### General
- Python 3.8+ compatibility (oldest version on supported Wazuh hosts)
- No type hints in function signatures (reduces visual noise in simple scripts where types are obvious from context)
- No classes unless the domain genuinely requires objects with state. Prefer functions and module-level constants.
- No `print()` anywhere — use `emit()` for events (stdout), `log()` for diagnostics (stderr)

### Imports
- Standard library only — no third-party packages
- Group imports: stdlib first, then local modules, separated by a blank line
- Preferred stdlib modules: `json`, `sys`, `os`, `urllib.request`, `urllib.error`, `urllib.parse`, `datetime`, `argparse`, `tempfile`, `time`, `hashlib`, `hmac`, `base64`, `ssl`

### Naming
- Functions: `snake_case` — `load_state()`, `emit()`, `fetch_events()`
- Constants: `UPPER_SNAKE_CASE` — `DEBUG_LEVEL`, `DEFAULT_LOOKBACK`
- Variables: `snake_case` — `state_file`, `bearer_token`, `page_count`
- Module files: `{vendor}_{purpose}.py` — `proofpoint_siem.py`
- No abbreviations except the namespace prefix — prefer `credentials` over `creds`, `configuration` over `cfg`

### Functions
- Keep functions short — 20-40 lines typical, 60 maximum
- One return type per function (do not return `dict` sometimes and `None` other times without clear documentation)
- Use early returns for guard clauses:
```python
def fetch_events(cursor, config):
    if not config.enabled:
        return cursor  # nothing to do
    
    # main logic here
```

### Error handling
- Catch specific exceptions, not bare `except:`
- Every caught exception either emits an error event or re-raises
- Never silently swallow errors:

**Good** — catch specific exceptions and emit a structured error:
```python
except urllib.error.HTTPError as e:
    emit_error("module_name", f"HTTP {e.code}: {e.reason}")
    return cursor  # return unchanged cursor so next run retries
```

**Bad** — silently ignores all errors:
```python
except Exception:
    pass
```

### String formatting
- Use f-strings for simple interpolation: `f"Fetched {count} events"`
- Use `.format()` in the `log()` function to avoid evaluating arguments when debug is off
- Never use `%` formatting or string concatenation for URLs

---

## HTTP patterns

### Request construction
```python
def http_get(url, headers, timeout=30):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {body[:200]}")
```

### POST with JSON body
```python
def http_post(url, headers, body, timeout=30):
    data = json.dumps(body).encode("utf-8")
    headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {body_text[:200]}")
```

### Rate limit retry
```python
def http_with_retry(request_fn, *args, max_wait=60):
    try:
        return request_fn(*args)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            retry_after = int(e.headers.get("Retry-After", "30"))
            wait = min(retry_after, max_wait)
            log(1, "Rate limited. Waiting {} seconds", wait)
            time.sleep(wait)
            return request_fn(*args)  # one retry
        raise
```

---

## State management patterns

### Load
```python
def load_state(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
```

### Save (atomic)
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

---

## Emission patterns

### Standard event
```python
def emit(event):
    sys.stdout.write(json.dumps(event, separators=(",", ":")) + "\n")
    sys.stdout.flush()
```

### Error event
```python
def emit_error(source, message, code=None):
    event = {
        "integration": INTEGRATION_NAME,
        NAMESPACE: {
            "event_type": "error",
            "error_source": source,
            "error_message": message
        }
    }
    if code is not None:
        event[NAMESPACE]["error_code"] = code
    emit(event)
```

---

## Logging patterns

```python
DEBUG_LEVEL = 0  # set from env/CLI

def log(level, msg, *args):
    if level <= DEBUG_LEVEL:
        text = msg.format(*args) if args else msg
        sys.stderr.write(f"[{INTEGRATION_NAME}] {text}\n")
        sys.stderr.flush()
```

Usage:
```python
log(1, "Fetched {} events from {}", count, endpoint)    # info
log(2, "Request headers: {}", sanitize_headers(headers)) # verbose
log(3, "Raw response: {}", response_text[:500])           # trace
```

**Never log credentials at any level.** If logging headers, sanitize the Authorization value:
```python
def sanitize_headers(headers):
    safe = dict(headers)
    if "Authorization" in safe:
        safe["Authorization"] = "***"
    return safe
```

---

## Shell script conventions

### run.sh
```bash
#!/usr/bin/env bash
set -euo pipefail

# Configuration — environment variables only
export VN_SETTING="value"

# Resolve Python interpreter — system python3 first, Wazuh's bundled python3 as fallback
if command -v python3 &>/dev/null; then
    PYTHON="$(command -v python3)"
elif [[ -x /var/ossec/framework/python/bin/python3 ]]; then
    PYTHON="/var/ossec/framework/python/bin/python3"
else
    echo '{"integration":"vendorname","type":"error","vendorname":{"source":"orchestrator","error_code":"PYTHON_VERSION_ERROR","error_message":"python3 not found in PATH or /var/ossec/framework/python/bin"}}' >&1
    exit 1
fi

# Execute — replace shell with Python
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${PYTHON}" "$SCRIPT_DIR/vendorname.py" "$@"
```

- Always use `#!/usr/bin/env bash` (not `#!/bin/bash`)
- Always `set -euo pipefail`
- Always resolve the Python interpreter explicitly — do not rely on the `.py` shebang, which fails silently on hosts without `python3` in PATH. Fall back to Wazuh's bundled interpreter at `/var/ossec/framework/python/bin/python3`.
- On resolution failure, emit a structured JSON error to stdout so Wazuh's decoder still parses it, then exit 1.
- Always `exec` (no background processes, no lingering shell)
- Always forward `"$@"` for CLI arguments
- Use `${BASH_SOURCE[0]}` instead of `$0` to resolve paths correctly when the script is sourced or symlinked
- Never put credentials in `run.sh` — they go in `.secrets`

---

## Documentation conventions

### Configuration reference tables
```markdown
| Variable | Default | Description |
|---|---|---|
| `VN_SETTING` | `value` | One-line description ending in period. |
```

### Code examples in docs
- Always include the full command (with `sudo -u wazuh`)
- Always show expected output or what to look for
- Use comments to explain non-obvious parts

### README flow diagram
- Use ASCII art, not images (works in terminal, GitHub, and offline)
- Show the actual execution path, not an idealized architecture
- Include the credential chain
