# Design Principles

These principles are non-negotiable. They emerged from building and operating production integrations and represent hard-won lessons. Every template, code review, and AI prompt in this framework enforces them.

---

## 1. Zero external dependencies

**Rule**: The integration uses Python standard library only. No `pip install` on the SIEM host.

**Why**: SIEM hosts are security infrastructure. Adding third-party packages introduces supply chain risk, version conflicts, and maintenance burden. The Wazuh manager already has Python — `urllib.request`, `json`, `os`, `sys`, `tempfile`, `argparse`, and `datetime` cover every integration need.

**What this means in practice**:
- HTTP requests use `urllib.request`, not `requests`
- JSON parsing uses `json`, not any third-party parser
- Date handling uses `datetime`, not `arrow` or `pendulum`
- Argument parsing uses `argparse`, not `click`

---

## 2. Atomic state management

**Rule**: State is written via `tempfile.NamedTemporaryFile` + `os.replace()`. No direct file writes.

**Why**: A process kill, OOM, or system crash during a direct `open(file, 'w').write()` can leave the state file truncated or empty. The next run reads corrupt state and either crashes, re-fetches everything (duplicates), or skips events (gaps). Atomic writes eliminate this entire failure class.

**The pattern**:
```python
import tempfile, os, json

def save_state(path, state):
    dir_name = os.path.dirname(path)
    with tempfile.NamedTemporaryFile('w', dir=dir_name, delete=False) as tmp:
        json.dump(state, tmp)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name
    os.replace(tmp_path, path)  # atomic on POSIX
```

---

## 3. Independent failure isolation

**Rule**: One data stream failing never prevents the others from running. Every failure is caught, logged, and emitted as a structured error event.

**Why**: Vendor APIs have independent failure modes. The audit endpoint might return 500 while the sign-in endpoint works fine. If a single exception in one module aborts the entire run, healthy streams are starved until the broken one recovers.

**The pattern**:
```python
# In the orchestrator
for module_name, fetch_fn in modules:
    try:
        new_cursor = fetch_fn(credentials, state.get(cursor_key))
        state[cursor_key] = new_cursor
    except Exception as e:
        emit_error(module_name, str(e))
        # Do NOT re-raise — continue to next module
```

---

## 4. Secure credential chain

**Rule**: Credentials are loaded from a three-tier priority chain. They are never logged, never hardcoded, and never passed as CLI arguments.

**The chain** (first match wins per key):
1. **systemd encrypted credentials** (`$CREDENTIALS_DIRECTORY/{key}`) — memory-backed, encrypted at rest on TPM-equipped systems. Most secure.
2. **Secrets file** (`.secrets` with `KEY=VALUE` format) — file on disk with restricted permissions (`chmod 640, chown root:wazuh`). Recommended for most deployments.
3. **Environment variables** — least secure, visible in `/proc/<pid>/environ` and process listings. Use only for development and testing.

**Why the chain**: Different deployment environments have different security capabilities. A hardened production server can use systemd credentials. A Docker container might use a mounted secrets file. A developer testing locally uses env vars. The chain adapts without code changes.

---

## 5. Single JSON lines to stdout

**Rule**: Events go to stdout as one JSON object per line. Diagnostics go to stderr. Never mix the two channels.

**Why**: The SIEM (Wazuh, Splunk, etc.) reads stdout to capture events. If a debug message or stack trace leaks into stdout, the SIEM tries to parse it as an event, fails, and either drops it silently or generates a decoder error. Stderr is the diagnostics channel — it appears in systemd journal or wodle logs but never enters the event pipeline.

**Enforcement**:
- `emit()` writes to `sys.stdout`
- `log()` writes to `sys.stderr`
- `print()` is never used anywhere (it defaults to stdout and adds ambiguity)

---

## 6. Vendor-namespaced fields

**Rule**: All vendor data is wrapped in a namespace object using a short, unique prefix.

**Why**: SIEMs have reserved field names. Wazuh reserves `id`, `type`, `status`, `data`, and many others. If a vendor API returns a field called `type` and we emit it at the top level, it collides with Wazuh's internal `type` field. The namespace eliminates this entire collision class.

**Convention**:
- 2-3 character prefix derived from the vendor name: `op` (1Password), `pp` (Proofpoint), `xdr` (Cortex XDR)
- All vendor fields nested under this prefix key
- In Wazuh rules, fields are referenced as `{prefix}.field_name`
- In OpenSearch, fields appear as `data.{prefix}.field_name`

---

## 7. Idempotent and resumable

**Rule**: The integration tracks its position (cursor, timestamp, or offset) and resumes from exactly where it left off. No duplicates, no gaps.

**Why**: Integrations run on a schedule (typically every 5 minutes). If the last run fetched events through cursor X, the next run must start from cursor X — not from "the last hour" or "since midnight." Time-based approaches create duplicates at boundaries and gaps on delays. Cursor-based approaches are exact.

**Bookmark types by API pattern**:
- **Cursor/token** (1Password) — the API returns an opaque cursor string. Store it, send it back next time.
- **Timestamp checkpoint** (Proofpoint) — the API returns a `queryEndTime`. Use it as `sinceTime` for the next request.
- **Last-seen ID + timestamp** (Cortex XDR) — the API supports `search_from` with a timestamp filter. Store both.

---

## 8. Observable

**Rule**: Every failure emits a structured error event through the same pipeline as normal events.

**Why**: If an integration fails silently, the absence of events is ambiguous — is it a quiet period or a broken integration? By emitting error events through stdout, the SIEM can alert on integration health using the same rules engine it uses for security events. The operator sees "Integration error: HTTP 401" in their dashboard, not silence.

**Error event structure**:
```json
{
  "integration": "vendorname",
  "vn": {
    "event_type": "error",
    "error_source": "module_name",
    "error_message": "descriptive message",
    "error_code": 401
  }
}
```

A dedicated rule matches these at an elevated severity level (typically level 8-10).
