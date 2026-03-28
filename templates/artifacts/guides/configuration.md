# {VENDOR_DISPLAY} Wodle — Configuration Reference

All configuration is controlled via environment variables set in `run.sh`.
No changes to `ossec.conf` are needed after the initial wodle block is added.

---

## Credential variables

| Variable | Description |
|---|---|
| `{VENDOR_UPPER}_API_KEY` | {VENDOR_DISPLAY} API key. Set via `.secrets` file (recommended) or env var. |
| `{VENDOR_UPPER}_SECRETS_FILE` | Path to the `.secrets` file (default: `<wodle_dir>/.secrets`). |

### Credential priority (first match wins per key)

1. **systemd credentials directory** (`$CREDENTIALS_DIRECTORY/{VENDOR_LOWER}_api_key`) — memory-backed, encrypted at rest on systems with a TPM. Most secure option.
2. **Secrets file** — `{VENDOR_UPPER}_SECRETS_FILE` or the default `.secrets` path. Plain `KEY=VALUE` format. Must be `chown root:wazuh`, `chmod 640`.
3. **Environment variables** in `run.sh` — least secure, avoid in production.

---

## API settings

| Variable | Default | Description |
|---|---|---|
| `{VENDOR_UPPER}_BASE_URL` | `https://api.vendor.com` | API base URL. |
| `{VENDOR_UPPER}_SOURCE` | `all` | Which event streams to poll. |
| `{VENDOR_UPPER}_LOOKBACK_HOURS` | `1` | Hours to look back on first run (no state file). |
| `{VENDOR_UPPER}_DEBUG` | `0` | Debug verbosity: `0`=off, `1`=info, `2`=verbose, `3`=trace. Always goes to stderr. |

---

## State file

| Variable | Default | Description |
|---|---|---|
| `{VENDOR_UPPER}_STATE_FILE` | `/var/ossec/wodles/{VENDOR_LOWER}/state.json` | Path to the state file. Must be writable by the wazuh user. |

### State file structure

```json
{
  "{MODULE_A}_cursor": "opaque-cursor-or-timestamp",
  "{MODULE_A}_last_poll": "2026-03-22T10:00:00Z"
}
```

Written atomically (`tempfile` + `os.replace`). Delete the file to reset and re-fetch from lookback window.

---

## CLI flags

| Flag | Description |
|---|---|
| `--source {MODULE_A}\|all` | Run only the specified source(s). |
| `--all` / `-a` | Ignore state; do not update state after run. For testing and backfill. |
| `--lookback <hours>` / `-l` | Hours to look back in `--all` mode. |
| `--debug 0–3` / `-d` | Override debug verbosity for this run. |

---

## Test commands

```bash
# Test — last 1 hour, no state change
sudo -u wazuh /var/ossec/wodles/{VENDOR_LOWER}/run.sh \
  --source {MODULE_A} --all --lookback 1 --debug 1

# Full run with verbose logging
sudo -u wazuh /var/ossec/wodles/{VENDOR_LOWER}/run.sh --debug 2
```
