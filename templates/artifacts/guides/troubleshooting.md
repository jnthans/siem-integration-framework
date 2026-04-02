# {VENDOR_DISPLAY} Wodle — Troubleshooting

---

## Quick diagnostics

```bash
# Is the wodle producing output?
sudo -u wazuh /var/ossec/wodles/{VENDOR_LOWER}/run.sh --all --lookback 1 --debug 1

# Are events reaching Wazuh?
tail -f /var/ossec/logs/alerts/alerts.json | jq 'select(.rule.groups[] == "{VENDOR_LOWER}")'

# Is the state file being updated?
cat /var/ossec/wodles/{VENDOR_LOWER}/state.json | jq .

# Check Wazuh manager logs for errors
grep -i "{VENDOR_LOWER}\|run.sh" /var/ossec/logs/ossec.log | tail -20
```

---

## Common problems

| Symptom | Cause | Fix |
|---|---|---|
| No events in dashboard | Decoder not matching | Verify `program_name` in decoder matches the `<tag>` value in ossec.conf. Run `wazuh-logtest` with a sample event. |
| Events appear but no rule fires | `decoded_as` mismatch | Ensure decoder `name` matches rule's `decoded_as` value exactly. |
| `Permission denied` | Wrong file ownership | `chown root:wazuh` and `chmod 750` (scripts) / `chmod 640` (secrets, Python modules). |
| `No module named {VENDOR}_utils` | Script not executable or wrong working dir | Add `#!/usr/bin/env python3` to all `.py` files. Verify `run.sh` uses `SCRIPT_DIR`. |
| Python traceback in alerts | Debug output on stdout | Verify all `log()` calls use stderr. Remove any `print()` statements. |
| Duplicate events | State not persisting | Check state file path is writable. Verify `--all` flag is not set in ossec.conf. |
| Missing events / gaps | State file corruption | Delete state file to force fresh start from lookback window. |
| HTTP 401 / 403 | Invalid or expired credentials | Regenerate API key. Verify `.secrets` file format (KEY=VALUE, no extra spaces). |
| HTTP 429 | Rate limit exceeded | Increase polling interval in ossec.conf. Check rate limit budget calculation. |
| Nested fields not queryable | JSON decoder not active | Verify `plugin_decoder` is `JSON_Decoder` in decoder XML. |

---

## Test commands

```bash
# Test connectivity and auth — last 1 hour, no state change
sudo -u wazuh /var/ossec/wodles/{VENDOR_LOWER}/run.sh \
  --all --lookback 1 --debug 1

# Backfill — fetch historical data (adjust hours as needed)
sudo -u wazuh /var/ossec/wodles/{VENDOR_LOWER}/run.sh \
  --all --lookback 24 --debug 1

# Test specific module only
sudo -u wazuh /var/ossec/wodles/{VENDOR_LOWER}/run.sh \
  --source {MODULE_A} --all --lookback 1 --debug 2

# Full trace (maximum verbosity)
sudo -u wazuh /var/ossec/wodles/{VENDOR_LOWER}/run.sh \
  --all --lookback 1 --debug 3 2>trace.log

# Test decoder matching
/var/ossec/bin/wazuh-logtest
# Paste a JSON event line from stdout and verify decoder/rule matches
```

---

## State management

### Reset all state (re-fetch from lookback window)
```bash
sudo rm /var/ossec/wodles/{VENDOR_LOWER}/state.json
sudo systemctl restart wazuh-manager
```

### Reset one module's state
```bash
# Edit state.json and remove the specific cursor key
sudo -u wazuh python3 -c "
import json
state = json.load(open('/var/ossec/wodles/{VENDOR_LOWER}/state.json'))
state.pop('{MODULE_A}_cursor', None)
json.dump(state, open('/var/ossec/wodles/{VENDOR_LOWER}/state.json', 'w'), indent=2)
"
```

### Inspect current cursor positions
```bash
cat /var/ossec/wodles/{VENDOR_LOWER}/state.json | jq .
```

---

## Log locations

| Log | Location | Contains |
|---|---|---|
| Wodle stderr | systemd journal or `/var/ossec/logs/ossec.log` | Debug messages, errors |
| Wazuh alerts | `/var/ossec/logs/alerts/alerts.json` | Decoded and rule-matched events |
| Wazuh archives | `/var/ossec/logs/archives/archives.json` | All decoded events (if archiving enabled) |
| OpenSearch | Wazuh Dashboard > Threat Hunting | Indexed events with full field access |
