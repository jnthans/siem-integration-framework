# Phase 3: Testing

Testing happens at three levels: standalone (outside Wazuh), integrated (through Wazuh), and operational (sustained production-like runs).

---

## Level 1: Standalone testing

Run the wodle directly from the command line, outside Wazuh. This validates API connectivity, authentication, pagination, and event transformation.

### First test: connectivity and auth
```bash
cd /var/ossec/wodles/vendorname/
sudo -u wazuh ./run.sh --source module_a --all --lookback 1 --debug 2
```

**Expected**: JSON events printed to stdout, debug info to stderr. If credentials are wrong, you see an error event with HTTP 401/403.

### Verify output format
Pipe stdout through `jq` to validate JSON structure:
```bash
sudo -u wazuh ./run.sh --all --lookback 1 --debug 0 | head -5 | jq .
```

Check that:
- Each line is valid JSON
- The `integration` field is present and correct
- All vendor data is under the namespace prefix
- Nested objects are preserved (not stringified)
- No debug output leaked into stdout

### Test pagination
Use a larger lookback to trigger multiple pages:
```bash
sudo -u wazuh ./run.sh --all --lookback 24 --debug 1 2>debug.log | wc -l
```

Check debug.log for pagination messages (e.g., "Page 2: 100 events", "Page 3: 42 events"). Verify the total event count is reasonable.

### Test error handling
Temporarily break credentials to verify error events:
```bash
# In a test .secrets file
VN_API_KEY=intentionally-invalid-key

sudo -u wazuh ./run.sh --all --debug 1
```

**Expected**: A structured error event on stdout (not a Python traceback). Other modules should still run.

### Test state management
```bash
# Run 1: normal execution, creates state
sudo -u wazuh ./run.sh --debug 1

# Verify state file
cat state.json | jq .

# Run 2: should fetch only new events since Run 1
sudo -u wazuh ./run.sh --debug 1

# Verify state file updated
cat state.json | jq .
```

### Test atomic state write
```bash
# Start a run, kill it mid-execution
sudo -u wazuh ./run.sh --lookback 168 --debug 1 &
PID=$!
sleep 2
kill -9 $PID

# State file should still be valid (from previous run)
cat state.json | jq .
```

---

## Level 2: Integrated testing

Test the full pipeline through Wazuh: wodle → decoder → rules → OpenSearch.

### Install and configure
1. Copy files to their Wazuh paths (see deployment guide)
2. Add the ossec.conf wodle stanza
3. Restart Wazuh manager

### Verify decoder matching
Check that events are being decoded:
```bash
# Tail the Wazuh alerts log
tail -f /var/ossec/logs/alerts/alerts.json | jq 'select(.rule.groups[] == "vendorname")'
```

If no events appear, check the decoder:
```bash
# Test decoder against a sample event
/var/ossec/bin/wazuh-logtest
# Paste a raw JSON event line, check that it matches the decoder
```

### Verify rule matching
For each event type, verify the correct rule fires:
```bash
# Look for specific rule IDs
grep '"rule":{"id":"100801"' /var/ossec/logs/alerts/alerts.json | head -3 | jq .
```

Check that:
- Rule ID matches the expected event type
- Severity level is correct
- Description interpolates field values correctly
- Groups are assigned properly

### Verify OpenSearch indexing
In the Wazuh Dashboard:
1. Go to **Threat Hunting** (or Discover)
2. Filter by `rule.groups: vendorname`
3. Verify events appear with correct fields under `data.vn.*`
4. Expand an event — check that nested objects are queryable

### Test error rule
If you have access to a test environment, temporarily break credentials and verify:
- The error event appears in OpenSearch
- The error rule (e.g., 100890) fires at the expected severity
- Other modules' events still appear

---

## Level 3: Operational testing

Sustained runs that validate behavior over time.

### Run for 24+ hours
Let the integration run on its normal schedule for at least a full day. Check for:
- **No duplicate events** — compare event counts between OpenSearch and the API's own reporting
- **No gaps** — verify continuous coverage by checking timestamps of first and last events per run
- **State file growth** — the state file should stay small (just cursors/timestamps, not accumulated data)
- **Memory/CPU** — the Python process should not leak memory across runs (each run is a fresh process, but verify)

### Test catch-up after downtime
1. Stop the Wazuh manager for 2+ hours
2. Restart it
3. Verify the integration catches up — processes the gap without duplicating events already ingested
4. Check that catch-up chunking works correctly (if applicable)

### Test rate limit behavior
If the vendor API has known rate limits:
1. Reduce the polling interval temporarily to stress the rate limit
2. Verify that 429 responses trigger retry logic
3. Verify that retry succeeds and no events are lost
4. Verify that the retry is logged (stderr debug level 1+)

---

## Common issues and fixes

| Symptom | Likely cause | Fix |
|---|---|---|
| No events in OpenSearch | Decoder not matching | Check `program_name` in decoder matches `run.sh` |
| Events appear but no rule fires | Base rule `decoded_as` mismatch | Verify decoder name matches rule's `decoded_as` |
| Duplicate events after restart | State not being saved | Check state file path is writable by wazuh user |
| Python traceback in alerts | Debug output on stdout | Ensure all `log()` calls use stderr |
| Nested fields not queryable | JSON not decoded | Verify `plugin_decoder` is `JSON_Decoder` |
| Permission denied | File ownership | `chown root:wazuh`, `chmod 750` for scripts, `640` for secrets |

---

## Testing checklist

- [ ] Standalone: auth and connectivity work
- [ ] Standalone: output is valid JSON with correct structure
- [ ] Standalone: pagination fetches all events
- [ ] Standalone: error handling emits structured error events
- [ ] Standalone: state file is created and updated correctly
- [ ] Standalone: state file survives kill -9
- [ ] Integrated: decoder matches events
- [ ] Integrated: rules fire with correct IDs and severity
- [ ] Integrated: events appear in OpenSearch with queryable fields
- [ ] Integrated: error rule fires on integration failures
- [ ] Operational: no duplicates over 24+ hours
- [ ] Operational: catch-up works after downtime
- [ ] Operational: rate limits handled gracefully
