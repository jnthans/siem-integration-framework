# SIEM Integration Framework — Examples

Condensed code patterns from three production integrations. Use these as concrete references when building a new integration.

---

## Example 1: Bearer token auth (1Password pattern)

### Auth headers
```python
def bearer_auth_headers(token):
    return {"Authorization": "Bearer " + token}
```

### Cursor-based pagination (POST)
```python
def fetch_events(credentials, cursor, config):
    headers = bearer_auth_headers(credentials["bearer_token"])
    headers["Content-Type"] = "application/json"
    url = config["base_url"] + "/api/v2/signinattempts"

    total = 0
    has_more = True

    body = {"limit": config.get("page_limit", 100)}
    if cursor:
        body["cursor"] = cursor
    else:
        start_time = (datetime.now(timezone.utc) - timedelta(hours=config["lookback_hours"])).isoformat()
        body["start_time"] = start_time

    while has_more:
        response = http_with_retry(lambda: http_post(url, headers, body))
        events = response.get("items", [])
        new_cursor = response.get("cursor")
        has_more = response.get("has_more", False)

        for raw in events:
            emit({
                "integration": "onepassword",
                "op": {
                    "event_type": "signin_attempt",
                    **raw
                }
            })
            total += 1

        if has_more and new_cursor:
            body = {"cursor": new_cursor, "limit": config.get("page_limit", 100)}

    log(1, "signin: {} events", total)
    return new_cursor or cursor
```

### Multi-stream orchestration
```python
# In orchestrator — three independent streams
streams = [
    ("audit", "audit_cursor", fetch_audit),
    ("signin", "signin_cursor", fetch_signin),
    ("itemusage", "itemusage_cursor", fetch_itemusage),
]
for name, key, fetch_fn in streams:
    if should_run(name, config):
        try:
            state[key] = fetch_fn(credentials, state.get(key), config)
        except Exception as e:
            emit_error(name, str(e))
```

---

## Example 2: Basic auth with time-window pagination (Proofpoint pattern)

### Auth headers
```python
def basic_auth_headers(principal, secret):
    import base64
    creds = "{}:{}".format(principal, secret)
    encoded = base64.b64encode(creds.encode("utf-8")).decode("ascii")
    return {"Authorization": "Basic " + encoded}
```

### Time-window chunking (gap catch-up)
```python
def fetch_siem_events(credentials, last_query_end, config):
    headers = basic_auth_headers(credentials["principal"], credentials["secret"])
    base_url = config["base_url"]

    if not last_query_end:
        # First run — use sinceSeconds for short lookback
        lookback_sec = config["lookback_hours"] * 3600
        if lookback_sec <= 3600:
            url = "{}/v2/siem/all?sinceSeconds={}&format=json".format(base_url, lookback_sec)
        else:
            # Chunk into 1-hour windows
            return _chunked_catchup(headers, base_url, config["lookback_hours"], config)
    else:
        url = "{}/v2/siem/all?sinceTime={}&format=json".format(base_url, last_query_end)

    response = http_with_retry(lambda: http_get(url, headers))
    query_end = response.get("queryEndTime", last_query_end)

    for category in ("messagesBlocked", "messagesDelivered", "clicksBlocked", "clicksPermitted"):
        for raw in response.get(category, []):
            emit({
                "integration": "proofpoint",
                "pp": {
                    "event_type": category,
                    **raw
                }
            })

    return query_end
```

### Separate polling cadences (People API)
```python
# In orchestrator — People API runs on its own schedule
people_interval = int(os.environ.get("PP_PEOPLE_INTERVAL", "86400"))
last_people = state.get("people_last_fetch", "")
if last_people:
    elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(last_people)).total_seconds()
    if elapsed < people_interval:
        log(1, "People: skipping ({}s until next fetch)", int(people_interval - elapsed))
    else:
        # Run people fetch
        try:
            fetch_people(credentials, config)
            state["people_last_fetch"] = datetime.now(timezone.utc).isoformat()
        except Exception as e:
            emit_error("people", str(e))
```

---

## Example 3: HMAC auth with mode system (Cortex XDR pattern)

### HMAC auth headers
```python
def xdr_auth_headers(api_key_id, api_key):
    import hashlib, string, secrets as sec
    nonce = "".join(sec.choices(string.ascii_letters + string.digits, k=64))
    timestamp = str(int(time.time()) * 1000)
    auth_string = "{}{}{}".format(api_key, nonce, timestamp)
    api_key_hash = hashlib.sha256(auth_string.encode("utf-8")).hexdigest()
    return {
        "x-xdr-auth-id": str(api_key_id),
        "x-xdr-nonce": nonce,
        "x-xdr-timestamp": timestamp,
        "Authorization": api_key_hash,
        "Content-Type": "application/json",
    }
```

### Offset-based pagination (POST)
```python
def fetch_incidents(credentials, last_timestamp, config):
    total = 0
    offset = 0
    page_size = 100

    while True:
        headers = xdr_auth_headers(credentials["key_id"], credentials["key"])
        body = {
            "request_data": {
                "search_from": offset,
                "search_to": offset + page_size,
                "sort": {"field": "modification_time", "keyword": "asc"},
                "filters": []
            }
        }
        if last_timestamp:
            body["request_data"]["filters"].append({
                "field": "modification_time",
                "operator": "gte",
                "value": last_timestamp
            })

        url = "https://{}/public_api/v1/incidents/get_incidents/".format(config["fqdn"])
        response = http_with_retry(lambda: http_post(url, headers, body))

        incidents = response.get("reply", {}).get("incidents", [])
        if not incidents:
            break

        for raw in incidents:
            emit({
                "integration": "cortex_xdr",
                "xdr_event_type": "incident",
                "xdr_severity": raw.get("severity", "unknown"),
                **{"xdr_" + k: v for k, v in raw.items()}
            })
            total += 1

        newest_ts = max(i.get("modification_time", 0) for i in incidents)
        offset += page_size

        if len(incidents) < page_size:
            break

    log(1, "Incidents: {} total", total)
    return newest_ts or last_timestamp
```

### Mode system (preset configurations)
```python
MODES = {
    "economy":  {"alerts": False, "enrichment": False},
    "balanced": {"alerts": True, "alert_severities": ["high", "critical"], "enrichment": False},
    "enriched": {"alerts": True, "alert_severities": ["low", "medium", "high", "critical"], "enrichment": True},
}

def load_config(args):
    mode_name = args.mode or os.environ.get("XDR_MODE", "balanced")
    mode = MODES[mode_name]
    config = {
        "mode": mode_name,
        "fetch_alerts": mode["alerts"],
        "alert_severities": mode.get("alert_severities", []),
        "enrichment": mode["enrichment"],
        # ... other config
    }
    return config
```

---

## Example 4: Push ingestion (HEC receiver pattern)

For sources that push instead of exposing a pollable API. There is no
cursor and no wodle — a long-running receiver (templates/receiver/
hec_receiver.py, concrete and runnable) accepts HEC batches and appends
framework-format JSON lines to a spool file that Wazuh tails. Dedup is
the sender's job.

### Token map — per-source auth via the credential chain
```python
# HEC_TOKENS (systemd credential > .secrets > env) holds
# comma-separated <token>:<source>:<namespace> triplets:
#   f2a4...:firewall:fw,9c81...:m365:m365
def parse_token_map(raw):
    tokens = {}
    for entry in raw.split(","):
        token, source, namespace = (p.strip() for p in entry.strip().split(":"))
        tokens[token] = {"source": source, "namespace": namespace}
    return tokens
# Revoke one sender: remove its triplet, restart the receiver.
```

### Batch parsing — HEC bodies are CONCATENATED JSON objects, not an array
```python
def parse_hec_batch(text):
    # {"event":...}{"event":...}  →  json.loads() would fail; loop raw_decode()
    decoder = json.JSONDecoder()
    envelopes = []
    idx, length = 0, len(text)
    while idx < length:
        while idx < length and text[idx] in " \t\r\n":
            idx += 1
        if idx >= length:
            break
        obj, idx = decoder.raw_decode(text, idx)
        envelopes.append(obj)
    return envelopes
```

### Envelope transform — HEC metadata preserved under namespaced hec_* keys
```python
def transform_envelope(envelope, source, namespace):
    payload = envelope.get("event")
    data = dict(payload) if isinstance(payload, dict) else {"message": payload}
    for meta in ("host", "source", "sourcetype", "time", "fields"):
        if meta in envelope:
            data["hec_" + meta] = envelope[meta]
    if "event_type" not in data:
        data["event_type"] = envelope.get("sourcetype") or "hec_event"
    return {"integration": source, namespace: data}
```

Input → spool line (token mapped to `firewall`/`fw`):
```json
{"event":{"action":"drop","src":"1.2.3.4"},"host":"fw01","sourcetype":"fw:traffic","time":1720000000}
```
```json
{"integration":"firewall","fw":{"action":"drop","src":"1.2.3.4","hec_host":"fw01","hec_sourcetype":"fw:traffic","hec_time":1720000000,"event_type":"fw:traffic"}}
```

### Spool discipline — durability boundary with backpressure
```python
# Acknowledge (200 {"text":"Success","code":0}) ONLY after the spool write.
# Rotate at HECR_SPOOL_MAX_BYTES (keep one .1 generation); above
# HECR_SPOOL_QUOTA_BYTES answer 503 {"text":"Server is busy","code":9} —
# well-behaved senders buffer and retry, nothing is dropped silently.
# Receiver's own failures (auth_failure, malformed_batch, spool_error,
# quota_exceeded) are spooled under integration=hec_receiver, ns "hecr".
```

### Decoder and per-source rules — prematch, no program_name
```xml
<!-- Spool lines arrive via <localfile log_format="json">; the receiver
     always writes "integration" as the first key, so prematch on it. -->
<decoder name="hec_spool">
  <prematch>^{"integration":</prematch>
</decoder>
<decoder name="hec_spool_json">
  <parent>hec_spool</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

```xml
<!-- One rule file per source, own reserved ID block — wodle pattern,
     but the base rule matches decoded_as hec_spool. -->
<group name="firewall,">
  <rule id="100850" level="0">
    <decoded_as>hec_spool</decoded_as>
    <field name="integration">firewall</field>
    <description>Firewall event (via HEC receiver).</description>
  </rule>
  <rule id="100851" level="5">
    <if_sid>100850</if_sid>
    <field name="fw.action">drop</field>
    <description>Firewall: dropped traffic from $(fw.src).</description>
    <group>firewall,firewall_drop,</group>
  </rule>
</group>
```

### Sender test (through the edge)
```sh
curl https://hec.example.com/services/collector/health
curl -X POST https://hec.example.com/services/collector/event \
     -H "Authorization: Splunk <token>" \
     -d '{"event":{"test":"hello"},"sourcetype":"smoke:test"}'
tail -1 /var/ossec/logs/hec/spool.jsonl    # on the receiver host
```

### Push flow diagram
```
push sender ──► edge (Cloudflare Tunnel / Tailscale: TLS, access policy)
                    └─► outbound-only tunnel ──► 127.0.0.1:8088 hec_receiver.py
                                                     │  token → source + namespace
                                                     │  envelope → framework JSON
                                                     ▼
                                    /var/ossec/logs/hec/spool.jsonl (rotate + quota)
                                                     │
                       ossec.conf <localfile log_format="json"> tails the spool
                                                     │
                              hec_spool decoder ──► per-source rules ──► dashboard
```

---

## Example decoder and rules (1Password pattern)

### Decoder
```xml
<decoder name="onepassword">
  <program_name>onepassword</program_name>
</decoder>
<decoder name="onepassword_json">
  <parent>onepassword</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

### Rules
```xml
<group name="onepassword,">
  <rule id="100700" level="0">
    <decoded_as>onepassword</decoded_as>
    <field name="integration">onepassword</field>
    <description>1Password integration event.</description>
  </rule>

  <rule id="100701" level="3">
    <if_sid>100700</if_sid>
    <field name="op.event_type">signin_attempt</field>
    <description>1Password: sign-in attempt by $(op.session.login.email).</description>
    <group>onepassword,authentication,</group>
  </rule>

  <rule id="100705" level="7">
    <if_sid>100701</if_sid>
    <field name="op.type">credentials_failed</field>
    <description>1Password: FAILED sign-in by $(op.session.login.email) from $(op.session.ip).</description>
    <group>onepassword,authentication_failure,</group>
  </rule>

  <rule id="100710" level="3">
    <if_sid>100700</if_sid>
    <field name="op.event_type">itemusage</field>
    <description>1Password: $(op.action) on $(op.item.title) by $(op.user.email).</description>
    <group>onepassword,data_access,</group>
  </rule>

  <rule id="100790" level="8">
    <if_sid>100700</if_sid>
    <field name="op.event_type">error</field>
    <description>1Password integration error ($(op.error_source)): $(op.error_message).</description>
    <group>onepassword,integration_error,</group>
  </rule>
</group>
```

---

## Example README flow diagram

```
ossec.conf <wodle command>
    └─► run.sh  (sets runtime config; execs vendorname.py)
            └─► vendorname.py  (parses args, loads state)
                    ├─► vendorname_events.py   → http_post() → emit() → stdout
                    └─► vendorname_people.py   → http_get()  → emit() → stdout
                                                    │
                                          vendorname_utils.py
                              (auth, HTTP, atomic state, emit, secrets)
                                          │
                          Secret priority chain (first match wins):
                          [systemd $CREDENTIALS_DIRECTORY]
                                    > [.secrets file]
                                    > [env vars]

stdout ──► Wazuh wodle manager ──► decoder.xml ──► rules.xml
                                                       │
                                           OpenSearch / Dashboard
```
