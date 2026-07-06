# Adapting to Other SIEMs

The framework architecture is Wazuh-native but the core integration logic (API fetching, state management, credential handling) is SIEM-agnostic. This guide maps the Wazuh-specific components to their equivalents in other SIEMs.

---

## What is SIEM-specific vs SIEM-agnostic

| Component | SIEM-specific? | What changes |
|---|---|---|
| `{vendor}_utils.py` | No | Identical across SIEMs |
| `{vendor}_events.py` (domain modules) | No | Identical across SIEMs |
| `{vendor}.py` (entry point) | Minimal | Only if scheduling or output format differs |
| `emit()` function | **Yes** | Output destination changes per SIEM |
| `run.sh` | **Yes** | Scheduling mechanism differs |
| Decoder/rules | **Yes** | Every SIEM has its own parsing/alerting config |
| Dashboard artifacts | **Yes** | SIEM-specific visualization format |

The Python code (layers 2-4 of the architecture) ports with zero or minimal changes. Layer 1 (shell wrapper) and the decoder/rules layer are rewritten per SIEM.

---

## Splunk

### Output method
Splunk modular inputs read from stdout — same as Wazuh. The `emit()` function works as-is. The entry point becomes a Splunk modular input script instead of a wodle command.

### Scheduling
Splunk handles scheduling via `inputs.conf`:
```ini
[script://./bin/vendorname.py]
interval = 300
sourcetype = vendor:events
index = main
disabled = 0
```

Replace `run.sh` + ossec.conf with this stanza. Environment variables move into a Splunk setup page or `inputs.conf` parameters.

### Parsing
Replace the Wazuh decoder with Splunk's `props.conf` and `transforms.conf`:
```ini
# props.conf
[vendor:events]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
KV_MODE = json
TIME_PREFIX = "timestamp":
TIME_FORMAT = %Y-%m-%dT%H:%M:%S
```

### Alerting
Replace Wazuh rules with Splunk saved searches or correlation searches (Enterprise Security).

### Packaging
Package as a Splunk app (`.spl` or `.tar.gz`) following Splunk's app directory structure.

---

## Microsoft Sentinel

### Output method
Sentinel does not read from stdout. Replace `emit()` with an HTTP POST to the Azure Monitor **Logs Ingestion API** (DCR-based) — the supported ingestion path. You need three Azure resources:

1. A **Data Collection Endpoint (DCE)** — provides the ingestion URL
2. A **Data Collection Rule (DCR)** — defines the target custom table and any transformation; note its immutable ID
3. A **Microsoft Entra app registration** granted the `Monitoring Metrics Publisher` role on the DCR — provides the bearer token

```python
import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone

def get_ingestion_token(tenant_id, client_id, client_secret):
    data = urllib.parse.urlencode({
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://monitor.azure.com/.default',
    }).encode()
    req = urllib.request.Request(
        f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token',
        data=data
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())['access_token']

def emit_sentinel(events, token, dce_endpoint, dcr_immutable_id, stream_name):
    """POST a batch of events. stream_name is e.g. 'Custom-VendorEvents_CL'."""
    now = datetime.now(timezone.utc).isoformat()
    body = json.dumps([dict(event, TimeGenerated=now) for event in events]).encode()
    req = urllib.request.Request(
        f'{dce_endpoint}/dataCollectionRules/{dcr_immutable_id}'
        f'/streams/{stream_name}?api-version=2023-01-01',
        data=body,
        headers={
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }
    )
    urllib.request.urlopen(req, timeout=30)
```

Batch events into arrays (up to ~1 MB per request) rather than posting one at a time — the Logs Ingestion API is designed for batches.

> **Legacy footnote**: the older HTTP Data Collector API (`SharedKey {workspace_id}:{signature}` against `https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01`) still functions but is deprecated and receives no new capabilities — use it only for existing deployments that already depend on it. If you maintain such code, build the `x-ms-date` header with `datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')` — `datetime.utcnow()` is deprecated as of Python 3.12.

### Scheduling
Use Azure Logic Apps, Azure Functions (timer trigger), or a VM with cron/systemd timer. The entry point runs the same — only the trigger mechanism changes.

### Parsing
Sentinel ingests JSON natively. With the Logs Ingestion API, the DCR's transformation maps incoming JSON fields to the custom table's columns (e.g., `VendorEvents_CL`). No decoder equivalent needed — but define a KQL parser function for convenience:
```kql
let VendorParser = () {
    VendorEvents_CL
    | extend EventType = tostring(vn_event_type_s)
    | extend ActorEmail = tostring(vn_actor_email_s)
};
```

### Alerting
Replace Wazuh rules with Sentinel Analytics Rules (KQL-based):
```kql
VendorEvents_CL
| where vn_event_type_s == "error"
| project TimeGenerated, vn_error_message_s, vn_error_source_s
```

---

## Elastic Security

### Output method
Two options:
1. **Filebeat custom input** — write JSON lines to a file, Filebeat ships them to Elasticsearch. `emit()` writes to a file instead of stdout.
2. **Direct Elasticsearch API** — POST events directly to an index. Replace `emit()` with an HTTP POST.

### Scheduling
Use cron, systemd timer, or Elastic's fleet agent with a custom input.

### Parsing
Define an Elasticsearch ingest pipeline:
```json
{
  "processors": [
    {
      "json": {
        "field": "message",
        "add_to_root": true
      }
    },
    {
      "remove": {
        "field": "message"
      }
    }
  ]
}
```

### Alerting
Use Elastic Security detection rules (KQL or EQL).

---

## QRadar

### Output method
QRadar accepts syslog. Replace `emit()` with a syslog sender that wraps the JSON in a syslog envelope:
```python
import socket

def emit_qradar(event, qradar_host, port=514):
    msg = json.dumps(event, separators=(",", ":"))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(f"<134>{msg}".encode(), (qradar_host, port))
    sock.close()
```

### Scheduling
Use cron or systemd timer on a dedicated log source host.

### Parsing
Create a QRadar DSM (Device Support Module) or custom log source type with a JSON property mapping.

### Alerting
Use QRadar offense rules.

---

## General porting process

1. **Copy the Python code** — utils, domain modules, and entry point
2. **Replace `emit()`** — adapt output to the target SIEM's ingestion method
3. **Replace scheduling** — use the target SIEM's scheduling mechanism
4. **Replace `run.sh`** — may not be needed if the SIEM handles execution directly
5. **Write parsing config** — decoder/props/ingest pipeline equivalent
6. **Write alerting rules** — rules/saved searches/analytics rules equivalent
7. **Test the full pipeline** — same testing process, different verification tools

The investment in clean architecture pays off here: steps 1 and most of 2 are copy operations. Steps 3-6 are SIEM-specific but follow documented patterns.
