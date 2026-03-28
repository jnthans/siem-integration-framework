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
Sentinel does not read from stdout. Replace `emit()` with an HTTP POST to the Azure Monitor Data Collector API (or the newer Logs Ingestion API):

```python
def emit_sentinel(event, workspace_id, shared_key, log_type):
    body = json.dumps([event])
    date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    signature = build_signature(workspace_id, shared_key, date, len(body), 'POST', 'application/json', '/api/logs')
    
    headers = {
        'Authorization': f'SharedKey {workspace_id}:{signature}',
        'Content-Type': 'application/json',
        'Log-Type': log_type,
        'x-ms-date': date
    }
    
    req = urllib.request.Request(
        f'https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01',
        data=body.encode(), headers=headers
    )
    urllib.request.urlopen(req)
```

### Scheduling
Use Azure Logic Apps, Azure Functions (timer trigger), or a VM with cron/systemd timer. The entry point runs the same — only the trigger mechanism changes.

### Parsing
Sentinel ingests JSON natively via the Data Collector API. Fields appear in the custom log table (e.g., `VendorEvents_CL`). No decoder equivalent needed — but define a KQL parser function for convenience:
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
    sock = socket.socket(socket.AF_INET, socket.SOCK_UDP)
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
