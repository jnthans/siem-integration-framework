# Data Flow

This document traces the path of a single vendor event from API response to SIEM dashboard.

---

## End-to-end flow

```
Vendor API
    │
    ▼
Domain module fetches via HTTP (GET or POST)
    │
    ▼
JSON response parsed — events extracted from response body
    │
    ▼
Each event transformed:
  - Wrapped in vendor namespace (e.g., {"op": {...}})
  - Metadata added (integration name, event_type, timestamp)
  - Flattened where needed for SIEM compatibility
    │
    ▼
emit() writes one JSON line to stdout
    │
    ▼
Wazuh wodle manager captures stdout
    │
    ▼
Decoder matches on program name → extracts JSON
    │
    ▼
Rules evaluate extracted fields → assign rule ID, level, description
    │
    ▼
Event indexed in OpenSearch with all fields under data.*
    │
    ▼
Dashboard visualizations query data.{namespace}.*
```

---

## Stage details

### 1. API fetch

The domain module constructs and executes the API request. Key behaviors:

- **Pagination**: The module handles vendor-specific pagination (cursor-based, offset-based, or time-window chunking). Each page is processed before requesting the next.
- **Rate limiting**: HTTP 429 responses trigger a sleep-and-retry cycle. The `Retry-After` header is respected when present, capped at a configurable maximum (default 60 seconds).
- **Timeouts**: Configurable connect and read timeouts prevent indefinite hangs.
- **Error isolation**: A failed request emits a structured error event and returns. It never raises an exception that could block other modules.

### 2. Event transformation

Each raw vendor event is transformed into the standard emission format:

```json
{
  "integration": "vendorname",
  "vendor_namespace": {
    "event_type": "signin_attempt",
    "field_a": "value",
    "field_b": {
      "nested_field": "preserved as-is"
    }
  }
}
```

Transformation rules:

- **Namespace isolation**: All vendor fields live under a short prefix key. This prevents collisions with Wazuh's reserved field names (`id`, `type`, `status`, `data`, etc.).
- **Nested JSON preserved**: Vendor objects (locations, actors, threat maps) are emitted as native JSON — never flattened into dot-notation strings. This enables rich OpenSearch queries.
- **Timestamps normalized**: Vendor timestamps are passed through as-is (ISO 8601). No timezone conversion — the SIEM handles display localization.
- **No data dropped**: Every field the API returns is emitted. Filtering happens in rules, not in the wodle.

### 3. Emission

The `emit()` function in utils handles output:

```python
def emit(event: dict) -> None:
    """Write a single JSON event to stdout (one line, no trailing newline issues)."""
    line = json.dumps(event, separators=(",", ":"))
    sys.stdout.write(line + "\n")
    sys.stdout.flush()
```

Critical constraints:
- One JSON object per line — Wazuh's wodle manager reads line-delimited JSON
- `separators=(",", ":")` — compact output, no unnecessary whitespace
- Explicit `flush()` — ensures the SIEM receives the event immediately
- No `print()` — avoids platform-specific newline behavior

### 4. Wazuh decoder

The decoder registers the integration's program name and activates JSON decoding:

```xml
<decoder name="json_decoder">
  <parent>vendorname</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

This tells Wazuh to parse the stdout line as JSON and make all fields available under `data.*` for rule matching.

### 5. Wazuh rules

Rules match on decoded fields to assign severity, description, and grouping:

```xml
<rule id="100801" level="5">
  <decoded_as>vendorname</decoded_as>
  <field name="integration">vendorname</field>
  <field name="vn.event_type">signin_attempt</field>
  <description>Vendor: sign-in attempt by $(vn.actor.email)</description>
  <group>vendorname,authentication,</group>
</rule>
```

Rules are the primary filtering and classification layer. The wodle emits everything; rules decide what matters.

### 6. OpenSearch indexing

Once a rule matches, the event is indexed in OpenSearch. Fields appear under `data.*`:

- `data.integration` → `"vendorname"`
- `data.vn.event_type` → `"signin_attempt"`
- `data.vn.actor.email` → `"user@example.com"`

Dashboard visualizations query these fields directly. The namespace prefix means vendor fields never collide with Wazuh's own indexed fields.

---

## State management flow

```
Start of run
    │
    ▼
load_state(state_file_path)
  → Returns dict (empty dict if file missing or first run)
    │
    ▼
Pass relevant cursor/timestamp to each domain module
    │
    ▼
Module fetches from cursor position
  → Returns updated cursor after processing
    │
    ▼
Orchestrator collects updated cursors from all modules
    │
    ▼
save_state(state_file_path, updated_state)
  → Writes to temp file first
  → os.replace() atomically swaps temp → state file
    │
    ▼
End of run — state is durable, consistent, and crash-safe
```

The atomic write pattern ensures that if the process is killed at any point during the write, the previous state file remains intact. The next run resumes from the last successful checkpoint.

---

## Credential flow

```
run.sh sets env vars (paths, non-secret config)
    │
    ▼
{vendor}_utils.py credential_chain():
    │
    ├─► Check $CREDENTIALS_DIRECTORY/{key}     [systemd — most secure]
    │     Found? → return value
    │
    ├─► Check secrets file (KEY=VALUE format)   [.secrets file — recommended]
    │     Found? → return value
    │
    └─► Check $ENV_VAR                          [environment — least secure]
          Found? → return value
          Not found? → raise error (credential is required)
```

The chain is evaluated per credential key, not globally. This means one credential can come from systemd while another comes from the secrets file — useful in migration scenarios.

---

## Error event flow

When something goes wrong, the integration emits a structured error event through the same stdout pipeline:

```json
{
  "integration": "vendorname",
  "vn": {
    "event_type": "error",
    "error_source": "siem_api",
    "error_message": "HTTP 401: invalid credentials",
    "error_code": 401
  }
}
```

This error event flows through the same decoder → rules → OpenSearch pipeline. A dedicated rule matches error events at a higher severity level, enabling SIEM alerts on integration health issues. The operator sees integration failures in the same dashboard they use for vendor events — no need to SSH into the host and check logs.
