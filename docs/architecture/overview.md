# Architecture Overview

Every integration built with this framework follows the same four-layer architecture. The layers are identical across integrations — only the vendor-specific API logic changes.

---

## The four layers

### Layer 1: Shell wrapper (`run.sh`)

The outermost layer. This is the command target referenced in `ossec.conf`. It does three things and nothing more:

1. Sets environment variables (API endpoints, modes, feature flags)
2. Resolves the path to the Python entry point
3. Execs the Python process (replacing itself — no parent shell lingers)

The shell wrapper is the only file that changes between deployment environments. All environment-specific configuration lives here, keeping the Python code portable.

### Layer 2: Entry point / orchestrator (`{vendor}.py`)

The main Python script. Responsibilities:

1. Parse CLI arguments (overrides for source, debug, lookback, mode)
2. Load and validate configuration from environment variables
3. Load persisted state (cursors, timestamps) from the state file
4. Call each domain module in sequence, passing credentials and state
5. Save updated state atomically after successful processing
6. Handle top-level exceptions and emit structured error events

The entry point never contains API-specific logic. It orchestrates — it does not fetch, parse, or transform vendor data.

### Layer 3: Domain modules (`{vendor}_events.py`, `{vendor}_siem.py`, etc.)

One module per logical API surface or data type. Each module:

1. Constructs API requests (URLs, headers, query parameters, POST bodies)
2. Calls the shared HTTP function from utils
3. Iterates through paginated responses
4. Transforms each vendor event into the namespaced output format
5. Calls `emit()` for each event
6. Returns updated cursor/bookmark state to the orchestrator

Domain modules are where all vendor-specific logic lives. They import from utils but never from each other. This isolation ensures a bug in one module cannot affect another.

### Layer 4: Shared utilities (`{vendor}_utils.py`)

The foundation layer. Provides all cross-cutting concerns:

1. **Credential loading** — the three-tier priority chain (systemd > secrets file > env vars)
2. **HTTP functions** — `http_get()`, `http_post()`, or `api_post()` with retry, timeout, and error handling
3. **State management** — `load_state()`, `save_state()` with atomic writes
4. **Event emission** — `emit()` writes a single JSON line to stdout
5. **Logging** — `log()` writes diagnostic messages to stderr at configurable verbosity
6. **Secrets file parsing** — `load_secrets_file()` for the `KEY=VALUE` format

Utils never import from domain modules or the entry point. Dependencies flow strictly downward: entry point → domain modules → utils.

---

## Component relationship

```
ossec.conf
  └─► run.sh                         [Layer 1: Shell wrapper]
        │  Sets env vars
        │  Execs Python
        └─► {vendor}.py               [Layer 2: Orchestrator]
              │  Parses args
              │  Loads state
              │  Calls modules
              ├─► {vendor}_events.py   [Layer 3: Domain module]
              │     │  Builds requests
              │     │  Paginates
              │     │  Transforms
              │     └─► emit() ──► stdout ──► Wazuh
              │
              ├─► {vendor}_people.py   [Layer 3: Domain module]
              │     └─► emit() ──► stdout ──► Wazuh
              │
              └─► {vendor}_utils.py    [Layer 4: Shared utilities]
                    ├── credential_chain()
                    ├── http_get() / http_post()
                    ├── load_state() / save_state()
                    ├── emit()
                    └── log()
```

---

## How many domain modules?

The answer depends on the vendor API surface:

- **One module** — the API has a single endpoint or closely related endpoints that share auth, pagination, and error handling (e.g., a vendor whose alert and incident endpoints use the same request format and response structure)
- **Two modules** — the API has distinct surfaces with different auth, pagination, or data models (e.g., Cortex XDR separates alerts and incidents into different modules because they have different response schemas and query patterns; Proofpoint has a SIEM API and a People API with different rate limits and schedules)
- **Three+ modules** — rare, but justified when the API surfaces are truly independent

The rule: each module should correspond to one logical API surface that could, in principle, run independently. If two endpoints share request format, pagination, and error handling, they belong in the same module. If they differ on any of those dimensions, separate them.

---

## What stays the same vs. what changes

| Component | Same across integrations | Changes per vendor |
|---|---|---|
| `run.sh` structure | Yes — env vars, exec pattern | Variable names, default values |
| Entry point flow | Yes — args, state, modules, save | Module names, config variables |
| Utils functions | ~90% identical | HTTP auth method, header construction |
| Domain modules | Pattern identical, logic differs | API URLs, pagination, field mapping |
| Decoder XML | Structural template identical | Program name, parent decoder |
| Rules XML | Pattern identical | Rule IDs, field names, descriptions |
| `artifacts/` layout | Identical directory structure | Content specific to vendor |

---

## SIEM-agnostic notes

The architecture is Wazuh-native but portable. The SIEM-specific touchpoints are:

1. **stdout emission** — Wazuh reads stdout from wodle commands. Splunk uses modular inputs (also stdout). Sentinel uses the Data Collector API (HTTP POST). The `emit()` function is the only place this changes.
2. **Decoder/rules** — Wazuh-specific XML. Other SIEMs have their own parsing configuration (Splunk props.conf/transforms.conf, Sentinel KQL parsers, Elastic ingest pipelines).
3. **ossec.conf stanza** — Wazuh-specific scheduling. Other SIEMs use their own scheduling mechanisms (Splunk inputs.conf, cron, systemd timers).
4. **File paths** — `/var/ossec/wodles/` is Wazuh-specific. The integration itself is path-agnostic through environment variables.

See [Adapting to other SIEMs](../guides/adapting-to-other-siems.md) for detailed guidance.
