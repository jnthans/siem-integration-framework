# Repository Structure

Every integration follows this directory layout. Consistency across integrations means operators and contributors know exactly where to find each component.

---

## Standard layout

```
wazuh-{vendor}/
├── wodle/
│   ├── {vendor}.py                  ← Entry point, CLI, orchestration
│   ├── {vendor}_{module_a}.py       ← Domain module (API surface A)
│   ├── {vendor}_{module_b}.py       ← Domain module (API surface B, if needed)
│   ├── {vendor}_utils.py            ← Shared utilities (auth, HTTP, state, emit, log)
│   ├── run.sh                       ← Runtime config wrapper (ossec.conf target)
│   └── .secrets.example             ← Credentials template
├── rules/
│   ├── {vendor}_rules.xml           ← Custom Wazuh rules
│   └── {vendor}_decoder.xml         ← JSON decoder registration
├── artifacts/
│   ├── configs/
│   │   └── ossec_{vendor}.conf      ← ossec.conf wodle stanza example
│   ├── guides/
│   │   ├── configuration.md         ← All env vars, CLI flags, credential chain
│   │   ├── rules-reference.md       ← Rule catalog, field reference, severity mapping
│   │   └── troubleshooting.md       ← Test commands, common errors, state reset
│   ├── objects/                      ← (Optional) Dashboard exports (.ndjson)
│   ├── overrides/                    ← (Optional) Docker compose overrides
│   └── images/                       ← Dashboard screenshots for README
├── .gitignore
└── README.md
```

---

## File naming conventions

| File | Naming pattern | Example |
|---|---|---|
| Entry point | `{vendor}.py` | `proofpoint.py` |
| Domain module | `{vendor}_{surface}.py` | `proofpoint_siem.py` |
| Utils | `{vendor}_utils.py` | `proofpoint_utils.py` |
| Shell wrapper | `run.sh` | `run.sh` (always) |
| Secrets template | `.secrets.example` | `.secrets.example` (always) |
| Decoder | `{vendor}_decoder.xml` | `proofpoint_decoder.xml` |
| Rules | `{vendor}_rules.xml` | `proofpoint_rules.xml` |
| ossec.conf example | `ossec_{vendor}.conf` | `ossec_proofpoint.conf` |

The vendor name in filenames should be lowercase, using underscores for multi-word names (e.g., `cortex_xdr`).

---

## .gitignore

```gitignore
# Credentials — never commit
.secrets
*.secrets
tenants.json

# Runtime state — host-specific
state.json
*.state

# Python
__pycache__/
*.pyc
*.pyo

# OS
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/
*.swp
*.swo
```

---

## What goes where

### `wodle/` — executable code only
Everything the Wazuh manager needs to execute the integration. No documentation, no configuration examples, no dashboards. If the file runs, it goes in `wodle/`.

### `rules/` — Wazuh decoder and rules only
The two XML files that configure Wazuh's parsing and alerting pipeline. These are copied to `/var/ossec/etc/decoders/` and `/var/ossec/etc/rules/` during installation.

### `artifacts/` — everything else
Configuration examples, documentation guides, dashboard exports, Docker overrides, screenshots. Organized into subdirectories by purpose. The `artifacts/` directory is a reference library — nothing in it is required for the integration to function.

### Root — repo-level files
README, .gitignore, LICENSE. These are standard open-source repo files. Use GitHub Releases for version history.
