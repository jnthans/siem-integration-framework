# SIEM Integration Framework

An open-source framework for building secure, reliable, and efficient SIEM integrations — distilled from production Wazuh wodles monitoring 1Password, Proofpoint TAP, and Cortex XDR.

**Framework site:** [https://jnthans.github.io/siem-integration-framework](https://jnthans.github.io/siem-integration-framework)

---

## What this is

This framework captures the repeatable architecture, process, coding conventions, and tooling behind a series of production SIEM integrations. Every integration we built followed the same pattern — this repo codifies that pattern so anyone (human or AI) can replicate it for any vendor API.

The framework is **Wazuh-primary** with guidance on adapting the architecture to Splunk, Microsoft Sentinel, Elastic, and other SIEMs.

---

## Who this is for

- **Security engineers** building integrations for their SIEM deployment
- **MSSPs/MSPs** needing repeatable integration patterns across client environments
- **AI models** (Claude, GPT, Copilot, etc.) assisting with integration development — see [`llm-references/`](llm-references/) for machine-readable blueprints
- **Open-source contributors** looking to extend the pattern to new vendor APIs

---

## Repository structure

```
siem-integration-framework/
├── docs/                          # Framework documentation (GitHub Pages site)
│   ├── architecture/              # System design and data flow
│   ├── process/                   # Step-by-step build process
│   ├── guides/                    # AI prompting, security, SIEM adaptation
│   └── reference/                 # Coding conventions, repo layout, rule design
├── templates/                     # Scaffold files — copy and customize
│   ├── wodle/                     # Python entry point, modules, utils, run.sh
│   ├── rules/                     # Decoder and rule XML templates
│   └── artifacts/                 # Config examples, guide templates
├── llm-references/                # Machine-readable files for AI-assisted building
│   ├── SYSTEM_PROMPT.md           # Drop-in system prompt for AI sessions
│   ├── ARCHITECTURE.md            # Architecture spec for LLM context
│   ├── CODING_STANDARDS.md        # Style and convention rules
│   ├── CHECKLIST.md               # End-to-end build checklist
│   └── EXAMPLES.md                # Condensed patterns from real integrations
└── examples/                      # Links to production integrations built with this framework
```

---

## Quick start

### 1. Use the templates

Copy the `templates/` directory and rename files for your target vendor:

```bash
cp -r templates/ my-wazuh-vendor/
cd my-wazuh-vendor/

# Rename files — replace 'integration' with your vendor name
mv wodle/integration.py wodle/vendorname.py
mv wodle/integration_module.py wodle/vendorname_events.py
mv wodle/integration_utils.py wodle/vendorname_utils.py
mv rules/integration_rules.xml rules/vendorname_rules.xml
mv rules/integration_decoder.xml rules/vendorname_decoder.xml
```

### 2. AI-assisted building

Feed the LLM reference files to your AI assistant:

```
Attach these files to your AI session:
  llm-references/SYSTEM_PROMPT.md      # Sets the AI's role and constraints
  llm-references/ARCHITECTURE.md       # Architecture it must follow
  llm-references/CODING_STANDARDS.md   # Code style it must use
  llm-references/CHECKLIST.md          # Step-by-step process to follow
```

Then prompt:

> "Build a Wazuh integration for [Vendor] using the [API name]. The API uses [auth method] and returns [data format]. Here is the API documentation: [link or paste]."

### 3. Follow the process

The framework documents a five-phase process:

1. **Plan** — Research the vendor API, map event types, reserve rule IDs
2. **Build** — Implement the wodle following the architecture and coding standards
3. **Test** — Validate with `--all --debug 1`, verify events in OpenSearch
4. **Deploy** — Install to the Wazuh manager, configure ossec.conf
5. **Document** — Write the three standard guides plus README

Each phase is detailed in [`docs/process/`](docs/process/).

---

## Production integrations built with this framework

| Integration | Vendor API | Event types | Repo |
|---|---|---|---|
| wazuh-1password | 1Password Events API v2 | Audit, sign-in, item usage | [jnthans/wazuh-1password](https://github.com/jnthans/wazuh-1password) |
| wazuh-proofpoint | Proofpoint TAP SIEM + People API | Messages, clicks, VAP, top clickers | [jnthans/wazuh-proofpoint](https://github.com/jnthans/wazuh-proofpoint) |
| wazuh-cortex-xdr | Cortex XDR REST API | Alerts, incidents | [jnthans/wazuh-cortex-xdr](https://github.com/jnthans/wazuh-cortex-xdr) |

---

## Design principles

These principles emerged from building and operating the integrations above. They are non-negotiable constraints in the framework:

1. **Zero external dependencies** — stdlib Python only. No pip installs on the SIEM host.
2. **Atomic state** — `tempfile` + `os.replace`. A kill -9 mid-write never corrupts state.
3. **Independent failure isolation** — one stream failing never blocks the others.
4. **Secure credential chain** — systemd credentials > secrets file > env vars. Never log secrets.
5. **Single JSON lines to stdout** — the SIEM reads stdout. Diagnostics go to stderr only.
6. **Vendor-namespaced fields** — all vendor data lives under a short prefix (`op.*`, `pp.*`, `xdr_*`) to avoid collisions with reserved SIEM field names.
7. **Idempotent and resumable** — cursor/timestamp bookmarking ensures no duplicates and no gaps.
8. **Observable** — every failure emits a structured error event the SIEM can alert on.

---

## Contributing

This framework improves every time someone builds an integration with it. Contributions welcome:

- **New integration?** Open a PR to add it to the examples table
- **Found a gap?** File an issue describing what the framework didn't cover
- **Better patterns?** PRs to templates, docs, or LLM references are all welcome

---

## License

MIT — see [LICENSE](LICENSE).
