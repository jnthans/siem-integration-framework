# SIEM Integration Framework

Architecture and patterns from three production Wazuh integrations — documented for humans and LLMs.

**Documentation site:** [https://jnthans.github.io/siem-integration-framework](https://jnthans.github.io/siem-integration-framework)

---

## What this is (and what it isn't)

I built three Wazuh wodle integrations — for 1Password, Proofpoint TAP, and Cortex XDR. Each one consumed a different vendor API with different auth, pagination, and event models. Each one ended up with the same architecture: the same four-layer design, the same state management, the same credential chain, the same error handling.

This repo extracts those patterns. It's a documented architecture, a set of copy-and-customize templates, and a collection of LLM-ready reference files that let an AI assistant produce framework-consistent integrations from vendor API docs.

It is **not** a library you install or a product you adopt. It's a pattern reference — here's what worked in production and why.

This is **Wazuh-focused**. The architecture is conceptually portable to any SIEM that ingests structured events, and there's a [guide exploring what that looks like](docs/guides/adapting-to-other-siems.md), but only the Wazuh path has been tested in production.

---

## Production integrations

These three integrations are running in production. The patterns in this repo were extracted from building them.

| Integration | Vendor API | Auth method | Pagination | Event types | Repo |
|---|---|---|---|---|---|
| wazuh-1password | 1Password Events API v2 | Bearer token | Cursor-based (POST) | Audit, sign-in, item usage | [jnthans/wazuh-1password](https://github.com/jnthans/wazuh-1password) |
| wazuh-proofpoint | Proofpoint TAP SIEM + People API | Basic auth | Time-window (GET) | Messages, clicks, VAP, top clickers | [jnthans/wazuh-proofpoint](https://github.com/jnthans/wazuh-proofpoint) |
| wazuh-cortex-xdr | Cortex XDR REST API | HMAC (API key + hash) | Offset-based (POST) | Alerts, incidents | [jnthans/wazuh-cortex-xdr](https://github.com/jnthans/wazuh-cortex-xdr) |

Each ended up with the identical four-layer architecture, the same CLI interface (`--source`, `--all`, `--lookback`, `--debug`), the same atomic state management, and zero external dependencies. The only things that differ are vendor-specific: endpoints, auth mechanisms, pagination models, and field mappings.

---

## What you can do with this repo

**Build a Wazuh integration** — Copy the [`templates/`](templates/) directory, rename files for your vendor, and fill in the vendor-specific details. The [build process docs](docs/process/) walk through each phase.

```bash
cp -r templates/ my-wazuh-vendor/
cd my-wazuh-vendor/
mv wodle/integration.py wodle/vendorname.py
mv wodle/integration_module.py wodle/vendorname_events.py
mv wodle/integration_utils.py wodle/vendorname_utils.py
```

**Feed it to an LLM** — The [`llm-references/`](llm-references/) directory contains files structured specifically for AI consumption. Attach them to a Claude or GPT session along with your vendor's API docs and prompt it to build the integration. See the next section.

**Study the patterns** — Read the [architecture docs](docs/architecture/) and [design principles](docs/architecture/design-principles.md) to understand the reasoning behind the decisions.

---

## LLM-ready references

This repo includes five files designed to be dropped into an AI assistant's context window. When paired with a vendor's API documentation, they produce integrations that follow the architecture without the human needing to enforce every convention manually.

| File | Purpose |
|---|---|
| [`SYSTEM_PROMPT.md`](llm-references/SYSTEM_PROMPT.md) | Sets the AI's role and constraints |
| [`ARCHITECTURE.md`](llm-references/ARCHITECTURE.md) | Architecture spec it must follow |
| [`CODING_STANDARDS.md`](llm-references/CODING_STANDARDS.md) | Python style and convention rules |
| [`CHECKLIST.md`](llm-references/CHECKLIST.md) | Step-by-step build process |
| [`EXAMPLES.md`](llm-references/EXAMPLES.md) | Real patterns from the three production integrations |

Attach these to your session and prompt:

> "Build a Wazuh integration for [Vendor] using the [API name]. The API uses [auth method] and returns [data format]. Here is the API documentation: [link or paste]."

The [AI prompting guide](docs/guides/ai-prompting.md) covers this workflow in detail.

---

## Repository structure

```
siem-integration-framework/
├── docs/                          # Architecture and process documentation (GitHub Pages site)
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
└── examples/                      # Links to the three production integrations
```

---

## Design principles

These principles emerged from building and operating the integrations above. Each one prevented a production incident or eliminated a class of bugs.

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

Contributions welcome:

- **Built something similar?** Open a PR to add it to the examples table
- **Found a gap?** File an issue describing what the patterns didn't cover
- **Better patterns?** PRs to templates, docs, or LLM references are all welcome

---

## License

MIT — see [LICENSE](LICENSE).
