# SIEM Integration Framework

An open-source framework for building secure, reliable, and efficient SIEM integrations.

Built from patterns proven in production across 1Password, Proofpoint TAP, and Cortex XDR integrations for Wazuh SIEM. Designed so humans and AI models alike can build new integrations faster and with fewer mistakes.

---

## Documentation

### Architecture
- [Overview](architecture/overview.md) — The universal integration architecture and its components
- [Data flow](architecture/data-flow.md) — How events move from vendor API to SIEM dashboard
- [Design principles](architecture/design-principles.md) — The non-negotiable constraints behind every decision

### Build process
- [Phase 1: Planning](process/planning.md) — API research, event mapping, rule ID reservation
- [Phase 2: Building](process/building.md) — Implementing the integration
- [Phase 3: Testing](process/testing.md) — Validation, debugging, edge cases
- [Phase 4: Deploying](process/deploying.md) — Installation and production rollout
- [Phase 5: Documenting](process/documenting.md) — The three standard guides and README

### Guides
- [AI-assisted building](guides/ai-prompting.md) — How to use LLMs effectively throughout the process
- [Adapting to other SIEMs](guides/adapting-to-other-siems.md) — Splunk, Sentinel, Elastic, QRadar
- [Security checklist](guides/security-checklist.md) — Pre-release security review

### Reference
- [Repository structure](reference/repo-structure.md) — Standard layout every integration follows
- [Coding conventions](reference/coding-conventions.md) — Python style, naming, error handling
- [Rule design](reference/rule-design.md) — Decoder and rule patterns for Wazuh

---

## Quick links

- [GitHub repo](https://github.com/jnthans/siem-integration-framework) — Templates, LLM references, and source
- [LLM reference files](https://github.com/jnthans/siem-integration-framework/tree/main/llm-references) — Machine-readable blueprints for AI-assisted development
- [Templates](https://github.com/jnthans/siem-integration-framework/tree/main/templates) — Scaffold files to copy and customize
