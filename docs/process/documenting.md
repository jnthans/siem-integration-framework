# Phase 5: Documenting

Every integration ships with four documents: a README and three reference guides. This consistency is intentional — operators who have used one integration know exactly where to find information in the next.

---

## Document 1: README.md

The README is the landing page. It answers: what is this, what does it do, how do I install it, and where do I find more detail?

### Standard README sections

1. **Title and one-line description** — what the integration does
2. **Dashboard screenshots** — visual proof it works (builds confidence before installation)
3. **Features list** — bullet points of key capabilities
4. **Installation steps** — numbered, copy-paste ready
5. **Repository structure** — tree view with one-line descriptions per file
6. **How it works** — ASCII flow diagram showing the data path
7. **Requirements** — Wazuh version, Python version, network access, vendor prerequisites
8. **Reference docs** — links to the three guides

### Style conventions

- Installation steps are numbered and assume zero prior knowledge of the integration
- Every command is copy-paste ready (includes `sudo`, full paths, etc.)
- The "How it works" ASCII diagram follows the actual execution flow from ossec.conf through to OpenSearch
- Requirements list the minimum supported versions, not the versions you happened to test on

---

## Document 2: Configuration reference (`artifacts/guides/configuration.md`)

Comprehensive reference for every knob the operator can turn. This is not a tutorial — it is a reference card.

### Standard sections

1. **Credential variables** — table of credential-related env vars
2. **Credential priority chain** — explanation of the three-tier chain with descriptions of each tier
3. **API/feature settings** — table of env vars that control behavior (endpoints, modes, lookback, intervals)
4. **State file** — path, format (JSON example), atomic write explanation, reset instructions
5. **CLI flags** — table of all flags with descriptions
6. **Test commands** — copy-paste examples for common testing scenarios
7. **Multi-tenant setup** — instructions for MSP/MSSP deployments (if applicable)
8. **Rate limit budget** — table showing API limits, default usage, and headroom percentage

### Table format

Use consistent table format for all variables:

| Variable | Default | Description |
|---|---|---|
| `VN_API_KEY` | *(required)* | Vendor API key. Set via `.secrets` (recommended) or env var. |
| `VN_DEBUG` | `0` | Debug verbosity: 0=off, 1=info, 2=verbose, 3=trace. |

---

## Document 3: Rules reference (`artifacts/guides/rules-reference.md`)

Maps every rule ID to its purpose. This is the document operators consult when they see a rule fire and need to understand what it means.

### Standard sections

1. **Rule ID ranges** — which IDs belong to which event family
2. **Rule catalog** — table with ID, level, description, and triggering condition for every rule
3. **Field reference** — table mapping namespace fields to their OpenSearch paths and example values
4. **Severity rationale** — why each event type has its assigned severity level
5. **Groups** — what Wazuh groups are assigned and what they mean
6. **MITRE ATT&CK mapping** (if applicable) — which tactics/techniques are tagged

### Rule catalog format

| Rule ID | Level | Description | Matches when |
|---|---|---|---|
| 100800 | 0 | Base rule (no alert) | Any vendorname event |
| 100801 | 3 | Sign-in attempt | `vn.event_type` = `signin` |
| 100802 | 7 | Failed sign-in | `vn.event_type` = `signin` AND `vn.outcome` = `failure` |
| 100890 | 8 | Integration error | `vn.event_type` = `error` |

---

## Document 4: Troubleshooting (`artifacts/guides/troubleshooting.md`)

Problem-solution pairs for every issue an operator is likely to encounter. Written as a reference, not a narrative.

### Standard sections

1. **Quick diagnostics** — commands to check if the integration is running and producing events
2. **Common problems** — table of symptom → cause → fix
3. **Test commands** — standalone execution examples for debugging
4. **State management** — how to reset state, force backfill, inspect cursor positions
5. **Log locations** — where to find wodle output, Wazuh manager logs, OpenSearch errors
6. **Getting help** — how to file an issue, what information to include

### Problem table format

| Symptom | Cause | Fix |
|---|---|---|
| No events in dashboard | Decoder not matching | Verify `program_name` matches `run.sh` path |
| `Permission denied` in logs | Wrong file ownership | `chown root:wazuh`, `chmod 640/750` |
| Events appear but wrong rule | Field name mismatch | Check namespace prefix in rules vs emitted JSON |

---

## Documentation checklist

- [ ] README has dashboard screenshots
- [ ] README installation steps are copy-paste ready
- [ ] README includes ASCII flow diagram
- [ ] Configuration reference covers every env var and CLI flag
- [ ] Configuration reference includes credential chain explanation
- [ ] Configuration reference has test command examples
- [ ] Rules reference has a row for every rule ID
- [ ] Rules reference includes field reference table
- [ ] Troubleshooting covers the 10 most common issues
- [ ] Troubleshooting includes state reset instructions
- [ ] All four documents follow the standard section ordering
