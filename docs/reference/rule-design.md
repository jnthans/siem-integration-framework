# Rule Design

Wazuh rules are the classification layer — they decide what matters, how much it matters, and how it is grouped. This reference covers the patterns used across all framework integrations.

---

## Decoder pattern

Every integration uses the same two-decoder pattern:

```xml
<!-- Match on program name (the run.sh script name in wodle output) -->
<decoder name="vendorname">
  <program_name>run.sh</program_name>
</decoder>

<!-- Activate JSON decoding for matched events -->
<decoder name="vendorname_json">
  <parent>vendorname</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

The `program_name` match identifies events from this integration. The child decoder activates Wazuh's built-in JSON parser, which automatically extracts all JSON fields and makes them available as `data.*` in OpenSearch and as direct field references in rules.

---

## Rule hierarchy

Rules follow a strict parent-child hierarchy:

```
Level 0: Base rule (decoded_as + integration match)
  └── Level 3-5: Event type rules (event_type match)
        └── Level 6-8: Conditional rules (specific field values)
              └── Level 9-12: Composite rules (multiple conditions)
```

### Base rule (level 0)

```xml
<rule id="100800" level="0">
  <decoded_as>vendorname</decoded_as>
  <field name="integration">vendorname</field>
  <description>Vendor integration base rule.</description>
  <group>vendorname,</group>
</rule>
```

Level 0 means no alert is generated. This rule exists only as a parent — all subsequent rules use `<if_sid>100800</if_sid>` to chain from it. The `decoded_as` and `integration` field double-match ensures only events from this specific integration trigger the rule tree.

### Event type rules (level 3-7)

```xml
<rule id="100801" level="3">
  <if_sid>100800</if_sid>
  <field name="vn.event_type">signin</field>
  <description>Vendor: sign-in attempt by $(vn.actor.email).</description>
  <group>vendorname,authentication,</group>
</rule>
```

One rule per event type. Severity reflects the baseline importance of the event type. Use field interpolation in descriptions with `$(field.path)` syntax.

### Conditional rules (level 6-10)

```xml
<rule id="100805" level="7">
  <if_sid>100801</if_sid>
  <field name="vn.outcome">failure</field>
  <description>Vendor: failed sign-in by $(vn.actor.email) from $(vn.client.ip).</description>
  <group>vendorname,authentication_failure,</group>
</rule>
```

These chain from event type rules and elevate severity based on specific conditions (failures, high-risk actions, anomalous behavior).

### Error rules (level 8-10)

```xml
<rule id="100890" level="8">
  <if_sid>100800</if_sid>
  <field name="vn.event_type">error</field>
  <description>Vendor integration error: $(vn.error_message).</description>
  <group>vendorname,integration_error,</group>
</rule>
```

Always at elevated severity. Integration failures should never go unnoticed — an operator needs to know when the data pipeline is broken.

---

## Severity guidelines

| Level | Category | Use for | Example |
|---|---|---|---|
| 0 | Silent | Base rules (parent only, no alert) | Integration base match |
| 2-3 | Informational | Successful routine operations | Successful sign-in, item read |
| 4-5 | Notable | Unusual but not malicious activity | New device, unusual location |
| 6-7 | Suspicious | Failed operations, policy violations | Failed auth, permission denied |
| 8-10 | Critical | Confirmed threats, integration errors | Blocked attack, API error |
| 12+ | Emergency | Composite correlation rules | Multiple failed auths + successful auth |

### Severity assignment principles

- **Default low, elevate on conditions** — start event types at level 3, add conditional child rules at higher levels
- **Errors are always high** — an operator ignoring integration errors leads to blind spots
- **Match vendor severity when possible** — if the vendor API includes a severity field, align your rule levels with it
- **Do not over-alert** — level 7+ generates alerts that need investigation. Routine operations at level 7 create alert fatigue.

---

## Rule ID allocation

### Convention
Reserve a 100-ID block per integration starting at 100000:
- 100500–100599: Cortex XDR
- 100600–100699: Proofpoint
- 100700–100799: 1Password

### Within the block
| Range | Purpose |
|---|---|
| xx00 | Base rule |
| xx01–xx49 | Event type rules (primary classification) |
| xx50–xx79 | Conditional rules (elevated severity) |
| xx80–xx89 | Reserved for future use |
| xx90–xx99 | Error and health rules |

---

## Group conventions

Groups enable dashboard filtering and cross-integration correlation.

### Standard groups
- `{vendorname},` — applied to every rule (base group)
- `authentication,` — sign-in events, login attempts
- `authentication_failure,` — failed authentication
- `{vendorname}_admin,` — administrative/audit actions
- `integration_error,` — integration health events

### MITRE ATT&CK groups
When event types map to MITRE tactics, add tactic groups:
```xml
<group>vendorname,authentication,mitre_initial_access,</group>
```

---

## Field reference conventions

In rules, fields are referenced by their JSON path relative to the emitted event. In OpenSearch, they appear under `data.*`.

| Rule reference | OpenSearch path | Example value |
|---|---|---|
| `vn.event_type` | `data.vn.event_type` | `signin` |
| `vn.actor.email` | `data.vn.actor.email` | `user@example.com` |
| `vn.outcome` | `data.vn.outcome` | `failure` |
| `integration` | `data.integration` | `vendorname` |

### Description interpolation
Use `$(field.path)` in rule descriptions to include event-specific values:
```xml
<description>Vendor: $(vn.action) by $(vn.actor.email) on $(vn.target.name).</description>
```

This makes alerts immediately actionable — the operator sees what happened, who did it, and what was affected without opening the full event.

---

## Testing rules

### wazuh-logtest
```bash
/var/ossec/bin/wazuh-logtest
```
Paste a raw JSON event line. The tool shows which decoder matched and which rules fired, including the full chain from base rule to final match.

### Verify field extraction
In wazuh-logtest output, check that all fields you reference in rules are present in the decoded output. If a field is missing, the rule will not match — even if the JSON contains the field.

### Common rule issues
- **Decoder name mismatch**: `<decoded_as>` in the rule must exactly match `<decoder name="">` in the decoder file
- **Field path wrong**: JSON path in `<field name="">` must match the emitted JSON structure, not the OpenSearch path
- **Missing trailing comma in groups**: Wazuh group syntax requires a trailing comma: `<group>vendorname,authentication,</group>`
- **Parent rule not found**: `<if_sid>` references a rule ID that does not exist or is in a file loaded after this one
