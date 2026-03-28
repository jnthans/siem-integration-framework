# {VENDOR_DISPLAY} Wodle — Rules Reference

Rule ID range: **{RULE_BASE}00–{RULE_BASE}99**

---

## Rule catalog

| Rule ID | Level | Description | Matches when |
|---|---|---|---|
| {RULE_BASE}00 | 0 | Base rule (no alert) | Any {VENDOR_LOWER} integration event |
| {RULE_BASE}01 | 3 | Event type A | `{NAMESPACE}.event_type` = `event_type_a` |
| {RULE_BASE}02 | 3 | Sign-in attempt | `{NAMESPACE}.event_type` = `signin` |
| {RULE_BASE}50 | 7 | Failed sign-in | `{NAMESPACE}.outcome` = `failure` |
| {RULE_BASE}90 | 8 | Integration error | `{NAMESPACE}.event_type` = `error` |

---

## Field reference

| Rule field | OpenSearch path | Example value |
|---|---|---|
| `integration` | `data.integration` | `{VENDOR_LOWER}` |
| `{NAMESPACE}.event_type` | `data.{NAMESPACE}.event_type` | `signin` |
| `{NAMESPACE}.actor.email` | `data.{NAMESPACE}.actor.email` | `user@example.com` |
| `{NAMESPACE}.outcome` | `data.{NAMESPACE}.outcome` | `success` |
| `{NAMESPACE}.error_message` | `data.{NAMESPACE}.error_message` | `HTTP 401: invalid credentials` |

---

## Severity rationale

| Level | Used for | Rationale |
|---|---|---|
| 0 | Base rule | Parent only — no alert generated |
| 3 | Routine events | Informational, normal operations |
| 5 | Notable events | Unusual but not necessarily malicious |
| 7 | Failures | Requires investigation |
| 8 | Integration errors | Pipeline health — must not go unnoticed |

---

## Groups

| Group | Applied to | Purpose |
|---|---|---|
| `{VENDOR_LOWER}` | All rules | Integration-level filtering |
| `authentication` | Sign-in events | Cross-integration auth correlation |
| `authentication_failure` | Failed sign-ins | Failed auth monitoring |
| `integration_error` | Error events | Integration health alerting |
