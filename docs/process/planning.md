# Phase 1: Planning

Planning is the most important phase. A well-researched plan prevents rework during building. Expect to spend 30-40% of total project time here.

---

## Step 1: Research the vendor API

Read the vendor's API documentation end to end before writing any code. You are looking for:

### Authentication method
- **Bearer token** (1Password) — simplest. Token in Authorization header.
- **Basic auth** (Proofpoint) — principal:secret, base64-encoded.
- **API key + ID with HMAC** (Cortex XDR) — most complex. Requires hash computation per request.
- **OAuth 2.0** — requires token refresh flow. Less common in SIEM-facing APIs.

Document the exact auth mechanism and note any header construction requirements.

### Available endpoints
List every endpoint you plan to use. For each one, record:
- HTTP method (GET vs POST)
- Base URL and path
- Required vs optional parameters
- Response format (JSON structure, field names, nesting)
- Rate limits (requests per minute/hour/day)
- Data retention period (how far back can you query?)

### Pagination model
This is critical — get it wrong and you will either miss events or duplicate them.
- **Cursor-based** — API returns an opaque token. You send it back to get the next page. Preferred model — no edge cases.
- **Time-window** — You specify `sinceTime`/`untilTime`. Requires chunking logic for gaps. Watch for off-by-one at boundaries.
- **Offset-based** — `offset=0, limit=100`, then `offset=100`. Fragile if events are inserted between pages.

### Event types and fields
For each event type the API returns:
- What is the event type identifier? (field name and values)
- What fields does each event contain?
- Which fields are always present vs optional?
- Are there nested objects? What do they contain?
- Are there fields that overlap with SIEM reserved names?

### Rate limits and quotas
- Requests per minute/hour/day per endpoint
- Burst limits vs sustained limits
- What happens when you hit the limit? (429 with Retry-After? 403? Queuing?)
- Calculate your budget: at a 5-minute polling interval, how many requests per day?

---

## Step 2: Map event types to rule families

Create a table mapping each vendor event type to a Wazuh rule family:

| Vendor event type | Rule family | Base severity | MITRE tactic (if applicable) |
|---|---|---|---|
| `signin_attempt` | Authentication | 3-7 (by outcome) | Initial Access |
| `item_usage` | Data Access | 3-5 | Collection |
| `audit_action` | Admin Activity | 3-8 (by action) | — |
| `error` | Integration Health | 8-10 | — |

This mapping drives rule design in Phase 2. Getting it right now prevents rule rewrites later.

### Severity guidelines

| Wazuh level | Meaning | Use for |
|---|---|---|
| 2-3 | Low / informational | Successful routine operations (logins, reads) |
| 4-5 | Medium / notable | Unusual but not necessarily malicious activity |
| 6-7 | High / suspicious | Failed auth, policy violations, anomalous access |
| 8-10 | Critical / actionable | Confirmed threats, integration errors, blocked attacks |
| 12+ | Emergency | Reserved for correlation rules or extremely high-confidence threats |

---

## Step 3: Reserve rule ID range

Every integration needs a dedicated, non-overlapping rule ID range. Wazuh's built-in rules use IDs below 100000. Custom integrations use 100000+.

**Convention from our integrations**:
- Cortex XDR: 100500–100599
- Proofpoint: 100600–100699
- 1Password: 100700–100799

Reserve a 100-ID block for your integration. Within that block:
- First ID (xx00): Base rule — matches on `decoded_as` and `integration` field
- Error rules: xx90–xx99
- Event type rules: grouped logically in between

Document your reservation in the integration's rules reference guide.

---

## Step 4: Choose the namespace prefix

Pick a 2-4 character prefix for the vendor namespace. Requirements:
- Short (it will appear in every rule and every OpenSearch query)
- Unique (must not conflict with other integrations in the same deployment)
- Recognizable (someone reading `pp.senderIP` should know it means Proofpoint)

**Examples from our integrations**:
- `op` — 1Password (from "OnePassword")
- `pp` — Proofpoint
- `xdr` — Cortex XDR

Avoid generic prefixes like `api`, `evt`, `src`, or `int` — they will collide.

---

## Step 5: Design the module split

Based on the API surface you documented in Step 1, decide how many domain modules you need:

- **One module**: API has one endpoint or multiple endpoints with identical auth, pagination, and response format
- **Two modules**: API has distinct surfaces (e.g., SIEM API vs People API) with different rate limits, schedules, or data models
- **Three+ modules**: Rare. Justify each additional module.

Name each module: `{vendor}_{surface}.py` (e.g., `proofpoint_siem.py`, `proofpoint_people.py`)

---

## Step 6: Document the plan

Before writing code, create a brief plan document (even just notes) covering:

1. Vendor API: endpoints, auth method, pagination model
2. Event types: what you will ingest, mapped to rule families
3. Rule ID range: your reserved block
4. Namespace prefix: your chosen prefix
5. Module split: which modules and what each covers
6. Rate limit budget: requests per interval, headroom calculation
7. Known constraints: API quirks, data retention limits, known issues

This document becomes the input for Phase 2 and is invaluable context when prompting an AI assistant.

---

## Planning checklist

- [ ] Read vendor API documentation end to end
- [ ] Document authentication method and header construction
- [ ] List all endpoints with method, parameters, and response format
- [ ] Identify pagination model (cursor, time-window, offset)
- [ ] Map every event type to fields, severity, and rule family
- [ ] Calculate rate limit budget at target polling interval
- [ ] Reserve a 100-ID rule block
- [ ] Choose namespace prefix
- [ ] Decide module split
- [ ] Write planning notes document
