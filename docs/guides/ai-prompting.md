# AI-Assisted Building

This guide covers how to use LLMs (Claude, GPT, Copilot, etc.) effectively throughout the integration development process. The framework includes machine-readable reference files specifically designed for AI consumption.

---

## The LLM reference files

The `llm-references/` directory contains five files designed to be fed directly into AI context:

| File | Purpose | When to use |
|---|---|---|
| `SYSTEM_PROMPT.md` | Sets the AI's role, constraints, and output expectations | Attach at session start |
| `ARCHITECTURE.md` | Complete architecture spec the AI must follow | Attach at session start |
| `CODING_STANDARDS.md` | Style rules, naming conventions, patterns | Attach at session start |
| `CHECKLIST.md` | Step-by-step process for building an integration | Attach when starting a new build |
| `EXAMPLES.md` | Condensed code patterns from real integrations | Attach when the AI needs concrete examples |

### How to use them

**Option A — Full context (recommended for new integrations)**:
Attach all five files to your AI session, then prompt with the vendor API details. The AI has everything it needs to build a complete, framework-compliant integration.

**Option B — Targeted context (for specific tasks)**:
Attach only the relevant file(s). For example, when writing rules, attach `CODING_STANDARDS.md` and `EXAMPLES.md`. When debugging, attach `ARCHITECTURE.md`.

**Option C — Paste into system/custom instructions**:
If your AI tool supports system prompts or custom instructions, paste `SYSTEM_PROMPT.md` there. It persists across messages without re-attaching.

---

## Prompting patterns that work

### Starting a new integration

**Good prompt — gives the AI everything it needs:**
```
Build a Wazuh integration for [Vendor Name] using the [API Name].

API details:
- Base URL: https://api.vendor.com/v2
- Auth: Bearer token in Authorization header
- Endpoints: /events (GET, cursor-paginated), /users (GET, offset-paginated)
- Rate limit: 100 requests/minute
- Documentation: [paste relevant sections or link]

Use rule ID range 100800-100899.
Use namespace prefix "vn".
```

**Why it works**: It provides the three things the AI cannot infer — the vendor API specifics, the rule ID range, and the namespace prefix. The framework files supply everything else.

**Bad prompt — too vague:**
```
Make a Wazuh integration for Vendor X
```

**Why it fails**: The AI has to guess the API details, auth method, and event types. It will produce generic code that needs extensive rework.

### Iterating on a specific component

```
Here is my current vendorname_utils.py: [paste file]

The vendor API returns HTTP 429 with a JSON body containing {"retry_after": 30} 
instead of the standard Retry-After header. Update the HTTP function to handle 
this while keeping the standard header support as a fallback.
```

**Why it works**: It gives the AI the current code, the specific problem, and the expected behavior. The AI can make a surgical change.

### Debugging

```
My integration events appear in Wazuh logs but no rule fires. Here is my decoder:
[paste decoder XML]

Here is my base rule:
[paste rule XML]

Here is a sample event from stdout:
[paste JSON line]

What is wrong?
```

**Why it works**: The AI has all three pieces of the pipeline (decoder → event → rule) and can trace the mismatch.

---

## Patterns that produce bad results

### Do not ask the AI to guess the API

The AI's training data may contain outdated or incorrect API documentation. Always provide:
- The current API documentation (paste relevant sections)
- A sample API response (paste one from your testing)
- The exact auth mechanism

### Do not skip the framework files

Without the framework files, the AI will produce code that "works" but does not follow the architecture. Common deviations:
- Uses `print()` instead of `emit()` and `log()`
- Writes state directly instead of atomic writes
- Mixes stdout and stderr
- Omits the credential chain
- Flattens nested JSON
- Uses `requests` library instead of stdlib

The framework files prevent all of these.

### Do not ask for everything at once without structure

**Bad**: "Build the complete integration including all files, tests, rules, decoder, README, and dashboard."

**Better**: Build in phases, validating each one:
1. "Build `vendorname_utils.py` with the credential chain, HTTP function, state management, and emit function."
2. "Now build `vendorname_events.py` using the utils. Here is the API response format: [paste]"
3. "Now build `vendorname.py` orchestrator with argparse and module calling."
4. "Now build the decoder and rules XML."
5. "Now write the README following the framework template."

### Do not let the AI invent field names

Provide the actual API response. If the AI invents field names, the rules will not match real events:

```
Here is an actual API response from the vendor:
{
  "items": [
    {
      "uuid": "abc123",
      "timestamp": "2026-03-22T10:00:00Z",
      "action": "user.login",
      "actor_details": {
        "email": "user@example.com",
        "ip": "192.168.1.1"
      }
    }
  ],
  "cursor": "eyJhbGci..."
}

Build the domain module to handle this response format.
```

---

## Phase-by-phase AI usage

### Phase 1: Planning
- **Ask the AI to**: Summarize vendor API docs, identify pagination models, map event types to severity levels, calculate rate limit budgets
- **Provide**: API documentation (paste or link)
- **Attach**: `ARCHITECTURE.md` for context on what you are planning toward

### Phase 2: Building
- **Ask the AI to**: Write each file following the templates
- **Provide**: Planning notes, API sample responses, chosen namespace prefix, rule ID range
- **Attach**: All five LLM reference files

### Phase 3: Testing
- **Ask the AI to**: Debug issues, explain error messages, suggest test scenarios
- **Provide**: Actual error output, log snippets, sample events
- **Attach**: `ARCHITECTURE.md` (data flow context helps debugging)

### Phase 4: Deploying
- **Ask the AI to**: Generate ossec.conf stanza, systemd credential configuration
- **Provide**: Deployment environment details (bare metal, Docker, Kubernetes)
- **Attach**: `CHECKLIST.md` (deployment section)

### Phase 5: Documenting
- **Ask the AI to**: Write the README, configuration reference, rules reference, and troubleshooting guide
- **Provide**: The completed code files (so the AI documents what actually exists, not what it imagines)
- **Attach**: `CODING_STANDARDS.md` (documentation section) and `EXAMPLES.md` (README structure examples)

---

## Evaluating AI output

After the AI produces code, verify against these framework requirements:

1. **No external dependencies** — does it import anything outside stdlib?
2. **Atomic state writes** — does `save_state` use tempfile + os.replace?
3. **Stdout/stderr separation** — does emit() use stdout and log() use stderr? Any print() calls?
4. **Credential chain** — does it implement all three tiers?
5. **Error isolation** — does a module failure prevent other modules from running?
6. **Namespace prefix** — are all vendor fields under the namespace key?
7. **Error events** — are failures emitted as structured events?
8. **Pagination** — does it handle all pages, not just the first?
9. **No data dropped** — does it emit all vendor fields, not just the ones it thinks are important?
10. **run.sh uses exec** — does the shell wrapper replace itself with the Python process?
