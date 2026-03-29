# Production integrations

These three Wazuh integrations are running in production. The patterns in this repo were extracted from building them.

| Integration | Vendor API | Auth method | Pagination | Event types | Repo |
|---|---|---|---|---|---|
| wazuh-1password | 1Password Events API v2 | Bearer token | Cursor-based (POST) | Audit, sign-in, item usage | [jnthans/wazuh-1password](https://github.com/jnthans/wazuh-1password) |
| wazuh-proofpoint | Proofpoint TAP SIEM + People | Basic auth | Time-window (GET) | Messages, clicks, VAP, top clickers | [jnthans/wazuh-proofpoint](https://github.com/jnthans/wazuh-proofpoint) |
| wazuh-cortex-xdr | Cortex XDR REST API | HMAC (API key + hash) | Offset-based (POST) | Alerts, incidents | [jnthans/wazuh-cortex-xdr](https://github.com/jnthans/wazuh-cortex-xdr) |

## What is the same across all three

Each integration ended up with the identical architecture:

- **Four-layer design**: `run.sh` → `{vendor}.py` → `{vendor}_{module}.py` → `{vendor}_utils.py`
- **Same repo layout**: `wodle/`, `rules/`, `artifacts/` with identical subdirectory structure
- **Same credential chain**: systemd > `.secrets` > env vars
- **Same state management**: atomic writes via `tempfile` + `os.replace`
- **Same CLI interface**: `--source`, `--all`, `--lookback`, `--debug`
- **Same documentation**: README + three standard guides
- **Zero external deps**: stdlib Python only

The only things that differ are the vendor-specific details: API endpoints, auth mechanisms, pagination models, event types, and field mappings.

## Adding your integration

Built something similar? Open a PR to add it to this table.
