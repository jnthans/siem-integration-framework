# Security Checklist

Review every item before releasing an integration. This checklist is derived from security issues encountered (or proactively avoided) across production deployments.

---

## Credential security

- [ ] Credentials are loaded via the three-tier priority chain (systemd > secrets file > env vars)
- [ ] Credential values are never written to logs at any debug level
- [ ] Credential values are never included in error events or error messages
- [ ] The secrets file template (`.secrets.example`) contains placeholder values, not real credentials
- [ ] The `.gitignore` excludes `.secrets`, `state.json`, and any file that could contain credentials
- [ ] Documentation specifies `chmod 640` and `chown root:wazuh` for the secrets file
- [ ] If multi-tenant tokens file exists, it has the same permission requirements documented

## Input validation

- [ ] API responses are validated before processing (check for expected keys, handle missing fields)
- [ ] Cursor/bookmark values from state files are treated as opaque — never interpolated into shell commands or SQL
- [ ] JSON parsing uses `json.loads()` with no custom deserialization hooks
- [ ] URL construction uses string formatting, not user-controlled input concatenation
- [ ] No `eval()`, `exec()`, or `subprocess` calls on data derived from API responses

## Output safety

- [ ] Events go to stdout only via `emit()` — no `print()` anywhere
- [ ] Diagnostics go to stderr only via `log()` — no stdout contamination
- [ ] Error messages describe the problem without including sensitive data (API keys, tokens, full URLs with query parameters containing secrets)
- [ ] Stack traces are caught and summarized — not passed raw to stdout
- [ ] JSON output uses `json.dumps()` with default serialization — no custom encoders that could leak internal state

## State file security

- [ ] State file path is configurable (not hardcoded to a world-writable location)
- [ ] State file contains only cursors/timestamps — no cached credentials or event data
- [ ] Atomic write pattern prevents state corruption on crash
- [ ] State file permissions are documented (`chmod 640`, writable by wazuh user)

## Network security

- [ ] All API connections use HTTPS (never HTTP)
- [ ] TLS certificate verification is enabled (no `ssl._create_unverified_context()`)
- [ ] Connection timeouts are set (prevent indefinite hangs)
- [ ] Read timeouts are set (prevent slow-loris style resource exhaustion)
- [ ] No proxy configuration is hardcoded — uses system proxy settings if needed

## Dependency security

- [ ] Zero external Python dependencies — stdlib only
- [ ] No vendored third-party code copied into the integration
- [ ] No `pip install` commands in installation docs
- [ ] No `requirements.txt` or `setup.py` that would imply external dependencies

## File system security

- [ ] All file operations use the configured paths (state file, secrets file) — no temporary files in `/tmp` (use the wodle directory)
- [ ] `tempfile.NamedTemporaryFile` is created in the same directory as the target file (ensures same filesystem for atomic rename)
- [ ] No files are created with world-readable permissions
- [ ] The wodle directory is owned by `root:wazuh` with appropriate permissions

## Process security

- [ ] `run.sh` uses `exec` to replace the shell with Python (no lingering shell process)
- [ ] `run.sh` uses `set -euo pipefail` (fail fast)
- [ ] The Python process runs as the `wazuh` user, not root
- [ ] No SUID/SGID bits on any files
- [ ] Process does not spawn child processes or shell commands based on API data

## Documentation security

- [ ] Installation docs do not instruct users to disable SELinux or firewall rules beyond the specific API endpoint
- [ ] No real credentials, API keys, or tokens appear anywhere in documentation (use obviously fake placeholders)
- [ ] Troubleshooting docs do not suggest running the integration as root for debugging
- [ ] Multi-tenant docs emphasize credential isolation between tenants

## Rule security

- [ ] Rules do not expose sensitive field values in alert descriptions (e.g., do not interpolate API keys or full session tokens)
- [ ] Error rules fire at elevated severity to ensure integration failures are noticed
- [ ] Rule IDs are in the reserved custom range (100000+) — no collisions with Wazuh built-in rules
