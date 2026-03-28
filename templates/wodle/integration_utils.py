#!/usr/bin/env python3
"""
{VENDOR_DISPLAY} — Shared utilities.

Provides credential loading, HTTP functions, state management,
event emission, and logging. All other modules import from here.

Replace {VENDOR}, {VENDOR_DISPLAY}, {NAMESPACE}, {INTEGRATION_NAME}
with your vendor-specific values.
"""

import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request

# ── Constants ──

INTEGRATION_NAME = "{VENDOR_LOWER}"   # e.g., "onepassword", "proofpoint"
NAMESPACE = "{NAMESPACE}"              # e.g., "op", "pp", "xdr"
DEBUG_LEVEL = 0                        # overwritten by config at startup


# ── Logging ──

def log(level, msg, *args):
    """Write diagnostic message to stderr at configurable verbosity.

    Levels: 1=info, 2=verbose, 3=trace. Level 0 messages always print.
    Arguments are only formatted if the message will be emitted.
    """
    if level <= DEBUG_LEVEL:
        text = msg.format(*args) if args else msg
        sys.stderr.write("[{}] {}\n".format(INTEGRATION_NAME, text))
        sys.stderr.flush()


# ── Event emission ──

def emit(event):
    """Write a single JSON event to stdout (one line). Wazuh reads this."""
    line = json.dumps(event, separators=(",", ":"))
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def emit_error(source, message, code=None):
    """Emit a structured error event through the normal pipeline."""
    event = {
        "integration": INTEGRATION_NAME,
        NAMESPACE: {
            "event_type": "error",
            "error_source": source,
            "error_message": str(message)[:500]  # truncate to avoid huge error events
        }
    }
    if code is not None:
        event[NAMESPACE]["error_code"] = code
    emit(event)


# ── Secrets ──

def load_secrets_file(path):
    """Parse a KEY=VALUE secrets file. Returns dict.

    - Lines starting with # are comments
    - Blank lines are ignored
    - Values may be single or double quoted
    - No subshell evaluation
    """
    secrets = {}
    if not path or not os.path.isfile(path):
        log(2, "Secrets file not found: {}", path)
        return secrets

    with open(path, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                log(2, "Secrets file line {} skipped (no =)", line_num)
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            # Strip optional quotes
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            secrets[key] = value

    log(2, "Loaded {} keys from secrets file", len(secrets))
    return secrets


def get_secret(cred_name, env_var, secrets):
    """Load a credential from the three-tier priority chain.

    Priority (first match wins):
      1. systemd credentials directory ($CREDENTIALS_DIRECTORY/{cred_name})
      2. Secrets file (secrets dict, keyed by env_var name)
      3. Environment variable ($env_var)

    Returns the credential value or raises RuntimeError if not found.
    Never logs the credential value itself.
    """
    # Tier 1: systemd credentials
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        cred_path = os.path.join(cred_dir, cred_name)
        if os.path.isfile(cred_path):
            with open(cred_path, "r") as f:
                value = f.read().strip()
            if value:
                log(2, "Credential '{}' loaded from systemd", cred_name)
                return value

    # Tier 2: secrets file
    if env_var in secrets:
        log(2, "Credential '{}' loaded from secrets file", cred_name)
        return secrets[env_var]

    # Tier 3: environment variable
    value = os.environ.get(env_var)
    if value:
        log(2, "Credential '{}' loaded from environment", cred_name)
        return value

    raise RuntimeError(
        "Credential '{}' not found in systemd credentials, secrets file, or ${}".format(
            cred_name, env_var
        )
    )


# ── State management ──

def load_state(path):
    """Load persisted state from a JSON file. Returns empty dict if missing."""
    try:
        with open(path, "r") as f:
            state = json.load(f)
        log(2, "State loaded from {}", path)
        return state
    except FileNotFoundError:
        log(1, "No state file — first run")
        return {}
    except json.JSONDecodeError as e:
        log(0, "WARNING: State file corrupt ({}). Starting fresh.", e)
        return {}


def save_state(path, state):
    """Atomically write state to a JSON file.

    Uses tempfile + os.replace() so a kill mid-write never corrupts
    the existing state file.
    """
    dir_name = os.path.dirname(path) or "."
    with tempfile.NamedTemporaryFile(
        "w", dir=dir_name, delete=False, suffix=".tmp"
    ) as tmp:
        json.dump(state, tmp, indent=2)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name
    os.replace(tmp_path, path)
    log(2, "State saved to {}", path)


# ── HTTP ──

def http_get(url, headers, timeout=30):
    """HTTP GET with error handling. Returns parsed JSON response."""
    log(3, "GET {}", url)
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            log(3, "Response: {} bytes", len(body))
            return json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError("HTTP GET {} returned {}: {}".format(url, e.code, body[:200]))


def http_post(url, headers, body, timeout=30):
    """HTTP POST with JSON body. Returns parsed JSON response."""
    log(3, "POST {}", url)
    data = json.dumps(body).encode("utf-8")
    headers = dict(headers)  # copy to avoid mutating caller's dict
    headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8")
            log(3, "Response: {} bytes", len(resp_body))
            return json.loads(resp_body)
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError("HTTP POST {} returned {}: {}".format(url, e.code, resp_body[:200]))


def http_with_retry(request_fn, max_wait=60):
    """Execute an HTTP function with automatic 429 retry.

    Reads the Retry-After header and sleeps accordingly (capped at max_wait).
    Retries once. If the retry also fails, the exception propagates.

    Usage:
        response = http_with_retry(lambda: http_get(url, headers))
    """
    try:
        return request_fn()
    except RuntimeError as e:
        error_msg = str(e)
        if "429" not in error_msg:
            raise
        log(1, "Rate limited (429). Checking retry delay...")
        # Try to extract retry-after from the error or use default
        wait = min(30, max_wait)  # default if header not parseable
        log(1, "Waiting {} seconds before retry", wait)
        time.sleep(wait)
        return request_fn()


# ── Header construction helpers ──

def bearer_auth_headers(token):
    """Build Authorization headers for Bearer token auth."""
    return {"Authorization": "Bearer {}".format(token)}


def basic_auth_headers(username, password):
    """Build Authorization headers for HTTP Basic auth."""
    import base64
    credentials = "{}:{}".format(username, password)
    encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
    return {"Authorization": "Basic {}".format(encoded)}


# Uncomment and customize if your vendor uses HMAC auth:
# def hmac_auth_headers(api_key_id, api_key, body=""):
#     """Build headers for HMAC-based authentication."""
#     import hashlib
#     import hmac as hmac_mod
#     nonce = str(int(time.time() * 1000))
#     auth_string = api_key_id + nonce + api_key
#     hash_digest = hashlib.sha256(auth_string.encode("utf-8")).hexdigest()
#     return {
#         "x-xdr-auth-id": str(api_key_id),
#         "x-xdr-nonce": nonce,
#         "Authorization": hash_digest
#     }
