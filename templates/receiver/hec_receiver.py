#!/usr/bin/env python3
"""
HEC Receiver — push-based ingestion endpoint for the SIEM Integration Framework.

A long-running, Splunk-HEC-compatible HTTP receiver. Push sources (HEC
senders, log shippers, vendor webhook forwarders) POST event batches here;
the receiver validates the token, transforms each HEC envelope into the
framework's namespaced JSON format, and appends it to a spool file that
Wazuh tails via <localfile> with log_format json.

Unlike the wodle templates, this file is concrete and runnable as-is —
no {VENDOR} placeholders.

Security model: binds loopback only (127.0.0.1) by default. TLS, WAF,
rate limiting, and pre-origin auth are the edge layer's job (Cloudflare
Tunnel, Tailscale serve/funnel — see docs/guides/push-ingestion.md).
Never bind a public interface with this server.

Endpoints:
  POST /services/collector             HEC event batches
  POST /services/collector/event       (and /event/1.0 — same handler)
  GET  /services/collector/health      {"text":"HEC is healthy","code":17}

Auth: "Authorization: Splunk <token>" or "Authorization: Bearer <token>".
Each token maps to a source name and namespace, so a single receiver can
serve multiple senders with per-source revocation.

Configuration (environment variables, CLI flags override):
  HECR_BIND_ADDR          default 127.0.0.1 (keep loopback)
  HECR_PORT               default 8088
  HECR_SPOOL_FILE         default /var/ossec/logs/hec/spool.jsonl
  HECR_SPOOL_MAX_BYTES    default 52428800 (50 MB) — rotate above this
  HECR_SPOOL_QUOTA_BYTES  default 209715200 (200 MB) — 503 above this
  HECR_MAX_BODY_BYTES     default 1048576 (1 MB) — 413 above this
  HECR_SECRETS_FILE       default .secrets next to this script
  HECR_DEBUG              default 0 (0-3, stderr only)

Tokens come from the three-tier credential chain (systemd credentials >
secrets file > environment) under the key HEC_TOKENS, formatted as
comma-separated <token>:<source>:<namespace> triplets — see
.secrets.example.
"""

import argparse
import json
import hmac
import os
import sys
import threading
import time
import urllib.parse
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── Constants ──

INTEGRATION_NAME = "hec_receiver"
NAMESPACE = "hecr"                     # namespace for the receiver's own events
DEBUG_LEVEL = 0                        # overwritten by config at startup

DEFAULT_PORT = 8088
DEFAULT_BIND = "127.0.0.1"
DEFAULT_SPOOL_FILE = "/var/ossec/logs/hec/spool.jsonl"
DEFAULT_SPOOL_MAX_BYTES = 50 * 1024 * 1024
DEFAULT_SPOOL_QUOTA_BYTES = 200 * 1024 * 1024
DEFAULT_MAX_BODY_BYTES = 1 * 1024 * 1024

CONFIG = {}                            # populated by main() before serving


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


# ── Secrets (same three-tier chain as the wodle templates) ──

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

    # Expected permissions: 640 (root:wazuh) or stricter. Group read is
    # required for the wazuh user; anything looser leaks tokens.
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o004 or mode & 0o022:
        log(
            0,
            "WARNING: Secrets file {} has loose permissions ({:03o}) — "
            "world-readable or group/world-writable. Run: chmod 640 {} && chown root:wazuh {}",
            path, mode, path, path,
        )

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
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        cred_path = os.path.join(cred_dir, cred_name)
        if os.path.isfile(cred_path):
            with open(cred_path, "r") as f:
                value = f.read().strip()
            if value:
                log(2, "Credential '{}' loaded from systemd", cred_name)
                return value

    if env_var in secrets:
        log(2, "Credential '{}' loaded from secrets file", cred_name)
        return secrets[env_var]

    value = os.environ.get(env_var)
    if value:
        log(2, "Credential '{}' loaded from environment", cred_name)
        return value

    raise RuntimeError(
        "Credential '{}' not found in systemd credentials, secrets file, or ${}".format(
            cred_name, env_var
        )
    )


def parse_token_map(raw):
    """Parse the HEC_TOKENS value into {token: {"source":..., "namespace":...}}.

    Format: comma-separated <token>:<source>:<namespace> triplets, e.g.
      f2a4...:firewall:fw,9c81...:m365:m365

    Each token maps to one source name (becomes the "integration" field)
    and one namespace (the vendor prefix key). Revoke a source by removing
    its triplet and restarting the receiver.
    """
    tokens = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(":")
        if len(parts) != 3 or not all(p.strip() for p in parts):
            log(0, "WARNING: Skipping malformed HEC_TOKENS entry (want token:source:namespace)")
            continue
        token, source, namespace = (p.strip() for p in parts)
        tokens[token] = {"source": source, "namespace": namespace}
    return tokens


# ── Spool file ──
#
# The spool is the durability boundary: once a batch is written here and
# acknowledged with 200, Wazuh picks it up via <localfile log_format=json>.
# Writes are serialized with a lock (ThreadingHTTPServer handles each
# connection on its own thread) and the file is opened line-buffered so
# every line is pushed to the OS on write.

_spool_lock = threading.Lock()
_quota_lock = threading.Lock()         # guards the over_quota flag only
_spool = {"fh": None, "over_quota": False}


def _spool_size(path):
    try:
        return os.path.getsize(path)
    except FileNotFoundError:
        return 0


def _rotate_if_needed():
    """Rotate spool -> spool.1 when the active file exceeds the max size.

    Keeps one rotated file; a rotation overwrites the previous spool.1.
    Wazuh tails the live file and follows the truncation, so events in a
    rotated file have already been read under normal operation. Worst-case
    disk use is ~2x HECR_SPOOL_MAX_BYTES, which the quota should exceed.

    Caller must hold _spool_lock.
    """
    path = CONFIG["spool_file"]
    if _spool_size(path) < CONFIG["spool_max_bytes"]:
        return
    if _spool["fh"] is not None:
        _spool["fh"].close()
        _spool["fh"] = None
    os.replace(path, path + ".1")
    log(1, "Spool rotated: {} -> {}.1", path, path)


def spool_append(events):
    """Append framework events to the spool as JSON lines.

    Raises OSError on write failure — callers translate that into an HTTP
    500 so the sender knows the batch was not durably accepted.
    """
    with _spool_lock:
        _rotate_if_needed()
        if _spool["fh"] is None:
            _spool["fh"] = open(CONFIG["spool_file"], "a", buffering=1)
        for event in events:
            _spool["fh"].write(json.dumps(event, separators=(",", ":")) + "\n")


def spool_over_quota():
    """Check the disk quota (live + rotated spool). Returns True when over.

    Emits a one-shot quota_exceeded event on the transition into the over-
    quota state so the SIEM sees the backpressure begin, without spamming
    an event per rejected request. The transition event is written outside
    _quota_lock because spool_append() takes _spool_lock (non-reentrant).
    """
    path = CONFIG["spool_file"]
    total = _spool_size(path) + _spool_size(path + ".1")
    over = total >= CONFIG["spool_quota_bytes"]

    transition_event = None
    with _quota_lock:
        if over and not _spool["over_quota"]:
            _spool["over_quota"] = True
            log(0, "Spool quota exceeded ({} of {} bytes) — rejecting with 503",
                total, CONFIG["spool_quota_bytes"])
            transition_event = receiver_event("quota_exceeded", spool_bytes=total,
                                              quota_bytes=CONFIG["spool_quota_bytes"])
        elif not over and _spool["over_quota"]:
            _spool["over_quota"] = False
            log(0, "Spool back under quota — accepting again")

    if transition_event is not None:
        try:
            spool_append([transition_event])
        except OSError as e:
            log(0, "Could not spool quota_exceeded event: {}", e)
    return over


# ── Event construction ──

def receiver_event(event_type, **fields):
    """Build one of the receiver's own structured events (auth failures,
    malformed batches, spool errors, lifecycle). These flow through the
    same spool -> decoder -> rules pipeline as sender data, so the SIEM
    can alert on receiver health."""
    data = dict(fields)
    data["event_type"] = event_type
    return {"integration": INTEGRATION_NAME, NAMESPACE: data}


def transform_envelope(envelope, source, namespace):
    """Transform one HEC envelope into the framework event format.

    {"event": {...}, "host": "h", "source": "s", "sourcetype": "st", "time": 1720...}
      -> {"integration": "<source>", "<namespace>": {<event fields>,
          "hec_host": "h", "hec_source": "s", "hec_sourcetype": "st", "hec_time": 1720...}}

    HEC metadata is preserved under hec_-prefixed keys so it can never
    collide with vendor payload fields. A non-object event (HEC allows raw
    strings) is wrapped as {"message": ...}. All payload fields are
    preserved — filtering happens in rules, not here.
    """
    payload = envelope.get("event")
    if isinstance(payload, dict):
        data = dict(payload)
    elif payload is None:
        data = {}
    else:
        data = {"message": payload}

    for meta in ("host", "source", "sourcetype", "time", "fields"):
        if meta in envelope:
            data["hec_" + meta] = envelope[meta]

    if "event_type" not in data:
        data["event_type"] = envelope.get("sourcetype") or "hec_event"

    return {"integration": source, namespace: data}


def parse_hec_batch(text):
    """Parse a HEC batch body into a list of envelope dicts.

    HEC batches are CONCATENATED JSON objects — {"event":...}{"event":...}
    — not a JSON array, so json.loads() on the whole body fails for any
    batch of more than one event. Loop raw_decode() instead, skipping
    whitespace between objects.

    Raises ValueError (or its subclass json.JSONDecodeError) on malformed
    input.
    """
    decoder = json.JSONDecoder()
    envelopes = []
    idx = 0
    length = len(text)
    while idx < length:
        while idx < length and text[idx] in " \t\r\n":
            idx += 1
        if idx >= length:
            break
        obj, idx = decoder.raw_decode(text, idx)
        if not isinstance(obj, dict):
            raise ValueError("batch item {} is not a JSON object".format(len(envelopes)))
        envelopes.append(obj)
    return envelopes


def gunzip_capped(data, max_bytes):
    """Decompress a gzip body with an output cap (gzip-bomb guard).

    Raises ValueError if the decompressed size exceeds max_bytes;
    zlib.error propagates for corrupt input.
    """
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = decompressor.decompress(data, max_bytes + 1)
    if len(out) > max_bytes or decompressor.unconsumed_tail:
        raise ValueError("decompressed body exceeds {} bytes".format(max_bytes))
    return out


# ── HTTP handler ──
#
# http.server carries a stdlib warning against production use on untrusted
# networks. It is acceptable here ONLY because the server binds loopback
# and every request first traverses a hardened edge (Cloudflare Tunnel or
# Tailscale) that terminates TLS and enforces access policy. See
# docs/guides/push-ingestion.md for the reasoning and high-volume
# alternatives (Vector / Fluent Bit native HEC sources).

class HecReceiverHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"      # keep-alive for batching senders
    timeout = 30                       # per-connection socket timeout (slow-sender guard)
    server_version = "hec-receiver/1.0"
    sys_version = ""                   # do not advertise the Python version

    # -- plumbing --

    def log_message(self, fmt, *args):
        # Route http.server's access/error lines through the framework
        # log() pattern instead of raw stderr writes.
        log(2, "{} {}", self.client_address[0], fmt % args)

    def _respond(self, status, payload, close=False):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def _client_ip(self):
        # Behind Cloudflare Tunnel / a reverse proxy the TCP peer is
        # always 127.0.0.1; the edge supplies the real client address.
        # These headers are only trustworthy when an edge sets them —
        # which is the only supported deployment.
        for header in ("CF-Connecting-IP", "X-Forwarded-For"):
            value = self.headers.get(header)
            if value:
                return value.split(",")[0].strip()
        return self.client_address[0]

    def _authorize(self):
        """Validate the Authorization header against the token map.

        Returns the token's {"source":..., "namespace":...} mapping, or
        None after sending the error response and spooling an auth_failure
        event. Accepts both "Splunk <token>" and "Bearer <token>" schemes.
        """
        header = self.headers.get("Authorization", "")
        token = None
        for scheme in ("Splunk ", "Bearer "):
            if header.startswith(scheme):
                token = header[len(scheme):].strip()
                break

        if not token:
            self._auth_failure("missing_token")
            self._respond(401, {"text": "Token is required", "code": 2}, close=True)
            return None

        # Constant-time comparison against each configured token; the
        # token value itself is never logged or spooled.
        for known, mapping in CONFIG["tokens"].items():
            if hmac.compare_digest(token, known):
                return mapping

        self._auth_failure("invalid_token")
        self._respond(403, {"text": "Invalid token", "code": 4}, close=True)
        return None

    def _auth_failure(self, reason):
        log(1, "Auth failure ({}) from {}", reason, self._client_ip())
        try:
            spool_append([receiver_event("auth_failure", reason=reason,
                                         client_ip=self._client_ip(),
                                         path=self.path)])
        except OSError as e:
            log(0, "Could not spool auth_failure event: {}", e)

    # -- endpoints --

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path.rstrip("/")
        if path in ("/services/collector/health", "/services/collector/health/1.0"):
            self._respond(200, {"text": "HEC is healthy", "code": 17})
        else:
            self._respond(404, {"text": "Not Found", "code": 404})

    def do_POST(self):
        # Error paths below respond before reading the request body, so
        # they close the connection — otherwise the unread body bytes
        # would be parsed as the next request on the kept-alive socket.
        path = urllib.parse.urlsplit(self.path).path.rstrip("/")
        if path not in ("/services/collector",
                        "/services/collector/event",
                        "/services/collector/event/1.0"):
            self._respond(404, {"text": "Not Found", "code": 404}, close=True)
            return

        mapping = self._authorize()
        if mapping is None:
            return

        if spool_over_quota():
            # Sender backpressure: well-behaved HEC clients retry 503s
            # with the same payload, so nothing is lost while the
            # operator frees disk or Wazuh catches up.
            self._respond(503, {"text": "Server is busy", "code": 9}, close=True)
            return

        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._respond(411, {"text": "Length Required", "code": 6}, close=True)
            return
        if length > CONFIG["max_body_bytes"]:
            # Do not read the oversized body; drop the connection after
            # responding so the socket is not left mid-stream.
            self._respond(413, {"text": "Request too large (maximum is {} bytes)".format(
                CONFIG["max_body_bytes"]), "code": 6}, close=True)
            return

        raw = self.rfile.read(length)

        if self.headers.get("Content-Encoding", "").lower() == "gzip":
            try:
                raw = gunzip_capped(raw, CONFIG["max_body_bytes"])
            except (ValueError, zlib.error) as e:
                self._bad_batch(mapping, "gzip: {}".format(e))
                return

        try:
            text = raw.decode("utf-8")
            envelopes = parse_hec_batch(text)
        except (UnicodeDecodeError, ValueError) as e:
            self._bad_batch(mapping, str(e))
            return

        if not envelopes:
            self._respond(400, {"text": "No data", "code": 5})
            return

        events = [transform_envelope(env, mapping["source"], mapping["namespace"])
                  for env in envelopes]
        try:
            spool_append(events)
        except OSError as e:
            log(0, "Spool write failed: {}", e)
            try:
                spool_append([receiver_event("spool_error", error=str(e)[:500],
                                             source=mapping["source"])])
            except OSError:
                pass  # spool is down; the stderr line above is the record
            self._respond(500, {"text": "Internal server error", "code": 8})
            return

        log(2, "Accepted {} events for source '{}'", len(events), mapping["source"])
        self._respond(200, {"text": "Success", "code": 0})

    def _bad_batch(self, mapping, error):
        log(1, "Malformed batch from source '{}': {}", mapping["source"], error)
        try:
            spool_append([receiver_event("malformed_batch", source=mapping["source"],
                                         client_ip=self._client_ip(),
                                         error=str(error)[:500])])
        except OSError as e:
            log(0, "Could not spool malformed_batch event: {}", e)
        self._respond(400, {"text": "Invalid data format", "code": 6})


# ── Startup ──

def parse_args():
    parser = argparse.ArgumentParser(description="HEC-compatible receiver for push-based SIEM ingestion")
    parser.add_argument("--bind", help="Bind address (default $HECR_BIND_ADDR or 127.0.0.1)")
    parser.add_argument("--port", type=int, help="Bind port (default $HECR_PORT or 8088)")
    parser.add_argument("--spool-file", help="Spool file path (default $HECR_SPOOL_FILE)")
    parser.add_argument("--debug", "-d", type=int, choices=(0, 1, 2, 3),
                        help="Verbosity 0-3, stderr only (default $HECR_DEBUG or 0)")
    return parser.parse_args()


def load_config(args):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return {
        "bind": args.bind or os.environ.get("HECR_BIND_ADDR", DEFAULT_BIND),
        "port": args.port or int(os.environ.get("HECR_PORT", DEFAULT_PORT)),
        "spool_file": args.spool_file or os.environ.get("HECR_SPOOL_FILE", DEFAULT_SPOOL_FILE),
        "spool_max_bytes": int(os.environ.get("HECR_SPOOL_MAX_BYTES", DEFAULT_SPOOL_MAX_BYTES)),
        "spool_quota_bytes": int(os.environ.get("HECR_SPOOL_QUOTA_BYTES", DEFAULT_SPOOL_QUOTA_BYTES)),
        "max_body_bytes": int(os.environ.get("HECR_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES)),
        "secrets_file": os.environ.get("HECR_SECRETS_FILE", os.path.join(script_dir, ".secrets")),
        "debug": args.debug if args.debug is not None else int(os.environ.get("HECR_DEBUG", "0")),
    }


def main():
    global DEBUG_LEVEL

    args = parse_args()
    config = load_config(args)
    DEBUG_LEVEL = config["debug"]

    secrets = load_secrets_file(config["secrets_file"])
    raw_tokens = get_secret("hec_tokens", "HEC_TOKENS", secrets)
    config["tokens"] = parse_token_map(raw_tokens)
    if not config["tokens"]:
        log(0, "ERROR: HEC_TOKENS contained no valid token:source:namespace entries")
        sys.exit(1)

    CONFIG.update(config)

    spool_dir = os.path.dirname(config["spool_file"]) or "."
    os.makedirs(spool_dir, exist_ok=True)

    if config["bind"] not in ("127.0.0.1", "::1", "localhost"):
        log(0, "WARNING: binding {} — this server is designed for loopback behind a "
               "tunnel edge. Non-loopback binds expose an unencrypted, un-rate-limited "
               "endpoint.", config["bind"])

    server = ThreadingHTTPServer((config["bind"], config["port"]), HecReceiverHandler)
    server.daemon_threads = True

    try:
        spool_append([receiver_event("receiver_started",
                                     bind="{}:{}".format(config["bind"], config["port"]),
                                     sources=sorted({m["source"] for m in config["tokens"].values()}))])
    except OSError as e:
        log(0, "ERROR: cannot write spool file {}: {}", config["spool_file"], e)
        sys.exit(1)

    log(0, "Listening on {}:{} — {} token(s), spool {}",
        config["bind"], config["port"], len(config["tokens"]), config["spool_file"])
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log(0, "Shutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
