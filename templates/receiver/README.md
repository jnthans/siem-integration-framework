# HEC Receiver — push-based ingestion

A long-running, Splunk-HEC-compatible HTTP receiver for push sources that
cannot be polled: HEC senders, log shippers, vendor webhook forwarders.
It is the push-side counterpart to the wodle templates — same credential
chain, same namespaced JSON output, same decoder/rules patterns — but a
different runtime model (persistent service + spool file instead of
scheduled poller + stdout).

Read first:
- [Ingestion models](../../docs/architecture/ingestion-models.md) — when to poll vs. receive
- [Push ingestion guide](../../docs/guides/push-ingestion.md) — edge layer options and full setup

```
Push sender ──► Edge (Cloudflare Tunnel / Tailscale) ──► 127.0.0.1:8088 hec_receiver.py
                TLS, WAF, access policy                        │
                                                               ▼
                                              /var/ossec/logs/hec/spool.jsonl
                                                               │
                                    Wazuh <localfile log_format="json"> tails it
                                                               │
                                              decoder ──► rules ──► dashboard
```

Unlike the wodle templates, `hec_receiver.py` is concrete and runnable
as-is — no `{VENDOR}` placeholders. Per-sender specifics live in the token
map, not in code.

## Files

| File | Purpose |
|---|---|
| `hec_receiver.py` | The receiver. Stdlib only, binds loopback, HEC-compatible endpoints |
| `hec_receiver.service` | systemd unit — wazuh user, sandboxing directives, `LoadCredential` |
| `.secrets.example` | Token map format: `token:source:namespace` triplets |
| `cloudflared-config.example.yml` | Cloudflare Tunnel ingress (default public edge) |
| `tailscale.example.md` | Tailscale serve (tailnet-only) and Funnel (public) edges |
| `ossec.conf.snippet` | Wazuh `<localfile>` block that tails the spool |
| `receiver_decoder.xml` | Prematch decoder + JSON_Decoder for spool lines |
| `receiver_rules.xml` | Receiver health/error rules (xx90–xx99 block) + per-source example |

## Quickstart

1. **Install the receiver**

   ```sh
   sudo install -d -o root -g wazuh -m 750 /opt/hec-receiver
   sudo install -o root -g wazuh -m 640 hec_receiver.py /opt/hec-receiver/
   sudo install -d -o wazuh -g wazuh -m 750 /var/ossec/logs/hec
   ```

2. **Create tokens** — one per sender (`openssl rand -hex 32`), written as
   `token:source:namespace` triplets to `/etc/hec-receiver/hec_tokens`
   (chmod 600). See `.secrets.example` for the format.

3. **Start it**

   ```sh
   sudo cp hec_receiver.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now hec_receiver
   ```

4. **Wire up Wazuh** — copy `receiver_decoder.xml` to
   `/var/ossec/etc/decoders/`, `receiver_rules.xml` (with `{RULE_BASE}`
   replaced by your reserved ID block) to `/var/ossec/etc/rules/`, add the
   `ossec.conf.snippet` block, restart the manager. The
   `receiver_started` event confirms the pipeline end-to-end.

5. **Choose an edge** — the receiver only listens on loopback; senders
   reach it through a tunnel. Start with Tailscale serve (tailnet-only)
   for validation, then Cloudflare Tunnel for public/third-party senders.
   See the [push ingestion guide](../../docs/guides/push-ingestion.md).

6. **Smoke test** (from wherever the edge allows):

   ```sh
   curl https://hec.example.com/services/collector/health
   curl -X POST https://hec.example.com/services/collector/event \
        -H "Authorization: Splunk <token>" \
        -d '{"event":{"test":"hello"},"sourcetype":"smoke:test"}'
   tail -1 /var/ossec/logs/hec/spool.jsonl   # on the receiver host
   ```

## Protocol notes

- Endpoints: `POST /services/collector` and `/services/collector/event`
  (also `/event/1.0`); `GET /services/collector/health` (no auth) returns
  `{"text":"HEC is healthy","code":17}`
- Auth: `Authorization: Splunk <token>` or `Authorization: Bearer <token>`
- Batches are **concatenated JSON objects** (`{"event":...}{"event":...}`),
  not a JSON array; `Content-Encoding: gzip` is supported
- Bodies over ~1 MB → `413`; spool over quota → `503` (senders should
  buffer and retry — that is the backpressure mechanism)
- Indexer acknowledgment (`useACK`) is not supported
- Each HEC envelope becomes one framework event:
  `{"integration":"<source>","<ns>":{...payload, "hec_host":..., "hec_source":..., "hec_sourcetype":..., "hec_time":...}}`
- Auth failures, malformed batches, and spool errors are themselves
  spooled as structured events under `integration=hec_receiver`, so the
  SIEM alerts on receiver health

## Security posture

The receiver deliberately uses Python's `http.server`. That is acceptable
**only** because it binds `127.0.0.1` and every request first traverses a
hardened edge that terminates TLS and enforces access policy. Never bind
a public interface. Dedup/replay is the sender's responsibility (push
model), and delivery durability is bounded by the spool quota. For
high-volume ingestion, use Vector or Fluent Bit's native HEC source
instead — the framework's zero-dependency principle governs wodle code on
the manager; the receiver is a separate deployment component. See the
[security checklist](../../docs/guides/security-checklist.md) push section
before going live.
