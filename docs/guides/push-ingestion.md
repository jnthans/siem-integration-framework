# Push Ingestion

How to deploy the framework's push-based ingestion model: an
HEC-compatible receiver on the Wazuh host, fronted by a tunnel so no
inbound ports are ever exposed. Read
[Ingestion models](../architecture/ingestion-models.md) first for when to
choose push over the default pull model.

```
Push sources ──► Edge (TLS / access policy) ──► outbound-only tunnel
                                                       │
                                        http://127.0.0.1:8088  hec_receiver.py
                                                       │
                                     /var/ossec/logs/hec/spool.jsonl (JSON lines)
                                                       │
                                     Wazuh <localfile log_format="json">
                                                       │
                                     decoder ──► rules ──► OpenSearch ──► dashboard
```

All files referenced here live in
[templates/receiver/](https://github.com/jnthans/siem-integration-framework/tree/main/templates/receiver);
its README has the receiver installation quickstart. This guide covers
the edge layer, protocol behavior, and operations.

---

## The edge layer

The receiver is **tunnel-agnostic**: it binds loopback, speaks plain
HTTP, and assumes nothing about the provider in front of it. Any tunnel
or reverse proxy that can forward HTTPS to a loopback port (ngrok, frp, a
DMZ nginx/Caddy) works the same way — the framework documents Tailscale
and Cloudflare as the supported paths.

| Edge | Public endpoint? | Best for | Key caveat |
|---|---|---|---|
| **1. Tailscale serve** (tailnet-only) | No | Senders you control; validation before going public | Senders must be tailnet nodes |
| **2. Cloudflare Tunnel** | Yes — your domain | Public/third-party senders (default) | Edge hardening is your configuration burden |
| **3. Tailscale Funnel** | Yes — `*.ts.net` | Homelab, low volume | No WAF/rate limiting/pre-origin auth — HEC token is the only auth |

Rule of thumb: start with 1 to validate the pipeline; move to 2 when
third-party senders need in; use 3 only where Cloudflare is overkill and
volume is low.

### Path 1: Tailscale tailnet-only — strongest, and the testing path

When every sender is a machine you control, don't create a public
endpoint at all:

```sh
sudo tailscale serve https / http://127.0.0.1:8088
```

The receiver is served at `https://<host>.<tailnet>.ts.net/` with a valid
TLS certificate, reachable only inside the tailnet. Tailnet ACLs restrict
*which* nodes can reach it (tag senders, allow only `tag:hec-sender →
tag:hec-receiver:443`), so network-layer authentication happens before
any HTTP request — the HEC token becomes defense-in-depth rather than the
sole auth layer.

This is also the recommended **validation workflow before any public
exposure**: serve tailnet-only, POST a test event from another tailnet
node, confirm the spool line and the Wazuh alert, and only then choose a
public edge if third-party senders are needed.
[templates/receiver/tailscale.example.md](https://github.com/jnthans/siem-integration-framework/blob/main/templates/receiver/tailscale.example.md)
has the commands, systemd persistence, a sample ACL snippet, and the
step-by-step validation.

### Path 2: Cloudflare Tunnel — default for public/third-party senders

`cloudflared` runs on the Wazuh host and dials **out** to Cloudflare's
edge; senders reach `https://hec.example.com`, which Cloudflare proxies
down the tunnel to `http://127.0.0.1:8088`. No inbound firewall rules, no
port forwards, no public IP on the host.

Setup (details in
[cloudflared-config.example.yml](https://github.com/jnthans/siem-integration-framework/blob/main/templates/receiver/cloudflared-config.example.yml)):

```sh
cloudflared tunnel login
cloudflared tunnel create hec-receiver
cloudflared tunnel route dns hec-receiver hec.example.com
# /etc/cloudflared/config.yml: ingress hec.example.com -> http://127.0.0.1:8088
cloudflared service install && systemctl enable --now cloudflared
```

The tunnel alone only hides the origin — **harden the edge** so junk
never reaches the receiver:

- **WAF path/method restriction**: allow only
  `POST /services/collector*` and `GET /services/collector/health`;
  block everything else at the edge.
- **Rate limiting**: a Cloudflare rate limiting rule on
  `/services/collector*` sized to your senders' batch cadence.
- **Pre-origin auth (Cloudflare Access)**: a service token (senders add
  `CF-Access-Client-Id`/`CF-Access-Client-Secret` headers) or mTLS. With
  Access enforced, unauthenticated requests are rejected at the edge and
  the HEC token becomes the second factor.

### Path 3: Tailscale Funnel — public, homelab/low-volume

```sh
sudo tailscale funnel --bg 443 http://127.0.0.1:8088
```

Same serve mechanism, but exposed to the internet on your `ts.net`
hostname. Caveats, honestly: ts.net domain only (no custom domains),
public ports limited to 443/8443/10000, non-configurable and undocumented
bandwidth limits, beta status — and **no edge WAF, rate limiting, or
pre-auth**. Every internet request reaches the receiver, so the HEC token
is the only auth layer; token strength and rotation escalate from
recommended to mandatory (see the
[security checklist](security-checklist.md)). Alert on `auth_failure`
bursts.

### Other alternatives

A DMZ reverse proxy (nginx/Caddy) in front of the receiver also works —
but note it still exposes 443 inbound somewhere, which is exactly what
the tunnel paths avoid; you take on TLS, patching, and DoS surface
yourself. ngrok/frp behave like Funnel: fine mechanically, bring your own
edge controls.

---

## HEC protocol notes

The receiver implements the subset of Splunk's HTTP Event Collector
protocol that senders actually use:

- **Endpoints**: `POST /services/collector`,
  `POST /services/collector/event` (and `/event/1.0`);
  `GET /services/collector/health` returns
  `{"text":"HEC is healthy","code":17}` without auth (edge health checks).
- **Auth**: `Authorization: Splunk <token>` or `Authorization: Bearer
  <token>`. Each token maps to a source name + namespace — one token per
  sender gives per-source revocation.
- **Batches are concatenated JSON objects**, not an array:
  `{"event":...}{"event":...}`. The receiver parses with a
  `json.JSONDecoder().raw_decode()` loop; `json.loads()` on the whole
  body would reject every multi-event batch.
- **`Content-Encoding: gzip`** is supported (with a decompression cap
  against gzip bombs).
- **Limits**: bodies over ~1 MB get `413`; over-quota spool gets `503
  {"text":"Server is busy","code":9}` — the sender-backpressure signal.
- **Not supported**: indexer acknowledgment (`useACK`), the `/raw`
  endpoint, channels. Senders requiring ack need Vector/Fluent Bit (below).

Each envelope becomes one framework event, preserving HEC metadata under
namespaced `hec_*` fields:

```json
{"event":{"action":"drop","src":"1.2.3.4"},"host":"fw01","sourcetype":"fw:traffic","time":1720000000}
```

becomes (token mapped to `firewall`/`fw`):

```json
{"integration":"firewall","fw":{"action":"drop","src":"1.2.3.4","hec_host":"fw01","hec_sourcetype":"fw:traffic","hec_time":1720000000,"event_type":"fw:traffic"}}
```

---

## Spool, rotation, and quota

The spool file is the durability boundary: a batch is acknowledged (200)
only after its lines are written. Wazuh tails the file via the
`<localfile log_format="json">` block in `ossec.conf.snippet`.

- **Rotation**: when the live file exceeds `HECR_SPOOL_MAX_BYTES`
  (default 50 MB) it rotates to `spool.jsonl.1`, keeping one generation.
  Wazuh follows the truncation; a rotated file's events have already been
  read in normal operation.
- **Quota**: when live + rotated size exceeds `HECR_SPOOL_QUOTA_BYTES`
  (default 200 MB) the receiver answers `503` until space frees up.
  Well-behaved HEC senders buffer and retry — nothing is silently
  dropped, and the `quota_exceeded` event (rule `{RULE_BASE}93`) tells
  you Wazuh has fallen behind or disk needs attention. Keep the quota at
  least 2× the rotation size.
- **Receiver health is in-band**: auth failures, malformed batches, spool
  errors, and lifecycle events are written to the same spool under
  `integration=hec_receiver`, so the dashboard alerts on receiver
  problems through the normal rules pipeline.

---

## A note on `http.server`, and when to use something else

The receiver uses Python's `http.server`, whose own documentation warns
against exposing it to untrusted traffic. That is acceptable here **only**
because of the deployment shape: it binds `127.0.0.1` behind a tunnel
edge that terminates TLS and enforces access policy, request bodies are
capped, and connections are timed out. Never bind it to a public
interface.

For high-volume ingestion (thousands of events/second, many concurrent
senders, ack semantics), run [Vector](https://vector.dev) or
[Fluent Bit](https://fluentbit.io) with their native HEC source instead,
writing to the same spool format. This does not violate the framework's
zero-dependency principle — that principle governs wodle code executed by
the Wazuh manager; the receiver is a separate deployment component, and
the stdlib implementation is simply the smallest thing that works at
moderate volume.
