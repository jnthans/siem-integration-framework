# Tailscale edge for the HEC receiver

Two Tailscale modes front the receiver. Both proxy HTTPS to the
loopback-bound receiver — the receiver itself needs no changes for either
(it stays tunnel-agnostic). See [push-ingestion.md](../../docs/guides/push-ingestion.md)
for the full edge decision matrix.

| Mode | Public endpoint? | Use for |
|---|---|---|
| `tailscale serve` | No — tailnet only | Senders you control; **testing before any public exposure** |
| `tailscale funnel` | Yes — `*.ts.net` | Public senders, homelab/low-volume |

---

## Mode 1: tailnet-only (`tailscale serve`)

Serves the receiver at `https://<host>.<tailnet>.ts.net/` with a valid TLS
certificate, reachable **only from inside your tailnet**. No public
endpoint exists at all — the strongest posture when every sender is a
machine you control (and the recommended way to validate the pipeline
before choosing any public edge).

```sh
sudo tailscale serve https / http://127.0.0.1:8088
```

(Newer Tailscale releases also accept the shorthand
`tailscale serve --bg http://127.0.0.1:8088`.)

Check what is being served:

```sh
tailscale serve status
```

### Persistence

The serve configuration is stored in tailscaled's state and survives
reboots — you only need tailscaled itself enabled:

```sh
sudo systemctl enable --now tailscaled
```

### Restrict which nodes can reach the receiver (tailnet ACLs)

Being on the tailnet should not automatically grant access to the
receiver. Tag the receiver host and the sender nodes, then allow only
senders to reach port 443 on the receiver (admin console → Access
controls):

```jsonc
{
  "tagOwners": {
    "tag:hec-receiver": ["autogroup:admin"],
    "tag:hec-sender":   ["autogroup:admin"]
  },
  "acls": [
    // Only tagged senders may reach the receiver's HTTPS port.
    { "action": "accept",
      "src": ["tag:hec-sender"],
      "dst": ["tag:hec-receiver:443"] }
  ]
}
```

In this mode the network layer already authenticates senders (tailnet
membership + ACLs), so the HEC token becomes **defense-in-depth** rather
than the sole auth layer — still use per-source tokens for attribution
and revocation.

### Validate before going public

1. From another tailnet node (tagged `tag:hec-sender`):

   ```sh
   curl https://<host>.<tailnet>.ts.net/services/collector/health
   curl -X POST https://<host>.<tailnet>.ts.net/services/collector/event \
        -H "Authorization: Splunk <token>" \
        -d '{"event":{"test":"hello"},"sourcetype":"smoke:test"}'
   ```

2. Confirm the event landed in the spool on the receiver host:

   ```sh
   tail -1 /var/ossec/logs/hec/spool.jsonl
   ```

3. Confirm Wazuh picked it up (decoder + rules installed, manager
   restarted): check `/var/ossec/logs/alerts/alerts.json` or the
   dashboard.

4. Only then, if third-party senders outside the tailnet are needed,
   choose a public edge — Cloudflare Tunnel (default) or Funnel (below).

---

## Mode 2: public via Tailscale Funnel

Exposes the same `ts.net` hostname to the whole internet:

```sh
sudo tailscale funnel --bg 443 http://127.0.0.1:8088
tailscale funnel status
```

Suitable for homelab and low-volume third-party senders. **Know the
caveats before choosing it:**

- Hostname is your `*.ts.net` name only — no custom domains
- Public ports are limited to 443, 8443, and 10000
- Bandwidth is limited by Tailscale (non-configurable, undocumented
  limits) — not for high-volume ingestion
- Funnel is beta-status functionality
- **No edge WAF, no rate limiting, no pre-origin auth** — unlike
  Cloudflare Tunnel, every internet request reaches the receiver, and the
  HEC token is the ONLY auth layer

Because the token is the sole gate, the security checklist's token items
escalate from recommended to **mandatory**: long random tokens
(`openssl rand -hex 32`), one token per source, scheduled rotation, and
alerting on `auth_failure` bursts (rule `{RULE_BASE}90`).
