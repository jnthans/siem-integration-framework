# Ingestion Models

The framework supports two ingestion models. Everything downstream of
ingestion — namespaced JSON, decoders, rules, dashboards — is identical;
what differs is how events arrive and where durability lives.

| | **Pull (wodle poller)** | **Push (HEC receiver)** |
|---|---|---|
| Runtime | Scheduled process (every ~5 min), exits between runs | Long-running service (systemd) |
| Initiator | We call the vendor API | Sender calls us |
| Position tracking | Cursor/timestamp in a state file | None — no position to track |
| Durability | Vendor retains events; we re-fetch from the cursor | Spool file on disk; sender retries on 503 |
| Deduplication | Cursor guarantees no duplicates, no gaps | **Sender's job** — the receiver accepts what arrives |
| Delivery into Wazuh | stdout captured by the wodle manager | Spool tailed by `<localfile log_format="json">` |
| Network exposure | Outbound HTTPS only | Loopback bind behind an outbound-only tunnel |
| Failure mode | Missed poll → next run catches up from cursor | Receiver down → sender must buffer and retry |
| Templates | `templates/wodle/` | `templates/receiver/` |

## Pull: scheduled poller + cursor state

The default model, used by every wodle integration. A short-lived process
wakes on the Wazuh scheduler, loads its cursor from the state file, asks
the vendor API "what happened since here," emits events to stdout, and
atomically saves the new cursor.

Its defining property is **exactly-once delivery derived from vendor
state**: because the vendor retains events and the API supports resuming
from a position, a crashed or skipped run loses nothing — the next run
resumes from the last durable cursor. Duplicates and gaps are design
errors, not operational events.

Choose pull whenever the vendor offers a queryable API with a
continuation mechanism (cursor, timestamp checkpoint, offset). It is
operationally simpler: no daemon, no disk quota, no inbound path.

## Push: long-running receiver + spool durability

Some sources cannot be polled — they only emit: HEC senders, webhook
forwarders, appliances that fire events at delivery time. For these, the
framework runs an HEC-compatible HTTP receiver behind an outbound-only
tunnel. The receiver validates a per-source token, transforms each
envelope into the same namespaced format a wodle would emit, and appends
it to a spool file that Wazuh tails.

The durability boundary moves: there is no vendor-side cursor to re-fetch
from, so **the spool file is the record of what was accepted**. The
receiver acknowledges a batch (HTTP 200) only after the spool write
succeeds, rotates the spool by size, and enforces a disk quota —
returning 503 when full so well-behaved senders buffer and retry
(backpressure) instead of losing events silently.

Consequences to design for:

- **Dedup is the sender's job.** A sender that times out waiting for the
  200 and retransmits will produce duplicates; the receiver cannot know.
  Idempotency, retry policy, and event IDs live sender-side.
- **Availability matters.** A poller that's down catches up; a receiver
  that's down depends on sender buffering. The tunnel + systemd restart
  policy are part of the delivery guarantee.
- **Capacity is bounded.** Spool quota defines how far Wazuh can fall
  behind before senders are pushed back on.

## Choosing

1. Vendor has a pollable API with cursors/timestamps → **pull** (default).
2. Source only pushes (HEC/webhook), or event latency must be seconds
   rather than a polling interval → **push**.
3. Both available → prefer pull; it gives exactly-once semantics for free.

See the [push ingestion guide](../guides/push-ingestion.md) for receiver
deployment and the edge layer options, and
[templates/receiver/](https://github.com/jnthans/siem-integration-framework/tree/main/templates/receiver)
for the runnable receiver.
