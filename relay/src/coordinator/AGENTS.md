# relay/src/coordinator

The relay's outbound half of the control plane. Nothing here may gate a turn: a
coordinator outage must leave running games untouched.

## Map

- `client/` — the held WebSocket. `mod.rs`: public handles + the caller-owned
  queues. `connect.rs`: dial, enroll, next-dial delay. `reader.rs`: apply inbound
  pushes. `writer.rs`: *every* send. `heartbeat.rs`: what goes up about sessions.
- `region_ping/` — UDP echo measurement of the pushed beacon set.
- `load_fence.rs` — the probe/ack broker a load-state answer fences against.
- `idle_exit.rs` — the self-reap countdown.

## Invariants that bite

- **Only the write half sends.** A frame the reader cannot act on without sending
  (identity challenge, flight grant, load-state request) is *routed* to the writer.
  Its `biased` order is deliberate: bulk must never delay a close-bearing notice.
- **The enroll proof is the first frame after the challenge.** A pending notice,
  drain re-assert, or parked flight request reaching the wire first is read as the
  proof and refuses the enroll — and a pending notice survives reconnects, so that
  locks the relay out permanently.
- **Undelivered work is caller-owned.** `OutboundQueues` outlives each connection:
  a notice is parked *before* its send await and cleared only after; a shipment
  stays in `pending_flights` until stored or dropped. Don't move it into the loop.
- Descriptor sets are declarative — a full set replaces (absences are leaves), a
  delta mutates what the connect-time full set established. Add no version or
  sequence tracking: one ordered connection already orders full-set before delta.
- Refusals only a deploy or provisioner fixes (version, region, identity, ledger)
  take the long backoff; a duplicate-relay-id close deliberately does not — it ages
  out on its own, so prompt retry is what makes it converge.
- Flight data is observability, never backpressure: a refusal, failed PUT, or no
  grant inside `FLIGHT_GRANT_TIMEOUT` drops the recording. At most
  `MAX_INFLIGHT_FLIGHT_UPLOADS` cycle at once; the blob never rides the socket.
- A load-state answer's `fenced` flag licenses reading its *absences* only. Any
  membership change across the wait (arrival, replaced epoch, a slot that left)
  makes it `false` while the facts still go up. The seat count in `load_fence.rs`,
  not the ask channel, bounds concurrent probing.
- Idle self-exit needs zero slots **and** no control connection, held continuously;
  either half alone reaps a healthy relay.

## Testing

`cargo test -p rally-point-relay --lib coordinator::` (73 tests). A stand-in
coordinator must run the `accept_enroll` fixture before reading any application
frame, or the relay blocks awaiting its challenge; inject short delays via
`run_descriptor_subscriber_with` instead of waiting production intervals.
End-to-end against the real coordinator: `coordinator/tests/descriptor_transport/`.
