# driver

## File map

- `mod.rs` — channel depths, capacity caps, `DriverTiming` (the injectable waiting
  windows), `LinkDriver`, `DriverError`, constructors.
- `channels.rs` — `TurnChannels`/`ChatOut`, the game thread's end of the seam.
- `run.rs` — `into_parts` (the one place a driver is split into link + seam + state),
  `run` / `run_reconnecting` / `session`: who owns closing the connection.
- `session.rs` — one connection's setup, the `select!` loop, and `ArmFlow`.
- `inbound.rs` / `outbound.rs` — the extracted `select!` arm bodies (relay → game, game → relay).
- `connectivity.rs` — `ConnectivityFence`: which relay-stamped link-lifecycle changes
  may still move the game's display, and whose departure is final.
- `send.rs` — one turn's wire handoff, packet send, the delivered-through cursor push.
- `reorder.rs` — `SlotReorder`: the per-slot ordered-release buffer and the delivery
  cursor a resume is read back from.
- `state.rs` — `GameSeam` (and the one place both halves of the seam's channels are wired),
  `LoopState`.
- `reconnect.rs` / `retention.rs` — re-dial + escalation; `RetentionRing` and what a
  resume re-sends off it, and how it anchors.
- `backoff.rs` — non-blocking game pushes, the waits that keep servicing the seam, jittered backoff.
- `teardown.rs` — the post-loop drain and the two delivery fences.

## Easy to break

- An arm handler returns `ArmFlow`: `Teardown` is the old `break 'serve` (falls into
  `drain_and_settle`), `End` the old `return`. Swapping them changes whether the game's final
  turns are drained. A bare `continue` inside a handler continues *its own* loop, never the
  session loop.
- Turns are datagrams and `seq` is only an ack handle. Loss is covered by redundancy and the
  maintenance flush, never retransmit-on-timeout; order is restored by the per-slot release.
- A turn too large for any datagram diverts to the reliable control stream, never enters the
  unacked window, and folds back through the link's dedup. Re-injecting one into the unacked
  window strands it forever — the redundancy pass always skips it.
- `UnackedWindowExhausted` and `OutageBufferExhausted` are deliberately terminal, not link
  failures: a re-dial cannot fix a peer that is genuinely behind, and bounding either by
  dropping turns would desync lockstep silently.
- A resume presents this client's *own* slot cursor always, an anchor of 0 included — its
  presence is what makes the relay seed the fresh window's acked holes. Same-relay and re-home
  anchors differ; read the comments before touching either.
- Escalation timing is budgeted against BW's ~45s native stall-drop; widening `ESCALATE_AFTER`,
  `REHOME_PROVIDER_DEADLINE` or `RECONNECT_DIAL_TIMEOUT` can push a re-home past it.
- Every driver → game push is non-blocking: awaiting one parks acks and outbound turns behind a
  stalled consumer.

## Tests

`cargo test -p rally-point-client --lib driver::` (or a topic, `driver::tests::recovery::`).
Fixtures in `tests/mod.rs`: `DriverFixture` is the default starting point — a driver running over
a loopback QUIC pair with the peer's link, a control-frame reader and the peer's control stream
already wired, and the endpoints owned so nothing has to be kept alive by hand; `finish()` is the
drop-the-seam-and-await epilogue. `ReconnectSessions` drives two consecutive sessions across a
simulated outage, `seam_only()` builds the game seam with no connection at all (for the waits that
only service it), `drive_unacked_session` leaves a known in-flight window behind, and
`connected_links()`/`test_driver` are the raw pieces for a test that needs `into_parts`. A test
never waits out a real window: the teardown fences, the leave-intent safety timeout and the
maintenance flush come from `DriverTiming`, and the escalation window from
`Reconnect::escalate_after`/`escalate_retry`. A test that asserts a window actually elapsed asserts
against the injected value, never the default.
