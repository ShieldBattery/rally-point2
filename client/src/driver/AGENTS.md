# driver

## File map

- `mod.rs` — channel depths and timing constants, `LinkDriver`, `DriverError`, constructors.
- `channels.rs` — `TurnChannels`/`ChatOut`, the game thread's end of the seam.
- `run.rs` — `run` / `run_reconnecting` / `session`: who owns closing the connection.
- `session.rs` — one connection's setup, the `select!` loop, and `ArmFlow`.
- `inbound.rs` / `outbound.rs` — the extracted `select!` arm bodies (relay → game, game → relay).
- `send.rs` — one turn's wire handoff, packet send, ordered release to the game.
- `state.rs` — `GameSeam`, `LoopState`, the connectivity-epoch fence, retention bookkeeping.
- `reconnect.rs` / `retention.rs` — re-dial + escalation; what a resume re-sends and how it anchors.
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
Fixtures in `tests/mod.rs`: `connected_links()` is a real QUIC pair, `into_session_parts` opens a
bare `session` without `run`, `spawn_session` + `next_control_frame` read the control stream one
frame at a time. Reconnect tests shorten the escalation window through
`Reconnect::escalate_after`/`escalate_retry` instead of waiting out the real ones.
