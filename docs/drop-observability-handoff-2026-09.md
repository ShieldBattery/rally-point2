# Drop-request observability: follow-ups from the 2026-09-19 prod incident

## What happened

Session `1789553671786726` (ShieldBattery game `01a0bb73-48f9-76b5-a1a3-cb34a339078e`, tenant
`prod`), a cross-relay 1v1: slot 1 homed on relay 1512 (kr, the session's primary/authority), slot 0
homed on relay 1539 (us-west). Twenty minutes in, slot 1's link timed out. Slot 0's player reported
that he saw the disconnect panel for the other player but could not drop him. He did not send a bug
report, so we had only the two flight recordings and the relays' CloudWatch logs.

What those showed:

- Relay 1512 recorded `slot_disconnected` + `drop_held` for slot 1. Relay 1539 got the mesh
  departure within the same second (`drop_held` slot 1) and was promoted to authority.
- Slot 0's link stayed up for the next 340 s (QUIC idle timeout is 10 s, so keepalives were flowing)
  and never redialed.
- Neither recording has a `DropRequested` event, and relay 1539's log has no `ignoring drop request`
  or `honoring manual drop request` line. So no `RequestDrop` frame ever reached the relay.
- Slot 0's link then ended with `QUIC connection lost: timed out` and no `client announced clean
  leave`: the client's process ended without teardown.

Ten minutes earlier the same dropped player, on the same relay 1512, dropped from another cross-relay
1v1 (session `1789553671786711`, survivor on relay 1443). That one resolved normally: `drop_requested`
at +99.5 s, honored after a 50.7 s hold, `leave_control_write` succeeded. Fleet-wide over the last
14 days drops are honored daily in every busy region, and 11 of the 12 cross-relay 1v1 matchmaking
drops since 09-06 ended with the survivor winning. So nothing systematic is broken. This was a
one-off failure somewhere on the survivor's side.

## The gap

We could not tell which of these happened, because no hop between "relay 1539 held the drop" and
"relay 1539 received a RequestDrop" leaves a positive trace anywhere we can read after the fact:

1. Relay 1539 fanned the mesh `SlotConnectivity{connected: false}` for slot 1 down slot 0's control
   stream. `pushes::push_connectivity` records nothing on success and logs failure at `info`.
   Compare leaves, which get a `LeaveControlWrite` flight event per recipient with `succeeded`.
2. The mesh `SlotConnectivity` arm in `mesh/dispatch.rs` can return silently when
   `mark_connection_down` or `admit_reconnect` rejects the frame. On paper that could not fire here
   (the preceding `SlotDeparted` moves the slot to `Down(E)` and a second `Down(E)` is idempotent),
   but a silent return is exactly the kind of thing we want to see in a recording.
3. The client driver's `Connectivity` arm (`client/src/driver/inbound.rs`) logs nothing when it
   admits a change and pushes it to the game, and only `debug` when `ConnectivityFence::admit`
   rejects it or the game channel is full.
4. The client driver's `on_request_drop` (`client/src/driver/outbound.rs`) logs nothing on a
   successful write and `debug` on failure.
5. Relay-side, a `RequestDrop` that fails the edge checks (`handle_drop_request`: names itself, not
   held, rate cap) is an info log only. The authority-side refusals in `honor_drop_request` (hold
   short of the floor, no hold, lost claim) are also log-only. `DropRequested` exists only for
   admitted requests. The logs are in CloudWatch, so this is workable, but the recording is what the
   ShieldBattery admin UI shows and what we reach for first.

Note on levels: rally-point-client's `tracing` events reach the game's log file through tracing's
`log` bridge, and the game logs at `debug` globally. Verified in real prod bug-report logs (rp2
`DEBUG` lines from `driver/inbound.rs` are present). So raising levels is not about visibility. The
ask is for positive-path breadcrumbs on rare, high-value events, and for recording rejections in the
flight recorder rather than only in logs.

## Requested changes

### Relay: flight events

1. **`ConnectivityControlWrite { recipient, connection_epoch, slot, connected, succeeded }`**,
   recorded in `pushes::push_connectivity`, mirroring `LeaveControlWrite`. Both the locally
   originated change (a home client's link died) and the mesh-originated one should record. Volume
   is bounded: a few per slot per game.
2. **`ConnectivityMeshRejected { source_relay, slot, connected, connection_epoch }`** (name to taste)
   at the two silent returns in the `SlotConnectivity` arm of `mesh/dispatch.rs`. Same for the
   `push_to_slots` queue-full case if it is cheap to thread through; today that is a `warn` log.
3. **`DropRequestRejected { requester, target, reason }`** in `handle_drop_request` for the edge
   rejections (`SelfTarget`, `NotDisconnected`, `RateCapped`, `OutOfRange`), and
   **`DropRequestRefused { requester, target, held_ms, reason }`** in `honor_drop_request` for the
   authority-side ones (`BelowFloor`, `NoHold`, `LostClaim`). With these, a recording alone answers
   "did any request arrive, and why was it not honored". Rate-capped duplicates could be folded into a
   counter on the per-slot row if the event volume worries you; a hostile flood is already dropped
   before the mesh, so it only affects the recorder.
4. Optional: an info log line when a request is admitted in `handle_drop_request` (today only the
   rejections log, and `honoring` logs later on the authority), so CloudWatch shows the same thing
   the recording does.

### Client (rally-point-client): positive-path logs

5. In the `Connectivity` arm of `driver/inbound.rs`: `info!` when a change is admitted and pushed
   to the game (slot, connected, epoch); `warn!` instead of `debug!` when the epoch gate rejects it or
   when the game channel is full. A handful of lines per game.
6. In `on_request_drop` (`driver/outbound.rs`): `info!` when the `RequestDrop` write completes
   (target slot); `warn!` on failure. This is the last hop before the relay and the one line that
   would have told us whether the survivor's client ever tried.

### Test

7. `relay/src/mesh/tests/dispatch_local.rs` covers a stale `SlotConnectivity(false)`, a stale
   `SlotDeparted`, then a current `SlotConnectivity(false)`. There is no test for the order every
   real cross-relay drop produces: `SlotDeparted(E)` first, then `SlotConnectivity(false, E)`, with the
   assertion that the local survivor's inbox still receives `(slot, false)`. Reading
   `record_departure_for_epoch` and `mark_connection_down` says it does; a test would pin it.

## Why it matters

The manual drop is the only thing a stalled survivor can do, and "I clicked Drop and nothing
happened" is the report we get. Today that report can only be answered if the survivor sends their
game log. With 1, 3 and 5/6 in place, the recording plus CloudWatch answer it without the client's
help, and the client log answers it precisely when we do get one.

## Pointers

- Flight events: `relay/src/observability/events.rs`
- Connectivity fan-out: `relay/src/routing/fan_out.rs` (`fan_out_connectivity`, `push_to_slots`),
  `relay/src/routing/slot_link/pushes.rs` (`push_connectivity`)
- Mesh arm: `relay/src/mesh/dispatch.rs` (`Kind::SlotConnectivity`)
- Drop requests: `relay/src/routing/drops.rs` (`handle_drop_request`, `honor_drop_request`)
- Client: `client/src/driver/inbound.rs` (`ControlInbound::Connectivity`),
  `client/src/driver/outbound.rs` (`on_request_drop`)
- CloudWatch: log group `/rp2/prod/relay` per region (us-west -> us-west-2, kr -> ap-northeast-2),
  30-day retention; filter on the session id.
