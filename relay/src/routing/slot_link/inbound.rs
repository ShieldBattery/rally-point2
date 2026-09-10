//! The client-facing halves of the serve loop: a datagram arriving from this
//! client, a peer's turn going back out to it, the ack-beacon cursors it pushes,
//! and the packet-send and link-sampling helpers those three share.

use super::*;

use rally_point_proto::messages::SlotConditions;

use crate::validation::validate_turn;

/// Handles one datagram received from this client: sample the path, validate and
/// fan out every fresh turn, feed the send-phase controller, and push the
/// advanced delivered-through cursor back over the beacon stream.
pub(super) async fn handle_received(
    link: &mut Link,
    ctx: &mut SlotLinkCtx,
    received: Result<Received, LinkError>,
) -> ControlFlow<()> {
    let received = match received {
        Ok(received) => received,
        Err(error) => {
            log_link_closed(&ctx.key, ctx.slot, &error);
            return ControlFlow::Break(());
        }
    };
    // Stamped before validation, forwarding, and the registry
    // locks below: the phase controller measures *wire arrival*,
    // and everything this arm does after this line is relay
    // processing time that must not leak into the measurement.
    let received_at = std::time::Instant::now();
    // Only a payload-bearing packet needs an ack in return; owing one for
    // a client's ack-only packet would bounce ack-only packets back and
    // forth on an idle link.
    if received.carried_payloads {
        ctx.acks_owed = true;
    }
    // Sample this client's QUIC path only when the packet advances
    // delivery. Ack-only packets and all-redundant recovery copies
    // cannot advance the game and would merely rotate the same
    // cumulative counters through the decision-maker again. During
    // active play a fresh turn arrives every game step, keeping the
    // published conditions current; Noq stats do not change while
    // idle, so a quiet slot's last sample stays valid. Sampling once
    // per packet (not per payload) is enough — all fresh payloads in
    // one packet share the same connection path.
    if should_sample_active_conditions(&received) {
        let sampled = sample_slot_conditions(link, ctx.slot, ctx.connection_epoch);
        ctx.flight_counters.note_link_gauges(
            sampled.upstream_lost_packets,
            sampled.cwnd,
            sampled.congestion_events,
        );
        let sample = sampled.conditions;
        let sample_is_current =
            crate::mesh::publish_conditions(&ctx.conditions, &ctx.key, ctx.slot, sample);
        // The decision it may fire schedules against frames observed
        // off validated turns below — never off raw packet claims —
        // and is broadcast later at fan-out.
        if sample_is_current {
            let _ = consensus::ingest_local_condition(&ctx.decision_makers, &ctx.key, &sample);
        }
    }
    // A packet that first-delivers exactly one turn times the
    // sender's phase; a catch-up burst (several previously-unseen
    // turns at once) times the recovery instead, so it is skipped.
    // Captured before the loop below moves the payloads, fed after
    // it so only a validated turn's arrival is ever measured.
    let solo_fresh_seq = match received.fresh.as_slice() {
        [only] => Some(only.seq),
        _ => None,
    };
    for payload in received.fresh {
        match validate_turn(ctx.slot, payload) {
            Ok(turn) => {
                let payload = turn.payload;
                ctx.flight_counters.note_validated(payload.seq);
                // NOTE: neither the frame observation nor the
                // desync comparator is fed here. Both client and
                // mesh ingress funnel through the session-level
                // dedup before consensus, so each distinct
                // `(slot, seq)` turn is counted once. Only
                // *validated* turns reach that
                // feed point (a rejected packet breaks the link
                // above without a trace in decision state), and
                // the coordinate is the minimum across slots, so
                // even a validated turn's inflated claim can only
                // mislead its own slot.
                crate::mesh::forward_client_turn(
                    &ctx.sessions,
                    &ctx.mesh_for_teardown,
                    &ctx.key,
                    ctx.slot,
                    payload,
                );
            }
            Err(error) => {
                tracing::warn!(
                    tenant = ctx.key.tenant.as_ref(),
                    session = ctx.key.session.0,
                    slot = ctx.slot.0,
                    %error,
                    "rejecting client turn and closing connection",
                );
                link.connection()
                    .close(VarInt::from_u32(INVALID_TURN_CLOSE), b"invalid turn");
                return ControlFlow::Break(());
            }
        }
    }
    // Feed the send-phase controller from this relay's own client
    // edge — the only vantage that sees this slot's wire arrivals
    // first-hand (a mesh-forwarded copy would time another relay's
    // hop). The controller evaluates on its own sparse schedule,
    // so this almost always returns nothing; when it does issue
    // corrections, each named slot gets its own directive.
    if let Some(seq) = solo_fresh_seq {
        let corrections = consensus::ingest_arrival_phase(
            &ctx.decision_makers,
            &ctx.key,
            ctx.slot,
            seq,
            received_at,
        );
        if !corrections.is_empty() {
            fan_out_phase_directives(&ctx.sessions, &ctx.key, &corrections);
        }
    }
    // Push the advanced delivered-through cursor to the client so it can
    // force-advance its unacked window. The relay receives only this
    // client's own slot, so one per-slot cursor suffices. Push only on
    // advance.
    if let Some(cursor) = link.delivered_through(ctx.slot) {
        ctx.beacon_writer
            .flush(&mut ctx.beacon_send, std::iter::once((ctx.slot, cursor)))
            .await;
    }
    if link.payloads_in_flight() > UNACKED_WINDOW_CAP {
        tracing::warn!(
            tenant = ctx.key.tenant.as_ref(),
            session = ctx.key.session.0,
            slot = ctx.slot.0,
            in_flight = link.payloads_in_flight(),
            "unacked window exhausted; isolating slot",
        );
        link.connection().close(
            VarInt::from_u32(ISOLATED_CLOSE),
            b"unacked window exhausted",
        );
        return ControlFlow::Break(());
    }
    ControlFlow::Continue(())
}

/// Handles one payload another slot forwarded to this client: send it as a
/// datagram, or divert it to the reliable control stream when no datagram on this
/// path can carry it. `None` means the roster dropped our sender.
pub(super) async fn handle_forwarded(
    link: &mut Link,
    ctx: &mut SlotLinkCtx,
    forwarded: Option<Payload>,
) -> ControlFlow<()> {
    match forwarded {
        Some(payload) => {
            // Counts every turn delivered to this client, datagram
            // and control-stream divert alike.
            ctx.flight_counters.note_forwarded();
            let fits = match link.payload_fits(&payload) {
                Ok(fits) => fits,
                Err(error) => {
                    log_link_closed(&ctx.key, ctx.slot, &error);
                    return ControlFlow::Break(());
                }
            };
            if !fits {
                ctx.flight_counters.note_oversize_divert();
                // Too large for any datagram on this client's path:
                // divert to the reliable control stream, whose QUIC
                // reliability replaces redundancy for this turn. A
                // write failure closes the link — nothing re-carries
                // a diverted turn, and dropping it would desync
                // lockstep.
                if let Err(error) = rally_point_transport::control::send_control_turn(
                    &mut ctx.control_send,
                    payload,
                )
                .await
                {
                    tracing::info!(
                        tenant = ctx.key.tenant.as_ref(),
                        session = ctx.key.session.0,
                        slot = ctx.slot.0,
                        %error,
                        "control stream send failed; closing slot link",
                    );
                    return ControlFlow::Break(());
                }
                return ControlFlow::Continue(());
            }
            // The forwarded turn goes out carrying our acks. If it
            // also re-carried unacked turns, recovery is riding the
            // stream, so push the flush out; if it carried none (a
            // near-MTU turn), leave the timer so the flush
            // retransmits them.
            match send_packet(link, Some(payload), &ctx.flight_counters) {
                Ok(carried_redundancy) => {
                    ctx.acks_owed = false;
                    if carried_redundancy {
                        ctx.flush_deadline = Instant::now() + FLUSH_INTERVAL;
                    }
                    if link.payloads_in_flight() > UNACKED_WINDOW_CAP {
                        tracing::warn!(
                            tenant = ctx.key.tenant.as_ref(),
                            session = ctx.key.session.0,
                            slot = ctx.slot.0,
                            in_flight = link.payloads_in_flight(),
                            "unacked window exhausted; isolating slot",
                        );
                        link.connection().close(
                            VarInt::from_u32(ISOLATED_CLOSE),
                            b"unacked window exhausted",
                        );
                        return ControlFlow::Break(());
                    }
                }
                Err(error) => {
                    log_link_closed(&ctx.key, ctx.slot, &error);
                    return ControlFlow::Break(());
                }
            }
        }
        // The roster dropped our sender: we've been deregistered.
        None => return ControlFlow::Break(()),
    }
    ControlFlow::Continue(())
}

/// Handles one delivered-through cursor the client pushed over the beacon
/// stream: retire the window, fold the end-to-end delivery truth, and share it
/// with the session's mesh peers on the throttled cadence.
pub(super) fn handle_beacon_cursor(
    link: &mut Link,
    ctx: &mut SlotLinkCtx,
    beacon_slot: SlotId,
    cursor: u64,
) -> ControlFlow<()> {
    link.retire_through(beacon_slot, cursor);
    // The same cursor is the end-to-end delivery truth:
    // origin `beacon_slot`'s turns reached THIS client
    // through `cursor`. Fold it locally and — throttled —
    // re-share it to the session's mesh peers so a
    // peer-homed authority can fold it too.
    consensus::observe_delivery(
        &ctx.decision_makers,
        &ctx.key,
        ctx.slot,
        beacon_slot,
        cursor,
        crate::consensus::delivery::DeliveryHome::Local,
    );
    if let Some(snapshot) =
        ctx.delivery_share
            .advance(beacon_slot, cursor, std::time::Instant::now())
    {
        crate::mesh::fan_out_delivery_cursors(&ctx.mesh_links, &ctx.key, ctx.slot, &snapshot);
    }
    if link.payloads_in_flight() > UNACKED_WINDOW_CAP {
        tracing::warn!(
            tenant = ctx.key.tenant.as_ref(),
            session = ctx.key.session.0,
            slot = ctx.slot.0,
            in_flight = link.payloads_in_flight(),
            "unacked window exhausted; isolating slot",
        );
        link.connection().close(
            VarInt::from_u32(ISOLATED_CLOSE),
            b"unacked window exhausted",
        );
        return ControlFlow::Break(());
    }
    ControlFlow::Continue(())
}

/// Sends one packet, returning whether it re-carried any still-unacked turn — if so,
/// retransmission is already riding the forward stream and the flush can rest.
///
/// A refused datagram (`PayloadTooLarge`) here is a *bundle* that outgrew a
/// path-MTU shrink between sizing and sending — a recoverable loss the next,
/// smaller bundle re-carries, so it is not an error. It can never be a lone
/// turn too big for the path: the forward branch pre-checks with
/// [`Link::payload_fits`] and diverts those to the control stream (and the
/// link itself refuses one pre-registration as a second line of defense).
pub(super) fn send_packet(
    link: &mut Link,
    payload: Option<Payload>,
    counters: &crate::observability::flight_recorder::SlotCounters,
) -> Result<bool, LinkError> {
    match link.send(payload) {
        Ok(redundant) => {
            counters.note_redundancy(redundant);
            Ok(redundant > 0)
        }
        Err(LinkError::PayloadTooLarge { needed, budget }) => {
            tracing::debug!(
                needed,
                budget,
                "datagram refused by a shrunken path; will re-carry"
            );
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// Logs a link ending for ordinary reasons (peer closed, transport error) at a
/// low level — these are expected over a game's life, not faults.
pub(super) fn log_link_closed(key: &SessionKey, slot: SlotId, error: &LinkError) {
    tracing::info!(
        tenant = key.tenant.as_ref(),
        session = key.session.0,
        slot = slot.0,
        %error,
        "client link closed",
    );
}

/// Whether an active-game receive should refresh this client's path sample.
/// Transport dedup leaves both ack-only packets and packets containing only
/// redundant payloads with an empty `fresh` slice; neither represents new game
/// progress, while any fresh payload makes one sample for the whole datagram
/// worthwhile.
#[inline]
pub(in crate::routing) fn should_sample_active_conditions(received: &Received) -> bool {
    !received.fresh.is_empty()
}

/// Samples this client's link: the QUIC path stats that become a
/// [`SlotConditions`] for the mesh sidecar and the decision-maker, plus the
/// recording-only gauges taken from the same snapshot. RTT comes from QUIC's
/// smoothed path estimate (via [`crate::mesh::rtt_us`], which owns the "0 means
/// no measurement" convention); lost/sent are cumulative counters the
/// decision-maker differences between consecutive samples to get a loss rate
/// over the interval. Multipath is disabled, so the default path owns this
/// connection's measurements. An absent path reports zero (no measurement);
/// the decision-maker ignores zero RTT and rejects regressing counters.
///
/// Sent UDP datagrams count individual GSO segments, not socket writes. Once
/// the handshake establishes the counter baseline, each datagram carries one
/// 1-RTT QUIC packet, matching the unit of the lost-packet counter.
pub(super) fn sample_slot_conditions(
    link: &Link,
    slot: SlotId,
    connection_epoch: u64,
) -> SampledLink {
    let path = link
        .connection()
        .path_stats(rally_point_transport::noq::PathId::ZERO)
        .unwrap_or_default();
    SampledLink {
        conditions: SlotConditions {
            slot: u32::from(slot.0),
            rtt_us: crate::mesh::rtt_us(path.rtt),
            lost_packets: path.lost_packets,
            sent_packets: path.udp_tx.datagrams,
            connection_epoch: Some(connection_epoch),
        },
        upstream_lost_packets: link.upstream_lost_packets(),
        cwnd: path.cwnd,
        congestion_events: path.congestion_events,
    }
}

/// One sampling of a client link: the conditions that travel (to the mesh
/// sidecar and the decision-maker) alongside the gauges that only ever land in
/// the flight recording. They are read from one `path_stats()` snapshot so the two
/// always describe the same instant.
pub(super) struct SampledLink {
    pub(super) conditions: SlotConditions,
    upstream_lost_packets: u64,
    cwnd: u64,
    congestion_events: u64,
}
