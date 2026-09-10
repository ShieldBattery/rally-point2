//! The turn-delivery half: client-originated forwarding (dedup, stamping,
//! local fan-out, then the mesh), mesh-origin delivery that stops at the local
//! clients, and the per-link sends that carry a turn or a resume replay out.

use std::collections::HashMap;

use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::{LinkConditions, MeshControlFrame, Payload, mesh_control_frame};

use crate::routing::{self, SessionKey};

use super::conditions::{ConditionsRegistry, snapshot_conditions};
use super::links::{MESH_STREAM_WRITE_TIMEOUT, SessionState};
use super::seen::{Seen, SeenRegistries, mark_seen};
use super::{MeshState, fan_out_to_mesh, mesh_session_key};

/// Forwards one turn received from a local client: session-level dedup,
/// buffer-directive stamping, then fan-out to local slots and every peer relay
/// serving the session.
///
/// Mesh-origin turns use `deliver_mesh_turn` instead. Keeping the two ingress
/// APIs separate makes the one-mesh-hop rule structural: a payload received
/// from a peer relay can reach this relay's local clients, but cannot be handed
/// back to the mesh.
///
/// Stamping is stamp-or-preserve: when this relay's decision-maker has an
/// active directive (it is the session's authority), the directive is set on
/// the outgoing payload; when it has none — every non-authority relay, always
/// — a stamp already on the turn is left untouched, so the authority's
/// broadcast survives the hop across relays that merely forward it.
pub fn forward_client_turn(
    sessions: &routing::Sessions,
    mesh: &MeshState,
    key: &SessionKey,
    slot: SlotId,
    payload: Payload,
) {
    // On a coordinator-managed relay, a session with no decision-maker is a
    // session no descriptor has named here yet — and until one does, the
    // relay cannot tell a current slot from one that already departed with an
    // exact final turn count (a re-homed group's dial racing its resumed
    // descriptor). A departed slot's turn fanned out in that window is a turn
    // past the leave's synchronization point, consumed by co-admitted
    // survivors but by no one else. Journal every pre-descriptor turn
    // instead; descriptor application drains the journal back through this
    // function, where the seeded decided-leave fence below sorts current
    // from departed. The maker check and the deposit run inside the
    // session's ingress gate (a racing retirement, which discards the
    // journal, cannot have this recreate entries for an ended session), and
    // the journal's one-shot resolved mark makes the pair atomic against the
    // descriptor's single drain: a deposit that loses that race is refused
    // and re-runs here against the maker that now provably exists.
    let payload = if mesh.provisional_turns.armed() {
        use crate::session::provisional_turns::{HoldOutcome, PennedIngress};
        enum Funnel {
            Proceed(Payload),
            Held,
            Overflow,
        }
        let Some(verdict) = mesh.gates.with_ingress(key, || {
            if crate::consensus::maker_exists(&mesh.decision_makers, key) {
                return Funnel::Proceed(payload);
            }
            match mesh
                .provisional_turns
                .hold(key, PennedIngress::Turn(slot, payload))
            {
                HoldOutcome::Held => Funnel::Held,
                HoldOutcome::Resolved(PennedIngress::Turn(_, payload)) => Funnel::Proceed(payload),
                HoldOutcome::Resolved(PennedIngress::Departure { .. }) => {
                    unreachable!("a turn deposit is echoed back as a turn")
                }
                HoldOutcome::Overflow(_) => Funnel::Overflow,
            }
        }) else {
            // Retired: dropped exactly like the gated delivery below would.
            return;
        };
        match verdict {
            Funnel::Proceed(payload) => payload,
            Funnel::Held => return,
            Funnel::Overflow => {
                // The overflowed turn was already transport-acknowledged and
                // a same-relay resume deliberately does not re-inject
                // acknowledged retention — it is genuinely unrecoverable, so
                // the slot that produced it now has a permanent hole in its
                // accepted sequence. `hold` already sealed the slot against
                // readmission, atomically with this verdict and inside the
                // ingress gate (an ordinary link close is reconnectable, and
                // a resume would carry on past the hole, cementing the
                // divergence — or retransmit into the still-full journal in
                // a close loop). All that remains is closing its link, whose
                // teardown journals a dropped departure the survivors
                // resolve through the drop flow once the descriptor lands.
                // The rest of the session's journal is untouched — only the
                // offender pays.
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    "provisional journal overflowed; the slot is sealed — closing its link",
                );
                routing::close_slots(sessions, key, std::slice::from_ref(&slot));
                return;
            }
        }
    } else {
        payload
    };
    // Terminal fence for this relay's own homed ingress: a slot whose synced
    // leave is decided has ended its participation — nothing it originates
    // afterward is part of the game, and a turn that entered the mesh here
    // could be consumed by a survivor that had not yet applied the leave,
    // diverging it from the survivors that did. The clean-leave intent
    // already stops its slot's forwarding in the same step it decides, but a
    // descriptor-seeded departure decides a slot that may still hold a live
    // (provisionally admitted) link, and a decided slot's zombie link can
    // outlive its decision in general. Mesh-delivered turns are deliberately
    // NOT fenced ([`deliver_mesh_turn`]): a peer home forwarded them before
    // the decision reached it, and local survivors may still need them to
    // reach a clean leave's exact count.
    if crate::consensus::slot_leave_decided(&mesh.decision_makers, key, slot) {
        tracing::debug!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            slot = slot.0,
            "dropping a turn from a slot whose leave is decided",
        );
        return;
    }
    let delivered = mesh.gates.with_ingress(key, || {
        deliver_turn_to_locals(
            sessions,
            &mesh.seen,
            &mesh.decision_makers,
            &mesh.turn_ring,
            key,
            slot,
            payload,
            crate::consensus::delivery::DeliveryHome::Local,
        )
    });
    if let Some(Some(payload)) = delivered {
        fan_out_to_mesh(&mesh.links, key, payload);
    }
}

/// Delivers one turn received from `peer` to this relay's local clients and
/// stops it there. Relay-origin payloads are one mesh hop only and must never
/// be re-forwarded to either their ingress peer or another relay — this
/// function reaches only the local delivery path, never `fan_out_to_mesh`.
pub(crate) fn deliver_mesh_turn(
    sessions: &routing::Sessions,
    mesh: &MeshState,
    key: &SessionKey,
    slot: SlotId,
    payload: Payload,
    peer: RelayId,
) {
    // The ingress gate makes the delivery's per-session mutations (the seen
    // gate, frame observation, the turn ring) atomic against a concurrent
    // retirement sweep — a retired session's mesh turns are dropped here.
    // Recursive-read, so the mesh-control dispatch arm that funnels an
    // oversize turn through this path re-enters its own session's gate.
    let _ = mesh.gates.with_ingress(key, || {
        deliver_turn_to_locals(
            sessions,
            &mesh.seen,
            &mesh.decision_makers,
            &mesh.turn_ring,
            key,
            slot,
            payload,
            crate::consensus::delivery::DeliveryHome::Peer(peer),
        )
    });
}

/// The shared local-delivery half of [`forward_client_turn`] and
/// [`deliver_mesh_turn`]: session-level dedup, buffer-directive stamping, and
/// fan-out to this relay's local slots. Returns the possibly stamped payload
/// when it was fresh so client ingress can send it to peer relays, or `None`
/// for a duplicate already delivered through another ingress instance. `home`
/// feeds both the delivery-tracking home stamp and the replay ring's
/// [`crate::session::turn_ring::TurnOrigin`].
// Eight references, one over clippy's default: bundling them into a struct
// would touch every call site (production and test) for one parameter's worth
// of churn, the same trade `SyncTracker::record` in `consensus/mod.rs` and
// `connect_and_stream` in `coordinator/client.rs` make.
#[allow(clippy::too_many_arguments)]
pub(super) fn deliver_turn_to_locals(
    sessions: &routing::Sessions,
    seen: &SeenRegistries,
    decision_makers: &crate::consensus::DecisionMakers,
    turn_ring: &crate::session::turn_ring::TurnRing,
    key: &SessionKey,
    slot: SlotId,
    mut payload: Payload,
    home: crate::consensus::delivery::DeliveryHome,
) -> Option<Payload> {
    let forwarded = mark_seen(seen, key, slot, payload.seq);
    if forwarded.seen == Seen::Duplicate {
        // Only the duplicate branch touches the recorder's maps —
        // the fresh-turn common path stays lock-free for the recorder.
        decision_makers.flight_recorder().note_dedup_drop(key, slot);
        return None;
    }
    if forwarded.prefix_advanced {
        // The relay's own record that this slot's simulation is still feeding
        // local lockstep, in order. Progress is taken here rather than from the
        // turn itself because a client picks what it sends and when, so any
        // count or stamp it supplies can be padded; only the turns it actually
        // produced move this prefix.
        crate::consensus::note_forward_advance(decision_makers, key, slot);
    }
    // The frame observation's one and only feed point, right after the
    // `mark_seen` dedup, for the same reason as the desync comparator just
    // below: link replacement, resume replay, and slot re-home overlap can
    // present the same turn more than once. The per-slot frame max is a harmless
    // monotone, but the seq-keyed frame *history* behind the leave-frame clamp
    // is a bounded append — duplicates walked twice would evict genuine history
    // and shrink the clamp's window. Lobby turns
    // carry no frame and don't move the consensus coordinate. Every turn here
    // was validated at its ingress client edge (the mesh never re-validates),
    // so only validated turns feed the coordinate.
    if let Some(frame) = payload.game_frame_count {
        crate::consensus::observe_turn_frame(
            decision_makers,
            key,
            slot,
            payload.seq,
            rally_point_proto::ids::GameFrameCount(frame),
            home,
        );
    }
    // The region-label release gate, evaluated here so it is checked only while
    // turns are actually flowing — no timer task, and a session that goes quiet
    // simply stops asking. It reads this relay's own clock and its own start
    // latch, and deliberately nothing out of `payload`: it sits OUTSIDE the frame
    // block above because a turn's `game_frame_count` is a client-asserted claim,
    // and this function delivers turns that originated at other relays too, so
    // keying the gate on one would let a single client open it on every relay
    // serving the session — its opponents' home relays included. The map comes
    // back on the one call that opens the gate, so the labels fan out to this
    // relay's local slots exactly once.
    if let Some(labels) = crate::consensus::maybe_release_region_labels(decision_makers, key) {
        routing::fan_out_region_labels(sessions, key, &labels);
    }
    // The desync comparator's one and only feed point. Every turn-delivery
    // path — client edge (datagram and oversize-control), mesh datagram, and
    // mesh oversize-control — funnels through here, and this is placed right
    // after the `mark_seen` dedup above. The comparator's per-slot ordinal
    // count is not idempotent the way `observe_frame`'s monotone max is — a
    // duplicate walked twice would silently drift the count and misalign
    // every later comparison. A no-op unless this relay is the session
    // authority.
    crate::consensus::observe_sync(
        decision_makers,
        key,
        slot,
        payload.game_frame_count,
        &payload.commands,
    );
    match crate::consensus::active_directive(decision_makers, key) {
        Some(directive) => payload.buffer_directive = Some(directive),
        // Preserving an upstream stamp also records its seq and buffer: an
        // authority's locally originated turns carry its directive directly to
        // every relay serving the session, so if this
        // relay is later promoted to authority, its own decisions number above
        // what clients already hold and baseline against the committed buffer
        // instead of restarting below it.
        None => {
            if let Some(incoming) = &payload.buffer_directive {
                crate::consensus::observe_directive(decision_makers, key, incoming);
            }
        }
    }
    // NOTE: player-leaves are NOT stamped here. A leave is delivered over the
    // reliable control stream (the relay pushes it to each surviving client), not
    // the turn envelope — a drop stops the turn stream, so an envelope stamp would
    // never reach the survivors it must unstall. See `routing`'s leave trigger.
    routing::fan_out(sessions, key, slot, payload.clone());
    // Record the fanned turn into the session's replay ring so a client that drops
    // and re-dials while its drop is undecided can be replayed what it missed. This is the one
    // choke point every turn-delivery path funnels through, placed right after the
    // `mark_seen` dedup, so each distinct `(slot, seq)` is recorded exactly once
    // even when ingress overlap presents a redundant copy. Buffered only once the
    // session has started: pre-start lobby traffic has its own ordered replay log
    // and must not be double-buffered here. The session's slot count rides along
    // so the ring's bounds fit the session's actual shape rather than assuming
    // the largest possible game.
    if let Some(slots) = crate::consensus::started_session_slot_count(decision_makers, key) {
        let origin = match home {
            crate::consensus::delivery::DeliveryHome::Local => {
                crate::session::turn_ring::TurnOrigin::Local
            }
            crate::consensus::delivery::DeliveryHome::Peer(_) => {
                crate::session::turn_ring::TurnOrigin::Mesh
            }
        };
        turn_ring.record(key, &payload, origin, slots);
    }
    Some(payload)
}

/// Whether `frame` is a resume-cursor ask, and if so, the local-origin turns
/// this relay's own client edge produced that the peer's cursors say it's
/// still missing, paired with the session they belong to. `None` for any
/// other frame kind, a session this link hasn't joined, or a resume ask this
/// relay has nothing to answer (an empty replay list — the ordinary case for
/// a session with no locally-homed slots). The frame's own `resuming` flag
/// governs a slot absent from its cursors — see
/// [`crate::session::turn_ring::TurnRing::replay_local`]'s doc for the two meanings
/// that carries.
///
/// Reads straight from the turn ring rather than mutating any session state,
/// so — unlike [`dispatch_mesh_control`] — this never needs to run inside
/// that function; [`run_mesh_link`]'s own select branch calls it separately,
/// before the dispatch, because the reply it computes has to go out over
/// *this* link directly (see [`send_resume_replay`]), which `dispatch_mesh_control`
/// has no way to do.
pub(super) fn resume_replay_for_frame(
    frame: &MeshControlFrame,
    joined: &HashMap<SessionId, SessionState>,
    mesh: &MeshState,
) -> Option<(SessionKey, Vec<Payload>)> {
    let Some(mesh_control_frame::Kind::MeshResumeCursors(resume)) = &frame.kind else {
        return None;
    };
    let key = joined.get(&SessionId(frame.session))?.key.clone();
    let cursors: HashMap<SlotId, u64> = resume
        .cursors
        .iter()
        .filter_map(|c| {
            u8::try_from(c.origin_slot)
                .ok()
                .map(|s| (SlotId(s), c.next_seq))
        })
        .collect();
    let payloads = mesh.turn_ring.replay_local(&key, &cursors, resume.resuming);
    (!payloads.is_empty()).then_some((key, payloads))
}

/// Sends one turn over `link`'s datagram path for `key`'s session, diverting
/// to the reliable control stream when it doesn't fit — mirroring the client
/// edge's own oversize divert. Shared by a freshly forwarded turn and a
/// resume-cursor replay, so a replayed turn enters the link's `AckManager` and
/// rides its redundancy exactly like a live one: no special bypass a live
/// send doesn't also go through. `context` only labels the failure log
/// (`"forward"` or `"resume replay"`); the send logic itself is identical
/// either way.
///
/// Returns `Some(carried_redundancy)` while the link is still good. The
/// redundancy bit lets the caller defer this session's maintenance flush just
/// as the client edge does: a live stream already re-carrying unacked turns
/// needs no extra packet. `None` is the caller's cue to close the link. A
/// payload that slips past the divert pre-check as oversize is logged and
/// treated as delivered (there is nothing to retry it with), not a link
/// failure, and reports that it carried no redundancy.
pub(super) async fn send_turn_over_link(
    link: &mut rally_point_transport::MeshLink,
    control_send: &mut rally_point_transport::noq::SendStream,
    key: &SessionKey,
    payload: Payload,
    conditions: Option<LinkConditions>,
    context: &'static str,
) -> Option<bool> {
    let session_id = key.session;
    let fits = match link.payload_fits(&payload, conditions.as_ref(), Some(key.tenant.as_ref())) {
        Ok(fits) => fits,
        Err(error) => {
            tracing::info!(%error, context, "mesh send failed; closing link");
            return None;
        }
    };
    if !fits {
        tracing::debug!(
            tenant = key.tenant.as_ref(),
            session = key.session.0,
            slot = payload.slot,
            seq = payload.seq,
            context,
            "diverting oversize turn to the mesh control stream",
        );
        let frame = MeshControlFrame {
            session: session_id.0,
            kind: Some(mesh_control_frame::Kind::OversizeTurn(payload)),
        };
        // Deadline-bounded like every reliable-stream write the driver makes
        // inline: a peer that stops reading its control receive-half would
        // otherwise suspend the whole driver loop on this write indefinitely.
        // See `MESH_STREAM_WRITE_TIMEOUT`.
        match tokio::time::timeout(
            MESH_STREAM_WRITE_TIMEOUT,
            rally_point_transport::mesh_control_stream::send_mesh_control_frame(
                control_send,
                &frame,
            ),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::info!(%error, context, "mesh control send failed; closing link");
                return None;
            }
            Err(_) => {
                tracing::warn!(context, "mesh control send stalled; closing link");
                return None;
            }
        }
        return Some(false);
    }
    match link.send(mesh_session_key(key), Some(payload), conditions) {
        Ok(redundant) => Some(redundant > 0),
        // The pre-check above diverts anything that can never ride this
        // session's datagrams, so this arm is the transient case: noq's
        // concurrently-running connection driver moved the live path budget
        // between the check and the send, or a conditions sidecar crowded a
        // floor-admitted turn out of a fallen-back datagram. Recoverable, not
        // a loss: the send layer registered the fresh turn before the wire
        // refused the bundle and recorded no carry, so returning
        // "no redundancy" here leaves the maintenance flush armed and its
        // sidecar-free packet re-carries the turn.
        Err(rally_point_transport::MeshLinkError::PayloadTooLarge { needed, budget }) => {
            tracing::debug!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                needed,
                budget,
                context,
                "bundle outgrew the live datagram budget; the flush re-carries it",
            );
            Some(false)
        }
        Err(error) => {
            tracing::info!(%error, context, "mesh send failed; closing link");
            None
        }
    }
}

/// Sends every payload in `payloads` over `link`'s datagram path for `key`, in
/// order, stopping at the first link-fatal failure — the resume-reply analog
/// of the live forward branch's own per-turn send, going straight out this
/// link rather than through the shared, `try_send`-based forward queue: a
/// large replay pumped through that bounded queue could itself fill it and
/// trip the very full-queue reset this exists to recover from. Samples the
/// outgoing conditions sidecar once for the whole batch — a backlog
/// catch-up burst does not need per-turn-fresh telemetry — rather than
/// resampling for each payload. Returns `Some(carried_redundancy)` when every
/// payload sent (or was diverted), where the bit is true if any send in the
/// replay re-carried an unacked turn; `None` means a link-fatal error.
pub(super) async fn send_resume_replay(
    link: &mut rally_point_transport::MeshLink,
    control_send: &mut rally_point_transport::noq::SendStream,
    conditions: &ConditionsRegistry,
    key: &SessionKey,
    payloads: Vec<Payload>,
) -> Option<bool> {
    let outgoing = snapshot_conditions(conditions, key);
    let mut carried_redundancy = false;
    for payload in payloads {
        let sent_redundancy = send_turn_over_link(
            link,
            control_send,
            key,
            payload,
            outgoing.clone(),
            "resume replay",
        )
        .await?;
        carried_redundancy |= sent_redundancy;
    }
    Some(carried_redundancy)
}
