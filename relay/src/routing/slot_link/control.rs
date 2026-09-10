//! The client's reliable control stream, inbound: the frame-kind dispatch and
//! the two frames with real work behind them - a clean leave-intent and an
//! oversize turn that no datagram on this path could carry.

use super::*;

use crate::consensus::MAX_GAME_RESULT_PAYLOAD_LEN;
use crate::validation::validate_turn;

use super::inbound::log_link_closed;

/// Handles one frame off this client's control stream. `None` means the reader
/// task ended, which costs the relay the only channel a leave-intent or a drop
/// request ever arrives on.
pub(super) fn handle_control_frame(
    link: &mut Link,
    ctx: &mut SlotLinkCtx,
    received: Option<ControlInbound>,
) -> ControlFlow<()> {
    match received {
        // A client only ever *sends* oversize turns up; it never sends
        // a leave (those are relay → client only). Ignore a stray one.
        Some(ControlInbound::Leave(_)) => {
            tracing::warn!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                "ignoring unexpected client-sent leave control frame",
            );
        }
        // Likewise the session-start directive is relay → client only;
        // a client never sends one up. Ignore a stray one, mirroring the
        // leave case above.
        Some(ControlInbound::SessionStart(_)) => {
            tracing::warn!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                "ignoring unexpected client-sent session-start control frame",
            );
        }
        // Connectivity frames are relay → client only; a client never
        // sends one up. Ignore a stray one, mirroring the cases above.
        Some(ControlInbound::Connectivity(_)) => {
            tracing::warn!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                "ignoring unexpected client-sent connectivity control frame",
            );
        }
        // Region labels are relay → client only, and the relay's own
        // copy comes from its coordinator descriptor — a client-sent
        // map is never a source of truth for anything. Ignore a stray
        // one, mirroring the cases above.
        Some(ControlInbound::RegionLabels(_)) => {
            tracing::warn!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                "ignoring unexpected client-sent region-label control frame",
            );
        }
        // Send-phase directives are relay → client only — the relay
        // computes them from its own arrival measurements, and a
        // client-sent one is never an input to anything. Ignore a
        // stray one, mirroring the region-label case above.
        Some(ControlInbound::PhaseDirective(_)) => {
            tracing::warn!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                "ignoring unexpected client-sent send-phase control frame",
            );
        }
        // The client acknowledging that it adopted its send-phase
        // directive. The slot is the authenticated connection's —
        // never a wire claim — and the acknowledgement can release
        // only that slot's own command fence, so this is a
        // client-asserted input with strictly self-scoped effect.
        Some(ControlInbound::PhaseApplied(delay_us)) => {
            consensus::note_phase_applied(&ctx.decision_makers, &ctx.key, ctx.slot, delay_us);
        }
        // The client announcing its own clean departure. The
        // client already flushed its outstanding turns and waited
        // for their acks before sending this, so nothing of its
        // game state is lost by cutting it off right here.
        //
        // Decide the leave immediately rather than waiting for
        // the link to actually die: it gives survivors the
        // "left" reason straight away instead of stalling
        // through the idle-timeout drop path. `break 'serve`
        // right after is the determinism cut this whole
        // mechanism rests on -- this task is the single place
        // that serializes the client's control frames against
        // its datagram turns, so once it has processed the
        // intent, no turn from this slot is forwarded again;
        // every survivor ends up with the identical final-turn
        // prefix and the same apply frame.
        //
        // The post-loop Trigger-A departure pass is skipped for
        // this exit (via `leave_announced`), since the clean
        // departure is announced here with the "left" reason --
        // deregistration, the presence report, and the
        // decision-maker's per-slot cleanup still all run as they
        // would for a dropped client. This client is homed on THIS
        // relay, so its own decision-maker records the departure and,
        // if this relay is the authority, decides the leave; either
        // way the departure is announced to the peer relays as a
        // `SlotDeparted` so their survivors (and the authority, if it
        // is a peer) hear of it.
        Some(ControlInbound::LeaveIntent) => return handle_leave_intent(link, ctx),
        Some(ControlInbound::OversizeTurn(payload)) => {
            return handle_oversize_turn(link, ctx, payload);
        }
        // The client's end-of-game result report. Processed in stream
        // order like any other control frame — a report that arrives
        // before a leave-intent is handled before the intent closes the
        // link — and, unlike the intent, it does not end the link: the
        // client keeps playing (a mid-game defeat report). The bytes are
        // opaque; the relay only enforces the ingress rule and forwards
        // them up the coordinator pipeline. The reporting slot is this
        // authenticated connection's slot, never a value from the
        // payload. An inadmissible payload is dropped without closing
        // the link.
        Some(ControlInbound::GameResult(payload)) => {
            if let Err(reason) = game_result_admissible(&payload) {
                tracing::debug!(
                    tenant = ctx.key.tenant.as_ref(),
                    session = ctx.key.session.0,
                    slot = ctx.slot.0,
                    len = payload.len(),
                    cap = MAX_GAME_RESULT_PAYLOAD_LEN,
                    reason,
                    "dropping inadmissible game-result payload",
                );
            } else {
                consensus::record_result(
                    &ctx.decision_makers,
                    &ctx.key,
                    ctx.slot,
                    payload.to_vec(),
                );
            }
        }
        // The client's report that its game loop has started. Bound
        // to this authenticated connection's slot, never a value
        // from the wire (the frame carries none), stamped against
        // this relay's own timeline, and forwarded up the
        // coordinator pipeline so the tenant can attribute a
        // stalled load to the slots that never got here. At most one
        // per link: a repeat is a logged drop, not a link close —
        // a client repeating a purely informational report is not
        // worth ending a game over.
        Some(ControlInbound::GameStarted) => {
            if ctx.game_started_reported {
                tracing::debug!(
                    tenant = ctx.key.tenant.as_ref(),
                    session = ctx.key.session.0,
                    slot = ctx.slot.0,
                    "dropping repeat game-started report on this link",
                );
            } else {
                ctx.game_started_reported = true;
                ctx.decision_makers.flight_recorder().record(
                    &ctx.key,
                    crate::observability::flight_recorder::FlightEvent::SlotGameStarted {
                        slot: ctx.slot.0,
                    },
                );
                consensus::record_slot_started(&ctx.decision_makers, &ctx.key, ctx.slot);
                // Only this relay hears the report, and every relay
                // serving the session needs it: its silent-slot
                // watch cannot weigh a slot it does not know has
                // left loading behind. Peers record it and stop
                // there -- reporting the load stays this home's job.
                crate::mesh::fan_out_slot_started(&ctx.mesh_links, &ctx.key, ctx.slot);
            }
        }
        // The client's lobby command. Admit it against the relay's
        // per-slot rate cap first — a failure drops the command
        // without closing the link, mirroring chat. An admitted
        // command is bound to the authenticated slot — never the
        // client-asserted `slot` on the wire, exactly as
        // `validate_turn` rebinds a turn's slot — then delivered to
        // local members (appended to the per-session replay log and
        // fanned to every other local member; the author is not
        // echoed, its own game echoes locally) and, only if that
        // delivery was itself admitted (the session's log cap can
        // still refuse it), forwarded once across each mesh link
        // serving the session so peer relays fan it to their
        // locals. The bytes are opaque; the relay frames nothing of
        // its own around them.
        Some(ControlInbound::Lobby(mut command)) => {
            if crate::session::lobby::admit(&ctx.lobby, &ctx.key, ctx.slot) {
                command.slot = u32::from(ctx.slot.0);
                if crate::session::lobby::deliver(&ctx.lobby, &ctx.key, command.clone()) {
                    crate::mesh::fan_out_lobby_command(&ctx.mesh_links, &ctx.key, command);
                }
            }
        }
        // The client's in-game chat message. Admit it against the
        // relay's size and rate caps first — either failure drops
        // the message without closing the link, since a lost chat
        // line is not correctness-critical the way a turn or lobby
        // command is. An admitted message is bound to the
        // authenticated slot — never the client-asserted `slot` on
        // the wire, exactly as a lobby command is — then delivered
        // to local members (no replay log; the author is not
        // echoed) and forwarded once across each mesh link serving
        // the session.
        Some(ControlInbound::Chat(mut chat_msg)) => {
            if crate::session::chat::admit(&ctx.chat, &ctx.key, ctx.slot, chat_msg.text.len()) {
                chat_msg.slot = u32::from(ctx.slot.0);
                crate::session::chat::deliver(&ctx.chat, &ctx.key, chat_msg.clone());
                crate::mesh::fan_out_chat(&ctx.mesh_links, &ctx.key, chat_msg);
            }
        }
        // The client's cosmetic-skin blob. Admit it against the
        // relay's size and rate caps first — either failure drops the
        // blob without closing the link, since a lost skin is cosmetic,
        // not correctness-critical the way a turn or lobby command is.
        // An admitted blob is bound to the authenticated slot — never
        // the client-asserted `slot` on the wire, exactly as a lobby
        // command or chat message is — then delivered to local members
        // (stored in the latest-per-slot map and fanned to every other
        // local member; the author is not echoed) and, only if that
        // delivery was itself admitted (the session's distinct-slot cap
        // can still refuse a brand-new slot), forwarded once across each
        // mesh link serving the session so peer relays store and fan it
        // to their locals. The bytes are opaque; the relay frames
        // nothing of its own around them.
        Some(ControlInbound::Skin(mut skin)) => {
            if crate::session::skin::admit(&ctx.skins, &ctx.key, ctx.slot, skin.payload.len()) {
                skin.slot = u32::from(ctx.slot.0);
                if crate::session::skin::deliver(&ctx.skins, &ctx.key, skin.clone()) {
                    crate::mesh::fan_out_skin(&ctx.mesh_links, &ctx.key, skin);
                }
            }
        }
        // The client's acknowledgement of a load-state fence probe.
        // Bound to this authenticated connection's slot and session,
        // never to anything the frame carries, so no client can ack in
        // another's name. Its arrival is the whole fence: this stream
        // is ordered, and the client writes any `GameStarted` it owes
        // ahead of the ack, so everything of this slot's that the game
        // had signalled is already handled above. An ack for a probe
        // the relay no longer holds — a repeat, or one whose fence
        // already lapsed — resolves nothing and is dropped without
        // closing the link. The epoch is this task's own, so the ack
        // fences the connection the probe was actually written to and
        // never a later one that took the same seat.
        Some(ControlInbound::LoadStateProbeAck(probe_id)) => {
            if !ctx
                .load_fence
                .resolve(probe_id, &ctx.key, ctx.slot, ctx.connection_epoch)
            {
                tracing::debug!(
                    tenant = ctx.key.tenant.as_ref(),
                    session = ctx.key.session.0,
                    slot = ctx.slot.0,
                    probe_id,
                    "dropping a load-state fence ack for an unknown probe",
                );
            }
        }
        // A fence probe only ever travels relay → client; a relay never
        // receives one, so ignore a stray one.
        Some(ControlInbound::LoadStateProbe(_)) => {
            tracing::warn!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                "ignoring unexpected client-sent load-state probe control frame",
            );
        }
        // The client's manual request to drop a disconnected slot. The
        // requester is this authenticated connection's slot, never a
        // value from the wire. Reject silently (log at info, never close
        // the link — a mis-click must not disconnect the requester) when
        // it names itself or a slot this relay has no reason to believe is
        // gone; rate-limit per requester so a double-click storm can't
        // flood the mesh. An accepted request is handled locally (this
        // relay may be the authority) and broadcast to every peer so a
        // peer-homed authority honors it too.
        Some(ControlInbound::RequestDrop(wire_target)) => {
            handle_drop_request(
                &ctx.sessions,
                &ctx.mesh_for_teardown,
                &ctx.key,
                ctx.slot,
                wire_target,
            );
        }
        // The reader task ended: a one-sided stream reset, an
        // over-cap frame, a decode failure, or a clean EOF. This
        // stream is the only channel `RequestDrop` and a clean
        // leave-intent ever arrive on -- unlike the beacon
        // side-channel below (a pure one-way cursor feed whose loss
        // a real link failure surfaces separately via
        // `link.recv()`), nothing else in this loop will ever
        // notice this is gone. Disarming and limping on would
        // silently strand an F10 quit as a drop+hold and lose
        // `RequestDrop` outright, so instead close the connection
        // and let the client's ordinary reconnect path rebuild
        // every stream fresh -- harmless if the connection was
        // already dying for the same reason this reader ended.
        None => {
            tracing::info!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                "control stream reader ended; closing so the client reconnects with fresh streams",
            );
            link.connection().close(
                VarInt::from_u32(CONTROL_STREAM_LOST_CLOSE),
                b"control stream lost",
            );
            return ControlFlow::Break(());
        }
    }
    ControlFlow::Continue(())
}

/// Handles the client's announcement of its own clean departure: retire the
/// generation, announce the "left" departure, and close the link - the
/// confirmation the departing client's driver waits for.
fn handle_leave_intent(link: &mut Link, ctx: &mut SlotLinkCtx) -> ControlFlow<()> {
    tracing::info!(
        tenant = ctx.key.tenant.as_ref(),
        session = ctx.key.session.0,
        slot = ctx.slot.0,
        "client announced clean leave",
    );
    // Retire the active generation before its terminal
    // SlotDeparted is enqueued. A concurrently joining mesh
    // link snapshots this same registry, so it now observes
    // either true(E) before the departure or no active E at
    // all â€” never departure followed by a stale replay-true.
    let _ = crate::mesh::unpublish_conditions(
        &ctx.conditions,
        &ctx.key,
        ctx.slot,
        Some(ctx.connection_epoch),
    );
    // Gated like the teardown announce: a clean leave
    // landing after the session's retirement must not
    // write into swept state.
    let announced = ctx.mesh_for_teardown.gates.with_ingress(&ctx.key, || {
        announce_departure(
            &ctx.drop_holds,
            &ctx.decision_makers,
            &ctx.sessions,
            &ctx.mesh_links,
            &ctx.mesh_for_teardown.provisional_turns,
            &ctx.key,
            ctx.slot,
            LEAVE_REASON_LEFT,
            // The one intent-origin exact count: this
            // handler is the slot's single ingress, it
            // stops forwarding in the same step (`break
            // 'serve` below), and a decided leave refuses
            // readmission, so nothing past this count can
            // ever reach a client. Every other departure
            // origin passes `None` — see `end_slot_link`
            // (a finalized drop's count comes through
            // `finalize_drop`'s own seal instead).
            crate::mesh::forwarded_count(&ctx.mesh_for_teardown.seen, &ctx.key, ctx.slot),
            Some(ctx.connection_epoch),
        )
    });
    // Marked announced only when the announce (or its
    // journal deposit) actually happened: a refused gate
    // or a stood-down announce leaves the teardown's
    // fallback drop-announcement armed as the recovery
    // path rather than silently suppressed.
    ctx.leave_announced = announced == Some(true);
    // The client's driver never expects an ack for the
    // intent itself -- closing the link is the
    // confirmation it waits on, so give it one now
    // rather than leaving the connection to linger
    // until some other path notices it's unused.
    link.connection()
        .close(VarInt::from_u32(LEAVE_PROCESSED_CLOSE), b"leave processed");
    ControlFlow::Break(())
}

/// Handles an oversize turn the client sent over the control stream because no
/// datagram could carry it: the same attacker-facing ingress a datagram turn
/// gets, folded through the link's dedup before it is validated and forwarded.
fn handle_oversize_turn(
    link: &mut Link,
    ctx: &mut SlotLinkCtx,
    payload: Payload,
) -> ControlFlow<()> {
    // A turn larger than any legitimate one can ever be is
    // rejected before it can occupy the count-bounded forward
    // queues (see `MAX_OVERSIZE_TURN_COMMANDS_LEN`). Closing
    // the link — rather than dropping the turn and stranding
    // peers on the seq gap — is the same response a malformed
    // turn gets, and only removes the offending client.
    if payload.commands.len() > MAX_OVERSIZE_TURN_COMMANDS_LEN {
        tracing::warn!(
            tenant = ctx.key.tenant.as_ref(),
            session = ctx.key.session.0,
            slot = ctx.slot.0,
            len = payload.commands.len(),
            cap = MAX_OVERSIZE_TURN_COMMANDS_LEN,
            "rejecting over-cap oversize client turn and closing connection",
        );
        link.connection()
            .close(VarInt::from_u32(INVALID_TURN_CLOSE), b"oversize turn");
        return ControlFlow::Break(());
    }
    // Dedup under the *authorized* slot — the wire slot is a
    // claim the relay never trusts (validate_turn rebinds it
    // the same way on the datagram path), so a lied-about
    // slot can't open a second seq space.
    let fresh = match link.deliver_external(ctx.slot, payload.seq) {
        Ok(fresh) => fresh,
        Err(error) => {
            log_link_closed(&ctx.key, ctx.slot, &error);
            return ControlFlow::Break(());
        }
    };
    if !fresh {
        return ControlFlow::Continue(());
    }
    match validate_turn(ctx.slot, payload) {
        Ok(turn) => {
            let payload = turn.payload;
            ctx.flight_counters.note_validated(payload.seq);
            // NOTE: no frame-observation or
            // desync-comparator call here either —
            // `forward_client_turn` funnels into the one
            // post-dedup consensus feed point,
            // exactly as on the datagram path (see its note
            // above).
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
                "rejecting oversize client turn and closing connection",
            );
            link.connection()
                .close(VarInt::from_u32(INVALID_TURN_CLOSE), b"invalid turn");
            return ControlFlow::Break(());
        }
    }
    ControlFlow::Continue(())
}
