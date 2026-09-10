//! The phases that run before the serve loop: activating the slot under the
//! session's ingress gate, the connect-time control-stream pushes, anchoring a
//! resuming client's receive window, and replaying what it missed.

use super::*;

use super::inbound::sample_slot_conditions;

/// Runs the activation prologue for a freshly registered slot, reporting whether
/// it landed (a session retired mid-activation refuses it and the link is torn
/// down instead of serving).
#[allow(clippy::too_many_arguments)]
pub(super) fn activate_slot(
    link: &Link,
    sessions: &Sessions,
    mesh_for_teardown: &crate::mesh::MeshState,
    mesh_links: &crate::mesh::MeshLinks,
    conditions: &crate::mesh::ConditionsRegistry,
    decision_makers: &Arc<crate::consensus::DecisionMakers>,
    key: &SessionKey,
    slot: SlotId,
    connection_epoch: u64,
    resumed_dial: bool,
) -> bool {
    // The activation prologue runs as ONE ingress critical section: the
    // admission gate (`server.rs`) necessarily released across the
    // handshake-ack await before this task started, so a retirement can land
    // in between — and these mutations would then recreate the close-report,
    // presence, and condition state the sweep just removed, for a session the
    // coordinator already ended. Under the gate, either the sweep waits for
    // this block or this block observes the retirement and the link is torn
    // down instead of serving.
    let activated = mesh_for_teardown.gates.with_ingress(key, || {
        // A slot link is serving this session (again): any session-closed report an
        // earlier emptying latched no longer describes this relay, so the next
        // emptying must report anew. See `consensus::claim_close_report`.
        consensus::reopen_close_report(decision_makers, key);

        // This client joining may change who decides the session's buffer — most
        // notably a first client arriving on the relay that heads the authority
        // order, which turns the descriptor-time verdict into a live one. The
        // roster already includes this slot (registration preceded this task), so
        // report it and re-derive. The peers learn the new count from the mesh
        // drivers' presence reconcile, off the same roster.
        report_own_presence(sessions, mesh_for_teardown, key);

        // Feed an immediate conditions sample from the completed QUIC handshake into
        // the session's decision-maker BEFORE announcing presence, so when this slot
        // completes the expected set and the authority sizes the initial buffer depth,
        // this slot's measured path RTT is already accounted for. A pre-start `ingest`
        // can emit no directive — `decide` bails until a framed turn gives it a
        // consensus coordinate — so this only accumulates state. Publishing it also
        // seeds the mesh sidecar for this slot.
        let handshake_sample = sample_slot_conditions(link, slot, connection_epoch).conditions;
        crate::mesh::activate_conditions(conditions, key, slot, handshake_sample);
        let _ = consensus::ingest_local_condition(decision_makers, key, &handshake_sample);

        // Tell the coordinator this slot's client is here, so the tenant can name
        // who actually arrived instead of inferring it from a load deadline. Fired
        // on every activation (a reconnect included); the coordinator keeps the
        // ever-connected set and dedups the tenant notification itself. Inside the
        // ingress section so a session retired mid-activation reports nothing.
        consensus::record_slot_connected(decision_makers, key, slot, resumed_dial);

        // Announce this slot's presence to the mesh and record it into the session's
        // live-slot set. On the authority relay, this slot completing the descriptor's
        // expected set fires the session-start directive to every slot (local and
        // across the mesh); if the session already started before this slot arrived (a
        // late or reconnecting slot), the directive is re-pushed straight to it. The
        // roster already includes this slot (registration preceded this task), so
        // `fan_out_session_start` reaches it too.
        announce_slot_present(sessions, decision_makers, mesh_links, key, slot);

        // Announce this slot's link as connected to every slot in the session (local
        // and across the mesh), so survivors' connectivity displays reflect it. A
        // pre-start frame (this is the initial dial for most slots) is harmless — a
        // client ignores connectivity until it cares — and a re-register (a later
        // reconnect feature) reuses this same signal. Independent of the session-start
        // and leave paths.
        broadcast_connectivity(
            sessions,
            mesh_links,
            key,
            slot,
            true,
            Some(connection_epoch),
        );
    });
    activated.is_some()
}

/// The pushes a slot gets for state the session reached before its link came up:
/// the region-label map once the release gate has opened, and the send-phase
/// delay the controller already commanded it.
pub(super) fn push_connect_time_state(
    sessions: &Sessions,
    decision_makers: &Arc<crate::consensus::DecisionMakers>,
    key: &SessionKey,
    slot: SlotId,
) {
    // A session whose release gate opened before this slot's link came up has
    // labels every other member already holds, and no later gate opening will
    // fire for it — so push the map straight down this slot. The gate's own
    // fan-out may also have reached this slot (the roster seats it before this
    // task runs), which costs a duplicate frame at worst: each carries the
    // complete map, so a client applies it idempotently. A session whose gate is
    // still shut pushes nothing, and this slot picks the labels up from the
    // fan-out when the gate opens.
    if let Some(labels) = consensus::released_region_labels(decision_makers, key) {
        deliver_region_labels_to_slot(sessions, key, slot, labels);
    }
    // A slot connecting after the phase controller already issued it a delay
    // picks that delay back up, so a reconnecting client resumes the send
    // phase its peers' alignment was computed against instead of snapping back
    // to its natural one. A slot never corrected gets nothing.
    if let Some(delay_us) = consensus::commanded_phase_delay(decision_makers, key, slot) {
        deliver_phase_directive_to_slot(
            sessions,
            key,
            slot,
            PhaseDirective {
                delay_us,
                slew_us_per_s: crate::consensus::phase::SLEW_US_PER_S,
            },
        );
    }
}

/// Anchors a resuming client's own-slot receive window and seeds it with the
/// receipts this relay already holds for the slot. `Break` means the presented
/// anchor was refused and the link has been closed and torn down.
pub(super) fn apply_resume_anchor(
    link: &mut Link,
    ctx: &mut SlotLinkCtx,
    resume_cursors: &mut std::collections::HashMap<SlotId, u64>,
) -> ControlFlow<()> {
    // Anchor this connection's own-slot receive window. A re-homing client presents
    // a cursor for *its own* slot (peers present per-peer cursors; a slot never
    // resumes from itself) whose value is the oldest seq it will re-send — its
    // retention ring's front. This fresh relay's dedup would otherwise base that
    // slot's window at 0 and, once the resumed high-seq stream passed the window,
    // reject it as out-of-window and drop the link — which, because every re-homed
    // slot crosses the window at the same absolute seq, tears down the whole group
    // at once and leaves a later peer death unconfirmable to the survivor. The entry
    // is consumed here because it is an anchor, not a delivery position: the replay
    // below skips this slot by name regardless. Absent (a fresh dial or a peer-only
    // reconnect), this is a no-op and the window bases at 0 as before.
    //
    // The anchor is transport state only: it bases this link's dedup window, and
    // nothing else. It never feeds the slot's final turn count — that comes from
    // the session-level forward gate (`crate::mesh::forwarded_count`), which
    // only ever advances over turns genuinely forwarded — so a fabricated
    // anchor cannot manufacture game state, only break this one connection's
    // own resume.
    if let Some(anchor) = resume_cursors.remove(&ctx.slot) {
        // Reject rather than clamp-and-continue: a client's own-slot anchor
        // this far beyond anything a real session could ever produce is a
        // corrupted or hostile value on a connection that hasn't sent a
        // single turn yet, not a resume worth attempting. Task-isolated to
        // this one connection -- see `MAX_SANE_RESUME_ANCHOR`. This slot may
        // already have been announced present/connected above, so it gets
        // the same full departure/close protocol every other early exit here
        // runs, not a bare return.
        if anchor > MAX_SANE_RESUME_ANCHOR {
            tracing::warn!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                anchor,
                cap = MAX_SANE_RESUME_ANCHOR,
                "resume-cursor anchor exceeds the sane ceiling; refusing the reconnect",
            );
            link.connection().close(
                VarInt::from_u32(RESUME_ANCHOR_INVALID_CLOSE),
                b"resume anchor out of range",
            );
            end_slot_link(
                &ctx.sessions,
                &ctx.mesh_for_teardown,
                &ctx.key,
                ctx.slot,
                ctx.connection_epoch,
                false,
            );
            return ControlFlow::Break(());
        }
        // A lie tripwire, not a gate: an honest anchor never names a seq past
        // what some relay acked to the client, so on this slot's long-term home
        // it sits at or below the forward gate's count. It can legitimately
        // exceed it after a re-home onto a relay whose mesh-forwarded view of
        // the slot lags its old home's acks — by transit gaps at most, roughly
        // a receive window — so anything far past that margin is a client
        // asserting acks for turns that were never forwarded. Warn-only: the
        // count is relay-authored regardless (see the comment above), so a
        // lying anchor gains nothing and hard-rejecting would risk refusing
        // that legitimate lagging-rehome resume.
        if let Some(count) =
            crate::mesh::forwarded_count(&ctx.mesh_for_teardown.seen, &ctx.key, ctx.slot)
            && anchor > count.saturating_add(RESUME_ANCHOR_LIE_MARGIN)
        {
            tracing::warn!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                anchor,
                forwarded_count = count,
                margin = RESUME_ANCHOR_LIE_MARGIN,
                "resume-cursor anchor claims acks far past this relay's forwarded prefix",
            );
        }
        link.anchor_receive_window(ctx.slot, anchor);
        // Reconcile the fresh receive window with the receipts this relay
        // already holds for the slot. The client's anchor is its oldest
        // *unacked* seq, and selective packet acks make its unacked window
        // sparse: a seq above the anchor that was acknowledged to the client
        // will never be re-sent, so without a seed the fresh window's
        // contiguous prefix (and the ack-beacon cursor it drives) would wedge
        // at that hole until the live stream ran a full receive window past
        // the stuck base and the link was rejected as out-of-window.
        //
        // Two session-lifetime stores together cover every seq this relay has
        // ever acknowledged for the slot, across connection churn and every
        // phase of the session's life: the provisional journal (turns
        // accepted before a descriptor named the session; its overflow seals
        // the slot against readmission, so no resumable slot has an evicted
        // entry) and the forward gate's seen registry (every turn that passed
        // the gate, pre-start included — unlike the bounded replay ring, it
        // never evicts). The journal is read BEFORE the gate: a descriptor
        // drain only ever moves entries journal → gate, so a turn in transit
        // is seen by at least one of the two reads.
        for seq in ctx
            .mesh_for_teardown
            .provisional_turns
            .held_turn_seqs(&ctx.key, ctx.slot)
        {
            link.seed_delivered(ctx.slot, seq);
        }
        let receipts = crate::mesh::slot_receipts(&ctx.mesh_for_teardown.seen, &ctx.key, ctx.slot);
        if let Some(through) = receipts.forwarded_through {
            link.seed_delivered_through(ctx.slot, through);
        }
        for seq in receipts.ahead {
            link.seed_delivered(ctx.slot, seq);
        }
    }
    ControlFlow::Continue(())
}

/// Replays what a reconnecting client missed while its link was down: the turns
/// the session recorded past its cursors, then every departure and decided leave
/// it was not connected to hear. `Break` means a write failed and the link has
/// been torn down.
pub(super) async fn replay_to_reconnecting_client(
    ctx: &mut SlotLinkCtx,
    resume_cursors: &std::collections::HashMap<SlotId, u64>,
) -> ControlFlow<()> {
    // Replay to this client the turns the session recorded that it has not already
    // received. Its cursors name a delivery position per peer slot it has heard
    // from; every recorded turn at or past one of those is written down the reliable
    // control stream, oldest-first, and so is every turn from a peer the cursors do
    // not name at all — a peer a client has never heard from is precisely the one
    // whose turns went down the link that just died, and nothing else will carry
    // them again. The client's own slot is never replayed to it. They ride the
    // stream as ordinary oversize-turn frames — the path the client already folds
    // into its per-slot reorder buffer — so the replayed turns splice ahead of the
    // live datagram turns that resume once this loop runs, and the client's per-slot
    // seq ordering holds regardless of which path delivered each turn. Done before
    // the serve loop so no live forward can outrun the replay on the control stream.
    for payload in ctx.turn_ring.replay(&ctx.key, resume_cursors, ctx.slot) {
        if let Err(error) =
            rally_point_transport::control::send_control_turn(&mut ctx.control_send, payload).await
        {
            tracing::info!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                %error,
                "replaying a missed turn to a reconnecting client failed; closing slot link",
            );
            end_slot_link(
                &ctx.sessions,
                &ctx.mesh_for_teardown,
                &ctx.key,
                ctx.slot,
                ctx.connection_epoch,
                ctx.leave_announced,
            );
            return ControlFlow::Break(());
        }
    }

    // Replay the session's leave state the same way: a departure or a decided
    // leave is pushed to each survivor exactly once, at the moment it happens
    // (`broadcast_connectivity`, `fan_out_leave`), so a client whose link was
    // down at that moment never hears it — the turn replay above brings it to
    // the departed slot's last frame, and without the leave directive it then
    // stalls at the next frame forever. The client-side twin of the mesh's
    // `reconcile_leaves_on_join`: every recorded departure replays as a
    // connectivity-down (a departure record at this moment means the slot is
    // genuinely still gone — a re-registered slot's record was reinstated
    // away), and every decided leave replays as the directive itself. Both are
    // idempotent on the client (the leave tracker dedups by slot; connectivity
    // is a level signal), so copies the client already held are harmless, and
    // both skip this slot itself (a slot is never pushed its own departure —
    // and a reconnect for a slot whose own leave was decided was refused at
    // admission). Empty on a fresh dial: no session history, nothing missed.
    let (departures, directives) = consensus::leave_reconcile(&ctx.decision_makers, &ctx.key);
    for (departed, _, _, departed_epoch) in departures {
        if departed == ctx.slot {
            continue;
        }
        if let Err(error) = rally_point_transport::control::send_control_connectivity(
            &mut ctx.control_send,
            departed.0,
            false,
            departed_epoch,
        )
        .await
        {
            tracing::info!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                %error,
                "replaying a departure to a reconnecting client failed; closing slot link",
            );
            end_slot_link(
                &ctx.sessions,
                &ctx.mesh_for_teardown,
                &ctx.key,
                ctx.slot,
                ctx.connection_epoch,
                ctx.leave_announced,
            );
            return ControlFlow::Break(());
        }
    }
    for leave in directives {
        if leave.slot == u32::from(ctx.slot.0) {
            continue;
        }
        let result =
            rally_point_transport::control::send_control_leave(&mut ctx.control_send, leave).await;
        record_leave_control_write(
            &ctx.decision_makers,
            &ctx.key,
            ctx.slot,
            ctx.connection_epoch,
            &leave,
            true,
            result.is_ok(),
        );
        if let Err(error) = result {
            tracing::info!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                %error,
                "replaying a decided leave to a reconnecting client failed; closing slot link",
            );
            end_slot_link(
                &ctx.sessions,
                &ctx.mesh_for_teardown,
                &ctx.key,
                ctx.slot,
                ctx.connection_epoch,
                ctx.leave_announced,
            );
            return ControlFlow::Break(());
        }
    }
    ControlFlow::Continue(())
}
