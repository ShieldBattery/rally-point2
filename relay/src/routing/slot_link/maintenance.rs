//! The serve loop's timer and signal arms: the maintenance flush that keeps a
//! quiet link's acks and retransmits moving, the pre-start conditions sampler,
//! and the two shutdown signals a slot can be woken by.

use super::*;

use std::sync::atomic::Ordering;

use super::inbound::{log_link_closed, sample_slot_conditions, send_packet};

/// The fixed-cadence maintenance flush.
pub(super) fn maintenance_flush(link: &mut Link, ctx: &mut SlotLinkCtx) -> ControlFlow<()> {
    // The fixed-cadence maintenance flush. When a forwarded turn is
    // unacked or we owe acks, send an ack-only packet: it re-carries
    // unacked turns oldest-first (its full budget has room the near-MTU
    // forwarded packets did not) and folds in any acks owed. This is what
    // retransmits a forwarded turn the fresh stream can't re-carry, and
    // what acks a client with no return traffic; it stays silent when
    // nothing is unacked and nothing is owed.
    if ctx.acks_owed || link.payloads_in_flight() > 0 {
        if let Err(error) = send_packet(link, None, &ctx.flight_counters) {
            log_link_closed(&ctx.key, ctx.slot, &error);
            return ControlFlow::Break(());
        }
        ctx.acks_owed = false;
    }
    ctx.flush_deadline = Instant::now() + FLUSH_INTERVAL;
    ControlFlow::Continue(())
}

/// The pre-start conditions sampler's tick.
pub(super) fn resample_pre_start(link: &Link, ctx: &mut SlotLinkCtx) {
    // Pre-start conditions sampler. Lobby traffic rides the reliable
    // control stream, so no datagram arrives to drive the receive-path
    // sampler until the game starts — this keeps each slot's link stats
    // current so the authority's initial-depth computation at coverage
    // reflects live conditions. It stops once the session starts; the
    // receive-driven sampler covers the running game, so nothing is
    // double-sampled.
    if consensus::session_started(&ctx.decision_makers, &ctx.key) {
        ctx.pre_start_sampling = false;
    } else {
        let sample = sample_slot_conditions(link, ctx.slot, ctx.connection_epoch).conditions;
        if crate::mesh::publish_conditions(&ctx.conditions, &ctx.key, ctx.slot, sample) {
            let _ = consensus::ingest_local_condition(&ctx.decision_makers, &ctx.key, &sample);
        }
        ctx.pre_start_deadline = Instant::now() + PRE_START_SAMPLE_INTERVAL;
    }
}

/// Answers the roster's shutdown signal: log and close with the code the
/// signaler's stamped reason picks.
pub(super) fn handle_shutdown(link: &mut Link, ctx: &SlotLinkCtx, close_reason: &AtomicU8) {
    // Something asked for this slot's link to end. Close it and leave;
    // deregistration below then frees the slot, only now that this task is
    // actually gone. The reason the signaler stamped picks the close code:
    // a silenced slot's link was healthy, so saying "isolated" for it would
    // send whoever reads the client's log after the wrong problem.
    match SlotCloseReason::from_raw(close_reason.load(Ordering::Acquire)) {
        SlotCloseReason::SilentSlot => {
            tracing::info!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                "slot stopped producing turns; closing connection",
            );
            link.connection().close(
                VarInt::from_u32(SILENT_SLOT_CLOSE),
                b"slot stopped producing turns",
            );
        }
        SlotCloseReason::Unspecified => {
            tracing::info!(
                tenant = ctx.key.tenant.as_ref(),
                session = ctx.key.session.0,
                slot = ctx.slot.0,
                "isolating lagging slot; closing connection",
            );
        }
    }
}

/// Answers the provisional-admission reap signal.
pub(super) fn handle_provisional_reap(link: &mut Link, ctx: &SlotLinkCtx) {
    // This session was admitted with no applied descriptor and its
    // provisional deadline passed with none arriving. Close with a
    // distinct code so a redialing client can tell this apart from a
    // terminal refusal -- a fresh dial re-admits with its own new
    // provisional window.
    tracing::info!(
        tenant = ctx.key.tenant.as_ref(),
        session = ctx.key.session.0,
        slot = ctx.slot.0,
        "provisional admission expired with no applied descriptor; closing connection",
    );
    link.connection().close(
        VarInt::from_u32(PROVISIONAL_EXPIRED_CLOSE),
        b"provisional admission expired",
    );
    // The teardown below announces (journals) an ordinary
    // dropped departure, exactly like any other link death: the
    // journal is append-only and survives the reap, so if the
    // slot redials (this close is retryable) the drain-time
    // reclaim check stands the stale drop down, and if it never
    // does, the departure drains truthfully once a descriptor
    // arrives — or is retained with the journal, whose retention
    // rule no local fact can safely cut short.
}
