//! A rollback client's statistics reports, inbound: admitted at a bounded rate
//! and size, bound to the link's own slot, and kept for the flight recording,
//! whose sample rows carry the latest and whose disconnect carries the last.

use super::*;

use rally_point_proto::messages::RollbackStats;

/// How many statistics reports one link accepts within
/// [`ROLLBACK_STATS_WINDOW`]. A client reports every half minute or so and once
/// more at game end, which can land right behind a periodic report, so two fit;
/// more than that is a client misbehaving, and its extras are dropped.
pub(in crate::routing) const ROLLBACK_STATS_PER_WINDOW: usize = 2;

/// The window [`ROLLBACK_STATS_PER_WINDOW`] counts reports over.
pub(in crate::routing) const ROLLBACK_STATS_WINDOW: Duration = Duration::from_secs(5);

/// The most entries either of a report's histograms may hold. The layout's
/// histograms have a dozen or so entries; this leaves room for a later layout
/// to widen them while keeping what a recording stores per slot small.
pub(super) const MAX_ROLLBACK_STATS_HISTOGRAM_LEN: usize = 64;

/// When one link last accepted statistics reports, oldest first: the rate
/// limit's whole state.
#[derive(Debug, Default)]
pub(in crate::routing) struct RollbackStatsAdmission {
    accepted: [Option<Instant>; ROLLBACK_STATS_PER_WINDOW],
}

impl RollbackStatsAdmission {
    /// Admits a report arriving at `now`, noting it, unless the link already
    /// accepted [`ROLLBACK_STATS_PER_WINDOW`] within the window before it.
    pub(in crate::routing) fn admit(&mut self, now: Instant) -> bool {
        if let Some(oldest) = self.accepted[0]
            && now.saturating_duration_since(oldest) < ROLLBACK_STATS_WINDOW
        {
            return false;
        }
        self.accepted.rotate_left(1);
        self.accepted[ROLLBACK_STATS_PER_WINDOW - 1] = Some(now);
        true
    }

    /// Whether this link has accepted any report.
    pub(in crate::routing) fn any_accepted(&self) -> bool {
        self.accepted.iter().any(Option::is_some)
    }
}

/// Handles a statistics report off this client's control stream. The report is
/// the client's account of its own game, bound to this authenticated
/// connection's slot (the frame names none), and only ever recorded: nothing
/// decides on it. So a report that is outside a rollback session, too large, or
/// over the rate limit is dropped without closing the link.
pub(super) fn handle_rollback_stats(ctx: &mut SlotLinkCtx, stats: RollbackStats) {
    let longest = stats
        .rollback_histogram
        .len()
        .max(stats.pipe_histogram.len());
    let refusal = if longest > MAX_ROLLBACK_STATS_HISTOGRAM_LEN {
        Some("a histogram is too long")
    } else if !ctx.decision_makers.rollback_enabled(&ctx.key) {
        Some("the session does not roll back")
    } else if !ctx.rollback_stats.admit(Instant::now()) {
        Some("the link is over its rate limit")
    } else {
        None
    };
    if let Some(reason) = refusal {
        tracing::debug!(
            tenant = ctx.key.tenant.as_ref(),
            session = ctx.key.session.0,
            slot = ctx.slot.0,
            reason,
            "dropping a rollback-stats report",
        );
        return;
    }
    ctx.flight_counters.note_rollback_stats(stats.into());
}

/// Records the slot's latest statistics as one flight event as its link ends,
/// if this link accepted any. The final report rides in just ahead of the leave
/// intent, so no sample row would ever show it.
pub(super) fn record_final_rollback_stats(ctx: &SlotLinkCtx) {
    if !ctx.rollback_stats.any_accepted() {
        return;
    }
    if let Some(stats) = ctx.flight_counters.rollback_stats() {
        ctx.decision_makers.flight_recorder().record(
            &ctx.key,
            crate::observability::flight_recorder::FlightEvent::SlotRollbackStats {
                slot: ctx.slot.0,
                stats,
            },
        );
    }
}
