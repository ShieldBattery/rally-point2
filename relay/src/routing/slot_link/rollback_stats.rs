//! A rollback client's statistics reports, inbound: admitted at a bounded rate
//! and size, bound to the link's own slot, and kept for the flight recording,
//! whose sample rows carry the latest and whose disconnect carries the last.

use super::*;

use rally_point_proto::messages::RollbackStats;

use crate::observability::flight_recorder::ClientRollbackStats;

/// How many statistics reports one link admits to the slot's sample rows within
/// [`ROLLBACK_STATS_WINDOW`]. A client reports every half minute or so and once
/// more at game end, which can land right behind a periodic report, so two fit.
/// A report past them (a reconnect replays the newest report, so a periodic one
/// and the final one can follow it inside one window) is held on the link rather
/// than dropped, since it may be the newest the client ever sends.
pub(in crate::routing) const ROLLBACK_STATS_PER_WINDOW: usize = 2;

/// The window [`ROLLBACK_STATS_PER_WINDOW`] counts reports over.
pub(in crate::routing) const ROLLBACK_STATS_WINDOW: Duration = Duration::from_secs(5);

/// The most entries either of a report's histograms may hold. The layout's
/// histograms have a dozen or so entries; this leaves room for a later layout
/// to widen them while keeping what a recording stores per slot small.
pub(super) const MAX_ROLLBACK_STATS_HISTOGRAM_LEN: usize = 64;

/// When one link last accepted statistics reports, oldest first, and the newest
/// report the rate limit held back since the last it admitted.
#[derive(Debug, Default)]
pub(in crate::routing) struct RollbackStatsAdmission {
    accepted: [Option<Instant>; ROLLBACK_STATS_PER_WINDOW],
    held: Option<ClientRollbackStats>,
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

    /// Takes a report arriving at `now`: returns it to go to the slot's sample
    /// rows if the rate limit admits it, and otherwise holds it, as the newest,
    /// until the link ends or a later report is admitted.
    pub(in crate::routing) fn offer(
        &mut self,
        now: Instant,
        stats: ClientRollbackStats,
    ) -> Option<ClientRollbackStats> {
        if self.admit(now) {
            self.held = None;
            Some(stats)
        } else {
            self.held = Some(stats);
            None
        }
    }

    /// The report the link held back, newer than any it admitted.
    pub(in crate::routing) fn held(&self) -> Option<&ClientRollbackStats> {
        self.held.as_ref()
    }
}

/// Handles a statistics report off this client's control stream. The report is
/// the client's account of its own game, bound to this authenticated
/// connection's slot (the frame names none), and only ever recorded: nothing
/// decides on it. So a report that is outside a rollback session or too large
/// is dropped without closing the link, and one over the rate limit is held on
/// the link (see [`ROLLBACK_STATS_PER_WINDOW`]).
pub(super) fn handle_rollback_stats(ctx: &mut SlotLinkCtx, stats: RollbackStats) {
    let longest = stats
        .rollback_histogram
        .len()
        .max(stats.pipe_histogram.len());
    let refusal = if longest > MAX_ROLLBACK_STATS_HISTOGRAM_LEN {
        Some("a histogram is too long")
    } else if !ctx.decision_makers.rollback_enabled(&ctx.key) {
        Some("the session does not roll back")
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
    match ctx.rollback_stats.offer(Instant::now(), stats.into()) {
        Some(stats) => ctx.flight_counters.note_rollback_stats(stats),
        None => tracing::debug!(
            tenant = ctx.key.tenant.as_ref(),
            session = ctx.key.session.0,
            slot = ctx.slot.0,
            "holding a rollback-stats report over the link's rate limit",
        ),
    }
}

/// Records the slot's latest statistics as one flight event as its link ends,
/// if this link accepted any: the report the rate limit held back if there is
/// one, since it is newer than any admitted. The final report rides in just
/// ahead of the leave intent, so no sample row would ever show it.
pub(super) fn record_final_rollback_stats(ctx: &SlotLinkCtx) {
    if !ctx.rollback_stats.any_accepted() {
        return;
    }
    let stats = match ctx.rollback_stats.held() {
        Some(held) => Some(held.clone()),
        None => ctx.flight_counters.rollback_stats(),
    };
    if let Some(stats) = stats {
        ctx.decision_makers.flight_recorder().record(
            &ctx.key,
            crate::observability::flight_recorder::FlightEvent::SlotRollbackStats {
                slot: ctx.slot.0,
                stats,
            },
        );
    }
}
