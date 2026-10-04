//! The rate limit on one link's rollback statistics reports: a burst of
//! [`ROLLBACK_STATS_PER_WINDOW`] at most within any [`ROLLBACK_STATS_WINDOW`]
//! goes to the sample rows, and the newest past it is held for the link's end.

use tokio::time::Instant;

use crate::observability::flight_recorder::ClientRollbackStats;

use super::super::slot_link::{
    ROLLBACK_STATS_PER_WINDOW, ROLLBACK_STATS_WINDOW, RollbackStatsAdmission,
};

#[test]
fn a_link_accepts_a_burst_of_reports_per_window_and_more_once_it_slides() {
    let start = Instant::now();
    let mut admission = RollbackStatsAdmission::default();
    assert!(!admission.any_accepted());

    for _ in 0..ROLLBACK_STATS_PER_WINDOW {
        assert!(admission.admit(start));
    }
    assert!(admission.any_accepted());
    assert!(
        !admission.admit(start + ROLLBACK_STATS_WINDOW / 2),
        "a report past the burst inside the window is refused",
    );
    // A refused report spends nothing: once the window has slid past the
    // burst, reports are accepted again, one per expired acceptance.
    let later = start + ROLLBACK_STATS_WINDOW;
    assert!(admission.admit(later));
    assert!(admission.admit(later));
    assert!(!admission.admit(later + ROLLBACK_STATS_WINDOW / 2));
}

fn stats_through(through_turn: u32) -> ClientRollbackStats {
    ClientRollbackStats {
        through_turn,
        ..ClientRollbackStats::default()
    }
}

#[test]
fn a_report_over_the_rate_limit_is_held_as_the_newest() {
    let start = Instant::now();
    let mut admission = RollbackStatsAdmission::default();
    // A reconnect replays the newest report, a periodic one follows, and the
    // final one comes before the window has slid.
    assert_eq!(
        admission.offer(start, stats_through(1416)),
        Some(stats_through(1416))
    );
    assert_eq!(
        admission.offer(start, stats_through(1440)),
        Some(stats_through(1440))
    );
    assert_eq!(admission.offer(start, stats_through(1464)), None);
    assert_eq!(admission.held(), Some(&stats_through(1464)));
    // A later admitted report is newer than the held one.
    let later = start + ROLLBACK_STATS_WINDOW;
    assert_eq!(
        admission.offer(later, stats_through(1488)),
        Some(stats_through(1488))
    );
    assert_eq!(admission.held(), None);
}
