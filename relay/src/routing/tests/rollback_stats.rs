//! The rate limit on one link's rollback statistics reports: a burst of
//! [`ROLLBACK_STATS_PER_WINDOW`] at most within any [`ROLLBACK_STATS_WINDOW`].

use tokio::time::Instant;

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
