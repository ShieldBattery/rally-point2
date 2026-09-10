//! The free-function API the turn path calls: every entry point takes
//! `&DecisionMakers`, holds the registry lock for the shortest possible span,
//! and does the logging and notice-sending the pure core does not.
//!
//! Split by the same concerns as `maker`, so a caller-facing function sits
//! beside the method it drives.

use super::*;

mod authority;
mod buffer;
mod departure;
mod leave;
mod silence;
mod start;

pub use authority::{
    FrameRegression, is_authority, observe_delivery, observe_frame, observe_sync,
    observe_turn_frame, session_e2e, set_authority, slot_frame, sync_maker,
};
pub use buffer::{
    active_directive, ingest_local_condition, ingest_local_conditions, ingest_remote_conditions,
    observe_directive, set_own_relay_id,
};
pub use departure::{
    FinalizeOutcome, activate_connection_epoch, claim_close_report, connection_epoch_matches,
    decide_abandoned_departures, departure_epoch, finalize_drop, maker_exists, record_departure,
    record_departure_for_epoch, record_result, remove_slot_for_epoch, reopen_close_report,
    result_for,
};
pub use leave::{
    claim_close_report_with_maker, decide_leave, decided_slots, deregister_maker,
    finalized_drops_enabled, has_reconnectable_departure, has_undecided_departure, leave_reconcile,
    leave_schedulable, normalize_observed_leave, observe_leave, reachable_frame, reinstate_slot,
    session_closed, slot_departed, slot_homed, slot_leave_decided, slot_strictly_homed,
};
pub use silence::{
    SILENCE_CHECK_INTERVAL, note_forward_advance, retained_load_state, retained_load_states,
    run_silence_watch,
};
pub use start::{
    adopt_session_start, commanded_phase_delay, ingest_arrival_phase, mark_session_started,
    maybe_release_region_labels, note_phase_applied, note_slot_present, record_peer_slot_started,
    record_slot_connected, record_slot_started, reevaluate_session_start, released_region_labels,
    session_initial_buffer_turns, session_started, set_region_labels, set_session_shape,
    slot_has_started, started_home_slots, started_session_slot_count,
};

#[cfg(test)]
pub(in crate::consensus) use departure::admit_reconnect_with;
pub(in crate::consensus) use leave::record_leave_event;

pub(crate) use departure::{
    admit_reconnect, mark_connection_down, record_departure_for_epoch_outcome,
};

/// The current wall clock in unix epoch milliseconds — a result report's or a
/// desync's `arrival_ms`/`detected_at_ms` stamp.
pub(in crate::consensus) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
