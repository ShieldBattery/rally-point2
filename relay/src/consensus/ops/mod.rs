//! The free-function API the turn path calls: every entry point takes
//! `&DecisionMakers`, holds the registry lock for the shortest possible span,
//! and does the logging and notice-sending the pure core does not.
//!
//! Split by the same concerns as `maker`, so a caller-facing function sits
//! beside the method it drives.

use super::*;

mod departure;

pub use departure::{
    FinalizeOutcome, activate_connection_epoch, claim_close_report, connection_epoch_matches,
    decide_abandoned_departures, departure_epoch, finalize_drop, maker_exists, record_departure,
    record_departure_for_epoch, record_result, remove_slot_for_epoch, reopen_close_report,
    result_for,
};

pub(crate) use departure::{
    mark_connection_down, record_departure_for_epoch_outcome, resolve_reconnect,
};
