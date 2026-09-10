//! The pre-connect tie-break that decides which relay of a pair dials.
//!
//! Small and self-contained: `should_dial_mesh` touches no link state, so
//! its cases sit apart from the tests that need a live connection.

use super::*;

#[test]
fn should_dial_mesh_is_true_when_our_id_is_lower() {
    // The lower id dials the higher: this side connects, the peer accepts.
    assert!(should_dial_mesh(RelayId(1), RelayId(2)));
}

#[test]
fn should_dial_mesh_is_false_when_our_id_is_higher() {
    // The higher id waits to accept — it does not dial back.
    assert!(!should_dial_mesh(RelayId(2), RelayId(1)));
}

#[test]
fn should_dial_mesh_is_false_for_equal_ids() {
    // Two relays with the same id is a misconfiguration: neither dials
    // rather than both racing to connect.
    assert!(!should_dial_mesh(RelayId(5), RelayId(5)));
}
