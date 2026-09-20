//! The pre-connect tie-break that decides which relay of a pair dials.
//!
//! Small and self-contained: `should_dial_mesh` touches no link state, so
//! its cases sit apart from the tests that need a live connection.

use super::*;

#[test]
fn only_the_lower_relay_id_of_a_pair_dials() {
    // The lower id dials the higher: that side connects, the peer accepts and
    // does not dial back. Two relays carrying the same id is a
    // misconfiguration, and there the rule matters most — neither dials,
    // rather than both racing to connect.
    for (ours, peer, expected) in [
        (RelayId(1), RelayId(2), true),
        (RelayId(2), RelayId(1), false),
        (RelayId(5), RelayId(5), false),
    ] {
        assert_eq!(
            should_dial_mesh(ours, peer),
            expected,
            "our id {ours:?} against peer {peer:?}",
        );
    }
}
