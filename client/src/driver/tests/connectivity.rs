//! The connectivity-epoch fence: which relay-stamped link-lifecycle changes
//! the driver admits, and what a final synced leave makes terminal.

use super::*;

#[test]
fn connectivity_epoch_fence_makes_down_terminal_until_a_new_epoch_opens() {
    let slot = SlotId(3);
    let mut states = ConnectivityEpochStates::default();
    let terminal = HashSet::new();

    assert!(admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        true,
        Some(11),
    ));
    assert!(admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        false,
        Some(11),
    ));
    assert!(!admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        true,
        Some(11),
    ));
    assert!(admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        true,
        Some(22),
    ));
    assert!(!admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        false,
        Some(11),
    ));
    assert!(!admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        false,
        None,
    ));
    assert!(admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        false,
        Some(22),
    ));
}

#[test]
fn delayed_retired_true_cannot_replace_the_live_client_epoch() {
    let slot = SlotId(3);
    let mut states = ConnectivityEpochStates::default();
    let terminal = HashSet::new();

    assert!(admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        true,
        Some(11),
    ));
    assert!(admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        false,
        Some(11),
    ));
    assert!(admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        true,
        Some(22),
    ));

    assert!(!admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        true,
        Some(11),
    ));
    assert_eq!(
        states.current.get(&slot),
        Some(&ConnectivityState {
            epoch: 22,
            connected: true,
        }),
        "a delayed true(E1) must not replace live E2 in the game display",
    );
    assert!(admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        true,
        Some(22),
    ));

    // A second replacement does not evict E1: every superseded token stays
    // fenced for the full client-session lifetime.
    assert!(admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        false,
        Some(22),
    ));
    assert!(admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        true,
        Some(33),
    ));
    for retired in [11, 22] {
        assert!(!admit_connectivity_epoch(
            &mut states,
            &terminal,
            slot,
            true,
            Some(retired),
        ));
    }
    assert_eq!(
        states.current.get(&slot),
        Some(&ConnectivityState {
            epoch: 33,
            connected: true,
        }),
    );
}

#[test]
fn connectivity_epoch_fence_accepts_legacy_only_before_upgrade() {
    let slot = SlotId(3);
    let mut states = ConnectivityEpochStates::default();
    let terminal = HashSet::new();

    assert!(admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        true,
        None,
    ));
    assert!(admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        false,
        None,
    ));
    assert!(admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        true,
        Some(11),
    ));
    assert!(!admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        false,
        None,
    ));
}

#[test]
fn final_leave_tombstone_rejects_every_later_connectivity_epoch() {
    let slot = SlotId(3);
    let mut states = ConnectivityEpochStates::default();
    let mut terminal = HashSet::new();

    // A replacement generation is live until the synced leave arrives.
    assert!(admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        true,
        Some(22),
    ));
    terminal.insert(slot);

    assert!(!admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        false,
        Some(22),
    ));
    assert!(!admit_connectivity_epoch(
        &mut states,
        &terminal,
        slot,
        true,
        Some(33),
    ));

    // Leave-first ordering is equally terminal, even without prior epoch
    // state and even for a legacy frame.
    let leave_first = SlotId(4);
    terminal.insert(leave_first);
    assert!(!admit_connectivity_epoch(
        &mut states,
        &terminal,
        leave_first,
        true,
        None,
    ));
}
