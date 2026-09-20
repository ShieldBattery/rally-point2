//! The connectivity-epoch fence: which relay-stamped link-lifecycle changes
//! the driver admits, what a final synced leave makes terminal, and the proof
//! that an admitted change actually reaches the game.

use super::*;

/// The fence's arms, one row each: the changes to admit first, then the change
/// offered and whether it must be admitted.
///
/// `setup` runs through the fence's own rules (each step is itself expected to
/// be admitted), so a row describes a reachable state rather than a
/// hand-written one.
#[test]
fn the_fence_admits_exactly_its_stated_arms() {
    let slot = SlotId(3);
    struct Row {
        what: &'static str,
        setup: &'static [(bool, Option<u64>)],
        offered: (bool, Option<u64>),
        admitted: bool,
    }
    let rows = [
        Row {
            what: "an unseen slot with no epoch at all",
            setup: &[],
            offered: (true, None),
            admitted: true,
        },
        Row {
            what: "an unseen slot's first epoch",
            setup: &[],
            offered: (false, Some(11)),
            admitted: true,
        },
        Row {
            what: "a down within the live epoch",
            setup: &[(true, Some(11))],
            offered: (false, Some(11)),
            admitted: true,
        },
        Row {
            what: "a re-up within an epoch already down: terminal in its epoch",
            setup: &[(true, Some(11)), (false, Some(11))],
            offered: (true, Some(11)),
            admitted: false,
        },
        Row {
            what: "an unseen up epoch opening a replacement",
            setup: &[(true, Some(11)), (false, Some(11))],
            offered: (true, Some(22)),
            admitted: true,
        },
        Row {
            what: "an unseen down epoch cannot open a replacement",
            setup: &[(true, Some(11))],
            offered: (false, Some(22)),
            admitted: false,
        },
        Row {
            what: "an epoch-less frame after an epoch was observed",
            setup: &[(true, Some(11))],
            offered: (false, None),
            admitted: false,
        },
        Row {
            what: "an epoch already retired by a replacement",
            setup: &[(true, Some(11)), (true, Some(22))],
            offered: (true, Some(11)),
            admitted: false,
        },
    ];

    for row in rows {
        let mut fence = ConnectivityFence::default();
        for &(connected, epoch) in row.setup {
            assert!(
                fence.admit(slot, connected, epoch),
                "setup step {connected}/{epoch:?} for \"{}\" must be admitted",
                row.what,
            );
        }
        let (connected, epoch) = row.offered;
        assert_eq!(
            fence.admit(slot, connected, epoch),
            row.admitted,
            "{}",
            row.what
        );
    }
}

/// The fence's whole lifecycle on one slot: `Down(E)` is terminal inside its
/// own epoch, a previously unseen `level=true` epoch opens a replacement, and
/// every epoch the replacement supersedes stays retired for good — a delayed
/// frame from one can never regress the game's display, and nothing evicts a
/// retired token as further replacements arrive.
#[test]
fn a_replacement_epoch_retires_every_superseded_one_for_the_session() {
    let slot = SlotId(3);
    let mut fence = ConnectivityFence::default();

    assert!(fence.admit(slot, true, Some(11)));
    assert!(fence.admit(slot, false, Some(11)));
    // Down is terminal within its own epoch: nothing reopens E1 but a
    // replacement.
    assert!(!fence.admit(slot, true, Some(11)));
    assert!(fence.admit(slot, true, Some(22)));

    assert!(!fence.admit(slot, true, Some(11)));
    assert_eq!(
        fence.state(slot),
        Some(ConnectivityState {
            epoch: 22,
            connected: true,
        }),
        "a delayed true(E1) must not replace live E2 in the game display",
    );
    // A delayed down from the retired epoch is refused too, and so is an
    // epoch-less frame: admission of those ended the moment an epoch appeared.
    assert!(!fence.admit(slot, false, Some(11)));
    assert!(!fence.admit(slot, false, None));
    // The live epoch keeps being admitted, in both directions.
    assert!(fence.admit(slot, true, Some(22)));
    assert!(fence.admit(slot, false, Some(22)));

    // A second replacement does not evict E1: every superseded token stays
    // fenced for the full client-session lifetime.
    assert!(fence.admit(slot, true, Some(33)));
    for retired in [11, 22] {
        assert!(!fence.admit(slot, true, Some(retired)));
    }
    assert_eq!(
        fence.state(slot),
        Some(ConnectivityState {
            epoch: 33,
            connected: true,
        }),
    );
}

#[test]
fn connectivity_epoch_fence_accepts_legacy_only_before_upgrade() {
    let slot = SlotId(3);
    let mut fence = ConnectivityFence::default();

    assert!(fence.admit(slot, true, None));
    assert!(fence.admit(slot, false, None));
    assert!(fence.admit(slot, true, Some(11)));
    assert!(!fence.admit(slot, false, None));
}

#[test]
fn final_leave_tombstone_rejects_every_later_connectivity_epoch() {
    let slot = SlotId(3);
    let mut fence = ConnectivityFence::default();

    // A replacement generation is live until the synced leave arrives.
    assert!(fence.admit(slot, true, Some(22)));
    fence.mark_terminal(slot);

    assert!(!fence.admit(slot, false, Some(22)));
    assert!(!fence.admit(slot, true, Some(33)));

    // Leave-first ordering is equally terminal, even without prior epoch
    // state and even for a legacy frame.
    let leave_first = SlotId(4);
    fence.mark_terminal(leave_first);
    assert!(!fence.admit(leave_first, true, None));
}

#[tokio::test]
async fn an_admitted_change_reaches_the_game_and_a_fenced_one_does_not() {
    // The wiring the unit tests above cannot see: the control-stream arm runs
    // every `SlotConnectivity` frame through the fence before handing it to
    // the game, and latches a synced leave's subject as terminal.
    use rally_point_proto::messages::LeaveDirective;
    use rally_point_transport::control::{send_control_connectivity, send_control_leave};

    let mut fixture = DriverFixture::new().await;
    let subject = 5u8;

    for (connected, epoch) in [(true, Some(11)), (true, Some(22)), (true, Some(11))] {
        send_control_connectivity(&mut fixture.peer_control, subject, connected, epoch)
            .await
            .unwrap();
    }

    // Only the two admitted changes arrive; the delayed true(E1) was fenced.
    assert_eq!(
        fixture.chan.connectivity.recv().await.unwrap(),
        (SlotId(subject), true),
    );
    assert_eq!(
        fixture.chan.connectivity.recv().await.unwrap(),
        (SlotId(subject), true),
    );

    // A synced leave makes the slot terminal, so a later replacement epoch is
    // refused rather than making a departed player look connected again.
    send_control_leave(
        &mut fixture.peer_control,
        LeaveDirective {
            slot: u32::from(subject),
            leave_seq: 1,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        fixture.chan.leaves.recv().await.unwrap().slot,
        u32::from(subject),
    );
    send_control_connectivity(&mut fixture.peer_control, subject, true, Some(33))
        .await
        .unwrap();

    // A turn sent behind the fenced change proves the driver processed it and
    // moved on rather than merely lagging, so the empty channel below means
    // refused, not pending.
    fixture.peer.send(Some(turn(0, &[0xAB]))).unwrap();
    assert_eq!(
        fixture.chan.inbound.recv().await.unwrap().commands[0],
        0xAB,
        "the driver kept serving past the refused change",
    );
    assert!(
        fixture.chan.connectivity.try_recv().is_err(),
        "a post-leave epoch must never reach the game",
    );

    fixture.finish().await;
}
