//! Link registration and peer membership: joins reach only named peers,
//! dropped peers leave, reconnects re-sync, and the published desired-peer
//! set tracks descriptor/session changes without redundant republishes — plus
//! the authority verdict each descriptor's relay set implies.

use super::*;

#[test]
fn joins_only_named_peers_never_broadcasts() {
    let (control, _mesh, _sessions) = control_over(1);
    let (tx2, mut rx2) = link();
    let (tx3, mut rx3) = link();
    let _ = control.register_link(RelayId(2), 1, tx2);
    let _ = control.register_link(RelayId(3), 1, tx3);

    // Session 1 names only peer 2 — peer 3 serves a different session.
    control.apply_descriptor(&descriptor(1, &[2]));

    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
    assert!(
        rx3.try_recv().is_err(),
        "peer not in the descriptor must not be joined",
    );
}

#[test]
fn descriptor_before_link_joins_when_the_link_registers() {
    let (control, _mesh, _sessions) = control_over(1);

    // The descriptor names peer 2, but its link has not established yet.
    control.apply_descriptor(&descriptor(1, &[2]));

    // The link establishes — the deferred join fires now.
    let (tx2, mut rx2) = link();
    let _ = control.register_link(RelayId(2), 1, tx2);
    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
}

#[test]
fn re_applied_descriptor_leaves_a_dropped_peer() {
    let (control, _mesh, _sessions) = control_over(1);
    let (tx2, mut rx2) = link();
    let (tx3, mut rx3) = link();
    let _ = control.register_link(RelayId(2), 1, tx2);
    let _ = control.register_link(RelayId(3), 1, tx3);

    control.apply_descriptor(&descriptor(1, &[2, 3]));
    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
    assert_eq!(rx3.try_recv().unwrap(), MeshCommand::Join(key(1)));

    // Peer 3 churns out of the session; a re-pushed descriptor drops it.
    control.apply_descriptor(&descriptor(1, &[2]));
    assert_eq!(rx3.try_recv().unwrap(), MeshCommand::Leave(key(1)));
    // Peer 2 was already joined and is unchanged — no redundant re-join.
    assert!(
        rx2.try_recv().is_err(),
        "an unchanged peer must not be re-joined",
    );
}

#[test]
fn end_session_leaves_all_peers_and_forgets_membership() {
    let (control, _mesh, _sessions) = control_over(1);
    let (tx2, mut rx2) = link();
    let (tx3, mut rx3) = link();
    let _ = control.register_link(RelayId(2), 1, tx2);
    let _ = control.register_link(RelayId(3), 1, tx3);

    control.apply_descriptor(&descriptor(1, &[2, 3]));
    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
    assert_eq!(rx3.try_recv().unwrap(), MeshCommand::Join(key(1)));

    control.end_session(&key(1));
    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Leave(key(1)));
    assert_eq!(rx3.try_recv().unwrap(), MeshCommand::Leave(key(1)));

    // Membership was forgotten: a fresh descriptor for the same session id
    // joins from scratch rather than treating peer 2 as already joined.
    control.apply_descriptor(&descriptor(1, &[2]));
    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
}

#[test]
fn end_session_on_an_unknown_session_is_a_no_op() {
    let (control, _mesh, _sessions) = control_over(1);
    let (tx2, mut rx2) = link();
    let _ = control.register_link(RelayId(2), 1, tx2);
    // Never applied a descriptor for session 9.
    control.end_session(&key(9));
    assert!(rx2.try_recv().is_err());
}

#[test]
fn late_older_registration_cannot_replace_or_resurrect_after_the_new_link_dies() {
    let (control, _mesh, _sessions) = control_over(1);
    control.apply_descriptor(&descriptor(1, &[2]));

    let (old_tx, mut old_rx) = link();
    assert!(control.register_link(RelayId(2), 10, old_tx));
    assert_eq!(old_rx.try_recv().unwrap(), MeshCommand::Join(key(1)));

    // The link to peer 2 drops and reconnects: a newer generation registers
    // under the same id, and the desired session re-joins on that sender.
    let (new_tx, mut new_rx) = link();
    assert!(control.register_link(RelayId(2), 20, new_tx));
    assert_eq!(new_rx.try_recv().unwrap(), MeshCommand::Join(key(1)));

    let (late_tx, mut late_rx) = link();
    assert!(!control.register_link(RelayId(2), 10, late_tx));
    control.apply_descriptor(&descriptor(2, &[2]));
    assert_eq!(new_rx.try_recv().unwrap(), MeshCommand::Join(key(2)));
    assert!(late_rx.try_recv().is_err());

    // Make the current sender fail so reconcile removes it, then prove the
    // retained generation tombstone still rejects E1.
    drop(new_rx);
    control.apply_descriptor(&descriptor(3, &[2]));
    let (resurrect_tx, mut resurrect_rx) = link();
    assert!(!control.register_link(RelayId(2), 10, resurrect_tx));
    assert!(resurrect_rx.try_recv().is_err());
}

#[test]
fn drops_a_descriptor_self_reference() {
    // A descriptor that erroneously lists this relay among its own peers
    // must not produce a self-join — a relay never meshes with itself — and
    // must not publish it as a peer to dial either.
    let (control, _mesh, _sessions) = control_over(1);
    let mut peers_rx = control.desired_peers();
    let (tx1, mut rx1) = link();
    // Even if a link were somehow registered under our own id, we don't join.
    let _ = control.register_link(RelayId(1), 1, tx1);
    control.apply_descriptor(&descriptor(1, &[1, 2]));
    assert!(
        rx1.try_recv().is_err(),
        "a relay must not join a link to itself",
    );
    let published = peers_rx.borrow_and_update().clone();
    assert_eq!(published.len(), 1, "a relay never dials itself");
    assert_eq!(published[0].relay_id, RelayId(2));
}

#[test]
fn a_terminal_leave_is_delivered_under_backlog() {
    // A session's final `Leave` — with no later descriptor to re-push it —
    // must not be lost behind a backlog of undrained commands, and neither
    // may any of the backlogged joins: the command channel is unbounded
    // precisely because a dropped terminal `Leave` has no later event to
    // correct it. The backlog here is deeper than the bounded channel this
    // replaced, and every command must come out in order.
    let (control, _mesh, _sessions) = control_over(1);
    let (tx2, mut rx2) = link();
    let _ = control.register_link(RelayId(2), 1, tx2);

    const BACKLOG: u64 = 64; // well beyond the previous 32-deep bound
    for s in 1..=BACKLOG {
        control.apply_descriptor(&descriptor(s, &[2]));
    }
    // Session 1 ends — its `Leave` is the terminal event for that session,
    // queued behind the whole backlog.
    control.end_session(&key(1));

    // Drain: the backlogged joins, then session 1's `Leave` — present, not
    // dropped despite the backlog.
    for s in 1..=BACKLOG {
        assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(s)));
    }
    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Leave(key(1)));
    assert!(rx2.try_recv().is_err());
}

#[test]
fn a_closed_link_is_dropped_and_a_reconnect_re_syncs() {
    // When a link's driver has exited (its receiver dropped), the stale
    // sender is removed but intent is kept, so a reconnect re-joins from
    // scratch rather than the session being lost.
    let (control, _mesh, _sessions) = control_over(1);
    let (tx2_dead, rx2_dead) = link();
    let _ = control.register_link(RelayId(2), 1, tx2_dead);
    drop(rx2_dead); // the driver exited; the channel is now closed

    // Applying a descriptor tries to join over the dead link and fails; the
    // link is dropped, but the desired membership is kept.
    control.apply_descriptor(&descriptor(1, &[2]));

    // The peer reconnects: a fresh link registers and the kept intent
    // re-joins on it.
    let (tx2_new, mut rx2_new) = link();
    let _ = control.register_link(RelayId(2), 2, tx2_new);
    assert_eq!(rx2_new.try_recv().unwrap(), MeshCommand::Join(key(1)));
}

#[test]
fn apply_descriptor_publishes_desired_peers_with_addresses() {
    let (control, _mesh, _sessions) = control_over(1);
    let mut peers_rx = control.desired_peers();
    assert!(peers_rx.borrow_and_update().is_empty());

    control.apply_descriptor(&descriptor(1, &[2, 3]));

    assert!(peers_rx.has_changed().unwrap());
    let published = peers_rx.borrow_and_update().clone();
    assert_eq!(published.len(), 2);
    // Sorted by id, each carrying the address and pinned cert the
    // descriptor named — the cert is what the dialer's trust config pins.
    assert_eq!(published[0].relay_id, RelayId(2));
    assert_eq!(
        published[0].relay_addr,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14902))
    );
    assert_eq!(published[0].cert_der, vec![2u8; 4]);
    assert_eq!(published[1].relay_id, RelayId(3));
    assert_eq!(published[1].cert_der, vec![3u8; 4]);
}

#[test]
fn ending_a_session_republishes_the_shrunk_peer_set() {
    let (control, _mesh, _sessions) = control_over(1);
    let mut peers_rx = control.desired_peers();
    control.apply_descriptor(&descriptor(1, &[2]));
    peers_rx.borrow_and_update();

    control.end_session(&key(1));
    assert!(peers_rx.has_changed().unwrap());
    assert!(peers_rx.borrow_and_update().is_empty());
}

#[test]
fn an_unchanged_peer_set_does_not_republish() {
    let (control, _mesh, _sessions) = control_over(1);
    let mut peers_rx = control.desired_peers();
    control.apply_descriptor(&descriptor(1, &[2]));
    peers_rx.borrow_and_update();

    // A second session naming the same peer leaves the desired-peer union
    // unchanged, so the dialer isn't needlessly re-woken.
    control.apply_descriptor(&descriptor(2, &[2]));
    assert!(
        !peers_rx.has_changed().unwrap(),
        "an unchanged peer set must not republish",
    );
}

#[test]
fn apply_descriptor_stamps_correlation_ids_that_a_departure_notice_carries() {
    // End to end through the production apply path: a descriptor carrying
    // the tenant's correlation ids, applied, must leave the registry able
    // to stamp them into a departure notice -- without depending on the
    // coordinator's in-memory session-refs store surviving to notice time.
    let (control, mesh, _sessions) = control_over(1);
    let makers = mesh.session.decision_makers.clone();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(tx);

    let mut first = descriptor(1, &[]);
    first.external_id = Some("game-old".to_owned());
    first.slot_refs = vec![SlotExternalRef {
        slot: SlotId(0),
        external_ref: "sb-user-3".to_owned(),
    }];
    control.apply_descriptor(&first);

    // A changed re-apply must replace the stale correlation ids rather than
    // keep the ones the first push stamped.
    let second = SessionDescriptor {
        external_id: Some("game-new".to_owned()),
        ..first
    };
    control.apply_descriptor(&second);

    makers.observe_frame(
        &key(1),
        SlotId(1),
        rally_point_proto::ids::GameFrameCount(10),
    );
    assert!(
        makers
            .decide_leave(&key(1), SlotId(0), 0x4000_0006)
            .is_some(),
        "single-relay session is its own authority, so decide_leave succeeds",
    );

    let consensus::RelayNotice::Departure(notice) = rx.try_recv().expect("one departure notice")
    else {
        panic!("a departure notice");
    };
    assert_eq!(
        notice.external_id,
        Some("game-new".to_owned()),
        "the re-applied descriptor's refs replace the stale ones",
    );
    assert_eq!(notice.external_ref, Some("sb-user-3".to_owned()));
}

#[test]
fn a_repushed_descriptor_moves_authority_with_the_relay_set() {
    // The id-order fallback, stated directly: our_id 3 with peer 2 present
    // means the peer is lower, so it decides, not us.
    let (control, mesh, _sessions) = control_over(3);
    let deferring = mesh.session.decision_makers.clone();
    control.apply_descriptor(&descriptor(1, &[2]));
    assert!(
        !deferring.lock().get(&key(1)).unwrap().is_authority(),
        "a relay that isn't the lowest id defers to the peer that is",
    );

    // Relay 2 starts as the session's only relay: it is the authority, which
    // is also what a single-relay (no-peer) descriptor must produce.
    let (control, mesh, _sessions) = control_over(2);
    let makers = mesh.session.decision_makers.clone();
    control.apply_descriptor(&descriptor(1, &[]));
    assert!(
        makers.lock().get(&key(1)).unwrap().is_authority(),
        "a single-relay session is its own authority",
    );

    // A player homed on relay 1 joins: the re-pushed descriptor names a
    // lower id, so relay 2 is demoted — a frozen verdict here would leave
    // the session with two authorities stamping conflicting directives.
    control.apply_descriptor(&descriptor(1, &[1]));
    assert!(
        !makers.lock().get(&key(1)).unwrap().is_authority(),
        "a lower-id relay joining demotes this one",
    );

    // Relay 1's players leave: the re-push drops it, promoting relay 2
    // back — a frozen verdict here would leave the session with none.
    control.apply_descriptor(&descriptor(1, &[]));
    assert!(
        makers.lock().get(&key(1)).unwrap().is_authority(),
        "the lowest id leaving promotes the next",
    );
}
