//! Descriptor application: a full set reconciles to exactly what was pushed, a
//! delta converges to the same place, an unrecognized frame is a no-op, and each
//! apply records its lag and set size.

use super::*;

#[test]
fn reconcile_applies_descriptors_then_leaves_dropped_sessions() {
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let (tx2, mut rx2) = mpsc::unbounded_channel();
    let _ = control.register_link(RelayId(2), 1, tx2);
    let applied = AppliedSessions::new();

    // First push: session 1 names peer 2 → Join.
    reconcile(&control, &[descriptor(1, &[2])], &applied);
    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
    assert!(applied.snapshot().contains(&key(1)));

    // Second push: the session has dropped out of the set → Leave.
    reconcile(&control, &[], &applied);
    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Leave(key(1)));
    assert!(applied.is_empty());
}

#[test]
fn reconcile_is_idempotent_on_a_repeated_set() {
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let (tx2, mut rx2) = mpsc::unbounded_channel();
    let _ = control.register_link(RelayId(2), 1, tx2);
    let applied = AppliedSessions::new();

    reconcile(&control, &[descriptor(1, &[2])], &applied);
    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));

    // A re-sync of the same set (e.g. on reconnect) issues no further commands.
    reconcile(&control, &[descriptor(1, &[2])], &applied);
    assert!(rx2.try_recv().is_err(), "an unchanged set is a no-op");
}

#[test]
fn reconcile_tracks_multiple_sessions_and_leaves_only_the_one_that_dropped() {
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let (tx2, mut rx2) = mpsc::unbounded_channel();
    let _ = control.register_link(RelayId(2), 1, tx2);
    let applied = AppliedSessions::new();

    // Two sessions on the link to peer 2.
    reconcile(
        &control,
        &[descriptor(1, &[2]), descriptor(2, &[2])],
        &applied,
    );
    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));
    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(2)));

    // Session 1 ends; session 2 remains. Only session 1 is left.
    reconcile(&control, &[descriptor(2, &[2])], &applied);
    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Leave(key(1)));
    assert!(rx2.try_recv().is_err(), "session 2 stays joined");
    assert_eq!(applied.snapshot(), HashSet::from([key(2)]));
}

#[test]
fn a_delta_adds_removes_and_mutates_converging_to_a_full_reconcile() {
    // The delta path and a full-set reconcile of the same target leave the relay
    // in the same applied state — a delta is only a cheaper way to reach it.
    let delta_control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let (d2_tx, mut d2_rx) = mpsc::unbounded_channel();
    let (d3_tx, mut d3_rx) = mpsc::unbounded_channel();
    let _ = delta_control.register_link(RelayId(2), 1, d2_tx);
    let _ = delta_control.register_link(RelayId(3), 1, d3_tx);
    let delta_applied = AppliedSessions::new();

    // Connect-time full set: sessions 1 and 2 both mesh peer 2.
    reconcile(
        &delta_control,
        &[descriptor(1, &[2]), descriptor(2, &[2])],
        &delta_applied,
    );
    // Drain the baseline joins so the post-delta command stream is clean.
    while d2_rx.try_recv().is_ok() {}
    while d3_rx.try_recv().is_ok() {}

    // One delta: add session 3 (meshing peer 2), remove session 1, and mutate
    // session 2 in place to mesh peer 3 instead of peer 2.
    apply_message(
        &delta_control,
        CoordinatorToRelay::DescriptorDelta {
            staged_at_unix_ms: None,
            upserts: vec![descriptor(3, &[2]), descriptor(2, &[3])],
            removals: vec![DescriptorKey {
                tenant: TenantId(TENANT.to_owned()),
                session: SessionId(1),
            }],
        },
        &delta_applied,
        &ControlConnStats::new(),
    );

    let d2: Vec<MeshCommand> = std::iter::from_fn(|| d2_rx.try_recv().ok()).collect();
    let d3: Vec<MeshCommand> = std::iter::from_fn(|| d3_rx.try_recv().ok()).collect();
    assert!(
        d2.contains(&MeshCommand::Join(key(3))),
        "the added session joins peer 2: {d2:?}",
    );
    assert!(
        d2.contains(&MeshCommand::Leave(key(1))),
        "the removed session leaves peer 2: {d2:?}",
    );
    assert!(
        d3.contains(&MeshCommand::Join(key(2))),
        "the mutated session re-applies and joins its new peer 3: {d3:?}",
    );

    // A full-set reconcile straight to the same target set on a fresh relay.
    let full_control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let full_applied = AppliedSessions::new();
    reconcile(
        &full_control,
        &[descriptor(2, &[3]), descriptor(3, &[2])],
        &full_applied,
    );

    assert_eq!(
        delta_applied.snapshot(),
        full_applied.snapshot(),
        "the delta converges to the same applied set as the full reconcile",
    );
    assert_eq!(delta_applied.snapshot(), HashSet::from([key(2), key(3)]));
}

#[test]
fn a_delta_records_the_applied_set_size_after_the_delta_and_its_apply_lag() {
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let applied = AppliedSessions::new();
    let stats = ControlConnStats::new();

    // Seed a four-session baseline via the connect-time full set.
    apply_message(
        &control,
        CoordinatorToRelay::Descriptors {
            descriptors: vec![
                descriptor(1, &[]),
                descriptor(2, &[]),
                descriptor(3, &[]),
                descriptor(4, &[]),
            ],
            staged_at_unix_ms: None,
        },
        &applied,
        &stats,
    );

    // A delta that only removes one session, staged ~1.5s ago.
    let staged = now_unix_ms().saturating_sub(1_500);
    apply_message(
        &control,
        CoordinatorToRelay::DescriptorDelta {
            staged_at_unix_ms: Some(staged),
            upserts: vec![],
            removals: vec![DescriptorKey {
                tenant: TenantId(TENANT.to_owned()),
                session: SessionId(1),
            }],
        },
        &applied,
        &stats,
    );

    let snap = stats.snapshot();
    assert_eq!(
        snap.descriptor_set_len, 3,
        "the recorded length is the applied-set size after the delta, not the delta's one entry",
    );
    assert!(
        (1_500..10_000).contains(&snap.descriptor_apply_lag_ms),
        "the delta's stamp yields an apply-lag sample exactly like a full set (observed {}ms)",
        snap.descriptor_apply_lag_ms,
    );
}

#[test]
fn a_delta_upsert_reconciles_dials_that_raced_it_and_starts_the_session() {
    // The dial-race fix must still fire when the session's descriptor arrives as
    // a delta upsert, not only as a full set: both clients register before the
    // descriptor lands, their maker-less announces drop, and the delta's
    // per-descriptor apply reconciles the roster it already holds, reaches
    // coverage, and delivers the start directive to the connected clients.
    use rally_point_proto::ids::SlotId;

    let makers = std::sync::Arc::new(crate::consensus::new_decision_makers());
    let sessions: crate::routing::Sessions = std::sync::Arc::default();
    let mesh_links = crate::mesh::new_mesh_links();

    let (_reg0, mut inbox0) = crate::routing::register(&sessions, &key(1), SlotId(0), 1)
        .expect("slot 0 registers into an empty roster");
    let (_reg1, mut inbox1) = crate::routing::register(&sessions, &key(1), SlotId(1), 1)
        .expect("slot 1 registers into an empty roster");
    assert!(
        !crate::consensus::note_slot_present(&makers, &key(1), SlotId(0)),
        "an announce with no maker yet drops the presence",
    );
    assert!(
        !crate::consensus::note_slot_present(&makers, &key(1), SlotId(1)),
        "an announce with no maker yet drops the presence",
    );

    let control = MeshControl::new(RelayId(1), makers.clone(), std::sync::Arc::default())
        .with_broadcast(sessions.clone(), mesh_links);
    let applied = AppliedSessions::new();

    // The session's descriptor arrives as a delta upsert (single relay, no peers).
    let mut desc = descriptor(1, &[]);
    desc.expected_slots = vec![SlotId(0), SlotId(1)];
    apply_message(
        &control,
        CoordinatorToRelay::DescriptorDelta {
            staged_at_unix_ms: None,
            upserts: vec![desc],
            removals: vec![],
        },
        &applied,
        &ControlConnStats::new(),
    );

    assert!(
        makers.lock().get(&key(1)).unwrap().is_started(),
        "the delta upsert reconciles the already-registered roster and covers the expected set",
    );
    assert!(
        inbox0.try_recv_start().is_some(),
        "slot 0's connected client receives the start directive",
    );
    assert!(
        inbox1.try_recv_start().is_some(),
        "slot 1's connected client receives the start directive",
    );
    assert!(
        applied.snapshot().contains(&key(1)),
        "the delta upsert records the session into the applied set",
    );
}

#[tokio::test]
async fn a_close_slot_message_signals_the_named_held_slot() {
    // A CloseSlot down-frame reaches the roster: the named slot's shutdown
    // signal fires (its link task would then close and deregister), and a slot
    // the relay does not hold is a harmless no-op.
    let sessions: crate::routing::Sessions = std::sync::Arc::default();
    let mesh_links = crate::mesh::new_mesh_links();
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    )
    .with_broadcast(sessions.clone(), mesh_links);

    let (mut guard, inbox) =
        crate::routing::register(&sessions, &key(1), rally_point_proto::ids::SlotId(0), 1)
            .expect("slot 0 registers");
    guard.disarm();
    let shutdown = inbox.shutdown_handle();

    let applied = AppliedSessions::new();
    apply_message(
        &control,
        CoordinatorToRelay::CloseSlot {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(1),
            // Name a held slot and one the relay does not hold.
            slots: vec![
                rally_point_proto::ids::SlotId(0),
                rally_point_proto::ids::SlotId(7),
            ],
        },
        &applied,
        &ControlConnStats::new(),
    );

    tokio::time::timeout(Duration::from_millis(100), shutdown.notified())
        .await
        .expect("the held slot was signaled to close");
}

#[test]
fn an_unknown_message_is_skipped_and_does_not_disturb_state_or_later_messages() {
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let (tx2, mut rx2) = mpsc::unbounded_channel();
    let _ = control.register_link(RelayId(2), 1, tx2);
    let applied = AppliedSessions::new();

    // A known message joins session 1.
    apply_message(
        &control,
        CoordinatorToRelay::Descriptors {
            descriptors: vec![descriptor(1, &[2])],
            staged_at_unix_ms: None,
        },
        &applied,
        &ControlConnStats::new(),
    );
    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Join(key(1)));

    // An unknown message is a no-op: no commands, applied state untouched.
    apply_message(
        &control,
        CoordinatorToRelay::Unknown,
        &applied,
        &ControlConnStats::new(),
    );
    assert!(rx2.try_recv().is_err(), "an unknown message issues nothing");
    assert_eq!(applied.snapshot(), HashSet::from([key(1)]));

    // A later known message still applies — the unknown one did not break the
    // stream's state.
    apply_message(
        &control,
        CoordinatorToRelay::Descriptors {
            descriptors: vec![],
            staged_at_unix_ms: None,
        },
        &applied,
        &ControlConnStats::new(),
    );
    assert_eq!(rx2.try_recv().unwrap(), MeshCommand::Leave(key(1)));
}

#[test]
fn an_unknown_frame_decodes_and_skips_rather_than_closing_the_stream() {
    // The exact rolling-deploy path: a frame a newer coordinator sent that
    // this build predates decodes to `Unknown` (not the serde error that
    // would propagate and close the connection), and applies as a no-op.
    let json = r#"{"type":"future_thing","whatever":true}"#;
    let message: CoordinatorToRelay =
        serde_json::from_str(json).expect("an unknown type must not be a decode error");
    assert_eq!(message, CoordinatorToRelay::Unknown);

    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let (tx2, mut rx2) = mpsc::unbounded_channel();
    let _ = control.register_link(RelayId(2), 1, tx2);
    let applied = AppliedSessions::new();
    apply_message(&control, message, &applied, &ControlConnStats::new());
    assert!(rx2.try_recv().is_err());
    assert!(applied.is_empty());
}

#[test]
fn an_applied_descriptor_set_records_its_apply_lag_and_length() {
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let applied = AppliedSessions::new();
    let stats = ControlConnStats::new();

    // A set staged ~1.5s ago applies with a lag at least that large — the apply
    // clock is never earlier than the staging stamp we synthesize here.
    let staged = now_unix_ms().saturating_sub(1_500);
    apply_message(
        &control,
        CoordinatorToRelay::Descriptors {
            descriptors: vec![descriptor(1, &[]), descriptor(2, &[])],
            staged_at_unix_ms: Some(staged),
        },
        &applied,
        &stats,
    );
    let snap = stats.snapshot();
    assert!(
        (1_500..10_000).contains(&snap.descriptor_apply_lag_ms),
        "the apply lag reflects the staging gap (observed {}ms)",
        snap.descriptor_apply_lag_ms,
    );
    assert_eq!(snap.descriptor_set_len, 2, "the last applied set's size");

    // A backward clock skew (a set stamped in the future) clamps to zero rather
    // than reading as a huge lag, and still updates the set length.
    apply_message(
        &control,
        CoordinatorToRelay::Descriptors {
            descriptors: vec![descriptor(1, &[])],
            staged_at_unix_ms: Some(now_unix_ms() + 60_000),
        },
        &applied,
        &stats,
    );
    let snap = stats.snapshot();
    assert_eq!(
        snap.descriptor_apply_lag_ms, 0,
        "a backward clock skew clamps the lag to zero",
    );
    assert_eq!(snap.descriptor_set_len, 1);

    // An unstamped set (an older coordinator) holds the last lag sample but still
    // updates the set length.
    apply_message(
        &control,
        CoordinatorToRelay::Descriptors {
            descriptors: vec![],
            staged_at_unix_ms: None,
        },
        &applied,
        &stats,
    );
    let snap = stats.snapshot();
    assert_eq!(
        snap.descriptor_apply_lag_ms, 0,
        "an unstamped push leaves the last lag sample untouched",
    );
    assert_eq!(snap.descriptor_set_len, 0);
}
