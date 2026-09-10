//! What a fresh link registration replays and asks for: leave state, local
//! slots, started reports, and the resume-cursor exchange with the replay it
//! answers.

use super::*;

/// A `Join`-time reconcile re-sends this relay's known leave state for the
/// session down the freshly registered link: a `SlotDeparted` for each
/// recorded departure and a `LeaveDirective` for each cached leave — so a
/// link that died and redialed reconverges.
#[test]
fn reconcile_leaves_on_join_re_announces_known_state() {
    use rally_point_proto::control::BufferBounds;
    use rally_point_proto::ids::GameFrameCount;

    let makers = Arc::new(crate::consensus::new_decision_makers());
    let key = control_key();
    let _ = crate::consensus::sync_maker(
        &makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        crate::consensus::Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    // The authority decided one slot's leave (caches a directive and records a
    // departure), and separately recorded a bare departure for another slot.
    crate::consensus::observe_frame(&makers, &key, SlotId(1), GameFrameCount(50));
    let leave = crate::consensus::decide_leave(&makers, &key, SlotId(1), 3)
        .expect("the authority decides slot 1's leave");
    crate::consensus::record_departure(
        &makers,
        &key,
        SlotId(2),
        crate::consensus::DepartureStamps {
            last_frame: Some(GameFrameCount(60)),
            ..Default::default()
        },
        0x4000_0006,
    );

    let (control_tx, mut control_rx) = mpsc::unbounded_channel();
    reconcile_leaves_on_join(&makers, &control_tx, &key);

    let mut departed = Vec::new();
    let mut directives = Vec::new();
    while let Ok(frame) = control_rx.try_recv() {
        assert_eq!(frame.session, 1);
        match frame.kind {
            Some(mesh_control_frame::Kind::SlotDeparted(sd)) => departed.push(sd.slot),
            Some(mesh_control_frame::Kind::LeaveDirective(d)) => directives.push(d),
            other => panic!("unexpected reconcile frame {other:?}"),
        }
    }
    departed.sort_unstable();
    assert_eq!(departed, vec![1, 2], "both departures re-announced");
    assert_eq!(
        directives,
        vec![leave],
        "the cached leave re-announced verbatim"
    );
}

/// A `Join`-time reconcile re-shares every game-started report this relay's
/// own home clients made, so a peer that joined the mesh after those reports
/// — or a relay that replaced one — learns the set instead of treating those
/// slots as still loading. A peer's own shared report is never re-shared, so
/// nothing loops the mesh.
#[test]
fn join_reconcile_re_shares_this_relay_s_own_started_slots() {
    use rally_point_proto::control::BufferBounds;

    let makers = Arc::new(crate::consensus::new_decision_makers());
    let key = control_key();
    let _ = crate::consensus::sync_maker(
        &makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        crate::consensus::Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    crate::consensus::record_slot_started(&makers, &key, SlotId(2));
    crate::consensus::record_slot_started(&makers, &key, SlotId(0));
    // A peer's slot, learned over the mesh: recorded here, never re-shared.
    crate::consensus::record_peer_slot_started(&makers, &key, SlotId(1));

    let (control_tx, mut control_rx) = mpsc::unbounded_channel();
    reconcile_started_slots_on_join(&makers, &control_tx, &key);
    reconcile_started_slots_on_join(&makers, &control_tx, &key);

    let mut started = Vec::new();
    while let Ok(frame) = control_rx.try_recv() {
        assert_eq!(frame.session, key.session.0);
        match frame.kind {
            Some(mesh_control_frame::Kind::SlotStarted(s)) => started.push(s.slot),
            other => panic!("unexpected started reconcile frame {other:?}"),
        }
    }
    assert_eq!(
        started,
        vec![0, 2, 0, 2],
        "every own started slot, in slot order, on every join",
    );
}

#[test]
fn join_reconcile_replays_each_active_slot_and_generation_every_time() {
    let conditions = new_conditions_registry();
    let key = control_key();
    for (slot, epoch) in [
        (SlotId(2), Some(22)),
        (SlotId(0), Some(11)),
        (SlotId(1), None),
    ] {
        activate_conditions(
            &conditions,
            &key,
            slot,
            SlotConditions {
                slot: u32::from(slot.0),
                rtt_us: 20_000,
                lost_packets: 0,
                sent_packets: 1,
                connection_epoch: epoch,
            },
        );
    }

    let (control_tx, mut control_rx) = mpsc::unbounded_channel();
    reconcile_local_slots_on_join(&conditions, &control_tx, &key);
    reconcile_local_slots_on_join(&conditions, &control_tx, &key);

    let mut present = Vec::new();
    let mut connected = Vec::new();
    while let Ok(frame) = control_rx.try_recv() {
        match frame.kind {
            Some(mesh_control_frame::Kind::SlotPresent(slot)) => {
                present.push(slot.slot);
            }
            Some(mesh_control_frame::Kind::SlotConnectivity(change)) => {
                assert!(change.connected);
                connected.push((change.slot, change.connection_epoch));
            }
            other => panic!("unexpected local-slot reconcile frame {other:?}"),
        }
    }
    assert_eq!(present, vec![0, 1, 2, 0, 1, 2]);
    assert_eq!(
        connected,
        vec![(0, Some(11)), (2, Some(22)), (0, Some(11)), (2, Some(22))]
    );
}

#[test]
fn resume_cursor_snapshot_is_the_forward_gate_prefix_plus_one() {
    let seen = new_seen_registries();
    let key = control_key();
    // Slot 0 has a contiguous 0..3 prefix; slot 1 has forwarded nothing yet
    // (an out-of-order arrival alone, still gapped at 0) and so has no
    // prefix at all; slot 2 has forwarded exactly seq 0.
    for seq in 0..3 {
        mark_seen(&seen, &key, SlotId(0), seq);
    }
    mark_seen(&seen, &key, SlotId(1), 5); // gapped: no contiguous prefix yet
    mark_seen(&seen, &key, SlotId(2), 0);

    let mut cursors = resume_cursor_snapshot(&seen, &key);
    cursors.sort_by_key(|&(slot, _)| slot);
    assert_eq!(
        cursors,
        vec![(SlotId(0), 3), (SlotId(2), 1)],
        "slot 1's gapped, prefix-less state is absent, not zeroed",
    );
    // Slot 1's omission is not the same as "nothing known about this
    // session" -- the session has genuine forward-gate history (this
    // relay HAS exchanged mesh traffic for it), which is exactly what
    // licenses a resume reply to answer the omitted slot from the start
    // rather than read the omission as a first join.
    assert!(
        has_resumable_state(&seen, &key),
        "a gapped slot still counts as forward-gate history for the session",
    );
}

#[test]
fn resume_cursor_snapshot_of_an_untouched_session_is_empty() {
    let seen = new_seen_registries();
    let key = control_key();
    assert!(resume_cursor_snapshot(&seen, &key).is_empty());
    assert!(
        !has_resumable_state(&seen, &key),
        "no forward-gate entry at all reads as a first join, not a resume",
    );
}

#[test]
fn resume_cursor_saturates_at_the_sequence_ceiling() {
    let seen = new_seen_registries();
    let key = control_key();
    let mut session_seen = MeshSeen::new();
    session_seen.slots.insert(
        SlotId(0),
        SlotSeen {
            forwarded_through: Some(u64::MAX),
            ahead: BTreeSet::new(),
            prefix_collapsed: false,
        },
    );
    seen.lock().insert(key.clone(), session_seen);

    assert_eq!(
        resume_cursor_snapshot(&seen, &key),
        vec![(SlotId(0), u64::MAX)],
    );
}

#[test]
fn reconcile_resume_cursors_on_join_sends_an_empty_frame_for_a_first_join() {
    // A session this relay has never forwarded anything for -- a first
    // Join, or a peer that predates this link entirely -- sends a frame
    // with no cursors AND `resuming = false`, which the wire's own doc
    // marks as "replay nothing", never as "replay from the very start".
    let seen = new_seen_registries();
    let key = control_key();
    let (control_tx, mut control_rx) = mpsc::unbounded_channel();

    reconcile_resume_cursors_on_join(&seen, &control_tx, &key);

    let frame = control_rx.try_recv().expect("a frame was sent");
    assert_eq!(frame.session, key.session.0);
    match frame.kind {
        Some(mesh_control_frame::Kind::MeshResumeCursors(resume)) => {
            assert!(resume.cursors.is_empty());
            assert!(!resume.resuming, "no forward-gate history to resume from");
        }
        other => panic!("expected MeshResumeCursors, got {other:?}"),
    }
}

#[test]
fn reconcile_resume_cursors_on_join_sends_the_current_snapshot() {
    let seen = new_seen_registries();
    let key = control_key();
    mark_seen(&seen, &key, SlotId(0), 0);
    mark_seen(&seen, &key, SlotId(0), 1);

    let (control_tx, mut control_rx) = mpsc::unbounded_channel();
    reconcile_resume_cursors_on_join(&seen, &control_tx, &key);

    let frame = control_rx.try_recv().expect("a frame was sent");
    match frame.kind {
        Some(mesh_control_frame::Kind::MeshResumeCursors(resume)) => {
            assert_eq!(resume.cursors.len(), 1);
            assert_eq!(resume.cursors[0].origin_slot, 0);
            assert_eq!(resume.cursors[0].next_seq, 2);
            assert!(resume.resuming, "the session has forward-gate history");
        }
        other => panic!("expected MeshResumeCursors, got {other:?}"),
    }
}

#[test]
fn a_wholly_gapped_session_still_sends_an_empty_but_resuming_frame() {
    // The case a naive "cursors is empty means fresh join" reading would
    // get wrong: every slot this relay has EVER seen for the session is
    // still gapped (no contiguous prefix on any of them), so the cursor
    // list is empty exactly like a first join's -- but the session has
    // real forward-gate history, so `resuming` must still be true. This
    // is what stops that history from being silently dropped on the floor
    // when the shape of the data alone can't tell the two cases apart.
    let seen = new_seen_registries();
    let key = control_key();
    mark_seen(&seen, &key, SlotId(0), 5); // arrived, but gapped below 5

    let (control_tx, mut control_rx) = mpsc::unbounded_channel();
    reconcile_resume_cursors_on_join(&seen, &control_tx, &key);

    let frame = control_rx.try_recv().expect("a frame was sent");
    match frame.kind {
        Some(mesh_control_frame::Kind::MeshResumeCursors(resume)) => {
            assert!(
                resume.cursors.is_empty(),
                "no slot formed a contiguous prefix"
            );
            assert!(
                resume.resuming,
                "the gap does not erase the session's forward-gate history",
            );
        }
        other => panic!("expected MeshResumeCursors, got {other:?}"),
    }
}

#[test]
fn resume_replay_answers_only_with_this_relays_own_locally_originated_turns() {
    // The ring can hold both locally and remotely originated entries; a
    // resume reply must carry only the `Local` ones so this relay never
    // forwards a peer-origin payload to another relay.
    let mesh = new_mesh_state();
    let key = control_key();
    mesh.turn_ring.record(
        &key,
        &Payload {
            slot: 0,
            seq: 0,
            ..Default::default()
        },
        crate::session::turn_ring::TurnOrigin::Local,
        crate::session::turn_ring::MAX_GAME_SLOTS,
    );
    mesh.turn_ring.record(
        &key,
        &Payload {
            slot: 0,
            seq: 1,
            ..Default::default()
        },
        crate::session::turn_ring::TurnOrigin::Mesh,
        crate::session::turn_ring::MAX_GAME_SLOTS,
    );
    mesh.turn_ring.record(
        &key,
        &Payload {
            slot: 0,
            seq: 2,
            ..Default::default()
        },
        crate::session::turn_ring::TurnOrigin::Local,
        crate::session::turn_ring::MAX_GAME_SLOTS,
    );

    let mut joined = HashMap::new();
    joined.insert(
        key.session,
        SessionState {
            key: key.clone(),
            flush_deadline: tokio::time::Instant::now(),
            _registration: register_mesh_link(
                &mesh.links,
                key.clone(),
                mpsc::channel(1).0,
                mpsc::unbounded_channel().0,
                Arc::new(tokio::sync::Notify::new()),
            ),
        },
    );

    let frame = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::MeshResumeCursors(
            rally_point_proto::messages::MeshResumeCursors {
                cursors: vec![rally_point_proto::messages::MeshResumeCursor {
                    origin_slot: 0,
                    next_seq: 0,
                }],
                // A listed slot's cursor is honored by seq either way --
                // `resuming` only changes the answer for a slot the
                // cursors omit, and every recorded slot here is listed.
                resuming: false,
            },
        )),
    };

    let (got_key, payloads) =
        resume_replay_for_frame(&frame, &joined, &mesh).expect("something to replay");
    assert_eq!(got_key, key);
    assert_eq!(
        payloads.iter().map(|p| p.seq).collect::<Vec<_>>(),
        vec![0, 2],
        "only the two locally-originated seqs are replayed",
    );
}

#[test]
fn resume_replay_answers_an_unlisted_slot_from_zero_only_when_the_ask_is_resuming() {
    // The mesh-side counterpart of `TurnRing::replay_local`'s own unit test,
    // but exercised through the actual wire frame and `resume_replay_for_frame`
    // -- proves the `resuming` bit is correctly read off the frame and
    // threaded through, not just that `TurnRing` honors it in isolation.
    let mesh = new_mesh_state();
    let key = control_key();
    mesh.turn_ring.record(
        &key,
        &Payload {
            slot: 0,
            seq: 0,
            ..Default::default()
        },
        crate::session::turn_ring::TurnOrigin::Local,
        crate::session::turn_ring::MAX_GAME_SLOTS,
    );
    mesh.turn_ring.record(
        &key,
        &Payload {
            slot: 0,
            seq: 1,
            ..Default::default()
        },
        crate::session::turn_ring::TurnOrigin::Local,
        crate::session::turn_ring::MAX_GAME_SLOTS,
    );

    let mut joined = HashMap::new();
    joined.insert(
        key.session,
        SessionState {
            key: key.clone(),
            flush_deadline: tokio::time::Instant::now(),
            _registration: register_mesh_link(
                &mesh.links,
                key.clone(),
                mpsc::channel(1).0,
                mpsc::unbounded_channel().0,
                Arc::new(tokio::sync::Notify::new()),
            ),
        },
    );

    // Slot 0 is entirely unlisted in both asks -- this relay's own
    // gap-tracking never formed a contiguous prefix for it before the
    // asker's link died.
    let non_resuming_ask = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::MeshResumeCursors(
            rally_point_proto::messages::MeshResumeCursors {
                cursors: vec![],
                resuming: false,
            },
        )),
    };
    assert!(
        resume_replay_for_frame(&non_resuming_ask, &joined, &mesh).is_none(),
        "a first-join ask with an unlisted slot still replays nothing for it",
    );

    let resuming_ask = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::MeshResumeCursors(
            rally_point_proto::messages::MeshResumeCursors {
                cursors: vec![],
                resuming: true,
            },
        )),
    };
    let (_, payloads) = resume_replay_for_frame(&resuming_ask, &joined, &mesh)
        .expect("a resuming ask replays the unlisted slot from the start");
    assert_eq!(
        payloads.iter().map(|p| p.seq).collect::<Vec<_>>(),
        vec![0, 1],
    );
}

#[test]
fn resume_replay_is_none_for_an_unjoined_session_or_an_empty_result() {
    let mesh = new_mesh_state();
    let key = control_key();
    let joined = HashMap::new();

    let empty_ask = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::MeshResumeCursors(
            rally_point_proto::messages::MeshResumeCursors {
                cursors: vec![],
                resuming: false,
            },
        )),
    };
    assert!(
        resume_replay_for_frame(&empty_ask, &joined, &mesh).is_none(),
        "an unjoined session has no key to reply under",
    );

    // A different frame kind is never mistaken for a resume ask.
    let other = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::SessionStart(
            rally_point_proto::messages::SessionStart::default(),
        )),
    };
    assert!(resume_replay_for_frame(&other, &joined, &mesh).is_none());
}

#[test]
fn a_first_joins_empty_cursors_ask_for_no_replay_even_on_a_populated_ring() {
    // A first-join peer's cursor frame carries no entries AND `resuming =
    // false` (proven by
    // `reconcile_resume_cursors_on_join_sends_an_empty_frame_for_a_first_join`
    // above); this proves the receiving side honors that absent-means-nothing
    // semantic even when it has plenty it COULD reply with -- a newly-added
    // relay's own clients get their backfill from their own client-side
    // reconnect, not from a mesh peer's unsolicited replay. Contrast
    // `resume_replay_answers_an_unlisted_slot_from_zero_only_when_the_ask_is_resuming`,
    // where the identical empty cursor list means the opposite because
    // `resuming` is true there.
    let mesh = new_mesh_state();
    let key = control_key();
    mesh.turn_ring.record(
        &key,
        &Payload {
            slot: 0,
            seq: 0,
            ..Default::default()
        },
        crate::session::turn_ring::TurnOrigin::Local,
        crate::session::turn_ring::MAX_GAME_SLOTS,
    );

    let mut joined = HashMap::new();
    joined.insert(
        key.session,
        SessionState {
            key: key.clone(),
            flush_deadline: tokio::time::Instant::now(),
            _registration: register_mesh_link(
                &mesh.links,
                key.clone(),
                mpsc::channel(1).0,
                mpsc::unbounded_channel().0,
                Arc::new(tokio::sync::Notify::new()),
            ),
        },
    );

    let first_join_ask = MeshControlFrame {
        session: key.session.0,
        kind: Some(mesh_control_frame::Kind::MeshResumeCursors(
            rally_point_proto::messages::MeshResumeCursors {
                cursors: vec![],
                resuming: false,
            },
        )),
    };
    assert!(
        resume_replay_for_frame(&first_join_ask, &joined, &mesh).is_none(),
        "a non-resuming empty cursor map replays nothing, regardless of what the ring holds",
    );
}

#[test]
fn resume_cursor_snapshot_survives_the_links_own_registration_ending() {
    // The forward-gate cursors live in `SeenRegistries`, a session-keyed
    // registry entirely separate from `MeshLinks` -- a link dying (its
    // `MeshLinkRegistration` dropping) must not touch the cursors a fresh
    // link on the same session will read on its own next Join.
    let seen = new_seen_registries();
    let links = new_mesh_links();
    let key = control_key();

    mark_seen(&seen, &key, SlotId(0), 0);
    mark_seen(&seen, &key, SlotId(0), 1);
    let before = resume_cursor_snapshot(&seen, &key);

    // A link registers for the session, then dies (its registration drops,
    // deregistering it from `MeshLinks` -- the RAII path a redial's old
    // link and this test both exercise).
    let registration = register_mesh_link(
        &links,
        key.clone(),
        mpsc::channel(1).0,
        mpsc::unbounded_channel().0,
        Arc::new(tokio::sync::Notify::new()),
    );
    drop(registration);
    assert!(
        links.lock().get(&key).is_none(),
        "the dead link's registration is gone from MeshLinks",
    );

    assert_eq!(
        resume_cursor_snapshot(&seen, &key),
        before,
        "the cursors a fresh link's Join will read are unaffected by the dead link",
    );
}
