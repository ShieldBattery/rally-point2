//! The shared local-delivery path: the replay ring's bounds, the region-label
//! release gate, and the consensus feeds a duplicate turn must not disturb.

use super::*;

/// Builds a single-command turn payload carrying one `0x37` sync command
/// (`ring` = the ordinal mod 16), plus a made-up `game_frame_count`.
fn sync_payload(seq: u64, slot: u8, ordinal: u8, value: [u8; 5]) -> Payload {
    let mut commands = vec![0x37u8, (slot << 4) | (ordinal % 16)];
    commands.extend_from_slice(&value);
    Payload {
        seq,
        slot: u32::from(slot),
        commands: commands.into(),
        game_frame_count: Some(1000 + u32::from(ordinal)),
        ..Default::default()
    }
}

/// The replay ring's bounds must follow the session's actual shape through
/// the production path: `deliver_turn_to_locals` reads the decision-maker's
/// slot count and sizes the ring with it, so a 2-slot session's ring caps
/// at the 2-slot bound rather than the largest-game bound. Exercised
/// through the choke point itself (not `TurnRing` in isolation) to prove
/// the count actually arrives there.
#[test]
fn the_replay_ring_is_bounded_by_the_sessions_actual_slot_count() {
    use crate::consensus::{self, Authority};
    use rally_point_proto::control::BufferBounds;

    let sessions = routing::Sessions::default();
    let seen = new_seen_registries();
    let decision_makers = Arc::new(consensus::new_decision_makers());
    let turn_ring = crate::session::turn_ring::TurnRing::new();
    let key = control_key();
    let _ = consensus::sync_maker(
        &decision_makers,
        &key,
        BufferBounds::new(1, 6).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0), SlotId(1)].into(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    consensus::mark_session_started(&decision_makers, &key);

    // Overfill past the 2-slot count bound (empty commands, so the byte
    // bound never binds): the ring holds exactly the 2-slot cap, proving
    // it was not sized for the largest possible game.
    let cap = crate::session::turn_ring::max_turns(2);
    for seq in 0..(cap + 5) as u64 {
        deliver_turn_to_locals(
            &sessions,
            &seen,
            &decision_makers,
            &turn_ring,
            &key,
            SlotId(0),
            Payload {
                seq,
                slot: 0,
                ..Default::default()
            },
            crate::consensus::delivery::DeliveryHome::Local,
        );
    }
    assert_eq!(turn_ring.len(&key), cap);
    assert!(
        cap < crate::session::turn_ring::max_turns(crate::session::turn_ring::MAX_GAME_SLOTS),
        "the 2-slot bound is genuinely tighter than the full-game bound",
    );
}

/// A relay whose region-label gate is driven by the production turn path, on
/// a shortened release delay so the wait is milliseconds rather than the
/// production ten seconds. Returns the registries plus the label map the
/// descriptor recorded.
fn region_label_relay(
    delay: std::time::Duration,
) -> (
    routing::Sessions,
    SeenRegistries,
    Arc<crate::consensus::DecisionMakers>,
    crate::session::turn_ring::TurnRing,
    SessionKey,
    Vec<rally_point_proto::messages::RegionLabel>,
) {
    use crate::consensus::{self, Authority};
    use rally_point_proto::control::BufferBounds;
    use rally_point_proto::messages::RegionLabel;

    let sessions = routing::Sessions::default();
    let seen = new_seen_registries();
    let decision_makers = Arc::new(consensus::new_decision_makers_with_region_delay(delay));
    let turn_ring = crate::session::turn_ring::TurnRing::new();
    let key = control_key();
    let _ = consensus::sync_maker(
        &decision_makers,
        &key,
        BufferBounds::new(1, 6).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    let labels = vec![
        RegionLabel {
            relay_id: 1,
            region: "us-east".to_owned(),
        },
        RegionLabel {
            relay_id: 2,
            region: "eu-central".to_owned(),
        },
    ];
    assert_eq!(
        consensus::set_region_labels(&decision_makers, &key, labels.clone()),
        None,
        "a descriptor alone never releases the labels",
    );
    (sessions, seen, decision_makers, turn_ring, key, labels)
}

/// The region-label release gate is evaluated on the production turn path, so
/// this drives that path to prove: nothing reaches a client before the session
/// starts, nothing reaches one before the release delay elapses (including
/// when a turn forges an enormous frame), the map that does reach them is the
/// descriptor's, and it is fanned out exactly once.
#[test]
fn region_labels_reach_local_slots_only_once_the_release_delay_has_elapsed() {
    use crate::consensus;

    let delay = std::time::Duration::from_millis(120);
    let (sessions, seen, decision_makers, turn_ring, key, labels) = region_label_relay(delay);

    let (_reg0, mut inbox0) = routing::register(&sessions, &key, SlotId(0), 1).unwrap();
    let (_reg1, mut inbox1) = routing::register(&sessions, &key, SlotId(1), 1).unwrap();

    let turn = |seq: u64, frame: u32| Payload {
        seq,
        slot: 0,
        game_frame_count: Some(frame),
        ..Default::default()
    };
    let deliver = |payload: Payload| {
        deliver_turn_to_locals(
            &sessions,
            &seen,
            &decision_makers,
            &turn_ring,
            &key,
            SlotId(0),
            payload,
            crate::consensus::delivery::DeliveryHome::Local,
        );
    };

    // Turns flowing before the session has started: no clock to measure from,
    // so nothing is released.
    deliver(turn(0, 1));
    assert_eq!(inbox0.try_recv_region_labels(), None);
    assert_eq!(inbox1.try_recv_region_labels(), None);

    // The session starts, but the delay has not elapsed — and a turn forging an
    // enormous frame does not change that. The gate reads no part of a payload,
    // so a claim a client controls cannot advance it.
    consensus::mark_session_started(&decision_makers, &key);
    deliver(turn(1, u32::MAX));
    assert_eq!(
        inbox0.try_recv_region_labels(),
        None,
        "a forged game frame does not open the gate",
    );
    assert_eq!(inbox1.try_recv_region_labels(), None);

    // Once the delay has genuinely elapsed, the next delivered turn opens the
    // gate and every local slot gets the descriptor's map, verbatim.
    std::thread::sleep(delay + std::time::Duration::from_millis(30));
    deliver(turn(2, 5));
    assert_eq!(inbox0.try_recv_region_labels().as_ref(), Some(&labels));
    assert_eq!(inbox1.try_recv_region_labels().as_ref(), Some(&labels));

    // Play continues; the gate does not re-fire.
    deliver(turn(3, 6));
    assert_eq!(inbox0.try_recv_region_labels(), None);
    assert_eq!(inbox1.try_recv_region_labels(), None);

    // A slot registering after the release reads the map off the maker and is
    // pushed it directly — the path a late or reconnecting slot's link task
    // takes, so it is not left without labels every other member holds.
    let (_reg2, mut inbox2) = routing::register(&sessions, &key, SlotId(2), 1).unwrap();
    let late = consensus::released_region_labels(&decision_makers, &key)
        .expect("the gate is open, so a late slot has labels to receive");
    routing::deliver_region_labels_to_slot(&sessions, &key, SlotId(2), late);
    assert_eq!(inbox2.try_recv_region_labels().as_ref(), Some(&labels));
}

/// The gate reads nothing out of the turn that triggers its evaluation, so a
/// frameless turn drives it exactly like a framed one. This pins the gate's
/// placement outside the frame-observation block: were it moved back inside,
/// a session whose turns carried no frames would seal its labels forever.
#[test]
fn a_frameless_turn_drives_the_region_label_gate_like_any_other() {
    use crate::consensus;

    let delay = std::time::Duration::from_millis(80);
    let (sessions, seen, decision_makers, turn_ring, key, labels) = region_label_relay(delay);
    let (_reg0, mut inbox0) = routing::register(&sessions, &key, SlotId(0), 1).unwrap();

    consensus::mark_session_started(&decision_makers, &key);
    std::thread::sleep(delay + std::time::Duration::from_millis(30));

    deliver_turn_to_locals(
        &sessions,
        &seen,
        &decision_makers,
        &turn_ring,
        &key,
        SlotId(0),
        Payload {
            seq: 0,
            slot: 0,
            game_frame_count: None,
            ..Default::default()
        },
        crate::consensus::delivery::DeliveryHome::Local,
    );
    assert_eq!(inbox0.try_recv_region_labels().as_ref(), Some(&labels));
}

/// The desync comparator must observe each distinct `(slot, seq)` turn
/// exactly once, even though the mesh legitimately delivers the same turn
/// to the authority via more than one path. `deliver_turn_to_locals` is
/// the one choke point every turn-delivery path funnels through (client
/// edge, mesh datagram, mesh oversize), so the comparator's feed lives
/// there, right after the `mark_seen` dedup — this proves a redelivered
/// duplicate doesn't reach it twice (which would silently drift the
/// slot's ordinal count and eventually misalign an otherwise-honest
/// comparison into a false desync).
#[test]
fn duplicate_turn_delivery_does_not_double_count_the_desync_comparator() {
    use crate::consensus::{self, Authority};
    use rally_point_proto::control::BufferBounds;

    let sessions = routing::Sessions::default();
    let seen = new_seen_registries();
    let decision_makers = Arc::new(consensus::new_decision_makers());
    let turn_ring = crate::session::turn_ring::TurnRing::new();
    let (tx, mut rx) = mpsc::unbounded_channel();
    decision_makers.set_notice_notifier(tx);
    let key = control_key();
    let _ = consensus::sync_maker(
        &decision_makers,
        &key,
        BufferBounds::new(1, 6).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );

    // Slot 0's very first turn (seq 0, sync ordinal 0), delivered twice at
    // the exact choke point every ingress path funnels through — simulating
    // link-replacement or resume overlap, not a sender bug.
    let value = [1, 2, 3, 4, 5];
    let first = sync_payload(0, 0, 0, value);
    assert!(
        deliver_turn_to_locals(
            &sessions,
            &seen,
            &decision_makers,
            &turn_ring,
            &key,
            SlotId(0),
            first.clone(),
            crate::consensus::delivery::DeliveryHome::Local,
        )
        .is_some(),
        "the first delivery is fresh",
    );
    assert!(
        deliver_turn_to_locals(
            &sessions,
            &seen,
            &decision_makers,
            &turn_ring,
            &key,
            SlotId(0),
            first,
            crate::consensus::delivery::DeliveryHome::Local,
        )
        .is_none(),
        "the redelivery is caught by mark_seen and never reaches the comparator",
    );

    // Slot 1 agrees at ordinal 0, then both slots race forward in
    // lockstep agreement far enough to clear the comparator's evaluation
    // margin. If the duplicate above had been double-counted, slot 0's
    // internal ordinal count would run one ahead of its true progress and
    // this honest agreement would eventually misalign into a false
    // mismatch.
    deliver_turn_to_locals(
        &sessions,
        &seen,
        &decision_makers,
        &turn_ring,
        &key,
        SlotId(1),
        sync_payload(0, 1, 0, value),
        crate::consensus::delivery::DeliveryHome::Local,
    );
    for ordinal in 1..12u8 {
        deliver_turn_to_locals(
            &sessions,
            &seen,
            &decision_makers,
            &turn_ring,
            &key,
            SlotId(0),
            sync_payload(u64::from(ordinal), 0, ordinal, value),
            crate::consensus::delivery::DeliveryHome::Local,
        );
        deliver_turn_to_locals(
            &sessions,
            &seen,
            &decision_makers,
            &turn_ring,
            &key,
            SlotId(1),
            sync_payload(u64::from(ordinal), 1, ordinal, value),
            crate::consensus::delivery::DeliveryHome::Local,
        );
    }

    assert!(
        rx.try_recv().is_err(),
        "no desync notice: the duplicate delivery did not perturb ordinal alignment",
    );
}

/// The leave-frame clamp's history must record each distinct `(slot, seq)`
/// turn exactly once even when a reconnect/resume overlap repeats a peer's
/// direct copy. The history is a bounded append — unlike
/// the per-slot frame max, which is a harmless monotone — so duplicates
/// walked twice would evict genuine low-seq history and leave
/// `reachable_frame` with nothing at or below its threshold, pushing its
/// fallback frames too high: exactly the opening a departing slot's
/// inflated frame claim needs to strand survivors past a reachable frame.
#[test]
fn duplicate_turn_delivery_does_not_corrupt_the_leave_frame_clamp_history() {
    use crate::consensus::{self, Authority};
    use rally_point_proto::control::BufferBounds;

    let sessions = routing::Sessions::default();
    let seen = new_seen_registries();
    let decision_makers = Arc::new(consensus::new_decision_makers());
    let turn_ring = crate::session::turn_ring::TurnRing::new();
    let key = control_key();
    let _ = consensus::sync_maker(
        &decision_makers,
        &key,
        BufferBounds::new(1, 6).unwrap(),
        Authority::Peer,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );

    // The survivor's turns each arrive twice: the home peer's direct copy,
    // then the same copy replayed after a link replacement. Only the first
    // passes the session-level dedup; the replay must leave no trace in the
    // frame history.
    for seq in 0..=21u64 {
        let payload = Payload {
            seq,
            slot: 0,
            game_frame_count: Some(100 + seq as u32),
            commands: vec![0x05].into(),
            ..Default::default()
        };
        assert!(
            deliver_turn_to_locals(
                &sessions,
                &seen,
                &decision_makers,
                &turn_ring,
                &key,
                SlotId(0),
                payload.clone(),
                crate::consensus::delivery::DeliveryHome::Peer(RelayId(2)),
            )
            .is_some(),
            "the direct copy is fresh",
        );
        assert!(
            deliver_turn_to_locals(
                &sessions,
                &seen,
                &decision_makers,
                &turn_ring,
                &key,
                SlotId(0),
                payload,
                crate::consensus::delivery::DeliveryHome::Peer(RelayId(2)),
            )
            .is_none(),
            "the replacement-link replay is a session-level duplicate",
        );
    }

    // With bounds max 6 the history keeps 10 entries (seqs 12..=21) and the
    // frontier is seq 21, so the proven-executed threshold is seq 15: the
    // survivor's provable frame is 115. Doubled appends would have evicted
    // everything at or below the threshold (leaving seqs 17..=21 twice) and
    // pushed the fallback to 117 — past what the survivor provably reached.
    assert_eq!(
        consensus::reachable_frame(&decision_makers, &key, SlotId(1)),
        Some(115),
        "the clamp ceiling reflects single-counted history",
    );
}
