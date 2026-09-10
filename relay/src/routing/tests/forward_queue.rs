//! The per-slot forward queue's two bounds and the lagging-peer signal they
//! raise, the close-signal path, and the game-result ingress rule.

use super::*;

#[tokio::test]
async fn close_slots_signals_a_held_slot_with_a_reason_and_skips_an_absent_one() {
    let sessions: Sessions = Arc::default();
    let k = key();
    let (mut g0, inbox0) = register(&sessions, &k, SlotId(0), 1).expect("slot 0 registers");
    g0.disarm();

    // Closing a slot this relay does not hold (slot 5) is a no-op — no panic,
    // and the held slot is untouched.
    close_slots(&sessions, &k, &[SlotId(5)]);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), inbox0.shutdown.notified())
            .await
            .is_err(),
        "an absent slot's close must not signal a held one",
    );

    // Closing the held slot fires its shutdown signal (its task would then
    // close the link and deregister), but leaves it in the roster meanwhile.
    close_slots(&sessions, &k, &[SlotId(0), SlotId(9)]);
    tokio::time::timeout(Duration::from_millis(100), inbox0.shutdown.notified())
        .await
        .expect("the held slot is signaled to close");
    assert!(
        sessions.lock().get(&k).unwrap().contains_key(&SlotId(0)),
        "close_slots signals, it does not yank the roster entry",
    );
    assert_eq!(
        SlotCloseReason::from_raw(inbox0.close_reason.load(Ordering::Acquire)),
        SlotCloseReason::Unspecified,
        "a terminal directive names no more specific cause",
    );

    // A silence eviction stamps its own reason before signaling, so the woken
    // link task can close with the code that names it.
    close_slots_for_silence(&sessions, &k, &[SlotId(0)]);
    tokio::time::timeout(Duration::from_millis(100), inbox0.shutdown.notified())
        .await
        .expect("the held slot is signaled to close");
    assert_eq!(
        SlotCloseReason::from_raw(inbox0.close_reason.load(Ordering::Acquire)),
        SlotCloseReason::SilentSlot,
    );
}

#[tokio::test]
async fn fan_out_signals_a_full_peer_and_keeps_delivering_to_healthy_ones() {
    let sessions: Sessions = Arc::default();
    let k = key();
    // Source (0), a healthy peer (1) we keep drained, and a peer (2) we never
    // drain so its queue fills. Disarm the guards — the test owns the roster.
    let (mut g0, _inbox0) = register(&sessions, &k, SlotId(0), 1).expect("slot 0 registers");
    let (mut g1, mut inbox1) = register(&sessions, &k, SlotId(1), 1).expect("slot 1 registers");
    let (mut g2, inbox2) = register(&sessions, &k, SlotId(2), 1).expect("slot 2 registers");
    g0.disarm();
    g1.disarm();
    g2.disarm();

    // Fan out past slot 2's capacity. Slot 1 is drained every turn and so never
    // fills; slot 2 is never drained and fills, getting signaled to disconnect.
    let mut delivered_to_1 = 0;
    for _ in 0..(FORWARD_CAPACITY + 8) {
        fan_out(&sessions, &k, SlotId(0), payload());
        if inbox1.forward_rx.try_recv().is_some() {
            delivered_to_1 += 1;
        }
    }

    // The healthy peer received every turn — the stuck one never blocked it.
    assert_eq!(delivered_to_1, FORWARD_CAPACITY + 8);

    // The stuck peer was signaled to shut down (its task would then close its
    // link and deregister)...
    tokio::time::timeout(Duration::from_millis(100), inbox2.shutdown.notified())
        .await
        .expect("slot 2 was signaled to disconnect");

    // ...but fan_out left it in the roster: the slot stays occupied until its own
    // task exits, so no replacement can register a second sender for it.
    let roster = sessions.lock();
    let slots = roster.get(&k).expect("group present");
    assert!(slots.contains_key(&SlotId(1)));
    assert!(slots.contains_key(&SlotId(2)));
}

#[tokio::test]
async fn normal_payloads_fill_the_count_bound_without_tripping_the_byte_budget() {
    // A queue filled to the payload-count bound with normal-size turns must not
    // be byte-isolated: the count bound is what governs honest lagging traffic.
    let sessions: Sessions = Arc::default();
    let k = key();
    let (mut g0, _inbox0) = register(&sessions, &k, SlotId(0), 1).expect("slot 0 registers");
    let (mut g1, inbox1) = register(&sessions, &k, SlotId(1), 1).expect("slot 1 registers");
    g0.disarm();
    g1.disarm();

    // A few hundred command bytes is a generous normal turn; a full
    // count-bounded queue of them is only ~FORWARD_CAPACITY * 512 bytes, far
    // under the byte budget.
    const { assert!(FORWARD_CAPACITY * 512 < FORWARD_BYTE_BUDGET) };
    for _ in 0..FORWARD_CAPACITY {
        fan_out(&sessions, &k, SlotId(0), payload_of(512));
    }

    // The queue holds exactly the count bound and never crossed the byte
    // budget, so the slot was not signaled to disconnect.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), inbox1.shutdown.notified())
            .await
            .is_err(),
        "a count-full queue of normal turns must not trip the byte budget",
    );
}

#[tokio::test]
async fn oversize_payloads_trip_the_byte_budget_before_the_count_bound() {
    // Max-oversize turns pin far more per payload, so a queue of them must be
    // byte-isolated well before it reaches the payload-count bound.
    let sessions: Sessions = Arc::default();
    let k = key();
    let (mut g0, _inbox0) = register(&sessions, &k, SlotId(0), 1).expect("slot 0 registers");
    let (mut g1, mut inbox1) = register(&sessions, &k, SlotId(1), 1).expect("slot 1 registers");
    g0.disarm();
    g1.disarm();

    // Never drain slot 1: fan out max-oversize turns until the budget trips.
    // The byte budget admits exactly FORWARD_BYTE_BUDGET / oversize-len turns,
    // which is a quarter of the count bound.
    let admitted = FORWARD_BYTE_BUDGET / MAX_OVERSIZE_TURN_COMMANDS_LEN;
    assert!(
        admitted < FORWARD_CAPACITY,
        "the budget trips before the count bound"
    );
    for _ in 0..FORWARD_CAPACITY {
        fan_out(
            &sessions,
            &k,
            SlotId(0),
            payload_of(MAX_OVERSIZE_TURN_COMMANDS_LEN),
        );
    }

    // The slot was signaled to disconnect (the byte budget, not the count
    // bound)...
    tokio::time::timeout(Duration::from_millis(100), inbox1.shutdown.notified())
        .await
        .expect("the oversize spray trips the byte budget");

    // ...and only the under-budget turns were ever enqueued — far fewer than
    // the count bound would have allowed.
    let mut resident = 0;
    while inbox1.forward_rx.try_recv().is_some() {
        resident += 1;
    }
    assert_eq!(resident, admitted);
}

#[tokio::test]
async fn draining_the_forward_queue_frees_the_byte_budget() {
    // The budget is resident bytes, not a cumulative total: a queue filled to
    // the budget accepts again once its turns are drained.
    let sessions: Sessions = Arc::default();
    let k = key();
    let (mut g0, _inbox0) = register(&sessions, &k, SlotId(0), 1).expect("slot 0 registers");
    let (mut g1, mut inbox1) = register(&sessions, &k, SlotId(1), 1).expect("slot 1 registers");
    g0.disarm();
    g1.disarm();

    let admitted = FORWARD_BYTE_BUDGET / MAX_OVERSIZE_TURN_COMMANDS_LEN;
    // Fill the queue right up to the budget — every turn lands, none isolates.
    for _ in 0..admitted {
        fan_out(
            &sessions,
            &k,
            SlotId(0),
            payload_of(MAX_OVERSIZE_TURN_COMMANDS_LEN),
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), inbox1.shutdown.notified())
            .await
            .is_err(),
        "a queue filled exactly to the budget must not isolate",
    );

    // Drain every turn; each drain releases its bytes from the resident count.
    for _ in 0..admitted {
        assert!(inbox1.forward_rx.recv().await.is_some());
    }

    // The freed budget accepts a fresh full batch, again without isolating —
    // proving the count tracks resident bytes, not a running total.
    for _ in 0..admitted {
        fan_out(
            &sessions,
            &k,
            SlotId(0),
            payload_of(MAX_OVERSIZE_TURN_COMMANDS_LEN),
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), inbox1.shutdown.notified())
            .await
            .is_err(),
        "a drained queue must accept a fresh batch up to the budget",
    );
    let mut resident = 0;
    while inbox1.forward_rx.try_recv().is_some() {
        resident += 1;
    }
    assert_eq!(resident, admitted);
}

#[tokio::test]
async fn mesh_turn_preserves_an_upstream_stamp_on_a_non_authority_relay() {
    use crate::consensus::{self, Authority};
    use rally_point_proto::control::BufferBounds;
    use rally_point_proto::messages::BufferDirective;

    let sessions: Sessions = Arc::default();
    let seen = crate::mesh::new_seen_registries();
    let makers = Arc::new(consensus::new_decision_makers());
    let turn_ring = crate::session::turn_ring::TurnRing::new();
    let k = key();

    // This relay is not the session's authority: its own maker never has a
    // directive, so the forward step must leave an incoming stamp alone.
    let _ = consensus::sync_maker(
        &makers,
        &k,
        BufferBounds::new(0, 20).unwrap(),
        Authority::Peer,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );

    // A local client to fan out to.
    let (mut guard, mut inbox) = register(&sessions, &k, SlotId(1), 1).expect("slot 1 registers");
    guard.disarm();

    // A turn stamped by the authority arrives over the mesh.
    let stamp = BufferDirective {
        buffer_turns: 6,
        apply_at_frame: 40,
        decision_seq: 5,
        authority_relay_id: None,
    };
    let stamped = Payload {
        buffer_directive: Some(stamp),
        commands: vec![0x05].into(),
        ..payload()
    };
    let mut mesh_state = crate::mesh::new_mesh_state();
    mesh_state.seen = seen.clone();
    mesh_state.decision_makers = makers.clone();
    mesh_state.turn_ring = turn_ring.clone();
    crate::mesh::deliver_mesh_turn(
        &sessions,
        &mesh_state,
        &k,
        SlotId(0),
        stamped,
        rally_point_proto::ids::RelayId(2),
    );

    let delivered = inbox
        .forward_rx
        .try_recv()
        .expect("the turn fans out to the local slot");
    assert_eq!(
        delivered.buffer_directive,
        Some(stamp),
        "the authority's stamp survives the hop through a non-authority relay",
    );
    // And the relay recorded the stamp's seq, so a later promotion to
    // authority numbers its own decisions above what clients already hold.
    {
        let mut registry = makers.lock();
        let maker = registry.get_mut(&k).unwrap();
        maker.observe_frame(SlotId(0), rally_point_proto::ids::GameFrameCount(1));
        let _ = maker.sync(
            BufferBounds::new(0, 20).unwrap(),
            Authority::SelfRelay,
            &std::collections::HashSet::new(),
        );
    }
    consensus::ingest_local_conditions(
        &makers,
        &k,
        &rally_point_proto::messages::LinkConditions {
            slots: vec![rally_point_proto::messages::SlotConditions {
                slot: 0,
                rtt_us: 150_000,
                lost_packets: 0,
                sent_packets: 100,
                connection_epoch: None,
            }],
        },
    )
    .expect("promoted, its first decision fires");
    let own = consensus::active_directive(&makers, &k).expect("a directive is queued");
    assert!(
        own.decision_seq > stamp.decision_seq,
        "a promoted relay continues the session's numbering",
    );

    // A redundant copy of the stamped turn is dropped before local fan-out,
    // stamp and all.
    let duplicate = Payload {
        buffer_directive: Some(stamp),
        commands: vec![0x05].into(),
        ..payload()
    };
    crate::mesh::deliver_mesh_turn(
        &sessions,
        &mesh_state,
        &k,
        SlotId(0),
        duplicate,
        rally_point_proto::ids::RelayId(2),
    );
    assert!(
        inbox.forward_rx.try_recv().is_none(),
        "the session-level duplicate is dropped",
    );
}

// -- GameResult ingress --

/// An empty payload is the wire sentinel for "no result reported", never a
/// real report, so it is inadmissible regardless of the size cap.
#[test]
fn empty_game_result_is_inadmissible() {
    assert_eq!(game_result_admissible(&[]), Err("empty"));
}

/// A payload over the cap is an ill-formed report.
#[test]
fn oversize_game_result_is_inadmissible() {
    let payload = vec![0u8; MAX_GAME_RESULT_PAYLOAD_LEN + 1];
    assert_eq!(game_result_admissible(&payload), Err("oversize"));
}

/// A non-empty, within-cap payload -- including one sized exactly at the
/// cap -- is admissible.
#[test]
fn well_formed_game_result_is_admissible() {
    assert_eq!(game_result_admissible(&[0xDE, 0xAD]), Ok(()));
    let at_cap = vec![0u8; MAX_GAME_RESULT_PAYLOAD_LEN];
    assert_eq!(game_result_admissible(&at_cap), Ok(()));
}
