//! The per-slot forward queue's two bounds and the lagging-peer signal they
//! raise, the close signals and the codes that name their cause, and the
//! game-result ingress rule.

use super::*;

/// Every close code the relay can end a client connection with stays distinct,
/// because each is a diagnostic a client's own logs are read for: collapsing
/// any two would make "the descriptor was merely slow" and "your turn was
/// rejected" indistinguishable after the fact. Both the codes a routing path
/// raises and the ones the accept path refuses a dial with are checked
/// together, since a client sees them on the same connection.
#[test]
fn every_relay_close_code_names_its_own_cause() {
    let causes = [
        ("a turn that failed validation", close_codes::INVALID_TURN),
        ("a slot already connected", close_codes::SLOT_TAKEN),
        ("an unfinished authorization", close_codes::AUTH_TIMEOUT),
        ("a link isolated behind its bounds", close_codes::ISOLATED),
        (
            "a leave-intent the relay processed",
            close_codes::LEAVE_PROCESSED,
        ),
        ("a slot that already departed", close_codes::SLOT_DEPARTED),
        ("a lost control stream", close_codes::CONTROL_STREAM_LOST),
        ("a slot homed on another relay", close_codes::SLOT_NOT_HOMED),
        (
            "an insane resume anchor",
            close_codes::RESUME_ANCHOR_INVALID,
        ),
        (
            "an expired provisional window",
            close_codes::PROVISIONAL_EXPIRED,
        ),
        ("a retired session", close_codes::SESSION_RETIRED),
        (
            "a full provisional journal",
            close_codes::PROVISIONAL_CAPACITY,
        ),
        ("a slot that went silent", close_codes::SILENT_SLOT),
    ];
    let mut by_code = std::collections::HashMap::new();
    for (cause, code) in causes {
        assert!(
            by_code.insert(code, cause).is_none(),
            "{cause} shares close code {code:#04x} with {}",
            by_code[&code],
        );
    }
}

/// The cause a signaler stamps survives the round trip through the shared
/// byte the woken link task reads it back from, and an unrecognized byte
/// degrades to the generic close rather than to some other specific cause.
#[test]
fn a_stamped_close_reason_round_trips_and_an_unknown_byte_degrades() {
    for reason in [SlotCloseReason::Unspecified, SlotCloseReason::SilentSlot] {
        assert_eq!(SlotCloseReason::from_raw(reason as u8), reason);
    }
    assert_eq!(
        SlotCloseReason::from_raw(0xFF),
        SlotCloseReason::Unspecified
    );
}

#[tokio::test(start_paused = true)]
async fn close_slots_signals_a_held_slot_with_a_reason_and_skips_an_absent_one() {
    let sessions: Sessions = Arc::default();
    let k = key();
    let inbox0 = registered(&sessions, &k, SlotId(0));
    let shutdown = inbox0.shutdown_handle();

    // Closing a slot this relay does not hold (slot 5) is a no-op — no panic,
    // and the held slot is untouched. With the clock paused there is nothing
    // else to wait on, so the timeout resolves without real time passing.
    close_slots(&sessions, &k, &[SlotId(5)]);
    assert!(
        tokio::time::timeout(Duration::from_secs(60), shutdown.notified())
            .await
            .is_err(),
        "an absent slot's close must not signal a held one",
    );

    // Closing the held slot fires its shutdown signal (its task would then
    // close the link and deregister), but leaves it in the roster meanwhile.
    close_slots(&sessions, &k, &[SlotId(0), SlotId(9)]);
    shutdown.notified().await;
    assert!(
        sessions.lock().get(&k).unwrap().contains_key(&SlotId(0)),
        "close_slots signals, it does not yank the roster entry",
    );
    assert_eq!(
        inbox0.close_reason(),
        SlotCloseReason::Unspecified,
        "a terminal directive names no more specific cause",
    );

    // A silence eviction stamps its own reason before signaling, so the woken
    // link task can close with the code that names it.
    close_slots_for_silence(&sessions, &k, &[SlotId(0)]);
    shutdown.notified().await;
    assert_eq!(inbox0.close_reason(), SlotCloseReason::SilentSlot);
}

#[tokio::test(start_paused = true)]
async fn fan_out_signals_a_full_peer_and_keeps_delivering_to_healthy_ones() {
    let sessions: Sessions = Arc::default();
    let k = key();
    // Source (0), a healthy peer (1) we keep drained, and a peer (2) we never
    // drain so its queue fills.
    let _inbox0 = registered(&sessions, &k, SlotId(0));
    let mut inbox1 = registered(&sessions, &k, SlotId(1));
    let inbox2 = registered(&sessions, &k, SlotId(2));

    // Fan out past slot 2's capacity. Slot 1 is drained every turn and so never
    // fills; slot 2 is never drained and fills, getting signaled to disconnect.
    let mut delivered_to_1 = 0;
    for _ in 0..(FORWARD_CAPACITY + 8) {
        fan_out(&sessions, &k, SlotId(0), payload());
        if inbox1.try_recv_forward().is_some() {
            delivered_to_1 += 1;
        }
    }

    // The healthy peer received every turn — the stuck one never blocked it.
    assert_eq!(delivered_to_1, FORWARD_CAPACITY + 8);

    // The stuck peer was signaled to shut down (its task would then close its
    // link and deregister)...
    inbox2.shutdown_handle().notified().await;

    // ...but fan_out left it in the roster: the slot stays occupied until its own
    // task exits, so no replacement can register a second sender for it.
    let roster = sessions.lock();
    let slots = roster.get(&k).expect("group present");
    assert!(slots.contains_key(&SlotId(1)));
    assert!(slots.contains_key(&SlotId(2)));
}

#[tokio::test(start_paused = true)]
async fn normal_payloads_fill_the_count_bound_without_tripping_the_byte_budget() {
    // A queue filled to the payload-count bound with normal-size turns must not
    // be byte-isolated: the count bound is what governs honest lagging traffic.
    let sessions: Sessions = Arc::default();
    let k = key();
    let _inbox0 = registered(&sessions, &k, SlotId(0));
    let inbox1 = registered(&sessions, &k, SlotId(1));

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
        never_signaled(&inbox1).await,
        "a count-full queue of normal turns must not trip the byte budget",
    );
}

#[tokio::test(start_paused = true)]
async fn oversize_payloads_trip_the_byte_budget_before_the_count_bound() {
    // Max-oversize turns pin far more per payload, so a queue of them must be
    // byte-isolated well before it reaches the payload-count bound.
    let sessions: Sessions = Arc::default();
    let k = key();
    let _inbox0 = registered(&sessions, &k, SlotId(0));
    let mut inbox1 = registered(&sessions, &k, SlotId(1));

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
    inbox1.shutdown_handle().notified().await;

    // ...and only the under-budget turns were ever enqueued — far fewer than
    // the count bound would have allowed.
    let mut resident = 0;
    while inbox1.try_recv_forward().is_some() {
        resident += 1;
    }
    assert_eq!(resident, admitted);
}

#[tokio::test(start_paused = true)]
async fn draining_the_forward_queue_frees_the_byte_budget() {
    // The budget is resident bytes, not a cumulative total: a queue filled to
    // the budget accepts again once its turns are drained.
    let sessions: Sessions = Arc::default();
    let k = key();
    let _inbox0 = registered(&sessions, &k, SlotId(0));
    let mut inbox1 = registered(&sessions, &k, SlotId(1));

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
        never_signaled(&inbox1).await,
        "a queue filled exactly to the budget must not isolate",
    );

    // Drain every turn; each drain releases its bytes from the resident count.
    for _ in 0..admitted {
        assert!(inbox1.try_recv_forward().is_some());
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
        never_signaled(&inbox1).await,
        "a drained queue must accept a fresh batch up to the budget",
    );
    let mut resident = 0;
    while inbox1.try_recv_forward().is_some() {
        resident += 1;
    }
    assert_eq!(resident, admitted);
}

/// Whether `inbox`'s slot went unsignaled. Only sound under a paused clock,
/// where the shutdown notification is the one thing that could ever resolve:
/// the timeout then fires the instant the runtime runs out of other work, so
/// the negative costs no real time despite naming a generous window.
async fn never_signaled(inbox: &SlotInbox) -> bool {
    tokio::time::timeout(Duration::from_secs(60), inbox.shutdown_handle().notified())
        .await
        .is_err()
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
    seed_maker(&makers, &k, Authority::Peer, &[], &[]);

    // A local client to fan out to.
    let mut inbox = registered(&sessions, &k, SlotId(1));

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
    let mesh_state = crate::mesh::MeshState {
        seen: seen.clone(),
        session: SessionState {
            decision_makers: makers.clone(),
            turn_ring: turn_ring.clone(),
            ..SessionState::default()
        },
        ..crate::mesh::MeshState::default()
    };
    crate::mesh::deliver_mesh_turn(
        &sessions,
        &mesh_state,
        &k,
        SlotId(0),
        stamped,
        rally_point_proto::ids::RelayId(2),
    );

    let delivered = inbox
        .try_recv_forward()
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
    makers
        .ingest_local_conditions(
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
    let own = makers.active_directive(&k).expect("a directive is queued");
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
        inbox.try_recv_forward().is_none(),
        "the session-level duplicate is dropped",
    );
}

/// The `GameResult` ingress predicate, over every branch it has. An empty
/// payload is the wire sentinel for "no result reported", never a real one,
/// so it is inadmissible regardless of the size cap; a payload over the cap is
/// an ill-formed report; anything in between — including one sized exactly at
/// the cap — is admissible.
#[test]
fn a_game_result_is_admissible_only_when_non_empty_and_within_the_cap() {
    assert_eq!(game_result_admissible(&[]), Err("empty"));
    assert_eq!(game_result_admissible(&[0xDE, 0xAD]), Ok(()));
    assert_eq!(
        game_result_admissible(&vec![0u8; MAX_GAME_RESULT_PAYLOAD_LEN]),
        Ok(()),
    );
    assert_eq!(
        game_result_admissible(&vec![0u8; MAX_GAME_RESULT_PAYLOAD_LEN + 1]),
        Err("oversize"),
    );
}
