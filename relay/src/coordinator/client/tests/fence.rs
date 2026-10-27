//! The load-state fence: which slots are probed, what an ack proves, and every
//! way a membership change across the wait withholds the fenced verdict.

use super::*;

/// The connection epoch a fence fixture's link registers on, and the one a
/// client that dials back in takes. Any two distinct values do — an epoch is an
/// equality fence, not an ordering key.
const LINK_EPOCH: u64 = 0x51;
const REPLACEMENT_EPOCH: u64 = 0x52;

/// The slots an answer names closed, without their epochs.
fn closed_slot_ids(load: &FencedLoadState) -> Vec<rally_point_proto::ids::SlotId> {
    load.closed_slots.iter().map(|closed| closed.slot).collect()
}

#[tokio::test]
async fn a_live_unstarted_slot_that_acks_fences_the_answer() {
    // The fence's positive case: the one slot that could be holding a report
    // back answers the probe on the link the probe went down, and the roster is
    // unchanged either side of the wait, so the snapshot's absences may be read
    // as proof.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();
    let (mut registration, mut inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), LINK_EPOCH)
            .expect("slot 0 registers");
    registration.disarm();
    decision_makers.note_slot_connected(&key(7), SlotId(0), false, None, None);

    // Stand in for slot 0's link task: take the probe off its push queue and
    // resolve it exactly as `run_slot_link` does on the client's ack, with the
    // epoch that link carries.
    let ack = async {
        loop {
            if let Some(probe_id) = inbox.try_recv_load_state_probe() {
                assert!(fence.resolve(probe_id, &key(7), SlotId(0), LINK_EPOCH));
                return;
            }
            tokio::task::yield_now().await;
        }
    };
    let (load, ()) = tokio::join!(
        fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)),
        ack,
    );
    assert!(
        load.fenced(),
        "every slot that could hold something back acked"
    );
    assert!(load.fenced_live && load.closed_slots.is_empty());
    assert_eq!(load.state.slots, vec![SlotId(0)]);
    assert!(load.state.started.is_empty());
}

#[tokio::test]
async fn a_slot_that_arrives_mid_fence_leaves_the_answer_unfenced() {
    // A client that dials in after the roster was read is live and unstarted in
    // the snapshot without ever having been asked anything, and it is not
    // "away", so the ever-connected check passes it. Its own `GameStarted` may
    // be queued in its driver right now — exactly what the fence exists to rule
    // out — so the membership change alone withholds the claim.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();
    let (mut registration, mut inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), LINK_EPOCH)
            .expect("slot 0 registers");
    registration.disarm();
    decision_makers.note_slot_connected(&key(7), SlotId(0), false, None, None);

    let ack = async {
        loop {
            if let Some(probe_id) = inbox.try_recv_load_state_probe() {
                // Slot 1 connects while slot 0's probe is outstanding.
                let (mut late, _late_inbox) =
                    crate::routing::register(&sessions, &key(7), SlotId(1), LINK_EPOCH)
                        .expect("slot 1 registers");
                late.disarm();
                assert!(fence.resolve(probe_id, &key(7), SlotId(0), LINK_EPOCH));
                return;
            }
            tokio::task::yield_now().await;
        }
    };
    let (load, ()) = tokio::join!(
        fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)),
        ack,
    );
    assert!(
        !load.fenced_live,
        "a slot nobody probed cannot be vouched for, however promptly the rest answered",
    );
    assert!(!load.fenced());
    assert!(
        load.closed_slots.is_empty(),
        "the arrival is live, not closed"
    );
    assert_eq!(
        load.state.slots,
        vec![SlotId(0), SlotId(1)],
        "the arrival is still reported; only the negative inference is withheld",
    );
}

#[tokio::test]
async fn a_link_replaced_after_acking_leaves_the_answer_unfenced() {
    // The ack spoke for one stream's position. The client then dialed back in,
    // and the new stream has its own queue of owed reports that the old one's
    // ack says nothing about — so the same slot on a new epoch is as unfenced
    // as one that never answered, even though the seat never looked empty.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();
    let (registration, mut inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), LINK_EPOCH)
            .expect("slot 0 registers");
    // Left armed: dropping it is how this test ends the link that acked.
    let mut original = Some(registration);
    decision_makers.note_slot_connected(&key(7), SlotId(0), false, None, None);

    let ack = async {
        loop {
            if let Some(probe_id) = inbox.try_recv_load_state_probe() {
                assert!(fence.resolve(probe_id, &key(7), SlotId(0), LINK_EPOCH));
                drop(original.take());
                let (mut reconnect, _reconnect_inbox) =
                    crate::routing::register(&sessions, &key(7), SlotId(0), REPLACEMENT_EPOCH)
                        .expect("the reconnect claims the seat");
                reconnect.disarm();
                return;
            }
            tokio::task::yield_now().await;
        }
    };
    let (load, ()) = tokio::join!(
        fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)),
        ack,
    );
    assert!(
        !load.fenced_live,
        "an ack from the connection before the reconnect fences nothing"
    );
    assert!(
        load.closed_slots.is_empty(),
        "a slot that dialed back in is live again, so it is not closed",
    );
    assert_eq!(
        load.state.slots,
        vec![SlotId(0)],
        "the seat is occupied throughout, so nothing but the epoch gives the swap away",
    );
}

#[tokio::test]
async fn a_live_unstarted_slot_that_never_acks_leaves_the_answer_unfenced() {
    // Silence is not an ack. The slot's facts still go up — the answer is as
    // real as any other — but nothing licenses reading its absence from
    // `started` as proof its game never began. What a stuck client costs is one
    // fence window, so the window is injected short rather than waited out.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence =
        crate::coordinator::load_fence::LoadStateFence::with_timeout(Duration::from_millis(50));
    let (mut registration, mut inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), LINK_EPOCH)
            .expect("slot 0 registers");
    registration.disarm();
    decision_makers.note_slot_connected(&key(7), SlotId(0), false, None, None);

    let load = fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)).await;
    assert!(
        !load.fenced_live,
        "an unanswered probe leaves its slot unfenced"
    );
    assert!(load.closed_slots.is_empty());
    assert_eq!(load.state.slots, vec![SlotId(0)]);
    assert!(
        inbox.try_recv_load_state_probe().is_some(),
        "the probe was written to the slot's stream even though it went unanswered",
    );
}

#[tokio::test]
async fn a_started_slot_is_not_probed_at_all() {
    // A slot that already reported has nothing left to owe, so the fence spends
    // no probe on it and the answer is fenced outright.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();
    let (mut registration, mut inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), LINK_EPOCH)
            .expect("slot 0 registers");
    registration.disarm();
    decision_makers.note_slot_connected(&key(7), SlotId(0), false, None, None);
    decision_makers.note_slot_started(&key(7), SlotId(0));

    let load = fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)).await;
    assert!(load.fenced());
    assert_eq!(load.state.started, vec![SlotId(0)]);
    assert!(
        inbox.try_recv_load_state_probe().is_none(),
        "a slot with nothing left to report is not probed",
    );
}

#[tokio::test]
async fn a_slot_that_connected_and_then_dropped_can_never_be_fenced() {
    // There is no stream to probe and the client may be holding its report for
    // the stream it opens next, so this relay cannot vouch for the slot's
    // absence however promptly everything else answers.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();
    let (registration, _inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), LINK_EPOCH)
            .expect("slot 0 registers");
    decision_makers.note_slot_connected(&key(7), SlotId(0), false, None, None);
    // The link ends: the guard deregisters the slot, leaving it ever-connected
    // and not live.
    drop(registration);

    let load = fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)).await;
    assert!(!load.fenced());
    assert!(load.state.slots.is_empty());
    assert_eq!(load.state.ever_connected, vec![SlotId(0)]);
    // It is named rather than silently spoiling the answer, and nothing else
    // here was left unvouched.
    assert_eq!(closed_slot_ids(&load), vec![SlotId(0)]);
    assert!(load.fenced_live);
}

#[tokio::test]
async fn closed_slots_are_named_while_the_live_ones_are_still_fenced() {
    // Two slots drop at once beside one that stays and acks. The fence cannot
    // reach the two, but naming them keeps the third's verdict usable: the
    // answer vouches for every slot outside the closed set.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();
    for slot in [SlotId(0), SlotId(1)] {
        let (registration, _inbox) =
            crate::routing::register(&sessions, &key(7), slot, LINK_EPOCH).expect("registers");
        decision_makers.note_slot_connected(&key(7), slot, false, None, None);
        drop(registration);
    }
    let (mut registration, mut inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(2), LINK_EPOCH)
            .expect("slot 2 registers");
    registration.disarm();
    decision_makers.note_slot_connected(&key(7), SlotId(2), false, None, None);

    let ack = async {
        loop {
            if let Some(probe_id) = inbox.try_recv_load_state_probe() {
                assert!(fence.resolve(probe_id, &key(7), SlotId(2), LINK_EPOCH));
                return;
            }
            tokio::task::yield_now().await;
        }
    };
    let (load, ()) = tokio::join!(
        fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)),
        ack,
    );
    assert_eq!(closed_slot_ids(&load), vec![SlotId(0), SlotId(1)]);
    assert!(load.fenced_live, "the one live slot acked on its own link");
    assert!(
        !load.fenced(),
        "the closed slots still withhold the whole verdict"
    );
}

#[tokio::test]
async fn a_closed_slot_beside_a_silent_live_one_withholds_the_live_verdict() {
    // Naming the closed slot says nothing about the rest: a live slot that never
    // acks is as unvouched as ever.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence =
        crate::coordinator::load_fence::LoadStateFence::with_timeout(Duration::from_millis(50));
    let (registration, _inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), LINK_EPOCH)
            .expect("slot 0 registers");
    decision_makers.note_slot_connected(&key(7), SlotId(0), false, None, None);
    drop(registration);
    let (mut registration, _silent_inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(1), LINK_EPOCH)
            .expect("slot 1 registers");
    registration.disarm();
    decision_makers.note_slot_connected(&key(7), SlotId(1), false, None, None);

    let load = fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)).await;
    assert_eq!(closed_slot_ids(&load), vec![SlotId(0)]);
    assert!(!load.fenced_live);
}

#[tokio::test]
async fn a_slot_that_dropped_and_dialed_back_in_is_fenced_on_its_new_link() {
    // A drop the client recovers from before the question is asked leaves
    // nothing behind: the new link is live, is probed on its own epoch, and
    // acks, so the slot is neither closed nor unvouched.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();
    let (registration, _inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), LINK_EPOCH)
            .expect("slot 0 registers");
    decision_makers.note_slot_connected(&key(7), SlotId(0), false, None, None);
    drop(registration);
    let (mut reconnect, mut inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), REPLACEMENT_EPOCH)
            .expect("the reconnect claims the seat");
    reconnect.disarm();
    decision_makers.note_slot_connected(&key(7), SlotId(0), true, None, None);

    let ack = async {
        loop {
            if let Some(probe_id) = inbox.try_recv_load_state_probe() {
                assert!(fence.resolve(probe_id, &key(7), SlotId(0), REPLACEMENT_EPOCH));
                return;
            }
            tokio::task::yield_now().await;
        }
    };
    let (load, ()) = tokio::join!(
        fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)),
        ack,
    );
    assert!(load.closed_slots.is_empty());
    assert!(load.fenced());
}

#[tokio::test]
async fn a_slot_activating_mid_snapshot_is_never_taken_for_a_closed_one() {
    // The snapshot's two reads take different locks. A slot that registers and
    // activates between them must come out live and unfenced — asked again next
    // read — and never as ever-connected-but-gone beside a live verdict, which
    // would let a tenant blame a player who is right there.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();
    let mut arrival = None;
    let load = fenced_load_state_snapshot_with(&sessions, &decision_makers, &fence, key(7), || {
        let (mut registration, inbox) =
            crate::routing::register(&sessions, &key(7), SlotId(0), LINK_EPOCH)
                .expect("slot 0 registers");
        registration.disarm();
        decision_makers.note_slot_connected(&key(7), SlotId(0), false, None, None);
        arrival = Some(inbox);
    })
    .await;
    assert!(arrival.is_some(), "the arrival landed between the reads");
    assert!(
        load.closed_slots.is_empty(),
        "the arrival is live, not closed"
    );
    assert_eq!(load.state.slots, vec![SlotId(0)]);
    assert!(
        !load.fenced_live,
        "a live link nobody probed is not vouched for"
    );
}

#[tokio::test]
async fn a_slot_leaving_mid_snapshot_is_reported_closed() {
    // The other way a link can change between the reads: the slot acked, then its
    // link ended before the roster was read. It is genuinely gone, so it is named
    // closed, and the live verdict over everything else still stands.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();
    let (registration, mut inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), LINK_EPOCH)
            .expect("slot 0 registers");
    decision_makers.note_slot_connected(&key(7), SlotId(0), false, None, None);
    let mut link = Some(registration);

    let ack = async {
        loop {
            if let Some(probe_id) = inbox.try_recv_load_state_probe() {
                assert!(fence.resolve(probe_id, &key(7), SlotId(0), LINK_EPOCH));
                return;
            }
            tokio::task::yield_now().await;
        }
    };
    let (load, ()) = tokio::join!(
        fenced_load_state_snapshot_with(&sessions, &decision_makers, &fence, key(7), || {
            drop(link.take());
        }),
        ack,
    );
    assert!(link.is_none(), "the link ended between the reads");
    assert_eq!(closed_slot_ids(&load), vec![SlotId(0)]);
    assert!(load.state.slots.is_empty());
    assert!(load.fenced_live);
}

#[tokio::test]
async fn a_closed_slot_names_the_link_whose_closure_left_it_closed() {
    // Two closed readings of one slot are one disconnection only if nothing
    // reconnected in between, so each names its link: a slot that comes back and
    // leaves again is reported on its new link's epoch.
    use rally_point_proto::control::ClosedSlot;
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();
    let closed_on = |epoch| ClosedSlot {
        slot: SlotId(0),
        link_epoch: Some(epoch),
    };
    for epoch in [LINK_EPOCH, REPLACEMENT_EPOCH] {
        let (registration, _inbox) =
            crate::routing::register(&sessions, &key(7), SlotId(0), epoch).expect("registers");
        decision_makers.note_slot_connected(
            &key(7),
            SlotId(0),
            epoch != LINK_EPOCH,
            None,
            Some(epoch),
        );
        drop(registration);

        let load = fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)).await;
        assert_eq!(load.closed_slots, vec![closed_on(epoch)]);
        assert!(load.fenced_live);
    }
}

#[tokio::test]
async fn a_link_that_comes_and_goes_mid_snapshot_withholds_the_live_verdict() {
    // The closed slot's epoch is read before the roster. A link of the slot that
    // activates and closes between the two reads leaves that epoch naming the
    // earlier closure, not the one the roster saw, so the answer must not vouch
    // for it.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();
    let (registration, _inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), LINK_EPOCH).expect("registers");
    decision_makers.note_slot_connected(&key(7), SlotId(0), false, None, Some(LINK_EPOCH));
    drop(registration);

    let load = fenced_load_state_snapshot_with(&sessions, &decision_makers, &fence, key(7), || {
        let (registration, _inbox) =
            crate::routing::register(&sessions, &key(7), SlotId(0), REPLACEMENT_EPOCH)
                .expect("the reconnect registers");
        decision_makers.note_slot_connected(
            &key(7),
            SlotId(0),
            true,
            None,
            Some(REPLACEMENT_EPOCH),
        );
        drop(registration);
    })
    .await;
    assert_eq!(closed_slot_ids(&load), vec![SlotId(0)]);
    assert!(
        !load.fenced_live,
        "the closure the roster saw is not the one named"
    );
}

#[tokio::test]
async fn a_slot_that_never_connected_here_needs_no_fence() {
    // Nothing this relay serves is holding anything for a slot no client ever
    // opened a stream for, so its absence is attestable as it stands — which is
    // the whole point of answering an empty session at all.
    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();

    let load = fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)).await;
    assert!(
        load.fenced(),
        "an absence with no client behind it needs no probe"
    );
    assert!(load.state.slots.is_empty() && load.state.ever_connected.is_empty());
}

#[tokio::test]
async fn an_ask_beyond_the_fence_cap_is_shed_without_probing() {
    // The bound that actually holds. The ask channel is drained the instant a
    // question arrives, so its depth caps questions queued, not probing under
    // way; the seat caps the probing. An ask that finds none costs nothing —
    // no task, no probe, no answer — and the coordinator reads that silence as
    // this relay not having attested.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();
    let (mut registration, mut inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), LINK_EPOCH)
            .expect("slot 0 registers");
    registration.disarm();
    decision_makers.note_slot_connected(&key(7), SlotId(0), false, None, None);
    let sources = HeartbeatSources {
        session_gates: crate::session::gate::SessionGates::default(),
        provisional_turns: crate::session::provisional_turns::ProvisionalTurnPen::default(),
        sessions: Arc::clone(&sessions),
        decision_makers: Arc::clone(&decision_makers),
        region_rtt_cache: RegionRttCache::default(),
        load_fence: fence.clone(),
    };
    let (answers_tx, mut answers_rx) =
        tokio::sync::mpsc::channel::<LoadStateAnswer>(LOAD_STATE_ASK_CAPACITY);

    let mut seats: Vec<_> = (0..crate::coordinator::load_fence::MAX_ACTIVE_LOAD_FENCES)
        .map(|_| fence.try_start().expect("a fence under the cap starts"))
        .collect();
    start_load_state_answer(
        &sources,
        LoadStateAsk {
            request_id: 1,
            settle_lobby: false,
            key: key(7),
        },
        &answers_tx,
    );
    // A fence task registers and delivers every probe before its first await,
    // so one turn of the scheduler is enough for a spawned one to be visible.
    tokio::task::yield_now().await;
    assert_eq!(
        fence.pending_count(),
        0,
        "a shed ask starts no fence, so nothing was probed",
    );
    assert!(inbox.try_recv_load_state_probe().is_none());
    assert!(answers_rx.try_recv().is_err(), "and it produces no answer");

    // The control: with a seat free the same ask does probe, so the silence
    // above is the cap and not the harness.
    seats.pop();
    start_load_state_answer(
        &sources,
        LoadStateAsk {
            request_id: 2,
            settle_lobby: false,
            key: key(7),
        },
        &answers_tx,
    );
    tokio::task::yield_now().await;
    assert_eq!(fence.pending_count(), 1);
    assert!(inbox.try_recv_load_state_probe().is_some());
}
