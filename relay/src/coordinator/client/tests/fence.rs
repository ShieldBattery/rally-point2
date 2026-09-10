//! The load-state fence: which slots are probed, what an ack proves, and every
//! way a membership change across the wait withholds the fenced verdict.

use super::*;

/// A session with a decision-maker and no bounds worth speaking of — enough for
/// the retained load state a fence reads and re-reads.
fn fence_fixture() -> (Sessions, Arc<crate::consensus::DecisionMakers>) {
    let sessions: Sessions = Arc::default();
    let decision_makers = Arc::new(crate::consensus::new_decision_makers());
    let _ = crate::consensus::sync_maker(
        &decision_makers,
        &key(7),
        BufferBounds { min: 1, max: 6 },
        crate::consensus::Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    (sessions, decision_makers)
}

/// The connection epoch a fence fixture's link registers on, and the one a
/// client that dials back in takes. Any two distinct values do — an epoch is an
/// equality fence, not an ordering key.
const LINK_EPOCH: u64 = 0x51;
const REPLACEMENT_EPOCH: u64 = 0x52;

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
    crate::consensus::record_slot_connected(&decision_makers, &key(7), SlotId(0), false);

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
    let ((state, fenced), ()) = tokio::join!(
        fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)),
        ack,
    );
    assert!(fenced, "every slot that could hold something back acked");
    assert_eq!(state.slots, vec![SlotId(0)]);
    assert!(state.started.is_empty());
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
    crate::consensus::record_slot_connected(&decision_makers, &key(7), SlotId(0), false);

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
    let ((state, fenced), ()) = tokio::join!(
        fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)),
        ack,
    );
    assert!(
        !fenced,
        "a slot nobody probed cannot be vouched for, however promptly the rest answered",
    );
    assert_eq!(
        state.slots,
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
    crate::consensus::record_slot_connected(&decision_makers, &key(7), SlotId(0), false);

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
    let ((state, fenced), ()) = tokio::join!(
        fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)),
        ack,
    );
    assert!(
        !fenced,
        "an ack from the connection before the reconnect fences nothing"
    );
    assert_eq!(
        state.slots,
        vec![SlotId(0)],
        "the seat is occupied throughout, so nothing but the epoch gives the swap away",
    );
}

#[tokio::test]
async fn a_live_unstarted_slot_that_never_acks_leaves_the_answer_unfenced() {
    // Silence is not an ack. The slot's facts still go up — the answer is as
    // real as any other — but nothing licenses reading its absence from
    // `started` as proof its game never began. This one waits out a real
    // `LOAD_STATE_FENCE_TIMEOUT`, which is what a stuck client costs.
    use rally_point_proto::ids::SlotId;

    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();
    let (mut registration, mut inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), LINK_EPOCH)
            .expect("slot 0 registers");
    registration.disarm();
    crate::consensus::record_slot_connected(&decision_makers, &key(7), SlotId(0), false);

    let (state, fenced) =
        fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)).await;
    assert!(!fenced, "an unanswered probe leaves its slot unfenced");
    assert_eq!(state.slots, vec![SlotId(0)]);
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
    crate::consensus::record_slot_connected(&decision_makers, &key(7), SlotId(0), false);
    crate::consensus::record_slot_started(&decision_makers, &key(7), SlotId(0));

    let (state, fenced) =
        fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)).await;
    assert!(fenced);
    assert_eq!(state.started, vec![SlotId(0)]);
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
    crate::consensus::record_slot_connected(&decision_makers, &key(7), SlotId(0), false);
    // The link ends: the guard deregisters the slot, leaving it ever-connected
    // and not live.
    drop(registration);

    let (state, fenced) =
        fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)).await;
    assert!(!fenced);
    assert!(state.slots.is_empty());
    assert_eq!(state.ever_connected, vec![SlotId(0)]);
}

#[tokio::test]
async fn a_slot_that_never_connected_here_needs_no_fence() {
    // Nothing this relay serves is holding anything for a slot no client ever
    // opened a stream for, so its absence is attestable as it stands — which is
    // the whole point of answering an empty session at all.
    let (sessions, decision_makers) = fence_fixture();
    let fence = crate::coordinator::load_fence::LoadStateFence::new();

    let (state, fenced) =
        fenced_load_state_snapshot(&sessions, &decision_makers, &fence, key(7)).await;
    assert!(fenced, "an absence with no client behind it needs no probe");
    assert!(state.slots.is_empty() && state.ever_connected.is_empty());
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
    crate::consensus::record_slot_connected(&decision_makers, &key(7), SlotId(0), false);
    let sources = HeartbeatSources {
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
            key: key(7),
        },
        &answers_tx,
    );
    tokio::task::yield_now().await;
    assert_eq!(fence.pending_count(), 1);
    assert!(inbox.try_recv_load_state_probe().is_some());
}
