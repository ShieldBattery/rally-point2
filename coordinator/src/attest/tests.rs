use rally_point_proto::ids::SlotId;

use super::*;

fn tid() -> TenantId {
    TenantId("sb-test".to_owned())
}

fn snapshot(session: SessionId, ever_connected: &[u8]) -> AttestedSnapshot {
    AttestedSnapshot {
        state: SessionPresence {
            tenant: tid(),
            session,
            slots: vec![],
            ever_connected: ever_connected.iter().map(|&s| SlotId(s)).collect(),
            started: vec![],
            started_at_ms: None,
        },
        fenced: true,
    }
}

#[tokio::test]
async fn a_request_reaches_the_relay_and_its_answer_reaches_the_waiter() {
    let attest = LoadStateAttest::new();
    let mut asks = attest.subscribe(RelayId(1));
    let mut pending = attest
        .request(RelayId(1), &tid(), SessionId(5))
        .expect("the relay is connected");
    let ask = asks.recv().await.expect("the question was queued");
    assert_eq!(ask.tenant, tid());
    assert_eq!(ask.session, SessionId(5));

    attest
        .resolve(ask.request_id, RelayId(1), snapshot(SessionId(5), &[0, 2]))
        .expect("the id is outstanding for this relay");
    assert_eq!(
        pending.recv().await.map(|s| s.state.ever_connected),
        Some(vec![SlotId(0), SlotId(2)]),
    );
}

#[tokio::test]
async fn a_relay_with_no_connection_cannot_be_asked() {
    let attest = LoadStateAttest::new();
    assert!(attest.request(RelayId(9), &tid(), SessionId(5)).is_none());
    assert_eq!(attest.pending_count(), 0);
}

#[tokio::test]
async fn a_dead_connection_is_dropped_rather_than_asked_again() {
    // The writer's receiver going away means nothing will read the question, so
    // the request fails outright instead of parking a waiter nothing can answer.
    let attest = LoadStateAttest::new();
    let asks = attest.subscribe(RelayId(1));
    drop(asks);
    assert!(attest.request(RelayId(1), &tid(), SessionId(5)).is_none());
    assert!(attest.request(RelayId(1), &tid(), SessionId(5)).is_none());
    assert_eq!(attest.pending_count(), 0);
}

#[tokio::test]
async fn ids_do_not_cross_match_between_relays_sessions_or_reads() {
    let attest = LoadStateAttest::new();
    let mut asks_one = attest.subscribe(RelayId(1));
    let _asks_two = attest.subscribe(RelayId(2));
    let mut pending = attest
        .request(RelayId(1), &tid(), SessionId(5))
        .expect("connected");
    let ask = asks_one.recv().await.expect("queued");

    // Another relay answering in relay 1's name.
    assert_eq!(
        attest.resolve(ask.request_id, RelayId(2), snapshot(SessionId(5), &[0])),
        Err(StaleSnapshot),
    );
    // The right relay, the wrong session.
    assert_eq!(
        attest.resolve(ask.request_id, RelayId(1), snapshot(SessionId(6), &[0])),
        Err(StaleSnapshot),
    );
    // An id nobody is waiting on.
    assert_eq!(
        attest.resolve(
            ask.request_id.wrapping_add(1),
            RelayId(1),
            snapshot(SessionId(5), &[0]),
        ),
        Err(StaleSnapshot),
    );
    // None of that consumed the request, and the real answer still lands.
    attest
        .resolve(ask.request_id, RelayId(1), snapshot(SessionId(5), &[1]))
        .expect("outstanding");
    assert_eq!(
        pending.recv().await.map(|s| s.state.ever_connected),
        Some(vec![SlotId(1)]),
    );
    // A second answer for the same id is stale: the request is consumed.
    assert_eq!(
        attest.resolve(ask.request_id, RelayId(1), snapshot(SessionId(5), &[1])),
        Err(StaleSnapshot),
    );
}

#[tokio::test]
async fn a_waiter_that_gives_up_retires_its_request() {
    let attest = LoadStateAttest::new();
    let mut asks = attest.subscribe(RelayId(1));
    let pending = attest
        .request(RelayId(1), &tid(), SessionId(5))
        .expect("connected");
    let ask = asks.recv().await.expect("queued");
    assert_eq!(attest.pending_count(), 1);

    drop(pending);
    assert_eq!(attest.pending_count(), 0, "the map tracks live reads only");
    assert_eq!(
        attest.resolve(ask.request_id, RelayId(1), snapshot(SessionId(5), &[0])),
        Err(StaleSnapshot),
        "an answer for an abandoned read is discarded",
    );
}

#[tokio::test]
async fn a_full_question_channel_is_a_non_answer_rather_than_a_block() {
    // A relay whose writer has stopped draining must cost the read its
    // completeness claim, never the coordinator's thread. The sender stays —
    // the connection is alive and will drain — so the relay answers again the
    // moment it catches up.
    let attest = LoadStateAttest::new();
    let mut asks = attest.subscribe(RelayId(1));
    let mut filled = Vec::new();
    for _ in 0..LOAD_STATE_ASK_CAPACITY {
        filled.push(
            attest
                .request(RelayId(1), &tid(), SessionId(5))
                .expect("the channel has room"),
        );
    }
    assert!(
        attest.request(RelayId(1), &tid(), SessionId(5)).is_none(),
        "a full channel answers nothing rather than queueing behind the backlog",
    );
    assert_eq!(
        attest.pending_count(),
        LOAD_STATE_ASK_CAPACITY,
        "a refused question parks no waiter",
    );

    asks.recv().await.expect("the backlog drains");
    assert!(
        attest.request(RelayId(1), &tid(), SessionId(5)).is_some(),
        "the sender survives a full channel, so a caught-up relay is asked again",
    );
}

#[tokio::test]
async fn concurrent_reads_of_one_session_share_a_single_round() {
    // The fanout bound: one round's questions serve every read that joined it,
    // so a tenant polling a session hard cannot multiply fleet-wide traffic by
    // the number of requests it has in flight.
    let attest = LoadStateAttest::new();
    let RoundEntry::Leader(leader) = attest.begin_round(&tid(), SessionId(5)) else {
        panic!("the first caller leads");
    };
    let RoundEntry::Joined(watch) = attest.begin_round(&tid(), SessionId(5)) else {
        panic!("a second caller joins rather than leading");
    };
    // A different session is a different round: sharing is per-session. Bound
    // rather than matched in place — the handle retires its round when dropped.
    let other = attest.begin_round(&tid(), SessionId(6));
    assert!(matches!(other, RoundEntry::Leader(_)));
    assert_eq!(attest.round_count(), 2);

    let started_before_any_request = Instant::now();
    leader.publish(AttestRound {
        started_before_any_request,
        attested: Arc::new(HashSet::from([RelayId(1)])),
        fenced: Arc::new(HashSet::from([RelayId(1)])),
    });
    let joined = joined_round(watch).await.expect("the round published");
    assert_eq!(
        joined.started_before_any_request,
        started_before_any_request
    );
    assert_eq!(*joined.attested, HashSet::from([RelayId(1)]));
}

#[test]
fn a_round_stamped_at_the_very_instant_a_read_arrived_does_not_answer_it() {
    // Equal samples of a monotonic clock cannot order the two events, so the
    // read must not take the round; only a strictly later boundary can.
    let asked_at = Instant::now();
    assert!(!round_answers_read(asked_at, asked_at));
    assert!(!round_answers_read(
        asked_at - Duration::from_nanos(1),
        asked_at
    ));
    assert!(round_answers_read(
        asked_at + Duration::from_nanos(1),
        asked_at
    ));
}

/// A round stamped as having begun at `started`, carrying `relay` as its one
/// attesting and fenced answerer.
fn round_started_at(started: Instant, relay: RelayId) -> AttestRound {
    AttestRound {
        started_before_any_request: started,
        attested: Arc::new(HashSet::from([relay])),
        fenced: Arc::new(HashSet::from([relay])),
    }
}

#[tokio::test]
async fn a_read_that_arrived_mid_round_leads_its_own() {
    // The interleaving the boundary exists for: the leader takes its instant and
    // asks relay 1, which snapshots and answers; a read arrives; only then is
    // relay 2 asked. Relay 1's snapshot predates the second read entirely, so
    // the round cannot answer it however late the fan-out finished — the read
    // waits the round out and runs one of its own.
    let attest = LoadStateAttest::new();
    let rounds_run = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let joiner = tokio::spawn({
        let attest = attest.clone();
        let rounds_run = Arc::clone(&rounds_run);
        async move {
            // Arrives while the leader's round is mid-fan-out.
            tokio::time::sleep(Duration::from_millis(10)).await;
            shared_round(&attest, &tid(), SessionId(5), || {
                rounds_run.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                std::future::ready(round_started_at(Instant::now(), RelayId(2)))
            })
            .await
        }
    });

    let RoundEntry::Leader(leader) = attest.begin_round(&tid(), SessionId(5)) else {
        panic!("the first caller leads");
    };
    // The boundary, taken before the first relay is asked.
    let started_before_any_request = Instant::now();
    // Relay 1 answers, the joiner arrives, relay 2 is asked, the round finishes.
    tokio::time::sleep(Duration::from_millis(20)).await;
    leader.publish(round_started_at(started_before_any_request, RelayId(1)));

    let joined = joiner.await.expect("the joining read finishes");
    assert_eq!(
        *joined.attested,
        HashSet::from([RelayId(2)]),
        "the joiner answered from its own round, not the one it arrived into",
    );
    assert_eq!(
        rounds_run.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "and it ran exactly one round of its own",
    );
}

#[tokio::test]
async fn a_read_that_arrived_before_the_boundary_shares_the_round() {
    // The other side of the same rule, and the reason sharing is worth having:
    // a read already waiting when the round took its instant is covered by every
    // snapshot that round collects, so it answers from the shared outcome and
    // costs the fleet no questions of its own.
    let attest = LoadStateAttest::new();
    let rounds_run = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let RoundEntry::Leader(leader) = attest.begin_round(&tid(), SessionId(5)) else {
        panic!("the first caller leads");
    };
    let joiner = tokio::spawn({
        let attest = attest.clone();
        let rounds_run = Arc::clone(&rounds_run);
        async move {
            shared_round(&attest, &tid(), SessionId(5), || {
                rounds_run.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                std::future::ready(round_started_at(Instant::now(), RelayId(2)))
            })
            .await
        }
    });

    // Let the joiner arrive and park on the round, then take the boundary and
    // run the fan-out.
    tokio::time::sleep(Duration::from_millis(10)).await;
    leader.publish(round_started_at(Instant::now(), RelayId(1)));

    let joined = joiner.await.expect("the joining read finishes");
    assert_eq!(
        *joined.attested,
        HashSet::from([RelayId(1)]),
        "the joiner answers from the round it shared",
    );
    assert_eq!(
        rounds_run.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "and asks the fleet nothing of its own",
    );
}

#[tokio::test]
async fn a_round_whose_leader_leaves_without_publishing_frees_the_next_caller() {
    // A leader whose HTTP request was cancelled must not wedge the session: the
    // joiner learns there is no outcome and the entry is gone, so the next
    // caller leads.
    let attest = LoadStateAttest::new();
    let RoundEntry::Leader(leader) = attest.begin_round(&tid(), SessionId(5)) else {
        panic!("the first caller leads");
    };
    let RoundEntry::Joined(watch) = attest.begin_round(&tid(), SessionId(5)) else {
        panic!("a second caller joins");
    };

    drop(leader);
    assert!(joined_round(watch).await.is_none(), "there is no outcome");
    assert_eq!(attest.round_count(), 0, "the map tracks live rounds only");
    let next = attest.begin_round(&tid(), SessionId(5));
    assert!(matches!(next, RoundEntry::Leader(_)));
}

#[tokio::test]
async fn a_request_nobody_waits_on_is_no_longer_pending() {
    // What the control connection's writer checks before spending a frame: a
    // read that timed out retires its request on the way out.
    let attest = LoadStateAttest::new();
    let mut asks = attest.subscribe(RelayId(1));
    let pending = attest
        .request(RelayId(1), &tid(), SessionId(5))
        .expect("connected");
    let ask = asks.recv().await.expect("queued");
    assert!(attest.is_pending(ask.request_id));

    drop(pending);
    assert!(!attest.is_pending(ask.request_id));
}

#[tokio::test]
async fn a_reconnect_replaces_the_question_channel() {
    // A relay's fresh control connection owns the live receiver; the prior one's
    // is dropped, so a question can never be delivered to a dead writer.
    let attest = LoadStateAttest::new();
    let mut old = attest.subscribe(RelayId(1));
    let mut new = attest.subscribe(RelayId(1));
    let _pending = attest
        .request(RelayId(1), &tid(), SessionId(5))
        .expect("connected");
    assert!(new.recv().await.is_some());
    assert!(old.recv().await.is_none(), "the old channel is closed");
}
