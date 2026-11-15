//! A retired session's kept load facts: what each retirement path records, how a
//! record answers and combines with a state created after it, and how records
//! expire and are pruned.

use super::*;

/// Waits (bounded) until `session`'s lifecycle state has been retired.
async fn wait_until_retired(lc: &Lifecycle, session: SessionId) {
    timeout(Duration::from_secs(2), async {
        while lc.contains_state(&tid(), session) {
            tokio::time::sleep(SHORT / 4).await;
        }
    })
    .await
    .expect("the state is retired");
}

/// What a load-state read answers from a retired session's record alone: the
/// given facts, and nothing a completeness claim could rest on.
fn retired_answer(
    started_at_ms: Option<u64>,
    connected: &[u8],
    started: &[u8],
    forwarded: &[u8],
    lobby_violations: &[u8],
) -> SessionLoadState {
    SessionLoadState {
        evidence: Vec::new(),
        created_here: false,
        attestable: false,
        serving_relays: Vec::new(),
        started_at_ms,
        connected_slots: slots(connected),
        started_slots: slots(started),
        forwarded_slots: slots(forwarded),
        lobby_violation_slots: slots(lobby_violations),
    }
}

/// Registers `session` as served by relay 1 with player slots 0 and 1.
fn register_on_relay_one(lc: &Lifecycle, session: SessionId) {
    lc.register_session(
        tid(),
        session,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
}

#[tokio::test]
async fn a_session_that_started_and_closed_still_answers_its_load_facts() {
    // The short game: both players connected, one reported its loop, the relay
    // forwarded its turns, and the session closed, all before the tenant's load
    // deadline. The read that deadline triggers must still find every fact.
    let lc = Lifecycle::new(bare_setup());
    let s = SessionId(1);
    register_on_relay_one(&lc, s);
    lc.on_slot_connected(tid(), s, SlotId(1));
    lc.on_slot_connected(tid(), s, SlotId(0));
    lc.on_slot_started(tid(), s, SlotId(0));
    lc.on_session_started(tid(), s, 1_700_000_000_000);
    lc.on_lobby_violation(tid(), s, SlotId(1));
    lc.merge_load_state(&[SessionPresence {
        forwarded: slots(&[0]),
        ..presence_entry(&tid(), s, &[])
    }]);

    close(&lc, tid(), s, RelayId(1));
    assert!(!lc.contains_state(&tid(), s), "the live state is retired");
    assert_eq!(
        lc.load_state(&tid(), s),
        Some(retired_answer(
            Some(1_700_000_000_000),
            &[0, 1],
            &[0],
            &[0],
            &[1]
        )),
        "every positive fact survives the close, sorted, with no claim attached",
    );
}

#[tokio::test]
async fn a_never_started_reap_keeps_the_facts_its_state_held() {
    // A lobby violation marks nothing started, so a session can hold one and
    // still be reaped as never started.
    let lc = Lifecycle::with_tunables(
        bare_setup(),
        LifecycleTunables {
            never_started_grace: SHORT,
            ..Default::default()
        },
    );
    let s = SessionId(1);
    register_on_relay_one(&lc, s);
    lc.on_lobby_violation(tid(), s, SlotId(1));

    wait_until_retired(&lc, s).await;
    assert_eq!(
        lc.load_state(&tid(), s),
        Some(retired_answer(None, &[], &[], &[], &[1])),
    );
}

#[tokio::test]
async fn an_empty_session_reap_keeps_the_facts_its_state_held() {
    let (setup, s) = setup_with_relay_and_session();
    let lc = Lifecycle::with_tunables(
        setup.clone(),
        LifecycleTunables {
            empty_session_grace: SHORT,
            ..Default::default()
        },
    );
    lc.register_session(
        tid(),
        s,
        setup.serving_relays(&tid(), s),
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    lc.on_slot_connected(tid(), s, SlotId(0));
    lc.on_slot_started(tid(), s, SlotId(0));
    lc.on_relay_enrolled(RelayId(1), 7);
    lc.on_relay_heartbeat(
        RelayId(1),
        7,
        &[presence_entry(&tid(), s, &[0])],
        true,
        Instant::now(),
    );
    lc.on_relay_heartbeat(RelayId(1), 7, &[], true, Instant::now());

    wait_until_retired(&lc, s).await;
    assert_eq!(
        lc.load_state(&tid(), s),
        Some(retired_answer(None, &[0], &[0], &[], &[])),
    );
}

#[tokio::test]
async fn a_webhook_only_reap_keeps_the_facts_its_state_held() {
    // Restart amnesia: a notice lazily created the state, which never gains a
    // serving set and is reaped once idle. Its facts are kept like any other's.
    let lc = Lifecycle::with_tunables(
        bare_setup(),
        LifecycleTunables {
            webhook_grace: SHORT,
            ..Default::default()
        },
    );
    let s = SessionId(1);
    lc.on_slot_started(tid(), s, SlotId(0));

    wait_until_retired(&lc, s).await;
    assert_eq!(
        lc.load_state(&tid(), s),
        Some(retired_answer(None, &[], &[0], &[], &[])),
    );
}

#[tokio::test]
async fn an_expired_record_answers_nothing_and_is_dropped_on_read() {
    // A zero retention expires a record the moment it is written.
    let lc = Lifecycle::with_tunables(
        bare_setup(),
        LifecycleTunables {
            closed_load_facts_retention: Duration::ZERO,
            ..Default::default()
        },
    );
    let s = SessionId(1);
    register_on_relay_one(&lc, s);
    lc.on_slot_connected(tid(), s, SlotId(0));
    close(&lc, tid(), s, RelayId(1));
    assert_eq!(
        lc.closed_load_facts_count(),
        1,
        "the close recorded the facts"
    );

    assert_eq!(
        lc.load_state(&tid(), s),
        None,
        "an expired record is absent"
    );
    assert_eq!(
        lc.closed_load_facts_count(),
        0,
        "and the read that found it expired removed it",
    );
}

#[tokio::test]
async fn a_record_survives_a_later_state_for_the_session_and_absorbs_it() {
    // A late notice can lazily create a fresh state for a session that already
    // closed. While it lives, the answer is that state's with the record unioned
    // in; once it is reaped, the record absorbs it rather than being replaced.
    let lc = Lifecycle::with_tunables(
        bare_setup(),
        LifecycleTunables {
            webhook_grace: SHORT,
            ..Default::default()
        },
    );
    let s = SessionId(1);
    register_on_relay_one(&lc, s);
    lc.on_slot_connected(tid(), s, SlotId(0));
    lc.on_slot_started(tid(), s, SlotId(0));
    lc.on_session_started(tid(), s, 100);
    close(&lc, tid(), s, RelayId(1));

    lc.on_slot_started(tid(), s, SlotId(1));
    lc.on_session_started(tid(), s, 50);
    assert!(
        lc.contains_state(&tid(), s),
        "the late notice made a new state"
    );
    let combined = retired_answer(Some(100), &[0], &[0, 1], &[], &[]);
    assert_eq!(
        lc.load_state(&tid(), s),
        Some(combined.clone()),
        "both halves' sets, and the start instant recorded first",
    );

    wait_until_retired(&lc, s).await;
    assert_eq!(lc.closed_load_facts_count(), 1);
    assert_eq!(
        lc.load_state(&tid(), s),
        Some(combined),
        "the record absorbed the reaped state's facts and kept its own start",
    );
}

#[tokio::test]
async fn a_state_with_no_positive_fact_leaves_no_record() {
    let lc = Lifecycle::with_tunables(
        bare_setup(),
        LifecycleTunables {
            webhook_grace: SHORT,
            ..Default::default()
        },
    );
    let s = SessionId(1);
    register_on_relay_one(&lc, s);
    close(&lc, tid(), s, RelayId(1));
    assert_eq!(lc.closed_load_facts_count(), 0);
    assert_eq!(lc.load_state(&tid(), s), None);

    // Nor does a factless state disturb a record another retirement left: an
    // orphan with nothing in it is reaped without touching the record.
    let other = SessionId(2);
    register_on_relay_one(&lc, other);
    lc.on_slot_connected(tid(), other, SlotId(0));
    close(&lc, tid(), other, RelayId(1));
    lc.ensure_orphan_tracked(tid(), other);
    wait_until_retired(&lc, other).await;
    assert_eq!(lc.closed_load_facts_count(), 1);
    assert_eq!(
        lc.load_state(&tid(), other),
        Some(retired_answer(None, &[0], &[], &[], &[])),
    );
}

#[tokio::test]
async fn recording_a_retirement_prunes_every_expired_record() {
    // No timer prunes the map: writing a record drops whatever has expired by
    // then. The second retirement is stamped a full retention after the first,
    // so the first is expired at that instant and must be gone.
    let lc = Lifecycle::new(bare_setup());
    let first = SessionId(1);
    register_on_relay_one(&lc, first);
    lc.on_slot_connected(tid(), first, SlotId(0));
    close(&lc, tid(), first, RelayId(1));
    assert_eq!(lc.closed_load_facts_count(), 1);

    let second = SessionId(2);
    let mut state = lc.new_state(Vec::new());
    state.started_slots.insert(SlotId(1));
    {
        let _sessions = lc.inner.sessions.lock();
        lc.record_closed_load_facts(
            &(tid(), second),
            &state,
            Instant::now() + CLOSED_LOAD_FACTS_RETENTION,
        );
    }
    assert_eq!(
        lc.closed_load_facts_count(),
        1,
        "the expired record is pruned"
    );
    assert_eq!(lc.load_state(&tid(), first), None);
    assert_eq!(
        lc.load_state(&tid(), second),
        Some(retired_answer(None, &[], &[1], &[], &[])),
    );
}
