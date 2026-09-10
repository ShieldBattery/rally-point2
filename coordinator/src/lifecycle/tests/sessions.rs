//! Per-session facts: departure seeds handed to a re-home, liveness answers,
//! and how heartbeats accumulate a session's load state and completeness claim.

use super::*;

/// A departure's retained rehome seed carries the leave directive's exact
/// turn count alongside the kind, and the first record for a slot wins —
/// every relay serving the session reports the same decided leave, so a
/// duplicate notice never rewrites what the first one recorded.
#[tokio::test]
async fn departed_slots_carry_the_final_turn_count_first_record_wins() {
    let lc = Lifecycle::with_graces(bare_setup(), HOUR, HOUR, HOUR);
    let s = SessionId(1);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1), SlotId(2)]),
        HashSet::new(),
    );

    lc.on_departure(tid(), s, SlotId(0), DepartureKind::Left, Some(312), false);
    lc.on_departure(tid(), s, SlotId(1), DepartureKind::Dropped, None, false);
    // A duplicate notice for slot 0 (another relay's copy of the same
    // decided leave) never rewrites the first record.
    lc.on_departure(
        tid(),
        s,
        SlotId(0),
        DepartureKind::Dropped,
        Some(999),
        false,
    );
    // A dropped count WITH the home-finalization proof is retained, proof
    // and all, for the rehome seed to carry back out.
    lc.on_departure(tid(), s, SlotId(2), DepartureKind::Dropped, Some(77), true);

    let mut departed = lc.departed_slots(&tid(), s);
    departed.sort_by_key(|d| d.slot.0);
    assert_eq!(
        departed,
        vec![
            DepartedSlot {
                finalized: false,
                slot: SlotId(0),
                kind: DepartureKind::Left,
                final_turn_count: Some(312),
            },
            DepartedSlot {
                finalized: false,
                slot: SlotId(1),
                kind: DepartureKind::Dropped,
                final_turn_count: None,
            },
            DepartedSlot {
                finalized: true,
                slot: SlotId(2),
                kind: DepartureKind::Dropped,
                final_turn_count: Some(77),
            },
        ],
    );
}

#[tokio::test]
async fn is_alive_reports_live_gone_and_unknown() {
    let setup = bare_setup();
    let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
    let live = SessionId(1);
    lc.register_session(
        tid(),
        live,
        vec![RelayId(1)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );
    assert!(lc.is_alive(&tid(), live), "a created session is alive");

    // Unknown (never created) reads as not alive.
    assert!(
        !lc.is_alive(&tid(), SessionId(999)),
        "an unknown session is not alive"
    );

    // Fully closed reads as not alive.
    close(&lc, tid(), live, RelayId(1));
    assert!(!lc.is_alive(&tid(), live), "a closed session is not alive");
}

#[tokio::test]
async fn heartbeat_load_state_accumulates_and_the_first_start_instant_wins() {
    // The beat is the durable record: it restates each relay's whole retained
    // state, so what the load-state read answers converges on the union of
    // every serving relay's view even if not one notice ever arrived.
    let (setup, s) = setup_with_relay_and_session();
    let lc = Lifecycle::new(setup.clone());
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1), RelayId(2)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );

    lc.merge_load_state(&[heartbeat_load(s, &[1], &[1], &[1], Some(1_700_000_000_000))]);
    // The second serving relay's beat: its own slot unions in, and its later
    // latch instant never displaces the first one recorded.
    lc.merge_load_state(&[heartbeat_load(s, &[0], &[0], &[], Some(1_700_000_009_999))]);
    // A re-statement of what is already recorded changes nothing.
    lc.merge_load_state(&[heartbeat_load(s, &[1], &[1], &[1], None)]);

    let load = lc
        .load_state(&tid(), s)
        .expect("the session was created here");
    assert_eq!(load.connected_slots, vec![SlotId(0), SlotId(1)]);
    assert_eq!(load.started_slots, vec![SlotId(1)]);
    assert_eq!(
        load.started_at_ms,
        Some(1_700_000_000_000),
        "the first instant reported wins; a tenant may already have recorded it",
    );
}

#[tokio::test]
async fn a_beat_reads_a_live_slot_as_proof_it_ever_connected() {
    // A relay restates the ever-connected set it retained, but a slot that is
    // connected right now necessarily connected at some point — folding the
    // live roster in too recovers a slot-connected notice lost before the
    // relay had a decision-maker to retain it in.
    let (setup, s) = setup_with_relay_and_session();
    let lc = Lifecycle::new(setup.clone());
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );

    lc.merge_load_state(&[heartbeat_load(s, &[1], &[], &[], None)]);

    let load = lc.load_state(&tid(), s).expect("created here");
    assert_eq!(load.connected_slots, vec![SlotId(1)]);
}

#[tokio::test]
async fn a_registered_session_starts_attestable_and_reports_its_serving_set() {
    // The two facts a completeness claim needs from the coordinator: this
    // process created the session, and relay memory covering it is unbroken.
    // The serving set comes with them, because whoever asks must ask all of it.
    let (setup, s) = setup_with_relay_and_session();
    let lc = Lifecycle::new(setup.clone());
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1), RelayId(2)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );

    let load = lc.load_state(&tid(), s).expect("created here");
    assert!(load.created_here);
    assert!(load.attestable);
    assert_eq!(load.serving_relays, vec![RelayId(1), RelayId(2)]);
}

#[tokio::test]
async fn a_rehome_ends_the_completeness_claim_for_good() {
    // The departing relay's retained load state dies with its assignment and
    // the replacement starts empty, so nothing that comes after can speak for
    // what the old relay saw and never restated. The facts already folded in
    // are untouched — only the right to read an absence as proof is lost.
    let (setup, s) = setup_with_relay_and_session();
    let lc = Lifecycle::new(setup.clone());
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1), RelayId(2)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    lc.merge_load_state(&[heartbeat_load(s, &[0], &[0], &[], None)]);

    lc.on_rehome(&tid(), s, RelayId(1), RelayId(3));
    let load = lc.load_state(&tid(), s).expect("created here");
    assert!(!load.attestable);
    assert_eq!(load.serving_relays, vec![RelayId(3), RelayId(2)]);
    assert_eq!(
        load.connected_slots,
        vec![SlotId(0)],
        "positive evidence survives the break",
    );

    // A relay that restarted in place keeps the serving set but lost the same
    // memory, so a same-id swap clears the flag too — and nothing restores it.
    let (setup, s2) = setup_with_relay_and_session();
    let lc2 = Lifecycle::new(setup);
    lc2.register_session(
        tid(),
        s2,
        vec![RelayId(1)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );
    lc2.on_rehome(&tid(), s2, RelayId(1), RelayId(1));
    assert!(!lc2.load_state(&tid(), s2).unwrap().attestable);
    lc2.merge_load_state(&[heartbeat_load(s2, &[0], &[0], &[], None)]);
    assert!(
        !lc2.load_state(&tid(), s2).unwrap().attestable,
        "a later restatement cannot recover what the old process never sent",
    );
}

#[tokio::test]
async fn a_lineage_break_clears_exactly_the_sessions_that_relay_serves() {
    // A relay coming back as a new process loses what it had not restated. That
    // is a claim about its own sessions; a session served entirely by other
    // relays is unaffected.
    let (setup, s) = setup_with_relay_and_session();
    let lc = Lifecycle::new(setup.clone());
    let other = SessionId(s.0 + 1);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1), RelayId(2)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );
    lc.register_session(
        tid(),
        other,
        vec![RelayId(2)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );

    lc.on_relay_lineage_break(RelayId(1));
    assert!(!lc.load_state(&tid(), s).unwrap().attestable);
    assert!(
        lc.load_state(&tid(), other).unwrap().attestable,
        "a session relay 1 does not serve keeps its claim",
    );

    // Permanent: registering is what sets it, and only a re-registration (a
    // session starting over) can — a restatement never does.
    lc.merge_load_state(&[heartbeat_load(s, &[0], &[0], &[], None)]);
    assert!(!lc.load_state(&tid(), s).unwrap().attestable);
}

#[tokio::test]
async fn a_factless_restatement_never_creates_a_session_state() {
    // Heartbeats arrive for every live session every ~10s from every relay
    // serving it. A beat carrying no facts must leave an untracked session
    // untracked, or a coordinator restart would leak a state (and its drain
    // task) per pre-existing session on the very next beat.
    let (setup, s) = setup_with_relay_and_session();
    let lc = Lifecycle::new(setup.clone());

    lc.merge_load_state(&[heartbeat_load(s, &[], &[], &[], None)]);
    assert!(!lc.contains_state(&tid(), s));
    assert!(lc.load_state(&tid(), s).is_none());
}

#[tokio::test]
async fn a_session_this_coordinator_never_created_answers_its_facts_but_not_known() {
    // Restart amnesia: notices and beats for a session set up against a
    // previous process still lazily create a state, and the facts they carry
    // are answered with — the caller merges positive evidence either way. What
    // it must not do is claim completeness: those sets start wherever this
    // process came up, so an absent slot proves nothing.
    let (setup, s) = setup_with_relay_and_session();
    let lc = Lifecycle::new(setup.clone());

    lc.on_slot_connected(tid(), s, SlotId(0));
    lc.merge_load_state(&[heartbeat_load(s, &[1], &[1], &[1], Some(7))]);
    assert!(lc.contains_state(&tid(), s), "the facts are still recorded");
    let load = lc
        .load_state(&tid(), s)
        .expect("the facts are answered with");
    assert_eq!(load.connected_slots, vec![SlotId(0), SlotId(1)]);
    assert_eq!(load.started_slots, vec![SlotId(1)]);
    assert_eq!(load.started_at_ms, Some(7));
    assert!(
        !load.created_here && !load.attestable,
        "a lazily created state can answer for nothing before it existed",
    );
    assert!(
        load.serving_relays.is_empty(),
        "and it has no serving set to ask, either",
    );

    // Registering the session hands this coordinator the whole picture from
    // here on — including what it had already accumulated.
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0), SlotId(1)]),
        HashSet::new(),
    );
    let load = lc.load_state(&tid(), s).expect("created here now");
    assert!(load.created_here && load.attestable);
    assert_eq!(load.serving_relays, vec![RelayId(1)]);
    assert_eq!(load.connected_slots, vec![SlotId(0), SlotId(1)]);
}
