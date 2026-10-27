//! Closed slots: the slots a home relay saw connect that are now neither live nor
//! started, which no fence can reach. The read names them, vouches for everything
//! else, and lets setup finality rest on the live half of each relay's fence.

use super::*;

/// One relay homing every slot of a six-player session, registered the way
/// production does.
fn state_with_one_home_for_six() -> (CoordinatorState, SessionId) {
    let (setup, session) = SessionFixture {
        players: plain_players(&[0, 1, 2, 3, 4, 5]),
        ..Default::default()
    }
    .build();
    let state = state_over(setup);
    let serving = state.setup.serving_relays(&tenant_id(), session);
    assert_eq!(serving, vec![RelayId(1)]);
    state.lifecycle.register_session(
        tenant_id(),
        session,
        serving,
        (0..6).map(SlotId).collect(),
        std::collections::HashSet::new(),
    );
    (state, session)
}

/// What a current relay answers when `closed` connected and dropped before
/// starting, and every other slot it homes is live and acked its probe.
fn closed_on_a_live_fence(closed: &[u8]) -> AttestOptions {
    AttestOptions {
        fenced: closed.is_empty(),
        fenced_live: true,
        closed_slots: slots(closed),
        ..Default::default()
    }
}

#[tokio::test]
async fn a_closed_slot_is_named_and_setup_still_finalizes() {
    // The single quitter: every slot connected, one closed its app before any
    // game loop ran. The whole fence is out of reach, so `known` stays false, but
    // everything else is vouched for and the settle cut makes the lobby evidence
    // final regardless of what the departed client still holds.
    let (state, session) = state_with_one_home_for_six();
    let tenant = tenant_id();
    let _relay = spawn_attesting_relay(
        &state,
        RelayId(1),
        SessionPresence {
            ever_connected: slots(&[0, 1, 2, 3, 4, 5]),
            started_at_ms: Some(1_700_000_000_000),
            ..presence_entry(&tenant, session, &[1, 2, 3, 4, 5])
        },
        AttestOptions {
            setup_settled: true,
            ..closed_on_a_live_fence(&[0])
        },
    );

    let body = settle_lobby_load_state(router(state), session.0).await;
    assert_eq!(
        std::str::from_utf8(&body).unwrap(),
        r#"{"known":false,"turnsKnown":true,"closedKnown":true,"setupFinal":true,"startedAtMs":1700000000000,"connectedSlots":[0,1,2,3,4,5],"startedSlots":[],"forwardedSlots":[],"lobbyViolationSlots":[],"closedSlots":[0]}"#,
    );
}

#[tokio::test]
async fn several_closed_slots_are_all_named() {
    let (state, session) = state_with_one_home_for_six();
    let tenant = tenant_id();
    let _relay = spawn_attesting_relay(
        &state,
        RelayId(1),
        SessionPresence {
            ever_connected: slots(&[0, 1, 2, 3, 4, 5]),
            ..presence_entry(&tenant, session, &[1, 3, 5])
        },
        closed_on_a_live_fence(&[4, 0, 2]),
    );

    let body = read_load_state(router(state), session.0).await;
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["closedKnown"], true);
    assert_eq!(
        response["closedSlots"],
        serde_json::json!([0, 2, 4]),
        "ascending, whatever order the relay listed them in",
    );
}

#[tokio::test]
async fn a_relay_cannot_name_a_slot_it_does_not_home_closed() {
    // Slot 0 is relay 1's. Relay 2 naming it closed is forged or a bug, and the
    // tenant would blame a player on it, so it is dropped on ingest like any
    // other slot claim from a relay that does not home the slot.
    let (state, session) = state_with_split_homes();
    let tenant = tenant_id();
    let _one = spawn_attesting_relay(
        &state,
        RelayId(1),
        SessionPresence {
            ever_connected: slots(&[0]),
            ..presence_entry(&tenant, session, &[0])
        },
        AttestOptions::default(),
    );
    let _two = spawn_attesting_relay(
        &state,
        RelayId(2),
        SessionPresence {
            ever_connected: slots(&[1]),
            ..presence_entry(&tenant, session, &[1])
        },
        closed_on_a_live_fence(&[0]),
    );

    let body = read_load_state(router(state), session.0).await;
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["closedKnown"], true);
    assert_eq!(response["closedSlots"], serde_json::json!([]));
}

#[tokio::test]
async fn an_unfenced_live_slot_withholds_the_closed_claim_and_finality() {
    // Naming the closed slots vouches for nothing else. A live slot that never
    // acked could still be holding its start report, so neither the closed set
    // nor the setup decision may be taken as complete — though the named slot is
    // still reported.
    let (state, session) = state_with_one_home_for_six();
    let tenant = tenant_id();
    let _relay = spawn_attesting_relay(
        &state,
        RelayId(1),
        SessionPresence {
            ever_connected: slots(&[0, 1]),
            ..presence_entry(&tenant, session, &[1])
        },
        AttestOptions {
            fenced: false,
            fenced_live: false,
            closed_slots: slots(&[0]),
            setup_settled: true,
            ..Default::default()
        },
    );

    let body = settle_lobby_load_state(router(state), session.0).await;
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["closedKnown"], false);
    assert_eq!(response["setupFinal"], false);
    assert_eq!(response["closedSlots"], serde_json::json!([0]));
}

#[tokio::test]
async fn a_closed_claim_needs_turn_evidence() {
    // A closed slot's own start report may be parked in its client, so only the
    // forwarded set says how far its game got. A relay that predates that set
    // leaves the closed claim unvouched, even though setup can still finalize on
    // its live fence.
    let (state, session) = state_with_one_home_for_six();
    let tenant = tenant_id();
    let _relay = spawn_attesting_relay(
        &state,
        RelayId(1),
        SessionPresence {
            ever_connected: slots(&[0, 1]),
            ..presence_entry(&tenant, session, &[1])
        },
        AttestOptions {
            reports_turns: false,
            setup_settled: true,
            ..closed_on_a_live_fence(&[0])
        },
    );

    let body = settle_lobby_load_state(router(state), session.0).await;
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["turnsKnown"], false);
    assert_eq!(response["closedKnown"], false);
    assert_eq!(response["setupFinal"], true);
}

#[tokio::test]
async fn a_relay_predating_the_split_still_vouches_through_its_whole_fence() {
    // An older relay answers only `fenced`. A whole fence is a live fence with
    // nothing closed, so it supports the closed claim (with no closed slot) and
    // setup finality exactly as before; an unfenced one from such a relay
    // supports neither, since it never says which half failed.
    let (state, session) = state_with_one_home_for_six();
    let tenant = tenant_id();
    let relay = spawn_attesting_relay(
        &state,
        RelayId(1),
        presence_entry(&tenant, session, &[0]),
        AttestOptions {
            fenced: true,
            fenced_live: false,
            setup_settled: true,
            ..Default::default()
        },
    );
    let body = settle_lobby_load_state(router(state.clone()), session.0).await;
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["known"], true);
    assert_eq!(response["closedKnown"], true);
    assert_eq!(response["setupFinal"], true);
    relay.abort();

    let (state, session) = state_with_one_home_for_six();
    let _relay = spawn_attesting_relay(
        &state,
        RelayId(1),
        SessionPresence {
            ever_connected: slots(&[0]),
            ..presence_entry(&tenant, session, &[])
        },
        AttestOptions {
            fenced: false,
            fenced_live: false,
            setup_settled: true,
            ..Default::default()
        },
    );
    let body = settle_lobby_load_state(router(state), session.0).await;
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["closedKnown"], false);
    assert_eq!(response["setupFinal"], false);
}

#[tokio::test]
async fn a_broken_lineage_withholds_the_closed_claim() {
    // A relay that came back as a new process has forgotten every slot that
    // connected to the old one, so its closed set is missing exactly the slots
    // that left before the restart. Nothing it answers can vouch for that.
    let (state, session) = state_with_one_home_for_six();
    let tenant = tenant_id();
    state.lifecycle.on_relay_lineage_break(RelayId(1));
    let _relay = spawn_attesting_relay(
        &state,
        RelayId(1),
        SessionPresence {
            ever_connected: slots(&[0, 1]),
            ..presence_entry(&tenant, session, &[1])
        },
        AttestOptions {
            setup_settled: true,
            ..closed_on_a_live_fence(&[0])
        },
    );

    let body = settle_lobby_load_state(router(state), session.0).await;
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["closedKnown"], false);
    assert_eq!(response["setupFinal"], false);
    assert_eq!(response["closedSlots"], serde_json::json!([0]));
}
