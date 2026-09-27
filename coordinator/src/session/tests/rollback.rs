//! Rollback sessions: granted only on relays that all compare state hash reports, reported back
//! to the tenant either way, always running the finalized-drop handshake, and kept on such relays
//! across a re-home.

use super::*;

/// Enrolls a relay that supports rollback sessions (and so the finalized-drop handshake too).
fn enroll_rollback_relay(setup: &SessionSetup, id: u64, port: u16) {
    registry::enroll(
        setup.registry(),
        hello(id, port).with_capabilities(vec![
            rally_point_proto::control::CAPABILITY_FINALIZED_DROP_V1.to_owned(),
            rally_point_proto::control::CAPABILITY_ROLLBACK_V1.to_owned(),
        ]),
    );
}

fn create_rollback_session(setup: &SessionSetup) -> SessionResponse {
    let request = SessionRequest {
        rollback: true,
        ..request(two_players())
    };
    create_session(setup, request, ExpiresAt(u64::MAX))
        .unwrap()
        .response
}

#[test]
fn rollback_is_granted_only_on_relays_that_all_support_it() {
    // Relay 1 runs the finalized-drop handshake but can't compare state hash reports.
    let setup = fleet(&[(1, 14900, None, true)]).0;
    enroll_rollback_relay(&setup, 2, 14901);

    let resp = create_rollback_session(&setup);
    assert!(resp.rollback, "the tenant is told the session rolls back");
    assert_eq!(
        setup.serving_relays(&tid(), resp.session),
        vec![RelayId(2)],
        "only relays that compare reports serve a rollback session",
    );
    let staged = setup.descriptors().current_for(RelayId(2));
    assert!(staged[0].rollback);
    assert!(
        staged[0].finalized_drops,
        "a rollback session runs the handshake"
    );
}

#[test]
fn without_a_relay_that_supports_it_the_session_runs_lockstep() {
    let setup = fleet(&[(1, 14900, None, true)]).0;
    let resp = create_rollback_session(&setup);
    assert!(
        !resp.rollback,
        "the tenant is told to launch its clients in lockstep",
    );
    assert!(!setup.descriptors().current_for(RelayId(1))[0].rollback);
}

#[test]
fn a_session_the_tenant_did_not_ask_to_roll_back_never_does() {
    let setup = fleet(&[]).0;
    enroll_rollback_relay(&setup, 1, 14900);
    let resp = create_default_session(&setup);
    assert!(!resp.rollback);
    assert!(!setup.descriptors().current_for(RelayId(1))[0].rollback);
}

#[test]
fn a_rollback_session_runs_the_handshake_even_with_the_feature_switched_off() {
    let setup = SessionSetup::new(registry::RelayRegistry::new(), tenant_store())
        .with_finalized_drops(false);
    enroll_rollback_relay(&setup, 1, 14900);
    let resp = create_rollback_session(&setup);
    assert!(resp.rollback);
    let staged = setup.descriptors().current_for(RelayId(1));
    assert!(
        staged[0].finalized_drops,
        "clients apply a rollback session's leaves at the step a finalized count names",
    );
}

#[test]
fn a_rehome_keeps_a_rollback_session_on_relays_that_support_it() {
    let setup = fleet(&[(2, 14901, None, true)]).0;
    enroll_rollback_relay(&setup, 1, 14900);
    let resp = create_rollback_session(&setup);
    assert_eq!(setup.serving_relays(&tid(), resp.session), vec![RelayId(1)]);

    // The home dies with only relay 2 live, which can't compare reports.
    registry::remove(setup.registry(), RelayId(1));
    assert!(
        matches!(
            rehome(&setup, &tid(), resp.session, RelayId(1), vec![]),
            RehomeOutcome::Unavailable,
        ),
        "a rollback session never moves to a relay that can't compare its reports",
    );
    enroll_rollback_relay(&setup, 4, 14903);
    let RehomeOutcome::NewTarget(endpoint) =
        rehome(&setup, &tid(), resp.session, RelayId(1), vec![])
    else {
        panic!("expected a NewTarget once a relay that supports rollback exists");
    };
    assert_eq!(endpoint.relay_id, RelayId(4));
    assert!(setup.descriptors().current_for(RelayId(4))[0].rollback);
}
