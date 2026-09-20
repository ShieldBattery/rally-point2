//! Inbound control frames: what the reader's dispatch does with a decoded
//! frame, the `SessionClosed` generation fence, and the drain mark's.
//!
//! What a *heartbeat* then means — the ceilings, the generation fence, the
//! serving-relay filter and the fan-out — is the lifecycle's, and is tested
//! there (`lifecycle::tests::heartbeat`); the one beat here is about this
//! layer's decode-and-hand-off.

use super::*;

/// A `Heartbeat` framed as an inbound control message, carrying the given
/// session roster (marked complete) and no RTT reports.
fn heartbeat_with_sessions(sessions: Vec<rally_point_proto::control::SessionPresence>) -> Message {
    let heartbeat = RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions,
        region_rtts: vec![],
    };
    Message::Text(serde_json::to_string(&heartbeat).unwrap().into())
}

#[tokio::test]
async fn a_decoded_heartbeat_frame_reaches_the_lifecycles_ingest() {
    // This layer's whole share of a heartbeat: decode the frame and hand it to
    // the owner once. The roster it carries lands, so the hand-off is real and
    // carries the beat's contents — everything the ingest then decides is
    // asserted against `Lifecycle::ingest_heartbeat` directly.
    let fixture = bare_inbound_fixture();
    let tenant = tenant_id();
    let session = SessionId(77);
    fixture.note(&heartbeat_with_sessions(vec![presence_entry(
        &tenant,
        session,
        &[0],
    )]));

    assert_eq!(
        presence::fresh_slots(fixture.setup.presence(), &tenant, std::time::Instant::now()),
        vec![(session, SlotId(0))],
        "the frame's roster reached the ingest and was applied",
    );
}

#[tokio::test]
async fn session_closed_from_a_superseded_connection_cannot_close_the_live_epoch() {
    let (setup, lifecycle, session) =
        setup_with_session_and_notify("http://127.0.0.1:1/hook".to_owned());
    let tenant = tenant_id();
    lifecycle.register_session(
        tenant.clone(),
        session,
        vec![RelayId(1)],
        std::collections::HashSet::from([SlotId(0)]),
        std::collections::HashSet::new(),
    );
    let hello = (RelaySpec {
        id: 1,
        region: None,
    })
    .hello();
    let stale_generation = registry::enroll(setup.registry(), hello.clone());
    let current_generation = registry::enroll(setup.registry(), hello);
    lifecycle.on_relay_enrolled(RelayId(1), current_generation);

    let regions = RegionsConfig::default();
    let store = pair_rtts::PairRttStore::new();
    let rtt = idle_rtt_ingest(&regions, &store);
    let occupied = heartbeat_with_sessions(vec![presence_entry(&tenant, session, &[0])]);
    note_inbound_frame(
        &setup,
        &lifecycle,
        RelayId(1),
        current_generation,
        &occupied,
        &rtt,
    );

    let closed = Message::Text(
        serde_json::to_string(&RelayToCoordinator::SessionClosed {
            tenant: tenant.clone(),
            session,
        })
        .unwrap()
        .into(),
    );
    note_inbound_frame(
        &setup,
        &lifecycle,
        RelayId(1),
        stale_generation,
        &closed,
        &rtt,
    );
    assert!(
        lifecycle.is_alive(&tenant, session),
        "a late close from the predecessor cannot close the replacement",
    );

    note_inbound_frame(
        &setup,
        &lifecycle,
        RelayId(1),
        current_generation,
        &closed,
        &rtt,
    );
    assert!(
        !lifecycle.is_alive(&tenant, session),
        "the current connection's close still retires the session",
    );
}

#[test]
fn a_drain_mark_from_a_superseded_connection_cannot_mark_its_live_successor() {
    // A relay's stale connection can flush a `Draining` after the relay already
    // reconnected. The successor's enroll cleared the draining flag, and the
    // stale mark must not set it again: that would exclude a live, idle relay
    // from every new assignment until it re-enrolled once more. The live
    // connection runs its own drain exchange when its own `Draining` arrives.
    let reg = registry::RelayRegistry::new();
    let hello = (RelaySpec {
        id: 1,
        region: None,
    })
    .hello();
    let stale_generation = registry::enroll(&reg, hello.clone());
    let current_generation = registry::enroll(&reg, hello);
    let setup = session::SessionSetup::new(reg, crate::tenant::TenantStore::new());

    let draining = || {
        registry::enrolled_relays(setup.registry())
            .into_iter()
            .find(|relay| relay.relay_id == RelayId(1))
            .expect("relay 1 is enrolled")
            .draining
    };

    assert!(
        !apply_drain_mark(&setup, RelayId(1), stale_generation),
        "a Draining from the superseded connection draws no ack",
    );
    assert!(
        !draining(),
        "the live successor stays eligible for new assignments",
    );

    // The current connection's own Draining does apply.
    assert!(apply_drain_mark(&setup, RelayId(1), current_generation));
    assert!(
        draining(),
        "the relay its own connection drained is excluded from new assignments",
    );
}
