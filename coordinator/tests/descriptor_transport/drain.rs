//! The drain exchange: a relay asking to drain gets its current descriptor set
//! pushed as a full set (never a delta) and then an ack, is excluded from new
//! session assignment while draining, and steady-state deltas resume correctly
//! against the baseline the drain refreshed.

use rally_point_coordinator::api::ControlAuth;
use rally_point_coordinator::{registry, session};
use rally_point_proto::control::{
    CoordinatorToRelay, DescriptorKey, PlayerHandoff, RelayToCoordinator, SessionRequest, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::{ClientPublicKey, ExpiresAt};

use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message;

use crate::common::{connect_and_send_hello, prove_identity, relay_key};
use crate::helpers::*;

#[tokio::test]
async fn the_drain_exchange_pushes_a_full_set_and_later_deltas_stay_correct() {
    let (base_url, setup) = serve_coordinator_returning_setup(ControlAuth::Open).await;
    let mut socket = connect_and_send_hello(&base_url, relay_hello(1, 14900)).await;
    prove_identity(&mut socket, &relay_key(1)).await;

    // Full set on connect, then two adds delivered as deltas.
    let _ = read_to_descriptor_update(&mut socket).await;
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(1, &[2]));
    let _ = read_to_descriptor_update(&mut socket).await;
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(2, &[3]));
    let _ = read_to_descriptor_update(&mut socket).await;

    // The relay requests a drain: the coordinator pushes the whole current set (a full
    // set, not a delta), then a DrainAck.
    send_draining(&mut socket).await;
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::Descriptors { descriptors, .. } => assert_eq!(
            descriptors.iter().map(|d| d.session).collect::<Vec<_>>(),
            vec![SessionId(1), SessionId(2)],
            "the drain exchange pushes the whole set",
        ),
        other => panic!("the drain exchange must push a full set, got {other:?}"),
    }
    expect_drain_ack(&mut socket).await;

    // Steady state resumes as deltas, correct against the baseline the drain refreshed
    // from its full set: removing session 1 yields a removal-only delta.
    setup
        .descriptors()
        .remove(RelayId(1), &TenantId(TENANT.to_owned()), SessionId(1));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::DescriptorDelta {
            upserts, removals, ..
        } => {
            assert!(upserts.is_empty());
            assert_eq!(
                removals,
                vec![DescriptorKey {
                    tenant: TenantId(TENANT.to_owned()),
                    session: SessionId(1),
                }],
            );
        }
        other => panic!("post-drain steady state must resume deltas, got {other:?}"),
    }
}

#[tokio::test]
async fn a_draining_relay_gets_its_set_then_an_ack_and_is_excluded_from_new_sessions() {
    // One relay, enrolled over the socket; it serves one session, then drains.
    let (base_url, setup) = serve_coordinator_exposing_setup(&[]).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    // Enroll relay 1 via its Hello (proving possession), then give it a session so
    // its descriptor set is non-empty at drain time.
    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    prove_identity(&mut socket, &relay_key(1)).await;
    assert!(
        wait_for_enrollment(setup.registry(), RelayId(1)).await,
        "the relay enrolls from its Hello",
    );
    let session = create_one_slot_session(&setup);

    // The relay asks to drain.
    let draining = serde_json::to_string(&RelayToCoordinator::Draining).unwrap();
    socket.send(Message::Text(draining.into())).await.unwrap();

    // It receives its current descriptor set (naming the session) and then a
    // DrainAck — set before ack.
    let set = read_until_drain_ack(&mut socket).await;
    assert!(
        set.iter().any(|d| d.session == session),
        "the descriptor set pushed before the ack names the relay's session",
    );

    // The coordinator has marked it draining: a new session can no longer be
    // assigned (it was the only relay), and the registry reports it unavailable.
    assert!(!registry::is_available(setup.registry(), RelayId(1)));
    let err = session::create_session(
        &setup,
        SessionRequest {
            tenant: TenantId(TENANT.to_owned()),
            players: vec![PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0xCC; 32]),
                external_ref: None,
                observer: false,
                region: None,
            }],
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap_err();
    assert_eq!(err, registry::SessionSetupError::NoRelaysAvailable);
}

#[tokio::test]
async fn a_draining_relay_is_skipped_and_a_create_picks_the_other_relay() {
    // Relay 2 is pre-enrolled; relay 1 enrolls over the socket, then drains. A
    // create after the drain homes on the still-available relay 2.
    let (base_url, setup) = serve_coordinator_exposing_setup(&[(2, 14901)]).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    prove_identity(&mut socket, &relay_key(1)).await;
    assert!(wait_for_enrollment(setup.registry(), RelayId(1)).await);

    let draining = serde_json::to_string(&RelayToCoordinator::Draining).unwrap();
    socket.send(Message::Text(draining.into())).await.unwrap();
    // Its set is empty (it serves no session), and the ack still arrives after it.
    let set = read_until_drain_ack(&mut socket).await;
    assert!(
        set.is_empty(),
        "a relay serving nothing drains with an empty set"
    );

    // A fresh session homes on relay 2 — relay 1 (lower id, normally the primary) is
    // draining and excluded from the pick.
    let resp = session::create_session(
        &setup,
        SessionRequest {
            tenant: TenantId(TENANT.to_owned()),
            players: vec![PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0xDD; 32]),
                external_ref: None,
                observer: false,
                region: None,
            }],
            external_id: None,
            latency_estimate_ms: None,
        },
        ExpiresAt(u64::MAX),
    )
    .unwrap()
    .response;
    assert_eq!(
        resp.home_relay.relay_id,
        RelayId(2),
        "a create skips the draining relay and homes on the available one",
    );
}
