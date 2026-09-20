//! The drain exchange: a relay asking to drain gets its current descriptor set
//! pushed as a full set (never a delta) and then an ack, is excluded from new
//! session assignment while draining, and steady-state deltas resume correctly
//! against the baseline the drain refreshed.

use rally_point_coordinator::api::ControlAuth;
use rally_point_coordinator::registry;
use rally_point_proto::control::{CoordinatorToRelay, DescriptorKey, TenantId};
use rally_point_proto::ids::{RelayId, SessionId};

use crate::common::{ControlSocket, connect_and_send_hello, prove_identity, relay_key};
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
    // Two relays enrolled over their own sockets, drained one after the other:
    // relay 1 first (serving nothing, so its set is empty), then relay 2 (serving
    // the session the create in between homed on it). Each drain pushes the
    // relay's set before its ack, and each marks the relay unavailable — first
    // pushing a create onto the other relay, and finally leaving none at all.
    let (base_url, setup) = serve_coordinator_exposing_setup(&[]).await;

    let mut socket_one = enroll_over_socket(&base_url, 1, 14900).await;
    assert!(wait_for_enrollment(setup.registry(), RelayId(1)).await);
    let mut socket_two = enroll_over_socket(&base_url, 2, 14901).await;
    assert!(wait_for_enrollment(setup.registry(), RelayId(2)).await);

    // Relay 1 serves nothing, so it drains with an empty set — the ack still
    // follows it.
    send_draining(&mut socket_one).await;
    let set = read_until_drain_ack(&mut socket_one).await;
    assert!(
        set.is_empty(),
        "a relay serving nothing drains with an empty set",
    );
    assert!(!registry::is_available(setup.registry(), RelayId(1)));

    // A create now skips relay 1 — the lower id, normally the primary pick — and
    // homes on the still-available relay 2.
    let session = try_create_one_slot_session(&setup)
        .expect("relay 2 is available")
        .session;
    assert_eq!(
        setup.serving_relays(&TenantId(TENANT.to_owned()), session),
        vec![RelayId(2)],
        "a create skips the draining relay and homes on the available one",
    );

    // Relay 2 now drains: the set pushed before its ack names the session it
    // serves.
    send_draining(&mut socket_two).await;
    let set = read_until_drain_ack(&mut socket_two).await;
    assert!(
        set.iter().any(|d| d.session == session),
        "the descriptor set pushed before the ack names the relay's session",
    );
    assert!(!registry::is_available(setup.registry(), RelayId(2)));

    // With both relays draining, a new session can no longer be assigned at all.
    assert_eq!(
        try_create_one_slot_session(&setup).unwrap_err(),
        registry::SessionSetupError::NoRelaysAvailable,
    );
}

/// Opens a control socket, enrolls `id` over it with its Hello and proof of
/// possession, and returns the socket still open.
async fn enroll_over_socket(base_url: &str, id: u64, port: u16) -> ControlSocket {
    let mut socket = connect_and_send_hello(base_url, relay_hello(id, port)).await;
    prove_identity(&mut socket, &relay_key(id)).await;
    socket
}
