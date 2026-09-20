//! Descriptor push mechanics: full sets vs. deltas, an empty-diff wake sending
//! nothing, and the real relay client's Join/Leave stream converging to the
//! coordinator's watch set — including the initial connect-time Join and the
//! bootstrap secret that gates the connection before any of it.

use std::time::Duration;

use rally_point_coordinator::api::ControlAuth;
use rally_point_proto::control::{CoordinatorToRelay, DescriptorKey, TenantId};
use rally_point_proto::ids::{RelayId, SessionId};
use rally_point_proto::version::ProtocolVersion;
use rally_point_relay::coordinator;
use rally_point_relay::key::SessionKey;
use rally_point_relay::mesh::MeshCommand;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::{ClientRequestBuilder, Error as WsError};

use crate::common::{connect_and_send_hello, prove_identity, relay_key};
use crate::helpers::*;

#[tokio::test]
async fn a_delta_capable_relay_gets_a_full_set_then_deltas() {
    // The wiring this proves is that connect-time is always a full set — seeding
    // the baseline every later delta diffs against — and that the writer's
    // steady-state arm then emits deltas over a real socket. The diff shapes
    // themselves (a second add, an in-place mutation) are pure logic the
    // coordinator's own `diff_descriptors` tests cover without a socket, so one
    // add and one removal are enough here.
    let (base_url, setup) = serve_coordinator_returning_setup(ControlAuth::Open).await;
    let mut socket = connect_and_send_hello(&base_url, relay_hello(1, 14900)).await;
    prove_identity(&mut socket, &relay_key(1)).await;

    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::Descriptors { descriptors, .. } => assert!(descriptors.is_empty()),
        other => panic!("expected a full descriptor set on connect, got {other:?}"),
    }

    // An add: one upsert, no removals — not the whole set.
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(1, &[2]));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::DescriptorDelta {
            upserts, removals, ..
        } => {
            assert_eq!(
                upserts.iter().map(|d| d.session).collect::<Vec<_>>(),
                vec![SessionId(1)],
            );
            assert!(removals.is_empty());
        }
        other => panic!("expected an add delta, got {other:?}"),
    }

    // A removal: one removal, no upserts.
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
        other => panic!("expected a removal delta, got {other:?}"),
    }
}

#[tokio::test]
async fn a_pre_delta_relay_receives_full_sets_not_deltas() {
    let (base_url, setup) = serve_coordinator_returning_setup(ControlAuth::Open).await;
    // A relay negotiating only the supported floor — below the delta threshold, so it
    // would decode a delta as an unknown frame and drift.
    let mut socket = connect_and_send_hello(
        &base_url,
        relay_hello_at(1, 14900, ProtocolVersion::MIN_SUPPORTED),
    )
    .await;
    prove_identity(&mut socket, &relay_key(1)).await;

    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::Descriptors { descriptors, .. } => assert!(descriptors.is_empty()),
        other => panic!("expected a full set on connect, got {other:?}"),
    }

    // Every steady-state change is the whole current set, never a delta.
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(1, &[2]));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::Descriptors { descriptors, .. } => assert_eq!(
            descriptors.iter().map(|d| d.session).collect::<Vec<_>>(),
            vec![SessionId(1)],
        ),
        other => panic!("a pre-delta relay must receive a full set, got {other:?}"),
    }

    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(2, &[3]));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::Descriptors { descriptors, .. } => assert_eq!(
            descriptors.iter().map(|d| d.session).collect::<Vec<_>>(),
            vec![SessionId(1), SessionId(2)],
            "the whole current set, not just the change",
        ),
        other => panic!("a pre-delta relay must receive a full set, got {other:?}"),
    }
}

// Pinned to a single-threaded runtime: the test's whole argument is that the
// writer task cannot run between two synchronous outbox calls made without an
// await, which only holds when the runtime has one worker.
#[tokio::test(flavor = "current_thread")]
async fn an_empty_diff_wake_sends_no_frame() {
    let (base_url, setup) = serve_coordinator_returning_setup(ControlAuth::Open).await;
    let mut socket = connect_and_send_hello(&base_url, relay_hello(1, 14900)).await;
    prove_identity(&mut socket, &relay_key(1)).await;

    // The connect-time full set, then a real add to establish the baseline.
    let _ = read_to_descriptor_update(&mut socket).await;
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(1, &[2]));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::DescriptorDelta { upserts, .. } => assert_eq!(upserts.len(), 1),
        other => panic!("expected the baseline-establishing delta, got {other:?}"),
    }

    // Add then immediately remove the same session, with no await between the two
    // synchronous outbox calls: the writer cannot run between them, so it wakes
    // once to a set identical to what it last sent — an empty diff — and must send
    // nothing.
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(2, &[3]));
    setup
        .descriptors()
        .remove(RelayId(1), &TenantId(TENANT.to_owned()), SessionId(2));
    assert!(
        no_descriptor_update_within(&mut socket, Duration::from_millis(300)).await,
        "an empty-diff wake must send no frame",
    );

    // A subsequent real change still produces a delta — the writer resumed normally.
    setup
        .descriptors()
        .record(RelayId(1), a_descriptor(3, &[4]));
    match read_to_descriptor_update(&mut socket).await {
        CoordinatorToRelay::DescriptorDelta {
            upserts, removals, ..
        } => {
            assert_eq!(
                upserts.iter().map(|d| d.session).collect::<Vec<_>>(),
                vec![SessionId(3)],
            );
            assert!(removals.is_empty());
        }
        other => panic!("expected a delta for the real change, got {other:?}"),
    }
}

#[tokio::test]
async fn churn_through_the_real_client_converges_to_the_watch_set() {
    // The full delta round trip end to end: the real coordinator writer emits deltas
    // and the real relay client applies them. A burst of adds and removals must leave
    // the relay's meshed sessions equal to the coordinator's final watch set — which
    // covers both halves of the stream, since the sessions removed here were joined
    // first and must then be left.
    let (base_url, setup) = serve_coordinator_returning_setup(ControlAuth::Open).await;
    let (control, mut rx2) = relay_one_with_peer_link();

    tokio::spawn(coordinator::client::run_descriptor_subscriber_with(
        coordinator::client::EnrollConfig {
            coordinator_url: base_url,
            bootstrap_secret: None,
            relay_hello: relay_hello(1, 14900),
            identity_key: relay_key(1),
        },
        apply_targets(control),
        no_outbound(),
        heartbeat(Duration::from_secs(3600)),
        no_drain_rx(),
        no_control_connected(),
        backoff(),
    ));

    // Churn: add sessions 1..=6 (each meshing peer 2), then remove the even ones.
    for s in 1..=6u64 {
        setup
            .descriptors()
            .record(RelayId(1), a_descriptor(s, &[2]));
    }
    for s in [2u64, 4, 6] {
        setup
            .descriptors()
            .remove(RelayId(1), &TenantId(TENANT.to_owned()), SessionId(s));
    }

    // The relay's meshed sessions (the net of the Join/Leave stream on peer 2's link)
    // converge to the odd sessions — exactly the coordinator's final watch set.
    let want: std::collections::HashSet<SessionKey> = [1u64, 3, 5]
        .into_iter()
        .map(|s| session_key(SessionId(s)))
        .collect();
    let mut net: std::collections::HashSet<SessionKey> = std::collections::HashSet::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match timeout(Duration::from_millis(200), rx2.recv()).await {
            Ok(Some(MeshCommand::Join(k))) => {
                net.insert(k);
            }
            Ok(Some(MeshCommand::Leave(k))) => {
                net.remove(&k);
            }
            Ok(None) => break,
            Err(_) => {
                if net == want {
                    break;
                }
            }
        }
    }
    assert_eq!(
        net, want,
        "the relay's meshed sessions converge to the coordinator's watch set",
    );
}

#[tokio::test]
async fn the_pushed_descriptor_drives_a_join_on_connect() {
    let secret = "bootstrap-secret";
    let (base_url, session, _outbox) = coordinator_with_session(Some(secret)).await;
    let (control, mut rx2) = relay_one_with_peer_link();

    // The relay holds its control connection open with the matching secret.
    tokio::spawn(coordinator::client::run_descriptor_subscriber_with(
        coordinator::client::EnrollConfig {
            coordinator_url: base_url,
            bootstrap_secret: Some(secret.to_owned()),
            relay_hello: relay_hello(1, 14900),
            identity_key: relay_key(1),
        },
        apply_targets(control),
        no_outbound(),
        heartbeat(Duration::from_secs(3600)),
        no_drain_rx(),
        no_control_connected(),
        backoff(),
    ));

    // The coordinator pushes relay 1's current set on connect; it names peer 2,
    // so the link to peer 2 is told to join the session.
    let joined = timeout(Duration::from_secs(5), rx2.recv())
        .await
        .expect("a Join should arrive over the control connection")
        .expect("the link sender should be live");
    assert_eq!(joined, MeshCommand::Join(session_key(session)));
}

#[tokio::test]
async fn a_wrong_bootstrap_secret_is_refused_at_the_upgrade() {
    // The bootstrap secret is checked before the WebSocket upgrade, so a relay
    // presenting the wrong one never gets a socket to receive descriptors on —
    // the refusal is an HTTP 401, not a silent absence of pushes.
    let (base_url, _session, _outbox) = coordinator_with_session(Some("right-secret")).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let uri = ws_url.parse().expect("a ws:// control url");

    let wrong = ClientRequestBuilder::new(uri).with_header("Authorization", "Bearer wrong-secret");
    match tokio_tungstenite::connect_async(wrong).await {
        Err(WsError::Http(response)) => assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "a wrong bootstrap secret is refused before the upgrade",
        ),
        Err(other) => panic!("expected an HTTP 401, got {other:?}"),
        Ok(_) => panic!("a wrong bootstrap secret must not open a control connection"),
    }

    // The control for it: the same request with the right secret does upgrade.
    let uri = ws_url.parse().expect("a ws:// control url");
    let right = ClientRequestBuilder::new(uri).with_header("Authorization", "Bearer right-secret");
    let (_socket, response) = tokio_tungstenite::connect_async(right)
        .await
        .expect("the matching secret opens the control connection");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
}
