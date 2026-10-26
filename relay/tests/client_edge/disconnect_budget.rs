//! Disconnect budget admission and status over the client edge.

use std::time::{Duration, Instant};

use crate::helpers::*;
use rally_point_proto::close_codes;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_relay::key::SessionKey;
use rally_point_relay::mesh::{MeshState, control::MeshControl};
use rally_point_relay::session::disconnect_budget::{DISCONNECT_ALLOWANCE, EpisodeSnapshot};
use rally_point_transport::control::{ControlInbound, spawn_control_reader};
use rally_point_transport::noq;

fn managed_relay(tenant: &Tenant, session: SessionId) -> TestRelay {
    let mesh = MeshState::default();
    mesh.session.decision_makers.require_descriptors();
    let relay = start_relay_with_mesh(registry_for_one(tenant), mesh);
    let mut desc = descriptor(TENANT, session);
    desc.expected_slots = vec![SlotId(0), SlotId(1)];
    desc.homed_slots = vec![SlotId(0), SlotId(1)];
    desc.authority_order = vec![RelayId(1)];
    desc.finalized_drops = true;
    MeshControl::new(RelayId(1), &relay.mesh, relay.sessions.clone()).apply_descriptor(&desc);
    relay
}

fn key(session: SessionId) -> SessionKey {
    SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    }
}

#[tokio::test]
async fn exhausted_disconnected_slot_is_refused_on_resume() {
    let tenant = make_default_tenant();
    let session = SessionId(960);
    let relay = managed_relay(&tenant, session);
    let endpoint = client_endpoint(&relay.ca);
    let slot0 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(0)).await;
    let mut control0 = spawn_control_reader(slot0.connection().clone());
    let slot1 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(1)).await;
    slot1.connection().close(0u32.into(), b"outage");
    wait_for_connectivity(&mut control0, SlotId(1), false).await;

    let k = key(session);
    // A completed earlier outage consumes the full allowance; the current
    // outage remains locally owned and continues from its own generation.
    relay.mesh.session.disconnect_budgets.merge(
        &k,
        &[EpisodeSnapshot {
            slot: SlotId(1),
            connection_epoch: u64::MAX,
            elapsed: DISCONNECT_ALLOWANCE,
            complete: true,
        }],
        Instant::now(),
    );

    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(1), client_key.public);
    let redial = endpoint
        .connect(relay.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    // Admission can reject after acknowledging the handshake, so inspect the close.
    let _ = handshake(&redial, &token, &client_key, &[(SlotId(1), 0)]).await;
    let closed = tokio::time::timeout(Duration::from_secs(5), redial.closed())
        .await
        .expect("the exhausted resume is closed");
    match closed {
        noq::ConnectionError::ApplicationClosed(close) => assert_eq!(
            u64::from(close.error_code),
            u64::from(close_codes::SLOT_DEPARTED)
        ),
        other => panic!("expected the terminal departed close, got {other:?}"),
    }
}

#[tokio::test]
async fn status_updates_reach_client_while_turns_flow() {
    let tenant = make_default_tenant();
    let session = SessionId(961);
    let relay = managed_relay(&tenant, session);
    let endpoint = client_endpoint(&relay.ca);
    let mut slot0 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(0)).await;
    let mut reader = spawn_control_reader(slot0.connection().clone());
    let mut slot1 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(1)).await;

    // Wait for the connect-time snapshot before changing the accounting.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                reader.recv().await,
                Some(ControlInbound::DisconnectBudgets(_))
            ) {
                break;
            }
        }
    })
    .await
    .expect("initial budget snapshot");
    relay.mesh.session.disconnect_budgets.merge(
        &key(session),
        &[EpisodeSnapshot {
            slot: SlotId(1),
            connection_epoch: 123,
            elapsed: Duration::from_secs(30),
            complete: true,
        }],
        Instant::now(),
    );

    let mut tick = tokio::time::interval(Duration::from_millis(10));
    let mut seq = 0;
    let mut forwarded = 0;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    slot1.send(Some(build_turn(1, seq, None))).unwrap();
                    seq += 1;
                }
                received = slot0.recv() => {
                    forwarded += received.unwrap().fresh.len();
                    slot0.send(None).unwrap();
                }
                received = slot1.recv() => { received.unwrap(); }
                frame = reader.recv() => match frame.expect("control stream stays open") {
                    ControlInbound::DisconnectBudgets(snapshot) if snapshot.budgets.iter().any(|b|
                        b.slot == 1 && b.remaining_ms == 150_000 && !b.running
                    ) => break,
                    _ => {}
                }
            }
        }
    })
    .await
    .expect("updated budget snapshot during traffic");
    assert!(
        forwarded >= 10,
        "turns were forwarded while waiting for the update"
    );
}
