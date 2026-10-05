//! The `turns_complete` stamp end to end: every packet a relay sends its own client in a rollback
//! session carries how many of every slot's turns the relay holds without a gap, so a stalled
//! client can tell its own downlink's lag from the session waiting on a player.

use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::control::{BufferBounds, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_relay::consensus::{Authority, MakerSync};
use rally_point_relay::key::SessionKey;
use rally_point_transport::Link;

/// A rollback session over slots 0 and 1, both homed on a relay that is its authority.
fn rollback_relay(session: SessionId) -> (TestRelay, SessionKey, Tenant) {
    let tenant = make_default_tenant();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let mesh = rally_point_relay::mesh::MeshState::default();
    let _ = mesh.session.decision_makers.sync_maker(
        &key,
        MakerSync {
            expected_slots: [SlotId(0), SlotId(1)].into(),
            homed_slots: [SlotId(0), SlotId(1)].into(),
            rollback: true,
            finalized_drops: true,
            ..MakerSync::new(BufferBounds::new(0, 20).unwrap(), Authority::SelfRelay)
        },
    );
    let relay = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    (relay, key, tenant)
}

/// Receives on `link` until a packet stamps `count`, failing if none does within a few seconds.
/// Returns every stamp seen on the way, in arrival order.
async fn stamps_until(link: &mut Link, count: u64) -> Vec<u64> {
    let mut stamps = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let received = link.recv().await.expect("the link stays up");
            if let Some(stamp) = received.turns_complete {
                stamps.push(stamp);
                if stamp == count {
                    return;
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no packet stamped {count}; saw {stamps:?}"));
    stamps
}

#[tokio::test]
async fn a_client_learns_how_many_of_every_slots_turns_its_relay_holds() {
    let session = SessionId(341);
    let (relay, key, tenant) = rollback_relay(session);
    let endpoint = client_endpoint(&relay.ca);
    let mut slots = Vec::new();
    for slot in 0..2 {
        slots.push(connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(slot)).await);
    }
    wait_for_slots(&relay.sessions, &key, 2).await;

    // Slot 0 is ahead; slot 1, the one slot 0 waits on, has sent 6.
    for seq in 0..10 {
        slots[0]
            .send(Some(build_turn(0, seq, Some(10 + seq as u32))))
            .unwrap();
    }
    for seq in 0..6 {
        slots[1]
            .send(Some(build_turn(1, seq, Some(10 + seq as u32))))
            .unwrap();
    }
    let stamps = stamps_until(&mut slots[0], 6).await;
    assert!(
        stamps.iter().all(|&x| x <= 6),
        "never past slot 1: {stamps:?}"
    );

    for seq in 6..10 {
        slots[1]
            .send(Some(build_turn(1, seq, Some(10 + seq as u32))))
            .unwrap();
    }
    stamps_until(&mut slots[0], 10).await;
}
