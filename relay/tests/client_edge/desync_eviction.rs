//! A rollback session's desync verdict carried out end to end: the named
//! slot's link is closed and its re-dial refused, and the survivors receive a
//! finalized leave for it without asking for a drop.

use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::close_codes;
use rally_point_proto::control::{BufferBounds, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::{Payload, StateHashReport};
use rally_point_relay::consensus::{Authority, LEAVE_REASON_DROPPED, MakerSync};
use rally_point_relay::key::SessionKey;
use rally_point_relay::routing::{MeshEvictor, run_state_hash_watch};
use rally_point_transport::control::{ControlInbound, spawn_control_reader};
use rally_point_transport::noq::{ConnectionError, VarInt};

/// How many turns each slot sends: one past the first report step, so the
/// step is confirmable and the report rides the turn after it.
const TURNS: u64 = 9;

/// Slot `slot`'s turn `seq`, framed, with its report of the state after
/// eight turns riding the last one.
fn reporting_turn(slot: u8, seq: u64, hash: u64) -> Payload {
    Payload {
        state_hash: (seq == TURNS - 1).then_some(StateHashReport { step: 8, hash }),
        ..build_turn(slot, seq, Some(10 + seq as u32))
    }
}

#[tokio::test]
async fn a_diverged_slot_is_evicted_and_its_survivors_get_a_finalized_leave() {
    let tenant = make_default_tenant();
    let session = SessionId(330);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // A rollback session over three slots, all homed on this relay, which is
    // the authority: it judges the reports, homes the diverged slot, and
    // decides the leave.
    let mesh = rally_point_relay::mesh::MeshState::default();
    let makers = mesh.session.decision_makers.clone();
    let _ = makers.sync_maker(
        &key,
        MakerSync {
            expected_slots: [SlotId(0), SlotId(1), SlotId(2)].into(),
            homed_slots: [SlotId(0), SlotId(1), SlotId(2)].into(),
            rollback: true,
            finalized_drops: true,
            ..MakerSync::new(BufferBounds::new(0, 20).unwrap(), Authority::SelfRelay)
        },
    );
    let relay = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    tokio::spawn(run_state_hash_watch(
        makers.clone(),
        MeshEvictor {
            sessions: relay.sessions.clone(),
            mesh: relay.mesh.clone(),
        },
        Duration::from_millis(20),
    ));
    let endpoint = client_endpoint(&relay.ca);

    let mut slots = Vec::new();
    for slot in 0..3 {
        slots.push(connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(slot)).await);
    }
    let mut survivors = [
        spawn_control_reader(slots[0].connection().clone()),
        spawn_control_reader(slots[1].connection().clone()),
    ];
    let diverged = slots[2].connection().clone();
    wait_for_slots(&relay.sessions, &key, 3).await;

    // Slots 0 and 1 agree on the state after eight turns; slot 2 does not.
    for seq in 0..TURNS {
        for (slot, link) in slots.iter_mut().enumerate() {
            let hash = if slot == 2 { 0xbbbb } else { 0xaaaa };
            link.send(Some(reporting_turn(slot as u8, seq, hash)))
                .unwrap();
        }
    }

    let reason = tokio::time::timeout(Duration::from_secs(5), diverged.closed())
        .await
        .expect("the diverged slot's link is closed");
    assert!(
        matches!(
            reason,
            ConnectionError::ApplicationClosed(ref close)
                if close.error_code == VarInt::from_u32(close_codes::DESYNC_EVICTED)
        ),
        "closed as a desync eviction, got {reason:?}",
    );

    for reader in &mut survivors {
        let leave = loop {
            if let ControlInbound::Leave(leave) = recv_meaningful(reader).await {
                break leave;
            }
        };
        assert_eq!(leave.slot, 2);
        assert_eq!(leave.reason, LEAVE_REASON_DROPPED);
        assert!(leave.finalized, "the leave carries the home's sealed count");
        assert_eq!(
            leave.final_turn_count,
            Some(TURNS),
            "every turn the diverged slot sent before its link closed counts",
        );
    }

    // A re-dial is refused as a departed slot, which a client treats as final.
    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(2), client_key.public);
    let redial = endpoint
        .connect(relay.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let _ = handshake(&redial, &token, &client_key, &[]).await;
    let reason = tokio::time::timeout(Duration::from_secs(5), redial.closed())
        .await
        .expect("the re-dial is closed");
    assert!(
        matches!(
            reason,
            ConnectionError::ApplicationClosed(ref close)
                if close.error_code == VarInt::from_u32(close_codes::SLOT_DEPARTED)
        ),
        "a re-dial is refused as departed, got {reason:?}",
    );
}
