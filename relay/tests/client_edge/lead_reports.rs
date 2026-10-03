//! A rollback session's lead reports end to end: a player's turns are measured against the
//! session clock however they reach the relay, and the reports come back down that player's own
//! control stream.

use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::control::{BufferBounds, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::{LeadReport, Payload};
use rally_point_proto::rollback::LOCKSTEP_START_STEPS;
use rally_point_relay::consensus::{Authority, MakerSync};
use rally_point_relay::key::SessionKey;
use rally_point_transport::control::{ControlInbound, send_control_turn, spawn_control_reader};
use tokio::sync::mpsc;

/// How many turns each slot sends: the lockstep start, which anchors the clock, and enough after
/// it for a report.
const TURNS: u64 = LOCKSTEP_START_STEPS + 4;

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

/// The next lead report on `reader`, skipping every other control frame.
async fn next_lead_report(reader: &mut mpsc::Receiver<ControlInbound>) -> LeadReport {
    loop {
        if let ControlInbound::LeadReport(report) = recv_meaningful(reader).await {
            return report;
        }
    }
}

#[tokio::test]
async fn a_player_gets_lead_reports_for_its_turns_once_the_clock_is_anchored() {
    let session = SessionId(340);
    let (relay, key, tenant) = rollback_relay(session);
    let endpoint = client_endpoint(&relay.ca);
    let mut slots = Vec::new();
    for slot in 0..2 {
        slots.push(connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(slot)).await);
    }
    let mut reader = spawn_control_reader(slots[0].connection().clone());
    wait_for_slots(&relay.sessions, &key, 2).await;

    for seq in 0..TURNS {
        for (slot, link) in slots.iter_mut().enumerate() {
            link.send(Some(build_turn(slot as u8, seq, Some(10 + seq as u32))))
                .unwrap();
        }
    }

    let report = tokio::time::timeout(Duration::from_secs(5), next_lead_report(&mut reader))
        .await
        .expect("a lead report arrives");
    assert!(
        report.through_step >= LOCKSTEP_START_STEPS - 1,
        "only turns from the anchor on are measured",
    );
    assert!(report.samples >= 1);
    assert_eq!(report.pause_us, 0);
}

/// A turn too large for a datagram goes up the reliable stream instead, and is measured all the
/// same: a player whose every turn is oversize still gets reports.
#[tokio::test]
async fn a_player_sending_only_oversize_turns_still_gets_lead_reports() {
    let session = SessionId(341);
    let (relay, key, tenant) = rollback_relay(session);
    let endpoint = client_endpoint(&relay.ca);
    let mut slot0 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(1)).await;
    let mut reader = spawn_control_reader(slot1.connection().clone());
    wait_for_slots(&relay.sessions, &key, 2).await;

    let (mut oversize_send, _unused_recv) = slot1.connection().open_bi().await.unwrap();
    for seq in 0..TURNS {
        slot0
            .send(Some(build_turn(0, seq, Some(10 + seq as u32))))
            .unwrap();
        send_control_turn(
            &mut oversize_send,
            Payload {
                seq,
                slot: 1,
                commands: vec![0x05u8; 2000].into(),
                game_frame_count: Some(10 + seq as u32),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    let report = tokio::time::timeout(Duration::from_secs(5), next_lead_report(&mut reader))
        .await
        .expect("a lead report arrives for the oversize sender");
    assert!(report.samples >= 1);
}
