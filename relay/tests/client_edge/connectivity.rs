//! Flight-recorder coverage for client-facing connectivity control writes.

use crate::helpers::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_relay::key::SessionKey;
use rally_point_relay::observability::flight_recorder::FlightEvent;
use rally_point_transport::control::spawn_control_reader;

#[tokio::test]
async fn a_local_disconnect_records_the_successful_recipient_and_subject_epochs() {
    let tenant = make_default_tenant();
    let session = SessionId(420);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let relay = start_relay(registry_for_one(&tenant));
    let endpoint = client_endpoint(&relay.ca);
    let makers = relay.mesh.session.decision_makers.clone();

    let slot0 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(0)).await;
    let mut control0 = spawn_control_reader(slot0.connection().clone());
    let slot1 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(1)).await;

    // The initial connected fan-out gives us the two lifecycle epochs that the
    // later disconnect must carry back to the same recipient and subject.
    wait_for_connectivity(&mut control0, SlotId(1), true).await;
    let conditions = rally_point_relay::mesh::snapshot_conditions(&relay.mesh.conditions, &key)
        .expect("activation publishes both local links");
    let epoch = |slot| {
        conditions
            .slots
            .iter()
            .find(|row| row.slot == slot)
            .unwrap()
            .connection_epoch
            .unwrap()
    };
    let expected_epochs = (epoch(0), epoch(1));
    drop(slot1);
    wait_for_connectivity(&mut control0, SlotId(1), false).await;

    wait_until("the local disconnect write was not recorded", || {
        makers
            .flight_recorder()
            .events(&key)
            .into_iter()
            .any(|record| {
                matches!(
                    record.event,
                    FlightEvent::ConnectivityControlWrite {
                        recipient: 0,
                        slot: 1,
                        connected: false,
                        succeeded: true,
                        subject_connection_epoch: Some(_),
                        ..
                    }
                )
            })
    })
    .await;

    let events: Vec<_> = makers
        .flight_recorder()
        .events(&key)
        .into_iter()
        .map(|record| record.event)
        .collect();
    let connected = events.iter().find_map(|event| match event {
        FlightEvent::ConnectivityControlWrite {
            recipient: 0,
            slot: 1,
            connected: true,
            succeeded: true,
            connection_epoch,
            subject_connection_epoch: Some(subject_connection_epoch),
        } => Some((*connection_epoch, *subject_connection_epoch)),
        _ => None,
    });
    let disconnected = events.iter().find_map(|event| match event {
        FlightEvent::ConnectivityControlWrite {
            recipient: 0,
            slot: 1,
            connected: false,
            succeeded: true,
            connection_epoch,
            subject_connection_epoch: Some(subject_connection_epoch),
        } => Some((*connection_epoch, *subject_connection_epoch)),
        _ => None,
    });

    assert_eq!(connected, Some(expected_epochs));
    assert_eq!(disconnected, Some(expected_epochs));
}

/// Starts a relay holding a coordinator descriptor for `session` that expects
/// slots 0-2, so the session has the decision-maker a production relay builds
/// from its descriptor (the one that tracks each member's live generation).
fn start_relay_expecting_three(tenant: &Tenant, session: SessionId) -> TestRelay {
    use rally_point_proto::control::SessionDescriptor;
    use rally_point_proto::ids::RelayId;
    use rally_point_relay::mesh::MeshState;
    use rally_point_relay::mesh::control::MeshControl;
    use rally_point_relay::routing::Sessions;
    use rally_point_relay::session::SessionState;

    let mesh = MeshState::new(SessionState::default());
    let control = MeshControl::new(RelayId(1), &mesh, Sessions::default());
    control.apply_descriptor(&SessionDescriptor {
        expected_slots: vec![SlotId(0), SlotId(1), SlotId(2)],
        ..descriptor(TENANT, session)
    });
    start_relay_with_mesh(registry_for_one(tenant), mesh)
}

/// Collects every connectivity frame `reader` receives until it has been quiet
/// for `quiet`, as `(slot, connected)` in arrival order.
async fn drain_connectivity(
    reader: &mut tokio::sync::mpsc::Receiver<rally_point_transport::control::ControlInbound>,
    quiet: std::time::Duration,
) -> Vec<(u32, bool)> {
    use rally_point_transport::control::ControlInbound;
    let mut changes = Vec::new();
    while let Ok(Some(frame)) = tokio::time::timeout(quiet, reader.recv()).await {
        if let ControlInbound::Connectivity(change) = frame {
            changes.push((change.slot, change.connected));
        }
    }
    changes
}

#[tokio::test]
async fn a_late_slot_learns_which_members_were_already_connected() {
    let tenant = make_default_tenant();
    let session = SessionId(421);
    let relay = start_relay_expecting_three(&tenant, session);
    let endpoint = client_endpoint(&relay.ca);

    let slot0 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(0)).await;
    let mut control0 = spawn_control_reader(slot0.connection().clone());
    let _slot1 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(1)).await;
    wait_for_connectivity(&mut control0, SlotId(1), true).await;

    // Both members connected before slot 2's link existed, so neither live
    // broadcast reached it; only the connect-time restatement can.
    let slot2 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(2)).await;
    let mut control2 = spawn_control_reader(slot2.connection().clone());
    let changes = drain_connectivity(&mut control2, std::time::Duration::from_millis(500)).await;

    assert!(
        changes.contains(&(0, true)),
        "slot 0 not restated: {changes:?}"
    );
    assert!(
        changes.contains(&(1, true)),
        "slot 1 not restated: {changes:?}"
    );
    assert!(
        changes.iter().all(|&(_, connected)| connected),
        "unexpected disconnect: {changes:?}"
    );
}

#[tokio::test]
async fn a_member_that_disconnected_is_not_restated_to_a_late_slot() {
    let tenant = make_default_tenant();
    let session = SessionId(422);
    let relay = start_relay_expecting_three(&tenant, session);
    let endpoint = client_endpoint(&relay.ca);

    let slot0 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(0)).await;
    let mut control0 = spawn_control_reader(slot0.connection().clone());
    let slot1 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(1)).await;
    wait_for_connectivity(&mut control0, SlotId(1), true).await;
    drop(slot1);
    wait_for_connectivity(&mut control0, SlotId(1), false).await;

    let slot2 = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(2)).await;
    let mut control2 = spawn_control_reader(slot2.connection().clone());
    let changes = drain_connectivity(&mut control2, std::time::Duration::from_millis(500)).await;

    assert!(
        changes.contains(&(0, true)),
        "slot 0 not restated: {changes:?}"
    );
    assert!(
        !changes.contains(&(1, true)),
        "a disconnected member was restated as connected: {changes:?}"
    );
}
