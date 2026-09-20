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
