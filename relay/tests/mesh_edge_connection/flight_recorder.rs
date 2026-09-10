//! The flight recorder capturing a client's lifecycle and flushing it on close.

use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_relay::routing::SessionKey;

use crate::helpers::*;

/// The flight recorder captures a real client's lifecycle end to end: the
/// connect event and validated-turn counters accumulate while the client plays,
/// and its disconnect empties the session, whose close-time flush lands the
/// blob at the file sink's tenant-scoped path.
#[tokio::test]
async fn the_flight_recorder_captures_a_client_lifecycle_and_flushes_on_close()
-> Result<(), AnyError> {
    use rally_point_relay::observability::flight_recorder::{FileSink, FlightBlob, FlightEvent};

    let tenant = make_tenant();
    let session = SessionId(1);
    let relay = Relay::start(&tenant, 1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let flight = relay.mesh.decision_makers.flight_recorder().clone();
    let dir = std::env::temp_dir().join(format!("rp2-flight-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    flight.set_sink(std::sync::Arc::new(FileSink::new(dir.clone())));

    // Two clients connect; slot 0 sends a couple of turns and slot 1 receives
    // them — the receive is what proves the relay validated and delivered both
    // before the disconnect below (dropping earlier could race the datagrams).
    let mut client_a = connect_client(relay.addr, &relay.ca, &tenant, session, SlotId(0)).await?;
    let mut client_b = connect_client(relay.addr, &relay.ca, &tenant, session, SlotId(1)).await?;
    client_a.send(Some(turn(0, 0)))?;
    client_a.send(Some(turn(0, 1)))?;
    let mut received = 0;
    while received < 2 {
        let got = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
            .await
            .map_err(|_| "client B did not receive the turns within 2s")?
            .map_err(|e| format!("client B link error: {e}"))?;
        received += got.fresh.len();
    }

    // The connect events landed when the link tasks started serving.
    let seen: Vec<FlightEvent> = flight.events(&key).into_iter().map(|r| r.event).collect();
    assert!(
        seen.contains(&FlightEvent::SlotConnected {
            slot: 0,
            resumed: false,
        }),
        "the connect event is recorded: {seen:?}",
    );

    // The clients disconnect: the session empties, the close-time flush writes
    // the blob to <dir>/<tenant>/<session>/<relay_id>.json (relay id 0 — this
    // dev relay never set one).
    drop(client_a);
    drop(client_b);
    let path = dir.join(TENANT).join("1").join("0.json");
    let mut blob: Option<FlightBlob> = None;
    for _ in 0..250 {
        if let Ok(json) = std::fs::read_to_string(&path) {
            blob = Some(serde_json::from_str(&json)?);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let blob = blob.expect("the close-time flush wrote the blob");

    let events: Vec<&FlightEvent> = blob.events.iter().map(|r| &r.event).collect();
    assert!(events.contains(&&FlightEvent::SlotConnected {
        slot: 0,
        resumed: false
    }));
    assert!(events.contains(&&FlightEvent::SlotDisconnected { slot: 0 }));
    assert!(events.contains(&&FlightEvent::SessionClosed));

    // The final counter snapshot carries the sender's validated turns and the
    // receiver's delivered ones.
    let last = blob.samples.last().expect("a final counter snapshot");
    let sender = last
        .slots
        .iter()
        .find(|s| s.slot == 0)
        .expect("slot 0's counters");
    assert!(
        sender.turns_validated >= 2,
        "both sent turns were validated: {sender:?}",
    );
    assert_eq!(sender.newest_seq, 1);
    let receiver = last
        .slots
        .iter()
        .find(|s| s.slot == 1)
        .expect("slot 1's counters");
    assert!(
        receiver.turns_forwarded >= 2,
        "both turns were delivered to slot 1: {receiver:?}",
    );

    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
