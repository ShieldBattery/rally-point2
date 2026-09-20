//! The coordinator's split reader/writer over one control connection: the reader
//! and writer halves run independently, so a flooded reader does not delay the
//! writer's descriptor push, and queued reap nudges coalesce per session — a
//! burst for one session arriving as a single `CloseSlot` carrying the merged
//! slot union, while nudges for two different sessions stay two frames.

use std::time::Duration;

use rally_point_proto::control::{CoordinatorToRelay, RelayToCoordinator, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use tokio::time::timeout;

use crate::common;
use crate::common::{read_to_descriptors, relay_key};
use crate::helpers::*;

#[tokio::test]
async fn an_inbound_flood_does_not_delay_a_descriptor_push() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    // A relay enrolls, then floods the coordinator with inbound heartbeats while a
    // session is created. Because reads and writes run on independent halves, the
    // writer keeps making progress under the reader's load, so the descriptor push
    // naming the new session still arrives promptly.
    let (base_url, setup) = serve_coordinator_exposing_setup(&[]).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    common::prove_identity(&mut socket, &relay_key(1)).await;
    assert!(wait_for_enrollment(setup.registry(), RelayId(1)).await);

    let (mut write, mut read) = socket.split();

    // Flood inbound heartbeats continuously from a side task.
    let flood = tokio::spawn(async move {
        let beat = serde_json::to_string(&RelayToCoordinator::Heartbeat {
            roster_complete: true,
            sessions: vec![],
            region_rtts: vec![],
        })
        .unwrap();
        loop {
            if write
                .send(Message::Text(beat.clone().into()))
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });

    // Create a session homed on the relay; its descriptor must be pushed.
    let session = create_one_slot_session(&setup);

    // Despite the flood, the descriptor push naming the session arrives quickly. The
    // session is created after enroll, so a delta-capable relay receives it as a
    // delta upsert; either the full set or a delta naming the session counts.
    let found = timeout(Duration::from_secs(3), async {
        while let Some(Ok(message)) = read.next().await {
            if let Message::Text(text) = message
                && let Ok(frame) = serde_json::from_str::<CoordinatorToRelay>(&text)
            {
                let names_session = match &frame {
                    CoordinatorToRelay::Descriptors { descriptors, .. } => {
                        descriptors.iter().any(|d| d.session == session)
                    }
                    CoordinatorToRelay::DescriptorDelta { upserts, .. } => {
                        upserts.iter().any(|d| d.session == session)
                    }
                    _ => false,
                };
                if names_session {
                    return true;
                }
            }
        }
        false
    })
    .await
    .expect("the descriptor push must arrive well within the bound despite the flood");
    assert!(
        found,
        "the writer pushed the new session's descriptor while the reader was flooded",
    );
    flood.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn queued_reaps_for_one_session_arrive_as_a_single_frame() {
    use futures_util::{SinkExt, StreamExt};
    use rally_point_coordinator::descriptors::SlotClose;
    use tokio_tungstenite::tungstenite::Message;

    // A burst of reap nudges for the SAME session, queued before the writer's reap
    // arm wakes, coalesces into one CloseSlot frame carrying the merged slot union.
    // A single-threaded runtime makes the burst-before-drain deterministic: the
    // writer task cannot run while this test task fires the nudges without awaiting.
    let (base_url, setup) = serve_coordinator_exposing_setup(&[]).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(1, 14900))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    common::prove_identity(&mut socket, &relay_key(1)).await;
    assert!(wait_for_enrollment(setup.registry(), RelayId(1)).await);

    // Drain the connect-time lead so the next frames read are the reap directives,
    // and so the writer is parked in its steady-state select before the burst.
    let _ = read_to_descriptors(&mut socket).await;

    // Fire the nudges synchronously (no await between), so they all queue on the
    // relay's reap channel before the writer drains any. Each nudge carries the
    // merged-so-far slot union for its session, so the last is the most complete.
    let tenant = TenantId(TENANT.to_owned());
    for slot in 0u8..8 {
        setup.reaps().send(
            RelayId(1),
            SlotClose {
                tenant: tenant.clone(),
                session: SessionId(1),
                slots: (0..=slot).map(SlotId).collect(),
            },
        );
    }

    // Exactly one CloseSlot frame arrives, carrying the full union of every nudge's
    // slots.
    let (session, slots) = timeout(Duration::from_secs(5), async {
        while let Some(Ok(Message::Text(text))) = socket.next().await {
            if let Ok(CoordinatorToRelay::CloseSlot { session, slots, .. }) =
                serde_json::from_str::<CoordinatorToRelay>(&text)
            {
                return (session, slots);
            }
        }
        panic!("no CloseSlot frame arrived");
    })
    .await
    .expect("a CloseSlot frame should arrive");
    assert_eq!(session, SessionId(1));
    assert_eq!(
        slots,
        (0u8..8).map(SlotId).collect::<Vec<_>>(),
        "the single frame carries the union of every coalesced nudge",
    );

    // No further CloseSlot for the same session follows within a short window — the
    // queued nudges collapsed into the one frame.
    let another = timeout(Duration::from_millis(300), async {
        while let Some(Ok(Message::Text(text))) = socket.next().await {
            if matches!(
                serde_json::from_str::<CoordinatorToRelay>(&text),
                Ok(CoordinatorToRelay::CloseSlot { .. })
            ) {
                return true;
            }
        }
        false
    })
    .await;
    assert!(
        matches!(another, Err(_) | Ok(false)),
        "the queued nudges coalesced into a single frame, not one per nudge",
    );

    // Coalescing is per session, not per connection: nudges for two different
    // sessions, queued the same way, must arrive as two frames.
    for session in [2u64, 3] {
        setup.reaps().send(
            RelayId(1),
            SlotClose {
                tenant: tenant.clone(),
                session: SessionId(session),
                slots: vec![SlotId(0)],
            },
        );
    }
    let mut seen = Vec::new();
    timeout(Duration::from_secs(5), async {
        while let Some(Ok(Message::Text(text))) = socket.next().await {
            if let Ok(CoordinatorToRelay::CloseSlot { session, .. }) =
                serde_json::from_str::<CoordinatorToRelay>(&text)
            {
                seen.push(session);
                if seen.len() == 2 {
                    return;
                }
            }
        }
        panic!("the two sessions' reap directives never both arrived");
    })
    .await
    .expect("two sessions must not merge into one frame");
    seen.sort();
    assert_eq!(seen, vec![SessionId(2), SessionId(3)]);
}
