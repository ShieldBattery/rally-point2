//! The coordinator's split reader/writer over one control connection: the reader
//! and writer halves run independently, so a flooded reader does not delay the
//! writer's descriptor push; queued reap nudges for the same session coalesce
//! into a single `CloseSlot` frame; and a relay that keeps heartbeating (so the
//! reader's liveness deadline never fires) but stops reading is still dropped by
//! the writer's own per-send stall bound.

use std::time::Duration;

use rally_point_coordinator::{registry, session};
use rally_point_proto::control::{
    CoordinatorToRelay, PlayerHandoff, RelayToCoordinator, SessionRequest, TenantId,
};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::{ClientPublicKey, ExpiresAt};
use rally_point_proto::version::ProtocolVersion;
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
}

#[tokio::test]
async fn a_relay_that_stops_reading_is_dropped_by_the_send_stall_bound_despite_heartbeats() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // The send-stall bound: a relay that keeps heartbeating — refreshing the
    // reader's liveness deadline forever — but stops READING must still lose its
    // registry entry, because the writer's per-send timeout runs from each send's
    // start, independent of the reader-refreshed deadline.
    //
    // Arranged over a real socket without guessing OS buffer sizes: a short liveness
    // plus a descriptor set the coordinator re-pushes every time it grows. The relay
    // enrolls at the pre-delta protocol floor ON PURPOSE — that version receives the
    // whole growing set on every change, so the unread bytes a never-draining peer
    // accumulates climb quadratically past whatever the buffers hold and a writer
    // send deterministically stalls. A delta-capable relay would receive only tiny
    // per-session diffs, far too little volume to fill a socket buffer within this
    // test's window. The heartbeats keep the reader's deadline fresh throughout, so
    // only the writer's bound can be what drops the connection.
    let liveness = Duration::from_millis(400);
    let (base_url, setup) = serve_coordinator_with_liveness(&[(1, 14900)], liveness).await;

    // A sizeable initial set, so each re-push already carries real weight.
    for _ in 0..1000 {
        create_one_slot_session(&setup);
    }

    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    // Enroll (the handshake requires reading the coordinator's challenge)...
    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello_at(
        1,
        14900,
        ProtocolVersion::MIN_SUPPORTED,
    )))
    .unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    common::prove_identity(&mut socket, &relay_key(1)).await;
    assert!(wait_for_enrollment(setup.registry(), RelayId(1)).await);

    // ...then never read again, only heartbeat — every ~25ms, well inside the 400ms
    // liveness — while growing the descriptor set so the coordinator keeps re-pushing
    // an ever-larger full set to a peer that never reads it.
    let heartbeat = serde_json::to_string(&RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions: vec![],
        region_rtts: vec![],
    })
    .unwrap();
    let mut beats = 0u32;
    let dropped = loop {
        // Deregistration is the drop being waited for; check before doing more work
        // (once the relay is gone, no session can home on it).
        if registry::peer(setup.registry(), RelayId(1)).is_none() {
            break true;
        }
        if socket
            .send(Message::Text(heartbeat.clone().into()))
            .await
            .is_err()
        {
            break true; // the coordinator tore the connection down; the send errors
        }
        beats += 1;
        if beats > 400 {
            break false; // ~10s of heartbeats with no drop: the bound never fired
        }
        // One more session → one more full re-push the peer will not drain, so the
        // coordinator's unread backlog keeps rising until a send stalls. A create
        // that fails for want of a relay means the drop already happened.
        let created = session::create_session(
            &setup,
            SessionRequest {
                tenant: TenantId(TENANT.to_owned()),
                players: vec![PlayerHandoff {
                    slot: SlotId(0),
                    client_pubkey: ClientPublicKey([0xAA; 32]),
                    external_ref: None,
                    observer: false,
                    region: None,
                }],
                external_id: None,
                latency_estimate_ms: None,
            },
            ExpiresAt(u64::MAX),
        )
        .is_ok();
        if !created {
            break true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert!(
        dropped,
        "a relay that heartbeats but never reads is dropped by the send-stall bound",
    );
    assert!(
        beats >= 2,
        "the relay actually heartbeated (refreshing the reader deadline) before the drop",
    );
    assert!(
        wait_for_deregistration(setup.registry(), RelayId(1)).await,
        "the wedged relay is deregistered",
    );
}
