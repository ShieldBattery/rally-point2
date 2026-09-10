//! What the relay reports about the sessions it holds: the heartbeat's roster
//! entries, the one-session load-state snapshot that must match them, and the
//! measured region round-trips a beat carries.

use super::*;

#[tokio::test]
async fn a_heartbeat_carries_the_live_roster_as_presence() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (frame_tx, frame_rx) = tokio::sync::oneshot::channel();

    // Stand-in coordinator: complete the enroll handshake, then read the first
    // heartbeat.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let hello = accept_enroll(&mut ws).await;
        let Message::Text(hello) = hello else {
            panic!("first frame is the Hello");
        };
        assert!(hello.contains("\"type\":\"hello\""));
        let beat = ws.next().await.unwrap().unwrap();
        let _ = frame_tx.send(beat);
    });

    // A slot registered in the roster before the subscriber starts, so the
    // first beat already carries it. The guard is disarmed and the inbox held
    // so the slot stays registered for the test's duration.
    let sessions: Sessions = Arc::default();
    let (mut guard, _inbox) =
        crate::routing::register(&sessions, &key(7), rally_point_proto::ids::SlotId(3), 1)
            .expect("slot 3 registers");
    guard.disarm();

    // The session's decision-maker holds the load state the beat restates:
    // slot 2 arrived and dropped again (so it is off the live roster but
    // still ever-connected), slot 3 arrived and reported its game loop.
    let decision_makers = std::sync::Arc::new(crate::consensus::new_decision_makers());
    let _ = crate::consensus::sync_maker(
        &decision_makers,
        &key(7),
        rally_point_proto::control::BufferBounds { min: 1, max: 6 },
        crate::consensus::Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    crate::consensus::record_slot_connected(
        &decision_makers,
        &key(7),
        rally_point_proto::ids::SlotId(2),
        false,
    );
    crate::consensus::record_slot_connected(
        &decision_makers,
        &key(7),
        rally_point_proto::ids::SlotId(3),
        false,
    );
    crate::consensus::record_slot_started(
        &decision_makers,
        &key(7),
        rally_point_proto::ids::SlotId(3),
    );

    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let (drain_rx, drain_acked) = no_drain();
    tokio::spawn(run_descriptor_subscriber_with(
        enroll(addr, drain_hello()),
        apply_targets(control, drain_acked),
        OutboundQueues::new(
            mpsc::unbounded_channel().1,
            no_flight(),
            ControlConnStats::new(),
        ),
        HeartbeatConfig {
            sources: HeartbeatSources {
                sessions: Arc::clone(&sessions),
                decision_makers,
                region_rtt_cache: RegionRttCache::default(),
                load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
            },
            interval: Duration::from_millis(50), // beat quickly so the test observes one
        },
        drain_rx,
        no_connected(),
        backoff(Duration::from_millis(20), Duration::from_secs(60)),
    ));

    let beat = tokio::time::timeout(Duration::from_secs(5), frame_rx)
        .await
        .expect("a heartbeat arrives")
        .unwrap();
    let Message::Text(text) = beat else {
        panic!("the heartbeat is a text frame");
    };
    let decoded: RelayToCoordinator = serde_json::from_str(&text).unwrap();
    assert_eq!(
        decoded,
        RelayToCoordinator::Heartbeat {
            roster_complete: true,
            sessions: vec![SessionPresence {
                tenant: TenantId(TENANT.to_owned()),
                session: SessionId(7),
                slots: vec![rally_point_proto::ids::SlotId(3)],
                ever_connected: vec![
                    rally_point_proto::ids::SlotId(2),
                    rally_point_proto::ids::SlotId(3),
                ],
                started: vec![rally_point_proto::ids::SlotId(3)],
                // The session never started on this relay — neither its own
                // coverage latch nor an adopted directive — so it has no
                // instant to restate.
                started_at_ms: None,
            }],
            region_rtts: vec![],
        },
        "the beat names the registered (tenant, session, slot) and the \
         session's retained load state",
    );
}

#[test]
fn a_beat_restates_the_load_state_of_a_session_whose_last_slot_left() {
    // A relay's makers, not its live roster, decide which sessions a beat
    // names. The roster drops a session the moment its last local slot leaves,
    // while the game runs on elsewhere — so keying the beat on the roster
    // would stop restating exactly the facts (who arrived here, who started)
    // the coordinator has no other durable source for.
    use rally_point_proto::ids::SlotId;

    let sessions: Sessions = Arc::default();
    let decision_makers = Arc::new(crate::consensus::new_decision_makers());
    let _ = crate::consensus::sync_maker(
        &decision_makers,
        &key(7),
        BufferBounds { min: 1, max: 6 },
        crate::consensus::Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    let (registration, _inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), 1).expect("slot 0 registers");
    crate::consensus::record_slot_connected(&decision_makers, &key(7), SlotId(0), false);
    crate::consensus::record_slot_started(&decision_makers, &key(7), SlotId(0));

    // The slot's link ends: the routing group goes with it, the maker stays.
    drop(registration);
    assert!(crate::routing::live_slots(&sessions).is_empty());

    let sources = HeartbeatSources {
        sessions: Arc::clone(&sessions),
        decision_makers: Arc::clone(&decision_makers),
        region_rtt_cache: RegionRttCache::default(),
        load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
    };
    assert_eq!(
        heartbeat_presence(&sources),
        vec![SessionPresence {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(7),
            slots: vec![],
            ever_connected: vec![SlotId(0)],
            started: vec![SlotId(0)],
            started_at_ms: None,
        }],
        "the session is still named, with no connected slot and its retained sets",
    );

    // A session with a connected slot but no maker (a provisional admission no
    // descriptor ever claimed) is named too, with nothing retained.
    let (mut unclaimed, _unclaimed_inbox) =
        crate::routing::register(&sessions, &key(8), SlotId(1), 1).expect("slot 1 registers");
    unclaimed.disarm();
    let roster = heartbeat_presence(&sources);
    assert_eq!(roster.len(), 2);
    let unclaimed = roster
        .iter()
        .find(|entry| entry.session == SessionId(8))
        .expect("the maker-less session is on the beat");
    assert_eq!(unclaimed.slots, vec![SlotId(1)]);
    assert!(unclaimed.ever_connected.is_empty() && unclaimed.started.is_empty());
}

#[tokio::test]
async fn a_load_state_request_is_answered_on_the_control_connection() {
    // The exchange the coordinator's completeness claim rests on: the relay
    // answers the question it was asked, from the state it holds, echoing the
    // correlation id back so the answer belongs to that request and no other.
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (frame_tx, frame_rx) = tokio::sync::oneshot::channel();

    // Stand-in coordinator: enroll the relay, push a load-state request, then
    // read frames until the snapshot arrives (a heartbeat may precede it).
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _hello = accept_enroll(&mut ws).await;
        let request = serde_json::to_string(&CoordinatorToRelay::LoadStateRequest {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(7),
            request_id: 99,
        })
        .unwrap();
        ws.send(Message::Text(request.into())).await.unwrap();
        while let Some(Ok(Message::Text(text))) = ws.next().await {
            if text.contains("\"type\":\"load_state_snapshot\"") {
                let _ = frame_tx.send(text.to_string());
                return;
            }
        }
    });

    // What this relay holds for the session: slot 2 arrived and dropped, slot 3
    // is here and running.
    let sessions: Sessions = Arc::default();
    let (mut guard, _inbox) =
        crate::routing::register(&sessions, &key(7), rally_point_proto::ids::SlotId(3), 1)
            .expect("slot 3 registers");
    guard.disarm();
    let decision_makers = std::sync::Arc::new(crate::consensus::new_decision_makers());
    let _ = crate::consensus::sync_maker(
        &decision_makers,
        &key(7),
        rally_point_proto::control::BufferBounds { min: 1, max: 6 },
        crate::consensus::Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    for slot in [2u8, 3] {
        crate::consensus::record_slot_connected(
            &decision_makers,
            &key(7),
            rally_point_proto::ids::SlotId(slot),
            false,
        );
    }
    crate::consensus::record_slot_started(
        &decision_makers,
        &key(7),
        rally_point_proto::ids::SlotId(3),
    );

    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let (drain_rx, drain_acked) = no_drain();
    tokio::spawn(run_descriptor_subscriber_with(
        enroll(addr, drain_hello()),
        apply_targets(control, drain_acked),
        OutboundQueues::new(
            mpsc::unbounded_channel().1,
            no_flight(),
            ControlConnStats::new(),
        ),
        HeartbeatConfig {
            sources: HeartbeatSources {
                sessions: Arc::clone(&sessions),
                decision_makers,
                region_rtt_cache: RegionRttCache::default(),
                load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
            },
            // Long enough that the snapshot is not merely a beat in disguise.
            interval: Duration::from_secs(3600),
        },
        drain_rx,
        no_connected(),
        backoff(Duration::from_millis(20), Duration::from_secs(60)),
    ));

    let text = tokio::time::timeout(Duration::from_secs(5), frame_rx)
        .await
        .expect("the relay answers promptly")
        .expect("the stand-in coordinator forwards the snapshot");
    assert_eq!(
        serde_json::from_str::<RelayToCoordinator>(&text).unwrap(),
        RelayToCoordinator::LoadStateSnapshot {
            request_id: 99,
            state: SessionPresence {
                tenant: TenantId(TENANT.to_owned()),
                session: SessionId(7),
                slots: vec![rally_point_proto::ids::SlotId(3)],
                ever_connected: vec![
                    rally_point_proto::ids::SlotId(2),
                    rally_point_proto::ids::SlotId(3),
                ],
                started: vec![rally_point_proto::ids::SlotId(3)],
                started_at_ms: None,
            },
            // Slot 2 arrived here and is gone: no stream to probe, and its
            // client may be holding a report for the stream it opens next, so
            // this answer's absences carry no proof.
            fenced: false,
        },
    );
}

#[test]
fn a_load_state_snapshot_reports_the_same_session_a_beat_would() {
    // An attested snapshot and a heartbeat's roster entry describe a session
    // identically — they read the same live roster and the same retained maker
    // state. What differs is only what the reader may assume about ordering.
    use rally_point_proto::ids::SlotId;

    let sessions: Sessions = Arc::default();
    let decision_makers = Arc::new(crate::consensus::new_decision_makers());
    let _ = crate::consensus::sync_maker(
        &decision_makers,
        &key(7),
        BufferBounds { min: 1, max: 6 },
        crate::consensus::Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    let (_registration, _inbox) =
        crate::routing::register(&sessions, &key(7), SlotId(0), 1).expect("slot 0 registers");
    crate::consensus::record_slot_connected(&decision_makers, &key(7), SlotId(0), false);
    crate::consensus::record_slot_started(&decision_makers, &key(7), SlotId(0));

    let sources = HeartbeatSources {
        sessions: Arc::clone(&sessions),
        decision_makers: Arc::clone(&decision_makers),
        region_rtt_cache: RegionRttCache::default(),
        load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
    };
    assert_eq!(
        session_load_snapshot(&sources.sessions, &sources.decision_makers, key(7)).0,
        heartbeat_presence(&sources)
            .into_iter()
            .find(|entry| entry.session == SessionId(7))
            .expect("the session is on the beat"),
    );
}

#[test]
fn a_session_this_relay_does_not_hold_snapshots_to_empty_rather_than_nothing() {
    // Empty is a real answer — "I know of no arrival here" — and is exactly
    // what a relay that never held the session has to say. The coordinator's
    // completeness claim rests on the difference between this and silence, and
    // silence is never produced here: every question gets an answer.
    let sources = HeartbeatSources {
        sessions: Arc::default(),
        decision_makers: Arc::new(crate::consensus::new_decision_makers()),
        region_rtt_cache: RegionRttCache::default(),
        load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
    };
    assert_eq!(
        session_load_snapshot(&sources.sessions, &sources.decision_makers, key(7)).0,
        SessionPresence {
            tenant: TenantId(TENANT.to_owned()),
            session: SessionId(7),
            slots: vec![],
            ever_connected: vec![],
            started: vec![],
            started_at_ms: None,
        },
    );
}

#[test]
fn heartbeat_region_rtts_snapshots_the_cache_sorted_by_region() {
    let cache = RegionRttCache::new();
    // An empty cache reports no RTTs — the beat's field stays off the wire.
    assert!(heartbeat_region_rtts(&cache).is_empty());

    // Insert out of region order; the snapshot is sorted by region id, so the
    // beat's wire output is deterministic regardless of map iteration order.
    cache.record(RegionId("us-east".to_owned()), 87);
    cache.record(RegionId("ap-southeast".to_owned()), 210);
    cache.record(RegionId("eu-central".to_owned()), 42);
    assert_eq!(
        heartbeat_region_rtts(&cache),
        vec![
            RegionRttReport {
                region: RegionId("ap-southeast".to_owned()),
                rtt_ms: 210,
            },
            RegionRttReport {
                region: RegionId("eu-central".to_owned()),
                rtt_ms: 42,
            },
            RegionRttReport {
                region: RegionId("us-east".to_owned()),
                rtt_ms: 87,
            },
        ],
    );
}
