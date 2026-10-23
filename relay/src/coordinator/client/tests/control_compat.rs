//! Unknown message kinds are additive; corrupt descriptor updates require resync.

use super::super::reader::{ReaderRoutes, read_control_frames};
use super::*;

#[tokio::test]
async fn future_message_keeps_websocket_usable_for_descriptor_acknowledgements() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let applied = AppliedSessions::default();
        let (connected, connected_rx) = watch::channel(false);
        SubscriberFixture {
            applied: applied.clone(),
            connected,
            ..Default::default()
        }
        .spawn(listener.local_addr().unwrap());
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        accept_enroll(&mut ws).await;
        for session in 1..=2 {
            ws.send(Message::Text(
                r#"{"type":"future_policy","policy":{"revision":42}}"#.into(),
            ))
            .await
            .unwrap();
            ws.send(Message::Text(
                serde_json::to_string(&CoordinatorToRelay::Descriptors {
                    ack_id: Some(session),
                    staged_at_unix_ms: None,
                    descriptors: vec![descriptor(session, &[])],
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
            assert_eq!(
                decode(ws.next().await.unwrap().unwrap()),
                RelayToCoordinator::DescriptorsApplied { ack_id: session }
            );
            assert_eq!(applied.snapshot(), HashSet::from([key(session)]));
            assert!(*connected_rx.borrow());
        }
    })
    .await
    .expect("future messages do not interrupt descriptor installation");
}

#[tokio::test]
async fn malformed_descriptor_disconnects_websocket_without_acknowledging_later_delta() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let applied = AppliedSessions::default();
        let (connected, mut connected_rx) = watch::channel(false);
        SubscriberFixture {
            applied: applied.clone(), connected,
            backoff: backoff(Duration::from_secs(3600), Duration::from_secs(3600)),
            ..Default::default()
        }.spawn(listener.local_addr().unwrap());
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        accept_enroll(&mut ws).await;
        ws.send(Message::Text(serde_json::to_string(&CoordinatorToRelay::Descriptors {
            ack_id: Some(1), staged_at_unix_ms: None, descriptors: vec![descriptor(1, &[])],
        }).unwrap().into())).await.unwrap();
        assert_eq!(decode(ws.next().await.unwrap().unwrap()), RelayToCoordinator::DescriptorsApplied { ack_id: 1 });
        assert!(*connected_rx.borrow_and_update());
        ws.feed(Message::Text(r#"{"type":"descriptors","ack_id":2,"descriptors":[{"session":2}]}"#.into())).await.unwrap();
        ws.feed(Message::Text(serde_json::to_string(&CoordinatorToRelay::DescriptorDelta {
            ack_id: Some(3), staged_at_unix_ms: None, upserts: vec![descriptor(3, &[])], removals: vec![],
        }).unwrap().into())).await.unwrap();
        ws.flush().await.unwrap();
        match ws.next().await {
            None | Some(Err(_)) | Some(Ok(Message::Close(_))) => {},
            other => panic!("invalid descriptor must end the connection without a later acknowledgement: {other:?}"),
        }
        connected_rx.wait_for(|connected| !*connected).await.unwrap();
        assert_eq!(applied.snapshot(), HashSet::from([key(1)]));
    }).await.expect("malformed known messages trigger a full resync by disconnecting");
}

#[tokio::test]
async fn unknown_only_stream_does_not_report_enrollment_acceptance() {
    let (connected, connected_rx) = watch::channel(false);
    let (ack, ack_rx) = watch::channel(None);
    let targets = targets();
    read_control_frames(
        futures_util::stream::iter([Ok(Message::Text(
            r#"{"type":"future_policy","ack_id":7}"#.into(),
        ))]),
        &targets,
        RelayId(1),
        routes(ack),
        ControlConnStats::new(),
        &connected,
    )
    .await
    .unwrap();
    assert!(!*connected_rx.borrow());
    assert_eq!(*ack_rx.borrow(), None);
    assert!(targets.applied.snapshot().is_empty());
}

#[tokio::test]
async fn malformed_descriptor_ends_reader_before_later_delta_is_acknowledged() {
    for malformed in [
        serde_json::json!({"type":"descriptors", "ack_id":2, "descriptors":[{"session":2}]}),
        serde_json::json!({"type":"descriptor_delta", "ack_id":2, "removals":"invalid"}),
        serde_json::json!({"ack_id":2, "descriptors":[]}),
    ] {
        let targets = targets();
        let (ack, ack_rx) = watch::channel(None);
        let (connected, connected_rx) = watch::channel(false);
        let initial = CoordinatorToRelay::Descriptors {
            ack_id: Some(1),
            staged_at_unix_ms: None,
            descriptors: vec![descriptor(1, &[])],
        };
        let later = CoordinatorToRelay::DescriptorDelta {
            ack_id: Some(3),
            staged_at_unix_ms: None,
            upserts: vec![descriptor(3, &[])],
            removals: vec![],
        };
        let frames = [
            serde_json::to_value(initial).unwrap(),
            malformed,
            serde_json::to_value(later).unwrap(),
        ]
        .into_iter()
        .map(|value| Ok(Message::Text(value.to_string().into())));
        let result = read_control_frames(
            futures_util::stream::iter(frames),
            &targets,
            RelayId(1),
            routes(ack),
            ControlConnStats::new(),
            &connected,
        )
        .await;
        assert!(matches!(result, Err(ControlError::Decode(_))));
        assert_eq!(*ack_rx.borrow(), Some(1));
        assert_eq!(targets.applied.snapshot(), HashSet::from([key(1)]));
        // The connection owner clears the signal when the reader returns.
        assert!(*connected_rx.borrow());
    }
}

fn targets() -> ControlApplyTargets {
    ControlApplyTargets {
        control: control(),
        applied: AppliedSessions::default(),
        fleet: FleetMeshPeers::default(),
        verifying_keys: SharedRegistry::default(),
        region_targets: RegionPingTargets::default(),
        drain_acked: watch::channel(false).0,
        retired: watch::channel(false).0,
    }
}

fn routes(descriptor_ack_tx: watch::Sender<Option<u64>>) -> ReaderRoutes {
    ReaderRoutes {
        challenge_tx: mpsc::unbounded_channel().0,
        flight_grant_tx: mpsc::unbounded_channel().0,
        load_state_tx: mpsc::channel(LOAD_STATE_ASK_CAPACITY).0,
        descriptor_ack_tx,
    }
}
