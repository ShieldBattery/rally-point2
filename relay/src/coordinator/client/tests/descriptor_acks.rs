//! Requested installation barriers follow complete local reconciliation and stay
//! scoped to the enrolled control connection.

use super::super::reader::{ReaderRoutes, read_control_frames};
use super::*;

#[tokio::test]
async fn requested_full_and_delta_acknowledge_applied_membership() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let applied = AppliedSessions::default();
    let (control, mesh, _) = control_over_state();
    SubscriberFixture {
        control,
        applied: applied.clone(),
        ..Default::default()
    }
    .spawn(listener.local_addr().unwrap());
    let (stream, _) = listener.accept().await.unwrap();
    let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
    // The fixture requires IdentityProof before accepting any application frame.
    accept_enroll(&mut ws).await;
    for (frame, ack_id, expected) in [
        (
            CoordinatorToRelay::Descriptors {
                ack_id: Some(1),
                staged_at_unix_ms: None,
                descriptors: vec![descriptor(1, &[]), descriptor(2, &[])],
            },
            1,
            HashSet::from([key(1), key(2)]),
        ),
        (
            CoordinatorToRelay::DescriptorDelta {
                ack_id: Some(2),
                staged_at_unix_ms: None,
                upserts: vec![descriptor(3, &[])],
                removals: vec![DescriptorKey {
                    tenant: key(1).tenant,
                    session: SessionId(1),
                }],
            },
            2,
            HashSet::from([key(2), key(3)]),
        ),
        (
            CoordinatorToRelay::Descriptors {
                ack_id: Some(3),
                staged_at_unix_ms: None,
                descriptors: vec![],
            },
            3,
            HashSet::new(),
        ),
    ] {
        ws.send(Message::Text(serde_json::to_string(&frame).unwrap().into()))
            .await
            .unwrap();
        let message = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("requested installation is acknowledged")
            .unwrap()
            .unwrap();
        assert_eq!(
            decode(message),
            RelayToCoordinator::DescriptorsApplied { ack_id }
        );
        assert_eq!(applied.snapshot(), expected);
        for session in 1..=3 {
            if session == 1 && ack_id >= 2 || ack_id == 3 {
                assert!(mesh.session.gates.is_retired(&key(session)));
            }
        }
    }
}

#[tokio::test]
async fn reader_coalesces_requested_ids_and_ignores_legacy_frames() {
    let applied = AppliedSessions::default();
    let targets = ControlApplyTargets {
        control: control(),
        applied: applied.clone(),
        fleet: FleetMeshPeers::default(),
        verifying_keys: SharedRegistry::default(),
        region_targets: RegionPingTargets::default(),
        drain_acked: watch::channel(false).0,
        retired: watch::channel(false).0,
    };
    let (descriptor_ack_tx, mut descriptor_ack_rx) = watch::channel(None);
    for (ids, expected) in [
        (vec![None, None], None),
        (vec![Some(1), Some(2), None, Some(3)], Some(3)),
    ] {
        let frames = ids.into_iter().map(|ack_id| {
            Ok(Message::Text(
                serde_json::to_string(&CoordinatorToRelay::Descriptors {
                    ack_id,
                    staged_at_unix_ms: None,
                    descriptors: vec![descriptor(1, &[])],
                })
                .unwrap()
                .into(),
            ))
        });
        read_control_frames(
            futures_util::stream::iter(frames),
            &targets,
            RelayId(1),
            ReaderRoutes {
                challenge_tx: mpsc::unbounded_channel().0,
                flight_grant_tx: mpsc::unbounded_channel().0,
                load_state_tx: mpsc::channel(LOAD_STATE_ASK_CAPACITY).0,
                descriptor_ack_tx: descriptor_ack_tx.clone(),
            },
            ControlConnStats::new(),
            &no_connected(),
        )
        .await
        .unwrap();
        assert_eq!(*descriptor_ack_rx.borrow_and_update(), expected);
        assert!(!descriptor_ack_rx.has_changed().unwrap());
        assert_eq!(applied.snapshot(), HashSet::from([key(1)]));
    }
}

#[tokio::test]
async fn writer_emits_only_the_latest_requested_acknowledgement() {
    let (recorded, mut frames) = mpsc::unbounded_channel();
    let sink = Box::pin(futures_util::sink::unfold((), move |(), frame| {
        recorded.send(frame).unwrap();
        std::future::ready(Ok::<_, tokio_tungstenite::tungstenite::Error>(()))
    }));
    let (ack_tx, ack_rx) = watch::channel(None);
    let (challenge_tx, challenge_rx) = mpsc::unbounded_channel();
    let mut outbound = OutboundQueues::new(
        mpsc::unbounded_channel().1,
        no_flight(),
        ControlConnStats::new(),
    );
    let mut drain = watch::channel(false).1;
    let heartbeat = heartbeat(Duration::from_secs(3600));
    let identity_key = throwaway_identity_key();
    let writer = write_control_frames(
        sink,
        &mut outbound,
        &mut drain,
        &heartbeat,
        &identity_key,
        RelayId(1),
        WriterRoutes {
            challenge_rx,
            flight_grant_rx: mpsc::unbounded_channel().1,
            load_state_rx: mpsc::channel(LOAD_STATE_ASK_CAPACITY).1,
            descriptor_ack_rx: ack_rx,
        },
    );
    tokio::pin!(writer);
    // An answered challenge proves the writer reached its steady-state loop;
    // its initial interval tick can legitimately be Pending on the first poll.
    challenge_tx.send([7; 32]).unwrap();
    let proof = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            frame = frames.recv() => frame.expect("the writer keeps its sink"),
            _ = writer.as_mut() => panic!("the writer stays connected"),
        }
    })
    .await
    .expect("the writer answers the routed challenge");
    assert!(matches!(
        decode(proof),
        RelayToCoordinator::IdentityProof { .. }
    ));
    // No request means no unsolicited frame to an older coordinator.
    assert!(futures_util::poll!(writer.as_mut()).is_pending());
    assert!(frames.try_recv().is_err());
    // Both applies complete before the writer is polled again.
    ack_tx.send_replace(Some(1));
    ack_tx.send_replace(Some(2));
    let ack = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            frame = frames.recv() => frame.expect("the writer keeps its sink"),
            _ = writer.as_mut() => panic!("the writer stays connected"),
        }
    })
    .await
    .expect("the writer sends the latest installation acknowledgement");
    assert_eq!(
        decode(ack),
        RelayToCoordinator::DescriptorsApplied { ack_id: 2 }
    );
    assert!(frames.try_recv().is_err());
}
