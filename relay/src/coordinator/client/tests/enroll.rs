//! Enrollment ordering and its outcome signal: the identity proof is the first
//! frame after the challenge whatever else is queued, and only a post-proof
//! application push reports the control connection connected.

use super::*;

#[tokio::test]
async fn the_enroll_proof_precedes_a_pending_notice_and_a_drain() {
    use tokio::net::TcpListener;

    // The coordinator sends the IdentityChallenge as the first post-Hello
    // frame and reads exactly one frame back expecting the IdentityProof. A
    // relay that reconnects with a queued notice AND mid-drain would, without
    // an enroll handshake that completes first, send that notice (or the
    // Draining) ahead of the proof and be refused. This asserts the proof is
    // the first frame after the challenge, with the notice and Draining
    // strictly behind it.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        // Read the Hello, then challenge and read the very next frame — the
        // proof must be it, ahead of the queued notice and the drain re-assert.
        let hello = ws.next().await.unwrap().unwrap();
        let Message::Text(hello) = hello else {
            panic!("first frame is the Hello");
        };
        assert!(hello.contains("\"type\":\"hello\""));
        let challenge =
            serde_json::to_string(&CoordinatorToRelay::IdentityChallenge { nonce: [7u8; 32] })
                .unwrap();
        ws.send(Message::Text(challenge.into())).await.unwrap();

        // Capture the next three frames in wire order: proof, then the notice
        // and the Draining (in whichever order the relay flushes them).
        let first = ws.next().await.unwrap().unwrap();
        let second = ws.next().await.unwrap().unwrap();
        let third = ws.next().await.unwrap().unwrap();
        let _ = frames_tx.send((first, second, third));
    });

    // Queue a notice AND set the relay mid-drain before it starts, so both
    // would race the proof if enrollment did not complete first.
    let (notices_tx, notices_rx) = mpsc::unbounded_channel();
    notices_tx
        .send(RelayNotice::Departure(dropped_notice()))
        .unwrap();
    let (_drain_tx, drain_rx) = watch::channel(true);
    let (drain_acked_tx, _drain_acked_rx) = watch::channel(false);

    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    tokio::spawn(run_descriptor_subscriber_with(
        enroll(addr, drain_hello()),
        apply_targets(control, drain_acked_tx),
        OutboundQueues::new(notices_rx, no_flight(), ControlConnStats::new()),
        heartbeat(Duration::from_secs(3600)), // no heartbeat during the test
        drain_rx,
        no_connected(),
        backoff(Duration::from_millis(20), Duration::from_secs(60)),
    ));

    let (first, second, third) = tokio::time::timeout(Duration::from_secs(5), frames_rx)
        .await
        .expect("the relay sends the proof then the queued frames")
        .unwrap();

    let decode = |message: Message| -> RelayToCoordinator {
        let Message::Text(text) = message else {
            panic!("a text frame");
        };
        serde_json::from_str(&text).unwrap()
    };

    assert!(
        matches!(decode(first), RelayToCoordinator::IdentityProof { .. }),
        "the identity proof must be the first frame after the challenge",
    );
    let rest = [decode(second), decode(third)];
    assert!(
        rest.contains(&RelayToCoordinator::Departure(dropped_notice())),
        "the queued notice goes out only after the proof",
    );
    assert!(
        rest.contains(&RelayToCoordinator::Draining),
        "the drain re-assert goes out only after the proof",
    );
}

// --- Control-connected reporting ---

#[tokio::test]
async fn an_enroll_refused_after_the_proof_never_reports_control_connected() {
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Stand-in coordinator: accept, complete the enroll challenge/proof, then
    // refuse the enrollment with the ledger-unauthorized close — the refusal
    // that lands only AFTER the proof round trip, so it exercises the path
    // where an application frame could otherwise be mistaken for acceptance.
    // No application frame is ever pushed, so the connection must never report
    // connected.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _hello = accept_enroll(&mut ws).await;
        let _ = ws
            .close(Some(CloseFrame {
                code: CloseCode::from(CONTROL_CLOSE_ENROLL_UNAUTHORIZED),
                reason: "not authorized by the ledger".into(),
            }))
            .await;
        while let Some(Ok(_)) = ws.next().await {}
    });

    let (connected_tx, mut connected_rx) = watch::channel(false);
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
        heartbeat(Duration::from_secs(3600)),
        drain_rx,
        connected_tx,
        // A long refusal backoff so the relay does not redial and re-drive the
        // handshake during the observation window (an enroll-unauthorized close
        // takes the refusal backoff).
        backoff(Duration::from_millis(20), Duration::from_secs(3600)),
    ));

    // Actively wait for connected to flip true across the whole attempt; the
    // wait must time out, since a post-proof refusal never pushes the
    // application frame that would report it.
    let observed = tokio::time::timeout(
        Duration::from_millis(500),
        connected_rx.wait_for(|connected| *connected),
    )
    .await;
    assert!(
        observed.is_err(),
        "a post-proof enroll refusal must never report the control connection connected",
    );
}

#[tokio::test]
async fn a_post_proof_application_frame_reports_control_connected() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Stand-in coordinator: accept, complete the enroll handshake, then push a
    // TenantKeys frame — the connect-time application frame an accepted enroll
    // always leads with. Hold the connection open so the relay does not redial.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _hello = accept_enroll(&mut ws).await;
        let keys = serde_json::to_string(&CoordinatorToRelay::TenantKeys { keys: vec![] }).unwrap();
        ws.send(Message::Text(keys.into())).await.unwrap();
        std::future::pending::<()>().await;
    });

    let (connected_tx, mut connected_rx) = watch::channel(false);
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
        heartbeat(Duration::from_secs(3600)),
        drain_rx,
        connected_tx,
        backoff(Duration::from_millis(20), Duration::from_secs(60)),
    ));

    // The relay reports connected once it reads the first post-proof
    // application frame (the TenantKeys push).
    tokio::time::timeout(
        Duration::from_secs(5),
        connected_rx.wait_for(|connected| *connected),
    )
    .await
    .expect("the relay reports the control connection connected on the first push")
    .unwrap();
}

#[tokio::test]
async fn the_enroll_proof_precedes_a_pending_flight_request() {
    use tokio::net::TcpListener;

    // A relay that reconnects with a parked flight shipment must send its
    // IdentityProof first: an upload-request frame ahead of the proof would be read
    // as the proof and refused. Assert the proof is the first frame after the
    // challenge, with the request strictly behind it.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let hello = ws.next().await.unwrap().unwrap();
        let Message::Text(hello) = hello else {
            panic!("first frame is the Hello");
        };
        assert!(hello.contains("\"type\":\"hello\""));
        let challenge =
            serde_json::to_string(&CoordinatorToRelay::IdentityChallenge { nonce: [7u8; 32] })
                .unwrap();
        ws.send(Message::Text(challenge.into())).await.unwrap();
        let first = ws.next().await.unwrap().unwrap();
        let second = ws.next().await.unwrap().unwrap();
        let _ = frames_tx.send((first, second));
    });

    let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let (shipment, _ack) = flight_shipment();
    flight_tx.try_send(shipment).unwrap();

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
            flight_rx,
            ControlConnStats::new(),
        ),
        heartbeat(Duration::from_secs(3600)),
        drain_rx,
        no_connected(),
        backoff(Duration::from_millis(20), Duration::from_secs(60)),
    ));

    let (first, second) = tokio::time::timeout(Duration::from_secs(5), frames_rx)
        .await
        .expect("the relay sends the proof then the shipment")
        .unwrap();
    let decode = |message: Message| -> RelayToCoordinator {
        let Message::Text(text) = message else {
            panic!("a text frame");
        };
        serde_json::from_str(&text).unwrap()
    };
    assert!(
        matches!(decode(first), RelayToCoordinator::IdentityProof { .. }),
        "the identity proof precedes the flight upload request",
    );
    assert!(
        matches!(
            decode(second),
            RelayToCoordinator::FlightUploadRequest { .. }
        ),
        "the flight upload request goes out only after the proof",
    );
}
