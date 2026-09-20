//! Enrollment ordering and its outcome signal: the identity proof is the first
//! frame after the challenge whatever else is queued, and only a post-proof
//! application push reports the control connection connected.

use super::*;

#[tokio::test]
async fn the_enroll_proof_precedes_every_kind_of_parked_work() {
    use tokio::net::TcpListener;

    // The coordinator sends the IdentityChallenge as the first post-Hello frame
    // and reads exactly one frame back expecting the IdentityProof. A relay that
    // reconnects with a queued notice, mid-drain, and holding a parked flight
    // shipment would, without an enroll handshake that completes first, send one
    // of those ahead of the proof and be refused — and a pending notice survives
    // reconnects, so that locks the relay out permanently. This asserts the proof
    // is the first frame after the challenge, with all three strictly behind it.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        // Read the Hello, then challenge and read the very next frame — the
        // proof must be it, ahead of everything the relay has parked.
        let hello = ws.next().await.unwrap().unwrap();
        let Message::Text(hello) = hello else {
            panic!("first frame is the Hello");
        };
        assert!(hello.contains("\"type\":\"hello\""));
        let challenge =
            serde_json::to_string(&CoordinatorToRelay::IdentityChallenge { nonce: [7u8; 32] })
                .unwrap();
        ws.send(Message::Text(challenge.into())).await.unwrap();

        // Capture the next four frames in wire order: the proof, then the
        // notice, the Draining and the upload request in whichever order the
        // relay flushes them.
        let mut frames = Vec::new();
        for _ in 0..4 {
            frames.push(ws.next().await.unwrap().unwrap());
        }
        let _ = frames_tx.send(frames);
    });

    // Queue a notice, set the relay mid-drain, and park a flight shipment before
    // it starts, so all three would race the proof if enrollment did not
    // complete first.
    let (notices_tx, notices) = mpsc::unbounded_channel();
    notices_tx
        .send(RelayNotice::Departure(dropped_notice()))
        .unwrap();
    let (flight_tx, flight) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let (shipment, _ack) = flight_shipment();
    flight_tx.try_send(shipment).unwrap();
    let (_drain_tx, drain) = watch::channel(true);

    SubscriberFixture {
        notices,
        flight,
        drain,
        ..Default::default()
    }
    .spawn(addr);

    let frames = tokio::time::timeout(Duration::from_secs(5), frames_rx)
        .await
        .expect("the relay sends the proof then the queued frames")
        .unwrap();
    let mut frames = frames.into_iter().map(decode);

    assert!(
        matches!(
            frames.next().unwrap(),
            RelayToCoordinator::IdentityProof { .. },
        ),
        "the identity proof must be the first frame after the challenge",
    );
    let rest: Vec<RelayToCoordinator> = frames.collect();
    assert!(
        rest.contains(&RelayToCoordinator::Departure(dropped_notice())),
        "the queued notice goes out only after the proof: {rest:?}",
    );
    assert!(
        rest.contains(&RelayToCoordinator::Draining),
        "the drain re-assert goes out only after the proof: {rest:?}",
    );
    assert!(
        rest.iter()
            .any(|frame| matches!(frame, RelayToCoordinator::FlightUploadRequest { .. })),
        "the flight upload request goes out only after the proof: {rest:?}",
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

    let (connected, mut connected_rx) = watch::channel(false);
    SubscriberFixture {
        connected,
        // A long refusal backoff so the relay does not redial and re-drive the
        // handshake during the observation window (an enroll-unauthorized close
        // takes the refusal backoff).
        backoff: backoff(Duration::from_millis(20), Duration::from_secs(3600)),
        ..Default::default()
    }
    .spawn(addr);

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

    let (connected, mut connected_rx) = watch::channel(false);
    SubscriberFixture {
        connected,
        ..Default::default()
    }
    .spawn(addr);

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
