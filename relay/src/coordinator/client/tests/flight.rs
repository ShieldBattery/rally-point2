//! Flight-recording uploads: the request/grant/PUT/done cycle, the concurrency
//! cap in action, and what a refusal or a connection death does to a parked
//! shipment.

use super::*;

// --- Flight recording uploads ---

/// A minimal in-process object store: an HTTP server that records every request's
/// method and exact body and answers 200, standing in for the presigned-URL target
/// a relay PUTs a recording to. Returns its base URL and the receive end of the
/// recorded requests.
async fn spawn_object_store() -> (String, mpsc::UnboundedReceiver<(String, Vec<u8>)>) {
    use tokio::net::TcpListener;
    let (put_tx, put_rx) = mpsc::unbounded_channel::<(String, Vec<u8>)>();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app =
        axum::Router::new().fallback(move |method: axum::http::Method, body: axum::body::Bytes| {
            let put_tx = put_tx.clone();
            async move {
                let _ = put_tx.send((method.to_string(), body.to_vec()));
                axum::http::StatusCode::OK
            }
        });
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/desync/sb-test/7/1.json.zst"), put_rx)
}

#[tokio::test]
async fn a_flight_recording_uploads_to_the_store_then_reports_done() {
    use tokio::net::TcpListener;

    // The object store the relay PUTs the compressed recording to.
    let (store_url, mut store_puts) = spawn_object_store().await;

    // The stand-in coordinator: enroll, read the upload request, grant the store
    // URL, then read the Done the relay sends after a successful PUT.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _hello = accept_enroll(&mut ws).await;

        let request = ws.next().await.unwrap().unwrap();
        let Message::Text(text) = request else {
            panic!("a text frame");
        };
        let RelayToCoordinator::FlightUploadRequest {
            request,
            session,
            bytes,
            ..
        } = serde_json::from_str(&text).unwrap()
        else {
            panic!("the frame is an upload request");
        };
        assert_eq!(session, SessionId(7));
        // The request carries the exact compressed byte count, not the blob.
        assert_eq!(bytes, "compressed-bytes".len() as u64);

        let grant = serde_json::to_string(&CoordinatorToRelay::FlightUploadGrant {
            request,
            url: store_url,
        })
        .unwrap();
        ws.send(Message::Text(grant.into())).await.unwrap();

        let done = ws.next().await.unwrap().unwrap();
        let _ = done_tx.send(done);
    });

    let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let (shipment, ack) = flight_shipment();
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

    // The store received a PUT of exactly the compressed bytes.
    let (method, body) = tokio::time::timeout(Duration::from_secs(5), store_puts.recv())
        .await
        .expect("the store received the upload")
        .expect("a PUT arrived");
    assert_eq!(method, "PUT", "the recording is uploaded with PUT");
    assert_eq!(
        body, b"compressed-bytes",
        "the exact compressed bytes are stored"
    );

    // The ack resolves only after the object is stored (delivery means stored).
    tokio::time::timeout(Duration::from_secs(5), ack)
        .await
        .expect("the ack resolves after storage")
        .unwrap();

    // The relay reports Done, and only after the successful PUT.
    let done = tokio::time::timeout(Duration::from_secs(5), done_rx)
        .await
        .expect("a done frame is sent")
        .unwrap();
    let Message::Text(text) = done else {
        panic!("a text frame");
    };
    assert!(
        matches!(
            serde_json::from_str::<RelayToCoordinator>(&text).unwrap(),
            RelayToCoordinator::FlightUploadDone { .. },
        ),
        "the relay reports the upload done",
    );
}

#[tokio::test]
async fn a_refused_upload_drops_its_recording_while_the_other_stays_in_flight() {
    use tokio::net::TcpListener;

    // The stand-in coordinator refuses the FIRST request, reads the second (both
    // are in flight at once), and holds the connection open so the relay processes
    // the refusal on it rather than re-requesting on a reconnect.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (second_tx, second_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _hello = accept_enroll(&mut ws).await;

        let first = ws.next().await.unwrap().unwrap();
        let Message::Text(text) = first else {
            panic!("a text frame");
        };
        let RelayToCoordinator::FlightUploadRequest { request, .. } =
            serde_json::from_str(&text).unwrap()
        else {
            panic!("the frame is an upload request");
        };
        let refused =
            serde_json::to_string(&CoordinatorToRelay::FlightUploadRefused { request }).unwrap();
        ws.send(Message::Text(refused.into())).await.unwrap();

        // The other shipment's request is already on the wire (both ship at once).
        let second = ws.next().await.unwrap().unwrap();
        let _ = second_tx.send(second);
        // Hold the connection open so the relay drops the refused recording on it,
        // rather than the read half ending the connection first (which would
        // re-request the shipment on the next connection instead of dropping it).
        std::future::pending::<()>().await;
    });

    let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let (first_shipment, first_ack) = flight_shipment();
    let (second_shipment, _second_ack) =
        flight_shipment_with_payload(Bytes::from_static(b"second-blob"));
    flight_tx.try_send(first_shipment).unwrap();
    flight_tx.try_send(second_shipment).unwrap();

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

    // The refused recording's ack resolves as not-stored (the sender is dropped).
    assert!(
        tokio::time::timeout(Duration::from_secs(5), first_ack)
            .await
            .expect("the ack resolves promptly")
            .is_err(),
        "a refused upload reports the recording lost, not stored",
    );

    // The other shipment's request went out too — it ships concurrently rather
    // than waiting for the first to resolve.
    let second = tokio::time::timeout(Duration::from_secs(5), second_rx)
        .await
        .expect("the second request arrives")
        .unwrap();
    let Message::Text(text) = second else {
        panic!("a text frame");
    };
    let RelayToCoordinator::FlightUploadRequest { bytes, .. } =
        serde_json::from_str(&text).unwrap()
    else {
        panic!("the frame is an upload request");
    };
    assert_eq!(
        bytes,
        "second-blob".len() as u64,
        "the other shipment's request is in flight alongside the refused one",
    );
}

#[tokio::test]
async fn a_queued_flight_shipment_is_delivered_after_a_reconnect() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (frame_tx, frame_rx) = tokio::sync::oneshot::channel();

    // Stand-in coordinator: drop the first dial mid-handshake so the relay
    // redials without touching the flight channel, then enroll and read the
    // shipment on the second connection.
    tokio::spawn(async move {
        let (first, _) = listener.accept().await.unwrap();
        drop(first);
        let (second, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(second).await.unwrap();
        let hello = accept_enroll(&mut ws).await;
        let Message::Text(hello) = hello else {
            panic!("first frame is the Hello");
        };
        assert!(hello.contains("\"type\":\"hello\""));
        let frame = ws.next().await.unwrap().unwrap();
        let _ = frame_tx.send(frame);
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

    let received = tokio::time::timeout(Duration::from_secs(5), frame_rx)
        .await
        .expect("the queued shipment re-requests after the reconnect")
        .unwrap();
    let Message::Text(text) = received else {
        panic!("a text frame");
    };
    // The shipment parked when the first connection died re-requests an upload URL
    // on the next connection — its small request, not the blob.
    assert!(matches!(
        serde_json::from_str::<RelayToCoordinator>(&text).unwrap(),
        RelayToCoordinator::FlightUploadRequest { .. },
    ));
}

#[tokio::test]
async fn the_read_half_applies_a_descriptor_while_an_upload_awaits_its_grant() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Stand-in coordinator: enroll, read the flight upload request but grant
    // nothing, then push a descriptor set and hold the connection open. The relay's
    // write half is parked awaiting the grant, so its read half must still apply
    // the descriptor — if reads were coupled to the writer's flight work, the
    // descriptor would never land and the applied set would stay empty.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _hello = accept_enroll(&mut ws).await;
        // Read (and never answer) the upload request.
        let _request = ws.next().await.unwrap().unwrap();
        let descriptors = serde_json::to_string(&CoordinatorToRelay::Descriptors {
            descriptors: vec![descriptor(1, &[])],
            staged_at_unix_ms: None,
        })
        .unwrap();
        ws.send(Message::Text(descriptors.into())).await.unwrap();
        std::future::pending::<()>().await;
    });

    let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let (shipment, _ack) = flight_shipment();
    flight_tx.try_send(shipment).unwrap();

    // The shared applied set the read half reconciles is the observable.
    let applied = AppliedSessions::new();
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let (drain_rx, drain_acked) = no_drain();
    tokio::spawn(run_descriptor_subscriber_with(
        enroll(addr, drain_hello()),
        ControlApplyTargets {
            control,
            applied: applied.clone(),
            fleet: FleetMeshPeers::default(),
            verifying_keys: SharedRegistry::default(),
            region_targets: RegionPingTargets::default(),
            drain_acked,
        },
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

    // The read half applies the pushed descriptor even though the write half is
    // still waiting for the upload grant.
    let landed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if applied.snapshot().contains(&key(1)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        landed.is_ok(),
        "the read half applied the descriptor while an upload awaited its grant",
    );
}

#[tokio::test]
async fn two_shipments_ship_concurrently_rather_than_one_at_a_time() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

    // Stand-in coordinator: enroll, then read TWO upload requests without granting
    // either. A strictly serial pipe would not send the second request until the
    // first shipment's whole grant→PUT→Done cycle finished, so reading both — with
    // no grant sent — proves the two proceed concurrently.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _hello = accept_enroll(&mut ws).await;
        let first = ws.next().await.unwrap().unwrap();
        let second = ws.next().await.unwrap().unwrap();
        let _ = frames_tx.send((first, second));
    });

    let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let (first_shipment, _first_ack) = flight_shipment();
    let (second_shipment, _second_ack) =
        flight_shipment_with_payload(Bytes::from_static(b"second-blob"));
    flight_tx.try_send(first_shipment).unwrap();
    flight_tx.try_send(second_shipment).unwrap();

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
        .expect("both upload requests go out before either is granted")
        .unwrap();
    let decode = |message: Message| -> RelayToCoordinator {
        let Message::Text(text) = message else {
            panic!("a text frame");
        };
        serde_json::from_str(&text).unwrap()
    };
    let mut requests = Vec::new();
    let mut byte_counts = HashSet::new();
    for frame in [decode(first), decode(second)] {
        let RelayToCoordinator::FlightUploadRequest { request, bytes, .. } = frame else {
            panic!("both frames are flight upload requests, got {frame:?}");
        };
        requests.push(request);
        byte_counts.insert(bytes);
    }
    assert_ne!(
        requests[0], requests[1],
        "each in-flight shipment carries a distinct correlation id",
    );
    assert_eq!(
        byte_counts,
        HashSet::from(["compressed-bytes".len() as u64, "second-blob".len() as u64,]),
        "both shipments' requests are on the wire at once",
    );
}

#[tokio::test]
async fn a_connection_death_re_requests_every_in_flight_shipment() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

    // Stand-in coordinator: on the FIRST connection, enroll and read both upload
    // requests (granting neither), then drop the socket with both shipments still
    // in flight. On the SECOND (reconnect), enroll and read both re-requests —
    // proving a connection death re-requests BOTH parked shipments, not just one.
    tokio::spawn(async move {
        let (first, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(first).await.unwrap();
        let _hello = accept_enroll(&mut ws).await;
        let _r1 = ws.next().await.unwrap().unwrap();
        let _r2 = ws.next().await.unwrap().unwrap();
        drop(ws);

        let (second, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(second).await.unwrap();
        let _hello = accept_enroll(&mut ws).await;
        let re1 = ws.next().await.unwrap().unwrap();
        let re2 = ws.next().await.unwrap().unwrap();
        let _ = frames_tx.send((re1, re2));
    });

    let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let (first_shipment, _first_ack) = flight_shipment();
    let (second_shipment, _second_ack) =
        flight_shipment_with_payload(Bytes::from_static(b"second-blob"));
    flight_tx.try_send(first_shipment).unwrap();
    flight_tx.try_send(second_shipment).unwrap();

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

    let (re1, re2) = tokio::time::timeout(Duration::from_secs(5), frames_rx)
        .await
        .expect("both shipments re-request after the reconnect")
        .unwrap();
    let decode = |message: Message| -> RelayToCoordinator {
        let Message::Text(text) = message else {
            panic!("a text frame");
        };
        serde_json::from_str(&text).unwrap()
    };
    let mut byte_counts = HashSet::new();
    for frame in [decode(re1), decode(re2)] {
        let RelayToCoordinator::FlightUploadRequest { bytes, .. } = frame else {
            panic!("both re-requests are flight upload requests, got {frame:?}");
        };
        byte_counts.insert(bytes);
    }
    assert_eq!(
        byte_counts,
        HashSet::from(["compressed-bytes".len() as u64, "second-blob".len() as u64,]),
        "the reconnect re-requests both in-flight shipments",
    );
}
