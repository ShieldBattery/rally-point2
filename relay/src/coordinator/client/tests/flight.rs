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
        let RelayToCoordinator::FlightUploadRequest {
            request,
            session,
            bytes,
            ..
        } = decode(request)
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

    let (flight_tx, flight) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let (shipment, ack) = flight_shipment();
    flight_tx.try_send(shipment).unwrap();

    SubscriberFixture {
        flight,
        ..Default::default()
    }
    .spawn(addr);

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
    assert!(
        matches!(decode(done), RelayToCoordinator::FlightUploadDone { .. }),
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
        let RelayToCoordinator::FlightUploadRequest { request, .. } = decode(first) else {
            panic!("the frame is an upload request");
        };
        let refused =
            serde_json::to_string(&CoordinatorToRelay::FlightUploadRefused { request }).unwrap();
        ws.send(Message::Text(refused.into())).await.unwrap();

        // The other shipment's request is already on the wire (both ship at once).
        let second = ws.next().await.unwrap().unwrap();
        let _ = second_tx.send((request, second));
        // Hold the connection open so the relay drops the refused recording on it,
        // rather than the read half ending the connection first (which would
        // re-request the shipment on the next connection instead of dropping it).
        std::future::pending::<()>().await;
    });

    let (flight_tx, flight) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let (first_shipment, first_ack) = flight_shipment();
    let (second_shipment, _second_ack) =
        flight_shipment_with_payload(Bytes::from_static(b"second-blob"));
    flight_tx.try_send(first_shipment).unwrap();
    flight_tx.try_send(second_shipment).unwrap();

    SubscriberFixture {
        flight,
        ..Default::default()
    }
    .spawn(addr);

    // The refused recording's ack resolves as not-stored (the sender is dropped).
    assert!(
        tokio::time::timeout(Duration::from_secs(5), first_ack)
            .await
            .expect("the ack resolves promptly")
            .is_err(),
        "a refused upload reports the recording lost, not stored",
    );

    // The other shipment's request went out too — it ships concurrently rather
    // than waiting for the first to resolve, under its own correlation id.
    let (first_request, second) = tokio::time::timeout(Duration::from_secs(5), second_rx)
        .await
        .expect("the second request arrives")
        .unwrap();
    let RelayToCoordinator::FlightUploadRequest {
        request: second_request,
        bytes,
        ..
    } = decode(second)
    else {
        panic!("the frame is an upload request");
    };
    assert_eq!(
        bytes,
        "second-blob".len() as u64,
        "the other shipment's request is in flight alongside the refused one",
    );
    assert_ne!(
        first_request, second_request,
        "each in-flight shipment carries a distinct correlation id",
    );
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

    let (flight_tx, flight) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let (shipment, _ack) = flight_shipment();
    flight_tx.try_send(shipment).unwrap();

    // The shared applied set the read half reconciles is the observable.
    let applied = AppliedSessions::new();
    SubscriberFixture {
        applied: applied.clone(),
        flight,
        ..Default::default()
    }
    .spawn(addr);

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

    let (flight_tx, flight) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let (first_shipment, _first_ack) = flight_shipment();
    let (second_shipment, _second_ack) =
        flight_shipment_with_payload(Bytes::from_static(b"second-blob"));
    flight_tx.try_send(first_shipment).unwrap();
    flight_tx.try_send(second_shipment).unwrap();

    SubscriberFixture {
        flight,
        ..Default::default()
    }
    .spawn(addr);

    let (re1, re2) = tokio::time::timeout(Duration::from_secs(5), frames_rx)
        .await
        .expect("both shipments re-request after the reconnect")
        .unwrap();
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

// --- The write half's flight bookkeeping, driven without a socket ---

/// A sink that accepts every frame and keeps it, so a test can drive the write
/// half directly and read what went out. Carries the WebSocket's error type, so
/// the generic bound is satisfied exactly as a live socket satisfies it.
fn recording_sink() -> (
    impl futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    std::sync::Arc<std::sync::Mutex<Vec<Message>>>,
) {
    let frames: std::sync::Arc<std::sync::Mutex<Vec<Message>>> = Default::default();
    let for_sink = std::sync::Arc::clone(&frames);
    let sink = Box::pin(futures_util::sink::unfold(
        (),
        move |(), message: Message| {
            let for_sink = std::sync::Arc::clone(&for_sink);
            async move {
                for_sink.lock().unwrap().push(message);
                Ok::<(), tokio_tungstenite::tungstenite::Error>(())
            }
        },
    ));
    (sink, frames)
}

/// Everything `write_control_frames` needs besides the shipments under test:
/// live senders for the drain, challenge, grant and load-state routes, so those
/// arms stay pending rather than disabling themselves.
struct WriterHarness {
    drain: watch::Receiver<bool>,
    heartbeat: HeartbeatConfig,
    identity_key: PrivateKeyDer<'static>,
    grants: mpsc::UnboundedSender<FlightGrant>,
    routes: Option<WriterRoutes>,
    _keepalive: (
        watch::Sender<bool>,
        mpsc::UnboundedSender<[u8; 32]>,
        mpsc::Sender<LoadStateAsk>,
    ),
}

impl WriterHarness {
    fn new() -> Self {
        let (drain_tx, drain) = watch::channel(false);
        let (challenge_tx, challenge_rx) = mpsc::unbounded_channel::<[u8; 32]>();
        let (grants, flight_grant_rx) = mpsc::unbounded_channel::<FlightGrant>();
        let (load_state_tx, load_state_rx) = mpsc::channel::<LoadStateAsk>(LOAD_STATE_ASK_CAPACITY);
        Self {
            drain,
            heartbeat: heartbeat(Duration::from_secs(3600)),
            identity_key: throwaway_identity_key(),
            grants,
            routes: Some(WriterRoutes {
                challenge_rx,
                flight_grant_rx,
                load_state_rx,
            }),
            _keepalive: (drain_tx, challenge_tx, load_state_tx),
        }
    }
}

#[tokio::test]
async fn a_shipment_with_no_grant_in_time_is_dropped() {
    // A coordinator that never answers — including an older one that decodes the
    // request as an unknown frame and silently drops it — must not wedge the
    // pipe: every shipment whose grant deadline passed is dropped and its
    // recording reported lost. Both go at once, so the sweep's swap-and-recheck
    // (the last entry lands in the freed index) is exercised rather than one
    // entry being skipped.
    let (flight_tx, flight) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let (first, first_ack) = flight_shipment();
    let (second, second_ack) = flight_shipment_with_payload(Bytes::from_static(b"second-blob"));
    flight_tx.try_send(first).unwrap();
    flight_tx.try_send(second).unwrap();

    let mut harness = WriterHarness::new();
    let mut outbound =
        OutboundQueues::new(mpsc::unbounded_channel().1, flight, ControlConnStats::new())
            .with_grant_timeout(Duration::from_millis(30));
    let (sink, frames) = recording_sink();

    let writer = write_control_frames(
        sink,
        &mut outbound,
        &mut harness.drain,
        &harness.heartbeat,
        &harness.identity_key,
        RelayId(1),
        harness.routes.take().expect("the routes are taken once"),
    );
    // The write half runs until its connection ends, so bound it: long enough
    // for both requests to go out and both grant deadlines to pass.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), writer)
            .await
            .is_err(),
        "the write half keeps running after dropping the recordings",
    );

    assert_eq!(
        frames.lock().unwrap().len(),
        2,
        "both upload requests went out before either deadline passed",
    );
    assert!(
        outbound.pending_flights.is_empty(),
        "an elapsed grant wait drops every shipment still waiting, not just one",
    );
    assert_eq!(
        outbound.stats.snapshot().flights,
        0,
        "the reported in-flight depth falls back to zero",
    );
    assert!(
        first_ack.await.is_err() && second_ack.await.is_err(),
        "both recordings report lost rather than stored",
    );
}

#[tokio::test]
async fn no_more_than_the_capped_number_of_shipments_are_in_flight_at_once() {
    // Five queued shipments, a cap of four: the fifth waits in the channel until
    // a seat frees, which is what keeps a teardown burst from turning a
    // background pipe into a bandwidth spike.
    let (flight_tx, flight) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let mut acks = Vec::new();
    for index in 0..MAX_INFLIGHT_FLIGHT_UPLOADS + 1 {
        let (shipment, ack) = flight_shipment_with_payload(Bytes::from(format!("blob-{index}")));
        flight_tx.try_send(shipment).unwrap();
        acks.push(ack);
    }

    let mut harness = WriterHarness::new();
    let mut outbound =
        OutboundQueues::new(mpsc::unbounded_channel().1, flight, ControlConnStats::new());
    let (sink, frames) = recording_sink();
    let grants = harness.grants.clone();

    let writer = write_control_frames(
        sink,
        &mut outbound,
        &mut harness.drain,
        &harness.heartbeat,
        &harness.identity_key,
        RelayId(1),
        harness.routes.take().expect("the routes are taken once"),
    );

    let drive = async {
        // Wait for the cap to fill, then hold still briefly: a missing cap would
        // pull the fifth shipment on the very next turn of the loop, so a short
        // window is enough to tell "waiting for a seat" from "about to go out".
        while frames.lock().unwrap().len() < MAX_INFLIGHT_FLIGHT_UPLOADS {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        let requested: Vec<u64> = frames
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .map(|frame| match decode(frame) {
                RelayToCoordinator::FlightUploadRequest { request, .. } => request,
                other => panic!("every frame is an upload request, got {other:?}"),
            })
            .collect();
        assert_eq!(
            requested.len(),
            MAX_INFLIGHT_FLIGHT_UPLOADS,
            "the fifth shipment stays queued while the cap is full",
        );

        // Refusing one frees its seat, and the fifth request goes out.
        grants
            .send(FlightGrant::Refused {
                request: requested[0],
            })
            .unwrap();
        while frames.lock().unwrap().len() <= MAX_INFLIGHT_FLIGHT_UPLOADS {
            tokio::task::yield_now().await;
        }
    };

    tokio::select! {
        _ = writer => panic!("the write half runs until its connection ends"),
        () = drive => {}
    }
}
