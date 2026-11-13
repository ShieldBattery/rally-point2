//! A stored recording stays parked if its completion frame cannot be sent.

use super::*;

fn sink(
    stall_done: bool,
) -> (
    impl futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    mpsc::UnboundedReceiver<Message>,
) {
    let (tx, rx) = mpsc::unbounded_channel();
    let sink = Box::pin(futures_util::sink::unfold(
        (),
        move |(), message: Message| {
            let tx = tx.clone();
            async move {
                let is_done = matches!(
                    decode(message.clone()),
                    RelayToCoordinator::FlightUploadDone { .. }
                );
                tx.send(message).unwrap();
                if stall_done && is_done {
                    std::future::pending::<()>().await;
                }
                Ok::<(), tokio_tungstenite::tungstenite::Error>(())
            }
        },
    ));
    (sink, rx)
}

fn routes() -> (WriterRoutes, mpsc::UnboundedSender<FlightGrant>) {
    let (grants, flight_grant_rx) = mpsc::unbounded_channel();
    (
        WriterRoutes {
            challenge_rx: mpsc::unbounded_channel().1,
            flight_grant_rx,
            load_state_rx: mpsc::channel(1).1,
            descriptor_ack_rx: watch::channel(None).1,
        },
        grants,
    )
}

#[tokio::test]
async fn canceled_completion_remains_parked_and_retries_on_the_next_connection() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let url = format!("http://{}/recording", listener.local_addr().unwrap());
    let (put_tx, mut puts) = mpsc::unbounded_channel();
    let app =
        axum::Router::new().fallback(move |method: axum::http::Method, body: axum::body::Bytes| {
            let put_tx = put_tx.clone();
            async move {
                put_tx.send((method, body)).unwrap();
                axum::http::StatusCode::OK
            }
        });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let (flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let (shipment, mut ack) = flight_shipment();
    flight_tx.try_send(shipment).unwrap();
    let mut outbound = OutboundQueues::new(
        mpsc::unbounded_channel().1,
        flight_rx,
        ControlConnStats::new(),
    );
    let (_drain_tx, mut drain) = watch::channel(false);
    let heartbeat = heartbeat(Duration::from_secs(3600));
    let identity = throwaway_identity_key();

    // Cancel the connection only after the PUT succeeds and the Done send is
    // actually pending, as when the reader ends the connection.
    {
        let (sink, mut frames) = sink(true);
        let (routes, grants) = routes();
        let writer = write_control_frames(
            sink,
            &mut outbound,
            &mut drain,
            &heartbeat,
            &identity,
            RelayId(1),
            routes,
        );
        tokio::pin!(writer);
        tokio::time::timeout(Duration::from_secs(5), async {
            let frame = tokio::select! {
                frame = frames.recv() => frame.unwrap(),
                result = &mut writer => panic!("writer ended before request: {:?}", result.err()),
            };
            let RelayToCoordinator::FlightUploadRequest { request, .. } = decode(frame) else {
                panic!("expected flight upload request");
            };
            grants.send(FlightGrant::Granted { request, url: url.clone() }).unwrap();
            let frame = tokio::select! {
                frame = frames.recv() => frame.unwrap(),
                result = &mut writer => panic!("writer ended before completion: {:?}", result.err()),
            };
            assert!(matches!(decode(frame), RelayToCoordinator::FlightUploadDone { request: done } if done == request));
            let (method, body) = puts.recv().await.unwrap();
            assert_eq!(method, axum::http::Method::PUT);
            assert_eq!(&body[..], b"compressed-bytes");
        }).await.expect("the completion send is reached");
    }

    assert_eq!(outbound.pending_flights.len(), 1);
    assert!(matches!(
        ack.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    // A fresh connection must re-request and re-upload the parked shipment;
    // its fresh grant is connection-local and cannot reuse the old request.
    {
        let (sink, mut frames) = sink(false);
        let (routes, grants) = routes();
        let writer = write_control_frames(
            sink,
            &mut outbound,
            &mut drain,
            &heartbeat,
            &identity,
            RelayId(1),
            routes,
        );
        tokio::pin!(writer);
        tokio::time::timeout(Duration::from_secs(5), async {
            let frame = tokio::select! {
                frame = frames.recv() => frame.unwrap(),
                result = &mut writer => panic!("writer ended before retry: {:?}", result.err()),
            };
            let RelayToCoordinator::FlightUploadRequest { request, .. } = decode(frame) else {
                panic!("expected a re-request");
            };
            grants.send(FlightGrant::Granted { request, url }).unwrap();
            let frame = tokio::select! {
                frame = frames.recv() => frame.unwrap(),
                result = &mut writer => panic!("writer ended before retry completion: {:?}", result.err()),
            };
            assert!(matches!(decode(frame), RelayToCoordinator::FlightUploadDone { request: done } if done == request));
            tokio::select! {
                result = &mut ack => result.expect("stored acknowledgement"),
                result = &mut writer => panic!("writer ended before acknowledgement: {:?}", result.err()),
            }
            let (method, body) = puts.recv().await.unwrap();
            assert_eq!(method, axum::http::Method::PUT);
            assert_eq!(&body[..], b"compressed-bytes");
        }).await.expect("the retry completes");
    }
    assert!(outbound.pending_flights.is_empty());
    server.abort();
}
