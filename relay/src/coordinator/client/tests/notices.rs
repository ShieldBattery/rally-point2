//! The notice pipe: the frame each notice kind serializes to, its survival across
//! a reconnect or a stalled send, and its priority over queued flight work.

use super::*;

/// Captures every frame a `send_notice` writes, so a test can assert exactly
/// what went on the wire. The sink carries the WebSocket's error type, so the
/// generic bound is satisfied exactly as the live socket satisfies it.
async fn capture_sent(notice: &RelayNotice) -> Vec<Message> {
    use std::sync::{Arc, Mutex};

    let captured: Arc<Mutex<Vec<Message>>> = Arc::default();
    let for_sink = Arc::clone(&captured);
    let mut sink = Box::pin(futures_util::sink::unfold(
        (),
        move |(), message: Message| {
            let for_sink = Arc::clone(&for_sink);
            async move {
                for_sink.lock().unwrap().push(message);
                Ok::<(), tokio_tungstenite::tungstenite::Error>(())
            }
        },
    ));
    send_notice(&mut sink, notice).await.unwrap();
    let frames = captured.lock().unwrap();
    frames.clone()
}

#[tokio::test]
async fn send_notice_emits_one_tagged_departure_frame() {
    let notice = RelayNotice::Departure(dropped_notice());
    let frames = capture_sent(&notice).await;
    assert_eq!(frames.len(), 1, "exactly one frame");
    let Message::Text(text) = &frames[0] else {
        panic!("a text frame");
    };
    let decoded: RelayToCoordinator = serde_json::from_str(text).unwrap();
    assert_eq!(decoded, RelayToCoordinator::Departure(dropped_notice()));
}

#[tokio::test]
async fn send_notice_emits_one_tagged_desync_frame() {
    // The desync kind rides the same pipe and wraps into the matching frame.
    let notice = RelayNotice::Desync(desync_notice());
    let frames = capture_sent(&notice).await;
    assert_eq!(frames.len(), 1, "exactly one frame");
    let Message::Text(text) = &frames[0] else {
        panic!("a text frame");
    };
    assert!(text.contains("\"type\":\"desync\""));
    let decoded: RelayToCoordinator = serde_json::from_str(text).unwrap();
    assert_eq!(decoded, RelayToCoordinator::Desync(desync_notice()));
}

/// A notice queued while the coordinator is unreachable is delivered on the
/// next successful connection, not lost. The first dial fails at the handshake
/// (the server drops the socket), so the relay never touches the channel; the
/// second dial completes, and the queued notice flushes right after the Hello.
/// Run for both notice kinds, since they share the one buffered pipe.
async fn a_queued_notice_is_delivered_after_a_reconnect(queued: RelayNotice) {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (frame_tx, frame_rx) = tokio::sync::oneshot::channel();

    // The stand-in coordinator: fail the first dial, then accept the second
    // and capture the frame that follows the enroll Hello.
    tokio::spawn(async move {
        // First connection: drop it mid-handshake so the relay's connect
        // fails and it redials — without ever entering its send loop, so the
        // queued notice stays in the channel rather than being consumed here.
        let (first, _) = listener.accept().await.unwrap();
        drop(first);

        // Second connection: complete the WebSocket handshake and the enroll
        // proof exchange, then read the flushed notice — which the relay sends
        // only after the proof.
        let (second, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(second).await.unwrap();
        let hello = accept_enroll(&mut ws).await;
        let Message::Text(hello) = hello else {
            panic!("first frame is the Hello");
        };
        assert!(hello.contains("\"type\":\"hello\""));
        let notice = ws.next().await.unwrap().unwrap();
        let _ = frame_tx.send(notice);
    });

    // Queue the notice before the subscriber starts: it sits in the unbounded
    // channel until a live connection can carry it.
    let (notices_tx, notices_rx) = mpsc::unbounded_channel();
    notices_tx.send(queued.clone()).unwrap();

    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let (drain_rx, drain_acked) = no_drain();
    tokio::spawn(run_descriptor_subscriber_with(
        enroll(
            addr,
            RelayHello::new(
                RelayId(1),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
                rally_point_proto::version::ProtocolVersion::CURRENT,
                vec![0xAB; 4],
            ),
        ),
        apply_targets(control, drain_acked),
        OutboundQueues::new(notices_rx, no_flight(), ControlConnStats::new()),
        heartbeat(Duration::from_secs(3600)), // no heartbeat during the test
        drain_rx,
        no_connected(),
        // Redial fast after the failed first dial.
        backoff(Duration::from_millis(20), Duration::from_secs(60)),
    ));

    let received = tokio::time::timeout(Duration::from_secs(5), frame_rx)
        .await
        .expect("the queued notice is delivered after the reconnect")
        .unwrap();
    let Message::Text(text) = received else {
        panic!("a text frame");
    };
    let decoded: RelayToCoordinator = serde_json::from_str(&text).unwrap();
    let expected = match queued {
        RelayNotice::Departure(notice) => RelayToCoordinator::Departure(notice),
        RelayNotice::Desync(notice) => RelayToCoordinator::Desync(notice),
        RelayNotice::Result(notice) => RelayToCoordinator::Result(notice),
        RelayNotice::SlotConnected(notice) => RelayToCoordinator::SlotConnected(notice),
        RelayNotice::SessionStarted(notice) => RelayToCoordinator::SessionStarted(notice),
        RelayNotice::SlotStarted(notice) => RelayToCoordinator::SlotStarted(notice),
        RelayNotice::SessionClosed { tenant, session } => {
            RelayToCoordinator::SessionClosed { tenant, session }
        }
    };
    assert_eq!(decoded, expected);
}

#[tokio::test]
async fn a_queued_departure_is_delivered_after_a_reconnect() {
    a_queued_notice_is_delivered_after_a_reconnect(RelayNotice::Departure(dropped_notice())).await;
}

#[tokio::test]
async fn a_queued_desync_is_delivered_after_a_reconnect() {
    a_queued_notice_is_delivered_after_a_reconnect(RelayNotice::Desync(desync_notice())).await;
}

#[tokio::test]
async fn the_notice_and_flight_pipes_do_not_block_each_other() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

    // Stand-in coordinator: enroll, then read two frames — a notice and a
    // flight shipment, in whichever order the two independent pipes flush them.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _hello = accept_enroll(&mut ws).await;
        let first = ws.next().await.unwrap().unwrap();
        let second = ws.next().await.unwrap().unwrap();
        let _ = frames_tx.send((first, second));
    });

    let (notices_tx, notices_rx) = mpsc::unbounded_channel();
    notices_tx
        .send(RelayNotice::Departure(dropped_notice()))
        .unwrap();
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
        OutboundQueues::new(notices_rx, flight_rx, ControlConnStats::new()),
        heartbeat(Duration::from_secs(3600)),
        drain_rx,
        no_connected(),
        backoff(Duration::from_millis(20), Duration::from_secs(60)),
    ));

    let (first, second) = tokio::time::timeout(Duration::from_secs(5), frames_rx)
        .await
        .expect("both pipes deliver")
        .unwrap();
    let decode = |message: Message| -> RelayToCoordinator {
        let Message::Text(text) = message else {
            panic!("a text frame");
        };
        serde_json::from_str(&text).unwrap()
    };
    let frames = [decode(first), decode(second)];
    assert!(
        frames
            .iter()
            .any(|f| matches!(f, RelayToCoordinator::Departure(_))),
        "the notice pipe delivered",
    );
    assert!(
        frames
            .iter()
            .any(|f| matches!(f, RelayToCoordinator::FlightUploadRequest { .. })),
        "the flight pipe delivered",
    );
}

/// A sink whose sends never complete: `poll_ready`/`poll_flush` stay Pending
/// forever, modeling a coordinator that never drains what the write half sends.
/// Once the writer parks an item and begins sending, it is stuck mid-send —
/// exactly the state the read half ending the connection would drop it in.
struct StalledSink;

impl futures_util::Sink<Message> for StalledSink {
    type Error = tokio_tungstenite::tungstenite::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Pending
    }

    fn start_send(self: std::pin::Pin<&mut Self>, _: Message) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Pending
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Pending
    }
}

#[tokio::test]
async fn a_notice_parked_mid_send_survives_the_write_half_being_dropped() {
    // The split's new exit path: the read half ends the connection while the
    // write half holds a notice parked mid-send. The notice must stay in the
    // caller-owned slot so the next connection's flush delivers it. Drive the
    // write half against a sink that never completes a send, so it parks the
    // notice and blocks, then drop it — the caller's slot must still hold it.
    let (notices_tx, notices_rx) = mpsc::unbounded_channel();
    notices_tx
        .send(RelayNotice::Departure(dropped_notice()))
        .unwrap();
    let (_flight_tx, flight_rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    // Live senders so the drain, challenge, and flight-grant arms stay pending (not
    // disabled), leaving the notices arm the one that fires.
    let (_drain_tx, mut drain_rx) = watch::channel(false);
    let (_challenge_tx, challenge_rx) = mpsc::unbounded_channel::<[u8; 32]>();
    let (_flight_grant_tx, flight_grant_rx) = mpsc::unbounded_channel::<FlightGrant>();
    let (_load_state_tx, load_state_rx) = mpsc::channel::<LoadStateAsk>(LOAD_STATE_ASK_CAPACITY);

    let mut outbound = OutboundQueues::new(notices_rx, flight_rx, ControlConnStats::new());
    let heartbeat = heartbeat(Duration::from_secs(3600));
    let identity_key = throwaway_identity_key();

    // The write half never completes (the sink stalls), so a short timeout drops
    // it exactly as the read half ending the connection would.
    let writer = write_control_frames(
        StalledSink,
        &mut outbound,
        &mut drain_rx,
        &heartbeat,
        &identity_key,
        RelayId(1),
        WriterRoutes {
            challenge_rx,
            flight_grant_rx,
            load_state_rx,
        },
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), writer)
            .await
            .is_err(),
        "the write half stays parked on the stalled send",
    );

    // The notice is back in the caller-owned slot — parked before the send await
    // and never cleared — ready for the next connection's flush.
    assert_eq!(
        outbound.pending,
        Some(RelayNotice::Departure(dropped_notice())),
        "a notice parked mid-send survives the write half being dropped",
    );
    assert_eq!(
        outbound.stats.snapshot().notices,
        1,
        "the parked notice is reflected in the reported queue depth",
    );
}

#[tokio::test]
async fn a_queued_flight_upload_does_not_delay_a_queued_notice() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

    // Stand-in coordinator: enroll, then read the first two frames. With both a
    // notice and a flight shipment queued, the write half's priority order must put
    // the notice first — if the flight arm outranked it, the coordinator would read
    // the upload request ahead of the notice.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _hello = accept_enroll(&mut ws).await;
        let first = ws.next().await.unwrap().unwrap();
        let second = ws.next().await.unwrap().unwrap();
        let _ = frames_tx.send((first, second));
    });

    // Queue the notice AND a flight shipment before the subscriber starts.
    let (notices_tx, notices_rx) = mpsc::unbounded_channel();
    notices_tx
        .send(RelayNotice::Departure(dropped_notice()))
        .unwrap();
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
        OutboundQueues::new(notices_rx, flight_rx, ControlConnStats::new()),
        heartbeat(Duration::from_secs(3600)),
        drain_rx,
        no_connected(),
        backoff(Duration::from_millis(20), Duration::from_secs(60)),
    ));

    let (first, second) = tokio::time::timeout(Duration::from_secs(5), frames_rx)
        .await
        .expect("both frames arrive")
        .unwrap();
    let decode = |message: Message| -> RelayToCoordinator {
        let Message::Text(text) = message else {
            panic!("a text frame");
        };
        serde_json::from_str(&text).unwrap()
    };
    assert_eq!(
        decode(first),
        RelayToCoordinator::Departure(dropped_notice()),
        "the notice ships before the queued flight upload request",
    );
    assert!(
        matches!(
            decode(second),
            RelayToCoordinator::FlightUploadRequest { .. }
        ),
        "the flight upload request ships after the notice",
    );
}
