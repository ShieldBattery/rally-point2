//! Dialing and redialing: the control URL the upgrade request targets, and which
//! coordinator close codes buy the long refusal backoff rather than a prompt
//! retry.

use super::*;

#[test]
fn to_ws_scheme_rewrites_http_and_passes_ws_through() {
    assert_eq!(to_ws_scheme("http://host:14910"), "ws://host:14910");
    assert_eq!(to_ws_scheme("https://host:14910"), "wss://host:14910");
    assert_eq!(to_ws_scheme("ws://host:14910"), "ws://host:14910");
}

#[test]
fn build_request_targets_the_control_path_and_sets_the_bearer() {
    let request = build_request("http://host:14910/", Some("s3cret")).unwrap();
    assert_eq!(request.uri().path(), "/relay/control");
    assert_eq!(request.uri().scheme_str(), Some("ws"));
    assert_eq!(
        request.headers().get(AUTHORIZATION).unwrap(),
        "Bearer s3cret",
    );
}

#[test]
fn build_request_without_a_secret_sets_no_authorization() {
    let request = build_request("http://host:14910", None).unwrap();
    assert!(request.headers().get(AUTHORIZATION).is_none());
}

// --- Protocol-version refusal backoff ---

/// Spawns a stand-in coordinator that, for every control connection, reads the
/// enroll Hello and then closes with `close_frame` — reporting the instant each
/// connection was accepted, so a test can measure the redial gap.
async fn spawn_closing_coordinator(
    close_frame: Option<tokio_tungstenite::tungstenite::protocol::CloseFrame>,
) -> (
    std::net::SocketAddr,
    mpsc::UnboundedReceiver<std::time::Instant>,
) {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (times_tx, times_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let _ = times_tx.send(std::time::Instant::now());
            let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                continue;
            };
            let _hello = ws.next().await;
            let _ = ws.close(close_frame.clone()).await;
            // Drain until the client answers the close, so it completes cleanly.
            while let Some(Ok(_)) = ws.next().await {}
        }
    });
    (addr, times_rx)
}

/// Spawns the subscriber against `addr` with a fast ordinary reconnect delay
/// and the given version-refusal delay, returning nothing — the stand-in
/// coordinator's accept times are the observable.
fn spawn_subscriber_with_delays(
    addr: std::net::SocketAddr,
    reconnect_delay: Duration,
    version_refused_delay: Duration,
) {
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
        no_connected(),
        backoff(reconnect_delay, version_refused_delay),
    ));
}

#[tokio::test]
async fn a_version_refusal_close_waits_the_refusal_backoff_before_redialing() {
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    // The coordinator refuses every connection with the version-mismatch close.
    let (addr, mut times_rx) = spawn_closing_coordinator(Some(CloseFrame {
        code: CloseCode::from(CONTROL_CLOSE_PROTOCOL_MISMATCH),
        reason: "no common protocol version: local supports v2..=v2, \
                 peer supports v1..=v1"
            .into(),
    }))
    .await;

    // Ordinary reconnect would redial in ~20ms; the refusal backoff is 500ms.
    spawn_subscriber_with_delays(addr, Duration::from_millis(20), Duration::from_millis(500));

    let first = tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
        .await
        .expect("the first dial arrives")
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
        .await
        .expect("the relay eventually redials")
        .unwrap();
    let gap = second.duration_since(first);
    assert!(
        gap >= Duration::from_millis(400),
        "a version refusal must wait the refusal backoff, not the ordinary \
         reconnect delay (observed gap: {gap:?})",
    );
}

#[tokio::test]
async fn an_unknown_region_close_waits_the_refusal_backoff_before_redialing() {
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    // The coordinator refuses every connection with the unknown-region close —
    // like a version mismatch, a redial changes nothing until the config is
    // fixed, so the relay must wait the long refusal backoff, not the ordinary
    // reconnect delay.
    let (addr, mut times_rx) = spawn_closing_coordinator(Some(CloseFrame {
        code: CloseCode::from(CONTROL_CLOSE_UNKNOWN_REGION),
        reason: "unknown region: region-z".into(),
    }))
    .await;

    spawn_subscriber_with_delays(addr, Duration::from_millis(20), Duration::from_millis(500));

    let first = tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
        .await
        .expect("the first dial arrives")
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
        .await
        .expect("the relay eventually redials")
        .unwrap();
    let gap = second.duration_since(first);
    assert!(
        gap >= Duration::from_millis(400),
        "an unknown-region refusal must wait the refusal backoff, not the ordinary \
         reconnect delay (observed gap: {gap:?})",
    );
}

#[tokio::test]
async fn an_identity_unproven_close_waits_the_refusal_backoff_before_redialing() {
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    // The coordinator refuses every connection with the identity-unproven
    // close — a bad signature or key mismatch is a config/implementation
    // fault, not something a redial fixes, so it takes the long backoff like
    // a version or region refusal.
    let (addr, mut times_rx) = spawn_closing_coordinator(Some(CloseFrame {
        code: CloseCode::from(CONTROL_CLOSE_IDENTITY_UNPROVEN),
        reason: "enroll proof-of-possession failed".into(),
    }))
    .await;

    spawn_subscriber_with_delays(addr, Duration::from_millis(20), Duration::from_millis(500));

    let first = tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
        .await
        .expect("the first dial arrives")
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
        .await
        .expect("the relay eventually redials")
        .unwrap();
    let gap = second.duration_since(first);
    assert!(
        gap >= Duration::from_millis(400),
        "an identity-unproven refusal must wait the refusal backoff, not the \
         ordinary reconnect delay (observed gap: {gap:?})",
    );
}

#[tokio::test]
async fn a_duplicate_relay_id_close_redials_at_the_normal_delay() {
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    // Unlike identity-unproven, a duplicate-relay-id refusal resolves on its
    // own (the stale entry ages out via the coordinator's liveness deadline),
    // so it must take the ordinary short delay, not the long refusal backoff
    // — proven the same way the plain-close test proves it: the refusal
    // backoff is set absurdly long, so a prompt redial proves the ordinary
    // path was taken.
    let (addr, mut times_rx) = spawn_closing_coordinator(Some(CloseFrame {
        code: CloseCode::from(CONTROL_CLOSE_DUPLICATE_RELAY_ID),
        reason: "relay id already enrolled under a different certificate".into(),
    }))
    .await;
    spawn_subscriber_with_delays(addr, Duration::from_millis(20), Duration::from_secs(3600));

    tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
        .await
        .expect("the first dial arrives")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), times_rx.recv())
        .await
        .expect(
            "a duplicate-relay-id refusal redials at the normal delay, \
             not the long refusal backoff",
        )
        .unwrap();
}

#[tokio::test]
async fn an_ordinary_close_redials_at_the_normal_delay() {
    // The coordinator closes normally (no version refusal). With the refusal
    // backoff set absurdly long, a redial arriving promptly proves the ordinary
    // path took the ordinary delay — the wrong branch would blow the timeout.
    let (addr, mut times_rx) = spawn_closing_coordinator(None).await;
    spawn_subscriber_with_delays(addr, Duration::from_millis(20), Duration::from_secs(3600));

    tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
        .await
        .expect("the first dial arrives")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), times_rx.recv())
        .await
        .expect("an ordinary close redials at the normal delay, not the refusal backoff")
        .unwrap();
}
