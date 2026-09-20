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
    let with_secret = build_request("http://host:14910/", Some("s3cret")).unwrap();
    assert_eq!(with_secret.uri().path(), "/relay/control");
    assert_eq!(with_secret.uri().scheme_str(), Some("ws"));
    assert_eq!(
        with_secret.headers().get(AUTHORIZATION).unwrap(),
        "Bearer s3cret",
    );

    // A relay the coordinator authenticates another way presents no bearer.
    let without_secret = build_request("http://host:14910", None).unwrap();
    assert_eq!(without_secret.uri().path(), "/relay/control");
    assert!(without_secret.headers().get(AUTHORIZATION).is_none());
}

// --- Refusal backoff ---

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

/// Builds a close frame carrying one of the coordinator's refusal codes.
fn refusal(code: u16, reason: &str) -> tokio_tungstenite::tungstenite::protocol::CloseFrame {
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    CloseFrame {
        code: CloseCode::from(code),
        reason: reason.to_owned().into(),
    }
}

/// The gap between the first two dials a relay makes against a coordinator that
/// answers every connection with `close_frame`, under the given redial delays.
async fn redial_gap(
    close_frame: Option<tokio_tungstenite::tungstenite::protocol::CloseFrame>,
    ordinary: Duration,
    version_refused: Duration,
) -> Duration {
    let (addr, mut times_rx) = spawn_closing_coordinator(close_frame).await;
    SubscriberFixture {
        backoff: backoff(ordinary, version_refused),
        ..Default::default()
    }
    .spawn(addr);

    let first = tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
        .await
        .expect("the first dial arrives")
        .unwrap();
    let second = tokio::time::timeout(Duration::from_secs(5), times_rx.recv())
        .await
        .expect("the relay eventually redials")
        .unwrap();
    second.duration_since(first)
}

#[tokio::test]
async fn an_operator_fix_refusal_waits_the_refusal_backoff_before_redialing() {
    // None of these resolves by redialing — a version mismatch, an unknown
    // region, a bad signature or key mismatch, and a relay the ledger does not
    // authorize each need a deploy or a provisioner — so all four take the long
    // backoff instead of hot-retrying against a coordinator that will keep
    // refusing. The four dials run concurrently, so the suite pays one backoff
    // rather than four.
    let cases = [
        (
            CONTROL_CLOSE_PROTOCOL_MISMATCH,
            "no common protocol version: local supports v2..=v2, peer supports v1..=v1",
        ),
        (CONTROL_CLOSE_UNKNOWN_REGION, "unknown region: region-z"),
        (
            CONTROL_CLOSE_IDENTITY_UNPROVEN,
            "enroll proof-of-possession failed",
        ),
        (
            CONTROL_CLOSE_ENROLL_UNAUTHORIZED,
            "not authorized by the ledger",
        ),
    ];

    // The ordinary reconnect would redial in ~20ms; the refusal backoff is 500ms.
    let gaps = futures_util::future::join_all(cases.map(|(code, reason)| async move {
        let gap = redial_gap(
            Some(refusal(code, reason)),
            Duration::from_millis(20),
            Duration::from_millis(500),
        )
        .await;
        (code, gap)
    }))
    .await;

    for (code, gap) in gaps {
        assert!(
            gap >= Duration::from_millis(400),
            "close code {code} must wait the refusal backoff, not the ordinary \
             reconnect delay (observed gap: {gap:?})",
        );
    }
}

#[tokio::test]
async fn a_close_that_resolves_on_its_own_redials_at_the_normal_delay() {
    // An ordinary close is just a connection ending, and a duplicate-relay-id
    // refusal ages out by itself once the coordinator's liveness deadline
    // retires the stale entry — so neither takes the long backoff. Proven by
    // setting the refusal backoff absurdly long: a prompt redial can only have
    // come from the ordinary path.
    let cases = [
        None,
        Some(refusal(
            CONTROL_CLOSE_DUPLICATE_RELAY_ID,
            "relay id already enrolled under a different certificate",
        )),
    ];

    let gaps = futures_util::future::join_all(cases.map(|close_frame| async move {
        redial_gap(
            close_frame,
            Duration::from_millis(20),
            Duration::from_secs(3600),
        )
        .await
    }))
    .await;

    for gap in gaps {
        assert!(
            gap < Duration::from_secs(2),
            "a close that resolves on its own redials at the normal delay, \
             not the refusal backoff (observed gap: {gap:?})",
        );
    }
}
