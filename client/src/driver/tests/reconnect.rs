//! Re-dialing: how a classified link failure leaves the old connection, how a
//! hung re-home provider is bounded, what each re-home answer does to the
//! escalation window, the outage buffer's cap, the resume cursors a re-dial
//! presents, and the backoff schedule.

use std::net::Ipv4Addr;
use std::sync::atomic::AtomicUsize;

use crate::dial::DialError;

use super::*;

#[tokio::test]
async fn a_classified_link_failure_closes_the_old_connection_before_the_re_dial() {
    // The relay's slot-liveness signal is the connection, not the client's
    // local stream state: after a control-stream-only death the old
    // connection is still fully alive relay-side, holding the roster seat.
    // Unless the reconnect loop closes it once the failure is classified,
    // the immediate re-dial bounces off SLOT_TAKEN until the relay's QUIC
    // idle timeout finally notices. The peer here stands in for the relay:
    // it must observe a deliberate application close, promptly.
    let (link_a, link_b, ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = test_driver(link_a);

    // The re-dial target is unreachable on purpose: this test is about the
    // OLD connection's fate at classification time, not the re-dial (whose
    // own success paths the resume/re-home tests cover).
    let reconnect = Reconnect {
        endpoint: crate::dial::ClientEndpoint::from_endpoint(ea.clone()),
        relay_addr: (Ipv4Addr::LOCALHOST, 1).into(),
        fallback_addrs: Vec::new(),
        server_name: "localhost".to_owned(),
        relay_id: 7,
        identity: fake_identity(SlotId(0)),
        rehome: None,
        escalate_after: None,
        escalate_retry: None,
    };
    let task = tokio::spawn(driver_a.run_reconnecting(reconnect));

    // The peer opens its control stream (as the relay does) and finishes it
    // at once: control stream dead, connection alive — the split that
    // classifies as a reconnect-eligible link failure.
    let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();
    let _ = peer_control_send.finish();

    let closed = tokio::time::timeout(Duration::from_secs(5), link_b.connection().closed())
        .await
        .expect("the old connection was never closed after classification");
    assert!(
        matches!(closed, noq::ConnectionError::ApplicationClosed(_)),
        "closed deliberately by the reconnect loop, not lost: {closed:?}",
    );

    // The driver is now parked re-dialing the unreachable target; the
    // re-dial paths themselves are covered elsewhere.
    task.abort();
    drop(chan_a);
}

#[tokio::test]
async fn a_hung_provider_ask_times_out_and_is_treated_as_unavailable() {
    let (mut seam, chan_a, mut state) = seam_only();
    let (provider, _asked) = HangingProvider::new();
    let provider: Arc<dyn RehomeProvider> = provider;

    let waited = tokio::time::timeout(
        Duration::from_secs(5),
        await_rehome(
            &provider,
            7,
            Duration::from_millis(50),
            &mut seam,
            &mut state,
        ),
    )
    .await
    .expect("the ask must be bounded by the driver's own deadline");
    assert!(
        matches!(waited, EscalationWait::TimedOut),
        "a hung ask times out rather than parking the loop",
    );
    drop(chan_a);
}

#[tokio::test]
async fn game_teardown_is_observed_while_a_provider_ask_is_pending() {
    let (mut seam, chan_a, mut state) = seam_only();
    let (provider, _asked) = HangingProvider::new();
    let provider: Arc<dyn RehomeProvider> = provider;

    // The game tears down mid-ask: drop its half of the seam shortly after
    // the await starts.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(chan_a);
    });
    let waited = tokio::time::timeout(
        Duration::from_secs(5),
        await_rehome(&provider, 7, Duration::from_secs(60), &mut seam, &mut state),
    )
    .await
    .expect("teardown must be observable while the ask is pending");
    assert!(
        matches!(waited, EscalationWait::GameGone),
        "the seam stays serviced during the ask",
    );
}

/// Drives `run_reconnecting` to the point where it escalates, handing back the
/// driver task and the game's channels. The peer plays the relay just long
/// enough to start the game — escalation is gated on the relay's `SessionStart`
/// reaching the driver — and then its connection dies; every same-relay re-dial
/// after that fails immediately against a deliberately invalid address, so the
/// loop reaches `provider` on the windows given rather than resuming.
async fn escalating_driver(
    provider: Arc<dyn RehomeProvider>,
    escalate_after: Duration,
    escalate_retry: Duration,
) -> (
    tokio::task::JoinHandle<Result<(), DriverError>>,
    TurnChannels,
) {
    use rally_point_transport::control::send_control_session_start;

    let (link_a, link_b, ea, _eb) = connected_links().await;
    let (driver_a, mut chan_a) = test_driver(link_a);
    let reconnect = Reconnect {
        endpoint: crate::dial::ClientEndpoint::from_endpoint(ea.clone()),
        // Port 0 is not a dialable remote, so every re-dial fails before it
        // touches the network: the loop's cadence is its backoff alone, with no
        // connection attempt's own duration blurring it.
        relay_addr: (Ipv4Addr::LOCALHOST, 0).into(),
        fallback_addrs: Vec::new(),
        server_name: "localhost".to_owned(),
        relay_id: 7,
        identity: fake_identity(SlotId(0)),
        rehome: Some(provider),
        escalate_after: Some(escalate_after),
        escalate_retry: Some(escalate_retry),
    };
    let task = tokio::spawn(driver_a.run_reconnecting(reconnect));

    let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();
    send_control_session_start(&mut peer_control_send, None)
        .await
        .unwrap();
    // Wait for the directive to actually reach the driver rather than guessing
    // at a delay: escalation is gated on it, so killing the link first would
    // leave the loop retrying the same relay forever.
    tokio::time::timeout(Duration::from_secs(5), chan_a.session_start.recv())
        .await
        .expect("the session-start directive never reached the driver")
        .expect("the session-start channel stays open");
    link_b.connection().close(0u32.into(), b"relay died");
    (task, chan_a)
}

/// A provider that answers every ask the same way — the coordinator saying
/// "stay where you are" or "no relay can take you yet" — counting the asks so a
/// test can see when the loop escalated again.
struct FixedAnswer {
    stay: bool,
    asks: Arc<AtomicUsize>,
}

impl RehomeProvider for FixedAnswer {
    fn rehome(&self, _dead_relay_id: u64) -> RehomeFuture<'_> {
        self.asks.fetch_add(1, Ordering::Relaxed);
        let outcome = if self.stay {
            RehomeOutcome::Stay
        } else {
            RehomeOutcome::Unavailable
        };
        Box::pin(std::future::ready(outcome))
    }
}

/// How many times a driver escalating on a zero-length window asks a provider
/// answering `stay`, within `window` of its first ask. With `escalate_after`
/// zero and `escalate_retry` long, the two answers separate cleanly: `Stay`
/// puts a full (zero) `escalate_after` between asks, so the next failed dial
/// escalates again, while `Unavailable` holds off for the whole
/// `escalate_retry`.
async fn asks_within(stay: bool, escalate_retry: Duration, window: Duration) -> usize {
    let asks = Arc::new(AtomicUsize::new(0));
    let provider = Arc::new(FixedAnswer {
        stay,
        asks: Arc::clone(&asks),
    });
    let (task, chan) = escalating_driver(provider, Duration::ZERO, escalate_retry).await;

    // Start the window at the first ask, not at the driver's start: how long
    // the loop takes to reach its first escalation is the backoff's business.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while asks.load(Ordering::Relaxed) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the loop never escalated to the provider at all",
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(window).await;
    let counted = asks.load(Ordering::Relaxed);

    drop(chan);
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    counted
}

#[tokio::test]
async fn a_stay_answer_re_escalates_on_the_next_failed_dial() {
    // `Stay` means the relay is live after all, so the loop resumes same-relay
    // retries with a fresh `escalate_after` window — zero here, so the next
    // failed dial escalates again. Reading `escalate_retry` instead (the long
    // window below) would leave this at one ask.
    let asks = asks_within(true, Duration::from_secs(4), Duration::from_millis(1_500)).await;
    assert!(
        asks >= 2,
        "a Stay answer must reset the window to escalate_after, got {asks} asks",
    );
}

#[tokio::test]
async fn an_unavailable_answer_holds_off_for_the_retry_cadence() {
    // `Unavailable` means there is nothing to re-home *to* yet, so the loop
    // waits out `escalate_retry` before asking again rather than hammering the
    // coordinator on every failed dial. Reading `escalate_after` instead (zero
    // here) would re-ask within the window below.
    let asks = asks_within(false, Duration::from_secs(4), Duration::from_millis(1_500)).await;
    assert_eq!(
        asks, 1,
        "an Unavailable answer must hold off for escalate_retry",
    );
}

#[tokio::test]
async fn a_hung_rehome_provider_does_not_freeze_the_reconnect_loop() {
    // End to end through `run_reconnecting`: the home relay dies mid-game,
    // escalation asks a provider that never answers, and the game then
    // tears down. The driver must end cleanly — observing the teardown
    // through the pending ask — instead of parking on the embedder's
    // future forever.
    let (provider, asked) = HangingProvider::new();
    let (task, chan_a) =
        escalating_driver(provider, Duration::ZERO, Duration::from_millis(100)).await;

    // Wait until the driver is actually parked on the provider, then tear
    // the game down. Without the seam staying serviced through the ask,
    // the teardown would never be observed and the driver would hang.
    tokio::time::timeout(Duration::from_secs(15), asked)
        .await
        .expect("escalation never asked the provider")
        .unwrap();
    drop(chan_a);

    let joined = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("the driver stayed frozen on the hung provider")
        .unwrap();
    assert!(
        joined.is_ok(),
        "a game teardown during the ask ends the driver cleanly: {joined:?}",
    );
}

#[tokio::test]
async fn an_untrusted_relay_certificate_is_classified_as_a_cert_rejection() {
    // The classifier that lets a cert/pin rejection escalate immediately rather
    // than wait out the timed window: a relay that restarted with a fresh
    // keypair can never be reached by a same-relay retry, and the escalation
    // budget is sized against BW's native stall-drop. It matches on the text
    // noq/rustls surfaces, so only a real rejection proves it still fires.
    use rally_point_transport::quic::{client_config, server_config};
    use rally_point_transport::rustls;
    use rally_point_transport::test_util::self_signed;

    let (chain, key, _ca) = self_signed();
    let peer = noq::Endpoint::server(
        server_config(chain, key).unwrap(),
        (Ipv4Addr::LOCALHOST, 0).into(),
    )
    .unwrap();
    let addr = peer.local_addr().unwrap();
    tokio::spawn(async move {
        // Presenting the certificate is all this peer has to do; the client
        // refuses it from there.
        if let Some(incoming) = peer.accept().await {
            let _ = incoming.await;
        }
    });

    // A client trusting an unrelated CA: the certificate the peer presents
    // cannot chain to it.
    let (_chain, _key, unrelated_ca) = self_signed();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(unrelated_ca).unwrap();
    let endpoint = noq::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    endpoint.set_default_client_config(client_config(roots).unwrap());
    let endpoint = crate::dial::ClientEndpoint::from_endpoint(endpoint);

    let error = endpoint
        .connect(addr, "localhost", &fake_identity(SlotId(0)))
        .await
        // Map the link away so the outcome is `Debug` for the assertions.
        .map(|_link| ())
        .expect_err("an untrusted certificate must fail the dial");
    assert!(
        matches!(error, DialError::Connection(_)),
        "a refused certificate fails the QUIC handshake itself, got {error:?}",
    );
    assert!(
        is_cert_rejection(&error),
        "the escalation fast path must recognise it: {error}",
    );
}

#[test]
fn a_token_is_expired_from_its_expiry_instant_onward() {
    // The reconnect loop stops before wasting a dial no relay could authorize,
    // on the same boundary the relay applies: the expiry instant itself already
    // counts as expired.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        !token_expired(&identity_expiring_at(SlotId(0), now + 60)),
        "a token still inside its window authorizes a re-dial",
    );
    assert!(
        token_expired(&identity_expiring_at(SlotId(0), now)),
        "the expiry instant itself counts as expired",
    );
    assert!(token_expired(&identity_expiring_at(SlotId(0), 0)));
}

/// A turn produced past [`OUTAGE_OUTBOUND_BUFFER_CAP`] during an outage
/// must not be silently dropped: `wait_backoff` surfaces
/// `WaitOutcome::BufferExhausted` the moment the buffer crosses the cap,
/// with every turn up to and including the one that tipped it over still
/// in `state.outbound_buffer` (nothing discarded on the way).
#[tokio::test]
async fn wait_backoff_reports_buffer_exhausted_once_the_outage_buffer_overflows() {
    let (mut seam, chan_a, mut state) = seam_only();
    let mut backoff = Backoff::new();

    // Fill to exactly the cap, then one more to tip it over. `wait_backoff`
    // processes queued turns one at a time in its own loop, so pre-filling
    // the channel is equivalent to a real caller producing them one by one
    // during the outage.
    for i in 0..=OUTAGE_OUTBOUND_BUFFER_CAP {
        chan_a
            .outbound
            .send(turn(0, &[(i % 256) as u8]))
            .await
            .unwrap();
    }

    match wait_backoff(&mut backoff, &mut seam, &mut state).await {
        WaitOutcome::BufferExhausted => {}
        WaitOutcome::Elapsed => panic!("expected BufferExhausted, got Elapsed"),
        WaitOutcome::GameGone => panic!("expected BufferExhausted, got GameGone"),
    }
    assert_eq!(
        state.outbound_buffer.len(),
        OUTAGE_OUTBOUND_BUFFER_CAP + 1,
        "nothing was dropped on the way to the trip -- every produced turn is \
         still buffered, proving the exhaustion is reported, not silently eaten",
    );
}

#[test]
fn backoff_base_schedule_doubles_from_the_initial_delay_then_caps() {
    assert_eq!(Backoff::base_delay(0), RECONNECT_BACKOFF_INITIAL);
    assert_eq!(Backoff::base_delay(1), Duration::from_secs(1));
    assert_eq!(Backoff::base_delay(2), Duration::from_secs(2));
    assert_eq!(Backoff::base_delay(3), Duration::from_secs(4));
    // 500ms << 4 = 8s would exceed the 5s cap, so it clamps there.
    assert_eq!(Backoff::base_delay(4), RECONNECT_BACKOFF_CAP);
    assert_eq!(Backoff::base_delay(5), RECONNECT_BACKOFF_CAP);
    // A far-out attempt saturates at the cap rather than overflowing the shift.
    assert_eq!(Backoff::base_delay(1_000), RECONNECT_BACKOFF_CAP);
}

#[test]
fn backoff_next_delay_jitters_within_half_of_base_and_advances_each_attempt() {
    let mut backoff = Backoff::new();
    // `next_delay` uses the current attempt's base then advances, so the base for
    // attempt N is what the Nth draw must fall within.
    for attempt in 0..8u32 {
        let base = Backoff::base_delay(attempt);
        let delay = backoff.next_delay();
        assert!(
            delay <= base,
            "attempt {attempt}: {delay:?} exceeds its base {base:?}"
        );
        assert!(
            delay >= base / 2,
            "attempt {attempt}: {delay:?} is below half its base {base:?}"
        );
    }

    // A reset returns to the initial delay's jitter band.
    backoff.reset();
    let first = backoff.next_delay();
    assert!(first >= RECONNECT_BACKOFF_INITIAL / 2 && first <= RECONNECT_BACKOFF_INITIAL);
}
