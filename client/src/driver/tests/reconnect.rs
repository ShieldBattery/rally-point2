//! Re-dialing: how a classified link failure leaves the old connection, how a
//! hung re-home provider is bounded, the outage buffer's cap, the resume
//! cursors a re-dial presents, and the backoff schedule.

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
    let (driver_a, chan_a) = LinkDriver::new(link_a);

    // The re-dial target is unreachable on purpose: this test is about the
    // OLD connection's fate at classification time, not the re-dial (whose
    // own success paths the resume/re-home tests cover).
    let reconnect = Reconnect {
        endpoint: crate::dial::ClientEndpoint::from_endpoint(ea.clone()),
        relay_addr: (Ipv4Addr::LOCALHOST, 1).into(),
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
    let (link_a, _link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let (_link, mut seam, mut state) = into_session_parts(driver_a);
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
    let (link_a, _link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let (_link, mut seam, mut state) = into_session_parts(driver_a);
    let (provider, _asked) = HangingProvider::new();
    let provider: Arc<dyn RehomeProvider> = provider;

    // The game tears down mid-ask: drop its half of the seam shortly after
    // the await starts.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
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

#[tokio::test]
async fn a_hung_rehome_provider_does_not_freeze_the_reconnect_loop() {
    // End to end through `run_reconnecting`: the home relay dies mid-game,
    // escalation asks a provider that never answers, and the game then
    // tears down. The driver must end cleanly — observing the teardown
    // through the pending ask — instead of parking on the embedder's
    // future forever.
    use rally_point_transport::control::send_control_session_start;

    let (link_a, link_b, ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let (provider, asked) = HangingProvider::new();

    let reconnect = Reconnect {
        endpoint: crate::dial::ClientEndpoint::from_endpoint(ea.clone()),
        // Unreachable: every same-relay re-dial fails, so escalation is
        // reached on the first attempt (the zero window below).
        relay_addr: (Ipv4Addr::LOCALHOST, 1).into(),
        server_name: "localhost".to_owned(),
        relay_id: 7,
        identity: fake_identity(SlotId(0)),
        rehome: Some(provider),
        escalate_after: Some(Duration::ZERO),
        escalate_retry: Some(Duration::from_millis(100)),
    };
    let task = tokio::spawn(driver_a.run_reconnecting(reconnect));

    // The peer plays the relay far enough to start the game (escalation is
    // gated on `SessionStart`), then its connection dies — a link failure.
    let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();
    send_control_session_start(&mut peer_control_send, None)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    link_b.connection().close(0u32.into(), b"relay died");

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

/// A turn produced past [`OUTAGE_OUTBOUND_BUFFER_CAP`] during an outage
/// must not be silently dropped: `wait_backoff` surfaces
/// `WaitOutcome::BufferExhausted` the moment the buffer crosses the cap,
/// with every turn up to and including the one that tipped it over still
/// in `state.outbound_buffer` (nothing discarded on the way).
#[tokio::test]
async fn wait_backoff_reports_buffer_exhausted_once_the_outage_buffer_overflows() {
    let (link_a, _link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let (_link, mut seam, mut state) = into_session_parts(driver_a);
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

#[tokio::test]
async fn resume_cursor_is_the_contiguous_high_water_and_absorbs_replayed_turns() {
    // The reconnect path derives its resume cursor from `next_seq` — the top of
    // the contiguous run delivered to the game, per slot. Drive the driver's
    // exact inbound ingest and confirm the cursor tracks that high-water and
    // that a replayed already-delivered turn neither advances it nor re-reaches
    // the game (the reorder buffer dedups the overlap a replay carries).
    let (inbound_tx, mut inbound_rx) = mpsc::channel::<Payload>(64);
    let mut next_seq: HashMap<SlotId, u64> = HashMap::new();
    let mut pending: HashMap<SlotId, BTreeMap<u64, Payload>> = HashMap::new();
    let slot = SlotId(0);

    ingest_turn(slot, 0, &mut next_seq, &mut pending, &inbound_tx);
    ingest_turn(slot, 1, &mut next_seq, &mut pending, &inbound_tx);
    // A gap at 2: seq 3 is held, so the cursor stays at the next-needed 2.
    ingest_turn(slot, 3, &mut next_seq, &mut pending, &inbound_tx);
    assert_eq!(resume_cursors(&next_seq), vec![(slot, 2)]);

    // A replay of an already-delivered turn (seq 1 < cursor 2) is dropped: the
    // cursor is unchanged and nothing new reaches the game.
    ingest_turn(slot, 1, &mut next_seq, &mut pending, &inbound_tx);
    assert_eq!(resume_cursors(&next_seq), vec![(slot, 2)]);

    // Seq 2 fills the gap: 2 and the held 3 both release, the cursor jumps to 4.
    ingest_turn(slot, 2, &mut next_seq, &mut pending, &inbound_tx);
    assert_eq!(resume_cursors(&next_seq), vec![(slot, 4)]);

    // The game saw 0,1,2,3 once each, in order — no duplicate from the replay.
    let mut delivered = Vec::new();
    while let Ok(payload) = inbound_rx.try_recv() {
        delivered.push((payload.seq, payload.commands[0]));
    }
    assert_eq!(delivered, vec![(0, 0), (1, 1), (2, 2), (3, 3)]);
}

#[test]
fn resume_cursors_map_every_received_peer_slot_to_its_next_needed_seq() {
    let mut next_seq = HashMap::new();
    next_seq.insert(SlotId(0), 5);
    next_seq.insert(SlotId(2), 0);
    let mut cursors = resume_cursors(&next_seq);
    cursors.sort();
    assert_eq!(cursors, vec![(SlotId(0), 5), (SlotId(2), 0)]);

    // No peer turns received yet → no cursors → the relay replays nothing, the
    // same as a fresh dial.
    assert!(resume_cursors(&HashMap::new()).is_empty());
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
