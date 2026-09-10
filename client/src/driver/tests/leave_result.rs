//! The client's own announcements up the control stream: the clean leave
//! intent and what holds it, the end-of-game result report, and the
//! game-started signal (including its fence-probe and reconnect re-assertion).

use super::*;

#[tokio::test]
async fn leave_intent_is_sent_immediately_when_nothing_is_outstanding() {
    // With no turns ever produced, the outbound queue and unacked window
    // are already empty: the intent must go out the moment the game
    // signals, without waiting on anything to drain.
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    // Watch the control stream the way the relay does.
    let mut control_rx = spawn_control_reader(link_b.connection().clone());

    chan_a.leave_intent.send(()).await.unwrap();

    let frame = tokio::time::timeout(Duration::from_secs(1), control_rx.recv())
        .await
        .expect("leave intent never arrived")
        .expect("control reader ended early");
    assert!(matches!(frame, ControlInbound::LeaveIntent));

    drop(chan_a.outbound);
    drop(chan_a.inbound);
    let _ = task.await;
}

#[tokio::test]
async fn leave_intent_waits_for_unacked_turns_to_drain_before_sending() {
    // A turn is still unacked when the game signals its departure: the
    // intent must not go out until the fake relay acks it — the driver
    // holds off announcing until the relay's view of our last turn is
    // final.
    let (link_a, mut link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    let mut control_rx = spawn_control_reader(link_b.connection().clone());

    // One turn goes out and the fake relay sees it, but deliberately
    // never acks it yet.
    chan_a.outbound.send(turn(0, &[0x11])).await.unwrap();
    let received = link_b.recv().await.unwrap();
    assert_eq!(
        received.fresh[0].commands[0], 0x11,
        "the relay saw the turn"
    );

    // Signal departure now, while that turn is still unacked.
    chan_a.leave_intent.send(()).await.unwrap();

    // The intent must not arrive while anything is unacked.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), control_rx.recv())
            .await
            .is_err(),
        "leave intent sent before its last turn was acked"
    );

    // The fake relay's ack-only flush retires it.
    link_b.send(None).unwrap();

    let frame = tokio::time::timeout(Duration::from_millis(500), control_rx.recv())
        .await
        .expect("leave intent never arrived after the ack")
        .expect("control reader ended early");
    assert!(matches!(frame, ControlInbound::LeaveIntent));

    drop(chan_a.outbound);
    drop(chan_a.inbound);
    let _ = task.await;
}

#[tokio::test]
async fn leave_intent_is_sent_after_the_safety_timeout_if_acks_never_arrive() {
    // The fake relay sees a turn but never acks it. The driver must not
    // wait on the drain condition forever once the game has signaled
    // departure — the safety timeout fires and the intent goes out
    // anyway.
    let (link_a, mut link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    let mut control_rx = spawn_control_reader(link_b.connection().clone());

    chan_a.outbound.send(turn(0, &[0x22])).await.unwrap();
    let _received = link_b.recv().await.unwrap(); // seen, never acked

    let before = tokio::time::Instant::now();
    chan_a.leave_intent.send(()).await.unwrap();

    let frame = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
        .await
        .expect("leave intent never arrived")
        .expect("control reader ended early");
    assert!(matches!(frame, ControlInbound::LeaveIntent));
    assert!(
        before.elapsed() >= LEAVE_INTENT_TIMEOUT,
        "intent went out before the safety timeout elapsed"
    );

    drop(chan_a.outbound);
    drop(chan_a.inbound);
    let _ = task.await;
}

#[tokio::test]
async fn run_returns_ok_when_the_link_closes_after_the_leave_intent() {
    // Once the intent has gone out, the relay closing the link is the
    // expected confirmation it processed the leave: `run` must return
    // `Ok`, not surface a `DriverError`.
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    let mut control_rx = spawn_control_reader(link_b.connection().clone());
    chan_a.leave_intent.send(()).await.unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(1), control_rx.recv())
        .await
        .expect("leave intent never arrived")
        .expect("control reader ended early");
    assert!(matches!(frame, ControlInbound::LeaveIntent));

    // The relay's confirmation is closing the link once it has processed
    // the intent — simulate that directly rather than the game dropping
    // its channels.
    link_b
        .connection()
        .close(noq::VarInt::from_u32(0), b"leave processed");

    match tokio::time::timeout(Duration::from_secs(5), task).await {
        Ok(joined) => assert!(
            joined.unwrap().is_ok(),
            "run() must return Ok after the link closes post-intent"
        ),
        Err(_) => panic!("driver never noticed the post-intent link close"),
    }
}

#[tokio::test]
async fn dropping_the_leave_intent_sender_without_signaling_does_not_affect_the_driver() {
    // An unclean teardown (the process dying, or a caller that never wires
    // leave-intent up) drops the sender without ever signaling. The driver
    // must keep running exactly as if leave-intent didn't exist — proven
    // here by still forwarding a turn afterward.
    let (link_a, mut link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    drop(chan_a.leave_intent);

    chan_a.outbound.send(turn(0, &[0x33])).await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(5), link_b.recv())
        .await
        .expect("driver stopped forwarding turns after its leave-intent sender was dropped")
        .unwrap();
    assert_eq!(received.fresh[0].commands[0], 0x33);

    drop(chan_a.outbound);
    drop(chan_a.inbound);
    let _ = task.await;
}

#[tokio::test]
async fn a_result_is_sent_immediately_over_a_live_link() {
    // A result report goes out the moment the game hands it over — mid-game,
    // with nothing draining and no leave signalled — not after any wind-down.
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    // Watch the control stream the way the relay does.
    let mut control_rx = spawn_control_reader(link_b.connection().clone());

    chan_a.result.send(vec![0x0A, 0x0B, 0x0C]).await.unwrap();

    let frame = tokio::time::timeout(Duration::from_secs(1), control_rx.recv())
        .await
        .expect("the result frame never arrived")
        .expect("control reader ended early");
    match frame {
        ControlInbound::GameResult(payload) => {
            assert_eq!(payload.as_ref(), &[0x0A, 0x0B, 0x0C])
        }
        other => panic!("expected a result frame, got {other:?}"),
    }

    drop(chan_a.outbound);
    drop(chan_a.inbound);
    let _ = task.await;
}

#[tokio::test]
async fn a_game_started_signal_writes_exactly_one_frame() {
    // The game announces its loop starting; the driver writes one
    // `GameStarted` frame on the connection. A second signal on the same
    // connection writes nothing — proven by following it with a leave intent
    // and seeing that frame arrive next, with no second GameStarted in
    // between. (A *fresh* connection does re-assert it; that is a separate
    // test.)
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    // Watch the control stream the way the relay does.
    let mut control_rx = spawn_control_reader(link_b.connection().clone());

    chan_a.game_started.send(()).await.unwrap();

    let frame = tokio::time::timeout(Duration::from_secs(1), control_rx.recv())
        .await
        .expect("the game-started frame never arrived")
        .expect("control reader ended early");
    assert!(
        matches!(frame, ControlInbound::GameStarted),
        "expected a game-started frame, got {frame:?}",
    );

    // A second announcement is dropped: the next frame on the wire is the
    // leave intent signalled after it, not another GameStarted.
    chan_a.game_started.send(()).await.unwrap();
    chan_a.leave_intent.send(()).await.unwrap();

    let next = tokio::time::timeout(Duration::from_secs(2), control_rx.recv())
        .await
        .expect("the leave intent never arrived")
        .expect("control reader ended early");
    assert!(
        matches!(next, ControlInbound::LeaveIntent),
        "a repeat game-started must be dropped, got {next:?}",
    );

    drop(chan_a.outbound);
    drop(chan_a.inbound);
    let _ = task.await;
}

#[tokio::test]
async fn a_fence_probe_pushes_a_signalled_game_started_ahead_of_its_ack() {
    // The fence's whole claim: whatever the game had signalled before the
    // probe was handled is on the wire AHEAD of the ack, so a relay that has
    // seen the ack cannot still be owed the report. The signal here is
    // deliberately not given time to be picked up by the live arm — it is
    // raced against the probe — because that race is the case the fence
    // exists for.
    use rally_point_transport::control::send_control_load_state_probe;

    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());
    let mut control_rx = spawn_control_reader(link_b.connection().clone());
    let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();

    chan_a.game_started.send(()).await.unwrap();
    send_control_load_state_probe(&mut peer_control_send, 0xABCD)
        .await
        .unwrap();

    let first = next_control_frame(&mut control_rx, "no frame answered the fence probe").await;
    assert!(
        matches!(first, ControlInbound::GameStarted),
        "the owed report must precede the ack, got {first:?}",
    );
    let second = next_control_frame(&mut control_rx, "the fence ack never arrived").await;
    assert!(
        matches!(second, ControlInbound::LoadStateProbeAck(0xABCD)),
        "expected the fence ack echoing the probe id, got {second:?}",
    );

    drop(chan_a.outbound);
    drop(chan_a.inbound);
    let _ = task.await;
}

#[tokio::test]
async fn a_fence_probe_with_nothing_owed_is_answered_by_the_ack_alone() {
    // A slot whose game has not started owes nothing, so the ack stands on
    // its own — the relay must be able to tell "nothing queued" from "a
    // report is on its way". Proven by following the ack with a leave intent
    // and seeing that arrive next, with no GameStarted in between.
    use rally_point_transport::control::send_control_load_state_probe;

    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());
    let mut control_rx = spawn_control_reader(link_b.connection().clone());
    let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();

    send_control_load_state_probe(&mut peer_control_send, 7)
        .await
        .unwrap();
    let frame = next_control_frame(&mut control_rx, "the fence ack never arrived").await;
    assert!(
        matches!(frame, ControlInbound::LoadStateProbeAck(7)),
        "expected the fence ack, got {frame:?}",
    );

    chan_a.leave_intent.send(()).await.unwrap();
    let next = next_control_frame(&mut control_rx, "the leave intent never arrived").await;
    assert!(
        matches!(next, ControlInbound::LeaveIntent),
        "an unstarted slot must announce nothing before its ack, got {next:?}",
    );

    drop(chan_a.outbound);
    drop(chan_a.inbound);
    let _ = task.await;
}

#[tokio::test]
async fn a_game_started_after_an_unfenced_probe_still_reaches_the_relay() {
    // Answering a probe must not consume the announcement path: a slot that
    // starts after the fence ran still reports, on the ordinary live path, so
    // a later read sees it.
    use rally_point_transport::control::send_control_load_state_probe;

    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());
    let mut control_rx = spawn_control_reader(link_b.connection().clone());
    let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();

    send_control_load_state_probe(&mut peer_control_send, 1)
        .await
        .unwrap();
    let frame = next_control_frame(&mut control_rx, "the fence ack never arrived").await;
    assert!(
        matches!(frame, ControlInbound::LoadStateProbeAck(1)),
        "expected the fence ack, got {frame:?}",
    );

    chan_a.game_started.send(()).await.unwrap();
    let frame = next_control_frame(&mut control_rx, "the later game-started never arrived").await;
    assert!(
        matches!(frame, ControlInbound::GameStarted),
        "expected the game-started frame, got {frame:?}",
    );

    drop(chan_a.outbound);
    drop(chan_a.inbound);
    let _ = task.await;
}

#[tokio::test]
async fn a_game_started_announcement_is_reasserted_on_the_reconnects_control_stream() {
    // The relay latches the report per link, so its copy dies with the link
    // that carried it. The announcement is a fact about the session, so the
    // driver re-asserts it on every control stream it opens — without that, a
    // report delivered moments before a drop leaves the tenant looking at a
    // slot that never started.
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let (link, seam, state) = into_session_parts(driver_a);
    let mut control_rx = spawn_control_reader(link_b.connection().clone());

    chan_a.game_started.send(()).await.unwrap();
    let session = spawn_session(link, seam, state);
    let frame = next_control_frame(&mut control_rx, "the game-started frame never arrived").await;
    assert!(
        matches!(frame, ControlInbound::GameStarted),
        "expected a game-started frame, got {frame:?}",
    );

    // The link dies under the driver, exactly as a real outage does; the game
    // seam stays open, so the reconnect path would re-dial here.
    link_b.connection().close(0u32.into(), b"outage");
    let (result, mut link, seam, state) = session.await.unwrap();
    assert!(result.is_err(), "the closed connection ends the session");

    // The re-dial: a fresh connection rebound in place, keeping the loop state
    // — which is where the announcement lives.
    let (link_c, link_d, _ec, _ed) = connected_links().await;
    link.rebind(link_c.connection().clone());
    let mut control_rx = spawn_control_reader(link_d.connection().clone());
    let session = spawn_session(link, seam, state);

    let frame = next_control_frame(&mut control_rx, "the announcement was never re-asserted").await;
    assert!(
        matches!(frame, ControlInbound::GameStarted),
        "the fresh control stream must carry the announcement again, got {frame:?}",
    );

    drop(chan_a);
    let _ = session.await;
}

#[tokio::test]
async fn a_game_started_signal_during_the_reconnect_gap_is_delivered_on_the_next_link() {
    // The game's loop can start while the driver is between links. Nothing is
    // listening then, so the signal waits in its channel and the next session
    // picks it up — losing it would be indistinguishable from a client that
    // never loaded.
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let (link, seam, state) = into_session_parts(driver_a);

    let session = spawn_session(link, seam, state);
    link_b.connection().close(0u32.into(), b"outage");
    let (result, mut link, seam, state) = session.await.unwrap();
    assert!(result.is_err(), "the closed connection ends the session");

    // Between links: the game announces its loop with no connection to carry
    // it.
    chan_a.game_started.send(()).await.unwrap();

    let (link_c, link_d, _ec, _ed) = connected_links().await;
    link.rebind(link_c.connection().clone());
    let mut control_rx = spawn_control_reader(link_d.connection().clone());
    let session = spawn_session(link, seam, state);

    let frame = next_control_frame(
        &mut control_rx,
        "a signal made during the outage never reached the relay",
    )
    .await;
    assert!(
        matches!(frame, ControlInbound::GameStarted),
        "expected a game-started frame, got {frame:?}",
    );

    drop(chan_a);
    let _ = session.await;
}

#[tokio::test]
async fn a_result_is_written_before_the_leave_intent_when_both_are_signalled() {
    // The ordering invariant: with a result expected, the game hands over the
    // payload and signals its departure; the driver must write the result
    // frame ahead of the leave-intent frame on the one ordered control stream,
    // regardless of which channel it services first.
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    let mut control_rx = spawn_control_reader(link_b.connection().clone());

    // The game marks a result expected before it can signal a leave, hands
    // over the payload, then signals its departure.
    chan_a.result_expected.store(true, Ordering::Relaxed);
    chan_a.result.send(vec![0xAA, 0xBB]).await.unwrap();
    chan_a.leave_intent.send(()).await.unwrap();

    let first = tokio::time::timeout(Duration::from_secs(2), control_rx.recv())
        .await
        .expect("the result frame never arrived")
        .expect("control reader ended early");
    match first {
        ControlInbound::GameResult(payload) => assert_eq!(payload.as_ref(), &[0xAA, 0xBB]),
        other => panic!("expected the result frame first, got {other:?}"),
    }

    let second = tokio::time::timeout(Duration::from_secs(2), control_rx.recv())
        .await
        .expect("the leave intent never arrived")
        .expect("control reader ended early");
    assert!(
        matches!(second, ControlInbound::LeaveIntent),
        "the leave intent must follow the result on the wire",
    );

    drop(chan_a.outbound);
    drop(chan_a.inbound);
    let _ = task.await;
}

#[tokio::test]
async fn the_leave_intent_still_goes_out_after_the_timeout_when_no_result_arrives() {
    // The game marked a result expected but never hands one over. The intent
    // must not be held forever — the leave-intent safety timeout fires and it
    // goes out anyway, since a missing or late result is harmless.
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    let mut control_rx = spawn_control_reader(link_b.connection().clone());

    chan_a.result_expected.store(true, Ordering::Relaxed);
    let before = tokio::time::Instant::now();
    chan_a.leave_intent.send(()).await.unwrap();

    let frame = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
        .await
        .expect("leave intent never arrived")
        .expect("control reader ended early");
    assert!(matches!(frame, ControlInbound::LeaveIntent));
    assert!(
        before.elapsed() >= LEAVE_INTENT_TIMEOUT,
        "the intent went out before the result-hold timeout elapsed",
    );

    drop(chan_a.outbound);
    drop(chan_a.inbound);
    let _ = task.await;
}
