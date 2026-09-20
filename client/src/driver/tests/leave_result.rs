//! The client's own announcements up the control stream: the clean leave
//! intent and what holds it, the end-of-game result report, and the
//! game-started signal (including its fence-probe and reconnect re-assertion).

use super::*;

#[tokio::test]
async fn leave_intent_is_sent_immediately_when_nothing_is_outstanding() {
    // With no turns ever produced, the outbound queue and unacked window
    // are already empty: the intent must go out the moment the game
    // signals, without waiting on anything to drain.
    let mut fixture = DriverFixture::new().await;

    fixture.chan.leave_intent.send(()).await.unwrap();

    let frame = fixture
        .next_control_frame("leave intent never arrived")
        .await;
    assert!(matches!(frame, ControlInbound::LeaveIntent));

    fixture.finish().await;
}

#[tokio::test]
async fn leave_intent_waits_for_unacked_turns_to_drain_before_sending() {
    // A turn is still unacked when the game signals its departure: the
    // intent must not go out until the fake relay acks it — the driver
    // holds off announcing until the relay's view of our last turn is
    // final.
    let (link_a, peer, ea, eb) = connected_links().await;
    let (driver_a, chan_a) = test_driver(link_a);
    // The one window this test keeps at its production length: it asserts the
    // intent is held back by the *drain* condition, so the safety timeout must
    // stay far beyond the windows below rather than being what releases it.
    // Nothing here ever waits it out, so its length costs no test time.
    let driver_a = driver_a.with_timing(DriverTiming {
        leave_intent_timeout: DriverTiming::default().leave_intent_timeout,
        ..TEST_TIMING
    });
    let mut fixture = DriverFixture::over(driver_a, chan_a, peer, ea, eb).await;

    // One turn goes out and the fake relay sees it, but deliberately
    // never acks it yet.
    fixture.chan.outbound.send(turn(0, &[0x11])).await.unwrap();
    let received = fixture.peer.recv().await.unwrap();
    assert_eq!(
        received.fresh[0].commands[0], 0x11,
        "the relay saw the turn"
    );

    // Signal departure now, while that turn is still unacked.
    fixture.chan.leave_intent.send(()).await.unwrap();

    // The intent must not arrive while anything is unacked.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), fixture.control_rx.recv())
            .await
            .is_err(),
        "leave intent sent before its last turn was acked"
    );

    // The fake relay's ack-only flush retires it.
    fixture.peer.send(None).unwrap();

    let frame = fixture
        .next_control_frame("leave intent never arrived after the ack")
        .await;
    assert!(matches!(frame, ControlInbound::LeaveIntent));

    fixture.finish().await;
}

/// What is holding a signalled leave intent back when the safety timeout has to
/// be the thing that releases it.
enum Hold {
    /// A turn the relay saw but never acked — the drain condition can never
    /// complete on its own.
    UnackedTurn,
    /// A result the game marked expected and then never handed over, which
    /// would otherwise keep the intent behind it on the ordered stream forever.
    UnsentResult,
}

#[tokio::test]
async fn the_safety_timeout_releases_a_held_leave_intent_whatever_is_holding_it() {
    // Either hold can last forever on its own, and neither may strand the
    // announcement: a late or missing result is harmless and a link whose acks
    // stopped is effectively dead already, while an unannounced departure gets
    // booked as a dropped link.
    for hold in [Hold::UnackedTurn, Hold::UnsentResult] {
        let mut fixture = DriverFixture::new().await;

        match hold {
            Hold::UnackedTurn => {
                fixture.chan.outbound.send(turn(0, &[0x22])).await.unwrap();
                let _seen_never_acked = fixture.peer.recv().await.unwrap();
            }
            Hold::UnsentResult => {
                fixture.chan.result_expected.store(true, Ordering::Relaxed);
            }
        }

        let before = tokio::time::Instant::now();
        fixture.chan.leave_intent.send(()).await.unwrap();

        let frame = fixture
            .next_control_frame("leave intent never arrived")
            .await;
        assert!(matches!(frame, ControlInbound::LeaveIntent));
        assert!(
            before.elapsed() >= TEST_TIMING.leave_intent_timeout,
            "the intent went out before the safety timeout elapsed",
        );

        fixture.finish().await;
    }
}

#[tokio::test]
async fn run_returns_ok_when_the_link_closes_after_the_leave_intent() {
    // Once the intent has gone out, the relay closing the link is the
    // expected confirmation it processed the leave: `run` must return
    // `Ok`, not surface a `DriverError`.
    let mut fixture = DriverFixture::new().await;

    fixture.chan.leave_intent.send(()).await.unwrap();
    let frame = fixture
        .next_control_frame("leave intent never arrived")
        .await;
    assert!(matches!(frame, ControlInbound::LeaveIntent));

    // The relay's confirmation is closing the link once it has processed
    // the intent — simulate that directly rather than the game dropping
    // its channels.
    fixture
        .peer
        .connection()
        .close(noq::VarInt::from_u32(0), b"leave processed");

    let joined = tokio::time::timeout(Duration::from_secs(5), fixture.task)
        .await
        .expect("driver never noticed the post-intent link close")
        .unwrap();
    assert!(
        joined.is_ok(),
        "run() must return Ok after the link closes post-intent"
    );
}

#[tokio::test]
async fn dropping_the_leave_intent_sender_without_signaling_does_not_affect_the_driver() {
    // An unclean teardown (the process dying, or a caller that never wires
    // leave-intent up) drops the sender without ever signaling. The driver
    // must keep running exactly as if leave-intent didn't exist — proven
    // here by still forwarding a turn afterward.
    let mut fixture = DriverFixture::new().await;
    drop(fixture.chan.leave_intent);

    fixture.chan.outbound.send(turn(0, &[0x33])).await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(5), fixture.peer.recv())
        .await
        .expect("driver stopped forwarding turns after its leave-intent sender was dropped")
        .unwrap();
    assert_eq!(received.fresh[0].commands[0], 0x33);

    drop(fixture.chan.outbound);
    drop(fixture.chan.inbound);
    let joined = tokio::time::timeout(Duration::from_secs(5), fixture.task)
        .await
        .expect("the driver stops once the game seam closes")
        .unwrap();
    assert!(joined.is_ok(), "a seam drop is a clean stop: {joined:?}");
}

#[tokio::test]
async fn a_result_is_sent_immediately_over_a_live_link() {
    // A result report goes out the moment the game hands it over — mid-game,
    // with nothing draining and no leave signalled — not after any wind-down.
    let mut fixture = DriverFixture::new().await;

    fixture
        .chan
        .result
        .send(vec![0x0A, 0x0B, 0x0C])
        .await
        .unwrap();

    let frame = fixture
        .next_control_frame("the result frame never arrived")
        .await;
    match frame {
        ControlInbound::GameResult(payload) => {
            assert_eq!(payload.as_ref(), &[0x0A, 0x0B, 0x0C])
        }
        other => panic!("expected a result frame, got {other:?}"),
    }

    fixture.finish().await;
}

#[tokio::test]
async fn a_game_started_signal_writes_exactly_one_frame() {
    // The game announces its loop starting; the driver writes one
    // `GameStarted` frame on the connection. A second signal on the same
    // connection writes nothing — proven by following it with a leave intent
    // and seeing that frame arrive next, with no second GameStarted in
    // between. (A *fresh* connection does re-assert it; that is a separate
    // test.)
    let mut fixture = DriverFixture::new().await;

    fixture.chan.game_started.send(()).await.unwrap();

    let frame = fixture
        .next_control_frame("the game-started frame never arrived")
        .await;
    assert!(
        matches!(frame, ControlInbound::GameStarted),
        "expected a game-started frame, got {frame:?}",
    );

    // A second announcement is dropped: the next frame on the wire is the
    // leave intent signalled after it, not another GameStarted.
    fixture.chan.game_started.send(()).await.unwrap();
    fixture.chan.leave_intent.send(()).await.unwrap();

    let next = fixture
        .next_control_frame("the leave intent never arrived")
        .await;
    assert!(
        matches!(next, ControlInbound::LeaveIntent),
        "a repeat game-started must be dropped, got {next:?}",
    );

    fixture.finish().await;
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

    let mut fixture = DriverFixture::new().await;

    fixture.chan.game_started.send(()).await.unwrap();
    send_control_load_state_probe(&mut fixture.peer_control, 0xABCD)
        .await
        .unwrap();

    let first = fixture
        .next_control_frame("no frame answered the fence probe")
        .await;
    assert!(
        matches!(first, ControlInbound::GameStarted),
        "the owed report must precede the ack, got {first:?}",
    );
    let second = fixture
        .next_control_frame("the fence ack never arrived")
        .await;
    assert!(
        matches!(second, ControlInbound::LoadStateProbeAck(0xABCD)),
        "expected the fence ack echoing the probe id, got {second:?}",
    );

    fixture.finish().await;
}

#[tokio::test]
async fn a_fence_probe_with_nothing_owed_is_answered_by_the_ack_alone() {
    // A slot whose game has not started owes nothing, so the ack stands on
    // its own — the relay must be able to tell "nothing queued" from "a
    // report is on its way". The ack being the *first* frame on the stream is
    // what proves nothing was pushed ahead of it.
    use rally_point_transport::control::send_control_load_state_probe;

    let mut fixture = DriverFixture::new().await;

    send_control_load_state_probe(&mut fixture.peer_control, 7)
        .await
        .unwrap();
    let frame = fixture
        .next_control_frame("the fence ack never arrived")
        .await;
    assert!(
        matches!(frame, ControlInbound::LoadStateProbeAck(7)),
        "expected the fence ack, got {frame:?}",
    );

    // And answering the probe must not have consumed the announcement path: a
    // slot that starts after the fence ran still reports, on the ordinary live
    // path, so a later read sees it.
    fixture.chan.game_started.send(()).await.unwrap();
    let next = fixture
        .next_control_frame("the later game-started never arrived")
        .await;
    assert!(
        matches!(next, ControlInbound::GameStarted),
        "a start after an unfenced probe must still reach the relay, got {next:?}",
    );

    fixture.finish().await;
}

#[tokio::test]
async fn a_game_started_announcement_is_reasserted_on_the_reconnects_control_stream() {
    // The relay latches the report per link, so its copy dies with the link
    // that carried it. The announcement is a fact about the session, so the
    // driver re-asserts it on every control stream it opens — without that, a
    // report delivered moments before a drop leaves the tenant looking at a
    // slot that never started.
    let (sessions, chan_a) = ReconnectSessions::start().await;
    let mut sessions = sessions;

    chan_a.game_started.send(()).await.unwrap();
    let frame = sessions
        .next_control_frame("the game-started frame never arrived")
        .await;
    assert!(
        matches!(frame, ControlInbound::GameStarted),
        "expected a game-started frame, got {frame:?}",
    );

    let mut sessions = sessions.reconnect().await;
    let frame = sessions
        .next_control_frame("the announcement was never re-asserted")
        .await;
    assert!(
        matches!(frame, ControlInbound::GameStarted),
        "the fresh control stream must carry the announcement again, got {frame:?}",
    );

    drop(chan_a);
    let _ = sessions.session.await;
}

#[tokio::test]
async fn a_game_started_signal_during_the_reconnect_gap_is_delivered_on_the_next_link() {
    // The game's loop can start while the driver is between links. Nothing is
    // listening then, so the signal waits in its channel and the next session
    // picks it up — losing it would be indistinguishable from a client that
    // never loaded. A different path from the re-assertion above: this signal
    // is taken by the next session's live arm, not replayed from the retained
    // announcement flag.
    let (sessions, chan_a) = ReconnectSessions::start().await;
    let mut sessions = sessions.reconnect().await;

    // Between links: the game announced its loop with no connection to carry
    // it, and the signal sat in its channel until this session came up.
    chan_a.game_started.send(()).await.unwrap();

    let frame = sessions
        .next_control_frame("a signal made during the outage never reached the relay")
        .await;
    assert!(
        matches!(frame, ControlInbound::GameStarted),
        "expected a game-started frame, got {frame:?}",
    );

    drop(chan_a);
    let _ = sessions.session.await;
}

#[tokio::test]
async fn a_result_is_written_before_the_leave_intent_when_both_are_signalled() {
    // The ordering invariant: with a result expected, the game hands over the
    // payload and signals its departure; the driver must write the result
    // frame ahead of the leave-intent frame on the one ordered control stream,
    // regardless of which channel it services first.
    let mut fixture = DriverFixture::new().await;

    // The game marks a result expected before it can signal a leave, hands
    // over the payload, then signals its departure.
    fixture.chan.result_expected.store(true, Ordering::Relaxed);
    fixture.chan.result.send(vec![0xAA, 0xBB]).await.unwrap();
    fixture.chan.leave_intent.send(()).await.unwrap();

    let first = fixture
        .next_control_frame("the result frame never arrived")
        .await;
    match first {
        ControlInbound::GameResult(payload) => assert_eq!(payload.as_ref(), &[0xAA, 0xBB]),
        other => panic!("expected the result frame first, got {other:?}"),
    }

    let second = fixture
        .next_control_frame("the leave intent never arrived")
        .await;
    assert!(
        matches!(second, ControlInbound::LeaveIntent),
        "the leave intent must follow the result on the wire",
    );

    fixture.finish().await;
}
