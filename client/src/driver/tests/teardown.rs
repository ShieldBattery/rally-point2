//! Closing down: the send-phase hold queue's interaction with a seam drop,
//! the final-turn fences a game close runs, and the clean-stop paths.

use super::*;

#[tokio::test]
async fn a_phase_directive_holds_the_wire_handoff_without_reordering() {
    // The relay commands a 30 ms send-phase delay. The driver must adopt
    // it (visible on the status watch), slew into it rather than stepping,
    // and keep every held turn in production order on the wire.
    let mut fixture = DriverFixture::new().await;
    fixture.command_phase_delay(30_000).await;

    // The directive is acknowledged upstream, echoing the commanded delay —
    // the relay releases this slot's command fence on the match.
    let acked = fixture
        .next_control_frame("the acknowledgement reaches the peer before the timeout")
        .await;
    assert!(
        matches!(acked, ControlInbound::PhaseApplied(30_000)),
        "expected the phase-applied echo, got {acked:?}"
    );

    // Let the slew accumulate real delay, then send a burst. The applied
    // delay climbs at the clamped ceiling of 10 ms per second, so this buys
    // a couple of milliseconds: enough that every turn takes the hold-queue
    // path, nowhere near the 30 ms a step would have jumped straight to.
    tokio::time::sleep(Duration::from_millis(200)).await;
    for i in 0..3u8 {
        fixture.chan.outbound.send(turn(0, &[i])).await.unwrap();
    }
    let mut seen = Vec::new();
    while seen.len() < 3 {
        let received = tokio::time::timeout(Duration::from_secs(5), fixture.peer.recv())
            .await
            .expect("the held turns reach the wire before the timeout")
            .expect("the peer link stays up");
        for payload in received.fresh {
            seen.push((payload.seq, payload.commands[0]));
        }
    }
    assert_eq!(seen, vec![(0, 0), (1, 1), (2, 2)]);

    // The applied delay really slewed: nonzero (the burst was held, not
    // sent instantly) yet nowhere near the target a step would have hit —
    // the clamped maximum rate can only cover a fraction of 30 ms so far.
    let status = *fixture.chan.phase_status.borrow();
    assert!(
        status.applied_us > 0 && status.applied_us < 30_000,
        "applied delay mid-slew, got {status:?}"
    );

    fixture.finish().await;
}

/// How big the final turn a teardown must still deliver is, which decides which
/// fence has to hold the connection open for it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FinalTurn {
    /// A datagram-sized turn: the unacked-window settle fence covers it.
    Datagram,
    /// A turn too large for any datagram, so it drains onto the reliable
    /// control stream — where a successful write proves nothing about receipt,
    /// so the stream fence must hold the connection open until the peer has
    /// actually read it.
    Oversize,
}

/// Drives the "hand the final turn over, then drop the seam" teardown and
/// asserts the turn still reaches the peer. `slewed` controls whether a
/// send-phase delay is in force (exercising the hold-queue drain) or not
/// (exercising the live arm / outbound drain); `beat` is how long the game
/// waits between the send and the drop — zero races the closed-seam select
/// arms against `outbound.recv` on purpose, so the turn may still be sitting
/// unread in the channel when teardown begins.
async fn final_turn_survives_seam_drop(size: FinalTurn, slewed: bool, beat: Duration) {
    let mut fixture = DriverFixture::new().await;
    if slewed {
        fixture.slewed_session(30_000).await;
    }

    let commands = match size {
        FinalTurn::Datagram => vec![0x2A],
        FinalTurn::Oversize => vec![0x77; 4096],
    };
    fixture
        .chan
        .outbound
        .send(turn(0, &commands))
        .await
        .unwrap();
    if !beat.is_zero() {
        tokio::time::sleep(beat).await;
    }
    drop(fixture.chan);

    match size {
        FinalTurn::Datagram => {
            let received = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let received = fixture.peer.recv().await.expect("peer link stays up");
                    if !received.fresh.is_empty() {
                        break received;
                    }
                }
            })
            .await
            .expect("the final turn reaches the wire despite the close");
            assert_eq!(received.fresh[0].seq, 0);
            assert_eq!(&received.fresh[0].commands[..], &commands[..]);
        }
        FinalTurn::Oversize => {
            // A phase directive's own acknowledgement echo can precede the turn
            // on the stream; skip past anything that isn't the turn itself.
            let payload = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match fixture
                        .control_rx
                        .recv()
                        .await
                        .expect("control reader closed early")
                    {
                        ControlInbound::OversizeTurn(payload) => break payload,
                        _ => continue,
                    }
                }
            })
            .await
            .expect("the oversize turn reaches the control stream despite the close");
            assert_eq!(payload.seq, 0);
            assert_eq!(&payload.commands[..], &commands[..]);
        }
    }

    tokio::time::timeout(Duration::from_secs(5), fixture.task)
        .await
        .expect("the driver stops after draining")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_game_close_flushes_a_turn_already_moved_into_the_hold_queue() {
    final_turn_survives_seam_drop(FinalTurn::Datagram, true, Duration::from_millis(1)).await;
}

#[tokio::test]
async fn a_game_close_flushes_a_turn_still_queued_in_the_outbound_channel() {
    // No beat: the closed-seam arms race `outbound.recv`, and whichever
    // wins, the turn must reach the wire.
    final_turn_survives_seam_drop(FinalTurn::Datagram, true, Duration::ZERO).await;
}

#[tokio::test]
async fn a_game_close_fences_a_zero_delay_final_datagram() {
    // No phase delay at all: the final turn goes (or is drained) straight
    // to a datagram, and the teardown fence must keep the connection open
    // until it is acked rather than let the close outrun it.
    final_turn_survives_seam_drop(FinalTurn::Datagram, false, Duration::ZERO).await;
}

#[tokio::test]
async fn a_game_close_delivers_an_oversize_held_turn() {
    // The stream fence reached via the *held* drain: the oversize turn is
    // already in the hold queue when the seam drops.
    final_turn_survives_seam_drop(FinalTurn::Oversize, true, Duration::from_millis(1)).await;
}

#[tokio::test]
async fn a_game_close_fences_a_zero_delay_oversize_turn() {
    // The same fence reached the other way: with no phase delay an oversize
    // final turn goes straight onto the reliable control stream from the live
    // arm (or from the teardown drain, if the closed-seam arms win the race).
    final_turn_survives_seam_drop(FinalTurn::Oversize, false, Duration::ZERO).await;
}

#[tokio::test]
async fn a_last_moment_leave_intent_still_completes_the_clean_leave() {
    // The game hands over its final turn, signals its clean leave, and
    // drops the seam in one motion. The intent was withheld while the
    // turn was outstanding; teardown must still send it once the turn is
    // fenced, or the relay books the departure as a dropped link.
    let mut fixture = DriverFixture::new().await;
    // Enough slew that the turn below is still held when the seam drops, so
    // the intent is genuinely withheld.
    fixture.slewed_session(30_000).await;

    fixture.chan.outbound.send(turn(0, &[0x2A])).await.unwrap();
    fixture.chan.leave_intent.send(()).await.unwrap();
    drop(fixture.chan);

    let mut saw_intent = false;
    let mut saw_turn = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !(saw_intent && saw_turn) {
        tokio::select! {
            delivered = fixture.control_rx.recv() => {
                match delivered {
                    Some(ControlInbound::LeaveIntent) => saw_intent = true,
                    Some(_) => {}
                    None => break,
                }
            }
            received = fixture.peer.recv() => {
                if let Ok(received) = received
                    && !received.fresh.is_empty()
                {
                    assert_eq!(received.fresh[0].commands[0], 0x2A);
                    saw_turn = true;
                }
            }
            () = tokio::time::sleep_until(deadline) => break,
        }
    }
    assert!(saw_turn, "the final turn reached the wire");
    assert!(saw_intent, "the clean-leave intent reached the wire");

    tokio::time::timeout(Duration::from_secs(5), fixture.task)
        .await
        .expect("the driver stops after the handshake")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_stalled_game_consumer_surfaces_instead_of_hanging() {
    // A depth-1 inbound buffer and a receiver that never drains: once it fills,
    // the driver must report the stall, not block its whole loop on the wedged
    // consumer (which would also freeze acks and link-failure detection). The
    // game's channels are held, untouched, for the whole test.
    let mut fixture = DriverFixture::with_capacity(1).await;

    // Several turns from the peer: with a depth-1 buffer and no draining, the
    // driver fills it and then has nowhere to put the next one.
    for i in 0..4u8 {
        fixture.peer.send(Some(turn(i as u64, &[i]))).unwrap();
    }

    match tokio::time::timeout(Duration::from_secs(5), fixture.task).await {
        Ok(joined) => assert!(matches!(joined.unwrap(), Err(DriverError::GameStalled))),
        Err(_) => panic!("driver hung on a stalled consumer instead of surfacing it"),
    }

    // A terminal error ends the driver, and the ended driver must not keep
    // holding its relay-side slot: the peer sees a deliberate close, not a
    // connection lingering until the QUIC idle timeout.
    let closed = tokio::time::timeout(Duration::from_secs(5), fixture.peer.connection().closed())
        .await
        .expect("the ended driver never closed its connection");
    assert!(
        matches!(closed, noq::ConnectionError::ApplicationClosed(_)),
        "closed deliberately by the driver, not lost: {closed:?}",
    );
}

#[tokio::test]
async fn stops_cleanly_when_the_game_drops_its_sender() {
    // No turns ever sent; dropping the seam is the game tearing down. A clean
    // exit must also actually close the connection rather than leave it open
    // until QUIC's own idle timeout — the driver's own link is owned by its
    // task and unobservable afterward, so the peer's connection ending is the
    // one place that close is visible. Before the fix this timed out: the
    // beacon and control-stream reader tasks each held their own
    // `connection.clone()` parked on `accept_*`, so nothing ever told the peer
    // the link was actually done.
    let fixture = DriverFixture::new().await;
    let peer_connection = fixture.peer.connection().clone();

    fixture.finish().await;

    match tokio::time::timeout(Duration::from_secs(5), peer_connection.closed()).await {
        Ok(_reason) => {}
        Err(_) => panic!(
            "the peer never observed the connection end -- the driver's clean exit \
             did not actually close it"
        ),
    }
}

#[tokio::test]
async fn stops_cleanly_when_the_game_drops_its_receiver() {
    // The game drops only its receiver on a quiet link: no turn is ever delivered
    // through which a failed send could surface the closure, so the driver must
    // notice it on its own and stop — otherwise the connection (and relay slot)
    // would leak. The sender is kept alive to the end so the stop is via the
    // dropped receiver, not the dropped sender.
    let fixture = DriverFixture::new().await;
    drop(fixture.chan.inbound);

    match tokio::time::timeout(Duration::from_secs(5), fixture.task).await {
        Ok(joined) => assert!(joined.unwrap().is_ok()),
        Err(_) => panic!("driver kept running after its receiver was dropped"),
    }
    drop(fixture.chan.outbound);
}
