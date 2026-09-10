//! Closing down: the send-phase hold queue's interaction with a seam drop,
//! the final-turn fences a game close runs, and the clean-stop paths.

use super::*;

#[tokio::test]
async fn a_phase_directive_holds_the_wire_handoff_without_reordering() {
    // The relay commands a 30 ms send-phase delay. The driver must adopt
    // it (visible on the status watch), slew into it rather than stepping,
    // and keep every held turn in production order on the wire.
    use rally_point_proto::messages::PhaseDirective;
    use rally_point_transport::control::send_control_phase_directive;

    let (link_a, mut link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());
    let mut control_rx = spawn_control_reader(link_b.connection().clone());

    let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();
    // An absurd slew rate proves the client clamps rather than trusts it.
    send_control_phase_directive(
        &mut peer_control_send,
        PhaseDirective {
            delay_us: 30_000,
            slew_us_per_s: 1_000_000,
        },
    )
    .await
    .unwrap();

    // The directive lands: the status watch shows the adopted target.
    let mut status_rx = chan_a.phase_status.clone();
    tokio::time::timeout(
        Duration::from_secs(5),
        status_rx.wait_for(|status| status.target_us == 30_000),
    )
    .await
    .expect("the directive reaches the driver before the timeout")
    .expect("the status watch stays open");
    // And is acknowledged upstream, echoing the commanded delay — the
    // relay releases this slot's command fence on the match.
    let acked = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
        .await
        .expect("the acknowledgement reaches the peer before the timeout")
        .expect("control reader closed early");
    assert!(
        matches!(acked, ControlInbound::PhaseApplied(30_000)),
        "expected the phase-applied echo, got {acked:?}"
    );

    // Let the slew accumulate a few milliseconds of real delay, then send
    // a burst. Every turn takes the hold-queue path and must still leave
    // in production order with contiguous driver-stamped seqs.
    tokio::time::sleep(Duration::from_millis(600)).await;
    for i in 0..3u8 {
        chan_a.outbound.send(turn(0, &[i])).await.unwrap();
    }
    let mut seen = Vec::new();
    while seen.len() < 3 {
        let received = tokio::time::timeout(Duration::from_secs(5), link_b.recv())
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
    let status = *status_rx.borrow();
    assert!(
        status.applied_us > 0 && status.applied_us < 30_000,
        "applied delay mid-slew, got {status:?}"
    );

    drop(chan_a);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the driver stops once the game seam closes")
        .unwrap()
        .unwrap();
}

/// Drives the "hand the final turn over, then drop the seam" teardown and
/// asserts the turn still reaches the peer. `slewed` controls whether a
/// send-phase delay is in force (exercising the hold-queue drain) or not
/// (exercising the just-sent-datagram fence); `beat` is how long the game
/// waits between the send and the drop — zero races the closed-seam
/// select arms against `outbound.recv` on purpose, so the turn may still
/// be sitting unread in the channel when teardown begins.
async fn final_turn_survives_seam_drop(slewed: bool, beat: Duration) {
    use rally_point_proto::messages::PhaseDirective;
    use rally_point_transport::control::send_control_phase_directive;

    let (link_a, mut link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();
    if slewed {
        send_control_phase_directive(
            &mut peer_control_send,
            PhaseDirective {
                delay_us: 30_000,
                slew_us_per_s: 1_000_000,
            },
        )
        .await
        .unwrap();
        let mut status_rx = chan_a.phase_status.clone();
        tokio::time::timeout(
            Duration::from_secs(5),
            status_rx.wait_for(|status| status.target_us == 30_000),
        )
        .await
        .expect("the directive reaches the driver")
        .expect("the status watch stays open");
        // Let the slew build a delay comfortably larger than the beat.
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    chan_a.outbound.send(turn(0, &[0x2A])).await.unwrap();
    if !beat.is_zero() {
        tokio::time::sleep(beat).await;
    }
    drop(chan_a);

    let received = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let received = link_b.recv().await.expect("peer link stays up");
            if !received.fresh.is_empty() {
                break received;
            }
        }
    })
    .await
    .expect("the final turn reaches the wire despite the close");
    assert_eq!(received.fresh[0].seq, 0);
    assert_eq!(received.fresh[0].commands[0], 0x2A);

    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the driver stops after draining")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_game_close_flushes_a_turn_already_moved_into_the_hold_queue() {
    final_turn_survives_seam_drop(true, Duration::from_millis(5)).await;
}

#[tokio::test]
async fn a_game_close_flushes_a_turn_still_queued_in_the_outbound_channel() {
    // No beat: the closed-seam arms race `outbound.recv`, and whichever
    // wins, the turn must reach the wire.
    final_turn_survives_seam_drop(true, Duration::ZERO).await;
}

#[tokio::test]
async fn a_game_close_fences_a_zero_delay_final_datagram() {
    // No phase delay at all: the final turn goes (or is drained) straight
    // to a datagram, and the teardown fence must keep the connection open
    // until it is acked rather than let the close outrun it.
    final_turn_survives_seam_drop(false, Duration::ZERO).await;
}

#[tokio::test]
async fn a_game_close_delivers_an_oversize_held_turn() {
    // An oversize final turn drains onto the reliable control stream at
    // teardown; a successful write proves nothing about receipt, so the
    // stream fence must hold the connection open until the peer has read
    // it.
    use rally_point_proto::messages::PhaseDirective;
    use rally_point_transport::control::send_control_phase_directive;

    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());
    let mut control_rx = spawn_control_reader(link_b.connection().clone());

    let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();
    send_control_phase_directive(
        &mut peer_control_send,
        PhaseDirective {
            delay_us: 30_000,
            slew_us_per_s: 1_000_000,
        },
    )
    .await
    .unwrap();
    let mut status_rx = chan_a.phase_status.clone();
    tokio::time::timeout(
        Duration::from_secs(5),
        status_rx.wait_for(|status| status.target_us == 30_000),
    )
    .await
    .expect("the directive reaches the driver")
    .expect("the status watch stays open");
    tokio::time::sleep(Duration::from_secs(2)).await;

    chan_a.outbound.send(turn(0, &[0x77; 4096])).await.unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    drop(chan_a);

    // The directive's own acknowledgement echo precedes the turn on the
    // stream; skip past anything that isn't the turn itself.
    let payload = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match control_rx
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
    assert_eq!(payload.commands.len(), 4096);

    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the driver stops after draining")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_game_close_fences_a_zero_delay_oversize_turn() {
    // With no phase delay, an oversize final turn goes straight onto the
    // reliable control stream from the live arm (or from the teardown
    // drain, if the closed-seam arms win the race) — and either way a
    // successful write proves nothing about receipt, so the stream fence
    // must hold the connection open until the peer has read it.
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());
    let mut control_rx = spawn_control_reader(link_b.connection().clone());

    chan_a.outbound.send(turn(0, &[0x66; 4096])).await.unwrap();
    drop(chan_a);

    let delivered = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
        .await
        .expect("the oversize turn reaches the control stream despite the close")
        .expect("control reader closed early");
    match delivered {
        ControlInbound::OversizeTurn(payload) => {
            assert_eq!(payload.seq, 0);
            assert_eq!(payload.commands.len(), 4096);
        }
        other => panic!("expected the oversize turn, got {other:?}"),
    }

    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the driver stops after the fence")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_last_moment_leave_intent_still_completes_the_clean_leave() {
    // The game hands over its final turn, signals its clean leave, and
    // drops the seam in one motion. The intent was withheld while the
    // turn was outstanding; teardown must still send it once the turn is
    // fenced, or the relay books the departure as a dropped link.
    use rally_point_proto::messages::PhaseDirective;
    use rally_point_transport::control::send_control_phase_directive;

    let (link_a, mut link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());
    let mut control_rx = spawn_control_reader(link_b.connection().clone());

    let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();
    send_control_phase_directive(
        &mut peer_control_send,
        PhaseDirective {
            delay_us: 30_000,
            slew_us_per_s: 1_000_000,
        },
    )
    .await
    .unwrap();
    let mut status_rx = chan_a.phase_status.clone();
    tokio::time::timeout(
        Duration::from_secs(5),
        status_rx.wait_for(|status| status.target_us == 30_000),
    )
    .await
    .expect("the directive reaches the driver")
    .expect("the status watch stays open");
    tokio::time::sleep(Duration::from_secs(2)).await;

    chan_a.outbound.send(turn(0, &[0x2A])).await.unwrap();
    chan_a.leave_intent.send(()).await.unwrap();
    drop(chan_a);

    let mut saw_intent = false;
    let mut saw_turn = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !(saw_intent && saw_turn) {
        tokio::select! {
            delivered = control_rx.recv() => {
                match delivered {
                    Some(ControlInbound::LeaveIntent) => saw_intent = true,
                    Some(_) => {}
                    None => break,
                }
            }
            received = link_b.recv() => {
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

    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the driver stops after the handshake")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_stalled_game_consumer_surfaces_instead_of_hanging() {
    // A depth-1 inbound buffer and a receiver that never drains: once it fills,
    // the driver must report the stall, not block its whole loop on the wedged
    // consumer (which would also freeze acks and link-failure detection).
    let (link_a, mut link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::with_capacity(link_a, 1);
    let task = tokio::spawn(driver_a.run());

    // Hold the inbound receiver open without ever draining it.
    let _inbound = chan_a.inbound;

    // Several turns from the peer: with a depth-1 buffer and no draining, the
    // driver fills it and then has nowhere to put the next one.
    for i in 0..4u8 {
        link_b.send(Some(turn(i as u64, &[i]))).unwrap();
    }

    match tokio::time::timeout(Duration::from_secs(5), task).await {
        Ok(joined) => assert!(matches!(joined.unwrap(), Err(DriverError::GameStalled))),
        Err(_) => panic!("driver hung on a stalled consumer instead of surfacing it"),
    }

    // A terminal error ends the driver, and the ended driver must not keep
    // holding its relay-side slot: the peer sees a deliberate close, not a
    // connection lingering until the QUIC idle timeout.
    let closed = tokio::time::timeout(Duration::from_secs(5), link_b.connection().closed())
        .await
        .expect("the ended driver never closed its connection");
    assert!(
        matches!(closed, noq::ConnectionError::ApplicationClosed(_)),
        "closed deliberately by the driver, not lost: {closed:?}",
    );
}

#[tokio::test]
async fn stops_cleanly_when_the_game_drops_its_sender() {
    let (link_a, _link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    // No turns ever sent; dropping the seam is the game tearing down.
    drop(chan_a.outbound);
    drop(chan_a.inbound);
    assert!(task.await.unwrap().is_ok());
}

#[tokio::test]
async fn stops_cleanly_when_the_game_drops_its_receiver() {
    let (link_a, _link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    // The game drops only its receiver on a quiet link: no turn is ever delivered
    // through which a failed send could surface the closure, so the driver must
    // notice it on its own and stop — otherwise the connection (and relay slot)
    // would leak. The sender is kept alive to the end so the stop is via the
    // dropped receiver, not the dropped sender.
    drop(chan_a.inbound);

    match tokio::time::timeout(Duration::from_secs(5), task).await {
        Ok(joined) => assert!(joined.unwrap().is_ok()),
        Err(_) => panic!("driver kept running after its receiver was dropped"),
    }
    drop(chan_a.outbound);
}

/// A clean driver exit actually closes the connection, rather than
/// leaving it open until QUIC's own idle timeout. `link_a` itself is
/// moved into the spawned driver task and unobservable afterward, so
/// this checks the one place the close is externally visible: the
/// peer's own connection sees it end. Before the fix, this timed out —
/// the beacon and control-stream reader tasks each held their own
/// `connection.clone()` parked on `accept_*`, so nothing ever told the
/// peer the link was actually done.
#[tokio::test]
async fn a_clean_stop_closes_the_connection_so_the_peer_observes_it_end() {
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let peer_connection = link_b.connection().clone();
    let task = tokio::spawn(driver_a.run());

    drop(chan_a.outbound);
    drop(chan_a.inbound);
    assert!(task.await.unwrap().is_ok());

    match tokio::time::timeout(Duration::from_secs(5), peer_connection.closed()).await {
        Ok(_reason) => {}
        Err(_) => panic!(
            "the peer never observed the connection end -- the driver's clean exit \
             did not actually close it"
        ),
    }
}
