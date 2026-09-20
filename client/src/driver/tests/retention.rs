//! The retention ring across a resume: which turns are re-injected into the
//! unacked window, which are restaged onto the control stream, and the
//! own-slot anchors a same-relay resume and a re-home each declare.

use super::*;

#[tokio::test]
async fn rehome_anchor_extends_below_the_front_only_through_contiguous_unacked() {
    // The semantics of the contiguous descent (sparse windows, holes,
    // outgrown retention) are pinned at the AckManager level; this covers
    // the driver glue: the anchor comes from the link's contiguous
    // extension when retention exists, and falls back to the oldest
    // unacked seq when it does not.
    let (mut client, _server, _client_ep, _server_ep) = connected_links().await;
    for seq in 0..3u64 {
        client.send(Some(turn(seq, &[0x42]))).unwrap();
    }
    // Retention front at 1: the unacked run 0..=2 is contiguous, so the
    // descent covers the full tail below the front.
    assert_eq!(
        rehome_own_slot_anchor(&client, SlotId(0), Some(1)),
        Some(0),
        "a contiguous unacked tail below the front extends the anchor",
    );
    // No retention: fall back to the oldest unacked seq.
    assert_eq!(
        rehome_own_slot_anchor(&client, SlotId(0), None),
        Some(0),
        "without retention the oldest unacked seq anchors",
    );
    // Neither source: no anchor.
    assert_eq!(rehome_own_slot_anchor(&client, SlotId(3), None), None);
}

#[tokio::test]
async fn reinject_retention_defers_oversize_turns_to_the_control_stream() {
    // On a re-home, a retained turn that still fits a datagram re-enters the
    // unacked window for the redundancy pass to re-carry. One too big for any
    // datagram must not: build_outgoing skips it on every pass, so it would sit
    // in the window forever — never re-delivered and stalling a peer that never
    // got it from the dead relay. Such a turn is staged for the fresh control
    // stream instead, and it genuinely crosses that stream whole.
    let (mut link_a, link_b, _ea, _eb) = connected_links().await;
    let mut state = LoopState::new(Arc::new(AtomicBool::new(false)), TEST_TIMING);

    state.retention.push_back(turn(0, &[0x01]));
    state.retention.push_back(turn(1, &vec![0x42; 4096]));

    reinject_retention(&mut link_a, &mut state);

    // The datagram-sized turn re-entered the window; the oversize one did not.
    assert_eq!(
        link_a.payloads_in_flight(),
        1,
        "only the datagram-sized turn re-enters the unacked window",
    );
    assert_eq!(state.pending_control_redivert.len(), 1);
    assert_eq!(
        state.pending_control_redivert[0].seq, 1,
        "the oversize turn is staged for the control stream, not the window",
    );

    // The staged turn is carriable on the control stream: sent over a fresh
    // bi-stream it crosses whole, and the peer's control reader folds it back as
    // an oversize turn — exactly the divert path a first-time oversize turn takes.
    let mut control_rx = spawn_control_reader(link_b.connection().clone());
    let (mut control_send, _recv) = link_a.connection().open_bi().await.unwrap();
    let staged = state.pending_control_redivert.remove(0);
    send_control_turn(&mut control_send, staged).await.unwrap();
    let delivered = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
        .await
        .expect("the deferred oversize turn never crossed the control stream")
        .expect("control reader closed early");
    match delivered {
        ControlInbound::OversizeTurn(payload) => {
            assert_eq!(payload.seq, 1);
            assert_eq!(
                payload.commands.len(),
                4096,
                "the oversize turn arrives whole"
            );
        }
        other => panic!("expected an oversize turn on the control stream, got {other:?}"),
    }
}

#[tokio::test]
async fn same_relay_resume_redivers_only_the_oversize_retained_turns() {
    // On a SAME-relay resume (unlike a re-home), ordinary-sized retained
    // turns must NOT be touched at all — the relay already received
    // everything it acked, and re-injecting them
    // into the datagram window risks the permanent prefix gap
    // `reconnect_link`'s own same-relay anchor comment describes. Only
    // the oversize subset — which never rode the datagram/ack path and so
    // carries no such risk — gets staged for the resumed connection's
    // control stream.
    let (link_a, _link_b, _ea, _eb) = connected_links().await;
    let mut state = LoopState::new(Arc::new(AtomicBool::new(false)), TEST_TIMING);

    state.retention.push_back(turn(0, &[0x01])); // datagram-sized
    state.retention.push_back(turn(1, &vec![0x42; 4096])); // oversize

    redivert_oversize_retention_on_same_relay_resume(&link_a, &mut state);

    assert_eq!(
        link_a.payloads_in_flight(),
        0,
        "same-relay resume never touches the datagram/unacked window",
    );
    assert_eq!(state.pending_control_redivert.len(), 1);
    assert_eq!(state.pending_control_redivert[0].seq, 1);

    // A second call (mirroring a run of failed same-relay resumes before
    // one finally succeeds) does not re-stage an already-staged turn.
    redivert_oversize_retention_on_same_relay_resume(&link_a, &mut state);
    assert_eq!(
        state.pending_control_redivert.len(),
        1,
        "an already-staged oversize turn is not duplicated on a later resume",
    );
}

#[tokio::test]
async fn a_driver_that_sent_an_oversize_turn_retains_it_for_a_resume() {
    // The premise the same-relay redeliver rests on: an oversize turn rides the
    // control stream once and is never acked, so unless the driver keeps it in
    // the retention ring there is nothing left for a resume to re-stage — and a
    // drop between the local write succeeding and the relay processing it would
    // silently lose the turn, stalling every peer on its seq forever. (What the
    // resume then does with it is the redivert tests above.)
    let (link_a, _link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = test_driver(link_a);

    let oversize = turn(0, &vec![0x42; 4096]);
    chan_a.outbound.send(oversize.clone()).await.unwrap();
    drop(chan_a.outbound);
    let (mut link, mut seam, mut state) = driver_a.into_parts();
    LinkDriver::session(&mut link, &mut seam, &mut state, SlotId(0))
        .await
        .expect("session stops cleanly once the outbound seam closes");

    assert_eq!(
        state.retention.len(),
        1,
        "the oversize turn was retained when it was first sent",
    );
    assert_eq!(state.retention[0].commands.len(), 4096);
}

#[tokio::test]
async fn driver_sends_key_the_unacked_window_under_the_authorized_slot() {
    // The embedder leaves every outbound turn's slot at 0; the driver stamps its
    // own authorized slot at send. Without that stamp a client on slot 1 keys its
    // in-flight turns under a phantom slot 0, so `oldest_replayable_seq(SlotId(1))`
    // (what a same-relay resume anchors on) sees nothing, and the relay's
    // ack-beacon — which names the authorized slot — prunes nothing either, so the
    // window grows unbounded on beacon retirement alone. Stamped, the window keys
    // under slot 1, the anchor query finds the in-flight seqs, the stamp is what
    // actually rides the datagram, and a beacon under slot 1 retires.
    let (mut link, state, mut peer, _ea, _eb) =
        drive_unacked_session(SlotId(1), &[&[0x01], &[0x02], &[0x03]]).await;

    assert_eq!(state.next_outbound_seq, 3, "three turns were produced");
    assert_eq!(
        link.oldest_replayable_seq(SlotId(1)),
        Some(0),
        "the in-flight window keys under the authorized slot",
    );
    assert_eq!(
        link.oldest_replayable_seq(SlotId(0)),
        None,
        "nothing is stranded under the wire-claim slot 0",
    );
    assert_eq!(link.payloads_in_flight(), 3);

    // The same stamp rides the wire: an undriven peer reading the raw link sees
    // the authorized slot on each turn, not the embedder's 0.
    let mut seen = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while seen.len() < 3 {
            let received = peer.recv().await.expect("peer link errored");
            for payload in received.fresh {
                assert_eq!(payload.slot, 1, "the wire turn carries slot 1");
                seen.push((payload.seq, payload.commands[0]));
            }
        }
    })
    .await
    .expect("the stamped turns never reached the peer");
    seen.sort();
    assert_eq!(seen, vec![(0, 0x01), (1, 0x02), (2, 0x03)]);

    // A beacon naming the wire-claim slot 0 prunes nothing — the turns aren't
    // keyed there.
    assert_eq!(
        link.retire_through(SlotId(0), 2),
        0,
        "no driver-sent turn is keyed under slot 0",
    );

    // A beacon naming the authorized slot retires the confirmed prefix (seqs 0
    // and 1), leaving only seq 2 in flight.
    assert_eq!(
        link.retire_through(SlotId(1), 1),
        2,
        "the authorized-slot cursor retires the driver's confirmed turns",
    );
    assert_eq!(link.oldest_replayable_seq(SlotId(1)), Some(2));
    assert_eq!(link.payloads_in_flight(), 1);
}

#[tokio::test]
async fn same_relay_resume_anchors_at_the_oldest_in_flight_seq_for_a_nonzero_slot() {
    // The live deadlock's shape: a client on slot 1 leaves a turn in flight, the
    // link drops, and the same-relay re-dial must present an own-slot anchor at
    // the oldest still-unacked seq so the relay's fresh receive window admits the
    // re-carried turn. Before the slot stamp the anchor fell through to
    // `next_outbound_seq` (one past the in-flight turn), and the relay classified
    // the re-carried turn as already-delivered and dropped it — a permanent stall.
    let (link, state, _peer, _ea, _eb) =
        drive_unacked_session(SlotId(1), &[&[0x01], &[0x02]]).await;

    // The exact cursor set `reconnect_link` presents on a same-relay re-dial.
    let own_slot = SlotId(1);
    let cursors = same_relay_resume_cursors(
        &[],
        link.oldest_replayable_seq(own_slot),
        oldest_restaged_oversize(&state.retention),
        own_slot,
        state.next_outbound_seq,
    );

    assert_eq!(
        cursors,
        vec![(own_slot, 0)],
        "the anchor is the oldest in-flight seq, not next_outbound — and an \
         anchor of 0 is still PRESENTED: the cursor's presence is what asks \
         the relay to seed the fresh window's acked holes, which an anchor-0 \
         resume needs exactly as a nonzero one does",
    );
    assert_ne!(
        state.next_outbound_seq, 0,
        "the bug regressed: the anchor skipped past the in-flight turn",
    );
}

#[test]
fn same_relay_cursor_anchors_below_a_restaged_oversize_turn() {
    // An oversize turn rides the control stream, never the unacked window —
    // so a resume where it is the only thing left to re-send has no
    // replayable datagram seq at all. The anchor must still name it:
    // falling through to next_outbound_seq would base the relay's window
    // above it, and the control-stream restage would be discarded as a
    // duplicate — a permanent hole for every peer.
    let mut retention: VecDeque<Payload> = VecDeque::new();
    retention.push_back(turn(0, &vec![0x42; 4096])); // oversize, lost
    retention.push_back(turn(1, &[0x01])); // datagram-sized, acked

    let oversize = oldest_restaged_oversize(&retention);
    assert_eq!(
        oversize,
        Some(0),
        "only the oversize entry is a control-stream restage",
    );

    let own_slot = SlotId(1);
    assert_eq!(
        same_relay_resume_cursors(&[], None, oversize, own_slot, 2),
        vec![(own_slot, 0)],
        "with no datagram replay, the restaged oversize turn is the anchor",
    );
    // With both sources, the anchor is the older of the two.
    assert_eq!(
        same_relay_resume_cursors(&[], Some(5), Some(3), own_slot, 9),
        vec![(own_slot, 3)],
    );
    assert_eq!(
        same_relay_resume_cursors(&[], Some(2), Some(7), own_slot, 9),
        vec![(own_slot, 2)],
    );
}

#[tokio::test]
async fn staged_oversize_turns_survive_a_control_stream_send_failure_and_deliver_on_retry() {
    // A re-home stages oversize retained turns for the fresh connection's control
    // stream. If that connection drops again mid-drain, the unsent turns must not
    // be lost: `redivert_pending_control` keeps each staged until its send
    // succeeds, so a failed attempt leaves them all in place and the next session
    // retries them. Without this, a peer that never got an oversize turn from the
    // dead relay would stall forever on that seq.
    let oversize = |seq: u64, byte: u8| turn(seq, &vec![byte; 4096]);
    let mut pending = vec![oversize(0, 0x11), oversize(1, 0x22)];

    // Attempt 1: a connection closed before the send, so `write_all` fails. Every
    // staged turn must remain — none dropped on the failure.
    {
        let (link_a, _link_b, _ea, _eb) = connected_links().await;
        let (mut control_send, _recv) = link_a.connection().open_bi().await.unwrap();
        link_a.connection().close(noq::VarInt::from_u32(0), b"boom");
        let result = redivert_pending_control(&mut control_send, &mut pending).await;
        assert!(result.is_err(), "a send over a dead connection must fail");
        assert_eq!(
            pending.len(),
            2,
            "a failed control-stream send loses no staged turn",
        );
    }

    // Attempt 2: a fresh connection whose peer reads its control stream. Both
    // staged turns cross, in seq order, and the staging drains empty.
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let mut control_rx = spawn_control_reader(link_b.connection().clone());
    let (mut control_send, _recv) = link_a.connection().open_bi().await.unwrap();
    redivert_pending_control(&mut control_send, &mut pending)
        .await
        .expect("the retry over a live connection delivers the staged turns");
    assert!(
        pending.is_empty(),
        "every staged turn was sent on the retry"
    );

    for expected_seq in [0u64, 1] {
        let delivered = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
            .await
            .expect("a staged oversize turn never crossed on the retry")
            .expect("control reader closed early");
        match delivered {
            ControlInbound::OversizeTurn(payload) => {
                assert_eq!(payload.seq, expected_seq);
                assert_eq!(
                    payload.commands.len(),
                    4096,
                    "the oversize turn arrives whole"
                );
            }
            other => panic!("expected an oversize turn on the control stream, got {other:?}"),
        }
    }
}
