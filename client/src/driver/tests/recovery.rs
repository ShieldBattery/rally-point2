//! Forward recovery: the maintenance flush's retransmits under near-MTU and
//! idle traffic, the ack beacon under reverse-path loss, and the unacked
//! window cap under sustained forward loss.

use super::*;

#[tokio::test]
async fn retransmits_an_unacked_turn_during_outbound_silence() {
    let (link_a, mut link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    // One turn, then silence: the game produces nothing more and the peer never
    // acks. The driver still has it in flight.
    chan_a.outbound.send(turn(0, &[0x42])).await.unwrap();

    // Drop the first datagram carrying it, simulating loss on the wire, so the
    // peer's dedup never sees the original.
    let _lost = link_b.connection().read_datagram().await.unwrap();

    // Recovery depends on a later packet re-carrying the unacked turn. With no
    // further turn and no peer traffic, the idle flush is the only thing that
    // re-sends it — it must arrive on a subsequent packet.
    let delivered = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let payloads = link_b.recv().await.unwrap().fresh;
            if !payloads.is_empty() {
                return payloads;
            }
        }
    })
    .await
    .expect("the dropped turn was never retransmitted");
    assert_eq!(delivered[0].commands[0], 0x42);

    drop(chan_a);
    let _ = task.await;
}

#[tokio::test]
async fn retransmits_a_dropped_turn_under_continuous_near_mtu_traffic() {
    let (link_a, mut link_b, _ea, _eb) = connected_links().await;
    let budget = link_b
        .connection()
        .max_datagram_size()
        .expect("loopback supports datagrams");
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    // The largest datagram-admissible turns: each fresh turn is close to
    // the admission floor, so two of them can never share one datagram and
    // a packet has no room to also re-carry an older unacked turn as
    // redundancy.
    let big_commands = rally_point_transport::GUARANTEED_DATAGRAM_BUDGET - 64;
    assert!(
        big_commands * 2 > budget,
        "premise: two near-floor turns must not share a {budget}-byte datagram",
    );
    let big = move || turn(0, &vec![0x7u8; big_commands]);

    // Turn 0 goes out, but its datagram is dropped on the wire.
    chan_a.outbound.send(big()).await.unwrap();
    let _lost = link_b.connection().read_datagram().await.unwrap();

    // A steady stream of further near-MTU turns follows with no idle gap. Their
    // packets have no room to re-carry turn 0 as redundancy, so they don't reset
    // the flush timer; it fires and retransmits turn 0 even with the link never
    // idle — proof recovery doesn't depend on outbound silence here.
    let sender = {
        let outbound = chan_a.outbound.clone();
        tokio::spawn(async move {
            for _ in 0..12 {
                if outbound.send(big()).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
    };

    // Turn 0 (seq 0) must reach the peer despite the unbroken fresh stream.
    let got_zero = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if link_b
                .recv()
                .await
                .unwrap()
                .fresh
                .iter()
                .any(|p| p.seq == 0)
            {
                return;
            }
        }
    })
    .await;
    assert!(
        got_zero.is_ok(),
        "dropped turn 0 was never retransmitted under continuous traffic"
    );

    sender.abort();
    drop(chan_a.outbound);
    let _ = task.await;
}

/// The head-of-line counterpart of the near-MTU test above: the dropped
/// turn is wide (fits a datagram alone, never beside another fresh turn),
/// and the continuing traffic is *small* — so its packets have plenty of
/// room for smaller redundancy. The refill must decline to pack any (the
/// wide turn heads the line and cannot ride), leaving the flush timer
/// armed to retransmit the wide turn on a fresh-free packet. Packing
/// smaller redundancy around the blocked head would reset the flush from
/// every packet and strand the wide turn behind continuous traffic.
#[tokio::test]
async fn retransmits_a_dropped_wide_turn_under_continuous_small_traffic() {
    let (link_a, mut link_b, _ea, _eb) = connected_links().await;
    let budget = link_b
        .connection()
        .max_datagram_size()
        .expect("loopback supports datagrams");
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    // The wide turn is the largest admissible; the following turns are
    // sized so that (a) wide + one of them exceeds the live budget — the
    // head-of-line block this test exists to exercise — while (b) any two
    // of them share a packet comfortably, so smaller redundancy *is*
    // available to wrongly pack around the blocked head. 64 bytes of
    // slack covers packet/element framing in both directions.
    let wide_commands = rally_point_transport::GUARANTEED_DATAGRAM_BUDGET - 64;
    let small_commands = budget - wide_commands;
    assert!(
        wide_commands + small_commands + 64 > budget,
        "premise (a): wide + small must exceed the {budget}-byte budget",
    );
    assert!(
        small_commands * 2 + 64 < budget,
        "premise (b): two smalls must share a {budget}-byte datagram",
    );

    // The wide turn goes out alone, and its datagram is dropped on the wire.
    chan_a
        .outbound
        .send(turn(0, &vec![0x7u8; wide_commands]))
        .await
        .unwrap();
    let _lost = link_b.connection().read_datagram().await.unwrap();

    // A steady stream of small turns follows with no idle gap. Each of
    // their packets could carry the *other* small turns as redundancy —
    // never the wide one — so recovery hinges on those packets carrying
    // none at all and the flush firing.
    let sender = {
        let outbound = chan_a.outbound.clone();
        tokio::spawn(async move {
            for _ in 0..24 {
                if outbound
                    .send(turn(0, &vec![0x7u8; small_commands]))
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
    };

    // The wide turn (seq 0) must reach the peer despite the unbroken
    // small-turn stream.
    let got_zero = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if link_b
                .recv()
                .await
                .unwrap()
                .fresh
                .iter()
                .any(|p| p.seq == 0)
            {
                return;
            }
        }
    })
    .await;
    assert!(
        got_zero.is_ok(),
        "dropped wide turn 0 was never retransmitted under continuous small traffic"
    );

    sender.abort();
    drop(chan_a.outbound);
    let _ = task.await;
}

#[tokio::test]
async fn an_idle_link_goes_quiet_after_a_turn_is_acked() {
    let (link_a, mut link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    // A sends one turn; the peer receives and acks it.
    chan_a.outbound.send(turn(0, &[0x55])).await.unwrap();
    let got = link_b.recv().await.unwrap();
    assert_eq!(got.fresh[0].commands[0], 0x55);
    link_b.send(None).unwrap();

    // The peer then sends a second ack-only packet — its own maintenance flush.
    // The driver must not treat that as something to ack, or the two would trade
    // ack-only packets forever.
    link_b.send(None).unwrap();

    // With the turn retired and only ack-only packets left, the link must fall
    // silent: the driver sends nothing across the several flushes in this window.
    let quiet = tokio::time::timeout(
        Duration::from_millis(600),
        link_b.connection().read_datagram(),
    )
    .await;
    assert!(
        quiet.is_err(),
        "driver kept sending on an idle link: {quiet:?}"
    );

    drop(chan_a);
    let _ = task.await;
}

#[tokio::test]
async fn the_beacon_retires_acked_turns_under_reverse_path_loss() {
    // Reverse-path loss: the peer *receives* the turns (redundancy keeps up),
    // but the acks riding the datagrams back are lost. Without the beacon, the
    // driver would re-carry these turns forever and `payloads_in_flight` would
    // grow past the cap. The beacon pushes the peer's `delivered_through`
    // cursor, the driver force-retires through it, and the window stays
    // bounded — the normal recovery path.
    //
    // This is the inversion of `forward_path_sustained_loss_trips_the_unacked_window_cap`:
    // there the peer never receives, so the beacon can't retire and the cap trips.
    // Here the peer *does* receive and pushes its cursor, so the beacon retires
    // and the driver stays alive past the cap — proving the force-advance works.
    // A regression in flush_beacon → stream → reader → retire_through would let
    // in_flight grow past the cap and trip UnackedWindowExhausted here.
    //
    // The observable is a count, not a timing sleep: a tripped driver stops
    // sending, so "the peer received all CAP+256 turns" deterministically proves
    // the driver sent past the cap without tripping — i.e., the beacon retired.
    // A fixed sleep can't reach that: at any point before the cap is stressed
    // in_flight is small whether the beacon works or not.
    let (link_a, mut link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    // The peer opens its outbound beacon uni-stream and pushes its
    // delivered_through cursor as it receives turns. This is what a real
    // relay/client does via flush_beacon; here we do it by hand since link_b
    // is a raw Link (no driver).
    let mut peer_beacon = link_b.connection().open_uni().await.unwrap();
    let total = (UNACKED_WINDOW_CAP + 256) as u32;

    let peer = tokio::spawn(async move {
        let mut last_pushed: Option<u64> = None;
        while let Ok(r) = link_b.recv().await {
            // The peer received these turns: its delivered_through advanced.
            // Push the new cursor to the driver. All turns here are slot 0.
            if let Some(cursor) = link_b.delivered_through(SlotId(0))
                && !matches!(last_pushed, Some(p) if p >= cursor)
            {
                let frame = beacon::encode_frame(SlotId(0), cursor);
                if peer_beacon.write_all(&frame).await.is_ok() {
                    last_pushed = Some(cursor);
                }
            }
            let _ = r; // drain; the count isn't the observable here
        }
    });

    // No ack datagrams are ever sent back — 100% reverse-path loss. The only
    // way the driver's window stays bounded is the beacon retiring through the
    // peer's pushed cursor. Flood past the cap: a working beacon retires as it
    // goes and the driver sends every turn (the flood completes); a broken
    // beacon lets in_flight hit the cap, the driver trips UnackedWindowExhausted,
    // and the outbound channel send fails early (the flood does NOT complete).
    //
    // The observable is whether the flood sent all `total` turns: that's
    // deterministic and race-free — a tripped driver stops sending, so a
    // broken beacon can't send past the cap no matter how long you wait.
    let flood = {
        let outbound = chan_a.outbound.clone();
        tokio::spawn(async move {
            let mut sent = 0u32;
            for i in 0..total {
                if outbound.send(turn(0, &[(i & 0xFF) as u8])).await.is_err() {
                    break; // Driver tripped or closed.
                }
                sent += 1;
                // A tiny pace lets the peer's recv + beacon push keep up, so
                // this is genuine reverse-path loss (turns arrive, acks
                // don't), not forward-path loss (peer can't receive fast
                // enough).
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            sent
        })
    };

    // Wait for the flood to finish (all turns sent, or the driver tripped and
    // the send broke). It returns the count it actually sent.
    let sent = tokio::time::timeout(Duration::from_secs(30), flood)
        .await
        .expect("the flood never completed — the driver or peer stalled")
        .expect("the flood task panicked");

    // The driver must have sent well past the cap without tripping — i.e., the
    // beacon retired the turns the peer confirmed it received. A broken beacon
    // lets in_flight hit the cap and the driver trips after ~CAP+1 turns (the
    // check is `in_flight > CAP`, so one more send crosses it), so the flood
    // stalls near CAP. The threshold sits at the midpoint between broken
    // (~CAP+1) and working (~CAP+256), giving margin against a few in-flight
    // datagrams dropped on the trip/close.
    assert!(
        sent > (UNACKED_WINDOW_CAP + 128) as u32,
        "driver tripped the cap under reverse-path loss — the beacon did not \
         retire the peer's confirmed-delivered turns (the flood sent only \
         {sent} turns before the driver stopped; a working beacon keeps the \
         driver sending past the {UNACKED_WINDOW_CAP}-turn cap)"
    );

    // And the driver must still be alive (not tripped) — the flood completed
    // because the beacon kept the window bounded, not because the channel
    // broke for another reason.
    assert!(
        !task.is_finished(),
        "driver task ended after the flood — it should still be alive with a \
         working beacon"
    );

    drop(chan_a.outbound);
    peer.abort();
    let _ = task.await;
}

#[tokio::test]
async fn forward_path_sustained_loss_trips_the_unacked_window_cap() {
    // Forward-path sustained loss: the peer genuinely receives slower than the
    // client produces — redundancy can't keep up, so `payloads_in_flight` grows
    // without bound. The beacon can only retire what the peer *got*, never what
    // it never received, so the window still grows past the cap. The driver must
    // trip `UnackedWindowExhausted` rather than let seqs race ahead until the
    // peer's receive window rejects them and drops the link (the status-quo
    // unbounded-growth failure this mechanism exists to prevent). This is the test
    // that catches a missing cap — a beacon-only design passes every other test
    // but fails here.
    let (link_a, link_b, _ea, _eb) = connected_links().await;
    let (driver_a, chan_a) = LinkDriver::new(link_a);
    let task = tokio::spawn(driver_a.run());

    // The peer never receives: drain its datagrams but never call `recv()`, so
    // its `delivered_through` never advances and the beacon can't retire
    // anything. Meanwhile the driver keeps producing turns. Each goes out and
    // stays unacked — genuine forward-path loss.
    //
    // We must drain the raw datagrams off the wire or noq's datagram buffer
    // fills and the connection stalls before the cap is reached. But we never
    // feed them to `link_b.recv()`, so no delivered_through advances.
    let drainer = {
        let conn = link_b.connection().clone();
        tokio::spawn(async move {
            // Drain datagrams without processing them — the peer "receives" at
            // the transport level but never advances its delivered cursor.
            loop {
                if conn.read_datagram().await.is_err() {
                    break;
                }
            }
        })
    };

    // Flood turns past the cap. The driver sends each one; none are acked and
    // the beacon can't retire them (delivered_through is stuck at None). When
    // in_flight exceeds UNACKED_WINDOW_CAP the driver trips.
    let flood = {
        let outbound = chan_a.outbound.clone();
        tokio::spawn(async move {
            for i in 0..(UNACKED_WINDOW_CAP + 64) as u16 {
                if outbound.send(turn(0, &[(i & 0xFF) as u8])).await.is_err() {
                    break;
                }
                // Don't pace: the goal is to outrun the peer, which never
                // processes anything.
            }
        })
    };

    // The driver must surface UnackedWindowExhausted, not hang.
    match tokio::time::timeout(Duration::from_secs(10), task).await {
        Ok(joined) => assert!(
            matches!(
                joined.unwrap(),
                Err(DriverError::UnackedWindowExhausted { in_flight, cap })
                    if in_flight > cap && cap == UNACKED_WINDOW_CAP
            ),
            "expected UnackedWindowExhausted"
        ),
        Err(_) => {
            panic!("driver hung under forward-path sustained loss instead of tripping the cap")
        }
    }

    drainer.abort();
    flood.abort();
}
