//! The ordered dispatch queue: `sessionClosed` ordering behind earlier
//! notices, a retrying notice blocking the ones behind it, and the overflow
//! drop policy that never drops the terminal job.

use super::*;

#[tokio::test]
async fn session_closed_fires_only_after_all_serving_relays_closed() {
    let (url, mut rx) = spawn_receiver(None).await;
    let setup = setup_with_notify(url);
    let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
    let s = SessionId(1);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1), RelayId(2)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );

    // The first serving relay closes: no sessionClosed yet, and still alive.
    close(&lc, tid(), s, RelayId(1));
    assert!(lc.is_alive(&tid(), s), "one relay closed is not the end");
    assert!(
        timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "sessionClosed must not fire while a serving relay is still open",
    );

    // The last serving relay closes: sessionClosed fires, and it is no longer
    // alive (its state was reaped).
    close(&lc, tid(), s, RelayId(2));
    let got = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("sessionClosed is delivered once every relay closed")
        .unwrap();
    assert_eq!(got.event, "sessionClosed");
    assert!(
        !lc.is_alive(&tid(), s),
        "a fully-closed session is not alive"
    );
}

#[tokio::test]
async fn a_retrying_notice_blocks_session_closed_behind_it() {
    // A departure whose delivery hangs blocks the queue: sessionClosed, enqueued
    // after it, cannot be delivered until the departure completes — the ordering
    // guarantee the sessionClosed signal rests on.
    let gate = StdArc::new(TokioNotify::new());
    let (url, mut rx) = spawn_receiver(Some(gate.clone())).await;
    let setup = setup_with_notify(url.clone());
    let lc = Lifecycle::with_graces(setup, HOUR, HOUR, HOUR);
    let s = SessionId(1);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );

    // Enqueue a departure webhook (its delivery will hang at the receiver).
    lc.enqueue_webhook(
        tid(),
        s,
        NotifyConfig { url },
        bytes::Bytes::from_static(br#"{"event":"departure"}"#),
        "departure",
    );
    // The last (only) serving relay closes → sessionClosed enqueued behind it.
    close(&lc, tid(), s, RelayId(1));

    // The departure request reaches the receiver and hangs; sessionClosed is
    // stuck behind it in the queue.
    let first = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("the departure request reaches the receiver")
        .unwrap();
    assert_eq!(first.event, "departure");
    assert!(
        timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "sessionClosed is blocked behind the stuck departure",
    );

    // Release the departure: it completes, then sessionClosed is delivered.
    gate.notify_one();
    let next = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("sessionClosed is delivered once the departure completes")
        .unwrap();
    assert_eq!(next.event, "sessionClosed");
}

#[tokio::test]
async fn a_full_queue_drops_the_newest_notice_but_never_the_terminal_one() {
    // A small injected capacity so the test can actually fill the queue
    // without pushing hundreds of notices through a fake endpoint. The
    // policy under test doesn't depend on the cap's size, only on there
    // being one.
    const CAPACITY: usize = 8;

    let gate = StdArc::new(TokioNotify::new());
    let (url, mut rx) = spawn_receiver(Some(gate.clone())).await;
    let setup = setup_with_notify(url.clone());
    let lc = Lifecycle::with_test_tunables(
        setup,
        HOUR,
        HOUR,
        HOUR,
        CAPACITY,
        HOUR,
        EmptyReapTunables {
            grace: HOUR,
            freshness: HOUR,
        },
    );
    let s = SessionId(1);
    lc.register_session(
        tid(),
        s,
        vec![RelayId(1)],
        HashSet::from([SlotId(0)]),
        HashSet::new(),
    );

    // The first notice is picked up by the drain task immediately and
    // hangs at the gate -- once `drain_queue` has dequeued it (proven by
    // it reaching the receiver), the channel's own buffer is empty again,
    // so this doesn't itself count against `CAPACITY` below.
    lc.enqueue_webhook(
        tid(),
        s,
        NotifyConfig { url: url.clone() },
        bytes::Bytes::from_static(br#"{"event":"first"}"#),
        "first",
    );
    let first = timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("the first notice reaches the receiver")
        .unwrap();
    assert_eq!(first.event, "first");

    // Fill the queue down to its reserved boundary: CAPACITY - 1 more
    // ordinary notices exactly exhaust the buffer down to the one slot
    // `push_ordinary` always leaves free for the terminal job.
    for i in 0..(CAPACITY - 1) {
        lc.enqueue_webhook(
            tid(),
            s,
            NotifyConfig { url: url.clone() },
            bytes::Bytes::from(format!(r#"{{"event":"queued-{i}"}}"#)),
            "queued",
        );
    }

    let dropped_before = DROPPED_NOTICE_COUNT.load(std::sync::atomic::Ordering::Relaxed);
    // One more ordinary notice: no room left but the reserved slot, so
    // this one — the newest — must be dropped rather than enqueued.
    lc.enqueue_webhook(
        tid(),
        s,
        NotifyConfig { url },
        bytes::Bytes::from_static(br#"{"event":"overflow"}"#),
        "overflow",
    );
    let dropped_after = DROPPED_NOTICE_COUNT.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        dropped_after,
        dropped_before + 1,
        "the overflowing notice was counted as a drop",
    );

    // The terminal job still finds its reserved slot: the session's one
    // relay closing pushes sessionClosed successfully even with the
    // queue otherwise completely full of ordinary notices.
    close(&lc, tid(), s, RelayId(1));

    // Release the gate and drain everything queued: each of the CAPACITY
    // - 1 ordinary notices arrives, in order, the dropped "overflow" one
    // never does, and sessionClosed is last — proving the cap neither
    // reordered nor evicted anything that was actually accepted.
    gate.notify_one();
    let mut events = Vec::new();
    for _ in 0..CAPACITY {
        let received = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("every accepted notice is delivered")
            .unwrap();
        events.push(received.event);
    }
    assert!(
        !events.contains(&"overflow".to_owned()),
        "the dropped notice never reaches the receiver: {events:?}",
    );
    assert_eq!(
        events.last().map(String::as_str),
        Some("sessionClosed"),
        "sessionClosed is delivered last: {events:?}",
    );
    assert!(
        timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "nothing arrives after sessionClosed",
    );
}
