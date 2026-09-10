//! The coordinated-drain seam: what the drain predicate reads, the `Draining`
//! frame the trigger sends, the ack that unblocks the sequence, and the
//! re-assertion a mid-drain reconnect owes.

use super::*;

#[test]
fn drained_idle_requires_both_no_slots_and_an_empty_applied_set() {
    let sessions: Sessions = std::sync::Arc::default();
    let applied = AppliedSessions::new();

    // Empty roster + empty applied set: provably unassigned, drained.
    assert!(drained_idle(&sessions, &applied));

    // An applied session with no dialed client (the pre-mark sliver: assigned
    // just before the drain, clients not yet connected) blocks the drain even
    // though no slot is held.
    applied.inner.lock().insert(key(1));
    assert!(
        !drained_idle(&sessions, &applied),
        "an assigned session whose clients have not dialed blocks the drain",
    );
    applied.inner.lock().clear();
    assert!(drained_idle(&sessions, &applied));

    // A held slot blocks the drain even with an empty applied set (e.g. a
    // post-restart session the coordinator no longer tracks).
    let (_guard, _inbox) =
        crate::routing::register(&sessions, &key(1), rally_point_proto::ids::SlotId(0), 1)
            .expect("slot 0 registers");
    assert!(
        !drained_idle(&sessions, &applied),
        "a held slot blocks the drain regardless of the applied set",
    );
}

#[test]
fn reconcile_updates_the_shared_applied_set_the_drain_predicate_reads() {
    // The subscriber-to-drain seam: a descriptor push reconciled into the shared
    // handle flips the drain predicate, and the next push removing the session
    // flips it back — what lets a drain wait out an assigned-but-undialed
    // session and exit the moment the coordinator's set empties.
    let sessions: Sessions = std::sync::Arc::default();
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let applied = AppliedSessions::new();
    assert!(drained_idle(&sessions, &applied));

    reconcile(&control, &[descriptor(1, &[])], &applied);
    assert!(
        !drained_idle(&sessions, &applied),
        "a pushed session is visible through the drain predicate",
    );

    reconcile(&control, &[], &applied);
    assert!(
        drained_idle(&sessions, &applied),
        "the session's removal on the next push re-drains the relay",
    );
}

#[tokio::test]
async fn a_drain_trigger_sends_a_draining_frame_after_the_hello() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (frames_tx, frames_rx) = tokio::sync::oneshot::channel();

    // Stand-in coordinator: accept, complete the enroll handshake, then read
    // the frame that follows once the relay is told to drain.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let hello = accept_enroll(&mut ws).await;
        let next = ws.next().await.unwrap().unwrap();
        let _ = frames_tx.send((hello, next));
    });

    let (drain_tx, drain_rx) = watch::channel(false);
    let (drain_acked_tx, _drain_acked_rx) = watch::channel(false);
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    tokio::spawn(run_descriptor_subscriber_with(
        enroll(addr, drain_hello()),
        apply_targets(control, drain_acked_tx),
        OutboundQueues::new(
            mpsc::unbounded_channel().1,
            no_flight(),
            ControlConnStats::new(),
        ),
        heartbeat(Duration::from_secs(3600)),
        drain_rx,
        no_connected(),
        backoff(Duration::from_millis(20), Duration::from_secs(60)),
    ));

    // Trigger the drain; the relay must send a Draining frame after its Hello.
    drain_tx.send(true).unwrap();

    let (hello, draining) = tokio::time::timeout(Duration::from_secs(5), frames_rx)
        .await
        .expect("the relay sends a Draining frame after the trigger")
        .unwrap();
    let Message::Text(hello) = hello else {
        panic!("the first frame is the Hello");
    };
    assert!(hello.contains("\"type\":\"hello\""));
    let Message::Text(draining) = draining else {
        panic!("the second frame is text");
    };
    assert_eq!(
        serde_json::from_str::<RelayToCoordinator>(&draining).unwrap(),
        RelayToCoordinator::Draining,
    );
}

#[tokio::test]
async fn a_drain_ack_fires_the_acked_signal() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Stand-in coordinator: accept, complete the enroll handshake, then send a
    // DrainAck and hold the connection open.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _hello = accept_enroll(&mut ws).await;
        let ack = serde_json::to_string(&CoordinatorToRelay::DrainAck).unwrap();
        ws.send(Message::Text(ack.into())).await.unwrap();
        // Keep the connection open so the relay doesn't reconnect mid-assert.
        std::future::pending::<()>().await;
    });

    let (_drain_tx, drain_rx) = watch::channel(false);
    let (drain_acked_tx, mut drain_acked_rx) = watch::channel(false);
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    tokio::spawn(run_descriptor_subscriber_with(
        enroll(addr, drain_hello()),
        apply_targets(control, drain_acked_tx),
        OutboundQueues::new(
            mpsc::unbounded_channel().1,
            no_flight(),
            ControlConnStats::new(),
        ),
        heartbeat(Duration::from_secs(3600)),
        drain_rx,
        no_connected(),
        backoff(Duration::from_millis(20), Duration::from_secs(60)),
    ));

    // The DrainAck flips the acked watch to true.
    tokio::time::timeout(Duration::from_secs(5), drain_acked_rx.changed())
        .await
        .expect("the DrainAck fires the acked signal")
        .unwrap();
    assert!(*drain_acked_rx.borrow());
}

#[tokio::test]
async fn a_reconnect_while_draining_re_sends_draining_after_the_hello() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();

    // Stand-in coordinator: the FIRST connection enrolls then reads Draining and
    // drops; the SECOND (reconnect) must again enroll then read Draining —
    // proving a relay that reconnects mid-drain re-asserts it right after the
    // enroll handshake completes.
    tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let hello = accept_enroll(&mut ws).await;
            let Message::Text(hello) = hello else {
                panic!("first frame is the Hello");
            };
            assert!(hello.contains("\"type\":\"hello\""));
            let draining = ws.next().await.unwrap().unwrap();
            let Message::Text(draining) = draining else {
                panic!("second frame is text");
            };
            assert_eq!(
                serde_json::from_str::<RelayToCoordinator>(&draining).unwrap(),
                RelayToCoordinator::Draining,
            );
            // Drop the first connection to force a reconnect; signal after the
            // second one re-sent its Draining.
            drop(ws);
        }
        let _ = done_tx.send(());
    });

    // Draining is already requested before the subscriber starts, so it must be
    // re-asserted on every connection right after the Hello.
    let (_drain_tx, drain_rx) = watch::channel(true);
    let (drain_acked_tx, _drain_acked_rx) = watch::channel(false);
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    tokio::spawn(run_descriptor_subscriber_with(
        enroll(addr, drain_hello()),
        apply_targets(control, drain_acked_tx),
        OutboundQueues::new(
            mpsc::unbounded_channel().1,
            no_flight(),
            ControlConnStats::new(),
        ),
        heartbeat(Duration::from_secs(3600)),
        drain_rx,
        no_connected(),
        backoff(Duration::from_millis(20), Duration::from_secs(60)),
    ));

    tokio::time::timeout(Duration::from_secs(5), done_rx)
        .await
        .expect("the reconnect re-sends Draining after the Hello")
        .unwrap();
}
