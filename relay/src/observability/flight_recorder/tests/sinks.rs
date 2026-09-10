//! Sink behavior: the file sink's path layout, the recent-store repeat
//! warning, the drain's deadline, and the coordinator sink's compression,
//! size cap, and shipment/ack plumbing.

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use super::*;

#[tokio::test]
async fn the_file_sink_writes_the_tenant_scoped_path() {
    let dir = std::env::temp_dir().join(format!("rp2-flight-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let recorder = FlightRecorder::default();
    recorder.set_identity(RelayId(7));
    recorder.set_sink(Arc::new(FileSink::new(dir.clone())));
    let k = key(42);
    recorder.record(
        &k,
        FlightEvent::SessionStart {
            initial_buffer_turns: None,
        },
    );

    assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Stored);

    let path = dir.join("sb-test").join("42").join("7.json");
    let json = std::fs::read_to_string(&path).expect("the blob file exists");
    let blob: FlightBlob = serde_json::from_str(&json).expect("the file is parseable JSON");
    assert_eq!(blob.session, 42);
    assert_eq!(blob.events.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_recent_store_window_reports_a_repeat_and_evicts_the_oldest() {
    let mut recent = RecentStores::default();
    assert!(!recent.note(&key(1)), "a first store is not a repeat");
    assert!(recent.note(&key(1)), "storing the same session again is");
    assert_eq!(
        recent.order.len(),
        1,
        "a repeat does not re-enter the window"
    );

    // One store past the cap evicts the oldest session, which then reads as a
    // first store again.
    for session in 2..=(RECENT_STORES as u64 + 1) {
        assert!(!recent.note(&key(session)), "each session is new");
    }
    assert_eq!(recent.order.len(), RECENT_STORES, "the window is capped");
    assert!(!recent.note(&key(1)), "the evicted session is forgotten");
}

#[tokio::test]
async fn a_store_for_an_already_stored_session_is_noticed() {
    let recorder = FlightRecorder::default();
    let sink = Arc::new(CaptureSink::default());
    recorder.set_sink(sink.clone());
    let k = key(1);
    recorder.record(
        &k,
        FlightEvent::SlotConnected {
            slot: 0,
            resumed: false,
        },
    );
    assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Stored);

    // The relay genuinely serves the session again — its retirement
    // cleared the close seal before the re-serve — and the second store
    // replaces what the first one wrote.
    recorder.clear_close_seal(&k);
    recorder.record(
        &k,
        FlightEvent::SlotConnected {
            slot: 0,
            resumed: true,
        },
    );
    assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Stored);

    assert_eq!(sink.blobs.lock().len(), 2, "both stores reached the sink");
    let mut recent = recorder.inner.recent_stores.lock();
    assert!(recent.note(&k), "the flushes remembered the stored session");
    assert_eq!(
        recent.order.len(),
        1,
        "one entry for the one session stored"
    );
}

#[tokio::test]
async fn without_a_sink_recording_continues_and_a_flush_is_a_logged_discard() {
    let recorder = FlightRecorder::default();
    let k = key(1);
    recorder.record(
        &k,
        FlightEvent::SessionStart {
            initial_buffer_turns: None,
        },
    );
    assert_eq!(recorder.flush_session(&k).await, FlushOutcome::NoSink);
    assert!(recorder.recorded_sessions().is_empty());

    // The discard is as terminal as a store: the key is close-sealed, so a
    // straggling event does not begin a replacement recording.
    recorder.record(&k, FlightEvent::SessionClosed);
    assert!(recorder.events(&k).is_empty());

    // A genuine re-serve records again.
    recorder.clear_close_seal(&k);
    recorder.record(&k, FlightEvent::SessionClosed);
    assert_eq!(recorder.events(&k).len(), 1);
}

#[tokio::test]
async fn the_drain_flush_respects_its_deadline_against_a_slow_sink() {
    let recorder = FlightRecorder::default();
    recorder.set_sink(Arc::new(SlowSink));
    recorder.record(
        &key(1),
        FlightEvent::SessionStart {
            initial_buffer_turns: None,
        },
    );
    recorder.record(
        &key(2),
        FlightEvent::SessionStart {
            initial_buffer_turns: None,
        },
    );

    let started = std::time::Instant::now();
    recorder.flush_all(Duration::from_millis(100)).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the drain flush returns at its deadline, not the sink's pace",
    );
}

#[tokio::test]
async fn the_coordinator_sink_compresses_a_shipment_that_reconstructs_the_blob() {
    let recorder = FlightRecorder::default();
    recorder.set_identity(RelayId(9));
    let (tx, mut rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    recorder.set_sink(Arc::new(CoordinatorSink::new(tx)));
    let k = key(42);
    recorder.record(
        &k,
        FlightEvent::SessionStart {
            initial_buffer_turns: Some(3),
        },
    );
    recorder.record(&k, FlightEvent::SessionClosed);

    // `store` blocks awaiting the connection's ack, so drive the flush
    // concurrently with the stand-in connection that pulls it and acks.
    let flush = tokio::spawn(async move { recorder.flush_session(&k).await });

    let shipment = rx.recv().await.expect("a shipment is queued");
    assert_eq!(shipment.tenant.as_ref(), "sb-test");
    assert_eq!(shipment.session, SessionId(42));
    assert!(!shipment.desynced, "no desync event was recorded");
    // The shipped payload is the zstd-compressed compact JSON of the blob;
    // decompressing it reconstructs the blob exactly.
    let json = zstd::decode_all(&shipment.payload[..]).expect("the payload decompresses");
    let blob: FlightBlob = serde_json::from_slice(&json).expect("the payload is the blob");
    assert_eq!(blob.tenant, "sb-test");
    assert_eq!(blob.session, 42);
    assert_eq!(blob.relay_id, 9);
    assert_eq!(blob.events.len(), 2);

    // The ack resolves the store to Stored.
    shipment
        .sent
        .send(())
        .expect("the sink is still awaiting the ack");
    assert_eq!(flush.await.unwrap(), FlushOutcome::Stored);
}

#[tokio::test]
async fn the_shipped_desynced_flag_is_set_only_when_a_desync_event_exists() {
    let recorder = FlightRecorder::default();
    let (tx, mut rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    recorder.set_sink(Arc::new(CoordinatorSink::new(tx)));
    let k = key(1);
    recorder.record(
        &k,
        FlightEvent::DesyncDetected {
            sync_ordinal: 5,
            diverged: vec![1],
            no_majority: false,
        },
    );
    let flush = tokio::spawn(async move { recorder.flush_session(&k).await });
    let shipment = rx.recv().await.expect("a shipment is queued");
    assert!(
        shipment.desynced,
        "a DesyncDetected event sets the shipped flag",
    );
    shipment.sent.send(()).unwrap();
    assert_eq!(flush.await.unwrap(), FlushOutcome::Stored);
}

#[tokio::test]
async fn an_oversized_compressed_blob_is_refused_and_ships_nothing() {
    let (tx, mut rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    let sink = CoordinatorSink::new(tx);
    // A blob whose *compressed* form exceeds the shipping cap — a pathological
    // payload the rings would never actually produce, built by hand to exercise
    // the wire-hygiene backstop. The tenant string is filled with high-entropy
    // (incompressible) bytes so zstd cannot shrink it below the cap.
    let blob = FlightBlob {
        version: BLOB_VERSION,
        // Twice the cap of high-entropy source: even at zstd's best case on a
        // 6-bit-per-symbol alphabet (~0.75 ratio) the compressed form clears the
        // 4 MiB cap comfortably.
        tenant: incompressible_string(MAX_SHIPPED_BLOB_BYTES * 2),
        session: 1,
        relay_id: 0,
        started_at_ms: 1,
        flushed_at_ms: 2,
        events_dropped: 0,
        samples_dropped: 0,
        events: vec![],
        samples: vec![],
    };
    assert!(
        sink.store(&blob).await.is_err(),
        "an oversized compressed blob is refused",
    );
    assert!(rx.try_recv().is_err(), "nothing was shipped");
}

#[tokio::test]
async fn a_full_shipment_queue_fails_the_flush_without_blocking() {
    let recorder = FlightRecorder::default();
    // Capacity one, its single slot pre-filled: the receiver stays bound and
    // alive, so the sink's next try_send sees a full (not closed) queue.
    let (tx, _rx) = mpsc::channel(1);
    tx.try_send(FlightShipment {
        tenant: TenantId("sb-test".to_owned()),
        session: SessionId(0),
        desynced: false,
        payload: Bytes::from_static(b"{}"),
        sent: oneshot::channel().0,
    })
    .expect("the first send fills the slot");
    recorder.set_sink(Arc::new(CoordinatorSink::new(tx)));
    let k = key(1);
    recorder.record(&k, FlightEvent::SessionClosed);
    // A full queue is a lost blob reported Failed — and, crucially, the flush
    // returns at once rather than blocking a session teardown.
    let outcome = tokio::time::timeout(Duration::from_secs(1), recorder.flush_session(&k))
        .await
        .expect("the flush returns at once, it does not hang");
    assert_eq!(outcome, FlushOutcome::Failed);
}

#[tokio::test]
async fn a_dropped_ack_sender_fails_the_flush() {
    let recorder = FlightRecorder::default();
    let (tx, mut rx) = mpsc::channel(FLIGHT_SHIP_QUEUE);
    recorder.set_sink(Arc::new(CoordinatorSink::new(tx)));
    let k = key(1);
    recorder.record(&k, FlightEvent::SessionClosed);
    let flush = tokio::spawn(async move { recorder.flush_session(&k).await });
    let shipment = rx.recv().await.expect("a shipment is queued");
    // The connection loop tears down before writing the frame: dropping the
    // shipment drops its ack sender, so the sink reports the blob lost.
    drop(shipment);
    assert_eq!(flush.await.unwrap(), FlushOutcome::Failed);
}
