//! Session-recording behavior: event/sample rings, seals and close
//! terminality, work-snapshot accounting, and the blob envelope's round trip.

use rally_point_proto::control::DepartureKind;

use super::*;

#[test]
fn the_event_ring_evicts_oldest_and_counts_the_loss() {
    let recorder = FlightRecorder::default();
    let k = key(1);
    for i in 0..(MAX_EVENTS_PER_SESSION + 3) {
        recorder.record(
            &k,
            FlightEvent::SlotConnected {
                slot: (i % 8) as u8,
                resumed: false,
            },
        );
    }
    let events = recorder.events(&k);
    assert_eq!(events.len(), MAX_EVENTS_PER_SESSION, "the ring is capped");
    // The three oldest (slots 0, 1, 2 of the first wrap) were evicted; the
    // ring now starts at the fourth event.
    assert_eq!(
        events[0].event,
        FlightEvent::SlotConnected {
            slot: 3,
            resumed: false
        },
        "eviction is oldest-first",
    );

    // The loss is counted into the flushed blob.
    let blob = recorder.take_blob(&k, true).expect("a recording exists");
    assert_eq!(blob.events_dropped, 3);
}

#[test]
fn counter_bumps_fold_into_a_sample_on_the_tick() {
    let recorder = FlightRecorder::default();
    let k = key(1);
    let counters = recorder.slot_counters(&k, SlotId(2));
    counters.note_validated(7);
    counters.note_validated(9);
    counters.note_forwarded();
    counters.note_oversize_divert();
    recorder.note_dedup_drop(&k, SlotId(2));

    // Drive the tick body directly with an empty conditions registry and no
    // e2e view.
    let conditions = crate::mesh::new_conditions_registry();
    recorder.sample_now(&conditions, |_| (None, None));

    let blob = recorder.take_blob(&k, true).expect("a recording exists");
    // One tick sample plus the final flush snapshot.
    assert_eq!(blob.samples.len(), 2);
    let row = &blob.samples[0].slots[0];
    assert_eq!(row.slot, 2);
    assert_eq!(row.turns_validated, 2);
    assert_eq!(row.newest_seq, 9);
    assert_eq!(row.turns_forwarded, 1);
    assert_eq!(row.oversize_diverts, 1);
    assert_eq!(row.dedup_drops, 1);
    assert_eq!(row.rtt_us, None, "no published conditions for the slot");
}

#[test]
fn relay_work_totals_aggregate_across_slots_and_survive_session_flush() {
    let recorder = FlightRecorder::default();
    let first_key = key(1);
    let second_key = key(2);
    let first = recorder.slot_counters(&first_key, SlotId(0));
    let second = recorder.slot_counters(&second_key, SlotId(3));

    first.note_validated(1);
    first.note_validated(2);
    first.note_forwarded();
    second.note_validated(7);
    second.note_forwarded();
    second.note_forwarded();
    second.note_oversize_divert();

    assert_eq!(
        recorder.relay_work_snapshot(),
        RelayWorkSnapshot {
            client_turns_validated: 3,
            local_turn_deliveries: 3,
            oversize_diverts: 1,
        }
    );

    // Removing the first session's recording (the synchronous core of a
    // flush) does not remove its contribution from relay-lifetime totals.
    let _ = recorder
        .take_blob(&first_key, true)
        .expect("a recording exists");
    assert_eq!(
        recorder.relay_work_snapshot(),
        RelayWorkSnapshot {
            client_turns_validated: 3,
            local_turn_deliveries: 3,
            oversize_diverts: 1,
        }
    );

    // The flush left the key close-sealed, so a straggling link's counters
    // count into the void — the deliberate cost of never re-creating a
    // flushed recording (see `CloseSeals`).
    recorder
        .slot_counters(&first_key, SlotId(0))
        .note_forwarded();
    assert_eq!(
        recorder.relay_work_snapshot(),
        RelayWorkSnapshot {
            client_turns_validated: 3,
            local_turn_deliveries: 3,
            oversize_diverts: 1,
        }
    );

    // A genuine re-serve clears the seal; new counters then wire into the
    // same relay-lifetime aggregate rather than restarting from zero.
    recorder.clear_close_seal(&first_key);
    recorder
        .slot_counters(&first_key, SlotId(0))
        .note_forwarded();
    assert_eq!(
        recorder.relay_work_snapshot(),
        RelayWorkSnapshot {
            client_turns_validated: 3,
            local_turn_deliveries: 4,
            oversize_diverts: 1,
        }
    );
}

#[test]
fn the_sampler_folds_published_link_conditions_into_the_row() {
    let recorder = FlightRecorder::default();
    let k = key(1);
    let counters = recorder.slot_counters(&k, SlotId(0));
    counters.note_redundancy(3);
    counters.note_redundancy(2);
    counters.note_redundancy(0);
    counters.note_link_gauges(9, 12_000, 4);

    let conditions = crate::mesh::new_conditions_registry();
    crate::mesh::activate_conditions(
        &conditions,
        &k,
        SlotId(0),
        rally_point_proto::messages::SlotConditions {
            slot: 0,
            rtt_us: 42_000,
            lost_packets: 3,
            sent_packets: 500,
            connection_epoch: None,
        },
    );
    recorder.sample_now(&conditions, |_| (Some(17), Some(2)));

    let blob = recorder.take_blob(&k, true).expect("a recording exists");
    let sample = &blob.samples[0];
    // The session-level end-to-end view rides the sample row.
    assert_eq!(sample.worst_e2e_lag_turns, Some(17));
    assert_eq!(sample.max_relay_hops, Some(2));
    let row = &sample.slots[0];
    assert_eq!(row.rtt_us, Some(42_000));
    assert_eq!(row.lost_packets, Some(3));
    assert_eq!(row.sent_packets, Some(500));
    // Redundancy accumulates across packets; the gauges are the link's
    // latest published values, not a running total.
    assert_eq!(row.redundant_payloads, 5);
    assert_eq!(row.upstream_lost_packets, 9);
    assert_eq!(row.cwnd, 12_000);
    assert_eq!(row.congestion_events, 4);
}

#[test]
fn the_blob_envelope_roundtrips_and_is_self_describing() {
    let recorder = FlightRecorder::default();
    recorder.set_identity(RelayId(7));
    let k = key(42);
    recorder.record(
        &k,
        FlightEvent::LeaveDecided {
            slot: 1,
            kind: DepartureKind::Dropped,
            reason: 0x4000_0006,
            apply_frame: 900,
            leave_seq: 3,
            finalized: true,
            final_turn_count: Some(44),
        },
    );
    recorder.record(
        &k,
        FlightEvent::LeaveMeshAccepted {
            source_relay: 9,
            slot: 1,
            reason: 0x4000_0006,
            apply_frame: 900,
            leave_seq: 3,
            finalized: true,
            final_turn_count: Some(44),
        },
    );
    recorder.record(
        &k,
        FlightEvent::LeaveControlWrite {
            recipient: 2,
            connection_epoch: 17,
            slot: 1,
            reason: 0x4000_0006,
            apply_frame: 900,
            leave_seq: 3,
            finalized: true,
            final_turn_count: Some(44),
            replayed: false,
            succeeded: true,
        },
    );
    recorder.record(&k, FlightEvent::SessionClosed);

    let blob = recorder.take_blob(&k, true).expect("a recording exists");
    assert_eq!(blob.version, BLOB_VERSION);
    assert_eq!(blob.tenant, "sb-test");
    assert_eq!(blob.session, 42);
    assert_eq!(blob.relay_id, 7);
    assert!(blob.started_at_ms > 0 && blob.flushed_at_ms >= blob.started_at_ms);

    let json = serde_json::to_string_pretty(&blob).unwrap();
    // The envelope is self-describing on the wire: version and tagged events.
    assert!(json.contains("\"version\": 1"));
    assert!(json.contains("\"event\": \"leave_decided\""));
    assert!(json.contains("leave_mesh_accepted"));
    assert!(json.contains("leave_control_write"));
    let back: FlightBlob = serde_json::from_str(&json).unwrap();
    assert_eq!(back, blob);
}

/// A recorded decision's derivation survives the blob round-trip with its
/// per-slot detail intact, and a directive without one stays absent rather
/// than serializing a hole.
#[test]
fn a_buffer_directives_derivation_roundtrips() {
    let recorder = FlightRecorder::default();
    recorder.set_identity(RelayId(7));
    let k = key(42);
    recorder.record(
        &k,
        FlightEvent::BufferDirective {
            buffer_turns: 12,
            apply_frame: 340,
            decision_seq: 2,
            inputs: Some(BufferDecisionInputs {
                law_target: 8,
                target: 13,
                shrink_target: 13,
                path_us: 125_000,
                loss_risk_us: 4_700,
                burst_turns: 4,
                cushion_turns: 4,
                stretch_turns: 1,
                shrink_floor: 13,
                edge_burned: true,
                eff_rtts: vec![
                    SlotEffRtt {
                        slot: 0,
                        eff_rtt_us: 45_000,
                    },
                    SlotEffRtt {
                        slot: 3,
                        eff_rtt_us: 205_000,
                    },
                ],
            }),
        },
    );
    recorder.record(
        &k,
        FlightEvent::BufferDirective {
            buffer_turns: 5,
            apply_frame: 900,
            decision_seq: 3,
            inputs: None,
        },
    );

    let blob = recorder.take_blob(&k, true).expect("a recording exists");
    let json = serde_json::to_string_pretty(&blob).unwrap();
    assert!(
        json.contains("\"eff_rtts\""),
        "the per-slot detail reaches the wire",
    );
    assert_eq!(
        json.matches("\"inputs\"").count(),
        1,
        "the directive with no derivation serializes no key for one",
    );

    let back: FlightBlob = serde_json::from_str(&json).unwrap();
    assert_eq!(back, blob);
}

#[tokio::test]
async fn a_flush_removes_the_recording() {
    let recorder = FlightRecorder::default();
    let sink = Arc::new(CaptureSink::default());
    recorder.set_sink(sink.clone());
    let k = key(1);
    recorder.record(&k, FlightEvent::SessionClosed);
    assert_eq!(recorder.recorded_sessions().len(), 1);

    assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Stored);
    assert!(recorder.recorded_sessions().is_empty(), "flush is terminal");
    assert_eq!(sink.blobs.lock().len(), 1);

    // A re-flush of the gone recording is a harmless Nothing.
    assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Nothing);
}

#[tokio::test]
async fn a_terminal_event_never_begins_a_recording() {
    let recorder = FlightRecorder::default();
    let sink = Arc::new(CaptureSink::default());
    recorder.set_sink(sink.clone());
    let k = key(1);

    recorder.record_existing(&k, FlightEvent::SessionClosed);

    assert!(
        recorder.recorded_sessions().is_empty(),
        "an event that only marks the end of an observation starts nothing",
    );
    assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Nothing);
    assert!(sink.blobs.lock().is_empty(), "nothing was stored");
}

#[tokio::test]
async fn a_terminal_event_lands_on_a_live_recording() {
    let recorder = FlightRecorder::default();
    let sink = Arc::new(CaptureSink::default());
    recorder.set_sink(sink.clone());
    let k = key(1);
    recorder.record(
        &k,
        FlightEvent::SlotConnected {
            slot: 3,
            resumed: false,
        },
    );

    recorder.record_existing(&k, FlightEvent::SessionClosed);

    assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Stored);
    let blobs = sink.blobs.lock();
    let stored = blobs.first().expect("the recording was stored");
    assert_eq!(
        stored.events.last().map(|record| &record.event),
        Some(&FlightEvent::SessionClosed),
        "the close seals the recording it was recorded against",
    );
}

#[tokio::test]
async fn a_second_close_stores_nothing_over_an_already_stored_recording() {
    let recorder = FlightRecorder::default();
    let sink = Arc::new(CaptureSink::default());
    recorder.set_sink(sink.clone());
    let k = key(1);
    recorder.record(
        &k,
        FlightEvent::BufferDirective {
            buffer_turns: 4,
            apply_frame: 1200,
            decision_seq: 9,
            inputs: None,
        },
    );
    recorder.record_existing(&k, FlightEvent::SessionClosed);
    assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Stored);

    // A close evaluated again for the same session — the relay serves it no
    // longer, so nothing has been recorded since.
    recorder.record_existing(&k, FlightEvent::SessionClosed);
    assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Nothing);

    let blobs = sink.blobs.lock();
    assert_eq!(blobs.len(), 1, "only the served session's recording stored");
    assert!(
        blobs[0]
            .events
            .iter()
            .any(|record| matches!(record.event, FlightEvent::BufferDirective { .. })),
        "the stored recording is the one holding what the relay observed",
    );
}

#[test]
fn a_retired_sessions_event_never_begins_a_recording() {
    // The seal covers close-to-retirement; the session gate covers
    // everything after retirement (which clears the seal). Together no
    // straggler can conjure a recording anywhere in the session's tail.
    let recorder = FlightRecorder::default();
    let gates = crate::session::gate::SessionGates::default();
    recorder.set_gates(gates.clone());
    let k = key(1);

    gates.retire(&k);
    recorder.record(
        &k,
        FlightEvent::SlotConnected {
            slot: 0,
            resumed: false,
        },
    );
    assert!(
        recorder.recorded_sessions().is_empty(),
        "a retired session's event records nothing",
    );

    // A genuine re-serve reopens the gate and records again.
    gates.reopen(&k);
    recorder.record(
        &k,
        FlightEvent::SlotConnected {
            slot: 0,
            resumed: false,
        },
    );
    assert!(!recorder.recorded_sessions().is_empty());
}

#[test]
fn a_seal_past_the_warn_threshold_is_retained_not_evicted() {
    // Volume must never evict a seal: an evicted seal would silently
    // reopen its closed-but-unretired session to the straggler overwrite
    // the seal exists to prevent. The threshold only trips the leak warn.
    let mut seals = CloseSeals::default();
    let first = key(1);
    seals.seal(&first);
    for session in 2..=(CLOSE_SEAL_WARN_THRESHOLD as u64 + 4) {
        seals.seal(&key(session));
    }
    assert!(
        seals.contains(&first),
        "the oldest seal survives any volume of later seals",
    );
    assert!(seals.warned, "crossing the threshold trips the leak warn");

    // Retirement clearing drains the set; the warn latch re-arms once the
    // count halves, so a later excursion warns again.
    for session in 1..=(CLOSE_SEAL_WARN_THRESHOLD as u64 + 4) {
        seals.clear(&key(session));
    }
    assert!(!seals.warned, "the warn latch re-arms as the set drains");
    assert!(!seals.contains(&first));
}

/// The regression the close seal exists for: a session's close flushes its
/// recording while the relay is still mesh-joined for it, and a delayed
/// mesh frame then produces an ordinary event (a late `SlotDeparted`
/// marking a drop hold). Without the seal that event re-created a
/// recording through create-on-first-touch, which lingered until the drain
/// flush and — one storage key per session per relay — displaced the real
/// stored recording with a contentless one.
#[tokio::test]
async fn a_straggling_event_after_the_close_flush_cannot_displace_the_stored_recording() {
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
    recorder.record_existing(&k, FlightEvent::SessionClosed);
    assert_eq!(recorder.flush_session(&k).await, FlushOutcome::Stored);

    // The straggler: still mesh-joined, a late mesh frame records a hold.
    recorder.record(&k, FlightEvent::DropHeld { slot: 1 });
    assert!(
        recorder.recorded_sessions().is_empty(),
        "the sealed key began no replacement recording",
    );

    // The drain flush finds nothing to store over the real recording.
    recorder.flush_all(Duration::from_secs(1)).await;
    assert_eq!(sink.blobs.lock().len(), 1, "only the real recording stored");

    // Membership retirement clears the seal; nothing arrives after it.
    recorder.clear_close_seal(&k);
    assert!(recorder.recorded_sessions().is_empty());
}
