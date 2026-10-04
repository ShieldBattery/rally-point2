//! A rollback session's figures in the recording: each home slot's lead
//! figures and its client's own statistics merged into its sample row, the
//! clock's stopped time on the row, and the final statistics as an event.

use super::*;

fn client_stats(through_turn: u32) -> ClientRollbackStats {
    ClientRollbackStats {
        version: 1,
        through_turn,
        ticks: 1_500,
        rollback_histogram: vec![900, 400, 200],
        pipe_histogram: vec![0, 0, 1_500],
        schedule_corrected_us: -21_000,
        lead_p90_max_us: 9_000,
        ..Default::default()
    }
}

fn lead_sample(turns: u32) -> SlotLeadSample {
    SlotLeadSample {
        turns,
        reports: 20,
        last_report: Some(LeadReportRecord {
            through_step: 263,
            median_us: -2_000,
            p90_us: 7_000,
            samples: 24,
            pause_us: 0,
        }),
        max_p90_us: Some(11_000),
        max_lateness_us: Some(38_000),
        lateness_histogram: vec![0, 0, 3, 100, 120, 10, 6, 1, 0, 0],
    }
}

#[test]
fn lead_figures_and_client_statistics_ride_their_own_slots_rows() {
    let recorder = FlightRecorder::default();
    let k = key(1);
    // Slot 0 is homed here and reports its statistics; slot 3's counters exist
    // (turns were forwarded to it) but it was never measured and never
    // reported.
    let home = recorder.slot_counters(&k, SlotId(0));
    home.note_validated(263);
    home.note_rollback_stats(client_stats(240));
    recorder.slot_counters(&k, SlotId(3)).note_forwarded();

    let conditions = crate::mesh::new_conditions_registry();
    recorder.sample_now(
        &conditions,
        |_| (None, None),
        |_| None,
        |_| {
            Some(LeadSamples {
                clock_pause_us: Some(84_000),
                slots: vec![(0, lead_sample(240))],
            })
        },
    );

    let blob = recorder.take_blob(&k, true).expect("a recording exists");
    let row = &blob.samples[0];
    assert_eq!(row.clock_pause_us, Some(84_000));
    assert_eq!(row.slots[0].slot, 0);
    assert_eq!(row.slots[0].lead, Some(lead_sample(240)));
    assert_eq!(row.slots[0].rollback_stats, Some(client_stats(240)));
    assert_eq!(row.slots[1].slot, 3);
    assert_eq!(
        (&row.slots[1].lead, &row.slots[1].rollback_stats),
        (&None, &None)
    );

    // The final flush snapshot keeps the client's statistics, which the
    // recorder holds itself, but not the lead figures or the clock, which
    // come from consensus state the flush may have outlived.
    let last = blob.samples.last().unwrap();
    assert_eq!(last.clock_pause_us, None);
    assert_eq!(last.slots[0].lead, None);
    assert_eq!(last.slots[0].rollback_stats, Some(client_stats(240)));

    // The whole blob reads back as it was written, and a row from before
    // these fields reads as having none of them.
    let json = serde_json::to_string(&blob).unwrap();
    let back: FlightBlob = serde_json::from_str(&json).unwrap();
    assert_eq!(back, blob);
    let old: SlotSample = serde_json::from_str(
        r#"{"slot": 1, "turns_validated": 0, "turns_forwarded": 0, "newest_seq": 0,
            "dedup_drops": 0, "oversize_diverts": 0, "redundant_payloads": 0,
            "upstream_lost_packets": 0, "cwnd": 0, "congestion_events": 0}"#,
    )
    .expect("a row from before the rollback figures still reads");
    assert_eq!((old.lead, old.rollback_stats), (None, None));
}

#[test]
fn a_lockstep_sessions_rows_carry_no_rollback_figures() {
    let recorder = FlightRecorder::default();
    let k = key(1);
    recorder.slot_counters(&k, SlotId(0)).note_validated(12);
    let conditions = crate::mesh::new_conditions_registry();
    recorder.sample_now(&conditions, |_| (None, None), |_| None, |_| None);

    let blob = recorder.take_blob(&k, true).expect("a recording exists");
    let json = serde_json::to_value(&blob.samples[0]).unwrap();
    assert!(json.get("clock_pause_us").is_none());
    let slot = &json["slots"][0];
    assert!(slot.get("lead").is_none());
    assert!(slot.get("rollback_stats").is_none());
}

#[test]
fn rollback_events_round_trip_through_the_blob() {
    let recorder = FlightRecorder::default();
    let k = key(1);
    let events = [
        FlightEvent::SessionClockAnchored {
            anchor_step: 23,
            adopted: true,
        },
        FlightEvent::SessionClockStopped {
            pause_us: 4_200_000,
        },
        FlightEvent::SlotRollbackStats {
            slot: 0,
            stats: client_stats(5_000),
        },
    ];
    for event in events.clone() {
        recorder.record(&k, event);
    }

    let blob = recorder.take_blob(&k, true).expect("a recording exists");
    let json = serde_json::to_value(&blob).unwrap();
    assert_eq!(json["events"][2]["event"], "slot_rollback_stats");
    assert_eq!(json["events"][2]["stats"]["through_turn"], 5_000);
    let back: FlightBlob = serde_json::from_value(json).unwrap();
    let recorded: Vec<FlightEvent> = back.events.into_iter().map(|r| r.event).collect();
    assert_eq!(recorded, events);
}
