//! The silence watch's acting half: what the relay does to a slot the
//! decision-makers named. Which slot gets named is the decision-makers' own
//! question, tested in `consensus::tests::silence`.

use super::*;

use std::time::Duration;

use parking_lot::Mutex;

use crate::consensus::SilentSlot;
use crate::observability::flight_recorder::{FlightEvent, FlightRecorder};
use crate::routing::silence::{SilenceCloser, close_silent_slots};

/// A closer that records what it was asked to close instead of touching a
/// roster, so the watch can be driven with no live slot task behind it.
#[derive(Default)]
struct RecordingCloser {
    closed: Mutex<Vec<(SessionKey, SlotId)>>,
}

impl SilenceCloser for RecordingCloser {
    fn close_silent_slot(&self, key: &SessionKey, slot: SlotId) {
        self.closed.lock().push((key.clone(), slot));
    }
}

fn named(slot: u8) -> SilentSlot {
    SilentSlot {
        slot: SlotId(slot),
        silent_for: Duration::from_millis(11_000),
        lead: Duration::from_millis(200),
    }
}

#[test]
fn every_named_slot_has_its_link_closed() {
    let closer = RecordingCloser::default();
    let one = session_key(1);
    let two = session_key(2);

    close_silent_slots(
        &FlightRecorder::default(),
        &closer,
        vec![(one.clone(), named(1)), (two.clone(), named(3))],
    );

    assert_eq!(
        *closer.closed.lock(),
        vec![(one, SlotId(1)), (two, SlotId(3))],
        "each session's named slot is closed in its own session",
    );
}

#[test]
fn an_eviction_is_recorded_with_the_margin_it_rested_on() {
    let recorder = FlightRecorder::default();
    let key = session_key(1);

    close_silent_slots(
        &recorder,
        &RecordingCloser::default(),
        vec![(key.clone(), named(1))],
    );

    let events: Vec<FlightEvent> = recorder
        .events(&key)
        .into_iter()
        .map(|record| record.event)
        .collect();
    assert!(
        events.contains(&FlightEvent::SlotEvictedSilent {
            slot: 1,
            silent_ms: 11_000,
            lead_ms: 200,
        }),
        "the recording carries the eviction with both measures: {events:?}",
    );
}

#[test]
fn a_tick_that_named_nobody_closes_nothing() {
    let closer = RecordingCloser::default();

    close_silent_slots(&FlightRecorder::default(), &closer, Vec::new());

    assert!(closer.closed.lock().is_empty());
}
