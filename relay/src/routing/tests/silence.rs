//! The silence watch's acting half: what the relay does to a slot the
//! decision-makers named, decided by what that slot's link still receives.
//! Which slot gets named is the decision-makers' own question, tested in
//! `consensus::tests::silence`.

use super::*;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rally_point_proto::control::BufferBounds;
use rally_point_proto::messages::SlotConditions;

use crate::consensus::{Authority, DecisionMakers, MakerSync};
use crate::observability::flight_recorder::FlightEvent;
use crate::routing::LinkReceipts;
use crate::routing::silence::{SilenceLinks, SilenceWatch, TRANSPORT_QUIET_GRACE};

const WINDOW: Duration = Duration::from_secs(10);

/// How the watch asked a link to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Closed {
    Evicted { slot: u8, connection_epoch: u64 },
    Quiet { slot: u8, connection_epoch: u64 },
}

/// Links whose receive counts the test sets, recording how the watch asked
/// each to end instead of touching a roster.
#[derive(Default)]
struct FakeLinks {
    receipts: Mutex<HashMap<SlotId, LinkReceipts>>,
    closed: Mutex<Vec<Closed>>,
}

impl FakeLinks {
    fn receiving(&self, slot: u8, connection_epoch: u64, frames: u64) {
        self.receipts.lock().insert(
            SlotId(slot),
            LinkReceipts {
                connection_epoch,
                frames,
            },
        );
    }

    fn closed(&self) -> Vec<Closed> {
        self.closed.lock().clone()
    }
}

impl SilenceLinks for FakeLinks {
    fn receipts(&self, _key: &SessionKey, slot: SlotId) -> Option<LinkReceipts> {
        self.receipts.lock().get(&slot).copied()
    }

    fn close_silent_slot(&self, _key: &SessionKey, slot: SlotId, connection_epoch: u64) {
        self.closed.lock().push(Closed::Evicted {
            slot: slot.0,
            connection_epoch,
        });
    }

    fn close_quiet_slot(&self, _key: &SessionKey, slot: SlotId, connection_epoch: u64) {
        self.closed.lock().push(Closed::Quiet {
            slot: slot.0,
            connection_epoch,
        });
    }
}

/// A two-slot session homed on this relay in which slot 1's turns stopped a
/// second in and slot 0's 200ms later, so slot 1 is the one everyone waits on
/// and is named once the session has sat still for a window.
fn stalled_session(key: &SessionKey) -> (DecisionMakers, Instant) {
    let makers = crate::consensus::new_decision_makers();
    let _ = makers.sync_maker(
        key,
        MakerSync {
            expected_slots: [SlotId(0), SlotId(1)].into(),
            homed_slots: [SlotId(0), SlotId(1)].into(),
            ..MakerSync::new(BufferBounds::new(0, 20).unwrap(), Authority::SelfRelay)
        },
    );
    let start = Instant::now();
    {
        let mut guard = makers.lock();
        let maker = guard.get_mut(key).expect("the sync created a maker");
        maker.mark_started();
        for slot in [0, 1] {
            assert!(maker.activate_connection_epoch(SlotId(slot), 1, start));
            maker.ingest_local_condition(&SlotConditions {
                slot: u32::from(slot),
                rtt_us: 50_000,
                lost_packets: 0,
                sent_packets: 10,
                connection_epoch: Some(1),
            });
            maker.note_slot_started(SlotId(slot), start);
        }
        maker.note_forward_advance(SlotId(1), start + Duration::from_secs(1));
        maker.note_forward_advance(SlotId(0), start + Duration::from_millis(1200));
    }
    (makers, start)
}

fn events(makers: &DecisionMakers, key: &SessionKey) -> Vec<FlightEvent> {
    makers
        .flight_recorder()
        .events(key)
        .into_iter()
        .map(|record| record.event)
        .collect()
}

fn evicted(makers: &DecisionMakers, key: &SessionKey, slot: u8) -> bool {
    makers
        .lock()
        .get(key)
        .is_some_and(|maker| maker.eviction(SlotId(slot)).is_some())
}

#[test]
fn a_named_slot_whose_link_keeps_receiving_is_evicted() {
    let key = key();
    let (makers, start) = stalled_session(&key);
    let links = FakeLinks::default();
    let mut watch = SilenceWatch::default();

    links.receiving(1, 1, 100);
    watch.tick(&makers, &links, WINDOW, start + Duration::from_secs(12));
    assert!(
        links.closed().is_empty(),
        "naming the slot is not yet evidence its client is still there",
    );
    assert!(events(&makers, &key).contains(&FlightEvent::SlotSilent {
        slot: 1,
        silent_ms: 11_000,
        lead_ms: 200,
    }));

    // A keepalive arrives: the network path is up while the turns are not.
    links.receiving(1, 1, 101);
    watch.tick(&makers, &links, WINDOW, start + Duration::from_secs(14));
    assert_eq!(
        links.closed(),
        vec![Closed::Evicted {
            slot: 1,
            connection_epoch: 1,
        }],
        "the eviction is ordered for the very connection that was named",
    );
    assert!(
        !evicted(&makers, &key, 1),
        "the link's own task marks the eviction as it ends the link, never the watch",
    );
    assert!(
        !events(&makers, &key)
            .iter()
            .any(|event| matches!(event, FlightEvent::SlotEvictedSilent { .. })),
        "only a link task that commits the eviction records one",
    );

    // Its teardown is still in flight: the order is not repeated.
    links.receiving(1, 1, 102);
    watch.tick(&makers, &links, WINDOW, start + Duration::from_secs(16));
    assert_eq!(links.closed().len(), 1);
}

#[test]
fn a_named_slot_whose_link_receives_nothing_is_left_to_the_transport() {
    let key = key();
    let (makers, start) = stalled_session(&key);
    let links = FakeLinks::default();
    let mut watch = SilenceWatch::default();

    links.receiving(1, 1, 100);
    for secs in [12, 14, 16, 20] {
        watch.tick(&makers, &links, WINDOW, start + Duration::from_secs(secs));
    }

    assert!(
        links.closed().is_empty(),
        "a dead path is the transport's to close, as a disconnect the client can come back from",
    );
    assert!(
        !evicted(&makers, &key, 1),
        "nothing refuses the slot's re-dial"
    );
}

#[test]
fn a_quiet_link_the_transport_has_not_closed_is_ended_as_a_lost_connection() {
    let key = key();
    let (makers, start) = stalled_session(&key);
    let links = FakeLinks::default();
    let mut watch = SilenceWatch::default();
    let named_at = start + Duration::from_secs(12);

    links.receiving(1, 1, 100);
    watch.tick(&makers, &links, WINDOW, named_at);
    watch.tick(
        &makers,
        &links,
        WINDOW,
        named_at + TRANSPORT_QUIET_GRACE - Duration::from_millis(1),
    );
    assert!(links.closed().is_empty(), "still inside the grace");

    watch.tick(&makers, &links, WINDOW, named_at + TRANSPORT_QUIET_GRACE);
    assert_eq!(
        links.closed(),
        vec![Closed::Quiet {
            slot: 1,
            connection_epoch: 1,
        }],
        "the session is never held on a link nothing will close",
    );
    assert!(
        !evicted(&makers, &key, 1),
        "a link that never showed its client is there is not evicted: it may still resume",
    );
    assert!(
        !events(&makers, &key).iter().any(|event| matches!(
            event,
            FlightEvent::SlotQuietLinkClosed { .. } | FlightEvent::SlotEvictedSilent { .. }
        )),
        "only the link task that ends the link records how it ended",
    );
}

#[test]
fn a_new_link_generation_starts_its_evidence_over() {
    let key = key();
    let (makers, start) = stalled_session(&key);
    let links = FakeLinks::default();
    let mut watch = SilenceWatch::default();

    links.receiving(1, 1, 100);
    watch.tick(&makers, &links, WINDOW, start + Duration::from_secs(12));
    links.receiving(1, 2, 500);
    watch.tick(&makers, &links, WINDOW, start + Duration::from_secs(14));
    assert!(
        links.closed().is_empty(),
        "another connection's count says nothing about the one that was named",
    );

    links.receiving(1, 2, 501);
    watch.tick(&makers, &links, WINDOW, start + Duration::from_secs(16));
    assert_eq!(
        links.closed(),
        vec![Closed::Evicted {
            slot: 1,
            connection_epoch: 2,
        }],
        "the new generation is judged on its own evidence, and only it is signalled",
    );
}

#[test]
fn a_slot_with_no_live_link_is_never_closed_here() {
    let key = key();
    let (makers, start) = stalled_session(&key);
    let links = FakeLinks::default();
    let mut watch = SilenceWatch::default();

    for secs in [12, 14] {
        watch.tick(&makers, &links, WINDOW, start + Duration::from_secs(secs));
    }
    watch.tick(
        &makers,
        &links,
        WINDOW,
        start + Duration::from_secs(12) + TRANSPORT_QUIET_GRACE,
    );

    assert!(links.closed().is_empty());
    assert!(!evicted(&makers, &key, 1));
}

#[test]
fn a_slot_that_moves_again_is_not_evicted_on_its_earlier_naming() {
    let key = key();
    let (makers, start) = stalled_session(&key);
    let links = FakeLinks::default();
    let mut watch = SilenceWatch::default();

    links.receiving(1, 1, 100);
    watch.tick(&makers, &links, WINDOW, start + Duration::from_secs(12));
    // The late turn arrives: the session is moving again, and the frames that
    // carried it are not evidence of a hung game.
    makers
        .lock()
        .get_mut(&key)
        .expect("the maker is still there")
        .note_forward_advance(SlotId(1), start + Duration::from_millis(12_500));
    links.receiving(1, 1, 140);
    watch.tick(&makers, &links, WINDOW, start + Duration::from_secs(14));

    assert!(links.closed().is_empty());
    assert!(!evicted(&makers, &key, 1));
}
