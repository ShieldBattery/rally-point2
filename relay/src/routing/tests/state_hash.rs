//! The state hash watch's acting half: what the relay does with a slot a
//! rollback verdict named. Which slots get named, and which of them this relay
//! homes, is the decision-makers' own question, tested in
//! `consensus::tests::state_hash`.

use super::*;

use parking_lot::Mutex;

use crate::consensus::DesyncEviction;
use crate::observability::flight_recorder::{FlightEvent, FlightRecorder};
use crate::routing::state_hash::{DesyncEvictor, end_desynced_slot_link, evict_desynced_slots};

/// An evictor that records what it was asked to do instead of touching a
/// roster or a mesh link, so the pass can be driven with neither behind it.
#[derive(Default)]
struct RecordingEvictor {
    closed: Mutex<Vec<(SessionKey, SlotId)>>,
    announced: Mutex<Vec<(SessionKey, SlotId, u64)>>,
}

impl DesyncEvictor for RecordingEvictor {
    fn close_desynced_slot(&self, key: &SessionKey, slot: SlotId) {
        self.closed.lock().push((key.clone(), slot));
    }

    fn announce_desync_eviction(&self, key: &SessionKey, slot: SlotId, sync_ordinal: u64) {
        self.announced
            .lock()
            .push((key.clone(), slot, sync_ordinal));
    }
}

fn named(slot: u8, sync_ordinal: u64, homed: bool) -> DesyncEviction {
    DesyncEviction {
        slot: SlotId(slot),
        sync_ordinal,
        homed,
    }
}

#[test]
fn a_homed_slot_is_closed_and_every_named_slot_is_announced() {
    let evictor = RecordingEvictor::default();
    let one = session_key(1);
    let two = session_key(2);

    evict_desynced_slots(
        &FlightRecorder::default(),
        &evictor,
        vec![
            (one.clone(), named(1, 8, true)),
            (two.clone(), named(3, 16, false)),
        ],
    );

    assert_eq!(
        *evictor.closed.lock(),
        vec![(one.clone(), SlotId(1))],
        "only the slot this relay homes has its link closed here",
    );
    assert_eq!(
        *evictor.announced.lock(),
        vec![(one, SlotId(1), 8), (two, SlotId(3), 16)],
        "every named slot is announced, so a peer that homes it evicts it",
    );
}

#[test]
fn a_home_eviction_is_recorded_with_the_step_it_rested_on() {
    let recorder = FlightRecorder::default();
    let one = session_key(1);
    let two = session_key(2);

    evict_desynced_slots(
        &recorder,
        &RecordingEvictor::default(),
        vec![
            (one.clone(), named(1, 8, true)),
            (two.clone(), named(3, 16, false)),
        ],
    );

    let events = |key: &SessionKey| -> Vec<FlightEvent> {
        recorder
            .events(key)
            .into_iter()
            .map(|record| record.event)
            .collect()
    };
    assert!(
        events(&one).contains(&FlightEvent::SlotEvictedDesync {
            slot: 1,
            sync_ordinal: 8,
        }),
        "the home records the eviction: {:?}",
        events(&one),
    );
    assert!(
        events(&two).is_empty(),
        "a slot homed elsewhere is recorded by its home, not here",
    );
}

#[test]
fn a_tick_with_no_verdict_does_nothing() {
    let evictor = RecordingEvictor::default();
    evict_desynced_slots(&FlightRecorder::default(), &evictor, Vec::new());
    assert!(evictor.closed.lock().is_empty());
    assert!(evictor.announced.lock().is_empty());
}

/// Seals three forwarded turns of slot 1, the harness's departing slot.
fn forward_three(h: &DropHarness, k: &SessionKey) {
    for seq in 0..3 {
        let _ = crate::mesh::mark_seen(&h.seen, k, SlotId(1), seq);
    }
}

/// A live evicted slot's link is signalled to close with the desync reason,
/// and nothing is decided until its own teardown has recorded the departure.
/// That teardown then finalizes the drop itself: the survivor receives a leave
/// carrying the sealed count, and nobody had to ask for the drop.
#[tokio::test]
async fn a_live_evicted_slot_is_closed_and_its_teardown_finalizes_the_drop() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), Some(&[0, 1]));
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    let mesh = h.mesh(&holds);
    let evicted = registered(&h.sessions, &k, SlotId(1));
    let shutdown = evicted.shutdown_handle();
    forward_three(&h, &k);

    assert!(h.makers.mark_desync_evicted(&k, SlotId(1)));
    end_desynced_slot_link(&h.sessions, &mesh, &k, SlotId(1));
    shutdown.notified().await;
    assert_eq!(evicted.close_reason(), SlotCloseReason::DesyncEvicted);
    assert!(
        h.inbox.try_recv_leave().is_none(),
        "nothing is decided while the link is still up",
    );

    // The woken link task's teardown.
    end_slot_link(&h.sessions, &mesh, &k, SlotId(1), 5, false);

    let leave = h
        .inbox
        .try_recv_leave()
        .expect("the teardown's finalized drop reaches the survivor");
    assert_eq!(leave.reason, LEAVE_REASON_DROPPED);
    assert_eq!(leave.final_turn_count, Some(3));
    assert!(leave.finalized);
    assert!(
        !holds.is_pending(&k, SlotId(1)),
        "the hold was claimed without waiting out any unlock floor",
    );
}

/// A slot that had already disconnected when the verdict named it has no link
/// left to close, so the eviction finalizes its held drop at once.
#[tokio::test]
async fn an_evicted_slot_already_gone_is_finalized_at_once() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), Some(&[0, 1]));
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    let mesh = h.mesh(&holds);
    let departed = registered(&h.sessions, &k, SlotId(1));
    forward_three(&h, &k);
    end_slot_link(&h.sessions, &mesh, &k, SlotId(1), 5, false);
    drop(departed);
    assert!(holds.is_pending(&k, SlotId(1)), "an ordinary drop is held");
    assert!(h.inbox.try_recv_leave().is_none());

    assert!(h.makers.mark_desync_evicted(&k, SlotId(1)));
    end_desynced_slot_link(&h.sessions, &mesh, &k, SlotId(1));

    let leave = h
        .inbox
        .try_recv_leave()
        .expect("the eviction finalizes the held drop");
    assert_eq!(leave.final_turn_count, Some(3));
    assert!(leave.finalized);
}

/// A home that is not the session authority seals the count and sends the
/// result over the mesh unprompted, for the authority to decide on.
#[tokio::test]
async fn a_home_that_is_not_the_authority_sends_its_result_over_the_mesh() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), Some(&[0, 1]));
    let _ = h.makers.set_authority(
        &k,
        crate::consensus::Authority::Peer,
        &std::collections::HashSet::new(),
    );
    let (fwd_tx, _fwd_rx) = tokio::sync::mpsc::channel(FORWARD_CAPACITY);
    let (ctl_tx, mut ctl_rx) = tokio::sync::mpsc::unbounded_channel();
    let _link = crate::mesh::register_mesh_link(
        &h.mesh_links,
        k.clone(),
        fwd_tx,
        ctl_tx,
        Arc::new(tokio::sync::Notify::new()),
    );
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    let mesh = h.mesh(&holds);
    let departed = registered(&h.sessions, &k, SlotId(1));
    forward_three(&h, &k);
    assert!(h.makers.mark_desync_evicted(&k, SlotId(1)));

    end_slot_link(&h.sessions, &mesh, &k, SlotId(1), 5, false);
    drop(departed);

    use rally_point_proto::messages::mesh_control_frame::Kind;
    let frames: Vec<_> = std::iter::from_fn(|| ctl_rx.try_recv().ok())
        .filter_map(|frame| frame.kind)
        .collect();
    let departed_at = frames
        .iter()
        .position(|kind| matches!(kind, Kind::SlotDeparted(d) if d.slot == 1))
        .expect("the departure is announced to the authority");
    let result_at = frames
        .iter()
        .position(|kind| {
            matches!(
                kind,
                Kind::FinalizeDropResult(r)
                    if r.slot == 1
                        && r.connection_epoch == Some(5)
                        && r.final_turn_count == Some(3)
            )
        })
        .expect("the sealed count goes to the authority unasked");
    assert!(
        departed_at < result_at,
        "the departure precedes the result on the ordered stream, so the authority holds \
         the record the result names",
    );
    assert!(
        h.inbox.try_recv_leave().is_none(),
        "only the authority decides the leave",
    );
}

/// A slot evicted for silence has its drop decided by the survivors' own
/// request like any lost client's; its teardown finalizes nothing by itself.
#[tokio::test]
async fn a_silence_evicted_slot_is_not_finalized_by_its_teardown() {
    let k = key();
    let mut h = drop_hold_harness(&k, SlotId(0), SlotId(1), Some(&[0, 1]));
    let holds = DropHolds::new(UNREACHABLE_UNLOCK, UNREACHABLE_UNLOCK);
    let mesh = h.mesh(&holds);
    let departed = registered(&h.sessions, &k, SlotId(1));
    forward_three(&h, &k);
    h.makers
        .lock()
        .get_mut(&k)
        .expect("the harness seeded a maker")
        .mark_evicted(SlotId(1), crate::consensus::EvictionCause::Silent);

    end_slot_link(&h.sessions, &mesh, &k, SlotId(1), 5, false);
    drop(departed);

    assert!(h.inbox.try_recv_leave().is_none());
    assert!(holds.is_pending(&k, SlotId(1)), "the drop stays held");
}
