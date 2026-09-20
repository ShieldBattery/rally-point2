//! Choosing a synced leave's apply frame, the frame-regression tripwire, and the final turn count.

use super::*;

/// The apply frame is one past the departing slot's own last observed
/// frame, whether that frame leads the session or trails it — a stalled
/// survivor's simulation pins at `last_frame + 1`, so scheduling from the
/// survivors' frames would put the leave past a frame the stalled ones can
/// reach. The trailing case is the one with teeth: with the departing slot
/// ahead, reading the basis off the maximum would give the same answer.
#[test]
fn decide_leave_schedules_from_the_departed_slot_not_the_survivors() {
    let mut maker = maker();
    // The departing slot (1) is the furthest ahead.
    maker.observe_frame(SlotId(0), GameFrameCount(40));
    maker.observe_frame(SlotId(1), GameFrameCount(50));
    let d = maker
        .decide_leave(SlotId(1), LEAVE_REASON_DROPPED)
        .expect("a leave is scheduled");
    assert_eq!(d.slot, 1);
    assert_eq!(d.reason, LEAVE_REASON_DROPPED);
    assert_eq!(
        d.apply_at_frame, 51,
        "one past the departed slot's last frame"
    );
    assert_eq!(d.leave_seq, 1);

    // And with the departing slot behind a fast survivor.
    let mut trailing = maker_with(bounds(0, 20));
    trailing.observe_frame(SlotId(0), GameFrameCount(80)); // a fast survivor
    trailing.observe_frame(SlotId(1), GameFrameCount(30)); // the departing slot, behind
    let d = trailing
        .decide_leave(SlotId(1), LEAVE_REASON_DROPPED)
        .unwrap();
    assert_eq!(
        d.apply_at_frame, 31,
        "one past the departed slot's frame, not the survivor's"
    );
}

/// No framed turn observed anywhere (pre-game / lobby): nothing to schedule.
#[test]
fn decide_leave_holds_without_a_frame_basis() {
    let mut maker = maker();
    assert_eq!(maker.decide_leave(SlotId(1), LEAVE_REASON_DROPPED), None);
}

/// A slot that never produced a framed turn has no frame of its own; the
/// session frame (the survivors' slowest) is the fallback basis.
#[test]
fn decide_leave_falls_back_to_the_session_frame_for_a_never_framed_slot() {
    let mut maker = maker();
    maker.observe_frame(SlotId(0), GameFrameCount(40)); // a framed survivor
    // Slot 1 departs having never framed a turn.
    let d = maker.decide_leave(SlotId(1), LEAVE_REASON_DROPPED).unwrap();
    assert_eq!(d.apply_at_frame, 41, "one past the session frame fallback");
}

// -- Leave apply-frame clamp: an inflated departing frame must
//    not schedule the leave past a frame the survivors can reach. Frames are
//    stamped one-per-turn (`frame = 100 + seq`); a survivor legitimately
//    *leads* the departing slot by the buffer depth before it stalls. --

/// The production shape of the stall this guards against: seed turns stamped
/// with a lobby-era index (215, 216), then in-loop turns from a restarted
/// counter (0, 1, ...). The first in-loop stamp trips the wire once; the
/// slot's frame stays at the high-water mark and later low stamps are quiet.
#[test]
fn a_stamp_below_the_high_water_mark_at_a_higher_seq_is_reported_once() {
    let mut maker = maker_with(bounds(0, 6));
    assert_eq!(
        maker.observe_turn_frame(SlotId(2), 0, GameFrameCount(215)),
        None
    );
    assert_eq!(
        maker.observe_turn_frame(SlotId(2), 1, GameFrameCount(216)),
        None
    );
    assert_eq!(
        maker.observe_turn_frame(SlotId(2), 2, GameFrameCount(0)),
        Some(FrameRegression { prior_frame: 216 }),
        "the restarted counter's first stamp is the report",
    );
    assert_eq!(
        maker.observe_turn_frame(SlotId(2), 3, GameFrameCount(1)),
        None,
        "one report per slot",
    );
    assert_eq!(
        maker.session_frame(),
        Some(GameFrameCount(216)),
        "the observation is not corrected: the high-water mark stands",
    );
}

/// Reordering on the wire: a lower seq landing after a higher one, whatever
/// its stamp, is not a regression — the counter never went backwards, the
/// turn is just late.
#[test]
fn an_out_of_order_lower_seq_never_trips_the_tripwire() {
    let mut maker = maker_with(bounds(0, 6));
    assert_eq!(
        maker.observe_turn_frame(SlotId(1), 5, GameFrameCount(105)),
        None
    );
    assert_eq!(
        maker.observe_turn_frame(SlotId(1), 3, GameFrameCount(103)),
        None,
        "a late, lower-seq turn with a lower stamp is ordinary reordering",
    );
    assert_eq!(
        maker.observe_turn_frame(SlotId(1), 6, GameFrameCount(106)),
        None
    );
}

/// The registry-level observer surfaces the report as a warning and a
/// flight event, so a recording shows the stamp restart directly instead of
/// leaving it to be inferred from directive arithmetic.
#[test]
fn a_frame_regression_is_recorded_as_a_flight_event() {
    let makers = new_decision_makers();
    let k = key();
    makers.lock().insert(k.clone(), maker_with(bounds(0, 6)));
    let home = crate::consensus::delivery::DeliveryHome::Local;
    observe_turn_frame(&makers, &k, SlotId(2), 0, GameFrameCount(126), home);
    observe_turn_frame(&makers, &k, SlotId(2), 1, GameFrameCount(0), home);
    observe_turn_frame(&makers, &k, SlotId(2), 2, GameFrameCount(1), home);

    let events: Vec<_> = makers
        .flight_recorder()
        .events(&k)
        .into_iter()
        .map(|record| record.event)
        .collect();
    assert_eq!(
        events,
        vec![
            crate::observability::flight_recorder::FlightEvent::FrameStampRegressed {
                slot: 2,
                seq: 1,
                frame: 0,
                prior_frame: 126,
            }
        ],
        "exactly one event, for the first backwards stamp",
    );
}

/// The exact production flow on the departing slot's home relay: read the
/// last frame and the reachability ceiling, record the departure with both,
/// A decided clean leave carries the record's home-authored final turn
/// count verbatim — the client-side synchronization point rides the
/// directive.
#[test]
fn a_decided_clean_leave_carries_the_home_authored_final_turn_count() {
    let mut maker = maker_with(bounds(0, 6));
    maker.observe_frame(SlotId(1), GameFrameCount(115));
    maker.record_departure(
        SlotId(1),
        DepartureStamps {
            final_turn_count: Some(112),
            ..framed(115)
        },
        LEAVE_REASON_LEFT,
    );
    let leave = maker
        .decide_leave(SlotId(1), LEAVE_REASON_LEFT)
        .expect("a leave is scheduled");
    assert_eq!(leave.final_turn_count, Some(112));
}

/// A dropped slot's directive never carries a count, even when its record
/// holds one: a drop has no ingress cut — the slot can be reconnecting
/// (here or on another relay) while an honored drop request or abandon
/// expiry decides this leave, pushing turns past the recorded count into
/// the mesh, and a count that under-runs turns that exist splits survivors
/// between count-scheduled and consumed-past-it application. A drop
/// schedules by frame instead, which its uniformly-stalled survivors apply
/// consistently.
#[test]
fn a_decided_drop_strips_the_final_turn_count() {
    let mut maker = maker_with(bounds(0, 6));
    maker.observe_frame(SlotId(1), GameFrameCount(115));
    maker.record_departure(
        SlotId(1),
        DepartureStamps {
            final_turn_count: Some(112),
            ..framed(115)
        },
        LEAVE_REASON_DROPPED,
    );
    let leave = maker
        .decide_leave(SlotId(1), LEAVE_REASON_DROPPED)
        .expect("a leave is scheduled");
    assert_eq!(leave.final_turn_count, None);
}

/// After a rehome, no single relay's forward gate provably covers what
/// every survivor consumed — the replaced relay can have delivered turns
/// toward one surviving relay that the slot's fresh home never carried —
/// so even a clean leave decided on a resumed session stamps no count and
/// falls back to frame scheduling.
#[test]
fn a_resumed_session_stamps_no_count_on_new_leaves() {
    let mut maker = maker_with(bounds(0, 6));
    maker.resumed = true;
    maker.observe_frame(SlotId(1), GameFrameCount(115));
    maker.record_departure(
        SlotId(1),
        DepartureStamps {
            final_turn_count: Some(112),
            ..framed(115)
        },
        LEAVE_REASON_LEFT,
    );
    let leave = maker
        .decide_leave(SlotId(1), LEAVE_REASON_LEFT)
        .expect("a leave is scheduled");
    assert_eq!(leave.final_turn_count, None);
}

/// A promoted authority re-derives a clean leave with the identical final
/// turn count: the count is part of the shared departure record, so a
/// handoff reproduces it exactly like the apply frame.
#[test]
fn a_handoff_rederivation_reproduces_the_final_turn_count() {
    let stamps = DepartureStamps {
        final_turn_count: Some(112),
        ..framed(115)
    };
    let mut peer = peer_maker_with(bounds(0, 6));
    peer.observe_frame(SlotId(1), GameFrameCount(115));
    peer.record_departure(SlotId(1), stamps, LEAVE_REASON_LEFT);
    let (leaves, _fresh) = peer.set_authority(Authority::SelfRelay, &HashSet::new());
    let rederived = leaves
        .iter()
        .find(|l| l.slot == 1)
        .expect("the promotion re-derives the leave");
    assert_eq!(rederived.final_turn_count, Some(112));
}

/// An observed peer directive's count folds into this relay's departure
/// record, so a later promotion here re-derives with the same count even
/// though no `SlotDeparted` ever carried it to this relay. Clean leaves
/// only: a dropped directive's count is stripped at observation, so its
/// record stays count-less too.
#[test]
fn an_observed_leave_folds_its_final_turn_count_into_the_record() {
    let mut maker = peer_maker_with(bounds(0, 6));
    let directive = LeaveDirective {
        finalized: false,
        slot: 2,
        reason: LEAVE_REASON_LEFT,
        apply_at_frame: 116,
        leave_seq: 1,
        final_turn_count: Some(112),
    };
    assert!(maker.observe_leave(&directive));
    assert_eq!(
        maker.departures.get(&SlotId(2)).unwrap().final_turn_count,
        Some(112),
    );

    let dropped = LeaveDirective {
        slot: 3,
        reason: LEAVE_REASON_DROPPED,
        leave_seq: 2,
        ..directive
    };
    assert!(maker.observe_leave(&dropped));
    assert_eq!(
        maker.departures.get(&SlotId(3)).unwrap().final_turn_count,
        None,
        "a dropped directive's stripped count never reaches the record",
    );
}
