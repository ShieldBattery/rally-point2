//! Region-label release: the wall-clock gate, what can and cannot open it, and re-sends after release.

use super::*;

#[test]
fn region_labels_stay_shut_in_until_the_release_delay_has_elapsed() {
    let mut maker = maker_with_labels(&[(1, "us-east"), (2, "eu-central")]);

    // A session that has not started has no clock to measure from, so the
    // gate cannot open however many turns are delivered.
    assert_eq!(
        maker.maybe_release_region_labels(REGION_LABEL_RELEASE_DELAY),
        None,
        "a session that never started never releases labels",
    );

    // Starting it begins the clock, but the delay has not elapsed.
    maker.mark_started();
    assert_eq!(
        maker.maybe_release_region_labels(REGION_LABEL_RELEASE_DELAY),
        None,
    );
    assert_eq!(maker.released_region_labels(), None);

    // Just short of the delay is still shut — the boundary that matters, since
    // a client whose game ends there has never been able to obtain a label.
    maker.backdate_session_start(REGION_LABEL_RELEASE_DELAY - Duration::from_millis(1));
    assert_eq!(
        maker.maybe_release_region_labels(REGION_LABEL_RELEASE_DELAY),
        None,
        "one millisecond short of the delay keeps the gate shut",
    );

    // Crossing it opens the gate and yields the whole map, once.
    maker.backdate_session_start(Duration::from_millis(1));
    let released = maker
        .maybe_release_region_labels(REGION_LABEL_RELEASE_DELAY)
        .expect("the elapsed delay opens the gate");
    assert_eq!(
        released.iter().map(|l| l.relay_id).collect::<Vec<_>>(),
        vec![1, 2],
    );
    assert_eq!(
        maker.maybe_release_region_labels(REGION_LABEL_RELEASE_DELAY),
        None,
        "the gate opens once; later turns fan nothing out again",
    );
    assert_eq!(
        maker.released_region_labels(),
        Some(released),
        "a slot connecting afterwards still reads the map",
    );
}

#[test]
fn a_forged_game_frame_cannot_open_the_region_label_gate() {
    // The gate takes no input a client controls. A turn claiming an enormous
    // `game_frame_count` the instant the session starts is the exact forgery
    // the wall-clock measure exists to defeat: `observe_turn_frame` accepts the
    // claim (it is the consensus coordinate's own input, defended by taking the
    // per-session minimum), and the gate stays shut regardless.
    let mut maker = maker_with_labels(&[(1, "us-east")]);
    maker.mark_started();
    maker.observe_frame(SlotId(0), GameFrameCount(u32::MAX));
    maker.observe_turn_frame(SlotId(0), 0, GameFrameCount(u32::MAX));

    assert_eq!(
        maker.maybe_release_region_labels(REGION_LABEL_RELEASE_DELAY),
        None,
        "no claimed frame, however large, advances the relay's clock",
    );
    assert_eq!(maker.released_region_labels(), None);
}

#[test]
fn every_session_start_path_starts_the_region_label_clock() {
    // The gate measures from the session-started latch, so a path that latched
    // `started` without recording the instant would leave that relay's labels
    // sealed for the whole game. All three latch paths must arm the clock.
    let backdated_release = |mut maker: DecisionMaker| {
        maker.backdate_session_start(REGION_LABEL_RELEASE_DELAY);
        maker
            .maybe_release_region_labels(REGION_LABEL_RELEASE_DELAY)
            .is_some()
    };

    // The authority's own coverage latch, via `maybe_start`.
    let mut authority = maker_with_labels(&[(1, "us-east")]);
    authority.set_expected_slots([SlotId(0)].into_iter().collect());
    assert!(authority.note_slot_present(SlotId(0)), "coverage latches");
    assert!(backdated_release(authority));

    // A peer relay adopting the authority's directive off the mesh.
    let mut peer = maker_with_labels(&[(1, "us-east")]);
    peer.adopt_session_start(Some(4));
    assert!(backdated_release(peer));

    // A relay resuming an already-running session from a rehome descriptor.
    let mut resumed = maker_with_labels(&[(1, "us-east")]);
    resumed.mark_started();
    assert!(backdated_release(resumed));
}

#[test]
fn a_re_delivered_session_start_does_not_defer_the_region_label_release() {
    // A start directive can arrive more than once (an authority handoff
    // re-firing it, a late slot's re-push). Re-stamping the clock on each would
    // let a session that keeps re-announcing its start hold the labels back
    // without bound, so only the first latch arms it.
    let mut maker = maker_with_labels(&[(1, "us-east")]);
    maker.mark_started();
    maker.backdate_session_start(REGION_LABEL_RELEASE_DELAY);

    maker.mark_started();
    maker.adopt_session_start(Some(4));
    assert!(
        maker
            .maybe_release_region_labels(REGION_LABEL_RELEASE_DELAY)
            .is_some(),
        "a re-delivered start leaves the original clock untouched",
    );
}

#[test]
fn a_replacement_relay_waits_out_its_own_release_delay() {
    // A relay taking over a running session latches started when it adopts the
    // session, so its clock is fresh and it conceals the labels again for a
    // full delay. Clients keep the map they already hold, so the cost is only
    // that a map CHANGED by the re-home reaches them one delay later — the
    // accepted trade for a gate no inherited, unverifiable start time can move.
    let mut replacement = maker_with_labels(&[(3, "ap-southeast")]);
    replacement.mark_started();
    assert_eq!(
        replacement.maybe_release_region_labels(REGION_LABEL_RELEASE_DELAY),
        None,
        "the replacement does not inherit the original relay's elapsed time",
    );

    replacement.backdate_session_start(REGION_LABEL_RELEASE_DELAY);
    assert!(
        replacement
            .maybe_release_region_labels(REGION_LABEL_RELEASE_DELAY)
            .is_some(),
        "once its own delay elapses it releases normally",
    );
}

#[test]
fn a_label_map_that_changes_after_release_is_re_sent_but_an_identical_one_is_not() {
    let mut maker = maker_with_labels(&[(1, "us-east")]);
    maker.mark_started();
    maker.backdate_session_start(REGION_LABEL_RELEASE_DELAY);
    assert!(
        maker
            .maybe_release_region_labels(REGION_LABEL_RELEASE_DELAY)
            .is_some()
    );

    // A re-push of the same descriptor changes nothing, so nothing is re-sent.
    assert_eq!(
        maker.set_region_labels(region_labels(&[(1, "us-east")])),
        None
    );

    // A re-home names a different relay: the clients holding the superseded
    // map must be corrected, so the new map comes back to be re-sent.
    let moved = region_labels(&[(4, "eu-central")]);
    assert_eq!(maker.set_region_labels(moved.clone()), Some(moved));
}

#[test]
fn a_session_with_no_region_labels_releases_nothing() {
    // An untagged fleet, a dev-injected descriptor, or a coordinator that
    // predates the map: the gate still opens, but there is nothing to send,
    // so no frame is ever produced.
    let mut maker = maker_with_labels(&[]);
    maker.mark_started();
    maker.backdate_session_start(REGION_LABEL_RELEASE_DELAY);
    assert_eq!(
        maker.maybe_release_region_labels(REGION_LABEL_RELEASE_DELAY),
        None,
    );
    assert_eq!(maker.released_region_labels(), None);

    // A descriptor arriving after the gate opened still reaches the clients:
    // the gate is open, so recording a non-empty map returns it to be sent.
    let late = region_labels(&[(6, "us-west")]);
    assert_eq!(maker.set_region_labels(late.clone()), Some(late));
}
