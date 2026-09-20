//! Session-close notices and the external refs stamped onto every notice.

use super::*;

/// `session_closed` fires one `SessionClosed` notice naming the tenant and
/// session, so the coordinator can count serving relays that have torn down.
#[test]
fn session_closed_fires_a_session_closed_notice() {
    let (registry, mut rx) = notifying_registry();
    let k = key();

    registry.session_closed(&k);
    match rx.try_recv().expect("a queued notice") {
        RelayNotice::SessionClosed { tenant, session } => {
            assert_eq!(tenant, k.tenant);
            assert_eq!(session, k.session);
        }
        other => panic!("expected a session-closed notice, got {other:?}"),
    }
}

/// A close for a session this relay recorded nothing of leaves the flight
/// recorder untouched: the close seals a recording, it never begins one.
#[test]
fn session_closed_does_not_begin_a_flight_recording() {
    let registry = new_decision_makers();
    let k = key();

    registry.session_closed(&k);

    assert!(
        registry.flight_recorder().recorded_sessions().is_empty(),
        "an unobserved session records nothing to flush",
    );
}

/// A close for a session no descriptor ever named (no maker — a provisional
/// admission) plants no close seal: no retirement will ever clear one, so a
/// seal would live for the relay's lifetime, and it would also silently
/// drop the recording of a genuinely fresh later admission for the same id.
/// A descriptor-named session's close still seals until retirement.
#[test]
fn session_closed_without_a_maker_plants_no_seal() {
    let registry = new_decision_makers();
    let k = key();
    registry.record_event(
        &k,
        FlightEvent::SlotConnected {
            slot: 0,
            resumed: false,
        },
    );

    // No tokio runtime here, so the flush (and its seal decision) runs
    // synchronously — deterministic for the assertion below.
    registry.session_closed(&k);
    assert!(
        registry.flight_recorder().recorded_sessions().is_empty(),
        "the close flushed the recording",
    );

    // A fresh admission for the same id records again — nothing sealed it.
    registry.record_event(
        &k,
        FlightEvent::SlotConnected {
            slot: 1,
            resumed: false,
        },
    );
    assert!(
        !registry.flight_recorder().recorded_sessions().is_empty(),
        "a maker-less close leaves no seal behind",
    );
}

/// The same close on a descriptor-named session (a maker exists) seals: a
/// straggling event before retirement must not conjure a replacement
/// recording.
#[test]
fn session_closed_with_a_maker_still_seals() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_default(&registry, &k, bounds(0, 20), Authority::SelfRelay);
    registry.record_event(
        &k,
        FlightEvent::SlotConnected {
            slot: 0,
            resumed: false,
        },
    );

    registry.session_closed(&k);
    registry.record_event(
        &k,
        FlightEvent::SlotConnected {
            slot: 1,
            resumed: false,
        },
    );
    assert!(
        registry.flight_recorder().recorded_sessions().is_empty(),
        "the seal blocks a straggler from recreating the recording",
    );
}

/// `set_session_refs` replaces rather than accumulates on a re-apply (a
/// changed descriptor), and `deregister_maker` drops both the maker and the
/// session's refs, so neither outlives the session it describes.
#[test]
fn set_session_refs_replaces_on_reapply_and_deregister_forgets() {
    let (registry, mut rx) = notifying_registry();
    let k = key();
    let _ = sync_default(&registry, &k, bounds(0, 20), Authority::SelfRelay);

    registry.set_session_refs(
        &k,
        Some("game-old".to_owned()),
        HashMap::from([(SlotId(1), "sb-user-old".to_owned())]),
    );
    // A re-applied descriptor with fresh refs replaces the old ones.
    registry.set_session_refs(
        &k,
        Some("game-new".to_owned()),
        HashMap::from([(SlotId(1), "sb-user-new".to_owned())]),
    );

    registry.observe_frame(&k, SlotId(0), GameFrameCount(40));
    assert!(
        registry
            .decide_leave(&k, SlotId(1), LEAVE_REASON_DROPPED)
            .is_some()
    );
    let notice = recv_departure(&mut rx);
    assert_eq!(notice.external_id, Some("game-new".to_owned()));
    assert_eq!(notice.external_ref, Some("sb-user-new".to_owned()));

    // Deregistering removes the maker and forgets the refs: a later
    // decide_leave on a freshly re-created maker for the same key sees none.
    assert!(registry.lock().contains_key(&k));
    registry.deregister_maker(&k);
    assert!(!registry.lock().contains_key(&k));
    let _ = sync_default(&registry, &k, bounds(0, 20), Authority::SelfRelay);
    registry.observe_frame(&k, SlotId(0), GameFrameCount(40));
    assert!(
        registry
            .decide_leave(&k, SlotId(1), LEAVE_REASON_DROPPED)
            .is_some()
    );
    let notice2 = recv_departure(&mut rx);
    assert!(
        notice2.external_id.is_none(),
        "deregistering forgot the old session's refs",
    );
}

// -- Synced player-leave (decide_leave) --
