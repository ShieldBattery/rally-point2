//! The admission gates and the rollback rule, both as tables: a row per
//! session state the gates can be handed, and a row per refusal the pipeline
//! can produce.

use rally_point_proto::ids::SlotId;

use super::*;
use crate::consensus::{Authority, DepartureStamps, LEAVE_REASON_LEFT};
use crate::session::provisional_turns::PennedIngress;
use crate::test_support::{seed_maker, session_key};

/// Runs the pre-register gates in order, returning the first refusal — exactly
/// what `serve_connection`'s loop over [`PRE_REGISTER_GATES`] does.
fn run_gates(session: &SessionState, key: &SessionKey, slot: SlotId) -> Option<Refusal> {
    PRE_REGISTER_GATES
        .iter()
        .find_map(|gate| gate(session, key, slot))
}

/// Applies a descriptor homing `homed` of `expected` on this relay.
fn home(session: &SessionState, key: &SessionKey, expected: &[u8], homed: &[u8]) {
    let _ = seed_maker(
        &session.decision_makers,
        key,
        Authority::SelfRelay,
        expected,
        homed,
    );
}

/// Records a departure for `slot` the way a dropped link's teardown would.
fn depart(session: &SessionState, key: &SessionKey, slot: SlotId) {
    crate::consensus::record_departure(
        &session.decision_makers,
        key,
        slot,
        DepartureStamps::default(),
        LEAVE_REASON_LEFT,
    );
}

/// Journals `slot`'s clean-leave intent, which seals it against readmission.
fn seal(session: &SessionState, key: &SessionKey, slot: SlotId) {
    session.provisional_turns.arm();
    assert!(session.provisional_turns.reserve(key));
    let held = session.provisional_turns.hold(
        key,
        PennedIngress::Departure {
            slot,
            reason: LEAVE_REASON_LEFT,
            connection_epoch: Some(9),
            revision: 0,
        },
    );
    assert_eq!(held, crate::session::provisional_turns::HoldOutcome::Held);
}

/// One row: a session state, the slot dialing into it, and the refusal the
/// gates owe that dial.
struct Case {
    what: &'static str,
    seed: fn(&SessionState, &SessionKey),
    slot: SlotId,
    expected: Option<Refusal>,
}

#[test]
fn the_pre_register_gates_refuse_exactly_their_own_cases() {
    let cases = [
        Case {
            what: "a dial that beat every descriptor is admitted unconditionally -- \
                   the descriptor-arrival race behaves as if the gates did not exist",
            seed: |_, _| {},
            slot: SlotId(0),
            expected: None,
        },
        Case {
            what: "a descriptor that homes the slot here admits it",
            seed: |session, key| home(session, key, &[0, 1], &[0, 1]),
            slot: SlotId(0),
            expected: None,
        },
        Case {
            what: "a descriptor that homes the slot elsewhere refuses it",
            seed: |session, key| home(session, key, &[0, 1, 2], &[0, 1]),
            slot: SlotId(2),
            expected: Some(NOT_HOMED),
        },
        Case {
            what: "an empty homed set is legacy/dev and stays permissive",
            seed: |session, key| home(session, key, &[0, 1], &[]),
            slot: SlotId(2),
            expected: None,
        },
        Case {
            what: "a departure with no hold pending is a decided leave: terminal",
            seed: |session, key| {
                home(session, key, &[0, 1], &[0, 1]);
                depart(session, key, SlotId(0));
            },
            slot: SlotId(0),
            expected: Some(ALREADY_DEPARTED),
        },
        Case {
            what: "a departure still under a pending hold is a resumable reconnect",
            seed: |session, key| {
                home(session, key, &[0, 1], &[0, 1]);
                depart(session, key, SlotId(0));
                session.drop_holds.hold(key.clone(), SlotId(0));
            },
            slot: SlotId(0),
            expected: None,
        },
        Case {
            what: "a journaled clean leave seals its slot against readmission",
            seed: |session, key| seal(session, key, SlotId(0)),
            slot: SlotId(0),
            expected: Some(ALREADY_DEPARTED),
        },
        Case {
            what: "another slot's seal does not touch this dial",
            seed: |session, key| seal(session, key, SlotId(1)),
            slot: SlotId(0),
            expected: None,
        },
        Case {
            what: "the home-relay gate runs first, so a slot that is both \
                   misrouted and departed reads as misrouted",
            seed: |session, key| {
                home(session, key, &[0, 1, 2], &[0, 1]);
                depart(session, key, SlotId(2));
            },
            slot: SlotId(2),
            expected: Some(NOT_HOMED),
        },
    ];

    for case in cases {
        let session = SessionState::default();
        let key = session_key(1);
        (case.seed)(&session, &key);
        assert_eq!(
            run_gates(&session, &key, case.slot),
            case.expected,
            "{}",
            case.what,
        );
    }
}

#[test]
fn the_post_register_seal_recheck_reads_the_same_seal() {
    // The authoritative read the pre-register fast-fail could only guess at.
    // It answers the same question about the same state -- what differs is
    // only when it runs, and that registration having succeeded proves any
    // seal the old link owed is already installed.
    let session = SessionState::default();
    let key = session_key(1);
    assert!(
        journal_seal_still_clear(&session, &key, SlotId(0)),
        "a disarmed journal seals nothing",
    );

    seal(&session, &key, SlotId(0));
    assert!(!journal_seal_still_clear(&session, &key, SlotId(0)));
    assert!(
        journal_seal_still_clear(&session, &key, SlotId(1)),
        "the seal is per slot",
    );

    // And it agrees with the pre-register gate on every slot: the two reads
    // differ in authority, never in answer.
    for slot in [SlotId(0), SlotId(1)] {
        assert_eq!(
            journaled_leave_seal(&session, &key, slot).is_none(),
            journal_seal_still_clear(&session, &key, slot),
        );
    }
}

#[test]
fn every_refusal_carries_the_rollback_its_cause_implies() {
    // The rule, pinned: a refusal that could have created session scaffolding
    // rolls it back; a refusal caused by the session's own retirement does
    // not, because retirement's sweep owns that state; a refusal from before
    // the roster was touched has nothing to undo.
    let table = [
        (NOT_HOMED, Rollback::Untouched),
        (ALREADY_DEPARTED, Rollback::Untouched),
        (DEPARTED_AT_ADMISSION, Rollback::Scaffolding),
        (SLOT_TAKEN, Rollback::Scaffolding),
        (PROVISIONAL_CAPACITY, Rollback::Scaffolding),
        (SESSION_RETIRED, Rollback::RetirementOwnsIt),
    ];
    for (refusal, expected) in table {
        assert_eq!(refusal.rollback, expected, "{:?}", refusal.kind);
    }
}

#[test]
fn the_two_departure_refusals_are_one_close_code_with_two_rollbacks() {
    // A client cannot tell a pre- from a post-register departure refusal, and
    // must not be able to: both are the one terminal close. What differs is
    // only what the relay has to clean up behind it.
    assert_eq!(ALREADY_DEPARTED.code, DEPARTED_AT_ADMISSION.code);
    assert_eq!(ALREADY_DEPARTED.reason, DEPARTED_AT_ADMISSION.reason);
    assert_eq!(ALREADY_DEPARTED.kind, DEPARTED_AT_ADMISSION.kind);
    assert_ne!(ALREADY_DEPARTED.rollback, DEPARTED_AT_ADMISSION.rollback);
}
