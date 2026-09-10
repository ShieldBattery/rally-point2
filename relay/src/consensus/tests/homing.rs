//! Slot homing, reconnectable departures, the close-report latch, and departure retirement.

use super::*;

/// No maker exists yet for the session — the descriptor-arrival race: a
/// client can dial before this relay has received any descriptor. Must
/// admit, exactly like `slot_departed`/`is_authority`'s "no maker" default,
/// so this check introduces no new wait or refusal window.
#[test]
fn slot_homed_admits_when_no_maker_exists() {
    let registry = new_decision_makers();
    assert!(slot_homed(&registry, &key(), SlotId(0)));
}

/// A maker exists but its homed set is empty — a legacy/dev descriptor, or
/// one that never carried the field. Empty means unenforced, so every slot
/// is admitted regardless.
#[test]
fn slot_homed_admits_every_slot_when_the_homed_set_is_empty() {
    let registry = new_decision_makers();
    let _ = sync_maker(
        &registry,
        &key(),
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        HashSet::new(), // empty homed_slots: unenforced
        HashSet::new(),
        None,
        false,
    );
    assert!(slot_homed(&registry, &key(), SlotId(0)));
    assert!(slot_homed(&registry, &key(), SlotId(7)));
}

/// A non-empty homed set admits only the slots it names and refuses every
/// other — the actual enforcement a production multi-relay descriptor
/// turns on.
#[test]
fn slot_homed_refuses_a_slot_absent_from_a_non_empty_homed_set() {
    let registry = new_decision_makers();
    let _ = sync_maker(
        &registry,
        &key(),
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        [SlotId(0), SlotId(2)].into_iter().collect(),
        HashSet::new(),
        None,
        false,
    );
    assert!(
        slot_homed(&registry, &key(), SlotId(0)),
        "slot 0 is homed here"
    );
    assert!(
        slot_homed(&registry, &key(), SlotId(2)),
        "slot 2 is homed here"
    );
    assert!(
        !slot_homed(&registry, &key(), SlotId(1)),
        "slot 1 is not in the homed set, so this relay refuses it",
    );
}

/// A departure defers the session-emptied close only while it mirrors the
/// re-register admission gate: recorded, undecided, of a homed slot, and
/// still held. A peer-homed slot's drop (held purely for authority-handoff
/// robustness), an unheld departure (a clean leave released its hold), and
/// a decided one (a peer authority's directive here) all defer nothing.
#[test]
fn a_reconnectable_departure_requires_homed_held_and_undecided() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::Peer,
        HashSet::new(),
        HashSet::new(),
        [SlotId(0)].into_iter().collect(),
        HashSet::new(),
        None,
        false,
    );
    let held_both: HashSet<SlotId> = [SlotId(0), SlotId(1)].into_iter().collect();

    // A peer-homed slot drops: undecided session-wide and held, but its
    // reconnect (if any) lands on its own home relay.
    record_departure(
        &registry,
        &k,
        SlotId(1),
        DepartureStamps::default(),
        DROPPED,
    );
    assert!(has_undecided_departure(&registry, &k));
    assert!(!has_reconnectable_departure(&registry, &k, &held_both));

    // This relay's own homed slot drops: while held, the close must wait —
    // but with the hold gone (a clean leave releases it), nothing can be
    // admitted back, so nothing waits.
    record_departure(
        &registry,
        &k,
        SlotId(0),
        DepartureStamps::default(),
        DROPPED,
    );
    assert!(has_reconnectable_departure(&registry, &k, &held_both));
    assert!(!has_reconnectable_departure(&registry, &k, &HashSet::new()));

    // The homed slot's leave is decided (a peer authority's directive): a
    // reconnect is refused terminally now, so even a lingering hold defers
    // nothing.
    assert!(observe_leave(
        &registry,
        &k,
        &LeaveDirective {
            finalized: false,
            slot: 0,
            reason: DROPPED,
            apply_at_frame: 1,
            leave_seq: 1,
            final_turn_count: None,
        },
    ));
    assert!(!has_reconnectable_departure(&registry, &k, &held_both));
    assert!(
        has_undecided_departure(&registry, &k),
        "the peer-homed drop is still undecided session-wide",
    );
}

/// With an empty homed set (unenforced — a legacy/dev descriptor), every
/// held undecided slot counts, matching `slot_homed`'s permissive
/// admission: a relay that would admit any slot's reconnect must also wait
/// on any slot's held drop.
#[test]
fn a_reconnectable_departure_counts_every_held_slot_when_the_homed_set_is_empty() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::Peer,
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    let held: HashSet<SlotId> = [SlotId(3)].into_iter().collect();
    assert!(!has_reconnectable_departure(&registry, &k, &held));
    record_departure(
        &registry,
        &k,
        SlotId(3),
        DepartureStamps::default(),
        DROPPED,
    );
    assert!(has_reconnectable_departure(&registry, &k, &held));
}

/// The abandoned-session force-decide commits even before any framed turn
/// was observed: an abandoned session has no survivors to schedule the
/// removal, so the apply frame is cosmetic, and holding the decision (as an
/// ordinary decide does pre-frame) would strand the slot's hold — and the
/// session close waiting on it — forever.
#[test]
fn force_decide_leave_commits_with_no_frame_basis() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.record_departure(SlotId(0), DepartureStamps::default(), DROPPED);
    assert_eq!(
        maker.decide_leave(SlotId(0), DROPPED),
        None,
        "an ordinary decide holds without a frame basis (and as a peer)",
    );
    let directive = maker
        .force_decide_leave(SlotId(0), DROPPED)
        .expect("the force-decide commits regardless");
    assert_eq!(directive.apply_at_frame, 0, "cosmetic pre-frame apply");
    assert_eq!(
        maker.force_decide_leave(SlotId(0), DROPPED),
        None,
        "a duplicate force-decide dedups",
    );
    assert!(!maker.has_undecided_departure());
}

/// The session-closed report latches once per emptying and reopens when the
/// relay serves the session again — and with no maker to latch on, every
/// claim succeeds (the only close such a session can reach).
#[test]
fn claim_close_report_latches_once_until_reopened() {
    let registry = new_decision_makers();
    let k = key();
    assert!(claim_close_report(&registry, &k));
    assert!(
        claim_close_report(&registry, &k),
        "no maker: every emptying reports",
    );

    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    assert!(claim_close_report(&registry, &k), "the first claim wins");
    assert!(
        !claim_close_report(&registry, &k),
        "a second evaluation finds the close already reported",
    );
    reopen_close_report(&registry, &k);
    assert!(
        claim_close_report(&registry, &k),
        "serving again reopens the latch for the next emptying",
    );
}

/// A rehome (or any later descriptor) replaces the homed set wholesale --
/// a slot moved off this relay stops being admissible, and one moved onto
/// it starts being admissible, with no accumulation across pushes.
#[test]
fn slot_homed_follows_a_later_descriptors_reassignment() {
    let registry = new_decision_makers();
    let _ = sync_maker(
        &registry,
        &key(),
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        [SlotId(0)].into_iter().collect(),
        HashSet::new(),
        None,
        false,
    );
    assert!(slot_homed(&registry, &key(), SlotId(0)));
    assert!(!slot_homed(&registry, &key(), SlotId(1)));

    // A later push (e.g. a rehome) moves slot 1 onto this relay and slot 0
    // off it.
    let _ = sync_maker(
        &registry,
        &key(),
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        [SlotId(1)].into_iter().collect(),
        HashSet::new(),
        None,
        false,
    );
    assert!(
        !slot_homed(&registry, &key(), SlotId(0)),
        "slot 0 moved off this relay",
    );
    assert!(
        slot_homed(&registry, &key(), SlotId(1)),
        "slot 1 moved onto this relay",
    );
}

// -- Departed-slot lifecycle (slot leaves the live roster, never resurrects) --

/// A departure retires the slot from the live roster on every relay, so the
/// session frame follows the survivors instead of staying pinned at the
/// departed slot's frozen last frame.
#[test]
fn a_departure_retires_the_slot_from_the_session_frame() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.observe_frame(SlotId(0), GameFrameCount(60));
    maker.observe_frame(SlotId(1), GameFrameCount(50));
    assert_eq!(maker.session_frame(), Some(GameFrameCount(50)));

    maker.record_departure(
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(50)),
            ..Default::default()
        },
        DROPPED,
    );
    assert_eq!(
        maker.session_frame(),
        Some(GameFrameCount(60)),
        "the survivors alone drive the session frame after a departure",
    );
}

/// A late frame observation for a departed slot (its final turns racing the
/// departure across the mesh) must not resurrect the slot's live state — the
/// re-created entry would re-pin the session frame at the departed slot.
#[test]
fn observe_frame_ignores_a_departed_slot() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    maker.observe_frame(SlotId(0), GameFrameCount(60));
    maker.record_departure(
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(50)),
            ..Default::default()
        },
        DROPPED,
    );

    maker.observe_frame(SlotId(1), GameFrameCount(52));
    assert!(!maker.slots.contains_key(&SlotId(1)), "no resurrection");
    assert_eq!(
        maker.session_frame(),
        Some(GameFrameCount(60)),
        "the late observation does not re-pin the session frame",
    );
}

/// A stale conditions sample for a departed slot (an in-flight datagram that
/// raced the departure) must not re-create its condition state either.
#[test]
fn conditions_ingest_does_not_resurrect_a_departed_slot() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    maker.observe_frame(SlotId(0), GameFrameCount(60));
    maker.record_departure(
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(50)),
            ..Default::default()
        },
        DROPPED,
    );

    let _ = maker.ingest_local(&conditions(1, 150_000, 0, 100));
    assert!(!maker.slots.contains_key(&SlotId(1)), "no resurrection");
    assert_eq!(
        maker.target(),
        None,
        "no live slot has conditions to size from"
    );
}

/// A `LinkConditions` sidecar's slot field is a raw wire `u32`, unvalidated
/// by the transport layer (unlike a turn payload's slot, which the link
/// layer already rejects out-of-range before delivery). A slot past `u8`
/// range must be skipped rather than truncated onto a real slot's tracked
/// RTT/loss state.
#[test]
fn conditions_ingest_skips_an_out_of_range_slot_without_corrupting_a_real_one() {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );

    let mut batch = conditions(5, 150_000, 0, 100);
    // 300 truncates to 44 (300 % 256) under a bare `as u8` cast -- if slot 44
    // ever exists, that would alias this malformed sample onto it. Neither
    // slot 44 nor slot 300 should end up tracked.
    batch
        .slots
        .push(rally_point_proto::messages::SlotConditions {
            slot: 300,
            rtt_us: 999_999,
            lost_packets: 0,
            sent_packets: 1,
            connection_epoch: None,
        });

    let _ = maker.ingest_local(&batch);

    assert!(
        maker.slots.contains_key(&SlotId(5)),
        "the well-formed slot in the same batch is still ingested"
    );
    assert!(
        !maker.slots.contains_key(&SlotId(44)),
        "the out-of-range slot must not alias onto slot 44 (300 truncated)"
    );
    assert_eq!(maker.slots.len(), 1, "only the valid slot was tracked");
}

/// The Join-time reconcile always includes a cached leave — even when the
/// survivors' session frame is at/past its apply frame. As in the promotion
/// case, the observed frames are send stamps that lead execution by the
/// buffer depth, so they cannot distinguish "every survivor applied it" from
/// "every survivor is stalled waiting for it"; the reconcile re-announces
/// unconditionally and receipt dedups by slot.
#[test]
fn reconcile_always_includes_a_cached_leave() {
    let mut maker =
        DecisionMaker::new(key(), bounds(0, 20), law(), Authority::Peer, HashSet::new());
    // Both slots observed off mesh turns; slot 1 is homed on the peer relay.
    maker.observe_frame(SlotId(0), GameFrameCount(40));
    maker.observe_frame(SlotId(1), GameFrameCount(50));
    maker.record_departure(
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(50)),
            ..Default::default()
        },
        DROPPED,
    );
    let leave = LeaveDirective {
        finalized: false,
        slot: 1,
        reason: DROPPED,
        apply_at_frame: 51,
        leave_seq: 1,
        final_turn_count: None,
    };
    let _ = maker.observe_leave(&leave);

    let (_, directives) = maker.leave_reconcile();
    assert_eq!(directives, vec![leave]);

    // The survivor's stamps reach and pass the apply frame: the directive is
    // still re-announced (and the departure record with it).
    maker.observe_frame(SlotId(0), GameFrameCount(75));
    let (departures, directives) = maker.leave_reconcile();
    assert_eq!(directives, vec![leave], "re-announced regardless of stamps");
    assert_eq!(departures.len(), 1, "the departure record is announced too");
    let (leaves, fresh) = maker.set_authority(Authority::SelfRelay, &HashSet::new());
    assert_eq!(
        leaves,
        vec![leave],
        "and a promotion re-broadcasts it just the same",
    );
    assert!(
        fresh.is_empty(),
        "already cached via observe_leave — not a fresh insert on promotion",
    );
}

// -- Desync comparator (SyncTracker via DecisionMaker::observe_sync) --
