//! Tests for drop holds: the marker-not-timer hold/release/claim semantics,
//! the abandoned-session timer's generation-checked expiry claim, the
//! `end_session` sweep's undecided-vs-decided split, and the per-requester
//! drop-request rate cap.

use super::*;
use crate::test_support::session_key as key_of;

fn key() -> SessionKey {
    key_of(1)
}

/// The expired-timer identity check: an old timer whose cancellation landed
/// after its sleep elapsed must not consume the entry of a fresh timer a
/// second abandonment armed under the same key — a bare remove-by-key would
/// fire immediately with the fresh timer's flag, stealing the full window
/// that second abandonment is owed.
#[tokio::test]
async fn an_expired_timer_cannot_claim_a_fresh_timers_entry() {
    let holds = DropHolds::new(Duration::from_secs(3600), Duration::from_secs(3600));
    let k = key();
    let gen_a = holds
        .arm_abandon(k.clone(), |_| {})
        .expect("first timer arms");
    assert_eq!(
        holds.arm_abandon(k.clone(), |_| {}),
        None,
        "arming over a live timer keeps the existing one",
    );
    // The reconnect cancels A; a second abandonment arms B afresh.
    holds.cancel_abandon(&k);
    let gen_b = holds
        .arm_abandon(k.clone(), |_| {})
        .expect("fresh timer arms");
    assert_ne!(gen_a, gen_b);

    // Timer A's belated expiry (the ordering where its sleep elapsed before
    // the cancellation reached its select): the entry it finds is not its
    // own, so it claims nothing and fires nothing.
    assert_eq!(holds.claim_expiry(&k, gen_a), None);
    assert!(
        holds.abandon_armed(&k),
        "the fresh timer keeps its entry — and with it, its full window",
    );

    // The fresh timer's own claim succeeds exactly once.
    assert_eq!(holds.claim_expiry(&k, gen_b), Some(false));
    assert!(!holds.abandon_armed(&k));
    assert_eq!(holds.claim_expiry(&k, gen_b), None, "a claim is one-shot");
}

#[test]
fn a_hold_is_pending_and_records_its_elapsed() {
    let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
    assert!(!holds.is_pending(&key(), SlotId(3)));
    assert!(holds.held_for(&key(), SlotId(3)).is_none());

    holds.hold(key(), SlotId(3));
    assert!(holds.is_pending(&key(), SlotId(3)));
    assert!(
        holds.held_for(&key(), SlotId(3)).is_some(),
        "a held slot reports how long it has stood",
    );
    assert_eq!(
        holds.pending_slots(&key()),
        [SlotId(3)].into_iter().collect()
    );
}

#[test]
fn releasing_a_hold_clears_it_and_a_second_release_finds_nothing_to_claim() {
    let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
    holds.hold(key(), SlotId(3));
    assert!(
        holds.release(&key(), SlotId(3)),
        "the first release claims a genuinely pending hold",
    );
    assert!(!holds.is_pending(&key(), SlotId(3)));
    assert!(holds.held_for(&key(), SlotId(3)).is_none());
    // The claim semantics that close the split-brain race: a second release
    // for the same slot -- a concurrent decide path that lost the race --
    // must see `false`, not silently "succeed" again, so it knows to stand
    // down rather than act a second time.
    assert!(
        !holds.release(&key(), SlotId(3)),
        "a second release for the same slot finds nothing left to claim",
    );
    // Releasing an absent hold is likewise a no-op, never a panic.
    assert!(!holds.release(&key(), SlotId(9)));
}

#[test]
fn take_if_pending_reinstates_and_removes_the_hold() {
    let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
    holds.hold(key(), SlotId(3));

    let reinstated = holds.take_if_pending(&key(), SlotId(3), || true);
    assert!(reinstated, "reinstate succeeded, so the claim reports true");
    assert!(
        !holds.is_pending(&key(), SlotId(3)),
        "the hold is removed once claimed, regardless of reinstate's outcome",
    );
}

#[test]
fn take_if_pending_still_removes_the_hold_when_reinstate_loses_the_photo_finish() {
    // `reinstate` returning false models `consensus::reinstate_slot` finding
    // the slot's leave already decided under its own lock -- a concurrent
    // `RequestDrop` or abandoned-session force-decide won the race. The hold
    // is still removed (it is exactly as resolved as one this call
    // reinstated), but the caller's overall claim reports false so it knows
    // to refuse the reconnect rather than admit it.
    let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
    holds.hold(key(), SlotId(3));

    let reinstated = holds.take_if_pending(&key(), SlotId(3), || false);
    assert!(!reinstated, "reinstate lost the photo finish");
    assert!(
        !holds.is_pending(&key(), SlotId(3)),
        "the hold is still removed even though reinstate reported false",
    );
}

#[test]
fn take_if_pending_never_calls_reinstate_when_nothing_is_pending() {
    let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
    let mut called = false;
    let reinstated = holds.take_if_pending(&key(), SlotId(3), || {
        called = true;
        true
    });
    assert!(
        !reinstated,
        "no hold was pending, so there is nothing to claim"
    );
    assert!(
        !called,
        "reinstate must never run when there was no hold to claim it against",
    );
}

#[test]
fn concurrent_claims_on_the_same_hold_have_exactly_one_winner() {
    // The property every decide path (an honored `RequestDrop`, the
    // abandoned-session force-decide) and every reconnect's `take_if_pending`
    // rests on: whichever thread's `release`/`take_if_pending` call actually
    // acquires the holds lock first wins the claim, and every other
    // concurrent claimant on the exact same `(key, slot)` must lose. This
    // drives genuine OS-thread contention (not just async interleaving) at
    // the primitive level, since the higher-level routing functions this
    // backs (`honor_drop_request`, `serve_connection`'s admission) have no
    // seam to inject a race into deterministically.
    use std::sync::Barrier;

    let holds = Arc::new(DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT));
    holds.hold(key(), SlotId(3));

    const CLAIMANTS: usize = 8;
    let barrier = Arc::new(Barrier::new(CLAIMANTS));
    let handles: Vec<_> = (0..CLAIMANTS)
        .map(|_| {
            let holds = Arc::clone(&holds);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                holds.release(&key(), SlotId(3))
            })
        })
        .collect();

    let wins: usize = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .filter(|&won| won)
        .count();
    assert_eq!(wins, 1, "exactly one concurrent claimant wins the hold");
    assert!(
        !holds.is_pending(&key(), SlotId(3)),
        "the hold is gone either way"
    );
}

#[test]
fn a_duplicate_hold_keeps_the_original_instant() {
    let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
    let first_seen = Instant::now();
    assert_eq!(holds.hold_at(key(), SlotId(3), first_seen), first_seen);
    // A second drop signal for the same slot, an hour later, must not restart
    // the window: the unlock floor is measured from when the slot was *first*
    // observed gone, so a repeating signal could otherwise hold it off forever.
    assert_eq!(
        holds.hold_at(key(), SlotId(3), first_seen + Duration::from_secs(3600)),
        first_seen,
        "a duplicate hold kept the original, older instant rather than resetting it",
    );
}

#[test]
fn a_never_requested_hold_never_decides_on_its_own() {
    // The core policy: a hold is a marker, not a timer. Even an unlock of zero —
    // "past the floor from the first instant" — decides nothing by itself; a
    // hold only clears when something explicitly releases it. Nothing is ever
    // spawned against a hold, so there is no task whose firing a wait could
    // catch: re-reading the registry is the whole observation.
    let holds = DropHolds::new(Duration::ZERO, ABANDONED_SESSION_TIMEOUT);
    holds.hold(key(), SlotId(3));
    assert!(
        holds.held_for(&key(), SlotId(3)).unwrap() >= holds.unlock(),
        "the hold is past its unlock floor from the very first instant",
    );
    assert!(
        holds.is_pending(&key(), SlotId(3)),
        "nothing removes a hold without an explicit release — no auto-drop",
    );
}

#[test]
fn end_session_sweeps_only_decided_holds_keeping_undecided_ones_and_other_sessions() {
    // Slot 0's drop is undecided (the common case: the last local slot's own
    // hold, freshly marked in the very teardown that empties the roster and
    // triggers this sweep). Slot 1's was already decided elsewhere (an earlier
    // honored request or force-decide) and its hold should have been released
    // then, but this proves the sweep is still correct as a defensive backstop
    // if it somehow wasn't.
    //
    // Run over both shapes of `decided`: nothing decided yet (the common
    // case, where every hold is still the sole path back to that drop being
    // resolved) and slot 1 decided.
    let other = key_of(2);
    for decided in [HashSet::new(), [SlotId(1)].into_iter().collect()] {
        let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
        holds.hold(key(), SlotId(0));
        holds.hold(key(), SlotId(1));
        holds.hold(other.clone(), SlotId(0));

        holds.end_session(&key(), &decided);
        assert!(
            holds.is_pending(&key(), SlotId(0)),
            "the undecided hold survives the sweep -- it's still the reconnect token",
        );
        assert_eq!(
            holds.is_pending(&key(), SlotId(1)),
            !decided.contains(&SlotId(1)),
            "a hold is swept exactly when its slot was already decided",
        );
        assert!(
            holds.is_pending(&other, SlotId(0)),
            "another session's holds are untouched",
        );
    }
}

/// The production burst-then-reject half of the cap. Recovery after a refill
/// is the token bucket's own test (`crate::rate_limit`), driven off synthetic
/// instants rather than a real two-second wait.
#[test]
fn a_burst_past_the_request_cap_is_rejected() {
    let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
    let requester = SlotId(2);
    // The first DROP_REQUEST_BURST requests in a burst are all admitted.
    for _ in 0..DROP_REQUEST_BURST {
        assert!(holds.admit_request(&key(), requester));
    }
    // The next, still within the burst window, is rejected — a double-click
    // storm is throttled, not honored repeatedly.
    assert!(!holds.admit_request(&key(), requester));
}

/// An injected cap replaces the production numbers wholesale: a registry built
/// with a burst of one rejects the second back-to-back request, where the
/// production burst would have admitted it.
#[test]
fn an_injected_request_rate_replaces_the_production_cap() {
    let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT)
        .with_request_rate(1, Duration::from_millis(1));
    let requester = SlotId(2);
    assert!(holds.admit_request(&key(), requester));
    assert!(
        !holds.admit_request(&key(), requester),
        "the injected burst of one is spent",
    );
}

#[test]
fn each_requester_has_its_own_budget() {
    let holds = DropHolds::new(DROP_UNLOCK, ABANDONED_SESSION_TIMEOUT);
    for _ in 0..DROP_REQUEST_BURST {
        assert!(holds.admit_request(&key(), SlotId(2)));
    }
    assert!(!holds.admit_request(&key(), SlotId(2)));
    // A different requester still has its full burst — the cap is per-slot.
    assert!(holds.admit_request(&key(), SlotId(5)));
}
