//! The token-bucket mechanics, over a bare `u32` key. The endpoints that use
//! these buckets each pick a different key; that choice is tested where the
//! endpoint's limiter lives, so nothing here needs a tenant or a session.

use super::*;

/// A limiter over a trivial key with the production bucket cap — the shape
/// every endpoint's limiter wraps.
fn limiter(burst: u32, refill_interval: Duration) -> KeyedTokenBuckets<u32> {
    KeyedTokenBuckets::new(burst, refill_interval, 4096)
}

#[test]
fn admits_a_burst_then_refuses_until_refill() {
    let buckets = limiter(3, Duration::from_secs(5));
    let t0 = Instant::now();
    // The full burst of 3 is admitted back-to-back.
    for _ in 0..3 {
        assert!(buckets.check_at(&1, t0));
    }
    // The 4th, with no time elapsed, is refused.
    assert!(!buckets.check_at(&1, t0));

    // After one refill interval, exactly one token is available again.
    let t1 = t0 + Duration::from_secs(5);
    assert!(buckets.check_at(&1, t1));
    assert!(!buckets.check_at(&1, t1));
}

#[test]
fn distinct_keys_hold_independent_buckets() {
    // One key spending its tokens must never touch another's — this is what
    // makes a well-chosen key enough to stop one caller starving another.
    let buckets = limiter(1, Duration::from_secs(5));
    let t0 = Instant::now();
    assert!(buckets.check_at(&1, t0));
    assert!(!buckets.check_at(&1, t0), "key 1's only token is spent");
    assert!(buckets.check_at(&2, t0), "key 2 has its own full burst");
}

#[test]
fn refill_is_capped_at_the_burst() {
    let buckets = limiter(3, Duration::from_secs(5));
    let t0 = Instant::now();
    // Spend one token, then wait a very long time: the bucket refills only to
    // the burst cap, not unbounded.
    assert!(buckets.check_at(&1, t0));
    let far = t0 + Duration::from_secs(3600);
    for _ in 0..3 {
        assert!(buckets.check_at(&1, far));
    }
    assert!(!buckets.check_at(&1, far));
}

#[test]
fn an_earlier_instant_does_not_re_credit_elapsed_time() {
    // `check` reads `Instant::now()` before taking the lock, so a caller that
    // lost the race arrives with an instant older than the bucket's anchor.
    // Re-anchoring there would credit the gap between the two instants again.
    let buckets = limiter(1, Duration::from_secs(1));
    let t0 = Instant::now() + Duration::from_secs(10);
    assert!(buckets.check_at(&1, t0));
    assert!(
        !buckets.check_at(&1, t0 - Duration::from_millis(900)),
        "the late caller finds the token spent",
    );
    assert!(
        !buckets.check_at(&1, t0 + Duration::from_millis(500)),
        "half an interval past the newest check is not a whole token",
    );
    assert!(buckets.check_at(&1, t0 + Duration::from_secs(1)));
}

#[test]
fn a_bucket_created_at_an_earlier_instant_is_not_idle_evicted_early() {
    // A fresh bucket stamped at a late caller's older instant would look idle
    // that much sooner, and its eviction re-grants a full burst early.
    let buckets = limiter(2, Duration::from_secs(1));
    let t0 = Instant::now() + Duration::from_secs(10);
    assert!(buckets.check_at(&0, t0));
    // Key 1 first appears with an instant 2.5 s older than the newest check,
    // and spends its burst.
    let late = t0 - Duration::from_millis(2_500);
    assert!(buckets.check_at(&1, late));
    assert!(buckets.check_at(&1, late));
    // Half a second after the newest check, key 1 has refilled half a token.
    // Anchored at `late` it would read 3 s idle -- the (burst + 1) interval
    // eviction threshold -- and come back with a fresh burst.
    let t1 = t0 + Duration::from_millis(500);
    assert!(
        !buckets.check_at(&1, t1),
        "a spent bucket is not evicted half an interval after it was spent",
    );
}

#[test]
fn idle_buckets_evict_on_access() {
    // The map must stay bounded by the keys actually in use: a bucket idle long
    // enough to have fully refilled is pruned on the next access.
    let buckets = limiter(3, Duration::from_secs(5));
    let t0 = Instant::now();
    for key in 0..100 {
        buckets.check_at(&key, t0);
    }
    assert_eq!(buckets.bucket_count(), 100, "one bucket per touched key");

    // (burst + 1) refill intervals later, every one of those buckets has
    // refilled to full and is evicted when the next, unrelated access sweeps
    // the map — leaving only the freshly created bucket.
    let later = t0 + Duration::from_secs(5) * 4 + Duration::from_secs(1);
    assert!(buckets.check_at(&1000, later));
    assert_eq!(
        buckets.bucket_count(),
        1,
        "idle buckets are pruned on access, bounding the map",
    );
}

#[test]
fn a_bucket_touched_within_the_idle_window_is_not_evicted() {
    // Eviction must not drop a key still within its idle window — a caller
    // asking at the steady-state cadence keeps its (partially spent) bucket.
    let buckets = limiter(3, Duration::from_secs(5));
    let t0 = Instant::now();
    assert!(buckets.check_at(&1, t0));
    assert!(buckets.check_at(&1, t0));
    // One refill interval later (well inside the idle window), the bucket is
    // still present and has only partially refilled — the third and fourth
    // asks are not a fresh full burst.
    let t1 = t0 + Duration::from_secs(5);
    assert!(buckets.check_at(&1, t1));
    assert_eq!(buckets.bucket_count(), 1, "the active bucket survives");
}

#[test]
fn a_unique_key_spray_is_bounded_by_the_cap_and_spares_an_active_bucket() {
    // A cardinality cap must bound the map no matter the rate: an authenticated
    // caller spraying unique keys can never grow it past the cap, and the
    // eviction (stalest first) never drops a legitimately active caller.
    let cap = 4;
    let buckets = KeyedTokenBuckets::new(1, Duration::from_secs(5), cap);
    let t0 = Instant::now();

    // Spray far more unique keys than the cap, all at t0.
    for key in 0..(cap as u32 * 3) {
        buckets.check_at(&key, t0);
    }
    assert!(
        buckets.bucket_count() <= cap,
        "the cap bounds the map under a unique-key spray",
    );

    // A legitimate caller arrives slightly later (within the idle window, so the
    // t0 buckets are cap-evicted rather than idle-evicted), spending its one
    // token so a later reset would be observable.
    let t1 = t0 + Duration::from_secs(1);
    let legit = 999;
    assert!(buckets.check_at(&legit, t1));
    assert!(
        !buckets.check_at(&legit, t1),
        "its single-token burst is spent"
    );

    // More unique garbage at t1. Eviction targets the stalest (older t0) buckets,
    // never the just-touched legit one; fewer sprays than the surviving t0 count
    // keeps at least one stale bucket present at every step.
    for key in 1000..(1000 + cap as u32 - 1) {
        buckets.check_at(&key, t1);
    }
    assert!(
        buckets.bucket_count() <= cap,
        "still bounded after the second spray"
    );

    // The legit bucket survived: its token is still spent, so it is refused —
    // a fresh (evicted-and-recreated) bucket would instead admit a full burst.
    assert!(
        !buckets.check_at(&legit, t1),
        "the active bucket was spared; it did not reset to a fresh burst",
    );
}
