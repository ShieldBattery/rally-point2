//! Rate limiting for the coordinator-mediated re-home endpoint.
//!
//! `POST /session/rehome` is tenant-authenticated (the tenant's app server signs
//! each request; game clients never call the coordinator directly), and the app
//! server may legitimately re-ask every few seconds while a session's home relay
//! is unreachable — so the limit is lenient, a small burst with a slow refill,
//! sized only to stop a misbehaving caller from hammering the endpoint. The limit
//! is per `(tenant, session)`: one session's re-asking never starves another's,
//! and the bucket is keyed on the *authenticated* tenant (whose signature the
//! request verified under) and the session it named.
//!
//! The buckets are held in-memory behind a plain mutex; every critical section is
//! a short, await-free token check. A coordinator restart forgets them, which only
//! grants a fresh burst — harmless for a rate limit that exists to bound abuse, not
//! to enforce correctness. Idle buckets are pruned lazily on access so the map
//! stays bounded by the sessions currently re-homing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::SessionId;

/// Burst capacity: how many re-home requests one session may make back-to-back
/// before it must wait for the bucket to refill. Three covers an app server that
/// re-asks a couple of times across a brief outage without tripping the limit.
pub const REHOME_BURST: u32 = 3;

/// How often one token refills. An app server may legitimately re-ask about every
/// five seconds while a relay is unreachable, so the steady-state rate matches that.
pub const REHOME_REFILL_INTERVAL: Duration = Duration::from_secs(5);

/// Hard cap on the number of live buckets. The time-window idle eviction alone only
/// bounds the map by `O(rate x window)`, so an authenticated caller spraying unique
/// garbage session ids at high rate could hold many thousands of buckets between
/// eviction sweeps. This cap bounds the map by cardinality regardless of rate: when
/// an insert would exceed it, the stalest bucket(s) are evicted to make room. A few
/// thousand comfortably covers every session a real coordinator re-homes at once
/// while keeping the worst-case memory footprint small.
pub const REHOME_BUCKET_CAP: usize = 4096;

/// The key of one session's rate-limit bucket: which session, for which tenant.
type BucketKey = (TenantId, SessionId);

/// A token bucket for one `(tenant, session)`.
struct Bucket {
    /// Tokens available now, fractional so a partial refill accrues between
    /// requests rather than being lost.
    tokens: f64,
    /// When the tokens were last refilled — the anchor the next check accrues from.
    last_refill: Instant,
}

/// The per-session re-home rate limiter, shared across every request handler.
/// Clone it cheaply (the state is behind one `Arc`) to hand a copy to the router
/// state.
#[derive(Clone)]
pub struct RehomeLimiter {
    buckets: Arc<Mutex<HashMap<BucketKey, Bucket>>>,
    burst: u32,
    refill_interval: Duration,
    /// Hard cap on live bucket count — [`REHOME_BUCKET_CAP`] in production; a test
    /// injects a small one to exercise the cardinality eviction cheaply.
    bucket_cap: usize,
}

impl Default for RehomeLimiter {
    fn default() -> Self {
        Self::new(REHOME_BURST, REHOME_REFILL_INTERVAL)
    }
}

impl RehomeLimiter {
    /// Builds a limiter with the given burst and refill interval, using the
    /// production bucket cap ([`REHOME_BUCKET_CAP`]). Production uses
    /// [`REHOME_BURST`]/[`REHOME_REFILL_INTERVAL`] (via [`Default`]); tests inject
    /// their own so they need not wait real seconds.
    pub fn new(burst: u32, refill_interval: Duration) -> Self {
        Self::with_bucket_cap(burst, refill_interval, REHOME_BUCKET_CAP)
    }

    /// Like [`new`](Self::new) but with an explicit bucket cap, so a test can drive
    /// the cardinality eviction with a handful of keys rather than several thousand.
    pub fn with_bucket_cap(burst: u32, refill_interval: Duration, bucket_cap: usize) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            burst,
            refill_interval,
            bucket_cap: bucket_cap.max(1),
        }
    }

    /// Whether a re-home request for `(tenant, session)` is admitted now,
    /// consuming a token if so. A fresh session starts with a full burst. Refills
    /// accrue at one token per [`refill_interval`](Self::new) up to the burst cap.
    pub fn check(&self, tenant: &TenantId, session: SessionId) -> bool {
        self.check_at(tenant, session, Instant::now())
    }

    /// [`check`](Self::check) against an explicit clock, so a test can advance time
    /// deterministically rather than sleeping.
    pub fn check_at(&self, tenant: &TenantId, session: SessionId, now: Instant) -> bool {
        let refill_per_sec = 1.0 / self.refill_interval.as_secs_f64();
        let burst = f64::from(self.burst);
        let mut buckets = self.buckets.lock();
        // Evict idle buckets lazily: a bucket untouched long enough to have
        // refilled from empty all the way back to its full burst is
        // indistinguishable from a never-seen session, so dropping it loses no
        // state and keeps the map bounded by the sessions actively re-homing. The
        // idle threshold is (burst + 1) refill intervals — the time to refill from
        // empty to full, plus a one-interval margin. This is the "pruned lazily on
        // access" the module docstring promises; it runs on every check, which is
        // fine for a map bounded by live re-homing sessions.
        let evict_after = self.refill_interval * self.burst.saturating_add(1);
        buckets.retain(|_, b| now.saturating_duration_since(b.last_refill) < evict_after);
        // Hard cardinality cap: if admitting a *new* session would exceed the cap
        // (idle eviction above didn't free enough — a high-rate spray of unique keys
        // keeps every bucket fresh), evict the stalest bucket(s) — oldest
        // `last_refill` — to make room. A stale bucket has refilled toward full, so
        // dropping it only grants a fresh burst, never refuses a live survivor; the
        // spray can never push a legitimate active session out because an active
        // session's bucket is by definition newer than the sprayer's oldest. Never
        // refuse the check outright — a full map must not become a DoS on the
        // sessions actually re-homing.
        let bucket_key = (tenant.clone(), session);
        if !buckets.contains_key(&bucket_key) {
            while buckets.len() >= self.bucket_cap {
                let Some(stalest) = buckets
                    .iter()
                    .min_by_key(|(_, bucket)| bucket.last_refill)
                    .map(|(key, _)| key.clone())
                else {
                    break;
                };
                buckets.remove(&stalest);
            }
        }
        let bucket = buckets.entry(bucket_key).or_insert(Bucket {
            tokens: burst,
            last_refill: now,
        });
        // Accrue refill for the elapsed time, capped at the burst.
        let elapsed = now
            .saturating_duration_since(bucket.last_refill)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(burst);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drops every bucket for `session` — called when the session closes, so the
    /// map stays bounded by the coordinator's live re-homing sessions.
    pub fn forget(&self, tenant: &TenantId, session: SessionId) {
        self.buckets
            .lock()
            .retain(|(t, s), _| !(t == tenant && *s == session));
    }

    /// The number of live buckets — a test hook for asserting idle eviction and
    /// close-time forgetting actually bound the map.
    #[cfg(test)]
    fn bucket_count(&self) -> usize {
        self.buckets.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid() -> TenantId {
        TenantId("sb-test".to_owned())
    }

    #[test]
    fn admits_a_burst_then_refuses_until_refill() {
        let limiter = RehomeLimiter::new(3, Duration::from_secs(5));
        let t0 = Instant::now();
        // The full burst of 3 is admitted back-to-back.
        for _ in 0..3 {
            assert!(limiter.check_at(&tid(), SessionId(1), t0));
        }
        // The 4th, with no time elapsed, is refused.
        assert!(!limiter.check_at(&tid(), SessionId(1), t0));

        // After one refill interval, exactly one token is available again.
        let t1 = t0 + Duration::from_secs(5);
        assert!(limiter.check_at(&tid(), SessionId(1), t1));
        assert!(!limiter.check_at(&tid(), SessionId(1), t1));
    }

    #[test]
    fn buckets_are_independent_per_session_and_tenant() {
        let limiter = RehomeLimiter::new(1, Duration::from_secs(5));
        let t0 = Instant::now();
        // Session 1 spends its only token; another session, and the same session
        // id under another tenant, are untouched.
        assert!(limiter.check_at(&tid(), SessionId(1), t0));
        assert!(!limiter.check_at(&tid(), SessionId(1), t0));
        assert!(limiter.check_at(&tid(), SessionId(2), t0));
        assert!(limiter.check_at(&TenantId("sb-other".to_owned()), SessionId(1), t0));
    }

    #[test]
    fn refill_is_capped_at_the_burst() {
        let limiter = RehomeLimiter::new(3, Duration::from_secs(5));
        let t0 = Instant::now();
        // Spend one token, then wait a very long time: the bucket refills only to
        // the burst cap, not unbounded.
        assert!(limiter.check_at(&tid(), SessionId(1), t0));
        let far = t0 + Duration::from_secs(3600);
        for _ in 0..3 {
            assert!(limiter.check_at(&tid(), SessionId(1), far));
        }
        assert!(!limiter.check_at(&tid(), SessionId(1), far));
    }

    #[test]
    fn idle_buckets_evict_on_access() {
        // The map must stay bounded by the sessions actively re-homing: a bucket
        // idle long enough to have fully refilled is pruned on the next access.
        let limiter = RehomeLimiter::new(3, Duration::from_secs(5));
        let t0 = Instant::now();
        for i in 0..100 {
            limiter.check_at(&tid(), SessionId(i), t0);
        }
        assert_eq!(
            limiter.bucket_count(),
            100,
            "one bucket per touched session"
        );

        // (burst + 1) refill intervals later, every one of those buckets has
        // refilled to full and is evicted when the next, unrelated access sweeps
        // the map — leaving only the freshly created bucket.
        let later = t0 + Duration::from_secs(5) * 4 + Duration::from_secs(1);
        assert!(limiter.check_at(&tid(), SessionId(1000), later));
        assert_eq!(
            limiter.bucket_count(),
            1,
            "idle buckets are pruned on access, bounding the map",
        );
    }

    #[test]
    fn a_bucket_touched_within_the_idle_window_is_not_evicted() {
        // Eviction must not drop a session still within its idle window — a session
        // re-asking at the steady-state cadence keeps its (partially spent) bucket.
        let limiter = RehomeLimiter::new(3, Duration::from_secs(5));
        let t0 = Instant::now();
        assert!(limiter.check_at(&tid(), SessionId(1), t0));
        assert!(limiter.check_at(&tid(), SessionId(1), t0));
        // One refill interval later (well inside the idle window), the bucket is
        // still present and has only partially refilled — the third and fourth
        // asks are not a fresh full burst.
        let t1 = t0 + Duration::from_secs(5);
        assert!(limiter.check_at(&tid(), SessionId(1), t1));
        assert_eq!(limiter.bucket_count(), 1, "the active bucket survives");
    }

    #[test]
    fn a_unique_key_spray_is_bounded_by_the_cap_and_spares_an_active_bucket() {
        // A cardinality cap must bound the map no matter the rate: an authenticated
        // caller spraying unique session ids can never grow it past the cap, and the
        // eviction (stalest first) never drops a legitimately active session.
        let cap = 4;
        let limiter = RehomeLimiter::with_bucket_cap(1, Duration::from_secs(5), cap);
        let t0 = Instant::now();

        // Spray far more unique sessions than the cap, all at t0.
        for i in 0..(cap as u64 * 3) {
            limiter.check_at(&tid(), SessionId(i), t0);
        }
        assert!(
            limiter.bucket_count() <= cap,
            "the cap bounds the map under a unique-key spray",
        );

        // A legitimate session re-homes slightly later (within the idle window, so
        // the t0 buckets are cap-evicted rather than idle-evicted), spending its one
        // token so a later reset would be observable.
        let t1 = t0 + Duration::from_secs(1);
        let legit = SessionId(999);
        assert!(limiter.check_at(&tid(), legit, t1));
        assert!(
            !limiter.check_at(&tid(), legit, t1),
            "its single-token burst is spent"
        );

        // More unique garbage at t1. Eviction targets the stalest (older t0) buckets,
        // never the just-touched legit one; fewer sprays than the surviving t0 count
        // keeps at least one stale bucket present at every step.
        for i in 1000..(1000 + cap as u64 - 1) {
            limiter.check_at(&tid(), SessionId(i), t1);
        }
        assert!(
            limiter.bucket_count() <= cap,
            "still bounded after the second spray"
        );

        // The legit bucket survived: its token is still spent, so it is refused —
        // a fresh (evicted-and-recreated) bucket would instead admit a full burst.
        assert!(
            !limiter.check_at(&tid(), legit, t1),
            "the active bucket was spared; it did not reset to a fresh burst",
        );
    }

    #[test]
    fn forget_drops_a_sessions_buckets() {
        let limiter = RehomeLimiter::new(1, Duration::from_secs(5));
        let t0 = Instant::now();
        assert!(limiter.check_at(&tid(), SessionId(1), t0));
        assert!(!limiter.check_at(&tid(), SessionId(1), t0));
        // After forgetting, the session starts fresh with a full burst.
        limiter.forget(&tid(), SessionId(1));
        assert!(limiter.check_at(&tid(), SessionId(1), t0));
    }
}
