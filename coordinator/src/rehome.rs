//! Rate limiting for the coordinator-mediated re-home endpoint and the load-state
//! read.
//!
//! Both are tenant-authenticated (the tenant's app server signs each request; game
//! clients never call the coordinator directly) and both are cheap to re-ask, so
//! both limits are lenient — sized only to stop a misbehaving caller from hammering
//! the endpoint. They differ in what they key on, which is what decides whose
//! traffic can starve whose.
//!
//! `POST /session/rehome` is limited per `(tenant, session)`: an app server may
//! legitimately re-ask every few seconds while a session's home relay is
//! unreachable, and one session's re-asking must never starve another's.
//!
//! `POST /session/load-state` is limited per **tenant**, because the cost it bounds
//! is fleet-wide rather than per-session: each read fans a question out to every
//! relay serving the named session and holds each one's writer while it answers, so
//! a tenant reading a thousand different sessions hard is exactly the load worth
//! capping. A refused read is a `429`; the answer is a snapshot the caller can
//! simply take again.
//!
//! Both are built on the shared [`KeyedTokenBuckets`](crate::rate_limit) machinery:
//! in-memory buckets behind a plain mutex, pruned lazily on access and hard-capped
//! by cardinality. A coordinator restart forgets them, which only grants a fresh
//! burst — harmless for limits that exist to bound abuse, not to enforce
//! correctness.

use std::time::{Duration, Instant};

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::SessionId;

use crate::rate_limit::KeyedTokenBuckets;

/// Burst capacity: how many re-home requests one session may make back-to-back
/// before it must wait for the bucket to refill. Three covers an app server that
/// re-asks a couple of times across a brief outage without tripping the limit.
pub const REHOME_BURST: u32 = 3;

/// How often one re-home token refills. An app server may legitimately re-ask about
/// every five seconds while a relay is unreachable, so the steady-state rate matches
/// that.
pub const REHOME_REFILL_INTERVAL: Duration = Duration::from_secs(5);

/// Hard cap on the number of live re-home buckets. The time-window idle eviction
/// alone only bounds the map by `O(rate x window)`, so an authenticated caller
/// spraying unique garbage session ids at high rate could hold many thousands of
/// buckets between eviction sweeps. This cap bounds the map by cardinality
/// regardless of rate. A few thousand comfortably covers every session a real
/// coordinator re-homes at once while keeping the worst-case memory footprint small.
pub const REHOME_BUCKET_CAP: usize = 4096;

/// Burst capacity for the load-state read: how many reads one tenant may make
/// back-to-back before it must wait. Ten covers a tenant whose load deadlines expire
/// together for a batch of games — a matchmaking wave adjudicating several stalled
/// loads at once — without letting a polling loop run free.
pub const LOAD_STATE_BURST: u32 = 10;

/// How often one load-state token refills: thirty reads a minute in steady state.
/// The read answers a question a tenant asks once its own load deadline expired, so
/// a healthy tenant spends far less than this; the rate is what a caller re-reading
/// after an incomplete answer can sustain without the fleet feeling it.
pub const LOAD_STATE_REFILL_INTERVAL: Duration = Duration::from_millis(2000);

/// Hard cap on the number of live load-state buckets. Keyed per tenant, so this is
/// bounded by enrolled tenants rather than by anything a caller supplies; the cap is
/// a backstop, not a working limit.
pub const LOAD_STATE_BUCKET_CAP: usize = 4096;

/// The per-session re-home rate limiter, shared across every request handler. Clone
/// it cheaply to hand a copy to the router state.
#[derive(Clone)]
pub struct RehomeLimiter {
    buckets: KeyedTokenBuckets<(TenantId, SessionId)>,
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
            buckets: KeyedTokenBuckets::new(burst, refill_interval, bucket_cap),
        }
    }

    /// Whether a re-home request for `(tenant, session)` is admitted now,
    /// consuming a token if so.
    pub fn check(&self, tenant: &TenantId, session: SessionId) -> bool {
        self.check_at(tenant, session, Instant::now())
    }

    /// [`check`](Self::check) against an explicit clock, so a test can advance time
    /// deterministically rather than sleeping.
    pub fn check_at(&self, tenant: &TenantId, session: SessionId, now: Instant) -> bool {
        self.buckets.check_at(&(tenant.clone(), session), now)
    }

    /// Drops every bucket for `session` — called when the session closes, so the
    /// map stays bounded by the coordinator's live re-homing sessions.
    pub fn forget(&self, tenant: &TenantId, session: SessionId) {
        self.buckets
            .retain_not(|(t, s)| t == tenant && *s == session);
    }

    /// The number of live buckets — a test hook for asserting idle eviction and
    /// close-time forgetting actually bound the map.
    #[cfg(test)]
    fn bucket_count(&self) -> usize {
        self.buckets.bucket_count()
    }
}

/// The per-tenant load-state read rate limiter, shared across every request
/// handler. Clone it cheaply to hand a copy to the router state.
#[derive(Clone)]
pub struct LoadStateLimiter {
    buckets: KeyedTokenBuckets<TenantId>,
    refill_interval: Duration,
}

impl Default for LoadStateLimiter {
    fn default() -> Self {
        Self::new(LOAD_STATE_BURST, LOAD_STATE_REFILL_INTERVAL)
    }
}

impl LoadStateLimiter {
    /// Builds a limiter with the given burst and refill interval, using the
    /// production bucket cap ([`LOAD_STATE_BUCKET_CAP`]). Production uses
    /// [`LOAD_STATE_BURST`]/[`LOAD_STATE_REFILL_INTERVAL`] (via [`Default`]); tests
    /// inject their own so they need not wait real seconds.
    pub fn new(burst: u32, refill_interval: Duration) -> Self {
        Self {
            buckets: KeyedTokenBuckets::new(burst, refill_interval, LOAD_STATE_BUCKET_CAP),
            refill_interval,
        }
    }

    /// Whether a load-state read for `tenant` is admitted now, consuming a token if
    /// so. A refused read is answered `429` with a `Retry-After`.
    pub fn check(&self, tenant: &TenantId) -> bool {
        self.check_at(tenant, Instant::now())
    }

    /// [`check`](Self::check) against an explicit clock, so a test can advance time
    /// deterministically rather than sleeping.
    pub fn check_at(&self, tenant: &TenantId, now: Instant) -> bool {
        self.buckets.check_at(tenant, now)
    }

    /// How long a refused caller should wait before re-reading: one refill
    /// interval, rounded up to whole seconds because `Retry-After` counts in
    /// seconds and rounding down would invite an immediately-refused retry.
    pub fn retry_after_secs(&self) -> u64 {
        self.refill_interval.as_secs().max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid() -> TenantId {
        TenantId("sb-test".to_owned())
    }

    #[test]
    fn load_state_reads_are_limited_per_tenant_not_per_session() {
        // The cost a load-state read imposes is fleet-wide — one read fans out to
        // every relay serving the named session — so the bucket must be the
        // tenant's, and reading a fresh session id must not buy a fresh burst.
        let limiter = LoadStateLimiter::new(2, Duration::from_secs(2));
        let t0 = Instant::now();
        assert!(limiter.check_at(&tid(), t0));
        assert!(limiter.check_at(&tid(), t0));
        assert!(
            !limiter.check_at(&tid(), t0),
            "the tenant's burst is spent whatever session it read",
        );
        // Another tenant is untouched.
        assert!(limiter.check_at(&TenantId("sb-other".to_owned()), t0));
        // One refill interval later, exactly one token is back.
        let t1 = t0 + Duration::from_secs(2);
        assert!(limiter.check_at(&tid(), t1));
        assert!(!limiter.check_at(&tid(), t1));
    }

    #[test]
    fn the_production_load_state_limit_is_thirty_reads_a_minute() {
        // The advertised steady-state rate, asserted against the constants rather
        // than restated in prose only.
        assert_eq!(
            Duration::from_secs(60).as_millis() / LOAD_STATE_REFILL_INTERVAL.as_millis(),
            30,
        );
        assert_eq!(LOAD_STATE_BURST, 10);
        assert_eq!(LoadStateLimiter::default().retry_after_secs(), 2);
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
