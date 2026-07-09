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
}

impl Default for RehomeLimiter {
    fn default() -> Self {
        Self::new(REHOME_BURST, REHOME_REFILL_INTERVAL)
    }
}

impl RehomeLimiter {
    /// Builds a limiter with the given burst and refill interval. Production uses
    /// [`REHOME_BURST`]/[`REHOME_REFILL_INTERVAL`] (via [`Default`]); tests inject
    /// their own so they need not wait real seconds.
    pub fn new(burst: u32, refill_interval: Duration) -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            burst,
            refill_interval,
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
        let bucket = buckets
            .entry((tenant.clone(), session))
            .or_insert(Bucket {
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
