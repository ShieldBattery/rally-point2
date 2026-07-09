//! Rate limiting for the coordinator-mediated re-home endpoint.
//!
//! `POST /session/rehome` is client-authenticated (a per-slot Ed25519 signature),
//! and a client may legitimately re-ask every few seconds while its home relay is
//! unreachable — so the limit is lenient, a small burst with a slow refill, sized
//! only to stop a misbehaving or compromised client from hammering the endpoint.
//! The limit is per `(tenant, session, slot)`: one slot's re-asking never starves
//! another's, and the bucket is keyed on the *authenticated* slot (from the
//! verified token), never a value the request body could spoof.
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
use rally_point_proto::ids::{SessionId, SlotId};

/// Burst capacity: how many re-home requests one slot may make back-to-back
/// before it must wait for the bucket to refill. Three covers a client that
/// re-asks a couple of times across a brief outage without tripping the limit.
pub const REHOME_BURST: u32 = 3;

/// How often one token refills. A client may legitimately re-ask about every five
/// seconds while its relay is unreachable, so the steady-state rate matches that.
pub const REHOME_REFILL_INTERVAL: Duration = Duration::from_secs(5);

/// The key of one slot's rate-limit bucket: which slot, in which session.
type BucketKey = (TenantId, SessionId, SlotId);

/// A token bucket for one `(tenant, session, slot)`.
struct Bucket {
    /// Tokens available now, fractional so a partial refill accrues between
    /// requests rather than being lost.
    tokens: f64,
    /// When the tokens were last refilled — the anchor the next check accrues from.
    last_refill: Instant,
}

/// The per-slot re-home rate limiter, shared across every request handler. Clone
/// it cheaply (the state is behind one `Arc`) to hand a copy to the router state.
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

    /// Whether a re-home request for `(tenant, session, slot)` is admitted now,
    /// consuming a token if so. A fresh slot starts with a full burst. Refills
    /// accrue at one token per [`refill_interval`](Self::new) up to the burst cap.
    pub fn check(&self, tenant: &TenantId, session: SessionId, slot: SlotId) -> bool {
        self.check_at(tenant, session, slot, Instant::now())
    }

    /// [`check`](Self::check) against an explicit clock, so a test can advance time
    /// deterministically rather than sleeping.
    pub fn check_at(
        &self,
        tenant: &TenantId,
        session: SessionId,
        slot: SlotId,
        now: Instant,
    ) -> bool {
        let refill_per_sec = 1.0 / self.refill_interval.as_secs_f64();
        let burst = f64::from(self.burst);
        let mut buckets = self.buckets.lock();
        let bucket = buckets
            .entry((tenant.clone(), session, slot))
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
            .retain(|(t, s, _), _| !(t == tenant && *s == session));
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
            assert!(limiter.check_at(&tid(), SessionId(1), SlotId(0), t0));
        }
        // The 4th, with no time elapsed, is refused.
        assert!(!limiter.check_at(&tid(), SessionId(1), SlotId(0), t0));

        // After one refill interval, exactly one token is available again.
        let t1 = t0 + Duration::from_secs(5);
        assert!(limiter.check_at(&tid(), SessionId(1), SlotId(0), t1));
        assert!(!limiter.check_at(&tid(), SessionId(1), SlotId(0), t1));
    }

    #[test]
    fn buckets_are_independent_per_slot_and_session() {
        let limiter = RehomeLimiter::new(1, Duration::from_secs(5));
        let t0 = Instant::now();
        // Slot 0 spends its only token; slot 1 and another session are untouched.
        assert!(limiter.check_at(&tid(), SessionId(1), SlotId(0), t0));
        assert!(!limiter.check_at(&tid(), SessionId(1), SlotId(0), t0));
        assert!(limiter.check_at(&tid(), SessionId(1), SlotId(1), t0));
        assert!(limiter.check_at(&tid(), SessionId(2), SlotId(0), t0));
    }

    #[test]
    fn refill_is_capped_at_the_burst() {
        let limiter = RehomeLimiter::new(3, Duration::from_secs(5));
        let t0 = Instant::now();
        // Spend one token, then wait a very long time: the bucket refills only to
        // the burst cap, not unbounded.
        assert!(limiter.check_at(&tid(), SessionId(1), SlotId(0), t0));
        let far = t0 + Duration::from_secs(3600);
        for _ in 0..3 {
            assert!(limiter.check_at(&tid(), SessionId(1), SlotId(0), far));
        }
        assert!(!limiter.check_at(&tid(), SessionId(1), SlotId(0), far));
    }

    #[test]
    fn forget_drops_a_sessions_buckets() {
        let limiter = RehomeLimiter::new(1, Duration::from_secs(5));
        let t0 = Instant::now();
        assert!(limiter.check_at(&tid(), SessionId(1), SlotId(0), t0));
        assert!(!limiter.check_at(&tid(), SessionId(1), SlotId(0), t0));
        // After forgetting, the slot starts fresh with a full burst.
        limiter.forget(&tid(), SessionId(1));
        assert!(limiter.check_at(&tid(), SessionId(1), SlotId(0), t0));
    }
}
