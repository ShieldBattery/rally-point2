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
        Self {
            buckets: KeyedTokenBuckets::new(burst, refill_interval, REHOME_BUCKET_CAP),
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
mod tests;
