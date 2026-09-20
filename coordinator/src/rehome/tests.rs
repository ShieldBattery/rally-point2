//! What each limiter keys on. The token-bucket mechanics these limiters are
//! built from — burst, refill, idle eviction, the cardinality cap — are tested
//! over a bare key beside [`KeyedTokenBuckets`](crate::rate_limit); what is left
//! here is the choice of key, which is what decides whose traffic can starve
//! whose.

use super::*;
use crate::test_support::tid;

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
fn buckets_are_independent_per_session_and_tenant() {
    // Re-homing is keyed per (tenant, session): one session re-asking hard must
    // not starve another's, and a tenant-blind key would let one tenant starve
    // another's session of the same id.
    let limiter = RehomeLimiter::new(1, Duration::from_secs(5));
    let t0 = Instant::now();
    assert!(limiter.check_at(&tid(), SessionId(1), t0));
    assert!(!limiter.check_at(&tid(), SessionId(1), t0));
    assert!(limiter.check_at(&tid(), SessionId(2), t0));
    assert!(limiter.check_at(&TenantId("sb-other".to_owned()), SessionId(1), t0));
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
