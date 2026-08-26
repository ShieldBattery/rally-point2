//! The per-session terminal ingress boundary.
//!
//! Descriptor retirement sweeps a session's state (its decision-maker, drop
//! holds, abandon timer, flight seal) but the paths that *feed* that state run
//! concurrently: client dials, the turn funnel, mesh control dispatch, and the
//! flight recorder's create-on-first-touch. Each of those used to check some
//! piece of state and then mutate another, so a retirement landing between the
//! check and the mutation could have the mutation resurrect what the sweep had
//! just removed — a recreated drop hold, a duplicate close report, a
//! contentless flight recording, or a freshly admitted client on a session the
//! coordinator already ended.
//!
//! [`SessionGates`] closes that race with one per-session reader/writer gate:
//!
//! - Every ingress runs its check **and** its mutations inside
//!   [`with_ingress`](SessionGates::with_ingress) (a read acquisition), which
//!   refuses when the session is retired.
//! - Retirement marks the session retired under the write side
//!   ([`retire`](SessionGates::retire)) **before** any state is swept. The
//!   write acquisition drains every in-flight ingress first, so their
//!   mutations land wholly before the sweeps; any ingress that starts after
//!   the mark observes it and refuses.
//!
//! A retired gate is lifted by the next descriptor naming the session
//! ([`reopen`](SessionGates::reopen) — a genuine re-serve), pruned by age
//! otherwise. A session that ends with no coordinator lifecycle at all (a
//! provisional admission no descriptor ever claimed) is discarded outright at
//! its emptied-session close ([`discard`](SessionGates::discard)) — no
//! retirement will ever come for it, and nothing remains for its gate to
//! guard.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

use crate::routing::SessionKey;

/// How long a retired session's gate is kept (absent a re-serve reopening it).
/// Two windows to cover. The short one — retirement's queued mesh Leave
/// commands still draining through the link drivers — is seconds at worst.
/// The long one is what actually sizes this: a retired session's client
/// tokens stay valid for the coordinator's token lifetime, and once the gate
/// is pruned a stale dial is admitted through the permissive no-maker path,
/// resurrecting roster/seen state for a session the coordinator already
/// ended. So the TTL is tied to the credential invariant, not a guess: the
/// fleet-wide token-lifetime ceiling the coordinator clamps its minting to,
/// plus an hour of margin. A retired entry is a key and a timestamp, so
/// holding a day's worth still bounds the map at trivial cost.
const RETIRED_GATE_TTL: Duration =
    Duration::from_secs(rally_point_proto::control::MAX_PLAYER_TOKEN_LIFETIME_SECS + 60 * 60);

#[derive(Default)]
struct GateState {
    /// When the session's descriptor was retired; `None` while it is served.
    retired_at: Option<Instant>,
}

/// One session's gate. The lock is the synchronization point: ingress holds
/// the read side across its critical section, retirement takes the write side
/// to mark.
#[derive(Default)]
struct SessionGate {
    state: RwLock<GateState>,
}

/// The relay-wide gate registry. Cheaply cloneable (one `Arc` inside); every
/// ingress family — client admission, the turn funnel, mesh dispatch, the
/// flight recorder — holds the same instance, or the boundary means nothing.
#[derive(Clone, Default)]
pub struct SessionGates {
    inner: Arc<Mutex<HashMap<SessionKey, Arc<SessionGate>>>>,
}

impl SessionGates {
    /// The session's gate, created on first touch. Creation is what arms the
    /// write barrier: `retire` also creates, so the entry exists whichever
    /// side gets there first.
    fn gate(&self, key: &SessionKey) -> Arc<SessionGate> {
        Arc::clone(self.inner.lock().entry(key.clone()).or_default())
    }

    /// Runs `f` as an ingress critical section for `key`: `None` (with `f`
    /// never run) when the session is retired, otherwise `Some(f())` executed
    /// under the gate's read side — a concurrent [`retire`](Self::retire)
    /// waits for it, so `f`'s mutations land wholly before the retirement
    /// sweeps.
    ///
    /// The read acquisition is recursive, so an ingress that funnels into
    /// another gated path (mesh dispatch delivering an oversize turn through
    /// the shared turn funnel, say) re-enters its own session's gate without
    /// deadlocking against a waiting writer.
    pub fn with_ingress<R>(&self, key: &SessionKey, f: impl FnOnce() -> R) -> Option<R> {
        let gate = self.gate(key);
        let state = gate.state.read_recursive();
        if state.retired_at.is_some() {
            return None;
        }
        Some(f())
    }

    /// Whether `key` is currently retired — the lock-free-shaped query for
    /// paths that only need the flag (the flight recorder's create-on-touch),
    /// not a critical section. Prefer [`with_ingress`](Self::with_ingress)
    /// anywhere the caller mutates per-session state.
    pub fn is_retired(&self, key: &SessionKey) -> bool {
        self.inner
            .lock()
            .get(key)
            .is_some_and(|gate| gate.state.read_recursive().retired_at.is_some())
    }

    /// Marks `key` retired. The write acquisition drains every in-flight
    /// ingress section first, so the caller's subsequent sweeps run against
    /// state no concurrent ingress is still mutating. Expired retired gates
    /// are pruned on the same (rare) call.
    pub fn retire(&self, key: &SessionKey) {
        let gate = self.gate(key);
        gate.state.write().retired_at = Some(Instant::now());
        let now = Instant::now();
        self.inner.lock().retain(|_, gate| {
            gate.state
                .read_recursive()
                .retired_at
                .is_none_or(|at| now.duration_since(at) < RETIRED_GATE_TTL)
        });
    }

    /// Lifts `key`'s retirement — a descriptor names the session again (a
    /// genuine re-serve). A no-op for a session that was never retired.
    ///
    /// The gate is cloned out and the registry mutex RELEASED before the
    /// write acquisition: an ingress critical section may take the registry
    /// mutex itself (an emptied-session close holds its gate's read side and
    /// then calls [`discard`](Self::discard)), so waiting for the write while
    /// holding the registry mutex would be an ABBA deadlock against it.
    pub fn reopen(&self, key: &SessionKey) {
        let gate = self.inner.lock().get(key).cloned();
        if let Some(gate) = gate {
            gate.state.write().retired_at = None;
        }
    }

    /// Drops `key`'s gate outright — the emptied-session close of a session
    /// with no coordinator lifecycle (no descriptor ever named it), where no
    /// retirement will ever come and nothing remains to guard. A later dial
    /// for the id is a genuinely fresh admission with a fresh gate.
    pub fn discard(&self, key: &SessionKey) {
        self.inner.lock().remove(key);
    }

    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.inner.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rally_point_proto::control::TenantId;
    use rally_point_proto::ids::SessionId;

    fn key(session: u64) -> SessionKey {
        SessionKey {
            tenant: TenantId("sb-test".to_owned()),
            session: SessionId(session),
        }
    }

    #[test]
    fn ingress_runs_while_served_and_refuses_after_retirement() {
        let gates = SessionGates::default();
        let k = key(1);
        assert_eq!(gates.with_ingress(&k, || 7), Some(7));

        gates.retire(&k);
        let mut ran = false;
        assert_eq!(gates.with_ingress(&k, || ran = true), None);
        assert!(!ran, "a retired session's ingress closure never runs");
        assert!(gates.is_retired(&k));
    }

    #[test]
    fn a_reopened_gate_admits_ingress_again() {
        let gates = SessionGates::default();
        let k = key(1);
        gates.retire(&k);
        assert!(gates.with_ingress(&k, || ()).is_none());

        gates.reopen(&k);
        assert_eq!(gates.with_ingress(&k, || 3), Some(3));
        assert!(!gates.is_retired(&k));
    }

    #[test]
    fn ingress_reenters_its_own_gate() {
        // The funnel case: mesh dispatch holds the gate and delivers through
        // the turn path, which takes the same session's gate again.
        let gates = SessionGates::default();
        let k = key(1);
        let nested = gates.with_ingress(&k, || gates.with_ingress(&k, || 11));
        assert_eq!(nested, Some(Some(11)));
    }

    #[test]
    fn retirement_prunes_only_expired_retired_gates() {
        let gates = SessionGates::default();
        let live = key(1);
        let retired = key(2);
        assert_eq!(gates.with_ingress(&live, || ()), Some(()));
        gates.retire(&retired);
        // Both entries survive: the live gate is not retired, the retired one
        // is younger than the TTL.
        assert_eq!(gates.tracked(), 2);
        assert!(!gates.is_retired(&live));
        assert!(gates.is_retired(&retired));
    }

    #[test]
    fn discard_forgets_the_gate_entirely() {
        let gates = SessionGates::default();
        let k = key(1);
        gates.retire(&k);
        gates.discard(&k);
        assert_eq!(gates.tracked(), 0);
        // A later dial is a genuinely fresh admission.
        assert_eq!(gates.with_ingress(&k, || 1), Some(1));
    }
}
