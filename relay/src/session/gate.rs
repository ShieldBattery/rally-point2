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
//!
//! Removing a gate is a ROTATION, not a plain map delete: the removed
//! instance is marked defunct, and every acquisition re-checks that mark
//! after taking the lock, retrying against the registry's current entry. A
//! caller that raced the removal (a dial blocked behind it, a retirement
//! about to stamp its tombstone) therefore always lands on the gate future
//! acquisitions will actually observe, never on an orphan. Cleanup that must
//! check ownership and remove in one step uses
//! [`discard_if`](SessionGates::discard_if), which runs the check under the
//! gate's write side so nothing can create session state between the verdict
//! and the removal.
//!
//! Lock order: gate → registry is the ONLY sanctioned blocking nesting. A
//! rotation holds its gate's lock while it takes the registry mutex to
//! remove the entry, so nothing may BLOCK on a gate lock while holding the
//! registry — that inversion is a cross-session deadlock with the registry
//! held, stalling every gate lookup on the relay. Paths that need a gate's
//! state after a registry lookup clone the `Arc` out and release the
//! registry first; the TTL prune, which genuinely needs both, probes each
//! gate with a non-blocking `try` read and keeps anything contended for the
//! next round.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Set — permanently — when this INSTANCE is rotated out of the registry
    /// (a discard removed the map entry while someone might still hold the
    /// `Arc`). Every acquisition checks it after taking the lock and, on
    /// `true`, re-fetches the registry's CURRENT gate instead of proceeding
    /// on the orphan. Without this, a dial blocked behind a discard would
    /// wake on the removed instance and run its admission outside any gate a
    /// later retirement could drain, and a retirement blocked the same way
    /// would stamp its tombstone on an instance no future acquisition can
    /// ever observe — silently un-retiring the session. Only ever set inside
    /// the registry mutex, immediately before the map removal, so a gate
    /// fetched from the map is never already defunct.
    defunct: AtomicBool,
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
    ///
    /// An acquisition that lands on a defunct instance (the gate was rotated
    /// out of the registry while this caller held its `Arc`) retries against
    /// the registry's current gate — see `SessionGate::defunct`.
    pub fn with_ingress<R>(&self, key: &SessionKey, f: impl FnOnce() -> R) -> Option<R> {
        loop {
            let gate = self.gate(key);
            let state = gate.state.read_recursive();
            if gate.defunct.load(Ordering::SeqCst) {
                continue;
            }
            if state.retired_at.is_some() {
                return None;
            }
            return Some(f());
        }
    }

    /// Runs `f` as an EXCLUSIVE critical section for `key`: `None` (with `f`
    /// never run) when the session is retired, otherwise `Some(f())` under
    /// the gate's write side — every in-flight ingress section drains first,
    /// and none can start until `f` returns. This is the serialization the
    /// provisional journal's drain needs: its validate-then-record pair must
    /// not interleave with a deposit (which runs under the read side), or a
    /// departure superseded between the two would still record first. Use
    /// sparingly — the write acquisition stalls the session's whole ingress
    /// — and never from inside an ingress section (the recursive read does
    /// not extend to the write side; that would deadlock).
    ///
    /// Retries past a defunct instance exactly as
    /// [`with_ingress`](Self::with_ingress) does.
    pub fn with_exclusive<R>(&self, key: &SessionKey, f: impl FnOnce() -> R) -> Option<R> {
        loop {
            let gate = self.gate(key);
            let state = gate.state.write();
            if gate.defunct.load(Ordering::SeqCst) {
                continue;
            }
            if state.retired_at.is_some() {
                return None;
            }
            return Some(f());
        }
    }

    /// Whether `key` is currently retired — the lock-free-shaped query for
    /// paths that only need the flag (the flight recorder's create-on-touch),
    /// not a critical section. Prefer [`with_ingress`](Self::with_ingress)
    /// anywhere the caller mutates per-session state.
    ///
    /// The gate is cloned out and the registry mutex released before the
    /// state lock is taken: BLOCKING on a gate lock while holding the
    /// registry inverts the gate→registry order everything else obeys (a
    /// rotation holds its gate's write side while it takes the registry to
    /// remove the entry), and the inversion deadlocks with the registry held
    /// — freezing gate lookup for every session, not just this one.
    pub fn is_retired(&self, key: &SessionKey) -> bool {
        loop {
            let Some(gate) = self.inner.lock().get(key).cloned() else {
                return false;
            };
            let state = gate.state.read_recursive();
            if gate.defunct.load(Ordering::SeqCst) {
                continue;
            }
            return state.retired_at.is_some();
        }
    }

    /// Marks `key` retired. The write acquisition drains every in-flight
    /// ingress section first, so the caller's subsequent sweeps run against
    /// state no concurrent ingress is still mutating. Expired retired gates
    /// are pruned on the same (rare) call.
    ///
    /// Retries past a defunct instance: a retirement that blocked behind a
    /// concurrent discard must land its tombstone on the registry's current
    /// gate, not on the removed orphan — stamping the orphan would leave the
    /// session observably un-retired, and a still-valid stale token could
    /// then resurrect it through the permissive no-maker admission path.
    pub fn retire(&self, key: &SessionKey) {
        loop {
            let gate = self.gate(key);
            let mut state = gate.state.write();
            if gate.defunct.load(Ordering::SeqCst) {
                continue;
            }
            state.retired_at = Some(Instant::now());
            break;
        }
        self.prune_expired();
    }

    /// Removes retired gates older than [`RETIRED_GATE_TTL`].
    ///
    /// Runs under the registry mutex, so each gate's state is probed with a
    /// NON-BLOCKING read (`try_read_recursive`): waiting on a gate lock here
    /// would invert the gate→registry order — a rotation holds its gate's
    /// write side while it takes the registry to remove the entry, so a
    /// prune blocking on that gate while a rotation waits for the registry
    /// is a cross-session deadlock with the registry held (every gate
    /// lookup relay-wide stalls behind it). A gate whose lock is contended
    /// is simply kept this round; the next retirement prunes it.
    ///
    /// Removal marks the instance defunct first, inside the registry mutex,
    /// exactly as every other rotation does — a holder of the pruned `Arc`
    /// (a stale dial about to acquire it) re-fetches instead of running
    /// against the orphan.
    fn prune_expired(&self) {
        self.prune_expired_with(RETIRED_GATE_TTL);
    }

    fn prune_expired_with(&self, ttl: Duration) {
        let now = Instant::now();
        self.inner.lock().retain(|_, gate| {
            let Some(state) = gate.state.try_read_recursive() else {
                return true;
            };
            let expired = state
                .retired_at
                .is_some_and(|at| now.duration_since(at) >= ttl);
            if expired {
                gate.defunct.store(true, Ordering::SeqCst);
            }
            !expired
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
    ///
    /// The removed instance is marked defunct (inside the registry mutex, so
    /// the mark and the removal are one step against every fetch): anyone
    /// who cloned the `Arc` before the removal and acquires it afterward —
    /// a blocked retirement, a queued dial — re-fetches the registry's
    /// current state instead of proceeding on the orphan.
    pub fn discard(&self, key: &SessionKey) {
        if let Some(gate) = self.inner.lock().remove(key) {
            gate.defunct.store(true, Ordering::SeqCst);
        }
    }

    /// Atomically discards `key`'s gate IF the ownership check `f` allows it,
    /// returning whether it did. The whole call is one EXCLUSIVE critical
    /// section on the gate: the write acquisition drains every in-flight
    /// ingress first (so no admission is mid-registration while `f` reads
    /// the roster), a retirement that already landed refuses without running
    /// `f` (the tombstone stands), a retirement that arrives later blocks
    /// until the rotation completes and then retries onto the fresh entry,
    /// and `f`'s verdict and the removal happen with no seam between them —
    /// nothing can create state for the session after `f` approves and
    /// before the gate is gone, because creating that state requires an
    /// ingress section this call excludes.
    ///
    /// This is what a check-then-discard sequence over separate locks cannot
    /// give: a concurrent admission commits its roster seat and its journal
    /// reservation inside ingress sections, so a cleanup that snapshots the
    /// roster and then separately removes the journal can interleave with it
    /// and erase an admission it never saw — acknowledged, but with the
    /// capacity reservation this cleanup just deleted.
    ///
    /// `f` runs under the gate's write side; it must not acquire this
    /// registry or any gate lock (its own session locks — roster, makers,
    /// journal — follow the same discipline every gated section already
    /// obeys). Never call from inside an ingress section: the write
    /// acquisition would deadlock against the held read, exactly as
    /// [`with_exclusive`](Self::with_exclusive) documents.
    #[must_use]
    pub fn discard_if(&self, key: &SessionKey, f: impl FnOnce() -> bool) -> bool {
        loop {
            let gate = self.gate(key);
            let state = gate.state.write();
            if gate.defunct.load(Ordering::SeqCst) {
                continue;
            }
            if state.retired_at.is_some() {
                return false;
            }
            if !f() {
                return false;
            }
            let mut map = self.inner.lock();
            gate.defunct.store(true, Ordering::SeqCst);
            if map
                .get(key)
                .is_some_and(|current| Arc::ptr_eq(current, &gate))
            {
                map.remove(key);
            }
            return true;
        }
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
    fn exclusive_sections_run_while_served_and_refuse_after_retirement() {
        let gates = SessionGates::default();
        let k = key(1);
        assert_eq!(gates.with_exclusive(&k, || 5), Some(5));
        gates.retire(&k);
        let mut ran = false;
        assert_eq!(gates.with_exclusive(&k, || ran = true), None);
        assert!(!ran, "a retired session's exclusive closure never runs");
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

    #[test]
    fn discard_if_refuses_a_retired_gate_without_running_the_check() {
        let gates = SessionGates::default();
        let k = key(1);
        gates.retire(&k);
        let mut ran = false;
        assert!(!gates.discard_if(&k, || {
            ran = true;
            true
        }));
        assert!(
            !ran,
            "a tombstone refuses the discard before the check runs"
        );
        assert!(gates.is_retired(&k), "the tombstone stands");
    }

    #[test]
    fn discard_if_rotates_when_the_check_approves() {
        let gates = SessionGates::default();
        let k = key(1);
        assert_eq!(gates.with_ingress(&k, || ()), Some(()));
        assert!(gates.discard_if(&k, || true));
        assert_eq!(gates.tracked(), 0);
        // A later dial gets a fresh, working gate.
        assert_eq!(gates.with_ingress(&k, || 2), Some(2));
    }

    #[test]
    fn discard_if_retains_when_the_check_refuses() {
        let gates = SessionGates::default();
        let k = key(1);
        assert_eq!(gates.with_ingress(&k, || ()), Some(()));
        assert!(!gates.discard_if(&k, || false));
        assert_eq!(gates.tracked(), 1);
    }

    #[test]
    fn a_retirement_racing_a_conditional_discard_always_lands_its_tombstone() {
        // The write side serializes them: a retirement that lands first
        // leaves a tombstone the discard refuses; one that blocks behind the
        // rotation retries onto the fresh registry entry rather than
        // stamping the removed orphan (which would leave the session
        // observably un-retired for a stale token to resurrect).
        for _ in 0..200 {
            let gates = SessionGates::default();
            let k = key(1);
            assert_eq!(gates.with_ingress(&k, || ()), Some(()));
            std::thread::scope(|s| {
                s.spawn(|| {
                    let _ = gates.discard_if(&k, || true);
                });
                s.spawn(|| gates.retire(&k));
            });
            assert!(gates.is_retired(&k));
        }
    }

    #[test]
    fn a_retirement_racing_an_in_section_discard_always_lands_its_tombstone() {
        // The emptied-close shape: the discard runs from INSIDE an ingress
        // section (read side held), so a concurrent retirement can block on
        // the very instance the section removes. The defunct mark makes the
        // woken retirement re-fetch and stamp the registry's current entry
        // instead of the orphan.
        for _ in 0..200 {
            let gates = SessionGates::default();
            let k = key(1);
            assert_eq!(gates.with_ingress(&k, || ()), Some(()));
            std::thread::scope(|s| {
                s.spawn(|| {
                    let _ = gates.with_ingress(&k, || gates.discard(&k));
                });
                s.spawn(|| gates.retire(&k));
            });
            assert!(gates.is_retired(&k));
        }
    }

    #[test]
    fn cleanup_and_cross_session_retirement_do_not_deadlock() {
        // A rotation holds its gate's write side and then takes the registry
        // to remove the entry; retirement's TTL prune holds the registry and
        // probes every gate. If the probe BLOCKED on a contended gate, these
        // two would deadlock across unrelated sessions with the registry
        // held. The prune's non-blocking probe (skip and keep) is what this
        // pins — under the blocking shape this test hangs.
        for _ in 0..100 {
            let gates = SessionGates::default();
            let a = key(1);
            let b = key(2);
            assert_eq!(gates.with_ingress(&a, || ()), Some(()));
            assert_eq!(gates.with_ingress(&b, || ()), Some(()));
            std::thread::scope(|s| {
                s.spawn(|| {
                    let _ = gates.discard_if(&a, || {
                        std::thread::yield_now();
                        true
                    });
                });
                s.spawn(|| gates.retire(&b));
            });
            assert!(gates.is_retired(&b));
        }
    }

    #[test]
    fn pruning_marks_the_removed_gate_defunct() {
        let gates = SessionGates::default();
        let k = key(1);
        gates.retire(&k);
        let held = gates.gate(&k);
        gates.prune_expired_with(Duration::ZERO);
        assert_eq!(gates.tracked(), 0, "the expired tombstone is pruned");
        assert!(
            held.defunct.load(Ordering::SeqCst),
            "a holder of the pruned instance must observe it as rotated out",
        );
        // A stale dial that raced the prune with the old Arc retries onto a
        // fresh gate and is admitted — the TTL's intent.
        assert_eq!(gates.with_ingress(&k, || 4), Some(4));
    }

    #[test]
    fn pruning_keeps_a_gate_whose_lock_is_contended() {
        let gates = SessionGates::default();
        let k = key(1);
        gates.retire(&k);
        let held = gates.gate(&k);
        {
            let _write = held.state.write();
            gates.prune_expired_with(Duration::ZERO);
            assert_eq!(gates.tracked(), 1, "a contended gate is kept this round");
            assert!(!held.defunct.load(Ordering::SeqCst));
        }
        gates.prune_expired_with(Duration::ZERO);
        assert_eq!(gates.tracked(), 0, "the next round prunes it");
    }

    #[test]
    fn a_conditional_discard_never_erases_a_concurrent_admissions_state() {
        use std::sync::atomic::{AtomicU32, Ordering};
        // Miniature of admission-vs-cleanup: the admission commits its state
        // (roster seat, journal reservation) inside an ingress section; the
        // cleanup's check and erasure are one exclusive section. Either the
        // check sees the committed state and refuses, or the erasure
        // finishes strictly before the admission runs (on the fresh gate) —
        // the state can never be created between the check and the erasure
        // and then deleted.
        for _ in 0..200 {
            let gates = SessionGates::default();
            let k = key(1);
            assert_eq!(gates.with_ingress(&k, || ()), Some(()));
            let state = AtomicU32::new(0);
            std::thread::scope(|s| {
                s.spawn(|| {
                    let _ = gates.discard_if(&k, || {
                        if state.load(Ordering::SeqCst) == 1 {
                            return false;
                        }
                        state.store(0, Ordering::SeqCst);
                        true
                    });
                });
                s.spawn(|| {
                    let admitted = gates.with_ingress(&k, || state.store(1, Ordering::SeqCst));
                    assert!(admitted.is_some(), "nothing retires the session here");
                });
            });
            assert_eq!(
                state.load(Ordering::SeqCst),
                1,
                "an admission that ran must keep its state; the cleanup may only \
                 erase before it or refuse after it",
            );
        }
    }
}
