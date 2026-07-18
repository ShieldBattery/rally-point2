//! Bounds "admit-first" client admission: a session with no applied
//! descriptor yet is admitted onto any relay a client's token names --
//! tolerating the create-response-to-client-dial race beating the
//! coordinator's asynchronous descriptor push (see
//! [`crate::consensus::slot_homed`]). Left unbounded, a stale or misrouted
//! token could park a session open indefinitely on a relay no descriptor will
//! ever name. This module marks such an admission provisional with a
//! deadline, and the relay's periodic sweep tears it down if no descriptor
//! claimed the session by then.
//!
//! # Marking and clearing
//!
//! [`ProvisionalSessions::mark_if_undescribed`] runs under the same
//! decision-maker registry lock [`crate::consensus::sync_maker`]'s own
//! check-and-insert does, so the two can never race past each other:
//! whichever observes the session's maker absent first completes -- a mark
//! recorded, or a maker inserted -- before the other proceeds. A mark that
//! momentarily wins the race against an in-flight descriptor is still
//! guaranteed to be cleared: `sync_maker`'s caller
//! ([`crate::mesh_control::MeshControl::apply_descriptor`]) clears the mark
//! right after creating the maker, and that call is strictly ordered after
//! the insert its own lock scope already completed. A session created any
//! other way -- a mesh Join, or a descriptor applied before any client ever
//! dials -- never gets a mark to begin with, because its maker already
//! exists by the time a client's own admission would go looking for one.
//!
//! # Arming
//!
//! Marking always happens at admission, coordinator-driven relay or not --
//! it is cheap, and correct even if a coordinator attaches later. Only the
//! sweep itself ([`run_sweep`]) is conditionally armed: a standalone relay
//! (`--mesh-peer`, no coordinator) never spawns it, since nothing will ever
//! apply a descriptor to clear a mark there, and reaping would just be timed
//! demolition of every session the relay serves. A coordinator-driven relay
//! arms the sweep only while its control connection is up -- an outage that
//! stops descriptor pushes from arriving must not be mistaken for a session
//! nobody will ever describe. See [`run_sweep`] for how a reconnect resumes
//! marks it had paused on rather than reaping them on stale time debt.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::watch;

use crate::consensus::DecisionMakers;
use crate::routing::{self, SessionKey, Sessions};

/// How long a client-admitted session may go with no applied descriptor
/// before the sweep tears it down. Generous relative to an ordinary
/// create-response-to-dial race (sub-second) or ordinary descriptor-push
/// latency, while still bounding how long a stale or misrouted token can hold
/// a session open on a relay no descriptor will ever name.
pub const PROVISIONAL_WINDOW: Duration = Duration::from_secs(10);

/// How often the sweep checks for an expired mark. Small relative to
/// [`PROVISIONAL_WINDOW`] so a reap lands close to the deadline rather than a
/// whole extra interval past it.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

type Marks = Arc<Mutex<HashMap<SessionKey, Instant>>>;

/// Per-relay registry of provisional-admission deadlines: a session admitted
/// by a client dial with no applied descriptor yet gets an entry here,
/// marking when it must be named by a descriptor or reaped. Cheap to clone
/// (an `Arc` around the map), so it rides in [`crate::mesh::MeshState`]
/// alongside the other per-session registries.
#[derive(Clone)]
pub struct ProvisionalSessions {
    marks: Marks,
    /// How far past a mark's creation (or restart) its deadline sits. A field
    /// rather than a bare use of [`PROVISIONAL_WINDOW`] so a test can inject a
    /// tiny window and drive the reap path without a real 10-second wait;
    /// production builds it with the constant.
    window: Duration,
}

impl ProvisionalSessions {
    /// An empty registry whose marks expire `window` after they are set (or
    /// last restarted).
    pub fn new(window: Duration) -> Self {
        Self {
            marks: Arc::new(Mutex::new(HashMap::new())),
            window,
        }
    }

    /// Marks `key` provisional with a deadline `window` (see [`Self::new`]) from now --
    /// unless, atomically under `decision_makers`' own lock, a maker already
    /// exists for it (a descriptor already named the session, or one is
    /// concurrently being applied). Returns whether the mark was recorded.
    /// See the module docs for why holding that lock across the mark is what
    /// closes the race with [`crate::consensus::sync_maker`]'s own
    /// check-and-insert.
    ///
    /// A duplicate call for an already-marked session -- a second slot's
    /// admission racing in before any descriptor arrives -- keeps the
    /// earlier deadline, so a steady trickle of dials can't hold a
    /// descriptor-less session open indefinitely.
    pub fn mark_if_undescribed(&self, decision_makers: &DecisionMakers, key: &SessionKey) -> bool {
        let makers = decision_makers.lock();
        if makers.contains_key(key) {
            return false;
        }
        let deadline = Instant::now() + self.window;
        self.marks.lock().entry(key.clone()).or_insert(deadline);
        true
    }

    /// Clears `key`'s provisional mark -- a descriptor named the session, or
    /// its local roster went empty with nothing left to protect. Idempotent;
    /// a no-op when no mark is present.
    pub fn clear(&self, key: &SessionKey) {
        self.marks.lock().remove(key);
    }

    /// Whether `key` is currently marked provisional, for tests.
    #[cfg(test)]
    pub fn is_marked(&self, key: &SessionKey) -> bool {
        self.marks.lock().contains_key(key)
    }

    /// Pushes every currently-marked session's deadline out to `window` (see
    /// [`Self::new`]) from now. Called when the coordinator control connection
    /// (re)establishes: the full descriptor set resyncs immediately on
    /// connect and will clear any mark it actually names, so this only has to
    /// give that resync room to land -- never reaping on time debt
    /// accumulated while the connection was down.
    fn restart_all(&self) {
        let deadline = Instant::now() + self.window;
        for value in self.marks.lock().values_mut() {
            *value = deadline;
        }
    }

    /// Removes and returns the keys whose deadline is at or before `now`.
    fn take_expired(&self, now: Instant) -> Vec<SessionKey> {
        let mut marks = self.marks.lock();
        let expired: Vec<SessionKey> = marks
            .iter()
            .filter(|&(_, &deadline)| deadline <= now)
            .map(|(key, _)| key.clone())
            .collect();
        for key in &expired {
            marks.remove(key);
        }
        expired
    }
}

/// Runs the provisional-admission sweep at the production cadence. Never
/// returns; spawned once per relay when a coordinator is configured -- see
/// the module docs for arming.
///
/// `decision_makers` is consulted before each reap so a session a descriptor
/// named just as its deadline passed is spared -- see [`run_sweep_with`].
pub async fn run_sweep(
    provisional: ProvisionalSessions,
    sessions: Sessions,
    decision_makers: Arc<DecisionMakers>,
    armed: watch::Receiver<bool>,
) {
    run_sweep_with(
        provisional,
        sessions,
        decision_makers,
        armed,
        SWEEP_INTERVAL,
    )
    .await;
}

/// [`run_sweep`] with the sweep interval injected, so a test can drive a reap
/// without waiting a whole production tick. `provisional`'s own configured
/// window (see [`ProvisionalSessions::new`]) governs how long a mark stands,
/// including on a rearm's restart.
///
/// A descriptor can name a session in the narrow window between the sweep
/// pulling its mark (`take_expired`) and the reap firing --
/// [`crate::mesh_control::MeshControl::apply_descriptor`] creates the session's
/// decision-maker and clears the mark concurrently. So each expired key is
/// checked against `decision_makers` before it is reaped: a maker now present
/// means a descriptor claimed the session, and the reap is skipped. The pulled
/// mark is already consumed, so a spared key needs nothing further. The check
/// mirrors [`ProvisionalSessions::mark_if_undescribed`]'s own maker check and is
/// deliberately best-effort -- a maker created strictly between the check and the
/// reap still reaps, but that residual is self-healing (the client reconnects and
/// is admitted cleanly), so no lock is held across the reap to close it.
pub async fn run_sweep_with(
    provisional: ProvisionalSessions,
    sessions: Sessions,
    decision_makers: Arc<DecisionMakers>,
    armed: watch::Receiver<bool>,
    sweep_interval: Duration,
) {
    let mut ticker = tokio::time::interval(sweep_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The arm state as of the last tick, so a rising edge (unarmed -> armed)
    // can be detected and restarted *on the very tick that observes it* --
    // deliberately a single-branch loop (polling `armed.borrow()`, a
    // synchronous read, rather than also `select!`-ing on `armed.changed()`)
    // so there is no second wakeup path that could race this one: reading the
    // transition and reaping expired marks happen back-to-back in the same
    // synchronous tick, so a tick can never observe "just armed" and reap on
    // stale time debt before the restart below has had a chance to run.
    let mut was_armed = *armed.borrow();
    loop {
        ticker.tick().await;
        let now_armed = *armed.borrow();
        if now_armed && !was_armed {
            // A fresh connect or reconnect: the coordinator is about to
            // resync the full descriptor set, so give every currently-marked
            // session a clean window rather than reaping on time debt from
            // the outage.
            provisional.restart_all();
        }
        was_armed = now_armed;
        if now_armed {
            for key in provisional.take_expired(Instant::now()) {
                // A descriptor may have named the session as its deadline passed:
                // skip the reap if a decision-maker now exists for it. The mark is
                // already consumed, so a spared key needs nothing further.
                if decision_makers.lock().contains_key(&key) {
                    continue;
                }
                tracing::info!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    "provisional session's deadline passed with no applied descriptor; reaping",
                );
                routing::reap_provisional(&sessions, &key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rally_point_proto::control::TenantId;
    use rally_point_proto::ids::SessionId;

    fn key(session: u64) -> SessionKey {
        SessionKey {
            tenant: TenantId("t".to_owned()),
            session: SessionId(session),
        }
    }

    #[test]
    fn marks_and_clears() {
        let provisional = ProvisionalSessions::new(Duration::from_secs(10));
        let makers = crate::consensus::new_decision_makers();
        assert!(!provisional.is_marked(&key(1)));

        assert!(provisional.mark_if_undescribed(&makers, &key(1)));
        assert!(provisional.is_marked(&key(1)));

        provisional.clear(&key(1));
        assert!(!provisional.is_marked(&key(1)));
        // Clearing an absent mark is a no-op, never a panic.
        provisional.clear(&key(1));
    }

    #[test]
    fn a_duplicate_mark_keeps_the_earlier_deadline() {
        let provisional = ProvisionalSessions::new(Duration::from_millis(10));
        let makers = crate::consensus::new_decision_makers();

        assert!(provisional.mark_if_undescribed(&makers, &key(1)));
        std::thread::sleep(Duration::from_millis(30));
        // A second admission for the same still-undescribed session must not
        // push the deadline out -- if it did, a fresh 10ms window from *this*
        // call would still be unexpired below.
        assert!(provisional.mark_if_undescribed(&makers, &key(1)));

        let expired = provisional.take_expired(Instant::now());
        assert_eq!(
            expired,
            vec![key(1)],
            "the original deadline governed, not a deadline refreshed by the duplicate call",
        );
    }

    #[test]
    fn mark_if_undescribed_refuses_once_a_maker_exists() {
        use crate::consensus::sync_maker;
        use rally_point_proto::control::BufferBounds;
        use std::collections::HashSet;

        let provisional = ProvisionalSessions::new(Duration::from_secs(10));
        let makers = crate::consensus::new_decision_makers();
        let _ = sync_maker(
            &makers,
            &key(1),
            BufferBounds::new(0, 20).unwrap(),
            crate::consensus::Authority::SelfRelay,
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
        );

        assert!(
            !provisional.mark_if_undescribed(&makers, &key(1)),
            "a descriptor already named the session; admission must not mark it provisional",
        );
        assert!(!provisional.is_marked(&key(1)));
    }

    #[test]
    fn take_expired_only_removes_past_deadlines() {
        let provisional = ProvisionalSessions::new(Duration::from_millis(10));
        let makers = crate::consensus::new_decision_makers();
        provisional.mark_if_undescribed(&makers, &key(1));

        let long_lived = ProvisionalSessions::new(Duration::from_secs(60));
        long_lived.mark_if_undescribed(&makers, &key(2));

        std::thread::sleep(Duration::from_millis(30));
        let expired = provisional.take_expired(Instant::now());
        assert_eq!(expired, vec![key(1)], "only the passed deadline is reaped");
        assert!(
            long_lived.is_marked(&key(2)),
            "the still-live deadline survives the sweep",
        );
    }

    #[test]
    fn restart_all_pushes_every_mark_out() {
        let provisional = ProvisionalSessions::new(Duration::from_millis(10));
        let makers = crate::consensus::new_decision_makers();
        provisional.mark_if_undescribed(&makers, &key(1));
        provisional.mark_if_undescribed(&makers, &key(2));

        std::thread::sleep(Duration::from_millis(30));
        provisional.restart_all();

        assert!(
            provisional.take_expired(Instant::now()).is_empty(),
            "both marks were pushed out to a fresh, un-expired deadline",
        );
        assert!(provisional.is_marked(&key(1)));
        assert!(provisional.is_marked(&key(2)));
    }

    #[tokio::test]
    async fn the_sweep_reaps_only_while_armed_and_a_rearm_restarts_the_window() {
        // A real-time test: the sweep compares deadlines against the wall clock
        // (`std::time::Instant`), so paused tokio time can't drive it and the
        // waits are real. The margins are therefore generous multiples of the
        // window, and the sweep ticks at a tenth of it, so a slow/loaded CI
        // runner's scheduling jitter has slack in every direction rather than
        // riding the edge of an assertion.
        let window = Duration::from_millis(100);
        let tick = window / 10;
        let provisional = ProvisionalSessions::new(window);
        let makers = Arc::new(crate::consensus::new_decision_makers());
        let sessions: Sessions = Arc::default();
        let (armed_tx, armed_rx) = watch::channel(false);

        provisional.mark_if_undescribed(&makers, &key(1));

        tokio::spawn(run_sweep_with(
            provisional.clone(),
            sessions,
            makers.clone(),
            armed_rx,
            tick,
        ));

        // Let the mark's window fully elapse while unarmed; many sweep ticks
        // pass over the now-expired mark, and it is left alone -- an outage must
        // not reap a legitimate session.
        tokio::time::sleep(window * 2).await;
        assert!(
            provisional.is_marked(&key(1)),
            "an expired mark is left alone while the sweep is unarmed",
        );

        // Rearming (a reconnect) must restart the window, not reap on the
        // accumulated debt: a short moment after arming (well under a fresh
        // `window`) the mark still stands.
        armed_tx.send(true).unwrap();
        tokio::time::sleep(window / 4).await;
        assert!(
            provisional.is_marked(&key(1)),
            "arming restarts the deadline rather than reaping immediately on stale debt",
        );

        // Well past the restarted window -- a full extra window of slack for
        // tick + scheduling jitter -- the sweep has reaped it.
        tokio::time::sleep(window * 2).await;
        assert!(
            !provisional.is_marked(&key(1)),
            "the mark is reaped once its restarted deadline passes while armed",
        );
    }

    #[tokio::test]
    async fn the_sweep_signals_a_registered_slots_connection_to_close() {
        // End-to-end from the registry through the real sweep into routing: a
        // session admitted with no descriptor gets its slot's provisional-reap
        // signal fired once the sweep observes its deadline passed while armed,
        // and the mark itself is consumed by the reap.
        let provisional = ProvisionalSessions::new(Duration::from_millis(20));
        let makers = Arc::new(crate::consensus::new_decision_makers());
        let sessions: Sessions = Arc::default();
        let (mut guard, inbox) =
            routing::register(&sessions, &key(1), rally_point_proto::ids::SlotId(0))
                .expect("slot 0 registers");
        guard.disarm();
        let reap_signal = inbox.provisional_reap_handle();

        provisional.mark_if_undescribed(&makers, &key(1));

        let (_armed_tx, armed_rx) = watch::channel(true);
        tokio::spawn(run_sweep_with(
            provisional.clone(),
            sessions,
            makers.clone(),
            armed_rx,
            Duration::from_millis(10),
        ));

        tokio::time::timeout(Duration::from_millis(200), reap_signal.notified())
            .await
            .expect("the sweep signals the registered slot's link to close");
        assert!(
            !provisional.is_marked(&key(1)),
            "the mark is consumed by the reap",
        );
    }

    #[tokio::test]
    async fn a_described_session_is_spared_when_its_maker_appears_before_the_reap() {
        use crate::consensus::sync_maker;
        use rally_point_proto::control::BufferBounds;
        use std::collections::HashSet;

        // The race the maker-check closes: a session marked provisional, then named
        // by a descriptor (its decision-maker created) with the mark not yet
        // cleared. The sweep's take_expired pulls the still-present mark, but the
        // maker now exists, so the session must be spared rather than reaped.
        let window = Duration::from_millis(20);
        let provisional = ProvisionalSessions::new(window);
        let makers = Arc::new(crate::consensus::new_decision_makers());
        let sessions: Sessions = Arc::default();

        let (mut guard, inbox) =
            routing::register(&sessions, &key(1), rally_point_proto::ids::SlotId(0))
                .expect("slot 0 registers");
        guard.disarm();
        let reap_signal = inbox.provisional_reap_handle();

        // Mark first (no maker yet), then create the maker as apply_descriptor's
        // sync_maker would -- leaving the mark in place to model the race window.
        assert!(provisional.mark_if_undescribed(&makers, &key(1)));
        let _ = sync_maker(
            &makers,
            &key(1),
            BufferBounds::new(0, 20).unwrap(),
            crate::consensus::Authority::SelfRelay,
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
            HashSet::new(),
        );
        assert!(
            provisional.is_marked(&key(1)),
            "the mark is still present when the sweep runs",
        );

        let (_armed_tx, armed_rx) = watch::channel(true);
        tokio::spawn(run_sweep_with(
            provisional.clone(),
            sessions,
            makers.clone(),
            armed_rx,
            Duration::from_millis(10),
        ));

        // Well past the deadline, the slot's reap signal must never fire: the maker
        // spared it. (take_expired still consumes the mark, so it is gone.)
        let fired = tokio::time::timeout(window * 4, reap_signal.notified()).await;
        assert!(
            fired.is_err(),
            "a session a descriptor named is not reaped even though its deadline passed",
        );
    }
}
