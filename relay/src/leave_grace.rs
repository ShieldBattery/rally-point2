//! A short hold on the authority's synced-leave decision for a slot that
//! *dropped* (its link died) rather than left cleanly.
//!
//! A dropped slot's departure is recorded and announced immediately (so every
//! relay knows it left and survivors learn who disconnected), but the decision
//! that removes it from lockstep — the permanent [`LeaveDirective`] — is held for
//! [`DISCONNECT_GRACE`] before it fires. A clean leave (the client announced its
//! own intent) is never held: an F10 quit must unstall survivors at once.
//!
//! The hold is deliberately **local and ephemeral**, not replicated state. The
//! durable record is the departure every relay already keeps (from `record_departure`
//! / a mesh `SlotDeparted`); this only gates *when* the relay that is currently
//! authority calls `decide_leave` against that record. A relay arms its own timer
//! when it observes the drop, so a failover during a grace does not lose the
//! departure — the promoted authority re-derives it from the shared record on
//! promotion (deciding immediately, since the record is what a promotion always
//! decides from), and every relay's leftover timer is a no-op `decide_leave` once
//! the slot is decided. The decision the timer eventually makes is byte-for-byte
//! the one an un-graced decision would have made: the grace changes timing, never
//! the directive's contents.
//!
//! Cancellation covers the ordering where a slot's clean-leave intent arrives
//! while a drop's grace for that same slot is still in flight: the clean path
//! cancels the pending hold and decides immediately, so the "left" outcome wins
//! over the held "dropped" one.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rally_point_proto::ids::SlotId;
use tokio::sync::oneshot;

use crate::routing::SessionKey;

/// The live-holds map: each held `(session, slot)` mapped to the cancel handle
/// (its timer task's `oneshot` sender) that a clean leave drops to cancel.
type PendingHolds = Arc<Mutex<HashMap<(SessionKey, SlotId), oneshot::Sender<()>>>>;

/// How long the authority holds a *dropped* slot's synced-leave decision before
/// firing it, giving survivors a window in which the slot could (in a later
/// reconnect feature) come back. Interim value: a fixed short hold, with no
/// manual-drop override yet. A clean leave bypasses it entirely.
pub const DISCONNECT_GRACE: Duration = Duration::from_millis(10_000);

/// Per-relay registry of in-flight leave-decision holds, keyed by the session and
/// slot whose drop is being held. Cheap to clone (an `Arc` around the shared map
/// plus the grace duration), so it rides in [`crate::mesh::MeshState`] alongside
/// the other per-session registries and is handed to every task that observes a
/// departure.
#[derive(Clone)]
pub struct LeaveGrace {
    /// Live holds. An entry's `oneshot::Sender` is the cancel handle: dropping it
    /// (via [`cancel`](Self::cancel), or when a timer finishes and removes its own
    /// entry) resolves the timer task's receiver, which then takes its cancel
    /// branch instead of deciding. A present entry means a grace is running for
    /// that `(session, slot)`.
    pending: PendingHolds,
    /// The hold duration. A field rather than a constant so a test can inject a
    /// tiny window and drive the full arm/expire path without a real 10-second
    /// wait; production builds it with [`DISCONNECT_GRACE`].
    grace: Duration,
}

impl LeaveGrace {
    /// A registry that holds dropped-slot decisions for `grace`.
    pub fn new(grace: Duration) -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            grace,
        }
    }

    /// Arms a hold for `(key, slot)`: after the grace elapses, `on_expire` runs —
    /// unless [`cancel`](Self::cancel) removed the hold first. Idempotent per
    /// slot: if a hold for the slot is already running, the existing one is kept
    /// (a duplicate drop signal does not restart the window). Must be called from
    /// within a Tokio runtime — it spawns the timer task.
    ///
    /// `on_expire` is the decision-and-broadcast step; it runs once, at expiry, on
    /// the timer task. It is synchronous (a `decide_leave` plus channel sends, no
    /// awaits) so the timer needs no borrowed state past the fire.
    pub fn arm<F>(&self, key: SessionKey, slot: SlotId, on_expire: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let entry = (key, slot);
        let (cancel_tx, cancel_rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock();
            if pending.contains_key(&entry) {
                // A hold is already running for this slot; keep it, so a redundant
                // drop signal cannot push the decision further out.
                return;
            }
            pending.insert(entry.clone(), cancel_tx);
        }
        let pending = Arc::clone(&self.pending);
        let grace = self.grace;
        tokio::spawn(async move {
            tokio::select! {
                () = tokio::time::sleep(grace) => {
                    // The hold elapsed: remove our own entry (so a later drop for
                    // this slot can arm afresh) and decide. Removing under the lock
                    // before deciding means a concurrent `cancel` either already
                    // won (our entry is gone, `remove` is a no-op) or loses (it runs
                    // after and finds nothing) — either way the decision is
                    // idempotent in `decide_leave`, so a race cannot double-decide.
                    pending.lock().remove(&entry);
                    on_expire();
                }
                _ = cancel_rx => {
                    // Cancelled (a clean leave superseded this drop). The canceller
                    // already removed the entry; nothing to decide here.
                }
            }
        });
    }

    /// Cancels a pending hold for `(key, slot)`, if one is running, so a clean
    /// leave that arrived during a drop's grace proceeds immediately instead of
    /// waiting the hold out. A no-op when no hold is pending. Removing the entry
    /// drops its cancel sender, which resolves the timer task's receiver and sends
    /// it down the cancel branch.
    pub fn cancel(&self, key: &SessionKey, slot: SlotId) {
        // The map key is owned; clone the session key to look it up.
        self.pending.lock().remove(&(key.clone(), slot));
    }

    /// Whether a hold is currently running for `(key, slot)` — for tests that
    /// assert a drop armed a grace and a clean leave cancelled it.
    #[cfg(test)]
    pub fn is_pending(&self, key: &SessionKey, slot: SlotId) -> bool {
        self.pending.lock().contains_key(&(key.clone(), slot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rally_point_proto::control::TenantId;
    use rally_point_proto::ids::SessionId;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId("t".to_owned()),
            session: SessionId(1),
        }
    }

    /// A tiny real grace so the timer path can be driven with a short sleep.
    const TINY: Duration = Duration::from_millis(40);

    #[tokio::test]
    async fn a_hold_fires_its_decision_after_the_grace() {
        let grace = LeaveGrace::new(TINY);
        let fired = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fired);
        grace.arm(key(), SlotId(3), move || {
            f.fetch_add(1, Ordering::SeqCst);
        });
        // Immediately after arming, the hold is pending and nothing has decided.
        assert!(grace.is_pending(&key(), SlotId(3)));
        assert_eq!(fired.load(Ordering::SeqCst), 0);

        // Past the grace, the decision has fired exactly once and the entry cleared.
        tokio::time::sleep(TINY + Duration::from_millis(40)).await;
        assert_eq!(fired.load(Ordering::SeqCst), 1);
        assert!(!grace.is_pending(&key(), SlotId(3)));
    }

    #[tokio::test]
    async fn a_cancel_before_expiry_suppresses_the_decision() {
        let grace = LeaveGrace::new(TINY);
        let fired = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fired);
        grace.arm(key(), SlotId(3), move || {
            f.fetch_add(1, Ordering::SeqCst);
        });
        grace.cancel(&key(), SlotId(3));
        assert!(!grace.is_pending(&key(), SlotId(3)));

        // Even past the grace, the cancelled hold never decides.
        tokio::time::sleep(TINY + Duration::from_millis(40)).await;
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_duplicate_arm_keeps_the_first_hold() {
        let grace = LeaveGrace::new(TINY);
        let fired = Arc::new(AtomicUsize::new(0));
        let f1 = Arc::clone(&fired);
        grace.arm(key(), SlotId(3), move || {
            f1.fetch_add(1, Ordering::SeqCst);
        });
        // A second arm for the same slot is ignored — its closure never runs.
        let f2 = Arc::clone(&fired);
        grace.arm(key(), SlotId(3), move || {
            f2.fetch_add(10, Ordering::SeqCst);
        });
        tokio::time::sleep(TINY + Duration::from_millis(40)).await;
        assert_eq!(
            fired.load(Ordering::SeqCst),
            1,
            "only the first hold's decision fired",
        );
    }
}
