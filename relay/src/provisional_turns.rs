//! A holding pen for turns from provisionally admitted clients.
//!
//! A valid token is deliberately admitted before any descriptor names its
//! session (the descriptor push races the first dials, and a re-homed group
//! can dial its replacement relay before the resumed descriptor lands there).
//! Provisional admission itself is safe — the bounded-admission sweep reaps a
//! session no descriptor ever claims — but provisional *turn fan-out* is not:
//! a resumed descriptor can reveal, after the fact, that one of the dialing
//! slots had already departed with an exact final turn count. Any turn that
//! slot originated past the count and any co-admitted survivor consumed
//! before the reveal is a turn beyond the leave's synchronization point —
//! the consumer diverges from every client that applies the leave at the
//! count. The pre-descriptor window is exactly when the relay cannot yet
//! tell a current slot from a departed one, so nothing originated in it may
//! reach another client until a descriptor proves the slot current.
//!
//! The pen closes that window without refusing anything: while a session has
//! no decision-maker (no descriptor has ever named it here), the turn funnel
//! deposits client turns here instead of fanning them out. Descriptor
//! application then drains the pen through the ordinary forward path — where
//! the freshly seeded decided leaves fence a departed slot's turns into the
//! void, and every current slot's turns flow exactly as if they had arrived a
//! moment later. A session that never gets a descriptor is reaped by the
//! provisional sweep and its pen entries discarded with it.
//!
//! Enabled only on a coordinator-managed relay (`main.rs` wiring): a
//! standalone dev/loopback relay has no descriptor source, so holding turns
//! there would starve sessions that legitimately never see one.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::Payload;

use crate::routing::SessionKey;

/// The most held turns one session may accumulate. The window a pen entry
/// lives is the descriptor-push delivery gap — milliseconds ordinarily,
/// seconds under control-plane lag, and never past the provisional sweep's
/// deadline — so this bounds a malicious or runaway provisional client, not a
/// healthy session. At the cap the newest turn is dropped (with a warning):
/// the oldest turns are the ones a later consumer needs first for in-order
/// consumption, so they are the ones worth keeping.
const PER_SESSION_CAP: usize = 1024;

/// The relay-wide pen. Cheaply cloneable (`Arc` inside); the turn funnel,
/// descriptor application, and session teardown must all hold the same
/// instance or the hold means nothing.
#[derive(Clone, Default)]
pub struct ProvisionalTurnPen {
    inner: Arc<PenInner>,
}

#[derive(Default)]
struct PenInner {
    /// Whether the relay is coordinator-managed — armed once at startup.
    /// Disarmed (the default, and every test constructor's state), `hold`
    /// refuses everything and the funnel fans out exactly as before.
    armed: AtomicBool,
    pending: Mutex<HashMap<SessionKey, VecDeque<(SlotId, Payload)>>>,
}

impl ProvisionalTurnPen {
    /// Arms the pen — the relay is coordinator-managed, so every session's
    /// descriptor is expected and pre-descriptor turns must be held. Called
    /// once at startup wiring; there is deliberately no disarm.
    pub fn arm(&self) {
        self.inner.armed.store(true, Ordering::Relaxed);
    }

    /// Whether the pen is armed. The turn funnel checks this before paying
    /// for the maker-existence lookup, so a disarmed relay's hot path costs
    /// one relaxed load.
    pub fn armed(&self) -> bool {
        self.inner.armed.load(Ordering::Relaxed)
    }

    /// Deposits one provisional turn. At the per-session cap the turn is
    /// dropped instead, with a warning — see [`PER_SESSION_CAP`].
    pub fn hold(&self, key: &SessionKey, slot: SlotId, payload: Payload) {
        let mut pending = self.inner.pending.lock();
        let queue = pending.entry(key.clone()).or_default();
        if queue.len() >= PER_SESSION_CAP {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                seq = payload.seq,
                cap = PER_SESSION_CAP,
                "provisional turn pen is full; dropping the newest turn",
            );
            return;
        }
        queue.push_back((slot, payload));
    }

    /// Takes every held turn for `key`, in arrival order, leaving the pen
    /// empty for the session. Called at descriptor application to drain the
    /// pen through the ordinary forward path.
    #[must_use]
    pub fn take(&self, key: &SessionKey) -> Vec<(SlotId, Payload)> {
        self.inner
            .pending
            .lock()
            .remove(key)
            .map(Vec::from)
            .unwrap_or_default()
    }

    /// Discards `key`'s held turns outright — the session ended (reaped,
    /// emptied, or retired) without a descriptor ever draining them.
    pub fn discard(&self, key: &SessionKey) {
        self.inner.pending.lock().remove(key);
    }

    #[cfg(test)]
    pub(crate) fn held(&self, key: &SessionKey) -> usize {
        self.inner.pending.lock().get(key).map_or(0, VecDeque::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rally_point_proto::control::TenantId;
    use rally_point_proto::ids::SessionId;

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId("sb-test".to_owned()),
            session: SessionId(7),
        }
    }

    fn turn(seq: u64) -> Payload {
        Payload {
            seq,
            slot: 1,
            commands: vec![0x05].into(),
            ..Default::default()
        }
    }

    #[test]
    fn held_turns_come_back_in_arrival_order_and_only_once() {
        let pen = ProvisionalTurnPen::default();
        pen.hold(&key(), SlotId(1), turn(0));
        pen.hold(&key(), SlotId(2), turn(0));
        pen.hold(&key(), SlotId(1), turn(1));

        let drained = pen.take(&key());
        let order: Vec<(u8, u64)> = drained.iter().map(|(s, p)| (s.0, p.seq)).collect();
        assert_eq!(order, vec![(1, 0), (2, 0), (1, 1)]);
        assert!(pen.take(&key()).is_empty(), "a drain empties the pen");
    }

    #[test]
    fn the_cap_drops_the_newest_turn() {
        let pen = ProvisionalTurnPen::default();
        for seq in 0..(PER_SESSION_CAP as u64 + 5) {
            pen.hold(&key(), SlotId(1), turn(seq));
        }
        let drained = pen.take(&key());
        assert_eq!(drained.len(), PER_SESSION_CAP);
        assert_eq!(
            drained.last().unwrap().1.seq,
            PER_SESSION_CAP as u64 - 1,
            "the oldest turns are the ones kept",
        );
    }

    #[test]
    fn discard_forgets_the_session() {
        let pen = ProvisionalTurnPen::default();
        pen.hold(&key(), SlotId(1), turn(0));
        pen.discard(&key());
        assert!(pen.take(&key()).is_empty());
    }

    #[test]
    fn arming_is_relay_wide_across_clones() {
        let pen = ProvisionalTurnPen::default();
        let clone = pen.clone();
        assert!(!clone.armed());
        pen.arm();
        assert!(clone.armed(), "the armed flag is shared, not per-clone");
    }
}
