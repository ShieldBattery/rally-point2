//! A journal for ingress from provisionally admitted clients.
//!
//! A valid token is deliberately admitted before any descriptor names its
//! session (the descriptor push races the first dials, and a re-homed group
//! can dial its replacement relay before the resumed descriptor lands there).
//! Provisional admission itself is safe — the bounded-admission sweep reaps a
//! session no descriptor ever claims — but provisional *ingress effects* are
//! not, in both directions:
//!
//! - A turn fanned out pre-descriptor can turn out to belong to a slot the
//!   descriptor reveals as already departed with an exact final turn count —
//!   a turn beyond the leave's synchronization point, consumed by co-admitted
//!   survivors but by no one else.
//! - A departure announced pre-descriptor lands in a maker-less void: nothing
//!   records it, yet the announce path marks it announced, so when the
//!   descriptor arrives the slot is expected-but-absent and the session
//!   stalls on it until the coordinator's holdout reap.
//!
//! The journal closes both without refusing anything: while a session has no
//! decision-maker, the turn funnel and the departure announce deposit their
//! ingress here, in arrival order. Descriptor application then drains the
//! journal through the ordinary paths — the freshly seeded decided leaves
//! fence a departed slot's turns, a current slot's turns flow as if they had
//! arrived a moment later, and a journaled departure announces into a maker
//! that now exists (a clean leave's exact count is recomputed there, after
//! its own turns drained ahead of it). A session that never gets a descriptor
//! is reaped by the provisional sweep and its journal discarded with it.
//!
//! **The drain is a one-shot state transition, not a sweep.** Depositors
//! check maker-absence and then insert; a descriptor can create the maker
//! between the two, and its drain must not run past an entry inserted just
//! after it. So a drained session is marked *resolved* under the journal's
//! own lock: a deposit that finds the mark refuses, and its caller re-runs
//! against the maker that now provably exists. The mark lives until the
//! session ends (retirement or the emptied-session close discards it).
//!
//! **Overflow fails closed, with recovery.** Every journaled turn was already
//! acknowledged at the transport layer, so silently dropping one would leave
//! a permanent hole in an accepted sequence. Past the cap the depositor
//! instead reports overflow, and the funnel discards the journal and reaps
//! the session's provisional links: each client re-dials, and the ordinary
//! resume machinery re-supplies everything the relay never forwarded.
//!
//! Armed only on a coordinator-managed relay (`main.rs` wiring): a
//! standalone dev/loopback relay has no descriptor source, so journaling
//! there would starve sessions that legitimately never see one.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::Payload;

use crate::routing::SessionKey;

/// The most journaled entries one session may accumulate. Sized to cover the
/// provisional window at worst-case turn traffic (a full lobby at game turn
/// rate for the sweep's whole deadline) with room to spare; a session that
/// genuinely exceeds it is reaped and recovered through resume rather than
/// silently holed — see the module doc's overflow policy.
const PER_SESSION_CAP: usize = 4096;

/// One deposited ingress effect, replayed in arrival order at the drain.
#[derive(Debug, PartialEq)]
pub enum PennedIngress {
    /// A client turn the funnel would have fanned out.
    Turn(SlotId, Payload),
    /// A departure the announce path would have recorded and broadcast. The
    /// exact final turn count is deliberately NOT captured here: a clean
    /// leave's count is derived at the drain, after the slot's own journaled
    /// turns have been forwarded ahead of it — the count captured at deposit
    /// time would be blind to them.
    Departure {
        slot: SlotId,
        reason: u32,
        connection_epoch: Option<u64>,
    },
}

/// What became of a deposit attempt. The refusing variants hand the entry
/// back, so the caller can run it through its ordinary path (or drop it
/// deliberately) instead of it being silently consumed.
#[derive(Debug, PartialEq)]
pub enum HoldOutcome {
    /// Journaled; the descriptor drain will replay it.
    Held,
    /// The session was already drained — its maker provably exists now — so
    /// nothing was journaled. The caller re-runs its ordinary path with the
    /// returned entry.
    Resolved(PennedIngress),
    /// The session's journal is full. Nothing was journaled; the caller
    /// fails the session closed (discard + provisional reap) rather than
    /// silently holing an acknowledged sequence.
    Overflow(PennedIngress),
}

/// One session's journal state — see the module doc's one-shot drain.
enum SessionPen {
    Gathering(VecDeque<PennedIngress>),
    Resolved,
}

/// The relay-wide journal. Cheaply cloneable (`Arc` inside); the turn funnel,
/// the departure announce, descriptor application, and session teardown must
/// all hold the same instance or the hold means nothing.
#[derive(Clone, Default)]
pub struct ProvisionalTurnPen {
    inner: Arc<PenInner>,
}

#[derive(Default)]
struct PenInner {
    /// Whether the relay is coordinator-managed — armed once at startup.
    /// Disarmed (the default, and every test constructor's state), nothing
    /// is ever journaled and every ingress path behaves exactly as before.
    armed: AtomicBool,
    sessions: Mutex<HashMap<SessionKey, SessionPen>>,
}

impl ProvisionalTurnPen {
    /// Arms the pen — the relay is coordinator-managed, so every session's
    /// descriptor is expected and pre-descriptor ingress must be journaled.
    /// Called once at startup wiring; there is deliberately no disarm.
    pub fn arm(&self) {
        self.inner.armed.store(true, Ordering::Relaxed);
    }

    /// Whether the pen is armed. Ingress paths check this before paying for
    /// the maker-existence lookup, so a disarmed relay's hot path costs one
    /// relaxed load.
    pub fn armed(&self) -> bool {
        self.inner.armed.load(Ordering::Relaxed)
    }

    /// Deposits one ingress effect — unless the session was already drained
    /// ([`Resolved`](HoldOutcome::Resolved), the caller's cue to re-run its
    /// ordinary path against the maker that now exists) or the journal is
    /// full ([`Overflow`](HoldOutcome::Overflow), the caller's cue to fail
    /// the session closed).
    #[must_use]
    pub fn hold(&self, key: &SessionKey, entry: PennedIngress) -> HoldOutcome {
        let mut sessions = self.inner.sessions.lock();
        match sessions
            .entry(key.clone())
            .or_insert_with(|| SessionPen::Gathering(VecDeque::new()))
        {
            SessionPen::Resolved => HoldOutcome::Resolved(entry),
            SessionPen::Gathering(queue) => {
                if queue.len() >= PER_SESSION_CAP {
                    return HoldOutcome::Overflow(entry);
                }
                queue.push_back(entry);
                HoldOutcome::Held
            }
        }
    }

    /// Takes every journaled entry for `key` in arrival order and marks the
    /// session resolved — the one-shot transition: a deposit racing this
    /// drain either landed before it (and is in the returned batch) or finds
    /// the mark and refuses. Called at descriptor application, whether or
    /// not anything was journaled, so the mark is set for every session the
    /// descriptor covers.
    #[must_use]
    pub fn take_and_resolve(&self, key: &SessionKey) -> Vec<PennedIngress> {
        match self
            .inner
            .sessions
            .lock()
            .insert(key.clone(), SessionPen::Resolved)
        {
            Some(SessionPen::Gathering(queue)) => queue.into(),
            Some(SessionPen::Resolved) | None => Vec::new(),
        }
    }

    /// Drops `key`'s journal state outright — gathered entries and the
    /// resolved mark alike. The session ended (reaped, emptied, or retired);
    /// a later dial for the id starts a genuinely fresh journal.
    pub fn discard(&self, key: &SessionKey) {
        self.inner.sessions.lock().remove(key);
    }

    #[cfg(test)]
    pub(crate) fn held(&self, key: &SessionKey) -> usize {
        match self.inner.sessions.lock().get(key) {
            Some(SessionPen::Gathering(queue)) => queue.len(),
            _ => 0,
        }
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

    fn turn(slot: u8, seq: u64) -> PennedIngress {
        PennedIngress::Turn(
            SlotId(slot),
            Payload {
                seq,
                slot: u32::from(slot),
                commands: vec![0x05].into(),
                ..Default::default()
            },
        )
    }

    #[test]
    fn entries_drain_in_arrival_order_and_only_once() {
        let pen = ProvisionalTurnPen::default();
        assert_eq!(pen.hold(&key(), turn(1, 0)), HoldOutcome::Held);
        assert_eq!(
            pen.hold(
                &key(),
                PennedIngress::Departure {
                    slot: SlotId(1),
                    reason: 3,
                    connection_epoch: Some(9),
                },
            ),
            HoldOutcome::Held,
        );
        assert_eq!(pen.hold(&key(), turn(2, 0)), HoldOutcome::Held);

        let drained = pen.take_and_resolve(&key());
        assert_eq!(drained.len(), 3);
        assert!(matches!(drained[0], PennedIngress::Turn(SlotId(1), _)));
        assert!(matches!(
            drained[1],
            PennedIngress::Departure {
                slot: SlotId(1),
                reason: 3,
                connection_epoch: Some(9),
            }
        ));
        assert!(matches!(drained[2], PennedIngress::Turn(SlotId(2), _)));
        assert!(
            pen.take_and_resolve(&key()).is_empty(),
            "a drain empties the journal",
        );
    }

    /// The one-shot transition: a deposit that lost the race against the
    /// drain is refused, so its caller re-runs against the maker the drain
    /// proves exists — never inserting past the only drain.
    #[test]
    fn a_deposit_after_the_drain_is_refused_as_resolved() {
        let pen = ProvisionalTurnPen::default();
        assert!(
            pen.take_and_resolve(&key()).is_empty(),
            "the drain marks even a never-deposited session",
        );
        assert!(matches!(
            pen.hold(&key(), turn(1, 0)),
            HoldOutcome::Resolved(PennedIngress::Turn(SlotId(1), _)),
        ));
        assert_eq!(pen.held(&key()), 0, "a refused deposit journals nothing");
    }

    #[test]
    fn overflow_refuses_the_deposit_without_journaling_it() {
        let pen = ProvisionalTurnPen::default();
        for seq in 0..PER_SESSION_CAP as u64 {
            assert_eq!(pen.hold(&key(), turn(1, seq)), HoldOutcome::Held);
        }
        assert!(matches!(
            pen.hold(&key(), turn(1, PER_SESSION_CAP as u64)),
            HoldOutcome::Overflow(_),
        ));
        assert_eq!(pen.held(&key()), PER_SESSION_CAP);
    }

    #[test]
    fn discard_forgets_entries_and_the_resolved_mark() {
        let pen = ProvisionalTurnPen::default();
        let _ = pen.take_and_resolve(&key());
        pen.discard(&key());
        assert_eq!(
            pen.hold(&key(), turn(1, 0)),
            HoldOutcome::Held,
            "a discarded session's later dial starts a fresh journal",
        );
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
