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
//! **The drain is a one-shot state machine, not a sweep.** A session moves
//! Gathering → Draining → Resolved, all under the journal's own lock.
//! Depositors that find `Resolved` refuse, and their caller re-runs against
//! the maker that provably exists by then; deposits landing mid-`Draining`
//! are journaled and replayed by the drain's own loop, so a clean-leave
//! intent racing the replay still orders AFTER the slot's in-flight turns —
//! its count is derived over all of them, and nothing is ever announced
//! ahead of turns it should have counted. Only the drain's atomic
//! empty-check flips a session to `Resolved`. The state lives until the
//! session ends (retirement, the reap, or the emptied-session close of a
//! drained journal discards it).
//!
//! **A journaled clean leave seals its slot.** The intent is terminal the
//! moment the client sent it, exactly as a maker's decided leave would be —
//! so admission refuses the slot from the deposit onward, and the same
//! token cannot redial into the pre-descriptor window and race the drained
//! leave's count with a fresh generation.
//!
//! **Overflow fails the offender closed.** Every journaled turn was already
//! acknowledged at the transport layer, and a same-relay resume deliberately
//! does not re-inject acknowledged retention — so an overflowed turn is
//! genuinely unrecoverable, and the only sound response is to stop the
//! slot that produced it: the funnel closes the offending slot's link, whose
//! teardown journals an ordinary dropped departure the survivors then
//! resolve through the drop flow. Departures themselves are cap-exempt
//! (at most one per slot), so no departure is ever lost to overflow.
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
pub(crate) const PER_SESSION_CAP: usize = 4096;

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
    /// fails the offending slot closed (its link is closed and its teardown
    /// journals a cap-exempt dropped departure) rather than silently holing
    /// an acknowledged sequence. Only turns overflow — departures are
    /// cap-exempt.
    Overflow(PennedIngress),
}

/// One session's journal state — see the module doc's one-shot drain.
///
/// `Draining` is the replay-in-progress phase: the drainer took a batch, but
/// deposits that land while it replays must still be journaled (a clean-leave
/// intent arriving mid-drain must order AFTER the slot's in-flight turns, or
/// its count snapshot would be blind to them). The drainer loops —
/// re-checking under the lock — until the queue is empty, and only that
/// empty check flips the state to `Resolved`.
enum Phase {
    Gathering(VecDeque<PennedIngress>),
    Draining(VecDeque<PennedIngress>),
    Resolved,
}

struct SessionPen {
    phase: Phase,
    /// Slots whose CLEAN leave was journaled — terminal to admission from
    /// the moment of the intent, exactly as a maker's decided leave would
    /// be: the same token must not redial into the pre-descriptor window,
    /// slip past the journal once the maker appears, and race the drained
    /// leave's count. Never removed while the session's journal state lives
    /// (by then the drained decided leave has taken over refusal).
    sealed: std::collections::HashSet<SlotId>,
}

impl SessionPen {
    fn gathering() -> Self {
        SessionPen {
            phase: Phase::Gathering(VecDeque::new()),
            sealed: std::collections::HashSet::new(),
        }
    }
}

/// One step of the drain loop — see [`ProvisionalTurnPen::continue_drain`].
pub enum DrainStep {
    /// Deposits landed during the replay; replay these too, then ask again.
    More(Vec<PennedIngress>),
    /// The queue was empty: the session is now `Resolved` and the drain is
    /// complete.
    Done,
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

    /// Deposits one ingress effect — unless the session was already fully
    /// drained ([`Resolved`](HoldOutcome::Resolved), the caller's cue to
    /// re-run its ordinary path against the maker that now exists) or the
    /// journal is full ([`Overflow`](HoldOutcome::Overflow), the caller's
    /// cue to fail the offender closed). A deposit landing mid-drain is
    /// journaled and replayed by the drain loop's next pass, so it stays
    /// ordered behind everything already in flight.
    ///
    /// A [`Departure`](PennedIngress::Departure) is exempt from the cap —
    /// there is at most one per slot, losing one strands the session on an
    /// expected-but-absent slot, and exempting a slot-bounded entry kind
    /// keeps memory bounded regardless. A clean-leave departure also seals
    /// its slot against readmission (see [`slot_sealed`](Self::slot_sealed)).
    #[must_use]
    pub fn hold(&self, key: &SessionKey, entry: PennedIngress) -> HoldOutcome {
        let mut sessions = self.inner.sessions.lock();
        let pen = sessions
            .entry(key.clone())
            .or_insert_with(SessionPen::gathering);
        let queue = match &mut pen.phase {
            Phase::Resolved => return HoldOutcome::Resolved(entry),
            Phase::Gathering(queue) | Phase::Draining(queue) => queue,
        };
        if matches!(entry, PennedIngress::Turn(..)) && queue.len() >= PER_SESSION_CAP {
            return HoldOutcome::Overflow(entry);
        }
        if let PennedIngress::Departure { slot, reason, .. } = &entry
            && *reason == crate::consensus::LEAVE_REASON_LEFT
        {
            pen.sealed.insert(*slot);
        }
        queue.push_back(entry);
        HoldOutcome::Held
    }

    /// Whether `slot` had a clean leave journaled — terminal to admission
    /// until the drained decided leave takes refusal over. Checked at client
    /// admission on a coordinator-managed relay; survives the whole
    /// Gathering → Draining → Resolved life of the journal state.
    pub fn slot_sealed(&self, key: &SessionKey, slot: SlotId) -> bool {
        self.inner
            .sessions
            .lock()
            .get(key)
            .is_some_and(|pen| pen.sealed.contains(&slot))
    }

    /// Begins the one-shot drain: takes the gathered batch and moves the
    /// session to `Draining`. Returns `None` when another drain is already
    /// in progress or the session is already `Resolved` (an idempotent
    /// descriptor replay) — a deposit racing an active drain is picked up by
    /// that drain's own [`continue_drain`](Self::continue_drain) loop.
    /// Called at descriptor application whether or not anything was
    /// journaled, so every covered session ends the call `Resolved`.
    #[must_use]
    pub fn begin_drain(&self, key: &SessionKey) -> Option<Vec<PennedIngress>> {
        let mut sessions = self.inner.sessions.lock();
        let pen = sessions
            .entry(key.clone())
            .or_insert_with(SessionPen::gathering);
        match &mut pen.phase {
            Phase::Gathering(queue) => {
                let batch = std::mem::take(queue);
                pen.phase = Phase::Draining(VecDeque::new());
                Some(batch.into())
            }
            Phase::Draining(_) | Phase::Resolved => None,
        }
    }

    /// One step of the drain loop: under the journal lock, either hands back
    /// the deposits that landed during the previous replay pass, or — only
    /// when the queue is empty — flips the session to `Resolved` and ends
    /// the drain. The empty-check and the flip are one atomic step, so no
    /// deposit can land between "queue looked empty" and "session resolved".
    #[must_use]
    pub fn continue_drain(&self, key: &SessionKey) -> DrainStep {
        let mut sessions = self.inner.sessions.lock();
        let Some(pen) = sessions.get_mut(key) else {
            // Discarded mid-drain (retirement/reap): nothing left to replay.
            return DrainStep::Done;
        };
        match &mut pen.phase {
            Phase::Draining(queue) if queue.is_empty() => {
                pen.phase = Phase::Resolved;
                DrainStep::Done
            }
            Phase::Draining(queue) => DrainStep::More(std::mem::take(queue).into()),
            // Not draining (discard + fresh deposits recreated Gathering, or
            // already resolved): this drainer's claim is gone either way.
            Phase::Gathering(_) | Phase::Resolved => DrainStep::Done,
        }
    }

    /// Drops `key`'s journal state outright — gathered entries, seals, and
    /// the resolved mark alike. The session ended (reaped, emptied, or
    /// retired); a later dial for the id starts a genuinely fresh journal.
    pub fn discard(&self, key: &SessionKey) {
        self.inner.sessions.lock().remove(key);
    }

    /// Whether `key` has journaled entries still awaiting a drain — read by
    /// the emptied-session close to keep the journal (and the session's
    /// gate) alive for the descriptor that will drain it, instead of
    /// discarding the only record of what happened pre-descriptor.
    pub fn has_undrained(&self, key: &SessionKey) -> bool {
        self.inner
            .sessions
            .lock()
            .get(key)
            .is_some_and(|pen| match &pen.phase {
                Phase::Gathering(queue) | Phase::Draining(queue) => !queue.is_empty(),
                Phase::Resolved => false,
            })
    }

    #[cfg(test)]
    pub(crate) fn held(&self, key: &SessionKey) -> usize {
        match self.inner.sessions.lock().get(key).map(|pen| &pen.phase) {
            Some(Phase::Gathering(queue)) | Some(Phase::Draining(queue)) => queue.len(),
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

    fn departure(slot: u8, reason: u32) -> PennedIngress {
        PennedIngress::Departure {
            slot: SlotId(slot),
            reason,
            connection_epoch: Some(9),
        }
    }

    #[test]
    fn entries_drain_in_arrival_order_and_only_once() {
        let pen = ProvisionalTurnPen::default();
        assert_eq!(pen.hold(&key(), turn(1, 0)), HoldOutcome::Held);
        assert_eq!(pen.hold(&key(), departure(1, 3)), HoldOutcome::Held);
        assert_eq!(pen.hold(&key(), turn(2, 0)), HoldOutcome::Held);

        let drained = pen.begin_drain(&key()).expect("the first drain claims");
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
        assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
        assert!(
            pen.begin_drain(&key()).is_none(),
            "a resolved session refuses a second drain",
        );
    }

    /// The one-shot transition: a deposit that lost the race against the
    /// drain is refused, so its caller re-runs against the maker the drain
    /// proves exists — never inserting past the completed drain.
    #[test]
    fn a_deposit_after_the_drain_is_refused_as_resolved() {
        let pen = ProvisionalTurnPen::default();
        let batch = pen
            .begin_drain(&key())
            .expect("the drain claims even a never-deposited session");
        assert!(batch.is_empty());
        assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
        assert!(matches!(
            pen.hold(&key(), turn(1, 0)),
            HoldOutcome::Resolved(PennedIngress::Turn(SlotId(1), _)),
        ));
        assert_eq!(pen.held(&key()), 0, "a refused deposit journals nothing");
    }

    /// A deposit landing mid-drain is journaled and handed to the drain's
    /// own next pass, ordered after everything already replayed — never
    /// announced ahead of the in-flight batch, never stranded after it.
    #[test]
    fn a_mid_drain_deposit_is_replayed_by_the_drain_loop() {
        let pen = ProvisionalTurnPen::default();
        assert_eq!(pen.hold(&key(), turn(1, 0)), HoldOutcome::Held);
        let first = pen.begin_drain(&key()).expect("claims");
        assert_eq!(first.len(), 1);

        // The clean-leave intent lands while the drainer replays.
        assert_eq!(pen.hold(&key(), departure(1, 3)), HoldOutcome::Held);
        match pen.continue_drain(&key()) {
            DrainStep::More(batch) => {
                assert_eq!(batch.len(), 1);
                assert!(matches!(batch[0], PennedIngress::Departure { .. }));
            }
            DrainStep::Done => panic!("the mid-drain deposit must be replayed"),
        }
        assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
    }

    /// A journaled clean leave seals its slot against readmission, and the
    /// seal survives the whole drain.
    #[test]
    fn a_clean_leave_seals_its_slot_across_the_drain() {
        let pen = ProvisionalTurnPen::default();
        assert!(!pen.slot_sealed(&key(), SlotId(1)));
        assert_eq!(
            pen.hold(&key(), departure(1, crate::consensus::LEAVE_REASON_LEFT)),
            HoldOutcome::Held,
        );
        assert!(pen.slot_sealed(&key(), SlotId(1)));

        let _ = pen.begin_drain(&key()).expect("claims");
        assert!(pen.slot_sealed(&key(), SlotId(1)), "sealed while draining");
        assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
        assert!(pen.slot_sealed(&key(), SlotId(1)), "sealed once resolved");

        pen.discard(&key());
        assert!(!pen.slot_sealed(&key(), SlotId(1)));
    }

    #[test]
    fn overflow_refuses_turns_but_never_departures() {
        let pen = ProvisionalTurnPen::default();
        for seq in 0..PER_SESSION_CAP as u64 {
            assert_eq!(pen.hold(&key(), turn(1, seq)), HoldOutcome::Held);
        }
        assert!(matches!(
            pen.hold(&key(), turn(1, PER_SESSION_CAP as u64)),
            HoldOutcome::Overflow(_),
        ));
        assert_eq!(
            pen.hold(&key(), departure(1, 3)),
            HoldOutcome::Held,
            "a departure is never lost to the cap",
        );
        assert_eq!(pen.held(&key()), PER_SESSION_CAP + 1);
    }

    #[test]
    fn discard_forgets_entries_and_the_resolved_mark() {
        let pen = ProvisionalTurnPen::default();
        let _ = pen.begin_drain(&key()).expect("claims");
        assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
        pen.discard(&key());
        assert_eq!(
            pen.hold(&key(), turn(1, 0)),
            HoldOutcome::Held,
            "a discarded session's later dial starts a fresh journal",
        );
    }

    #[test]
    fn has_undrained_tracks_pending_entries() {
        let pen = ProvisionalTurnPen::default();
        assert!(!pen.has_undrained(&key()));
        assert_eq!(pen.hold(&key(), turn(1, 0)), HoldOutcome::Held);
        assert!(pen.has_undrained(&key()));
        let _ = pen.begin_drain(&key()).expect("claims");
        assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
        assert!(!pen.has_undrained(&key()));
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
