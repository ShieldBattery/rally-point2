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
//! its own turns drained ahead of it).
//!
//! **The journal is append-only until drained or expired.** Journaled turns
//! are transport-acknowledged, the provisional reap's close is documented as
//! retryable, and a same-relay resume deliberately does not re-inject
//! acknowledged retention — so any path that deleted an undrained journal
//! while a still-valid token could redial the session would silently hole an
//! accepted sequence. Nothing therefore discards undrained entries: not the
//! sweep's reap (links close, the journal stays for the redial and the
//! descriptor), not the emptied-session close (which removes only a provably
//! empty journal, atomically — [`discard_if_empty`]
//! (ProvisionalTurnPen::discard_if_empty)). The two terminal owners are
//! descriptor retirement (the session's real end) and the stale prune
//! ([`prune_stale`](ProvisionalTurnPen::prune_stale)), which fires only once
//! the fleet's token ceiling has fully elapsed — past it, no client can
//! return for what the journal holds.
//!
//! **The drain is a one-shot state machine, not a sweep.** A session moves
//! Gathering → Draining → Resolved, all under the journal's own lock.
//! Depositors that find `Resolved` refuse, and their caller re-runs against
//! the maker that provably exists by then; deposits landing mid-`Draining`
//! are journaled and replayed by the drain's own loop, so a clean-leave
//! intent racing the replay still orders AFTER the slot's in-flight turns —
//! its count is derived over all of them, and nothing is ever announced
//! ahead of turns it should have counted. Only the drain's atomic
//! empty-check flips a session to `Resolved`. The state then lives until
//! descriptor retirement discards it (the reap never touches the journal,
//! and the emptied-session close removes only a provably empty one — see
//! the retention rule above).
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

/// The most journaled TURNS one session may accumulate. Sized to cover the
/// provisional window at worst-case turn traffic (a full lobby at game turn
/// rate for the sweep's whole deadline) with room to spare; a slot that
/// genuinely exceeds it is sealed and its link closed rather than its
/// accepted sequence silently holed — see the module doc's overflow policy.
pub(crate) const PER_SESSION_CAP: usize = 4096;

/// How long an undrained journal is retained waiting for its descriptor
/// before the stale prune may remove it: the fleet's token-lifetime ceiling
/// plus margin — the same credential bound the retired-session tombstone
/// uses, because the same invariant is at stake: once no token minted for
/// the session can still be valid, no client can redial for what the
/// journal holds, and only then is dropping acknowledged entries safe.
pub const JOURNAL_STALE_TTL: std::time::Duration = std::time::Duration::from_secs(
    rally_point_proto::control::MAX_PLAYER_TOKEN_LIFETIME_SECS + 60 * 60,
);

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
    ///
    /// `revision` is stamped by [`hold`](ProvisionalTurnPen::hold) (deposit
    /// callers pass `0`): each slot's newest journaled departure supersedes
    /// every older one, and an older one may already sit in a drain's
    /// private in-flight batch where the queue compaction cannot reach it —
    /// so the drain validates each departure's revision against the slot's
    /// current one ([`departure_is_current`]
    /// (ProvisionalTurnPen::departure_is_current)) and skips a superseded
    /// entry instead of replaying it. Without this, a superseded old-epoch
    /// drop replayed after a newer clean leave's teardown would install its
    /// stale generation first and have the real departure rejected as stale
    /// by the epoch fence.
    Departure {
        slot: SlotId,
        reason: u32,
        connection_epoch: Option<u64>,
        revision: u64,
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
    /// When this journal state was first created — the basis for the stale
    /// prune (see [`ProvisionalTurnPen::prune_stale`]): a journal is
    /// append-only until a descriptor drains it, and the prune is the ONLY
    /// path that may remove undrained entries, once no token that could
    /// still redial the session can remain valid.
    created_at: std::time::Instant,
    phase: Phase,
    /// Slots terminal to admission: a journaled CLEAN leave (the intent is
    /// final the moment the client sent it, exactly as a maker's decided
    /// leave would be — the same token must not redial into the
    /// pre-descriptor window, slip past the journal once the maker appears,
    /// and race the drained leave's count), or a journal OVERFLOW (the
    /// slot's accepted sequence has a permanent, unrecoverable hole — a
    /// reconnect would resume past it and cement the divergence). Never
    /// removed while the session's journal state lives (a drained decided
    /// leave takes over clean-leave refusal; an overflowed slot stays
    /// refused for the session's life).
    sealed: std::collections::HashSet<SlotId>,
    /// Each slot's current departure revision — the supersession token the
    /// drain validates before replaying a journaled departure (see
    /// [`PennedIngress::Departure`]'s `revision`).
    departure_revisions: HashMap<SlotId, u64>,
}

impl SessionPen {
    fn gathering() -> Self {
        SessionPen {
            created_at: std::time::Instant::now(),
            phase: Phase::Gathering(VecDeque::new()),
            sealed: std::collections::HashSet::new(),
            departure_revisions: HashMap::new(),
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
    pub fn hold(&self, key: &SessionKey, mut entry: PennedIngress) -> HoldOutcome {
        let mut sessions = self.inner.sessions.lock();
        let pen = sessions
            .entry(key.clone())
            .or_insert_with(SessionPen::gathering);
        let queue = match &mut pen.phase {
            Phase::Resolved => return HoldOutcome::Resolved(entry),
            Phase::Gathering(queue) | Phase::Draining(queue) => queue,
        };
        if let PennedIngress::Turn(slot, _) = &entry
            && queue.len() >= PER_SESSION_CAP
        {
            // Seal HERE, atomically with the overflow verdict and under the
            // caller's ingress gate: the overflowed slot's accepted
            // sequence has a permanent hole, so it must never be
            // readmitted. Sealing from the caller after the gate released
            // would race a retirement's terminal discard and recreate
            // journal state for an ended session.
            pen.sealed.insert(*slot);
            return HoldOutcome::Overflow(entry);
        }
        if let PennedIngress::Departure {
            slot,
            reason,
            revision,
            ..
        } = &mut entry
        {
            if *reason == crate::consensus::LEAVE_REASON_LEFT {
                pen.sealed.insert(*slot);
            }
            // At most one journaled departure per slot — an ENFORCED
            // invariant, not an assumption: only clean leaves seal, so a
            // maker-less slot can otherwise connect-and-drop in a loop
            // (its own valid token) and grow the cap-exempt departure
            // population without bound. The newest observation supersedes
            // the older one twice over: it is compacted out of the queue,
            // and its revision goes stale — which is what a drain's private
            // in-flight batch (beyond the compaction's reach) validates
            // before replaying.
            let current = pen.departure_revisions.entry(*slot).or_insert(0);
            *current += 1;
            *revision = *current;
            let slot = *slot;
            queue.retain(
                |queued| !matches!(queued, PennedIngress::Departure { slot: s, .. } if *s == slot),
            );
        }
        queue.push_back(entry);
        HoldOutcome::Held
    }

    /// Whether a journaled departure's `revision` is still the slot's
    /// current one — the drain's pre-replay validation: a departure
    /// superseded while it sat in the drain's private batch is skipped, not
    /// replayed, so a stale old-generation drop can never install itself
    /// ahead of the newer departure that superseded it.
    pub fn departure_is_current(&self, key: &SessionKey, slot: SlotId, revision: u64) -> bool {
        self.inner
            .sessions
            .lock()
            .get(key)
            .is_some_and(|pen| pen.departure_revisions.get(&slot) == Some(&revision))
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

    /// Whether `key` has journaled entries still awaiting a drain.
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

    /// Atomically discards `key`'s journal state IF it holds nothing — an
    /// empty, un-drained `Gathering` — returning whether it did. The
    /// emptied-session close uses this so its "nothing to keep" verdict and
    /// the removal are one step: a deposit racing the close either lands
    /// first (the discard refuses, the journal is retained) or lands after
    /// (recreating a fresh journal the stale prune eventually owns) — never
    /// into the void between a check and a separate removal. A `Draining`
    /// journal always refuses: an active drain owns the pen, and removing it
    /// would reset the departure revisions a drainer's private batch is
    /// validated against (the ABA the revisions exist to prevent).
    #[must_use]
    pub fn discard_if_empty(&self, key: &SessionKey) -> bool {
        let mut sessions = self.inner.sessions.lock();
        match sessions.get(key) {
            None => true,
            Some(pen) => match &pen.phase {
                Phase::Gathering(queue) if queue.is_empty() => {
                    sessions.remove(key);
                    true
                }
                _ => false,
            },
        }
    }

    /// Removes every journal that has waited longer than `ttl` for a
    /// descriptor that never came, sparing sessions `spare` claims. Returns
    /// the pruned keys so the caller can drop their session gates alongside.
    ///
    /// This is the journal's ONE terminal janitor, and `spare` carries half
    /// its proof obligation. Everything else retains: journaled entries are
    /// transport-acknowledged, a same-relay resume deliberately does not
    /// re-inject acknowledged retention, and the provisional reap's close is
    /// documented as retryable — so a journal may only be dropped when the
    /// session is provably terminal. `ttl` (the fleet token ceiling) proves
    /// no NEW link can ever be admitted; it proves nothing about links that
    /// never died, since token expiry is checked only at the handshake and a
    /// kept-alive connection outlives it freely. The caller's `spare` must
    /// therefore claim, at minimum, every session with a live roster link
    /// (a depositor may still be running) and every session with a maker
    /// (the descriptor came; retirement owns its cleanup). Active drains
    /// are spared like `Draining` everywhere else; `Resolved` journals
    /// belong to served sessions and are cleaned at retirement.
    #[must_use]
    pub fn prune_stale(
        &self,
        ttl: std::time::Duration,
        spare: impl Fn(&SessionKey) -> bool,
    ) -> Vec<SessionKey> {
        let now = std::time::Instant::now();
        let mut pruned = Vec::new();
        self.inner.sessions.lock().retain(|key, pen| {
            let expired = matches!(pen.phase, Phase::Gathering(_))
                && now.duration_since(pen.created_at) >= ttl
                && !spare(key);
            if expired {
                pruned.push(key.clone());
            }
            !expired
        });
        pruned
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
            revision: 0,
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
                ..
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

    /// At most one journaled departure per slot, as an enforced invariant: a
    /// maker-less slot connect-and-dropping in a loop must not grow the
    /// cap-exempt departure population without bound — the newest
    /// observation supersedes the older one, in the newer position, and the
    /// older one's revision goes stale.
    #[test]
    fn repeated_departures_for_one_slot_compact_to_the_newest() {
        let pen = ProvisionalTurnPen::default();
        assert_eq!(pen.hold(&key(), departure(1, 3)), HoldOutcome::Held);
        assert_eq!(pen.hold(&key(), turn(2, 0)), HoldOutcome::Held);
        assert_eq!(
            pen.hold(
                &key(),
                PennedIngress::Departure {
                    slot: SlotId(1),
                    reason: 3,
                    connection_epoch: Some(11),
                    revision: 0,
                },
            ),
            HoldOutcome::Held,
        );
        let drained = pen.begin_drain(&key()).expect("claims");
        assert_eq!(drained.len(), 2, "the older departure was superseded");
        assert!(matches!(drained[0], PennedIngress::Turn(SlotId(2), _)));
        assert!(matches!(
            drained[1],
            PennedIngress::Departure {
                slot: SlotId(1),
                connection_epoch: Some(11),
                revision: 2,
                ..
            }
        ));
    }

    /// A departure superseded while it sat in a drain's private in-flight
    /// batch — beyond the queue compaction's reach — fails the revision
    /// validation the drain runs before replaying it, while the superseding
    /// entry passes.
    #[test]
    fn a_superseded_departure_in_an_active_batch_fails_revision_validation() {
        let pen = ProvisionalTurnPen::default();
        assert_eq!(pen.hold(&key(), departure(1, 3)), HoldOutcome::Held);
        let batch = pen.begin_drain(&key()).expect("claims");
        let PennedIngress::Departure { revision: old, .. } = batch[0] else {
            panic!("the batch holds the journaled departure");
        };
        assert!(pen.departure_is_current(&key(), SlotId(1), old));

        // A newer generation's departure lands mid-drain.
        assert_eq!(
            pen.hold(&key(), departure(1, crate::consensus::LEAVE_REASON_LEFT)),
            HoldOutcome::Held,
        );
        assert!(
            !pen.departure_is_current(&key(), SlotId(1), old),
            "the batched departure is superseded and must not replay",
        );
        match pen.continue_drain(&key()) {
            DrainStep::More(next) => {
                let PennedIngress::Departure { revision, .. } = next[0] else {
                    panic!("the superseding departure drains next");
                };
                assert!(pen.departure_is_current(&key(), SlotId(1), revision));
            }
            DrainStep::Done => panic!("the superseding departure must drain"),
        }
    }

    /// Overflow seals the offending slot atomically with the verdict —
    /// installed by `hold` itself, under the caller's ingress gate, never as
    /// a separate post-gate step a retirement could interleave with.
    #[test]
    fn overflow_seals_the_slot_atomically_with_the_verdict() {
        let pen = ProvisionalTurnPen::default();
        for seq in 0..PER_SESSION_CAP as u64 {
            assert_eq!(pen.hold(&key(), turn(1, seq)), HoldOutcome::Held);
        }
        assert!(!pen.slot_sealed(&key(), SlotId(1)));
        assert!(matches!(
            pen.hold(&key(), turn(1, PER_SESSION_CAP as u64)),
            HoldOutcome::Overflow(_),
        ));
        assert!(pen.slot_sealed(&key(), SlotId(1)));
        assert!(
            !pen.slot_sealed(&key(), SlotId(2)),
            "only the overflowing slot is sealed",
        );
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

    /// `discard_if_empty` is the emptied close's atomic check-and-remove: it
    /// removes only a provably empty Gathering journal, refuses one holding
    /// entries, and refuses a Draining journal outright — an active drain
    /// owns the pen, and removing it would reset the revisions a drainer's
    /// private batch is validated against.
    #[test]
    fn discard_if_empty_removes_only_an_empty_gathering_journal() {
        let pen = ProvisionalTurnPen::default();
        assert!(pen.discard_if_empty(&key()), "an absent journal is empty");

        assert_eq!(pen.hold(&key(), turn(1, 0)), HoldOutcome::Held);
        assert!(!pen.discard_if_empty(&key()), "entries refuse the discard");

        let batch = pen.begin_drain(&key()).expect("claims");
        assert_eq!(batch.len(), 1);
        assert!(
            !pen.discard_if_empty(&key()),
            "a draining journal refuses even with an empty queue — the drain owns it",
        );
        assert!(matches!(pen.continue_drain(&key()), DrainStep::Done));
        assert!(
            !pen.discard_if_empty(&key()),
            "a resolved journal belongs to the session lifecycle, not the close",
        );
    }

    /// The stale prune removes only maker-less Gathering journals past the
    /// TTL — the one terminal janitor for a descriptor that never came.
    #[test]
    fn prune_stale_removes_only_expired_makerless_gathering_journals() {
        let pen = ProvisionalTurnPen::default();
        let stale = key();
        let described = SessionKey {
            tenant: rally_point_proto::control::TenantId("sb-test".to_owned()),
            session: SessionId(8),
        };
        let draining = SessionKey {
            tenant: rally_point_proto::control::TenantId("sb-test".to_owned()),
            session: SessionId(9),
        };
        assert_eq!(pen.hold(&stale, turn(1, 0)), HoldOutcome::Held);
        assert_eq!(pen.hold(&described, turn(1, 0)), HoldOutcome::Held);
        assert_eq!(pen.hold(&draining, turn(1, 0)), HoldOutcome::Held);
        let _ = pen.begin_drain(&draining).expect("claims");

        // A zero TTL makes every journal ripe; only the unclaimed,
        // maker-less Gathering one may go.
        let pruned = pen.prune_stale(std::time::Duration::ZERO, |k| *k == described);
        assert_eq!(pruned, vec![stale.clone()]);
        assert_eq!(pen.held(&stale), 0);
        assert_eq!(pen.held(&described), 1, "a maker spares the journal");
        // The draining journal's queue is empty (its entry sits in this
        // test's private batch), so probe the retained CLAIM instead of the
        // queue: a pruned key would hand a fresh drain out; the spared one
        // still refuses because the original drain owns it.
        assert!(
            pen.begin_drain(&draining).is_none(),
            "an active drain spares the journal — the claim survives the prune",
        );
        match pen.continue_drain(&draining) {
            DrainStep::Done => {}
            DrainStep::More(_) => panic!("nothing further was deposited mid-drain"),
        }

        // A generous TTL prunes nothing.
        assert!(
            pen.prune_stale(std::time::Duration::from_secs(3600), |_| false)
                .is_empty(),
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
