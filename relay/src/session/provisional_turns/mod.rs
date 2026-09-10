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
//! **The journal is append-only until drained, and retained until the
//! session provably ends.** Journaled turns are transport-acknowledged, the
//! provisional reap's close is documented as retryable, and a same-relay
//! resume deliberately does not re-inject acknowledged retention — so any
//! path that deleted an undrained journal while the session could still
//! become real would silently hole an accepted sequence. And no LOCAL fact
//! proves it cannot: token expiry only stops new handshakes (an established
//! link outlives it on keepalives), an empty local roster says nothing
//! about peer-homed survivors who will need these turns once the descriptor
//! lands, and a coordinator outage can delay that descriptor arbitrarily.
//! Nothing therefore discards undrained entries: not the sweep's reap
//! (links close, the journal stays for the redial and the descriptor), not
//! the emptied-session close (which removes only a provably empty journal,
//! atomically — [`discard_if_empty`](ProvisionalTurnPen::discard_if_empty)).
//! The ONE terminal owner is descriptor retirement — the coordinator ending
//! the session. A journal whose session is never described OR retired is
//! deliberately retained for the relay's lifetime — every cheaper janitor
//! tried here (age TTLs, roster emptiness) turned out to delete
//! acknowledged data some interleaving still needed. Reclaiming
//! these safely needs a coordinator-confirmed session-death signal — a
//! control-plane follow-up, not a local heuristic. Until then the
//! relay-wide footprint is bounded the only safe way left: NEW data fails
//! closed instead of old data being deleted. Turn deposits fail against an
//! aggregate byte budget (`AGGREGATE_TURN_BYTE_BUDGET`) exactly like a
//! per-session overflow, and deposits that would track a NEW session fail
//! against a session ceiling (`MAX_JOURNALED_SESSIONS`) — together a
//! finite worst-case footprint, with nothing retained ever deleted to make
//! room.
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
    /// current one ([`ProvisionalTurnPen::departure_is_current`]) and skips a
    /// superseded
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
    /// The journal refused the deposit: a turn hit the per-session cap or
    /// the aggregate byte budget (the depositing slot is sealed, and the
    /// caller closes its link rather than silently holing an acknowledged
    /// sequence), or the relay-wide session ceiling refused to CREATE a
    /// tracking entry (nothing inserted at all — admission's reservation
    /// makes this unreachable for turns; a departure reaches it only
    /// through the narrow emptied-close-discard race and is dropped with a
    /// warning).
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
    /// The `(slot, seq)` of every turn in the batch a drain currently holds
    /// privately (taken by [`ProvisionalTurnPen::begin_drain`] or
    /// [`ProvisionalTurnPen::continue_drain`], not yet finished). Such a turn
    /// has left the queue but not yet passed the forward gate, so a
    /// [`held_turn_seqs`](ProvisionalTurnPen::held_turn_seqs) read during the
    /// replay must still report it — every entry here was
    /// transport-acknowledged at deposit, and a resume-seeding read that
    /// missed one would leave a permanent hole in the resumed receive window.
    in_flight_turns: Vec<(SlotId, u64)>,
}

impl SessionPen {
    fn gathering() -> Self {
        SessionPen {
            phase: Phase::Gathering(VecDeque::new()),
            sealed: std::collections::HashSet::new(),
            departure_revisions: HashMap::new(),
            in_flight_turns: Vec::new(),
        }
    }
}

/// The `(slot, seq)` identity of every turn in a drain batch, for the pen's
/// in-flight shadow.
fn turn_identities(batch: &VecDeque<PennedIngress>) -> Vec<(SlotId, u64)> {
    batch
        .iter()
        .filter_map(|entry| match entry {
            PennedIngress::Turn(slot, payload) => Some((*slot, payload.seq)),
            PennedIngress::Departure { .. } => None,
        })
        .collect()
}

/// One step of the drain loop — see [`ProvisionalTurnPen::continue_drain`].
pub enum DrainStep {
    /// Deposits landed during the replay; replay these too, then ask again.
    More(Vec<PennedIngress>),
    /// The queue was empty: the session is now `Resolved` and the drain is
    /// complete.
    Done,
}

/// The relay-wide aggregate budget for journaled TURN bytes, across every
/// session. Sessions are unbounded over a relay's lifetime and tokens are
/// not relay-bound, so per-session caps alone let repeated valid tokens grow
/// one chosen relay without limit; this is the hard relay-wide ceiling. At
/// the budget, new turn deposits fail closed exactly like a per-session
/// overflow — the offending slot is sealed and its link closed — and nothing
/// already retained is ever deleted to make room. Generous against
/// legitimate use: real journals live for a descriptor-push gap measured in
/// seconds, so even a burst of concurrent rehomes sits orders of magnitude
/// below this.
const AGGREGATE_TURN_BYTE_BUDGET: usize = 64 * 1024 * 1024;

/// The relay-wide ceiling on tracked journal sessions. The byte budget
/// bounds turns, but departures are byte-exempt and every touched session
/// key holds a map entry — so without this, unbounded session churn (tokens
/// are not relay-bound, and session ids never repeat) could still grow the
/// map a kilobyte at a time. At the ceiling a deposit for a NOT-yet-tracked
/// session is refused outright, nothing is inserted, and nothing retained is
/// deleted; a descriptor's drain still tracks its session regardless (the
/// coordinator legitimized it, and its entry is reclaimed at retirement).
/// With per-session state capped in the low tens of KiB, the ceiling puts
/// the journal's worst-case footprint near 100 MiB, finite by construction.
const MAX_JOURNALED_SESSIONS: usize = 4096;

/// The accounting size of one journaled entry: a turn's command bytes plus a
/// flat allowance for the envelope; departures (tiny, per-slot-deduped)
/// count nothing — see [`ProvisionalTurnPen::hold`] for why they are exempt.
fn entry_turn_bytes(entry: &PennedIngress) -> usize {
    match entry {
        PennedIngress::Turn(_, payload) => payload.commands.len() + 64,
        PennedIngress::Departure { .. } => 0,
    }
}

/// The relay-wide journal. Cheaply cloneable (`Arc` inside); the turn funnel,
/// the departure announce, descriptor application, and session teardown must
/// all hold the same instance or the hold means nothing.
#[derive(Clone, Default)]
pub struct ProvisionalTurnPen {
    inner: Arc<PenInner>,
}

struct PenInner {
    /// Whether the relay is coordinator-managed — armed once at startup.
    /// Disarmed (the default, and every test constructor's state), nothing
    /// is ever journaled and every ingress path behaves exactly as before.
    armed: AtomicBool,
    /// The aggregate turn-byte ceiling — [`AGGREGATE_TURN_BYTE_BUDGET`] in
    /// production; injectable so a test can drive the budget path without
    /// megabytes of fixture.
    turn_byte_budget: usize,
    /// The tracked-session ceiling — [`MAX_JOURNALED_SESSIONS`] in
    /// production; injectable for the same reason.
    max_sessions: usize,
    state: Mutex<PenState>,
}

impl Default for PenInner {
    fn default() -> Self {
        PenInner {
            armed: AtomicBool::new(false),
            turn_byte_budget: AGGREGATE_TURN_BYTE_BUDGET,
            max_sessions: MAX_JOURNALED_SESSIONS,
            state: Mutex::new(PenState::default()),
        }
    }
}

/// Everything the journal mutex guards: the per-session states and the
/// relay-wide turn-byte total they sum to. One mutex, so the budget check,
/// the deposit, and every removal's release are each one atomic step.
#[derive(Default)]
struct PenState {
    sessions: HashMap<SessionKey, SessionPen>,
    /// Total [`entry_turn_bytes`] charged against the budget: every
    /// session's in-pen queue PLUS batches a drain has taken but not yet
    /// finished replaying — the budget tracks resident memory, and a taken
    /// batch's allocations live until the drainer replays, drops, and
    /// releases them ([`ProvisionalTurnPen::release_drained`]).
    turn_bytes: usize,
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

    /// Reserves `key`'s journal tracking entry — the session ceiling's real
    /// enforcement point, called at provisional admission BEFORE the link
    /// serves. Refusing here refuses the whole connection while nothing has
    /// been accepted yet; refusing a deposit later would acknowledge a turn
    /// the relay retains nowhere (the receive arm publishes
    /// delivered-through before it could observe the refusal), leaving a
    /// permanent sequence hole behind an unsealed slot. `true` when the
    /// session is already tracked or a slot was free; `false` when the
    /// ceiling is full and the session untracked.
    #[must_use]
    pub fn reserve(&self, key: &SessionKey) -> bool {
        let mut guard = self.inner.state.lock();
        let state = &mut *guard;
        if state.sessions.contains_key(key) {
            return true;
        }
        if state.sessions.len() >= self.inner.max_sessions {
            return false;
        }
        state.sessions.insert(key.clone(), SessionPen::gathering());
        true
    }

    /// Deposits one ingress effect — unless the session was already fully
    /// drained ([`Resolved`](HoldOutcome::Resolved), the caller's cue to
    /// re-run its ordinary path against the maker that now exists) or the
    /// journal is full ([`Overflow`](HoldOutcome::Overflow), the caller's
    /// cue to fail the offender closed). A deposit landing mid-drain is
    /// journaled and replayed by the drain loop's next pass, so it stays
    /// ordered behind everything already in flight.
    ///
    /// A [`Departure`](PennedIngress::Departure) is exempt from the
    /// per-session cap and the aggregate byte budget — there is at most one
    /// per slot (enforced by compaction), each is a few dozen bytes, and
    /// losing one strands the session on an expected-but-absent slot. Only
    /// the relay-wide session ceiling refuses one, and only when it would
    /// CREATE a new tracking entry (`MAX_JOURNALED_SESSIONS`). A
    /// clean-leave departure also seals its slot against readmission (see
    /// [`slot_sealed`](Self::slot_sealed)).
    #[must_use]
    pub fn hold(&self, key: &SessionKey, mut entry: PennedIngress) -> HoldOutcome {
        // Detach a turn's command bytes from their transport backing before
        // anything is retained: `commands` is a `Bytes` slice into the
        // received datagram, and journaling the slice would pin the whole
        // MTU-sized allocation (redundant co-carried payloads included) for
        // the journal's life while the accounting charged only the slice.
        // This is an exceptional, pre-descriptor path — the copy is cheap
        // and makes the charge below describe the actual owned allocation.
        if let PennedIngress::Turn(_, payload) = &mut entry {
            payload.commands = payload.commands.to_vec().into();
        }
        let entry_bytes = entry_turn_bytes(&entry);
        let mut guard = self.inner.state.lock();
        let state = &mut *guard;
        // The session ceiling: a deposit may not CREATE a tracking entry
        // past it. Admission reserves every provisional session's entry
        // before its link serves (refusing the CONNECTION when the ceiling
        // is full, before any turn could be acknowledged), so a turn can
        // only reach this refusal through an invariant breach; a departure
        // can also reach it through the narrow race where a sibling
        // teardown's emptied close discarded the reservation first. Refused
        // without inserting anything — including the seal, which would
        // itself be the map growth the ceiling exists to stop.
        if !state.sessions.contains_key(key) && state.sessions.len() >= self.inner.max_sessions {
            if matches!(entry, PennedIngress::Turn(..)) {
                tracing::error!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    "a turn reached the journal session ceiling; admission should have reserved                      this session's entry",
                );
            }
            return HoldOutcome::Overflow(entry);
        }
        let over_budget =
            state.turn_bytes.saturating_add(entry_bytes) > self.inner.turn_byte_budget;
        let pen = state
            .sessions
            .entry(key.clone())
            .or_insert_with(SessionPen::gathering);
        let queue = match &mut pen.phase {
            Phase::Resolved => return HoldOutcome::Resolved(entry),
            Phase::Gathering(queue) | Phase::Draining(queue) => queue,
        };
        if let PennedIngress::Turn(slot, _) = &entry
            && (queue.len() >= PER_SESSION_CAP || over_budget)
        {
            // Per-session cap or relay-wide budget: either way the turn
            // cannot be journaled, and dropping it silently would hole an
            // acknowledged sequence. Seal HERE, atomically with the
            // overflow verdict and under the caller's ingress gate: the
            // slot must never be readmitted past its hole. Sealing from
            // the caller after the gate released would race a
            // retirement's terminal discard and recreate journal state for
            // an ended session. Nothing already retained is deleted to
            // make room — the budget fails NEW data closed instead.
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
        state.turn_bytes += entry_bytes;
        HoldOutcome::Held
    }

    /// Whether a journaled departure's `revision` is still the slot's
    /// current one — the drain's pre-replay validation: a departure
    /// superseded while it sat in the drain's private batch is skipped, not
    /// replayed, so a stale old-generation drop can never install itself
    /// ahead of the newer departure that superseded it.
    pub fn departure_is_current(&self, key: &SessionKey, slot: SlotId, revision: u64) -> bool {
        self.inner
            .state
            .lock()
            .sessions
            .get(key)
            .is_some_and(|pen| pen.departure_revisions.get(&slot) == Some(&revision))
    }

    /// Whether `slot` is sealed against admission — a journaled clean leave
    /// (terminal until the drained decided leave takes refusal over) or an
    /// overflow (terminal for the session's life). Checked at client
    /// admission on a coordinator-managed relay; survives the whole
    /// Gathering → Draining → Resolved life of the journal state.
    pub fn slot_sealed(&self, key: &SessionKey, slot: SlotId) -> bool {
        self.inner
            .state
            .lock()
            .sessions
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
    ///
    /// A taken batch REMAINS charged against the byte budget: the budget is
    /// a resident-memory ceiling, and the batch's allocations live until
    /// the drainer replays (and drops) them — it releases the charge with
    /// [`release_drained`](Self::release_drained) as it finishes each batch.
    #[must_use]
    pub fn begin_drain(&self, key: &SessionKey) -> Option<Vec<PennedIngress>> {
        let mut guard = self.inner.state.lock();
        let state = &mut *guard;
        let pen = state
            .sessions
            .entry(key.clone())
            .or_insert_with(SessionPen::gathering);
        match &mut pen.phase {
            Phase::Gathering(queue) => {
                let batch = std::mem::take(queue);
                pen.in_flight_turns = turn_identities(&batch);
                pen.phase = Phase::Draining(VecDeque::new());
                Some(batch.into())
            }
            Phase::Draining(_) | Phase::Resolved => None,
        }
    }

    /// Releases `bytes` of drained-batch charge back to the budget — called
    /// by the drainer after it has replayed (and dropped) a batch it took
    /// via [`begin_drain`](Self::begin_drain) /
    /// [`continue_drain`](Self::continue_drain), summed with
    /// [`entry_bytes`](Self::entry_bytes). Every taken batch is replayed to
    /// completion before the drain loop asks for more (a mid-drain
    /// retirement only stops the NEXT step), so every charge taken out of a
    /// queue is eventually released here.
    pub fn release_drained(&self, bytes: usize) {
        let mut guard = self.inner.state.lock();
        guard.turn_bytes = guard.turn_bytes.saturating_sub(bytes);
    }

    /// The budget charge of one journaled entry, for the drainer's
    /// [`release_drained`](Self::release_drained) accounting.
    pub fn entry_bytes(entry: &PennedIngress) -> usize {
        entry_turn_bytes(entry)
    }

    /// One step of the drain loop: under the journal lock, either hands back
    /// the deposits that landed during the previous replay pass, or — only
    /// when the queue is empty — flips the session to `Resolved` and ends
    /// the drain. The empty-check and the flip are one atomic step, so no
    /// deposit can land between "queue looked empty" and "session resolved".
    #[must_use]
    pub fn continue_drain(&self, key: &SessionKey) -> DrainStep {
        let mut guard = self.inner.state.lock();
        let state = &mut *guard;
        let Some(pen) = state.sessions.get_mut(key) else {
            // Discarded mid-drain (the session was retired): nothing left
            // to replay.
            return DrainStep::Done;
        };
        // Whatever this step decides, the drainer has finished replaying the
        // batch it previously held (the drain loop replays to completion
        // before asking again), so that batch's in-flight shadow is done:
        // every turn in it has passed the forward gate and is covered by the
        // gate's own record now.
        pen.in_flight_turns.clear();
        match &mut pen.phase {
            Phase::Draining(queue) if queue.is_empty() => {
                pen.phase = Phase::Resolved;
                DrainStep::Done
            }
            // Like `begin_drain`, the taken batch stays charged until the
            // drainer releases it — the budget tracks resident memory, not
            // queue membership.
            Phase::Draining(queue) => {
                let batch = std::mem::take(queue);
                pen.in_flight_turns = turn_identities(&batch);
                DrainStep::More(batch.into())
            }
            // Not draining (a retirement's discard plus fresh deposits
            // recreated Gathering, or already resolved): this drainer's
            // claim is gone either way.
            Phase::Gathering(_) | Phase::Resolved => DrainStep::Done,
        }
    }

    /// Drops `key`'s journal state outright — gathered entries, seals,
    /// revisions, and the resolved mark alike. Descriptor retirement's path
    /// (the coordinator ended the session); a later dial for the id starts a
    /// genuinely fresh journal.
    pub fn discard(&self, key: &SessionKey) {
        let mut guard = self.inner.state.lock();
        let state = &mut *guard;
        if let Some(pen) = state.sessions.remove(key) {
            let released: usize = match &pen.phase {
                Phase::Gathering(queue) | Phase::Draining(queue) => {
                    queue.iter().map(entry_turn_bytes).sum()
                }
                Phase::Resolved => 0,
            };
            state.turn_bytes = state.turn_bytes.saturating_sub(released);
        }
    }

    /// Whether `key` has journaled entries still awaiting a drain.
    pub fn has_undrained(&self, key: &SessionKey) -> bool {
        self.inner
            .state
            .lock()
            .sessions
            .get(key)
            .is_some_and(|pen| match &pen.phase {
                Phase::Gathering(queue) | Phase::Draining(queue) => !queue.is_empty(),
                Phase::Resolved => false,
            })
    }

    /// Every turn seq this journal currently retains for `key`'s `slot`: the
    /// queued deposits plus the batch a drain holds privately in flight. Each
    /// was transport-acknowledged when it was deposited, so together with the
    /// forward gate's own record (which a drained turn enters before it
    /// leaves the in-flight shadow) this is the journal's half of the
    /// receipts a resumed connection's receive window is seeded from. A
    /// resume racing a drain reads this BEFORE the gate: entries only ever
    /// move journal → gate, so the pair of reads in that order sees every
    /// receipt in at least one of the two.
    pub fn held_turn_seqs(&self, key: &SessionKey, slot: SlotId) -> Vec<u64> {
        let guard = self.inner.state.lock();
        let Some(pen) = guard.sessions.get(key) else {
            return Vec::new();
        };
        let mut seqs: Vec<u64> = match &pen.phase {
            Phase::Gathering(queue) | Phase::Draining(queue) => queue
                .iter()
                .filter_map(|entry| match entry {
                    PennedIngress::Turn(s, payload) if *s == slot => Some(payload.seq),
                    _ => None,
                })
                .collect(),
            Phase::Resolved => Vec::new(),
        };
        seqs.extend(
            pen.in_flight_turns
                .iter()
                .filter(|(s, _)| *s == slot)
                .map(|&(_, seq)| seq),
        );
        seqs
    }

    /// Atomically discards `key`'s journal state IF it holds nothing — an
    /// empty, un-drained `Gathering` — returning whether it did. The
    /// emptied-session close uses this so its "nothing to keep" verdict and
    /// the removal are one step: a deposit racing the close either lands
    /// first (the discard refuses, the journal is retained) or lands after
    /// (recreating a fresh journal, retained like any other) — never into
    /// the void between a check and a separate removal. A `Draining`
    /// journal always refuses: an active drain owns the pen, and removing it
    /// would reset the departure revisions a drainer's private batch is
    /// validated against (the ABA the revisions exist to prevent).
    #[must_use]
    pub fn discard_if_empty(&self, key: &SessionKey) -> bool {
        let mut guard = self.inner.state.lock();
        let sessions = &mut guard.sessions;
        match sessions.get(key) {
            None => true,
            Some(pen) => match &pen.phase {
                // An empty Gathering holds zero turn bytes — nothing to
                // release from the aggregate total. A SEAL refuses the
                // discard even with an empty queue: a budget-overflow seal
                // is installed without a deposit, so in the window between
                // the sealed link's deregistration and its teardown's
                // departure deposit the pen is exactly empty-but-sealed —
                // and dropping the seal there would let the slot readmit
                // past its permanent hole.
                Phase::Gathering(queue) if queue.is_empty() && pen.sealed.is_empty() => {
                    sessions.remove(key);
                    true
                }
                _ => false,
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn with_turn_byte_budget(budget: usize) -> Self {
        ProvisionalTurnPen {
            inner: Arc::new(PenInner {
                turn_byte_budget: budget,
                ..PenInner::default()
            }),
        }
    }

    /// A pen with an explicit session ceiling — a test seam (like
    /// `mesh::new_mesh_state_with_provisional_window`) so an end-to-end test
    /// can drive the admission-time capacity refusal without four thousand
    /// fixture sessions. Production always builds the default ceiling.
    pub fn with_session_ceiling(max_sessions: usize) -> Self {
        ProvisionalTurnPen {
            inner: Arc::new(PenInner {
                max_sessions,
                ..PenInner::default()
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn held(&self, key: &SessionKey) -> usize {
        match self
            .inner
            .state
            .lock()
            .sessions
            .get(key)
            .map(|pen| &pen.phase)
        {
            Some(Phase::Gathering(queue)) | Some(Phase::Draining(queue)) => queue.len(),
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests;
