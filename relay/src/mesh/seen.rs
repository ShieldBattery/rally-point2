//! The session-level forward-once gate: which `(slot, seq)` turns this relay
//! has already delivered to a session's local clients, and the cursors read
//! back out of that record for resume, receipts, and leave counts.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use parking_lot::Mutex;
use rally_point_proto::ids::SlotId;

use crate::routing::SessionKey;

/// Session-level forward-once gate: records which `(slot, seq)` turns have
/// already been forwarded to this session's local clients, so a turn arriving
/// again through link replacement, resume replay, or re-home overlap is dropped
/// rather than delivered twice.
///
/// Mirrors the per-link `Dedup`'s structure (a contiguous delivered prefix plus
/// an `ahead` set per slot) but serves a different purpose: `Dedup` is
/// receive-side (it gates delivery to the link's consumer), while `MeshSeen` is
/// forward-gate-side (it gates fan-out to local clients). It has no receive
/// window — a turn far ahead of the prefix is simply new, not rejected — because
/// the mesh trusts its peer relays and the origin seqs are client-assigned.
///
/// The prefix-slide lets it forget old seqs without unbounded growth: a late
/// redundant copy of a retired seq is dropped as `<= delivered_through` rather
/// than re-checked against a growing set. The out-of-prefix sparse set that
/// backs that slide is itself capped (`SPARSE_SEEN_CAP`): a seq stream that
/// leaves permanent gaps below its high-water mark — an authenticated peer that
/// keeps reconnecting with an advancing resume anchor is the motivating case —
/// would otherwise pin those gaps in the set for the life of the session, so
/// beyond the cap the prefix collapses forward over the lowest gap rather than
/// hold it forever.
#[derive(Default)]
pub struct MeshSeen {
    /// Per-slot forward-gate state.
    pub(super) slots: HashMap<SlotId, SlotSeen>,
}

/// The largest number of out-of-prefix seqs one slot's forward gate holds before
/// it collapses its contiguous prefix forward to reclaim the space. Sized to the
/// transport's per-slot receive window (`RECEIVE_WINDOW` in
/// `rally_point_transport`, 4096): a link that legitimately runs that far ahead
/// of its contiguous prefix is already treated as broken there, so a sparse set
/// grown this deep is not in-flight reordering but permanent gaps — seqs that
/// will never arrive to fill them. Holding them forever is a memory-growth
/// vector on an authenticated-but-hostile peer; the cap bounds each slot's sparse
/// set to this many entries, independent of how far the seqs ahead of it climb.
pub(super) const SPARSE_SEEN_CAP: usize = 4096;

/// One slot's forward-once state.
pub(super) struct SlotSeen {
    /// Top of the contiguous forwarded prefix; `None` until seq 0 is forwarded.
    pub(super) forwarded_through: Option<u64>,
    /// Forwarded seqs above the prefix, kept until the gaps below them fill.
    /// Mirrors `Dedup::SlotDedup::ahead` so out-of-order mesh arrival doesn't
    /// cause a false "new" on a seq that was already forwarded out of order.
    /// Bounded to [`SPARSE_SEEN_CAP`] entries: past that the prefix collapses
    /// forward over the lowest gap (see [`SlotSeen::collapse_to_cap`]).
    pub(super) ahead: BTreeSet<u64>,
    /// Whether [`SlotSeen::collapse_to_cap`] has ever advanced the prefix over
    /// a gap. A collapsed prefix remains correct for the forward-once gate (the
    /// safe failure direction — see that method's doc) but no longer counts
    /// only turns that were actually forwarded, so [`forwarded_count`] refuses
    /// to answer from it: a leave scheduled on an inflated count would have
    /// survivors wait forever for turns that never existed.
    pub(super) prefix_collapsed: bool,
}

/// Whether a `(slot, seq)` has already been forwarded to local clients.
#[derive(Debug, PartialEq, Eq)]
pub enum Seen {
    /// First time this `(slot, seq)` has been forwarded — deliver it to locals.
    New,
    /// Already forwarded (at/below the contiguous prefix, or seen out of order).
    Duplicate,
}

/// What recording one turn at the forward gate did.
#[derive(Debug, PartialEq, Eq)]
pub struct Forwarded {
    /// Whether the turn was new here, or a copy of one already delivered.
    pub seen: Seen,
    /// Whether this turn moved the slot's gap-free forwarded prefix forward over
    /// turns that were genuinely forwarded: an in-order arrival, or one that
    /// closed the gap the prefix had stalled behind. A prefix pushed over a gap
    /// by the sparse-set cap (`SlotSeen::collapse_to_cap`) is not that, and neither is any later
    /// advance of a slot whose prefix has ever been collapsed — past a collapse
    /// the prefix no longer counts only turns that really arrived. Always false
    /// for a duplicate.
    ///
    /// This is the relay's own evidence that a slot's turns are still reaching
    /// local clients *in order*, and the only per-slot progress measure a client
    /// cannot inflate: turns can be withheld, or sent far ahead of the prefix,
    /// but nothing advances this except the missing turns themselves.
    pub prefix_advanced: bool,
}

impl Forwarded {
    /// A turn already delivered through an earlier ingress instance: no prefix
    /// moved, because nothing was recorded.
    fn duplicate() -> Self {
        Self {
            seen: Seen::Duplicate,
            prefix_advanced: false,
        }
    }
}

impl MeshSeen {
    /// Creates an empty forward-once set for one session.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `(slot, seq)` as forwarded and reports whether it's new or a
    /// duplicate, and whether it advanced the slot's gap-free prefix (see
    /// [`Forwarded`]). A duplicate is dropped silently — the turn already
    /// reached this relay's local clients through an earlier ingress instance.
    pub fn mark_forwarded(&mut self, slot: SlotId, seq: u64) -> Forwarded {
        let state = self.slots.entry(slot).or_insert_with(|| SlotSeen {
            forwarded_through: None,
            ahead: BTreeSet::new(),
            prefix_collapsed: false,
        });

        if state
            .forwarded_through
            .is_some_and(|forwarded| seq <= forwarded)
        {
            return Forwarded::duplicate();
        }
        let base = match state.forwarded_through {
            Some(through) => {
                let Some(next) = through.checked_add(1) else {
                    // Every u64 seq is at or below this prefix and the duplicate
                    // check above normally returns first. Keep the ceiling safe
                    // even if this code is rearranged later.
                    return Forwarded::duplicate();
                };
                next
            }
            None => 0,
        };

        // In-order delivery is the common case. Advance the prefix directly so
        // it does not allocate a tree node only for the contiguous-run fold to
        // remove that same node immediately.
        if seq == base {
            state.forwarded_through = Some(seq);
            state.absorb_contiguous_run();
            return Forwarded {
                seen: Seen::New,
                // A prefix that has ever been collapsed sits above a gap this
                // relay never forwarded, so nothing stacked on top of it proves
                // the slot's turns are still arriving in order.
                prefix_advanced: !state.prefix_collapsed,
            };
        }
        if !state.ahead.insert(seq) {
            return Forwarded::duplicate();
        }

        // Absorb any now-contiguous run into the forwarded prefix, so old seqs
        // can be forgotten, then bound the sparse remainder so a stream of
        // permanent gaps can't grow it without limit.
        let before = state.forwarded_through;
        state.absorb_contiguous_run();
        let closed_a_gap = state.forwarded_through != before;
        state.collapse_to_cap();
        Forwarded {
            seen: Seen::New,
            // Read after the collapse, so an arrival that absorbs a run and then
            // pushes the sparse set over the cap reports no progress either: the
            // prefix it leaves behind has jumped a gap.
            prefix_advanced: closed_a_gap && !state.prefix_collapsed,
        }
    }
}

impl SlotSeen {
    /// Folds the run of seqs sitting immediately above the contiguous prefix out
    /// of the sparse set and into the prefix. Called after a fresh seq lands: if
    /// it closed the gap the prefix was stalled behind, the whole run above it
    /// becomes contiguous and the seqs below can be forgotten.
    fn absorb_contiguous_run(&mut self) {
        let mut next = match self.forwarded_through {
            Some(through) => match through.checked_add(1) {
                Some(next) => next,
                None => return,
            },
            None => 0,
        };
        while self.ahead.remove(&next) {
            self.forwarded_through = Some(next);
            let Some(after) = next.checked_add(1) else {
                return;
            };
            next = after;
        }
    }

    /// Bounds the sparse out-of-prefix set to [`SPARSE_SEEN_CAP`] by collapsing
    /// the prefix forward over the lowest sparse seq (and any run contiguous
    /// above it) whenever the set is over the cap. The gap swallowed by that
    /// advance — every seq between the old prefix top and that lowest sparse seq
    /// — is thereafter reported as seen, so a turn that later arrives in it reads
    /// as a `Duplicate`, never a fresh forward.
    ///
    /// That is the safe failure direction for a forward-once gate. A gap left this far
    /// below the highest seen seq never fills in normal operation — its turn is
    /// lost for good, or the only thing that would arrive there is a replay — and
    /// the two ways to be wrong about it are not symmetric: a false `Duplicate`
    /// merely drops a late turn, while a false `New` re-delivers an
    /// already-delivered turn to local lockstep slots and can desync them.
    /// Collapsing chooses the `Duplicate` side deliberately.
    fn collapse_to_cap(&mut self) {
        while self.ahead.len() > SPARSE_SEEN_CAP {
            let lowest = self
                .ahead
                .pop_first()
                .expect("a set over a positive cap is non-empty");
            self.forwarded_through = Some(lowest);
            self.prefix_collapsed = true;
            self.absorb_contiguous_run();
        }
    }
}

/// Per-session forward-once registries: each `SessionKey` → the `MeshSeen`
/// for that session, shared across all slot links + mesh-link tasks so every
/// ingress — local client or mesh peer — marks before forwarding to locals.
///
/// This is the forward-once gate across ingress instances. A connection
/// replacement, resume replay, or slot re-home overlap can present a turn that
/// was already delivered through another client or mesh task; the shared state
/// drops that copy before it can duplicate a turn into a local lockstep slot.
pub type SeenRegistries = Arc<Mutex<HashMap<SessionKey, MeshSeen>>>;

/// Creates an empty seen-registry for a relay with no sessions yet.
pub fn new_seen_registries() -> SeenRegistries {
    Arc::new(Mutex::new(HashMap::new()))
}

/// Marks `(slot, seq)` as forwarded for `key`'s session, returning whether it's
/// new or a duplicate and whether it advanced the slot's gap-free prefix. Used
/// by both `run_slot_link` (local-client ingress) and `run_mesh_link` (mesh-peer
/// ingress) before fanning out to local clients.
pub fn mark_seen(
    registries: &SeenRegistries,
    key: &SessionKey,
    slot: SlotId,
    seq: u64,
) -> Forwarded {
    let mut roster = registries.lock();
    if let Some(seen) = roster.get_mut(key) {
        return seen.mark_forwarded(slot, seq);
    }
    roster
        .entry(key.clone())
        .or_default()
        .mark_forwarded(slot, seq)
}

/// Removes a session's seen registry (the session has ended). Idempotent.
pub fn deregister_seen(registries: &SeenRegistries, key: &SessionKey) {
    let mut roster = registries.lock();
    roster.remove(key);
}

/// The number of `slot`'s turns this relay has forwarded to the session's local
/// clients as a gap-free prefix (seqs `0..count`) — the home relay's source for
/// the departing slot's final turn count (`LeaveDirective::final_turn_count`),
/// the exact number of the slot's turns every client consumes before applying
/// its leave. Its one sound consumer is the clean-leave intent handler, which
/// reads it in the same step it cuts the slot's ingress; read anywhere else
/// (a drop, say), the slot may still push turns past the answer through a
/// reconnect, so every other departure origin stamps no count at all.
///
/// This forward-gate cursor, not any one connection's receive state, is the
/// authoritative basis for that count, for three reasons. It is session-level:
/// it survives connection replacement, so a reconnect that dies before its
/// resumed stream comes up still counts everything the slot's earlier
/// connections forwarded. It sits past validation, at the fan-out choke point:
/// only turns actually delivered toward local lockstep clients advance it, so a
/// delivered-but-invalid turn (which advances a link's receive cursor without
/// being forwarded) never inflates it. And it is relay-authored: a client's
/// resume-cursor anchor can teleport its own *link's* dedup base, but this
/// prefix only ever advances contiguously from what was genuinely forwarded, so
/// no claimed anchor can manufacture a count for turns that never existed.
///
/// `None` when the relay has no gap-free knowledge to answer from: the session
/// or slot has no forwarded prefix (nothing forwarded yet, or a re-homed slot
/// whose pre-rehome turns this relay never carried), or the prefix was
/// collapsed over a gap by the sparse-set cap (see `SlotSeen::collapse_to_cap`
/// — correct for the forward-once gate, but no longer a count of real turns).
/// Callers fall back to frame scheduling on `None`; a fabricated or inflated
/// exact count is strictly worse than no count.
pub fn forwarded_count(registries: &SeenRegistries, key: &SessionKey, slot: SlotId) -> Option<u64> {
    let roster = registries.lock();
    let state = roster.get(key)?.slots.get(&slot)?;
    if state.prefix_collapsed {
        return None;
    }
    // A prefix top of `u64::MAX` has no representable successor; no real
    // session approaches it, and answering `None` (frame fallback) is safe.
    state.forwarded_through?.checked_add(1)
}

/// A snapshot of `key`'s forward-gate cursors, as "next needed seq" per slot —
/// the seq immediately past each slot's contiguous forwarded-to-locals prefix.
/// A slot with no contiguous prefix (nothing forwarded yet, or a gap below
/// what has) is omitted entirely, not given a `0`. What an absent slot then
/// asks of the reply depends on [`has_resumable_state`] alongside this
/// snapshot: nothing, for a session with no forward-gate history at all
/// (a fresh join); that slot's turns from the very start, for a session that
/// does (see the wire frame's own doc for the full two-mode story — this
/// snapshot only ever answers "how far did I get", never "should an absent
/// slot mean nothing or everything").
///
/// Read from the same registry [`mark_forwarded`](MeshSeen::mark_forwarded)
/// writes, so the snapshot reflects exactly what this session has actually
/// delivered to its locals so far — by any path, not just this one link —
/// which is what makes it safe to read straight from here rather than from
/// any one mesh link's own transport state: a link dying and redialing never
/// touches this registry, so the cursors it hands the fresh link on rejoin are
/// unaffected by the death that made rejoining necessary in the first place.
/// At the unreachable-in-practice `u64::MAX` ceiling there is no representable
/// successor, so the cursor saturates at the ceiling. That can request one
/// already-delivered payload again, which the same forward gate drops safely.
pub fn resume_cursor_snapshot(registries: &SeenRegistries, key: &SessionKey) -> Vec<(SlotId, u64)> {
    let roster = registries.lock();
    let Some(seen) = roster.get(key) else {
        return Vec::new();
    };
    seen.slots
        .iter()
        .filter_map(|(&slot, state)| {
            state
                .forwarded_through
                .map(|through| (slot, through.saturating_add(1)))
        })
        .collect()
}

/// One slot's forward-gate receipt state, read for seeding a resumed
/// connection's receive window: the contiguous forwarded prefix plus the
/// sparse forwarded seqs above it. See [`slot_receipts`].
pub struct SlotReceipts {
    /// Top of the contiguous forwarded prefix, `None` before seq 0 arrives.
    pub forwarded_through: Option<u64>,
    /// Forwarded seqs above the prefix, sorted ascending.
    pub ahead: Vec<u64>,
}

/// A snapshot of every turn seq the forward gate has ever recorded for
/// `key`'s `slot` — the same session-lifetime registry
/// [`mark_forwarded`](MeshSeen::mark_forwarded) writes, which survives
/// connection replacement, covers pre-start traffic, and never evicts. That
/// is what makes it the authoritative half of resume-window seeding: a turn
/// the relay acknowledged to its client either passed the gate and is
/// recorded here, or is still held by the provisional journal (whose overflow
/// seals the slot against resuming at all), so a resumed connection's acked
/// holes can always be closed from the two together.
///
/// A prefix collapsed by the sparse cap (the private
/// `SlotSeen::collapse_to_cap`) is reported as-is, gaps and all: the gate
/// already treats the swallowed gaps as seen (an arrival in one is dropped as
/// a duplicate, the documented safe failure direction), so a receive window
/// seeded to match merely mirrors that verdict one layer down rather than
/// adding a new loss.
pub fn slot_receipts(registries: &SeenRegistries, key: &SessionKey, slot: SlotId) -> SlotReceipts {
    let roster = registries.lock();
    let Some(state) = roster.get(key).and_then(|seen| seen.slots.get(&slot)) else {
        return SlotReceipts {
            forwarded_through: None,
            ahead: Vec::new(),
        };
    };
    SlotReceipts {
        forwarded_through: state.forwarded_through,
        ahead: state.ahead.iter().copied().collect(),
    }
}

/// Whether `key` has ANY forward-gate history at all — an entry in the same
/// registry [`resume_cursor_snapshot`] reads, regardless of whether any slot
/// in it has formed a contiguous prefix yet. This is the `resuming` a
/// resume-cursor ask carries: `true` means "I have genuinely exchanged mesh
/// traffic for this session before" (even if every slot in the accompanying
/// snapshot is gapped or absent), which is what licenses a resume reply to
/// treat an absent slot as "everything from the start" rather than "nothing
/// asked for" — see the wire frame's own doc. `false` — no entry at all — is
/// indistinguishable from a first Join, so the conservative first-join
/// reading (nothing) is exactly what a session with no history should get.
pub fn has_resumable_state(registries: &SeenRegistries, key: &SessionKey) -> bool {
    registries.lock().contains_key(key)
}
