//! Receive-side payload dedup: the per-slot bookkeeping that turns a
//! redundantly-carried packet into first deliveries only.
//!
//! Redundancy puts the same payload in several packets, so every received
//! payload is offered here and handed on only the first time. The per-slot
//! state, the accept outcome, and the whole-packet transactional filter share
//! one file because they enforce one invariant together: a payload the caller
//! never received is never remembered as delivered.

use std::collections::{BTreeSet, HashMap};

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::Payload;

use super::{LinkError, RECEIVE_WINDOW};

/// Sorts, transactionally deduplicates, and retains only fresh payloads in the
/// decoded protobuf vector.
///
/// A packet leads with its fresh (highest) seq per slot, so low-seq-first sorting
/// keeps a deep-loss packet's high seq from shutting the window on older
/// redundant seqs alongside it. Every valid slot is snapshotted before the first
/// provisional `accept`: if a later payload is out of window or names a malformed
/// slot, restoring the snapshot prevents dedup from remembering earlier payloads
/// that the failed call never handed to its consumer.
///
/// On success `payloads` keeps its original allocation and contains only first
/// deliveries, ordered by `(slot, seq)`.
pub(crate) fn retain_fresh_payloads(
    dedup: &mut Dedup,
    payloads: &mut Vec<Payload>,
) -> Result<(), LinkError> {
    payloads.sort_by_key(|payload| (payload.slot, payload.seq));
    let snapshot = dedup.snapshot_sorted_payload_slots(payloads);
    let mut failure = None;

    payloads.retain(|payload| {
        // `Vec::retain` cannot stop early. Once the packet has failed, discard
        // its remaining elements without making any further provisional dedup
        // changes; the snapshot is restored after compaction completes.
        if failure.is_some() {
            return false;
        }

        // A truncating cast would alias an out-of-range wire slot onto a
        // different, valid slot's dedup key — corrupting that slot's window
        // instead of merely rejecting the malformed one.
        let Ok(slot) = u8::try_from(payload.slot).map(SlotId) else {
            failure = Some(LinkError::MalformedSlot(payload.slot));
            return false;
        };
        match dedup.accept(slot, payload.seq) {
            Delivery::New => true,
            Delivery::Duplicate => false,
            Delivery::OutOfWindow => {
                failure = Some(LinkError::PayloadOutOfWindow {
                    slot,
                    seq: payload.seq,
                });
                false
            }
        }
    });

    if let Some(error) = failure {
        dedup.restore(snapshot);
        Err(error)
    } else {
        Ok(())
    }
}

/// The outcome of offering a received payload `(slot, seq)` to the dedup state.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Delivery {
    /// First time this `(slot, seq)` has been delivered — hand it to the caller.
    New,
    /// Already delivered (at/below the contiguous prefix, or seen out of order).
    Duplicate,
    /// Beyond the receive window — the peer is racing too far ahead.
    OutOfWindow,
}

/// Receive-side payload dedup, per slot.
///
/// Each slot has its own contiguous delivered prefix (`delivered_through`) plus
/// an `ahead` set of delivered seqs above it waiting for the gaps below to fill,
/// because each slot carries its own monotonic seq space starting at 0 — a
/// single global cursor would conflate one slot's progress with another's. A seq
/// is a duplicate only if it's within that slot's known-delivered state — never
/// merely because a higher seq arrived first — so a redundant low seq is never
/// mistaken for one that aged out.
///
/// Shared by the client-edge [`Link`](super::Link) and the mesh `MeshLink`:
/// both own one
/// instance per connection and feed it received payloads, so `(slot, seq)` is
/// unambiguous within an instance. The client edge has one game per connection
/// by nature; the mesh shares one connection across sessions but gives each its
/// own instance, so the session never enters the key.
pub(crate) struct Dedup {
    /// Per-slot dedup state.
    pub(super) slots: HashMap<SlotId, SlotDedup>,
    /// The highest per-slot cursor force-retired via
    /// [`Link::retire_through`](super::Link::retire_through), so
    /// a desynced or replayed cursor can't retire turns the peer never confirmed.
    /// Inbound cursors are applied only when strictly greater than this; anything
    /// else is a no-op. Without it, a stream framing desync handing a garbage
    /// `u64` to `retire_through` could retire turns the peer never received —
    /// silent lockstep desync, worse than a crash.
    pub(super) retired_through: HashMap<SlotId, u64>,
    /// How far above the prefix a seq may sit before it's rejected — or, with
    /// `forward_collapse`, before the prefix collapses forward to admit it.
    pub(super) window: u64,
    /// Whether a seq beyond the window collapses the delivered prefix forward
    /// over the outstanding gaps (treating them as delivered) instead of being
    /// rejected as `OutOfWindow`.
    ///
    /// The strict mode is for links whose peer is untrusted (the relay's client
    /// edge): a seq racing past the window there means a broken or hostile
    /// sender, and the safe response is to refuse and close. The collapsing
    /// mode is for links whose peer is an authenticated relay (the mesh): a
    /// session legitimately enters a mesh link mid-stream — a link that died
    /// and redialed, a relay newly joining a running session — so its slots'
    /// seqs start wherever the game currently is, far past a from-zero window.
    /// A gap left a full window behind the live stream never fills (its turns
    /// are lost for good or were delivered on an earlier link), so collapsing
    /// over it mirrors the session-level forward gate's own cap behavior: a
    /// false "already delivered" merely drops a redundant copy, while refusing
    /// the live stream would reset the link forever.
    pub(super) forward_collapse: bool,
}

/// One slot's receive-side dedup state.
#[derive(Clone)]
pub(crate) struct SlotDedup {
    /// Top of the contiguous delivered prefix; `None` until seq 0 is delivered.
    pub(super) delivered_through: Option<u64>,
    /// Delivered seqs above the prefix, kept until the gaps below them fill.
    pub(super) ahead: BTreeSet<u64>,
}

impl SlotDedup {
    /// Advances the contiguous prefix through `seq`, then folds in any
    /// already-delivered run waiting immediately above it.
    ///
    /// The caller has established that `seq` is exactly the current receive
    /// base. Handling that overwhelmingly common in-order case directly keeps
    /// it out of `ahead`: inserting it there only for
    /// [`absorb_contiguous_run`](Self::absorb_contiguous_run) to remove it again
    /// would allocate a tree node on every in-order payload.
    fn advance_contiguous(&mut self, seq: u64) {
        self.delivered_through = Some(seq);
        self.absorb_contiguous_run();
    }

    /// Folds the run of seqs sitting immediately above the contiguous prefix
    /// out of the `ahead` set and into the prefix. Stops rather than overflows
    /// if the run reaches `u64::MAX`; there is no valid seq beyond it to keep
    /// absorbing anyway.
    fn absorb_contiguous_run(&mut self) {
        let mut next = match self.delivered_through {
            Some(top) => match top.checked_add(1) {
                Some(next) => next,
                None => return,
            },
            None => 0,
        };
        while self.ahead.remove(&next) {
            self.delivered_through = Some(next);
            let Some(after) = next.checked_add(1) else {
                return;
            };
            next = after;
        }
    }

    /// Collapses the delivered prefix forward until `seq` fits the receive
    /// window, treating the gaps it advances over as delivered. Only ever
    /// called from a forward-collapsing [`Dedup`] (see its `forward_collapse`
    /// field for the trust argument), with `seq` already known to be at least
    /// `window` past the current base.
    ///
    /// Advances over the lowest out-of-order seqs first — each pop may absorb a
    /// contiguous run above it — so the prefix lands on real delivery evidence
    /// wherever any exists. When nothing out-of-order remains (a pristine slot
    /// meeting a mid-stream session, or a prefix stalled behind a dead gap with
    /// nothing above it), the prefix jumps so `seq` sits at the window's top
    /// edge, keeping the full window *below* `seq` open: the sender's
    /// still-unacked backlog rides behind its freshest seq, and landing the
    /// base any higher would misread that backlog as already delivered and
    /// silently drop it.
    ///
    /// The prefix only ever moves forward here: every `ahead` entry is strictly
    /// below `seq` (each was accepted inside the then-current window, which sat
    /// entirely below a seq now at least a full window past base), and the
    /// empty-`ahead` jump target `seq - window` is at or above the base that
    /// proved too far behind.
    fn collapse_forward_until_fits(&mut self, seq: u64, window: u64) {
        loop {
            let base = self.delivered_through.map_or(0, |t| t + 1);
            if seq - base < window {
                return;
            }
            match self.ahead.pop_first() {
                Some(lowest) => {
                    self.delivered_through = Some(lowest);
                    self.absorb_contiguous_run();
                }
                None => {
                    self.delivered_through = Some(seq - window);
                    return;
                }
            }
        }
    }
}

impl Dedup {
    pub(crate) fn new() -> Self {
        Self::with_window(RECEIVE_WINDOW)
    }

    pub(crate) fn with_window(window: u64) -> Self {
        Self {
            slots: HashMap::new(),
            retired_through: HashMap::new(),
            window,
            forward_collapse: false,
        }
    }

    /// A dedup whose receive window collapses forward over outstanding gaps
    /// instead of rejecting a far-ahead seq — see the `forward_collapse` field
    /// for when that trust is warranted (authenticated mesh peers only).
    pub(crate) fn with_forward_collapse() -> Self {
        Self {
            forward_collapse: true,
            ..Self::with_window(RECEIVE_WINDOW)
        }
    }

    /// The top of the contiguous delivered prefix for `slot`, or `None` before
    /// the slot's first payload arrives.
    pub(crate) fn delivered_through(&self, slot: SlotId) -> Option<u64> {
        self.slots.get(&slot).and_then(|s| s.delivered_through)
    }

    /// Every slot's delivered-through cursor, for slots that have delivered at
    /// least one payload. Unlike the client edge (which tracks its own set of
    /// known peer slots independently, from the turns it produces), a mesh
    /// link's driver has no such side list of "which remote slots does this
    /// session carry" -- the slots this returns are exactly the ones this
    /// `Dedup` instance has actually seen traffic for, which is the complete
    /// and only set the mesh ack-cursor push needs.
    pub(crate) fn delivered_through_all(&self) -> Vec<(SlotId, u64)> {
        self.slots
            .iter()
            .filter_map(|(&slot, s)| s.delivered_through.map(|cursor| (slot, cursor)))
            .collect()
    }

    /// Records `(slot, seq)` as delivered and reports whether it's new, a
    /// duplicate, or out of the receive window.
    pub(crate) fn accept(&mut self, slot: SlotId, seq: u64) -> Delivery {
        let state = self.slots.entry(slot).or_insert_with(|| SlotDedup {
            delivered_through: None,
            ahead: BTreeSet::new(),
        });

        // A seq at or below the contiguous delivered prefix has already been
        // handed to the consumer. Comparing against `delivered_through` directly,
        // rather than a "next expected" seq derived by adding one, is what keeps a
        // prefix top of `u64::MAX` a duplicate when it repeats: there is no seq
        // above `u64::MAX` for a "next expected" to hold, so deriving one would
        // have to clamp back onto `u64::MAX` and misread the repeat as new. A
        // `u64::MAX` prefix is itself a value no real game can reach (that many
        // turns dwarfs any session's lifetime by orders of magnitude); the real
        // gate against it is the relay's resume-cursor anchor validation (see
        // `Link::anchor_receive_window`'s caller in `routing.rs`), which clamps a
        // client-supplied anchor before it can reach here. This is the
        // defense-in-depth backstop for the fold itself.
        if let Some(delivered) = state.delivered_through
            && seq <= delivered
        {
            return Delivery::Duplicate;
        }

        // The lowest seq not yet part of the contiguous delivered prefix. `seq` is
        // strictly above any existing prefix top (checked above), so that top is
        // below `u64::MAX` and this `+ 1` cannot overflow.
        let base = state.delivered_through.map_or(0, |t| t + 1);

        // In-order delivery is the normal case. Advance the prefix directly so
        // it doesn't take a trip through the out-of-order tree (and allocate a
        // node that the contiguous-run fold immediately frees). A zero-sized
        // test window historically rejects even its base, so leave that edge
        // case to the unchanged window logic below.
        if self.window != 0 && seq == base {
            state.advance_contiguous(seq);
            return Delivery::New;
        }

        if seq - base >= self.window {
            if !self.forward_collapse {
                return Delivery::OutOfWindow;
            }
            state.collapse_forward_until_fits(seq, self.window);
        }
        if !state.ahead.insert(seq) {
            return Delivery::Duplicate;
        }
        state.absorb_contiguous_run();
        Delivery::New
    }

    /// Snapshots each distinct valid slot named by payloads already sorted by
    /// `(slot, seq)`. Walking adjacent groups directly avoids first allocating a
    /// set and a separate touched-slot vector. Invalid slots are omitted because
    /// they can never mutate dedup before the packet is rejected.
    ///
    /// `None` means the slot had no entry, so restoring removes an entry created
    /// by the provisional packet rather than leaving empty state behind.
    fn snapshot_sorted_payload_slots(
        &self,
        payloads: &[Payload],
    ) -> Vec<(SlotId, Option<SlotDedup>)> {
        let mut snapshot = Vec::new();
        let mut previous = None;
        for payload in payloads {
            let Ok(slot) = u8::try_from(payload.slot).map(SlotId) else {
                continue;
            };
            if previous == Some(slot) {
                continue;
            }
            previous = Some(slot);
            snapshot.push((slot, self.slots.get(&slot).cloned()));
        }
        snapshot
    }

    /// Restores exactly the slots a prior
    /// [`snapshot_sorted_payload_slots`](Self::snapshot_sorted_payload_slots)
    /// call captured to their prior state, removing an entry that did not exist
    /// when the snapshot was taken. Slots outside the snapshot are untouched.
    pub(crate) fn restore(&mut self, snapshot: Vec<(SlotId, Option<SlotDedup>)>) {
        for (slot, state) in snapshot {
            match state {
                Some(state) => {
                    self.slots.insert(slot, state);
                }
                None => {
                    self.slots.remove(&slot);
                }
            }
        }
    }

    /// Marks `seq` as already delivered for `slot` without a payload being
    /// offered — the receive-window seed for receipts established outside
    /// this connection (a resuming relay's session-lifetime receipt records).
    /// Unlike an offer, this enforces no window bound: seeds come from the
    /// local trusted store, not the wire, and are bounded by that store's own
    /// size.
    pub(crate) fn mark_delivered(&mut self, slot: SlotId, seq: u64) {
        let state = self.slots.entry(slot).or_insert_with(|| SlotDedup {
            delivered_through: None,
            ahead: BTreeSet::new(),
        });
        match state.delivered_through {
            Some(top) if seq <= top => {}
            Some(top) if seq == top + 1 => state.advance_contiguous(seq),
            None if seq == 0 => state.advance_contiguous(0),
            _ => {
                state.ahead.insert(seq);
            }
        }
    }

    /// Bulk [`mark_delivered`](Self::mark_delivered): advances `slot`'s
    /// delivered prefix to at least `through` (never rewinding one already
    /// past it), drops out-of-order entries the new prefix swallowed, and
    /// folds in any run left contiguous above it. Seeding a long contiguous
    /// receipt prefix this way costs O(out-of-order entries), not one tree
    /// operation per seq.
    pub(crate) fn mark_delivered_through(&mut self, slot: SlotId, through: u64) {
        let state = self.slots.entry(slot).or_insert_with(|| SlotDedup {
            delivered_through: None,
            ahead: BTreeSet::new(),
        });
        if state.delivered_through.is_none_or(|top| top < through) {
            state.delivered_through = Some(through);
        }
        match through.checked_add(1) {
            Some(above) => state.ahead = state.ahead.split_off(&above),
            // A prefix at the u64 ceiling has no seq above it to keep.
            None => state.ahead.clear(),
        }
        state.absorb_contiguous_run();
    }

    /// Anchors `slot`'s receive window at `anchor`: sets the delivered prefix top to
    /// `anchor - 1` so the window's base becomes `anchor` and seqs below it are
    /// treated as already delivered. See
    /// [`Link::anchor_receive_window`](super::Link::anchor_receive_window) for why a
    /// re-homed session needs this. A no-op when `anchor` is 0 (the default base is
    /// already 0) or when the slot has already received something — anchoring only a
    /// pristine slot means it never rewinds a prefix that is already forming.
    pub(crate) fn anchor(&mut self, slot: SlotId, anchor: u64) {
        let Some(prefix_top) = anchor.checked_sub(1) else {
            return;
        };
        let state = self.slots.entry(slot).or_insert_with(|| SlotDedup {
            delivered_through: None,
            ahead: BTreeSet::new(),
        });
        if state.delivered_through.is_none() && state.ahead.is_empty() {
            state.delivered_through = Some(prefix_top);
        }
    }

    /// Advances the per-slot retired-through guard, returning whether the cursor
    /// was strictly greater than the last one applied for `slot` (so the caller
    /// should retire). A cursor not strictly advancing is a no-op.
    pub(crate) fn advance_retired_through(&mut self, slot: SlotId, through_seq: u64) -> bool {
        if matches!(self.retired_through.get(&slot), Some(prev) if *prev >= through_seq) {
            false
        } else {
            self.retired_through.insert(slot, through_seq);
            true
        }
    }
}
