//! Relay-side desync detection: the comparator across relays' independent
//! views of the turn stream.
//!
//! This file holds the tuning constants and the value types -- the ordinal
//! placement rules, the per-ordinal report set, and the tracker's own state.
//! The folding logic lives in `tracker`, the log and notice throttles in
//! `rate_limit`.

use super::*;

mod rate_limit;
mod tracker;

pub(crate) use rate_limit::{RateLimitedCounter, TokenBucket};

// ---------------------------------------------------------------------------
// Relay-side desync detection
// ---------------------------------------------------------------------------
//
// SC:R's lockstep sim exchanges a per-turn checksum through the command stream:
// each client emits exactly one `0x37` sync command per outgoing turn once its
// sync check is active. Because every client's Nth sync command covers the same
// simulated interval, two clients whose sims have diverged produce a *different*
// checksum at the same ordinal. Only the client's own sim reacts to a mismatch
// (by dropping the peer over a transport that is inert under this seam), so under
// netcode v2 a desync is invisible to everyone unless something that sees every
// slot's turns compares the checksums itself. That is what [`SyncTracker`] does,
// on the session's authority relay, off the same turn stream the buffer/leave
// consensus already reads.

/// The SC:R sync-command opcode. A 7-byte command emitted once per network
/// turn while the game's sync check is active: `[0]` = this opcode; `[1]` =
/// `(ring_index << 4) | hash_kind` — the high nibble is a 16-entry ring index
/// (advancing `+1 mod 16` per turn) the comparator uses to place each report,
/// the low nibble is the *hash kind* (1 or 2, never a sender/slot id — there
/// is no sender id anywhere in this payload; identity comes from framing),
/// locked to the ring index's parity (even → 1, odd → 2). So `[1]` cycles a
/// fixed 16-value sequence: `0x01, 0x12, 0x21, 0x32, …, 0xF2`. `[2:3]` is
/// `hash16` (the only byte range the comparator compares — see [`SyncValue`]);
/// `[4..7]` is per-sender, vision-masked fog/vision data the comparator never
/// reads (see [`SyncValue`] for why). This is definitive from a BinaryNinja RE
/// of the native `verify_peer_sync_slot`, not inferred from the wire.
///
/// **Startup burst:** the enable path emits the first sync command at ring
/// index 1 (`[1] = 0x12`), and the initial latency-depth flush emits several
/// more `0x37`s stamped *identically* (same ring, same bytes) before the first
/// per-turn record advances the ring — so a client's first few sync commands
/// legitimately repeat ring 1 with identical content. [`SyncTracker::record`]'s
/// same-ordinal duplicate-ignore absorbs this without any special-casing
/// (live-relay confirmed): a repeat lands back at the same placed ordinal via
/// ordinary nibble correction and is recognized as a duplicate. Ring index 0
/// (and therefore our internal ordinal 0, which anchors to whatever ring value
/// a tracker's very first observation happens to report — see
/// [`SyncTracker::join_expected`]) first appears only once the ring wraps,
/// around turn 15.
pub(in crate::consensus) const SYNC_COMMAND: u8 = 0x37;

/// The total length of a `0x37` sync command, mirroring the command-length table.
/// A `0x37` that does not measure this is not the sync command the comparator
/// understands (it never is on validated bytes, but the walk stays defensive).
pub(in crate::consensus) const SYNC_COMMAND_LEN: usize = 7;

/// The length, in bytes, of `hash16` — see [`SyncValue`] for why it's the only
/// comparable range in the 7-byte `0x37`.
pub(in crate::consensus) const SYNC_HASH16_LEN: usize = 2;

/// The `0x37` low nibble's valid hash-kind values (see [`SYNC_COMMAND`]'s
/// layout note): 1 for the even-ring per-unit hash, 2 for the odd-ring
/// game-header/rng hash. Any other low-nibble value is a malformed sync
/// command (defensive — validated bytes shouldn't produce this; see
/// [`SyncTracker::record`]).
pub(in crate::consensus) const SYNC_KIND_UNITS: u8 = 1;
pub(in crate::consensus) const SYNC_KIND_HEADER: u8 = 2;

/// The sync command's ring index is a 16-entry ring, so a slot's true ordinal
/// is congruent to its ring nibble modulo this. The comparator uses it to
/// *place* each report (the ordinal congruent to the ring nearest the slot's
/// expected position), not merely to validate one — see the module docs.
pub(in crate::consensus) const SYNC_RING_MODULUS: u64 = 16;

/// The floor for [`sync_eval_margin`]'s per-session margin, and the value it
/// returns for any buffer policy shallow enough not to need more: how far past
/// an ordinal the frontier (the furthest any compared slot has reached) must
/// move before that ordinal is evaluated. Replaces a same-instant "does
/// everyone agree right now" check, which is unsound once slots can
/// legitimately arrive out of order or lead each other by the latency
/// buffer's depth (see the module docs): the margin instead waits long enough
/// that every live slot's report for the ordinal has had time to show up,
/// whatever order it arrived in. 8 is also where the ring nibble's own
/// correction becomes ambiguous (see the module docs' bound note on steady-state
/// placement), so there is no benefit to a smaller floor.
pub(in crate::consensus) const SYNC_EVAL_MARGIN_MIN: u64 = 8;

/// A defensive backstop, not a live constraint under normal policy: buffer
/// bounds at or above this are absurd enough (half the in-flight window,
/// [`SYNC_WINDOW`]) that the evaluation margin they would imply
/// ([`sync_eval_margin`]) swallows most of the window's slack, so the
/// comparator disables itself for the session rather than risk starving on a
/// buffer depth it was never tuned for. Ordinary policy (today's dev tenant:
/// 1..=10) sits far under it — see [`BufferBounds`] for why depth itself no
/// longer threatens the comparator's correctness the way it used to.
pub(in crate::consensus) const SYNC_ABSURD_BUFFER_MAX: u32 = (SYNC_WINDOW / 2) as u32;

/// The most sync ordinals the comparator keeps in flight per session before
/// evicting the oldest incomplete one. Sized comfortably above what
/// [`sync_eval_margin`] can return under any buffer policy this session would
/// actually run with (see [`SYNC_ABSURD_BUFFER_MAX`]); it is a memory-safety
/// backstop for a slot whose sync stream stalls or stops (its ordinals then
/// never complete and would otherwise accumulate without bound).
pub(in crate::consensus) const SYNC_WINDOW: usize = 64;

/// The evaluation margin for a session whose buffer policy allows up to
/// `bounds_max` turns of latency-buffer depth: a slot's arrivals can lag the
/// frontier by roughly that depth, so a fixed margin under-waits once the
/// policy allows a deep buffer — this scales the margin with the policy
/// instead, floored at [`SYNC_EVAL_MARGIN_MIN`] (which also covers the
/// transport-reordering slack a buffer depth of 0 wouldn't). `+ 2` is a small
/// cushion above the depth itself for that same reordering slack at higher
/// depths.
///
/// The debug assertion is the tripwire for [`SYNC_WINDOW`] going stale: if a
/// future buffer policy ever needs a margin approaching half the window, the
/// window (and the memory budget it implies) needs revisiting right alongside
/// it, not silently.
pub(in crate::consensus) fn sync_eval_margin(bounds_max: u32) -> u64 {
    let margin = (u64::from(bounds_max) + 2).max(SYNC_EVAL_MARGIN_MIN);
    debug_assert!(
        margin.saturating_mul(2) <= SYNC_WINDOW as u64,
        "the evaluation margin ({margin}) should stay comfortably under half the eviction \
         window ({SYNC_WINDOW}); a much larger buffer policy needs the window revisited too",
    );
    margin
}

/// One slot's compared checksum: `0x37`'s `hash16` (`[2:3]`, little-endian) —
/// the *only* comparable byte range in the sync command.
///
/// The native `verify_peer_sync_slot` compares `hash16` and the hash kind
/// straight across peers, but checks `[4]` (a folded fog checksum), `[5]`
/// (fog window length), and `[6]` (a per-player vision bit) *pairwise*
/// against the receiver's own local fog buffer with the sender's player bit —
/// they are per-sender, vision-masked values that legitimately differ between
/// honest players in the same game (each player's fog of war differs). A
/// relay comparing them verbatim across all slots (as an earlier version of
/// this comparator did) manufactures a false desync at ordinary game start —
/// live-observed within the first few ordinals, long before any real
/// divergence. So the comparator never reads `[4..7]` at all; do not
/// "strengthen" this by adding them back.
///
/// **Cross-peer `hash16` equality is guaranteed by the native check's own
/// structure**, not merely observed: `verify_peer_sync_slot` only passes a
/// remote report when its `hash16` equals the value the *receiver* computed
/// from its own simulation for that ring index — so in any healthy game every
/// peer's `hash16` for a given ordinal is provably byte-identical (otherwise
/// SC:R's own detection would already be firing constantly). Whatever term
/// the decompiler's guessed local-player-id shift folds into the hash, it
/// must therefore be shared state, not something that diverges honestly
/// across peers.
pub(in crate::consensus) type SyncValue = [u8; SYNC_HASH16_LEN];

/// A relay-authoritative desync the comparator confirmed: two live slots'
/// checksums disagreed at the same sync ordinal. Pure data the registry layer
/// turns into a [`DesyncNotice`] (stamping correlation ids + a detection
/// timestamp) — the maker itself holds no clock and no tenant refs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDivergence {
    /// The per-slot sync ordinal the disagreement was observed at.
    pub sync_ordinal: u64,
    /// The `game_frame_count` of the turn whose sync command completed the
    /// comparison — a human-meaningful interval. `None` only if that turn carried
    /// no frame (it shouldn't; sync commands flow in-game).
    pub game_frame: Option<u32>,
    /// No strict majority shared one checksum (a 1v1 disagreement, or an even
    /// split), so which sim is authoritative is undecidable from the relay's
    /// view. `diverged` is empty when this is set.
    pub no_majority: bool,
    /// The minority slots that diverged from the agreeing majority, ascending.
    /// Empty when `no_majority`.
    pub diverged: Vec<SlotId>,
}

/// One slot's checksum report at an ordinal: its `hash16`, the hash kind
/// (`SYNC_KIND_UNITS`/`SYNC_KIND_HEADER`) it was reported under, and the frame
/// of the turn it rode.
#[derive(Debug, Clone, Copy)]
pub(in crate::consensus) struct SyncReport {
    pub(in crate::consensus) value: SyncValue,
    pub(in crate::consensus) kind: u8,
    pub(in crate::consensus) game_frame: Option<u32>,
}

/// One compared slot's bookkeeping: where it's expected to report next, and
/// where it first joined the compare set.
#[derive(Debug, Clone, Copy)]
pub(in crate::consensus) struct Member {
    /// This slot's next expected ordinal — the ordinal one past the last one
    /// it placed a report at. Used both as the anchor a new report is
    /// nibble-corrected against, and (via the max across all members) as the
    /// tracker's *frontier*: the furthest any compared slot has reached.
    pub(in crate::consensus) next_expected: u64,
    /// The ordinal this slot first joined the compare set at (its own true
    /// ordinal at first observation, after nibble correction — never
    /// retroactively 0). A member is only ever required to have reported an
    /// ordinal at or after this, so a slot that joins mid-stream (a promotion,
    /// or one whose sync simply started later) is never held responsible for
    /// intervals before it existed.
    pub(in crate::consensus) since: u64,
}

/// The per-session sync-checksum comparator. Lives on the authority relay's
/// [`DecisionMaker`] and is fed one call per turn (via
/// [`DecisionMaker::observe_sync`], called exactly once per distinct
/// `(slot, seq)` turn — see that method's docs), which walks the turn's
/// commands for `0x37`s and hands each here.
///
/// # How ordinals align
///
/// A slot's *sync ordinal* is the count of sync commands seen from it, and the
/// wire only carries the low 4 bits of that count: `ring`, the `0x37`'s
/// `[1] >> 4` (a 16-entry ring, `+1 mod 16` per turn). The low nibble (`[1] &
/// 0xF`) is the hash *kind* (1 or 2 — see [`SYNC_COMMAND`]'s layout note), not
/// a sender/slot id; there is no sender id anywhere in this payload at all.
/// Two properties of the transport make naive "arrival order is the ordinal"
/// counting wrong:
///
/// - **Reordering and lead.** QUIC datagrams are unordered at both the client
///   edge and on each direct mesh link, and a client legitimately runs up to the
///   latency buffer's depth *ahead* of its slowest peer's arrivals at the
///   relay (producing turn `k+1` only requires having *executed* step
///   `k+1 - depth`, not having every peer's turn `k` already in hand). So a
///   slot's own turns can arrive at the relay out of order, and a slot's very
///   first observed sync command can already be several ordinals into its
///   stream.
/// - **Duplication.** Link replacement, resume replay, and slot re-home overlap
///   can present the same turn to the authority more than once. The comparator relies on its caller
///   ([`DecisionMaker::observe_sync`]) handing it each distinct `(slot, seq)`
///   turn exactly once; counting is not idempotent the way `observe_frame`'s
///   monotone max is, so a duplicate that reached this far would silently
///   drift a slot's ordinal.
///
/// The fix is **nibble-corrected placement**, in two flavors depending on
/// whether the reporting slot is already known:
///
/// - **Steady state** (the slot has a [`Member`] entry already): placed at the
///   ordinal congruent to `ring` (mod 16) *nearest the slot's own
///   [`Member::next_expected`]*. This self-heals a reordered pair (a slot's
///   own turns arriving out of sequence) — nearest-match resolves an offset
///   of up to ±7 exactly. Critically, this bound is **transport-level
///   reordering only** (how far out of order the mesh/QUIC can deliver two of
///   *the same slot's* turns), which is far under ±7 regardless of the
///   session's configured buffer depth — a slot's own emission order isn't
///   affected by how much the buffer lets other slots lag behind it. See the
///   bound note below.
/// - **Join** (the slot's first-ever report): the transport-reordering
///   argument above doesn't apply, because there's no prior report from this
///   slot to be "out of order" relative to — its expected ordinal has to come
///   from somewhere else, and that somewhere else (the current *frontier*,
///   the furthest any member has reached) can be arbitrarily far from the
///   join's true ordinal, growing with the session's buffer depth (a deeper
///   buffer lets a fast slot's turns run further ahead of a slow slot's first
///   arrival). Nibble-correcting around the frontier is therefore unsound at
///   depth; instead the join anchors on the reporting turn's
///   `game_frame_count` ([`SyncTracker::join_expected`]): lockstep keeps every
///   client's frame for the same simulated interval within a couple of turns
///   of each other *regardless of buffer depth* (the depth is a session-wide
///   constant that cancels out across clients), so projecting from a recent
///   (ordinal, frame) calibration point and nibble-correcting around *that*
///   estimate lands on the true ordinal at any realistic depth. Falls back to
///   frontier+nibble when no frame is available to anchor on (either the
///   joining report carries none, or the tracker has no calibration yet), and
///   further to the ring's own face value when there is no frontier either
///   (the tracker's very first observation for the session at all — the
///   promotion-mid-stream case, where there is no earlier context of any
///   kind — see [`DecisionMaker::set_authority`]'s promotion reset).
///
/// Either way, a slot's join ordinal is tracked as [`Member::since`], so
/// nothing is retroactively required of it for ordinals before that. A
/// placement that lands below `base_ordinal` (already-retired territory —
/// possible right after a correction, or after an eviction) is dropped
/// silently; that one comparison is lost, which is acceptable.
///
/// **Bound note:** nibble correction is sound only while the gap between the
/// value it corrects around and the report's true ordinal stays under 8 (half
/// the 16-entry ring) — beyond that the nearest-match is ambiguous or wrong.
/// For steady state that gap is transport reordering, bounded independent of
/// buffer depth (see above). For a join, frame-anchoring keeps the gap to
/// lockstep's cross-client frame skew (a couple of turns) rather than the
/// buffer depth itself, so depth no longer threatens correctness either — see
/// [`BufferBounds`] for this from the policy side. [`SYNC_ABSURD_BUFFER_MAX`]
/// is the remaining backstop, for a policy so deep it stops being a
/// buffer-tuning question at all.
///
/// # What retires an ordinal
///
/// An ordinal is evaluated once the frontier has moved at least
/// [`sync_eval_margin`] past it (long enough that every live slot's report for
/// it, however reordered or however deep the buffer let it lag, should have
/// arrived) **and** every member whose `since` is at or before it has
/// reported it. A member that hasn't reported yet despite the margin is rare
/// but possible (a genuinely stalled link); [`SYNC_WINDOW`] eviction is the
/// backstop that bounds the wait.
///
/// A retired ordinal whose reports all agree retires silently. One with a
/// disagreement fires exactly one [`SyncDivergence`]: the strict-majority value
/// is authoritative and every other slot is the diverged minority (dropped from
/// the compare set, so the survivors keep being watched and a later second
/// divergence fires again at its own ordinal); with no strict majority the
/// comparator reports `no_majority` and goes dormant (the truth is unrecoverable
/// for the session). A slot that departs or is dropped stops being required.
///
/// # Bounded state
///
/// In-flight ordinals are capped at [`SYNC_WINDOW`]; a slot that stalls leaves
/// its ordinals forever-incomplete, so the oldest are evicted (with a
/// rate-limited warn naming who failed to report) rather than growing without
/// bound. Comparator state is reset wholesale on authority promotion — a real
/// desync diverges every interval, so the next interval after promotion catches
/// it, and transferring per-ordinal hash state across a handoff would be pure
/// complexity for a one-interval blind spot.
#[derive(Debug, Default)]
pub(in crate::consensus) struct SyncTracker {
    /// Once set, the comparator has reached a verdict it cannot refine (a
    /// no-majority split, a majority event that left fewer than two comparable
    /// slots, or absurd buffer bounds) and no-ops for the rest of the session.
    pub(in crate::consensus) dormant: bool,
    /// The lowest ordinal still awaiting evaluation; everything below has retired
    /// (agreed, fired, or been evicted).
    pub(in crate::consensus) base_ordinal: u64,
    /// Each compared slot's bookkeeping. The key set *is* the compare set: a
    /// slot enters on its first sync command and leaves on departure or as a
    /// dropped minority.
    pub(in crate::consensus) members: HashMap<SlotId, Member>,
    /// Reports awaiting a complete ordinal, keyed by ordinal then slot.
    pub(in crate::consensus) pending: BTreeMap<u64, HashMap<SlotId, SyncReport>>,
    /// The lowest-ordinal **corroborated** `(ordinal, median_frame)` calibration
    /// point, paired with `corroborated_latest` to derive the frames-per-ordinal
    /// rate for frame-anchored join placement (see [`Self::join_expected`]). A
    /// point is corroborated only once at least [`SYNC_CORROBORATION_MIN`]
    /// **distinct** slots have reported the same ordinal with a frame — the
    /// median of their frames, which a single attacker (controlling one slot)
    /// cannot move. This replaces the earlier single-slot-sourced calibration a
    /// lone slot could swing to shift an honest joiner a full ring cycle. Kept
    /// independent of `pending`/`members` so it survives ordinal retirement.
    pub(in crate::consensus) corroborated_first: Option<(u64, u32)>,
    /// The highest-ordinal corroborated `(ordinal, median_frame)` point, paired
    /// with `corroborated_first` for the rate and used as the projection anchor.
    pub(in crate::consensus) corroborated_latest: Option<(u64, u32)>,
    /// Rate-limit counter for the placement-correction debug log (a nonzero
    /// nibble correction — a reorder, a lead, or a join). Routine (every game
    /// start corrects the first ordinal after a join), so it logs at debug.
    pub(in crate::consensus) corrections: RateLimitedCounter,
    /// Rate-limit counter for the same-ordinal conflicting-value warn (a slot
    /// reporting two different checksums for the same placed ordinal — an
    /// honest client never does this).
    pub(in crate::consensus) duplicate_warns: RateLimitedCounter,
    /// Rate-limit counter for the malformed-hash-kind warn (the `0x37`'s low
    /// nibble is neither 1 nor 2 — validated bytes shouldn't produce this;
    /// see [`SyncTracker::record`]).
    pub(in crate::consensus) malformed_kind_warns: RateLimitedCounter,
    /// Rate-limit counter for the kind/parity-mismatch warn (a report's hash
    /// kind disagrees with its placed ordinal's expected parity — an
    /// alignment-drift indicator, not a desync; see [`SyncTracker::evaluate`]).
    pub(in crate::consensus) kind_parity_warns: RateLimitedCounter,
    /// Rate-limit counter for the window-eviction (stalled-slot) warn.
    pub(in crate::consensus) evict_warns: RateLimitedCounter,
    /// Rate-limit counter for the multiple-sync-commands-in-one-turn warn (an
    /// honest client emits exactly one `0x37` per outgoing turn; more than one
    /// is the flooding lever a malicious client would use to inflate its own
    /// frontier and seed join-placement calibration — see
    /// [`DecisionMaker::observe_sync`]).
    pub(in crate::consensus) multi_sync_warns: RateLimitedCounter,
    /// Rate-limit counter for the deferred-join-placement warn (a joining slot
    /// that can't be safely placed yet — no corroborated rate and the frontier is
    /// more than a ring cycle ahead; its report is dropped and retried).
    pub(in crate::consensus) defer_warns: RateLimitedCounter,
    /// Scratch buffer for [`Self::update_corroboration`]'s per-ordinal median:
    /// cleared and refilled on every call rather than reallocated, since it
    /// runs on every accepted sync report (the per-turn path).
    pub(in crate::consensus) frame_scratch: Vec<u32>,
}

/// The number of **distinct** slots that must report the same ordinal (each with
/// a frame) before that ordinal's `(ordinal, median_frame)` becomes a
/// corroborated calibration point for frame-anchored join placement. Three is the
/// smallest count whose **median** a single attacker — who controls exactly one
/// slot — provably cannot move: with ≤1 outlier among ≥3 values the median is
/// still an honest slot's frame. This is what lets the join projection be
/// tolerance-free (no "how close counts as agreeing?" parameter to tune).
pub(in crate::consensus) const SYNC_CORROBORATION_MIN: usize = 3;

/// The hash kind SC:R's native sync check ties to a ring index's parity: even
/// → [`SYNC_KIND_UNITS`] (the per-unit hash), odd → [`SYNC_KIND_HEADER`] (the
/// game-header/rng hash). A placed ordinal is always congruent to its true
/// ring index modulo 16 ([`SYNC_RING_MODULUS`]), and mod-16 preserves parity
/// (16 is even), so an honestly-placed report's ordinal parity exactly
/// predicts its kind — this is what [`SyncTracker::evaluate`]'s kind/parity
/// cross-check tests.
pub(in crate::consensus) fn expected_kind_for_ordinal(ordinal: u64) -> u8 {
    if ordinal.is_multiple_of(2) {
        SYNC_KIND_UNITS
    } else {
        SYNC_KIND_HEADER
    }
}
