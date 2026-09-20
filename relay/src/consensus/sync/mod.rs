//! Relay-side desync detection: the comparator across relays' independent
//! views of the turn stream.
//!
//! This file holds the tuning constants, canonical-ordinal comparison state,
//! and value types. `turns` establishes canonical ordinals, `tracker` folds
//! reports, and `rate_limit` owns warning throttles.

use super::*;

mod rate_limit;
mod tracker;
mod turns;

pub(in crate::consensus) use turns::{SyncCommand, SyncGap, SyncTurn, SyncTurns};

pub(crate) use rate_limit::{RateLimitedCounter, TokenBucket};

// ---------------------------------------------------------------------------
// Relay-side desync detection
// ---------------------------------------------------------------------------
//
// SC:R's lockstep simulation produces checksum commands in native sync
// generations. A command is staged in an outgoing buffer, while the native
// recorder advances after that buffer is flushed. A flush can therefore repeat
// a staged generation, and a buffer shrink can omit one from later emission.
// The legacy four-bit ring identifies the native generation modulo 16 but
// cannot describe omitted generations. With `Payload::sync_generation`, the
// origin supplies the absolute native generation that produced the staged
// checksum; `turns` validates that bounded, per-origin claim before `tracker`
// compares reports. That lets the authority relay compare every slot's
// independent view without assigning a shared emission ordinal.

/// The SC:R sync-command opcode. A 7-byte command staged in the outgoing
/// buffer while the game's sync check is active: `[0]` = this opcode; `[1]` =
/// `(ring_index << 4) | hash_kind`. The high nibble is the native generation
/// modulo the 16-entry ring; it is not an emitted-turn counter. The low nibble
/// is the *hash kind* (1 or 2, never a sender/slot id — there is no sender id
/// anywhere in this payload; identity comes from framing), locked to the ring
/// index's parity (even → 1, odd → 2). So `[1]` cycles a fixed 16-value
/// sequence: `0x01, 0x12, 0x21, 0x32, …, 0xF2`. `[2:3]` is `hash16` (the
/// only byte range the comparator compares — see [`SyncValue`]); `[4..7]` is
/// per-sender, vision-masked fog/vision data the comparator never reads (see
/// [`SyncValue`] for why). This is definitive from a BinaryNinja RE of the
/// native `verify_peer_sync_slot`, not inferred from the wire.
///
/// **Startup burst:** the enable path's first active command uses ring index 1
/// (`[1] = 0x12`), and the initial latency-depth flush can repeat that staged
/// generation before a later native record advances. `SyncTurns` maps repeated
/// generations to one canonical ordinal, and `SyncTracker` keeps the first
/// report for a slot at that ordinal.
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

/// The sync command's native generation ring has 16 positions. Legacy turns
/// unwrap only a repeat or one-step advance; enhanced turns verify the absolute
/// generation against this modulus before `SyncTracker` compares them.
pub(in crate::consensus) const SYNC_RING_MODULUS: u64 = 16;

/// The floor for [`sync_eval_margin`]'s per-session margin: how far past an
/// ordinal the frontier must move before the comparator trusts its report set
/// as complete. It covers transport reordering even for shallow buffers.
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

/// One origin's coverage at a checksum ordinal. A skipped generation advances
/// only that origin's coverage; it never invents a checksum value.
#[derive(Debug, Clone, Copy)]
pub(in crate::consensus) enum SyncObservation {
    Report(SyncReport),
    Skipped,
}

/// One compared slot's canonical ordinal progress. A slot joins the compare
/// set on its first ordered sync report and is never required before `since`.
#[derive(Debug, Clone, Copy)]
pub(in crate::consensus) struct Member {
    /// One past the greatest canonical ordinal this slot has reported. It is
    /// monotone even when a late older report is discarded.
    pub(in crate::consensus) next_expected: u64,
    /// The first canonical ordinal this slot reported to this comparator.
    pub(in crate::consensus) since: u64,
}

/// The authority's per-ordinal sync-checksum comparator. The ordered source
/// assigns canonical ordinals before reports reach this type, so this state
/// contains only comparison data and may reset independently on promotion.
#[derive(Debug, Default)]
pub(in crate::consensus) struct SyncTracker {
    /// Once set, the comparator has reached a verdict it cannot refine (a
    /// no-majority split, a majority event that left fewer than two comparable
    /// slots, or absurd buffer bounds) and no-ops for the rest of the session.
    pub(in crate::consensus) dormant: bool,
    /// Whether this reset instance has accepted its first canonical ordinal.
    /// This distinguishes a fresh promotion from a compare set that later became
    /// empty after it had already advanced.
    pub(in crate::consensus) initialized: bool,
    /// The lowest ordinal still awaiting evaluation; everything below has retired
    /// (agreed, fired, or been evicted).
    pub(in crate::consensus) base_ordinal: u64,
    /// Each compared slot's bookkeeping. The key set is the compare set: a slot
    /// enters on its first sync command and leaves on departure or as a dropped
    /// minority.
    pub(in crate::consensus) members: HashMap<SlotId, Member>,
    /// Origin coverage awaiting a complete ordinal, keyed by ordinal then slot.
    pub(in crate::consensus) pending: BTreeMap<u64, HashMap<SlotId, SyncObservation>>,
    /// Minorities confirmed divergent by this tracker instance. Their queued
    /// reports cannot recreate them after the verdict.
    pub(in crate::consensus) excluded: HashSet<SlotId>,
    /// Rate-limit counter for conflicting values from one slot at one ordinal.
    pub(in crate::consensus) duplicate_warns: RateLimitedCounter,
    /// Rate-limit counter for malformed hash-kind nibbles.
    pub(in crate::consensus) malformed_kind_warns: RateLimitedCounter,
    /// Rate-limit counter for reports whose kind disagrees with ordinal parity.
    pub(in crate::consensus) kind_parity_warns: RateLimitedCounter,
    /// Rate-limit counter for the window-eviction (stalled-slot) warn.
    pub(in crate::consensus) evict_warns: RateLimitedCounter,
    /// Rate-limit counter for extra sync commands packed into one turn.
    pub(in crate::consensus) multi_sync_warns: RateLimitedCounter,
}
/// The hash kind SC:R's native sync check ties to the canonical ordinal's
/// parity: even → [`SYNC_KIND_UNITS`] and odd → [`SYNC_KIND_HEADER`]. A report
/// with a mismatched kind is excluded from the comparison.
pub(in crate::consensus) fn expected_kind_for_ordinal(ordinal: u64) -> u8 {
    if ordinal.is_multiple_of(2) {
        SYNC_KIND_UNITS
    } else {
        SYNC_KIND_HEADER
    }
}
