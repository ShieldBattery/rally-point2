//! The latency-buffer decision-maker: the relay-side core of the runtime
//! consensus authority.
//!
//! This is the *decision* half of the buffer consensus -- which relay decides,
//! from what data, and the control law that turns network conditions into a
//! buffer-size change. The [`DecisionMaker`] itself is pure and synchronous: no
//! I/O, no async, no locks of its own. It is fed conditions and game-frame
//! observations by its caller and returns a [`Decision`] describing what (if
//! anything) to broadcast; the registry-level helpers at the bottom of this
//! module add the locking and logging the turn path needs.
//!
//! The broadcast rides the turn stream as envelope metadata: a decision queues
//! a directive that [`active_directive`](DecisionMaker::active_directive) hands
//! to the caller for every turn it forwards, which sets it on each payload's
//! `buffer_directive` field, until the whole session has passed the directive's
//! apply frame. It is deliberately *not* a command in the SC:R byte stream -- a
//! native latency command would cap the buffer at the game's built-in range and
//! would have to be forged into a slot's turn, and a client applies one turn
//! per remote player per step, so an extra command can't just be handed over.
//! Riding the envelope, the buffer has no ceiling and the game applies it out
//! of band, off the turn it arrives on. The value, the frame to apply it at,
//! and the decision seq that orders it are all this module produces; the caller
//! sets the wire field.
//!
//! # Authority and authority handoff
//!
//! The relays sit in a fixed priority order; the highest still serving live
//! players is the decision-maker. (Multiple relays serving one game is the
//! *normal* case -- players in different regions each connect to a nearby
//! relay, and the mesh carries turns between them. "Handoff" is specifically
//! when the authority relay drops out -- its players have all left -- and
//! authority falls to the next relay in the order, with no coordinator
//! round-trip.) Authority is an **injected input** to this core: the caller
//! (`MeshControl`) computes the verdict from the coordinator descriptor's
//! priority order (relay-id order is only the fallback for a descriptor that
//! carries none) and the live-player presence the relays track among
//! themselves -- the first relay in that order still serving players wins --
//! and re-injects it via [`DecisionMaker::sync`] on every descriptor push and
//! every presence change, so the verdict follows the relay set as players come
//! and go with no coordinator round-trip for handoff. A promoted relay's
//! decisions must outrank everything the previous authority broadcast; that is
//! what [`observe_directive`](DecisionMaker::observe_directive) is for.
//!
//! # The target formula
//!
//! The buffer is sized to the worst-case one-way delivery time -- the time for
//! a turn to travel from its sender, through the relay (and the mesh, for
//! cross-relay paths), to the slowest receiver, including loss recovery. The
//! formula:
//!
//! ```text
//! target = ceil(pairwise_path / turn_duration)
//!        + max(ceil(loss_risk / turn_duration), burst_turns)
//! ```
//!
//! Path and loss are `ceil`'d separately because loss recovery is quantized to
//! whole turns: a re-carry rides the next packet, exactly one turn_duration
//! later (packets are one turn apart). So a lost turn's delivery is
//! `path + N ** turn_duration` -- a whole number of turns *added* to the path
//! turns, not a continuous addition absorbed into the path's `ceil` slack.
//! Combining them into one `ceil` would absorb the loss term into the path's
//! fractional remainder and under-provision -- e.g. at 150ms path with one
//! re-carry, delivery is `41666 + 150000 = 191666us` needing `ceil(191666/41666)
//! = 5` turns; the separated form gives `4 + 1 = 5` (correct), a combined form
//! gives `ceil(157500/41666) = 4 = 166664us < 191666` (stalls on a single loss).
//!
//! At low latency with no loss, the target is just `ceil(path / turn_duration)`
//! -- the loss term is 0 and adds nothing. The minimum is 1 (any positive RTT
//! rounds up), not 2; the separation only adds turns when there is actual loss
//! to recover from.
//!
//! - **`pairwise_path = (eff_RTT_A + eff_RTT_B) / 2`** -- the worst one-way
//!   path for the two slowest players. Each slot's *effective RTT* is its
//!   QUIC RTT plus the one-way mesh hop from the authority relay to its home
//!   relay (0 for local slots, the relay-pair RTT for remote slots). A turn
//!   from player A to player B travels `eff_RTT_A/2 + eff_RTT_B/2`, so the
//!   worst pair is the two highest-eff-RTT players. Using the actual pairwise
//!   path (not `max_eff_RTT`) avoids overshooting when only one player has
//!   high latency -- lower buffer means less input delay, which feels better.
//! - **`loss_risk = max over slots of (loss_rate * eff_RTT)`** -- burst loss
//!   on a high-latency link is worse than on a low-latency one: more packets
//!   are in flight during the burst window, so more consecutive re-carries
//!   can be lost. The term scales with both loss rate and effective RTT,
//!   capturing that 5% loss on a 300ms link is more dangerous than 5% on 50ms.
//!   The rate itself is the worse of two windows over the slot's cumulative
//!   counters -- a short *attack* window (~1s) that reacts to a fresh burst,
//!   and a long *memory* window (~8s) that keeps pricing the loss in after it
//!   subsides. Random loss produces loss-free stretches many times longer
//!   than its mean gap; an instantaneous rate would zero the term in every
//!   such gap and the target (and with it the buffer) would flap.
//! - **`burst_turns`** -- the longest observed link *blackout* (consecutive
//!   sample intervals that lost every packet) within the loss memory, capped
//!   at a few turns. Real loss is mostly bursty -- queue overflows and wifi
//!   fades drop runs of consecutive packets -- and the mean-rate term
//!   structurally understates it: a 30ms blackout every 300ms is ~10% loss
//!   but delays the turns inside it by the blackout's whole duration in
//!   re-carries. The run length *is* that duration in turns.
//! - **The two loss terms fold with `max`, not a sum.** Both estimate one
//!   quantity -- the delivery delay the worst link's loss adds -- and the
//!   burst term exists precisely *because* the mean-rate term reads that
//!   quantity badly on bursty loss. A correction is not additive with the
//!   thing it corrects, and at the limit the two are visibly one event: a run
//!   of fully-dark intervals is exactly what drives the windowed rate to
//!   saturation, so summing there charges the buffer twice for one dark
//!   stretch. Taking the worse keeps whichever estimator is reading the
//!   current loss shape correctly -- the rate under uniform loss, the run
//!   under bursts -- and, the two being strongly correlated, it is also the
//!   markedly quieter signal: the target moves less often, so the buffer does
//!   too.
//! - **Both loss terms read only *flowing* traffic.** Conditions samples are
//!   receive-triggered, so a receive gap of a second or more is a stall or
//!   outage -- lateness no depth inside the bounds could absorb -- and the
//!   counters accumulated across it (flush re-carries and probes into a dead
//!   path, declared lost only once acks resume) are excluded from the loss
//!   windows rather than differenced in as weather, and the gap leaves no
//!   burst trace -- cumulative counters cannot tie a declaration to the
//!   packets that died, so no sound dead-path arbiter exists at this layer,
//!   and a recurring fade is priced when it shows on flowing traffic
//!   instead. Without the exclusion, a fade
//!   shorter than the QUIC idle timeout would be punished *harder* than one
//!   long enough to reconnect, whose epoch reset wipes the windows clean.
//! - **`turn_duration`** -- one game step at 24 turns/sec == ~41.7ms. Each
//!   buffer turn adds one step of dispatch delay, so the buffer is measured
//!   in turns.
//!
//! The `ceil` on the path naturally gives a minimum of 1 for any positive RTT
//! (a turn always has to travel some distance), so no separate floor is needed.
//!
//! # Local vs. remote slots
//!
//! The decision-maker distinguishes slots whose conditions it observes directly
//! (home clients on this relay) from slots whose conditions arrive via the mesh
//! sidecar (home clients on a peer relay). A remote slot's effective RTT
//! includes the mesh hop -- the one-way relay-pair RTT from the authority to
//! the slot's home relay -- so cross-relay paths are sized correctly. The caller
//! supplies the mesh RTT when ingesting remote conditions (sampled from the
//! `MeshLink`'s QUIC connection stats); the transport doesn't carry it in the
//! sidecar because the mesh RTT is a property of the relay-pair, not of any
//! individual client's link.
//!
//! **N-relay gap.** The single `mesh_rtt_us` parameter models the authority's
//! direct link to one peer. For N>2 relays, a turn between two *remote* slots on
//! different peer relays traverses their direct peer1<->peer2 link, whose RTT
//! the authority does not observe. A robust extension would distribute
//! relay-pair RTT observations explicitly. Until then, this simplification is
//! exact for two relays and approximate for remote-to-remote pairs in a larger
//! full mesh.
//!
//! # Jitter awareness
//!
//! `rtt_us` from QUIC is a smoothed *mean*. In lockstep a single turn
//! arriving above the mean stalls every player, so the buffer must cover a
//! high percentile of latency, not the average. Each slot keeps a ring
//! buffer of recent RTT samples (~1.3s at 24/sec) and the decision-maker uses
//! the **recent max** as a crude high-percentile estimator. A future
//! improvement would expose QUIC's RTTVAR in the conditions sidecar for a
//! more principled variance term; the recent-max is a practical stand-in that
//! catches the spikes that cause stalls.
//!
//! # Raise fast, lower slow (asymmetric dwell)
//!
//! When the target exceeds the current buffer, the decision-maker **jumps to
//! the target immediately, with no dwell** -- a player hurting now needs the
//! right buffer, and you can't dwell through a stall. When the target drops
//! below the current buffer, a shrink must be both **paced** and **earned**.
//! Paced: at least `min_dwell_turns` (120 ~ 5s at 24/sec) since the last
//! decision, so a multi-step descent walks down gradually. Earned: a shrink
//! never takes the buffer below the target's **trailing high-water mark**
//! (its maximum over the last `shrink_lookback_turns`, ~25s). The floor is
//! what actually prevents flapping: noisy conditions make the target *recur*
//! at its peak rather than sit on it, so a dwell alone still shrinks at every
//! dwell boundary (the target is momentarily below when it expires) and is
//! re-raised at the next peak -- changing the buffer on exactly the dwell
//! cadence, the worst outcome for players trying to acclimate to the game's
//! input latency. Parking at the high-water instead keeps the buffer still
//! for as long as the noise keeps recurring, and once conditions genuinely
//! improve the peaks age out of the lookback and the buffer walks down one
//! dwell per step -- deliberately biased toward "a little too high for a
//! little too long" over micro-stutter, but bounded (lookback + a dwell per
//! step), never stuck. Raises, by contrast, fire on the first worsening
//! sample.
//!
//! The floor and the dwell both act in quantized target space, which cannot
//! see how close the path sits to a whole-turn boundary: at 99% of a bucket
//! the path `ceil` leaves under a millisecond of real slack, and
//! sub-millisecond RTT noise flips the target a full turn -- a flap magnet
//! the turn-space machinery can only punish after the fact. Shrinks are
//! therefore also gated in *continuous* space: the lower branch evaluates a
//! target whose path term carries [`ControlLaw::shrink_headroom_us`] of
//! margin, so a shrink fires only when the path clears the lowered size's
//! capacity with real headroom, never on a favorable rounding of a path
//! riding the boundary. Raises always use the unmargined target -- headroom
//! must never delay a raise.
//!
//! One lookback cannot fit every noise pattern: peaks recurring just *past*
//! it would still bait a shrink that the next peak disproves. That gets
//! **edge probation**: a shrink landing exactly on the floor whose departed
//! level is promptly re-raised burns the edge, and the next floor-level
//! shrink must then clear a 4x-lookback peak-free window (~100s). One
//! strike -- the law may be wrong about a noisy edge once per episode before
//! it parks. Probation never gates shrinks landing safely *below* the floor
//! (the target regime falling outright), so genuine recovery stays fast; the
//! burn itself expires only after a long burn-free stretch.
//!
//! # Application at an agreed future turn
//!
//! A buffer change every client must apply identically is scheduled at a
//! future `game_frame_count` (the consensus coordinate), not applied at the
//! decision instant: the turn in flight when the decision is made is already
//! past the point where a mid-turn latency change is safe.
//!
//! The coordinate is the **minimum** of the per-slot frames observed from
//! validated turns -- the slowest participant's progress, which is what
//! lockstep actually advances by. Using the minimum (never a single payload's
//! claim) is also the defense against a hostile client: `game_frame_count` is
//! client-asserted and unvalidated, so a slot reporting an absurdly large
//! frame only inflates *its own* per-slot observation -- the session
//! coordinate stays pinned to the honest slots, and the worst a lone attacker
//! can do is under-report and stall decisions, which lockstep already lets it
//! do by stalling outright. (A single-slot session's coordinate is that slot's
//! own claim, but with no second client there is nobody to diverge from.)
//!
//! The change is scheduled a horizon ahead of that coordinate: the current
//! buffer span plus a fixed margin. The relay's view of the slowest client
//! lags by roughly the cushion (frames are observed off turns that took the
//! client->relay path), and the fastest client runs ahead of the slowest by at
//! most the cushion, so the horizon scales with the buffer rather than being a
//! constant that a large cushion could outrun.

pub mod delivery;
pub mod phase;

#[cfg(test)]
mod buffer_law_sim;

mod law;
mod maker;
mod ops;
mod registry;
mod slot;
mod sync;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rally_point_proto::commands::command_length;
use rally_point_proto::control::{
    BufferBounds, DepartedSlot, DepartureKind, DepartureNotice, DesyncNotice, DivergedSlot,
    GAME_SYNC_SAFE_BUFFER_MAX, ResultEcho, ResultNotice, SessionStartedNotice, SlotConnectedNotice,
    SlotStartedNotice, TenantId,
};
use rally_point_proto::ids::{GameFrameCount, RelayId, SessionId, SlotId};
use rally_point_proto::messages::{
    BufferDirective, LeaveDirective, LinkConditions, RegionLabel, SlotConditions,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::observability::flight_recorder::BufferDecisionInputs;
use crate::routing::SessionKey;

// Every submodule of this one reaches the rest of the module's internals
// through these globs: each file's own `use super::*` picks them up, so an item
// keeps resolving by its bare name wherever it was written.
use law::*;
use ops::*;
use registry::*;
use slot::*;
use sync::*;

pub use law::ControlLaw;
pub use maker::{DecisionMaker, DepartureStamps, RecordedDeparture, SilentSlot};
pub use ops::{
    FinalizeOutcome, FrameRegression, SILENCE_CHECK_INTERVAL, activate_connection_epoch,
    active_directive, adopt_session_start, claim_close_report, claim_close_report_with_maker,
    commanded_phase_delay, connection_epoch_matches, decide_abandoned_departures, decide_leave,
    decided_slots, departure_epoch, deregister_maker, finalize_drop, finalized_drops_enabled,
    has_reconnectable_departure, has_undecided_departure, ingest_arrival_phase,
    ingest_local_condition, ingest_local_conditions, ingest_remote_conditions, is_authority,
    leave_reconcile, leave_schedulable, maker_exists, mark_session_started,
    maybe_release_region_labels, normalize_observed_leave, note_forward_advance,
    note_phase_applied, note_slot_present, observe_delivery, observe_directive, observe_frame,
    observe_leave, observe_sync, observe_turn_frame, reachable_frame, record_departure,
    record_departure_for_epoch, record_peer_slot_started, record_result, record_slot_connected,
    record_slot_started, reevaluate_session_start, reinstate_slot, released_region_labels,
    remove_slot_for_epoch, reopen_close_report, result_for, retained_load_state,
    retained_load_states, run_silence_watch, session_closed, session_e2e,
    session_initial_buffer_turns, session_started, set_authority, set_own_relay_id,
    set_region_labels, set_session_shape, slot_departed, slot_frame, slot_has_started, slot_homed,
    slot_leave_decided, slot_strictly_homed, started_home_slots, started_session_slot_count,
    sync_maker,
};
pub use registry::{
    DecisionMakers, RelayNotice, RetainedLoadState, new_decision_makers,
    new_decision_makers_with_region_delay,
};
pub use sync::SyncDivergence;

pub(crate) use ops::{admit_reconnect, mark_connection_down, record_departure_for_epoch_outcome};
pub(crate) use slot::{ConnectionActivation, DepartureRecordOutcome, ReconnectAdmission};
pub(crate) use sync::{RateLimitedCounter, TokenBucket};

/// How long a relay withholds the session's relay → region labels from its
/// clients, measured on the relay's own clock from the moment it latched the
/// session started.
///
/// The labels place every member geographically, so a client that held them
/// early could see its opponents' regions and abandon the match while the game
/// had barely begun. Withholding them for a stretch of real gameplay is what
/// makes reading them cost something.
///
/// **Measured in wall-clock, never in game frames.** A turn's
/// `game_frame_count` is a client-asserted claim, and this relay delivers turns
/// that originated at *other* relays, so a single client inflating its own claim
/// would otherwise open this gate on every relay serving the session — its
/// opponents' home relays included. Nothing a client sends can advance a relay's
/// clock, so the gate has no client-controllable input at all. It is equally
/// proof against the opposite abuse: the gate is not tied to the session's
/// slowest slot, so no one slot can hold the labels back any longer than it can
/// hold back the visibly-stalled game itself.
///
/// Ten seconds sits comfortably past any "misclicked ready" moment and far short
/// of a game whose outcome is decided.
///
/// The clock is per-relay, and a relay that takes over a running session
/// (a re-home replacement) latches started when it adopts the session, so it
/// waits this out again before releasing anything. That is a deliberate
/// trade-off, not an oversight: clients keep the map they already hold, so the
/// only cost is that a map *changed* by the re-home reaches them one delay
/// later, and the alternative — trusting an inherited start time a fresh relay
/// cannot verify — would reintroduce an input the session's clients influence.
pub const REGION_LABEL_RELEASE_DELAY: Duration = Duration::from_secs(10);

/// The native `pending_leave_reason` value for an unclean drop
/// (`strPLAYER_WAS_DROPPED`). Any other nonzero reason renders as "player left".
/// A departure is classified for the coordinator by comparing against this
/// value, so the one source of truth lives here alongside the leave decision.
pub const LEAVE_REASON_DROPPED: u32 = 0x4000_0006;

/// The native SC:R `pending_leave_reason` value a voluntary quit produces — any
/// value other than [`LEAVE_REASON_DROPPED`] renders "player left", so this is the
/// canonical "left" reason the relay uses when it must synthesize a left departure
/// (a coordinator-seeded rehome departure whose kind is `Left`). The single source
/// of truth, re-used by `routing`.
pub const LEAVE_REASON_LEFT: u32 = 3;

/// The largest end-of-game result payload a session's decision-maker will
/// retain. The bytes are the tenant's opaque serialized result, forwarded
/// unparsed; this cap bounds what one slot's report can cost, independent of
/// which path admitted it — a client's own report on the control stream, or a
/// peer relay's `SlotDeparted` fold-in over the mesh. Owned here, next to the
/// state it bounds, so every admission point can enforce it without a
/// dependency on the routing layer.
pub const MAX_GAME_RESULT_PAYLOAD_LEN: usize = 4096;

/// Whether a result payload is one the relay should retain: non-empty (an
/// empty payload is the wire sentinel for "no result reported" -- see
/// `SlotDeparted.result_payload` -- so a real report can never be zero bytes)
/// and no larger than [`MAX_GAME_RESULT_PAYLOAD_LEN`]. Shared by every point
/// that admits a result into a decision-maker's state, so the bound holds no
/// matter which path -- a client's own report or a peer's mesh fold-in --
/// produced the payload.
fn result_payload_is_valid(payload: &[u8]) -> bool {
    !payload.is_empty() && payload.len() <= MAX_GAME_RESULT_PAYLOAD_LEN
}

/// The buffer size in turns. StarCraft's `net_user_latency` is the added
/// user latency (0/1/2 in the native game); the decision-maker may widen past
/// 2 via the same synced mechanism, so this is a plain `u32` rather than the
/// native 0--2 enum. One unit == one turn of dispatch delay applied identically
/// on every client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BufferSize(pub u32);

/// Who is the decision-making authority for this session.
///
/// The relays sit in a fixed priority order; the highest still serving live
/// players is the decision-maker. Handoff -- when the authority relay drops
/// out and authority falls to the next relay -- needs the coordinator-assigned
/// priority order and a presence signal, both of which land with the mesh
/// wiring + coordinator (Phase 3). Until then, authority is an injected input
/// so the decision core runs unchanged once peer conditions flow in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// This relay is the decision-maker. The relay decides from its own
    /// home-client conditions plus peer-relay conditions forwarded across the
    /// mesh.
    SelfRelay,
    /// Another relay is the decision-maker. This relay forwards conditions to
    /// the authority across the mesh but makes no decision itself.
    Peer,
}

/// One shrink decision, retained until the next decision so a prompt re-raise
/// can be recognized as disproving it (see `DecisionMaker::edge_burned`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShrinkRecord {
    /// The buffer level the shrink departed.
    from: u32,
    /// The session frame the shrink fired at.
    frame: u32,
}

/// A pending buffer-size change the decision-maker has decided to apply.
///
/// The change targets a future `game_frame_count` -- every client applies it at
/// the same simulated step, so the buffer moves identically for everyone. The
/// `applied_frame` is scheduled a horizon ahead of the session's slowest
/// observed frame so the broadcast reaches every client before that frame
/// arrives.
///
/// This is the decision the control law reached. The change queues a directive
/// the caller broadcasts by stamping it onto every turn it forwards (see
/// [`active_directive`](DecisionMaker::active_directive)); this value is what a
/// debug UI logs and what the decision was, distinct from the per-turn
/// broadcast that carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// The buffer size to apply, clamped to the coordinator's bounds.
    pub buffer: BufferSize,
    /// The frame at which every client must apply the new buffer. Guaranteed
    /// ahead of the session frame at decision time (the horizon is added to
    /// the slowest per-slot frame the authority has observed).
    pub applied_frame: GameFrameCount,
}
