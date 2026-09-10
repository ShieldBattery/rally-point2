//! The state a session runs on: the reconnect/retention tuning constants, the
//! driver's half of the game seam, the per-session state that must survive a
//! reconnect, the connectivity-epoch fence, and the retention ring's bookkeeping.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{LeaveDirective, Payload};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::leave_announcer::LeaveAnnouncer;
use crate::phase::{PhaseSlew, PhaseStatus};

use super::*;

/// The first reconnect backoff delay, doubled each attempt up to
/// [`RECONNECT_BACKOFF_CAP`].
pub(super) const RECONNECT_BACKOFF_INITIAL: Duration = Duration::from_millis(500);

/// The ceiling on the reconnect backoff delay.
pub(super) const RECONNECT_BACKOFF_CAP: Duration = Duration::from_secs(5);

/// Per-attempt bound on one reconnect dial. Short enough that several attempts fit
/// well inside the window before a survivor could request the drop, so a
/// recoverable drop reconnects before the slot could be decided departed.
pub(super) const RECONNECT_DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// Ceiling on turns buffered while the link is down. Under lockstep the game stalls
/// within a couple turns of losing the link — it can't advance without its peers'
/// turns — so this is a safety bound, not a tuned depth; past it the oldest buffered
/// turn is dropped (with a warning) rather than let the buffer grow without bound.
pub(super) const OUTAGE_OUTBOUND_BUFFER_CAP: usize = 256;

/// How many of this client's own recently-sent turns the retention ring keeps for
/// re-injection after a re-home. Independent of ack retirement — a turn the old
/// relay acked is dropped from the unacked window but kept here — so the ring can
/// re-carry it to a replacement relay whose turn ring is empty. A few times the
/// deepest realistic latency buffer; the byte cap ([`RETENTION_BYTE_CAP`]) bounds it
/// too, so an oversize turn can't blow the memory budget.
pub(super) const RETENTION_TURN_CAP: usize = 512;

/// The byte ceiling on the retention ring, enforced alongside
/// [`RETENTION_TURN_CAP`] so a run of large turns can't grow it past this even
/// under the turn cap. 256 KiB comfortably holds 512 ordinary (tens-of-bytes)
/// turns and still bounds a pathological run of near-MTU ones.
pub(super) const RETENTION_BYTE_CAP: usize = 256 * 1024;

/// How long a run of failed same-relay re-dials must persist before the driver
/// escalates to coordinator-mediated failover (asking the [`RehomeProvider`] where
/// to move). A cert/pin rejection — a restarted relay serving a fresh cert —
/// escalates immediately instead, since no same-relay retry can ever succeed.
///
/// **Timing budget.** BW's native transport drops a silent peer after roughly 45s
/// of stall, so a re-home must complete — coordinator round-trip plus a
/// [`RECONNECT_DIAL_TIMEOUT`]-bounded dial — inside that window or the game gives up
/// on the slot. The timed path spends ~10s here before the first escalation, then
/// the provider's own HTTP timeout (embedder-owned — the DLL sizes it to cover the
/// coordinator call), then a ≤3s dial: comfortably inside 45s. The cert/pin path
/// skips the 10s wait entirely. The one way to blow the budget is a genuine
/// "no live relay yet" stretch, where [`ESCALATE_RETRY`] re-asks every ~15s until
/// one appears — there is nothing to re-home *to*, so the stall-drop is unavoidable.
pub(super) const ESCALATE_AFTER: Duration = Duration::from_secs(10);

/// How often the driver re-escalates while the provider keeps answering
/// `Unavailable` (no relay can take the session over yet) or a re-home dial keeps
/// failing — the coordinator may gain a relay, so the driver re-asks on this
/// cadence while continuing its same-relay backoff in between. Kept below the ~45s
/// BW native stall-drop budget (see [`ESCALATE_AFTER`]) so a transiently-unavailable
/// coordinator is re-asked at least twice before the game would give up on the slot.
pub(super) const ESCALATE_RETRY: Duration = Duration::from_secs(15);

/// The driver's own bound on one [`RehomeProvider::rehome`] ask. The provider is
/// embedder code doing an app-server/coordinator round-trip and is expected to
/// enforce its own HTTP timeout well under this — the driver's bound exists so a
/// provider that hangs anyway (a stuck app-server call, a lost response) cannot
/// freeze reconnection, teardown observation, and the outage-buffer cap with it.
/// A timed-out ask is treated exactly as [`RehomeOutcome::Unavailable`]: resume
/// the same-relay backoff and re-ask on the [`ESCALATE_RETRY`] cadence. Sized to
/// fit the ~45s BW stall-drop budget ([`ESCALATE_AFTER`]'s doc): 10s to the first
/// escalation + this bound + a ≤3s dial still leaves budget for one retry ask.
pub(super) const REHOME_PROVIDER_DEADLINE: Duration = Duration::from_secs(20);

/// The driver's half of the game seam: the channels a [`LinkDriver`] owns to
/// exchange turns and control with the game thread. Bundled so a session runs over
/// them by reference and they outlive a reconnect that swaps the underlying link.
pub(super) struct GameSeam {
    pub(super) outbound: mpsc::Receiver<Payload>,
    pub(super) inbound: mpsc::Sender<Payload>,
    pub(super) leaves: mpsc::Sender<LeaveDirective>,
    pub(super) leave_intent: mpsc::Receiver<()>,
    pub(super) result: mpsc::Receiver<Vec<u8>>,
    pub(super) game_started: mpsc::Receiver<()>,
    pub(super) lobby_out: mpsc::Receiver<Vec<u8>>,
    pub(super) lobby_in: mpsc::Sender<(SlotId, Vec<u8>)>,
    pub(super) chat_out: mpsc::Receiver<ChatOut>,
    pub(super) chat_in: mpsc::Sender<(SlotId, ChatOut)>,
    pub(super) skin_out: mpsc::Receiver<Vec<u8>>,
    pub(super) skin_in: mpsc::Sender<(SlotId, Vec<u8>)>,
    pub(super) request_drop: mpsc::Receiver<SlotId>,
    pub(super) session_start: mpsc::Sender<Option<u32>>,
    pub(super) connectivity: mpsc::Sender<(SlotId, bool)>,
    pub(super) region_labels: mpsc::Sender<Vec<(u64, String)>>,
    pub(super) phase_status: watch::Sender<PhaseStatus>,
}

/// The driver state that must persist across a reconnect so a re-dialed session
/// resumes rather than restarts.
pub(super) struct LoopState {
    /// Per peer slot, the lowest seq not yet handed to the game — the reorder
    /// cursor. This *is* the authoritative per-slot delivery high-water mark: it is
    /// the top of the contiguous run delivered to the game, and thus the "next
    /// needed" seq presented as the resume cursor on a reconnect, so the relay
    /// replays exactly the turns missed and the reorder buffer/dedup absorb any
    /// overlap the replay carries.
    pub(super) next_seq: HashMap<SlotId, u64>,
    /// Per peer slot, turns that arrived ahead of `next_seq`, held until the gap
    /// below them fills. Preserved across a reconnect so turns received but not yet
    /// released aren't re-asked-for or lost.
    pub(super) pending: HashMap<SlotId, BTreeMap<u64, Payload>>,
    /// The client's own outbound payload seq counter. An origin identity every hop
    /// honors, so it is monotonic across reconnects and never rewinds.
    pub(super) next_outbound_seq: u64,
    /// The client's clean-departure announcer, persisted so a leave signaled before
    /// a drop is still honored after the reconnect.
    pub(super) announcer: LeaveAnnouncer,
    /// Turns the game produced while the link was down, flushed in order when the
    /// next session comes up.
    pub(super) outbound_buffer: VecDeque<Payload>,
    /// Whether the game has announced that its loop is running. Retained here
    /// rather than per-connection because it is a fact about the session, not
    /// about one link: once set, every control stream the driver opens re-asserts
    /// it, so an announcement whose write raced a link drop still reaches the
    /// relay. The relay latches one report per link and the coordinator dedups per
    /// slot, so re-asserting costs nothing beyond the frame.
    pub(super) game_started_announced: bool,
    /// Whether the relay's `SessionStart` directive has passed through the driver —
    /// the game has started. Gates escalation to coordinator-mediated failover: the
    /// driver only ever re-homes an in-game session, never a still-forming lobby.
    /// Latched once and kept across reconnects.
    pub(super) game_started: bool,
    /// A ring of this client's own recently-sent turns, retained for re-injection
    /// after a **re-home** so a replacement relay's empty turn ring still fans them
    /// out to peers. Bounded by [`RETENTION_TURN_CAP`] and [`RETENTION_BYTE_CAP`],
    /// drop-oldest — independent of ack retirement (a turn the old relay acked is
    /// dropped from the unacked window but stays here). Persisted across reconnects.
    pub(super) retention: VecDeque<Payload>,
    /// The running encoded-byte total of [`retention`](Self::retention), so the
    /// byte cap is enforced without re-summing the ring on every push.
    pub(super) retention_bytes: usize,
    /// Retained turns a resume deferred to the fresh connection's reliable
    /// control stream: turns too large to ride any datagram, staged here
    /// because re-injecting them into the unacked window would strand them
    /// there forever (the redundancy pass always skips a payload that can't
    /// fit a lone packet). A re-home stages them via [`reinject_retention`];
    /// a same-relay resume stages every still-retained oversize turn too
    /// ([`redivert_oversize_retention_on_same_relay_resume`]) — a
    /// control-stream write carries no acknowledgment, so a drop between the
    /// local write succeeding and the relay processing it is otherwise
    /// invisible. [`session`](Driver::session) drains this onto the control
    /// stream it opens on the new connection — the same divert path an
    /// oversize turn takes when first sent — and it empties on each drain.
    pub(super) pending_control_redivert: Vec<Payload>,
    /// Relay-stamped physical connection lifecycle per member. Kept across this
    /// client's own reconnect so a delayed connectivity frame from another
    /// member's superseded link cannot regress the game's display.
    /// Missing entries retain rolling-upgrade compatibility with relays that do
    /// not stamp epochs; once present, an epoch-less frame cannot downgrade it.
    pub(super) connectivity_states: ConnectivityEpochStates,
    /// Slots for which a final synced leave has reached this client. A leave is
    /// terminal game state, so no later physical-link generation may make its
    /// subject appear connected again. Kept across this client's reconnects.
    pub(super) terminal_connectivity_slots: HashSet<SlotId>,
    /// The send-phase delay this client is applying under the relay's
    /// `PhaseDirective`s: the newest commanded target and the applied value
    /// slewing toward it. Persisted across a reconnect — the delay is part of
    /// the session's phase alignment, not the connection's state — and the
    /// relay restates the current directive on register anyway.
    pub(super) phase_slew: PhaseSlew,
    /// Outbound turns held for their send-phase delay, oldest first, each with
    /// the deadline its wire handoff waits for. Deadlines are monotonic (a
    /// turn never overtakes an earlier one, even across a delay decrease), and
    /// turns here are unstamped — seq assignment happens at actual send, so
    /// the seq stream stays in production order. Persisted so a link failure
    /// cannot drop a held turn: the next session flushes these first, before
    /// any outage-buffered turns, keeping that order.
    pub(super) held: VecDeque<(Instant, Payload)>,
}

impl LoopState {
    pub(super) fn new(result_expected: Arc<AtomicBool>) -> Self {
        Self {
            next_seq: HashMap::new(),
            pending: HashMap::new(),
            next_outbound_seq: 0,
            announcer: LeaveAnnouncer::new(result_expected),
            outbound_buffer: VecDeque::new(),
            game_started_announced: false,
            game_started: false,
            retention: VecDeque::new(),
            retention_bytes: 0,
            pending_control_redivert: Vec::new(),
            connectivity_states: ConnectivityEpochStates::default(),
            terminal_connectivity_slots: HashSet::new(),
            phase_slew: PhaseSlew::new(Instant::now()),
            held: VecDeque::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ConnectivityState {
    pub(super) epoch: u64,
    pub(super) connected: bool,
}

#[derive(Debug, Default)]
pub(super) struct ConnectivityEpochStates {
    pub(super) current: HashMap<SlotId, ConnectivityState>,
    /// Superseded random epochs are retained for the whole session. They cannot
    /// be bounded safely: epochs have equality semantics, and a delayed reliable
    /// frame has no age after which it becomes safe to accept again.
    pub(super) retired: HashSet<(SlotId, u64)>,
}

/// Applies the same lifecycle fence the relays use to connectivity changes.
/// Down(E) is terminal, a previously unseen level=true epoch opens a replacement,
/// and epoch-less compatibility ends permanently once an epoch is observed.
pub(super) fn admit_connectivity_epoch(
    states: &mut ConnectivityEpochStates,
    terminal_slots: &HashSet<SlotId>,
    slot: SlotId,
    connected: bool,
    observed: Option<u64>,
) -> bool {
    if terminal_slots.contains(&slot) {
        return false;
    }
    if observed.is_some_and(|epoch| states.retired.contains(&(slot, epoch))) {
        return false;
    }
    match (states.current.get(&slot).copied(), observed) {
        (Some(current), Some(epoch)) if current.epoch == epoch => {
            if !current.connected && connected {
                return false;
            }
            states
                .current
                .insert(slot, ConnectivityState { epoch, connected });
            true
        }
        (Some(current), Some(epoch)) if connected => {
            states.retired.insert((slot, current.epoch));
            states.current.insert(
                slot,
                ConnectivityState {
                    epoch,
                    connected: true,
                },
            );
            true
        }
        (Some(_), _) => false,
        (None, Some(epoch)) => {
            states
                .current
                .insert(slot, ConnectivityState { epoch, connected });
            true
        }
        (None, None) => true,
    }
}

/// Records one of this client's own sent turns into the retention ring, evicting
/// the oldest turns until both the turn-count and byte caps hold. Called for every
/// turn the driver sends for its own slot (datagram or diverted), so a re-home can
/// re-inject them onto a replacement relay whose turn ring is empty.
pub(super) fn retain_sent(
    retention: &mut VecDeque<Payload>,
    retention_bytes: &mut usize,
    payload: &Payload,
) {
    retention.push_back(payload.clone());
    *retention_bytes += retained_size(payload);
    while retention.len() > RETENTION_TURN_CAP
        || (*retention_bytes > RETENTION_BYTE_CAP && retention.len() > 1)
    {
        if let Some(dropped) = retention.pop_front() {
            *retention_bytes = retention_bytes.saturating_sub(retained_size(&dropped));
        } else {
            break;
        }
    }
}

/// The size a retained turn counts against [`RETENTION_BYTE_CAP`]: its command
/// bytes (the variable bulk) plus a fixed allowance for the small fixed fields.
/// An estimate, not the exact encoded length — the byte cap is a memory safety
/// bound, so an approximation that avoids pulling a prost dependency into the lib
/// is enough.
pub(super) fn retained_size(payload: &Payload) -> usize {
    payload.commands.len() + 32
}
