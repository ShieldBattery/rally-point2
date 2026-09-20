//! Driving the home-relay link: the Tokio-side loop that carries SC:R turns over
//! an authorized [`Link`] and applies app-level forward recovery.
//!
//! [`connect`](crate::ClientEndpoint::connect) hands back a bare [`Link`]; a
//! [`LinkDriver`] wraps one and becomes the single owner of its send/receive state
//! on one task. The game thread never touches the link directly — it exchanges
//! turns over two channels ([`TurnChannels`]): it pushes the turns it produces to
//! `outbound`, and drains the peers' turns the relay forwards from `inbound`. This
//! is the Tokio half of the game seam; the game DLL bridges its lock-free
//! BW-thread handoff onto these channels.
//!
//! Recovery is the driver's job, layered on the link's redundancy. Each turn rides
//! a datagram that also re-carries still-unacked turns up to the live datagram
//! budget, so an ordinary dropped datagram is recovered by the next one with no
//! action here. On top of that the driver: retransmits unacked turns when the
//! outbound stream stops re-carrying them — fresh packets normally re-carry them as
//! redundancy, but when one is too full (a near-MTU turn) or the link is idle, a
//! maintenance flush re-carries them oldest-first, so a dropped turn still lands
//! without sending redundant packets while the stream is already covering it;
//! diverts a turn too large to ever fit a datagram onto the reliable control
//! stream (QUIC's stream reliability replaces redundancy for it — the tiny turns
//! of a lockstep game rarely produce one, but it must arrive, not error or drop);
//! and flushes acks for a quiet or one-way link so the peer still retires what it
//! has sent.
//!
//! The driver also announces this client's own clean departure. The game signals
//! intent to leave (F10 quit, game over) over [`TurnChannels::leave_intent`]; the
//! driver does not write the announcement immediately, since the relay must still
//! see every turn this client already produced. Instead it waits until the
//! outbound queue and the unacked window have both drained — every produced turn
//! sent, every sent turn acked — or a short safety timeout passes, then writes a
//! `LeaveIntent` control frame and treats the relay's subsequent close of the link
//! as a clean shutdown rather than a failure.
//!
//! The driver also forwards the game's end-of-game result report. The game hands
//! it over as opaque bytes on [`TurnChannels::result`], and the driver sends it
//! up the control stream at once — mid-game, over a live link — rather than
//! waiting on any drain. When the game marks a result expected
//! ([`TurnChannels::result_expected`]), a pending leave intent is held until the
//! result has gone out first, so the result frame precedes the intent on the one
//! ordered control stream; the leave-intent safety timeout still bounds the hold.
//!
//! The driver also announces that the game's loop has begun running. The game
//! signals once on [`TurnChannels::game_started`] and the driver writes a
//! `GameStarted` control frame — the relay forwards the fact up its coordinator
//! pipeline so the tenant can name the slots that finished loading instead of
//! inferring a failed load from a deadline. The signal is retained as session
//! state and re-asserted on every control stream the driver opens, so an
//! announcement that raced a link drop still lands on the next connection; the
//! relay accepts one per link and the coordinator dedups per slot, so the repeats
//! cost nothing. Purely informational, so a failed send is logged, left to the
//! next stream, and the driver keeps running — the same treatment a result report
//! gets.
//!
//! The driver also carries the game's in-game chat, the mid-game counterpart to
//! lobby commands: the game authors a message on [`TurnChannels::chat_out`] and
//! the driver writes it up the control stream at once — no drain to wait behind,
//! unlike a turn; other members' messages arrive on [`TurnChannels::chat_in`],
//! tagged with the author's slot. Unlike a lobby command, a failed chat send is
//! not correctness-critical: the driver logs it and keeps running rather than
//! treating it as a link failure, the same best-effort treatment the result
//! report gets.
//!
//! The same best-effort control-stream path carries each member's cosmetic-skin
//! blob: the game hands its own blob up on [`TurnChannels::skin_out`] and other
//! members' blobs arrive on [`TurnChannels::skin_in`], tagged with the author's
//! slot. Unlike chat the relay replays these on register, so a blob can arrive
//! again after a reconnect — the game applies each idempotently.
//!
//! Delivery to the game is **in seq order**. The link dedups and orders within a
//! datagram but follows arrival order across datagrams, so the driver buffers
//! received turns by transport seq and releases only the contiguous prefix — the
//! game never sees a later turn before an earlier one, even under datagram
//! reordering.
//!
//! The loop ends cleanly (returning `Ok`) when the game drops either end of the
//! seam. It ends with a [`DriverError`] when the link itself fails — the signal to
//! re-dial and resume from the last delivered turn — or when the game stalls (stops
//! draining, so the inbound buffer fills) or hands over an undeliverable turn.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rally_point_transport::control::ControlSendError;
use rally_point_transport::{Link, LinkError};

use state::GameSeam;

mod backoff;
mod channels;
mod connectivity;
mod inbound;
mod outbound;
mod reconnect;
mod reorder;
mod retention;
mod run;
mod send;
mod session;
mod state;
mod teardown;

#[cfg(test)]
mod tests;

pub use channels::{ChatOut, TurnChannels};
pub use reconnect::{Reconnect, RehomeFuture, RehomeOutcome, RehomeProvider};

/// Default depth of each turn channel between the game thread and the driver.
/// Turns are small and drained every tick, so this is a generous backstop against
/// a brief scheduling hiccup rather than a tuned buffer; a real backpressure model
/// is future work.
const TURN_CHANNEL_CAPACITY: usize = 1024;

/// Depth of the driver → game leave channel. Leaves are rare (one per departing
/// peer), so a small buffer is ample.
const LEAVE_CHANNEL_CAPACITY: usize = 16;

/// Depth of the game → driver leave-intent channel. The game signals its own
/// departure at most once, so capacity 1 is enough; a second signal (there
/// shouldn't be one) would simply wait for the driver to drain the first.
const LEAVE_INTENT_CHANNEL_CAPACITY: usize = 1;

/// Depth of the game → driver result channel. The game hands over its
/// end-of-game report at most once, so capacity 1 is enough; the driver sends
/// the first payload and drops any extra.
const RESULT_CHANNEL_CAPACITY: usize = 1;

/// Depth of the game → driver game-started channel. The game announces its loop
/// once, so capacity 1 is enough; the driver sends the first signal and drops
/// any extra.
const GAME_STARTED_CHANNEL_CAPACITY: usize = 1;

/// Depth of each lobby-command channel between the game thread and the driver.
/// Lobby commands flow only during pre-game setup — a burst of slot/color
/// assignments and the game-init, then silence — so a generous backstop against
/// a scheduling hiccup is ample; it is not a tuned buffer.
const LOBBY_CHANNEL_CAPACITY: usize = 256;

/// Depth of each chat channel between the game thread and the driver. Chat is
/// bursty but small (a human typing), so a generous backstop against a
/// scheduling hiccup is ample here too; it is not a tuned buffer.
const CHAT_CHANNEL_CAPACITY: usize = 256;

/// Depth of each skin channel between the game thread and the driver. A session
/// sends at most one blob per member plus the relay's replays on reconnect, so
/// this generous backstop against a scheduling hiccup is ample; it is not a tuned
/// buffer.
const SKIN_CHANNEL_CAPACITY: usize = 32;

/// Most turns the send-phase hold queue may retain before it starts sending
/// the oldest early. A real game holds at most a turn or two (the delay is a
/// fraction of one turn interval), so this is a memory backstop against a
/// runaway producer, not a tuned buffer — and it degrades the *delay*, never
/// the data: an over-cap turn still reaches the wire, just sooner than its
/// phase deadline asked.
pub(super) const HELD_TURN_CAP: usize = 64;

/// Depth of the manual-drop-request channel from the game thread to the driver.
/// A human clicks the drop button a handful of times at most; the relay
/// rate-limits the requests regardless, so a small backstop against a scheduling
/// hiccup is ample.
const REQUEST_DROP_CHANNEL_CAPACITY: usize = 16;

/// The windows the driver spends waiting rather than reacting. Production runs
/// on [`Default`]; a test that would otherwise pay one of them in real time
/// injects a shorter set through [`LinkDriver::with_timing`], so it waits on the
/// driver's behavior instead of on a window sized for a real network.
///
/// Only the waits belong here: the capacity caps, and the unacked-window cap
/// especially, are load-bearing against the relay's own limits and stay fixed.
#[derive(Debug, Clone, Copy)]
pub struct DriverTiming {
    /// How long a game-closed teardown may spend fencing delivery before letting
    /// the connection close: waiting out the unacked datagram window (with the
    /// flush re-carry running, so a lost final turn is retransmitted like a live
    /// one) and then, when anything rode the reliable control stream, waiting for
    /// the relay's own close to confirm the stream was read in full. One shared
    /// deadline across both fences, bounded so an unreachable relay cannot park
    /// teardown; comfortably past one RTT plus the relay's own flush cadence.
    pub teardown_settle: Duration,
    /// How long the driver waits, after the game signals its departure, for the
    /// outbound queue and unacked window to drain before announcing the leave
    /// anyway. If acks aren't coming within this bound the link is effectively
    /// dead and the ordinary drop path (idle timeout) covers it regardless;
    /// sending the intent late is still harmless — the relay stops forwarding
    /// this slot's turns the moment it sees the intent, so a few turns still in
    /// flight change nothing.
    pub leave_intent_timeout: Duration,
    /// How often the driver flushes a maintenance packet when the outbound stream
    /// is not already re-carrying unacked turns.
    ///
    /// The flush timer is reset whenever an outbound turn re-carries unacked turns
    /// as redundancy — the common case, where recovery rides the turn stream and
    /// the flush never fires, so it costs no extra packets. It is *not* reset by a
    /// send that carried no redundancy (a near-MTU turn that filled the datagram,
    /// or a stretch where the re-carry policy's spacing left nothing due) or by an
    /// idle stretch; in those cases it fires and sends a packet that re-carries
    /// whatever unacked turns the policy has due and folds in owed acks. It stays
    /// silent when nothing is unacked and no acks are owed. Set to a few turns at
    /// the 24-per-second turn rate: long enough that the flush stays out of a
    /// healthy turn stream's way, short enough that a turn the stream cannot
    /// re-carry is recovered within a handful of turn intervals rather than
    /// stalling every peer's lockstep behind it.
    pub flush_interval: Duration,
}

impl Default for DriverTiming {
    fn default() -> Self {
        Self {
            teardown_settle: Duration::from_secs(1),
            leave_intent_timeout: Duration::from_secs(2),
            flush_interval: Duration::from_millis(150),
        }
    }
}

/// The hard ceiling on payloads sent but not yet known-delivered. Under
/// *reverse*-path loss (the relay received the turns but the acks riding the
/// datagrams were lost), the beacon side-channel force-advances the window via
/// [`Link::retire_through`] and keeps it bounded. Under *forward*-path sustained
/// loss — redundancy can't keep up, the relay genuinely receives slower than
/// this client produces — the beacon can retire only what the relay *got*, never
/// what it never received, so the window still grows. When it crosses this cap
/// the driver trips [`DriverError::UnackedWindowExhausted`] rather than let seqs
/// race ahead until the relay's receive window rejects them as
/// `PayloadOutOfWindow` and drops the link (the status-quo unbounded-growth
/// failure). Unlike a link or control-stream failure, this is deliberately
/// terminal rather than routed into the reconnect loop (see
/// [`is_link_failure`]) — the peer being genuinely behind is not something a
/// re-dial fixes on its own.
///
/// Sat below the relay's receive window (4096) so it trips *before* a hard
/// reject, with margin for the packets in flight between the trip and any
/// retirement the beacon could still deliver.
pub(super) const UNACKED_WINDOW_CAP: usize = 1024;

/// Carries turns over one authorized home-relay [`Link`] until it closes.
///
/// Build one with [`new`](Self::new) from the [`Link`] a dial returned, spawn
/// [`run`](Self::run) on the Tokio runtime, and hand the paired [`TurnChannels`]
/// to the game seam.
pub struct LinkDriver {
    link: Link,
    /// The driver's end of every channel it exchanges turns and control with the
    /// game thread over — see [`GameSeam`] for what each one carries.
    seam: GameSeam,
    /// Whether the game will produce a result report; holds a pending leave
    /// intent until the result is sent so the result frame precedes it. Kept
    /// beside the seam because it is shared state, not a channel: the game
    /// stores into it and the session's announcer reads it.
    result_expected: Arc<AtomicBool>,
    /// The waiting windows every session this driver runs is timed against.
    timing: DriverTiming,
}

/// Why the driver stopped with a failure, as opposed to a clean shutdown (which
/// returns `Ok`).
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// The home-relay link failed — the connection was lost, or a received packet
    /// was malformed or inconsistent. This is the trigger for the reconnect path to
    /// re-dial and resume from the last delivered turn.
    #[error("home-relay link failed: {0}")]
    Link(#[from] LinkError),
    /// A turn too large for the datagram path could not go out on the reliable
    /// control stream either — the stream is gone (the connection dropped), or
    /// the turn exceeds even the control frame cap and no channel can deliver
    /// it. Either way the turn cannot be silently dropped (that desyncs
    /// lockstep), so the driver stops; a broken stream is the same reconnect
    /// trigger as a broken link.
    #[error("oversize turn could not be diverted: {0}")]
    ControlStream(#[from] ControlSendError),
    /// The control-stream reader task ended while the connection was otherwise
    /// alive — a one-sided stream reset, an over-cap frame, a decode failure, or
    /// a clean EOF. This is the only channel a synced `LeaveDirective`,
    /// `SessionStart`, and `SlotConnectivity` ever arrive on, so losing it is
    /// not a degradation the driver can quietly limp on through: reconnecting
    /// rebuilds every stream from scratch, exactly like a broken link.
    #[error("control stream reader ended")]
    ControlStreamLost,
    /// The game stopped draining a correctness-critical driver → game channel
    /// and its buffer filled — the inbound turn stream, or one of the reliable
    /// deliveries whose loss would corrupt game state (a synced leave, a lobby
    /// command, the session-start directive). The driver surfaces this instead
    /// of blocking on the handoff — parking there would also stall its acks and
    /// outbound turns — so the caller can tear down or resync. Best-effort
    /// deliveries (chat, skin blobs, connectivity display changes) never trip
    /// this: a full buffer just drops them.
    #[error("game stopped draining a correctness-critical channel; its buffer is full")]
    GameStalled,
    /// The unacked window crossed `UNACKED_WINDOW_CAP` even after the beacon
    /// side-channel retired everything the peer confirmed it received — the
    /// peer is genuinely behind, not just ack-starved. This is the sustained
    /// forward-loss case redundancy cannot cover: turns are being produced
    /// faster than the peer can receive them. Treated as terminal rather than
    /// fed into the reconnect loop's replay-from-cursor recovery, unlike a
    /// link or control-stream failure — see `is_link_failure`. Dropping
    /// further turns to keep the window bounded would desync lockstep, so the
    /// driver stops instead.
    #[error("unacked window exhausted: {in_flight} payloads in flight exceeds the {cap}-turn cap")]
    UnackedWindowExhausted { in_flight: usize, cap: usize },
    /// The outbound outage buffer crossed `OUTAGE_OUTBOUND_BUFFER_CAP` while
    /// the link was down — the game kept producing turns faster than the
    /// driver could hold them across the outage. Surfaced as a terminal error
    /// rather than silently discarding the oldest buffered turn: a dropped
    /// turn here is a genuine game-produced command, and the resumed session
    /// assigns the *surviving* turns gapless origin seqs — so a silent drop
    /// leaves no gap for any peer to ever detect, just a quietly shorter turn
    /// stream. A game producing this many turns during a genuinely dead link,
    /// without its own lockstep stalling first, is already abnormal; ending
    /// the session loudly beats a silent divergence.
    #[error(
        "outbound outage buffer exhausted: {buffered} turns produced during the outage exceeds the {cap}-turn cap"
    )]
    OutageBufferExhausted { buffered: usize, cap: usize },
    /// The relay refused a re-dial because this slot's leave was already decided
    /// (a survivor's drop request was honored, or it left cleanly), so the game has
    /// moved on without this client. Terminal for the reconnect loop — no dial can bring the
    /// slot back — so the driver ends and its channels close, which the game reads
    /// as end-of-session.
    #[error("relay refused the re-dial: slot already departed")]
    SlotDeparted,
    /// The authorization token expired while reconnecting, so no re-dial could ever
    /// be authorized. Terminal for the reconnect loop, like [`SlotDeparted`](Self::SlotDeparted).
    #[error("authorization token expired; cannot reconnect")]
    TokenExpired,
}

impl LinkDriver {
    /// Wraps a connected [`Link`] in a driver, returning it with the game thread's
    /// [`TurnChannels`]. Uses `TURN_CHANNEL_CAPACITY` for each direction.
    pub fn new(link: Link) -> (Self, TurnChannels) {
        Self::with_capacity(link, TURN_CHANNEL_CAPACITY)
    }

    /// [`new`](Self::new) with an explicit per-direction channel depth.
    pub fn with_capacity(link: Link, capacity: usize) -> (Self, TurnChannels) {
        let (seam, channels, result_expected) = GameSeam::with_capacity(capacity);
        let driver = Self {
            link,
            seam,
            result_expected,
            timing: DriverTiming::default(),
        };
        (driver, channels)
    }

    /// Replaces the waiting windows this driver's sessions run on. Only a test
    /// should call it: every window has a default sized against a real network,
    /// and shortening one trades that margin for not waiting it out.
    pub fn with_timing(mut self, timing: DriverTiming) -> Self {
        self.timing = timing;
        self
    }
}
