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
//! The driver also carries the game's in-game chat, the mid-game counterpart to
//! lobby commands: the game authors a message on [`TurnChannels::chat_out`] and
//! the driver writes it up the control stream at once — no drain to wait behind,
//! unlike a turn; other members' messages arrive on [`TurnChannels::chat_in`],
//! tagged with the author's slot. Unlike a lobby command, a failed chat send is
//! not correctness-critical: the driver logs it and keeps running rather than
//! treating it as a link failure, the same best-effort treatment the result
//! report gets.
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

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{GameChat, LeaveDirective, LobbyCommand, Payload};
use rally_point_transport::beacon::{flush_beacon, spawn_beacon_reader};
use rally_point_transport::control::{
    ControlInbound, ControlSendError, send_control_chat, send_control_game_result,
    send_control_lobby, send_control_request_drop, send_control_turn, spawn_control_reader,
};
use rally_point_transport::{Link, LinkError, quinn};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};

use crate::dial::{ClientEndpoint, DialError};
use crate::identity::Identity;
use crate::leave_announcer::LeaveAnnouncer;

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

/// Depth of each lobby-command channel between the game thread and the driver.
/// Lobby commands flow only during pre-game setup — a burst of slot/color
/// assignments and the game-init, then silence — so a generous backstop against
/// a scheduling hiccup is ample; it is not a tuned buffer.
const LOBBY_CHANNEL_CAPACITY: usize = 256;

/// Depth of each chat channel between the game thread and the driver. Chat is
/// bursty but small (a human typing), so a generous backstop against a
/// scheduling hiccup is ample here too; it is not a tuned buffer.
const CHAT_CHANNEL_CAPACITY: usize = 256;

/// Depth of the manual-drop-request channel from the game thread to the driver.
/// A human clicks the drop button a handful of times at most; the relay
/// rate-limits the requests regardless, so a small backstop against a scheduling
/// hiccup is ample.
const REQUEST_DROP_CHANNEL_CAPACITY: usize = 16;

/// How long the driver waits, after the game signals its departure, for the
/// outbound queue and unacked window to drain before announcing the leave
/// anyway. If acks aren't coming within this bound the link is effectively
/// dead and the ordinary drop path (idle timeout) covers it regardless;
/// sending the intent late is still harmless — the relay stops forwarding
/// this slot's turns the moment it sees the intent, so a few turns still in
/// flight change nothing.
const LEAVE_INTENT_TIMEOUT: Duration = Duration::from_secs(2);

/// How often the driver flushes a maintenance packet when the outbound stream is
/// not already re-carrying unacked turns.
///
/// The flush timer is reset whenever an outbound turn re-carries unacked turns as
/// redundancy — the common case, where recovery rides the turn stream and the flush
/// never fires, so it costs no extra packets. It is *not* reset by a send that
/// carried no redundancy (a near-MTU turn that filled the datagram) or by an idle
/// stretch; in those cases it fires and sends an ack-only packet that re-carries
/// unacked turns oldest-first and folds in owed acks. It stays silent when nothing
/// is unacked and no acks are owed. Set to a few turns at the 24-per-second turn
const FLUSH_INTERVAL: Duration = Duration::from_millis(150);

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
const UNACKED_WINDOW_CAP: usize = 1024;

/// One in-game chat message the game authored, to send up to the relay for the
/// other members. Mirrors `GameChat`'s wire shape minus the author `slot` —
/// the relay stamps that, exactly as it does for a lobby command, so the caller
/// never sets it. `target_kind`/`target_slot` are opaque scope hints the relay
/// never interprets (see `GameChat` in wire.proto); the driver just carries
/// them through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatOut {
    /// A scope hint for which members should display this message: 0 = all,
    /// 1 = allies, 2 = observers, 3 = a single named player (see `target_slot`).
    pub target_kind: u32,
    /// The recipient slot a `target_kind` of 3 names; meaningless otherwise.
    pub target_slot: u32,
    /// The chat line's text, UTF-8.
    pub text: String,
}

/// The game thread's end of the turn channels to a running [`LinkDriver`].
///
/// The game pushes the turns it produces to [`outbound`](Self::outbound) and
/// drains the peers' turns the relay forwards from [`inbound`](Self::inbound).
/// Dropping `outbound`, or dropping `inbound`, stops the driver cleanly. Letting
/// `inbound` fill without draining it does not — the game has stalled, and the
/// driver surfaces that as [`DriverError::GameStalled`] rather than parking on it.
pub struct TurnChannels {
    /// Turns the game produces, to be sent to the relay. The driver assigns each
    /// payload's transport `seq` and the relay rebinds its `slot` to the authorized
    /// one, so a caller leaves both fields at zero.
    pub outbound: mpsc::Sender<Payload>,
    /// Peers' turns the relay has forwarded, each tagged with its source slot.
    pub inbound: mpsc::Receiver<Payload>,
    /// Synced player-leaves the relay pushed down the reliable control stream. The
    /// game drains these into its leave tracker and applies each at its
    /// `apply_at_frame`, clearing the departed slot. They arrive here, off the turn
    /// path, because a drop stalls the game and stops turn flow — so the leave that
    /// must unstall it cannot ride the turns.
    pub leaves: mpsc::Receiver<LeaveDirective>,
    /// Signals the driver that the game is departing intentionally (F10 quit,
    /// game over) and wants that announced to the relay, rather than left for
    /// the relay to infer from link death. The driver does not send immediately
    /// on receiving this — it waits for the outbound queue and unacked window
    /// to drain first, so the relay sees every turn this client produced before
    /// it decides the leave. Dropping this sender without ever signaling (an
    /// unclean teardown, e.g. the process dying) is harmless: the driver simply
    /// keeps running as if leave-intent didn't exist, and the relay falls back
    /// to its usual link-death detection.
    pub leave_intent: mpsc::Sender<()>,
    /// The game's end-of-game result report, handed over as opaque serialized
    /// bytes. The driver sends it up the reliable control stream the moment it
    /// arrives — mid-game, ahead of any final-turn drain — because a defeat
    /// report goes out over a still-live link, not after the game has wound
    /// down. At most one is sent; a second payload is dropped, as is one handed
    /// over after the leave intent has already gone out.
    pub result: mpsc::Sender<Vec<u8>>,
    /// Set by the game, synchronously from its game thread, when it will produce
    /// a result report — before it can ever signal a leave intent. The driver
    /// reads it to hold a pending leave intent until the result has been sent (or
    /// the leave-intent safety timeout fires), so the result frame precedes the
    /// intent frame on the wire. Left `false` when no result is expected, and the
    /// intent is not held at all.
    pub result_expected: Arc<AtomicBool>,
    /// Lobby commands this game authored, to send up to the relay for the other
    /// members. The driver wraps each in a `LobbyCommand` and writes it up the
    /// reliable control stream at once — the relay stamps the authoring slot, so
    /// the caller leaves that to the relay and just hands over the bytes. Used
    /// only during pre-game setup; once the game starts, commands move to
    /// `outbound` (the datagram turn path).
    pub lobby_out: mpsc::Sender<Vec<u8>>,
    /// Lobby commands other members authored, as the relay fanned them down the
    /// reliable control stream, each tagged with its authoring slot. The game
    /// applies each to that member's lobby turn. The relay never echoes this
    /// client's own commands back (the game echoes those locally), and a member
    /// whose stream comes up after commands already flowed receives the relay's
    /// replay of the earlier ones here, in order, before the live ones.
    pub lobby_in: mpsc::Receiver<(SlotId, Vec<u8>)>,
    /// In-game chat messages this game authored, to send up to the relay for
    /// the other members. The driver wraps each in a `GameChat` and writes it
    /// up the reliable control stream at once — no drain to wait behind, unlike
    /// a turn — and the relay stamps the authoring slot, so the caller leaves
    /// that to the relay. Unlike [`lobby_out`](Self::lobby_out), this stays live
    /// for the whole game, not just pre-game setup. A send failure is
    /// best-effort: the driver logs it and continues rather than surfacing a
    /// [`DriverError`], since a lost chat line is not correctness-critical.
    pub chat_out: mpsc::Sender<ChatOut>,
    /// Chat messages other members authored, as the relay fanned them down the
    /// reliable control stream, each tagged with its authoring slot. There is no
    /// replay here (unlike [`lobby_in`](Self::lobby_in)) — chat is ephemeral, so
    /// a member whose stream comes up after a message already flowed simply
    /// never sees it.
    pub chat_in: mpsc::Receiver<(SlotId, ChatOut)>,
    /// Manual drop requests this game authored: the game submits the `SlotId` of a
    /// disconnected member it wants dropped, and the driver writes a `RequestDrop`
    /// up the reliable control stream naming that slot (the relay binds the
    /// requester to this client's authenticated slot, so the caller never sets it).
    /// A disconnection never removes a player on its own — a dropped slot stalls
    /// the game until a human asks for it to be dropped — so this is the game's
    /// escape from a stalled session. Fire-and-forget and best-effort: there is no
    /// ack (the [`leaves`](Self::leaves) `LeaveDirective` for the target is the
    /// only confirmation), a request the authority refuses (too early) can simply
    /// be submitted again, and a send failure is logged and swallowed rather than
    /// surfaced — losing one request costs nothing more than a click. Survives the
    /// driver's own reconnection like the other senders: the survivor making the
    /// request has a healthy link, so a request submitted mid-session goes out on
    /// the live stream.
    pub request_drop: mpsc::Sender<SlotId>,
    /// The relay-driven session-start directive, delivered once every expected
    /// slot has connected somewhere in the session's mesh. The driver forwards a
    /// unit here each time the relay pushes a `SessionStart` down the reliable
    /// control stream; the game begins on the first and treats any repeat as a
    /// no-op (the relay may re-deliver on a late slot's register or an authority
    /// handoff). Fieldless — the whole signal is that it arrived.
    pub session_start: mpsc::Receiver<()>,
    /// Slot-connectivity changes, each carrying `(slot, connected)`: a member's
    /// link died (`false`) or (re)registered (`true`). Best-effort and
    /// informational — the game uses it to drive a "player X disconnected" display,
    /// independent of the synced player-leave that actually removes a slot from
    /// lockstep (which arrives on [`leaves`](Self::leaves)). No replay and no
    /// ordering guarantee against the leave path: a change that flowed before this
    /// stream came up is simply never seen, and an unknown slot is a no-op for the
    /// game.
    ///
    /// Two sources feed this one channel:
    ///
    /// - **Peer slots** — the relay pushes these down the control stream as it does
    ///   the other directives.
    /// - **This client's own slot** — when the driver runs with reconnection
    ///   ([`run_reconnecting`](LinkDriver::run_reconnecting)) it emits
    ///   `(own_slot, false)` the moment its own link drops and `(own_slot, true)`
    ///   once it has re-established one, so the game learns of *its own*
    ///   disconnect/reconnect from an explicit signal rather than from these
    ///   channels closing (they now stay open across the outage). The driver knows
    ///   its own slot from its authorization token; the game tells its own slot from
    ///   a peer's by comparing against its local slot. This keeps the channel's
    ///   `(SlotId, bool)` shape unchanged.
    pub connectivity: mpsc::Receiver<(SlotId, bool)>,
}

/// Carries turns over one authorized home-relay [`Link`] until it closes.
///
/// Build one with [`new`](Self::new) from the [`Link`] a dial returned, spawn
/// [`run`](Self::run) on the Tokio runtime, and hand the paired [`TurnChannels`]
/// to the game seam.
pub struct LinkDriver {
    link: Link,
    /// Turns from the game thread to send to the relay.
    outbound: mpsc::Receiver<Payload>,
    /// Turns received from the relay to hand to the game thread.
    inbound: mpsc::Sender<Payload>,
    /// Synced player-leaves the relay pushed down the control stream, to hand to
    /// the game thread's leave tracker.
    leaves: mpsc::Sender<LeaveDirective>,
    /// The game thread's signal that it is departing intentionally.
    leave_intent: mpsc::Receiver<()>,
    /// The game thread's end-of-game result report, to send up the control
    /// stream as soon as it arrives.
    result: mpsc::Receiver<Vec<u8>>,
    /// Whether the game will produce a result report; holds a pending leave
    /// intent until the result is sent so the result frame precedes it.
    result_expected: Arc<AtomicBool>,
    /// Lobby commands the game authored, to send up the control stream.
    lobby_out: mpsc::Receiver<Vec<u8>>,
    /// Lobby commands other members authored (relay-stamped with their author
    /// slot), to hand to the game thread.
    lobby_in: mpsc::Sender<(SlotId, Vec<u8>)>,
    /// Chat messages the game authored, to send up the control stream.
    chat_out: mpsc::Receiver<ChatOut>,
    /// Chat messages other members authored (relay-stamped with their author
    /// slot), to hand to the game thread.
    chat_in: mpsc::Sender<(SlotId, ChatOut)>,
    /// Manual drop requests the game authored, to send up the control stream as
    /// `RequestDrop` frames.
    request_drop: mpsc::Receiver<SlotId>,
    /// The relay-driven session-start directive, to hand to the game thread when
    /// the relay pushes a `SessionStart` down the control stream.
    session_start: mpsc::Sender<()>,
    /// Slot-connectivity changes, to hand to the game thread when the relay
    /// pushes a `SlotConnectivity` down the control stream.
    connectivity: mpsc::Sender<(SlotId, bool)>,
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
    /// deliveries (chat, connectivity display changes) never trip this: a full
    /// buffer just drops them.
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
        let (outbound_tx, outbound_rx) = mpsc::channel(capacity);
        let (inbound_tx, inbound_rx) = mpsc::channel(capacity);
        // Leaves are rare (one per departing peer); a small channel is ample.
        let (leaves_tx, leaves_rx) = mpsc::channel(LEAVE_CHANNEL_CAPACITY);
        // The game signals its own departure at most once.
        let (leave_intent_tx, leave_intent_rx) = mpsc::channel(LEAVE_INTENT_CHANNEL_CAPACITY);
        // The game hands over its result report at most once.
        let (result_tx, result_rx) = mpsc::channel(RESULT_CHANNEL_CAPACITY);
        let result_expected = Arc::new(AtomicBool::new(false));
        // Lobby commands flow in both directions during pre-game setup.
        let (lobby_out_tx, lobby_out_rx) = mpsc::channel(LOBBY_CHANNEL_CAPACITY);
        let (lobby_in_tx, lobby_in_rx) = mpsc::channel(LOBBY_CHANNEL_CAPACITY);
        // Chat flows in both directions for the whole game, unlike lobby.
        let (chat_out_tx, chat_out_rx) = mpsc::channel(CHAT_CHANNEL_CAPACITY);
        let (chat_in_tx, chat_in_rx) = mpsc::channel(CHAT_CHANNEL_CAPACITY);
        // Manual drop requests flow game → driver only, for the whole game.
        let (request_drop_tx, request_drop_rx) = mpsc::channel(REQUEST_DROP_CHANNEL_CAPACITY);
        // The session-start directive arrives at most a handful of times (the
        // fire, plus any re-push on late register or authority handoff).
        let (session_start_tx, session_start_rx) = mpsc::channel(LEAVE_CHANNEL_CAPACITY);
        // Connectivity changes are rare (a slot flips a small number of times over
        // a game); the leave-sized channel is ample.
        let (connectivity_tx, connectivity_rx) = mpsc::channel(LEAVE_CHANNEL_CAPACITY);
        let driver = Self {
            link,
            outbound: outbound_rx,
            inbound: inbound_tx,
            leaves: leaves_tx,
            leave_intent: leave_intent_rx,
            result: result_rx,
            result_expected: Arc::clone(&result_expected),
            lobby_out: lobby_out_rx,
            lobby_in: lobby_in_tx,
            chat_out: chat_out_rx,
            chat_in: chat_in_tx,
            request_drop: request_drop_rx,
            session_start: session_start_tx,
            connectivity: connectivity_tx,
        };
        let channels = TurnChannels {
            outbound: outbound_tx,
            inbound: inbound_rx,
            leaves: leaves_rx,
            leave_intent: leave_intent_tx,
            result: result_tx,
            result_expected,
            lobby_out: lobby_out_tx,
            lobby_in: lobby_in_rx,
            chat_out: chat_out_tx,
            chat_in: chat_in_rx,
            request_drop: request_drop_tx,
            session_start: session_start_rx,
            connectivity: connectivity_rx,
        };
        (driver, channels)
    }

    /// Runs the link over one connection until the game seam closes (a clean stop →
    /// `Ok`) or the link fails (→ [`DriverError`]). No reconnection: a link failure
    /// ends the driver and drops every channel, leaving the caller to re-dial and
    /// rebuild. Use [`run_reconnecting`](Self::run_reconnecting) to have the driver
    /// re-dial itself and keep the channels alive across a drop.
    pub async fn run(self) -> Result<(), DriverError> {
        let LinkDriver {
            mut link,
            outbound,
            inbound,
            leaves,
            leave_intent,
            result,
            result_expected,
            lobby_out,
            lobby_in,
            chat_out,
            chat_in,
            request_drop,
            session_start,
            connectivity,
        } = self;
        let mut seam = GameSeam {
            outbound,
            inbound,
            leaves,
            leave_intent,
            result,
            lobby_out,
            lobby_in,
            chat_out,
            chat_in,
            request_drop,
            session_start,
            connectivity,
        };
        let mut state = LoopState::new(result_expected);
        // The no-reconnect entry has no token to read a slot from, and it never
        // re-dials (so no resume anchor is ever computed from the unacked window).
        // It stamps slot 0 — the value the embedder already sends and the relay
        // rewrites to the authorized slot on ingress — preserving prior behavior.
        let result = Self::session(&mut link, &mut seam, &mut state, SlotId(0)).await;
        // Every exit ends this driver, so close the connection on the error
        // exits too (`session` already closed it on `Ok`): the relay's
        // slot-liveness signal is the connection, not this driver's local
        // state, so an unclosed handle would hold the relay-side slot until
        // QUIC's own idle timeout. Done here, not inside `session`, so the
        // error's classification always reads the connection state the failure
        // actually left behind.
        if result.is_err() {
            link.connection().close(0u32.into(), b"driver ended");
        }
        result
    }

    /// Runs the link and, on a mid-session link failure, re-dials the home relay
    /// *itself* — keeping every game channel alive — instead of ending.
    ///
    /// Across a drop the driver: emits its own slot's connectivity as `false` then
    /// `true` on [`connectivity`](TurnChannels::connectivity) (so the game learns of
    /// its own disconnect/reconnect from an explicit signal, not from the channels
    /// closing); re-dials with capped exponential backoff, presenting per-slot
    /// resume cursors so the relay replays the turns missed during the outage; and
    /// rebinds the link in place, so the receive-side dedup and per-slot reorder
    /// buffers survive and the replay dedups against turns already delivered. Turns
    /// the game produces during the outage are buffered and flushed in order once
    /// the link is back; turns already sent but unacked at the drop re-carry
    /// themselves over the new connection.
    ///
    /// The loop ends — dropping the channels, which the game reads as end-of-session
    /// — on a clean game shutdown (→ `Ok`), a terminal relay refusal
    /// ([`DriverError::SlotDeparted`]), an expired token
    /// ([`DriverError::TokenExpired`]), or a non-link failure the loop can't fix (a
    /// stalled game, an exhausted unacked window).
    pub async fn run_reconnecting(self, reconnect: Reconnect) -> Result<(), DriverError> {
        let Reconnect {
            endpoint,
            relay_addr,
            server_name,
            relay_id,
            identity,
            rehome,
            escalate_after,
            escalate_retry,
        } = reconnect;
        // The driver knows its own slot from its token; it labels the
        // self-connectivity signal with it.
        let own_slot = identity.token().claims.slot;
        // The reconnect machinery, its target mutable so a successful re-home moves
        // where subsequent drops reconnect to.
        let mut rc = ReconnectDriver {
            target: ReconnectTarget {
                endpoint,
                relay_addr,
                server_name,
                relay_id,
            },
            identity,
            rehome,
            escalate_after: escalate_after.unwrap_or(ESCALATE_AFTER),
            escalate_retry: escalate_retry.unwrap_or(ESCALATE_RETRY),
        };
        let LinkDriver {
            mut link,
            outbound,
            inbound,
            leaves,
            leave_intent,
            result,
            result_expected,
            lobby_out,
            lobby_in,
            chat_out,
            chat_in,
            request_drop,
            session_start,
            connectivity,
        } = self;
        let mut seam = GameSeam {
            outbound,
            inbound,
            leaves,
            leave_intent,
            result,
            lobby_out,
            lobby_in,
            chat_out,
            chat_in,
            request_drop,
            session_start,
            connectivity,
        };
        let mut state = LoopState::new(result_expected);
        let mut backoff = Backoff::new();

        loop {
            match Self::session(&mut link, &mut seam, &mut state, own_slot).await {
                // A clean game shutdown, or a link close absorbed after our own
                // leave intent went out: the session is over, not to be resumed.
                Ok(()) => return Ok(()),
                // A link/stream failure: keep the channels alive and re-dial.
                Err(error) if is_link_failure(&error) => {
                    // Close the failed connection now that it is classified.
                    // After a control-stream-only death the connection is still
                    // alive, and the relay's slot-liveness signal is the
                    // connection — an unclosed one holds the roster seat, so
                    // the immediate re-dial below would bounce off SLOT_TAKEN
                    // until QUIC's idle timeout. Closed here, never inside
                    // `session`, so classification (and the distinction between
                    // a dead control stream and a dead connection it rests on)
                    // always reads the state the failure actually left behind.
                    // A no-op when the connection itself is what died.
                    link.connection()
                        .close(0u32.into(), b"re-dialing after link failure");
                    // Best-effort like every connectivity delivery: a game not
                    // draining its display changes must not park the reconnect
                    // loop before it even starts re-dialing.
                    let _ = push_to_game(&seam.connectivity, (own_slot, false));
                    match reconnect_link(&mut rc, &mut link, &mut seam, &mut state, &mut backoff)
                        .await
                    {
                        Reconnected::Resumed => {
                            let _ = push_to_game(&seam.connectivity, (own_slot, true));
                            // Loop: run the next session over the rebound link.
                        }
                        Reconnected::Terminal(error) => return Err(error),
                        Reconnected::GameGone => return Ok(()),
                    }
                }
                // A non-link failure (stalled game, exhausted window) or a terminal
                // relay refusal surfaced from within the session: reconnecting can't
                // help, so end — closing the connection, which may be perfectly
                // healthy, so the relay frees this slot promptly instead of
                // serving a driver that has given up until its idle timeout.
                Err(error) => {
                    link.connection().close(0u32.into(), b"driver ended");
                    return Err(error);
                }
            }
        }
    }

    /// Runs one connection's worth of the turn loop, over the already-established
    /// [`link`](Link) and the game [`seam`](GameSeam), threading the state that must
    /// survive a reconnect ([`LoopState`]). Returns a clean stop as `Ok`, and a link
    /// or terminal failure as [`DriverError`] for the caller to re-dial through or
    /// end on.
    ///
    /// Multiplexes over one task: receiving the client's peers' turns and handing
    /// them to the game, sending the turns the game produced, flushing ack-only
    /// packets during outbound silence, driving the ack-beacon side-channel that
    /// keeps the unacked window bounded under loss, sending the game's end-of-game
    /// result report the moment it arrives, and — once the game signals its own
    /// departure — announcing that leave to the relay after the outbound queue and
    /// unacked window have drained (and the result, if one was expected, has been
    /// sent).
    ///
    /// The beacon is two uni-streams — one each direction — and its read half runs
    /// in a dedicated task so a partial stream read is never dropped mid-frame
    /// inside a `select!` branch (which would desync the framing and hand a
    /// garbage `(slot, cursor)` to `retire_through`); the task forwards each
    /// complete `(slot, cursor)` over an mpsc channel, whose `recv` *is*
    /// cancel-safe.
    async fn session(
        link: &mut Link,
        seam: &mut GameSeam,
        state: &mut LoopState,
        own_slot: SlotId,
    ) -> Result<(), DriverError> {
        let result = Self::session_body(link, seam, state, own_slot).await;
        // A clean stop closes the connection here: the detached beacon and
        // control-stream reader tasks each hold their own `connection.clone()`,
        // parked on `accept_uni`/`accept_bi`, so `link`'s own handle going out
        // of scope alone is never the last one -- without this, a clean exit
        // leaves the connection (and the relay-side slot it holds) open until
        // QUIC's own idle timeout. Closing here wakes those readers, freeing
        // them and the slot promptly.
        //
        // Deliberately NOT done on an `Err` exit: closing the connection out
        // from under the caller here would blur the "control stream died,
        // connection didn't" distinction the reconnect classification
        // (`is_link_failure`) and its own tests rely on. The callers own the
        // error-path close instead -- `run`/`run_reconnecting` close the
        // connection once the error is classified, so the relay-side slot is
        // freed promptly there too.
        if result.is_ok() {
            link.connection().close(0u32.into(), b"session ended");
        }
        result
    }

    async fn session_body(
        link: &mut Link,
        seam: &mut GameSeam,
        state: &mut LoopState,
        own_slot: SlotId,
    ) -> Result<(), DriverError> {
        let GameSeam {
            outbound,
            inbound,
            leaves,
            leave_intent,
            result,
            lobby_out,
            lobby_in,
            chat_out,
            chat_in,
            request_drop,
            session_start,
            connectivity,
        } = seam;
        // The reorder/dedup cursors, the outbound seq counter, the leave announcer,
        // and any turns buffered during a prior outage all persist across a
        // reconnect, so they come from the caller's state, not fresh locals.
        let LoopState {
            next_seq,
            pending,
            next_outbound_seq,
            announcer,
            outbound_buffer,
            game_started,
            retention,
            retention_bytes,
            pending_control_redivert,
        } = state;

        // The ack-beacon side-channel. The client opens its outbound uni-stream
        // (open_uni completes locally, no peer round-trip); the peer's stream is
        // accepted lazily inside the reader task, so a one-way-traffic link that
        // never sends a beacon doesn't block the dial on an accept that never
        // completes. The reader decodes complete frames and folds each
        // `(slot, cursor)` into a per-slot latest-value cell — a cursor is
        // cumulative within its slot, so the newest is all this loop needs,
        // and the final cursor before traffic stops survives however slowly
        // this loop drains (see `BeaconCursors`).
        let mut beacon_send = link
            .connection()
            .open_uni()
            .await
            .map_err(|error| DriverError::Link(LinkError::from(error)))?;
        let mut beacon_rx = spawn_beacon_reader(link.connection().clone());

        // The reliable control stream — the divert path for a turn too large
        // to ever ride a datagram. Each side opens one bidirectional stream
        // and writes on it alone; the peer reads the stream it accepted. Our
        // send half exists from here on (open_bi completes locally); the
        // relay's frames arrive via the reader task, which accepts lazily so
        // a session that never sees an oversize turn parks it harmlessly.
        // The recv half of our own stream is unused by convention (the relay
        // writes on the stream *it* opened) and dropped.
        let (mut control_send, _our_stream_recv) = link
            .connection()
            .open_bi()
            .await
            .map_err(|error| DriverError::Link(LinkError::from(error)))?;
        let mut control_rx = spawn_control_reader(link.connection().clone());
        // The highest cursor the client has pushed to the peer, per slot. Push
        // only on advance so a healthy link with a static receive prefix sends
        // nothing.
        let mut last_beacon_sent: HashMap<SlotId, u64> = HashMap::new();
        // Whether the inbound beacon reader task is still feeding cursors. Once it
        // ends (the peer's beacon uni-stream closed or errored), `recv()` returns
        // `None` immediately on every poll — an always-ready future that would spin
        // the loop at 100% CPU. Disabling this branch on the first `None` keeps the
        // driver asleep; the real link failure surfaces separately via `link.recv()`.
        let mut beacon_alive = true;

        // Whether we've received from the relay since we last sent it a packet.
        // Every packet we send folds in the latest acks, so any outgoing turn
        // clears this too; the flush only needs to carry acks when no turn has.
        let mut acks_owed = false;
        // The next maintenance flush. Pushed out whenever an outbound turn re-carries
        // unacked turns (recovery is riding the stream, so no flush is due); left to
        // fire when a send carries no redundancy or the link is idle, so a turn the
        // fresh packets can't re-carry is still retransmitted.
        let mut flush_deadline = Instant::now() + FLUSH_INTERVAL;
        // Re-carry any oversize turns a re-home deferred to this connection's control
        // stream. Too large to ride a datagram, they were kept out of the unacked
        // window by `reinject_retention` (where the redundancy pass would skip them
        // forever) and staged here instead; the replacement relay needs them to fan
        // out to peers that never received them from the dead relay. They ride the
        // fresh control stream — the same divert path an oversize turn takes when
        // first sent — before the buffered live turns below, preserving seq order
        // (a retained turn's seq always precedes a turn produced during the outage).
        // Empty on a same-relay resume, which keeps the old relay's reliable state.
        if let Err(error) =
            redivert_pending_control(&mut control_send, pending_control_redivert).await
        {
            return announcer.absorb_link_close(Err(DriverError::from(error)));
        }
        // Flush any turns the game produced while the link was down, in seq order,
        // before live turns resume. On a fresh dial the buffer is empty; on a
        // reconnect these are the turns buffered during the outage. Each goes out
        // exactly like a live outbound turn: assigned its origin seq from the
        // persistent counter, sent on the datagram path when it fits or diverted to
        // the control stream when it cannot, and able to release a pending leave
        // intent it was the last thing holding. `next_outbound_seq`, the reorder
        // cursors, and the announcer all live in the persistent `state`, so a
        // resumed session continues the seq stream rather than rewinding it.
        for mut buffered in std::mem::take(outbound_buffer) {
            buffered.seq = *next_outbound_seq;
            buffered.slot = u32::from(own_slot.0);
            *next_outbound_seq += 1;
            // Retain a copy for a possible re-home re-injection before the turn is
            // handed to the link (which moves it).
            retain_sent(retention, retention_bytes, &buffered);
            if link.payload_fits(&buffered)? {
                match send_packet(link, Some(buffered)) {
                    Ok(carried_redundancy) => {
                        if carried_redundancy {
                            flush_deadline = Instant::now() + FLUSH_INTERVAL;
                        }
                    }
                    Err(error) => return announcer.absorb_link_close(Err(error)),
                }
                acks_owed = false;
                if check_cap(link.payloads_in_flight()) {
                    return Err(DriverError::UnackedWindowExhausted {
                        in_flight: link.payloads_in_flight(),
                        cap: UNACKED_WINDOW_CAP,
                    });
                }
            } else if let Err(error) = send_control_turn(&mut control_send, buffered).await {
                return announcer.absorb_link_close(Err(DriverError::from(error)));
            }
            announcer
                .maybe_send(&mut control_send, outbound, link)
                .await?;
        }
        // Mirrors `beacon_alive`: the game signals at most once, so this disarms
        // on the channel's first resolution (the real signal, or the sender
        // dropping without one) rather than only on `None` — either way there is
        // nothing further to receive, and leaving the branch armed past that
        // would either spin on a closed channel or just poll a channel that will
        // never produce anything else.
        let mut leave_intent_alive = true;

        // Mirrors `leave_intent_alive`: the game hands over a result at most
        // once, so this disarms on the channel's first resolution — the payload,
        // or the sender dropping without one — rather than spinning on a closed
        // channel.
        let mut result_alive = true;

        // Whether the game's lobby-command sender is still live. Unlike the
        // single-shot channels above, lobby commands stream during setup, so this
        // disarms only on the sender dropping (a `None`) — the game finished
        // authoring lobby commands (the game started, or it left) — after which
        // `recv()` is an always-ready `None` that would spin the loop.
        let mut lobby_out_alive = true;

        // Whether the game's chat sender is still live. Unlike lobby, chat
        // streams for the whole game, not just pre-game setup, but the disarm
        // rule is the same: only on the sender dropping (a `None`), after which
        // `recv()` is an always-ready `None` that would spin the loop.
        let mut chat_out_alive = true;

        // Whether the game's drop-request sender is still live. Like chat it
        // streams for the whole game, with the same disarm rule: only on the
        // sender dropping (a `None`), after which `recv()` is an always-ready
        // `None` that would spin the loop.
        let mut request_drop_alive = true;

        loop {
            // Armed only once the game has signaled its departure (the announcer
            // has a `deadline`); the day-out fallback keeps the branch dormant,
            // and the type checker satisfied, otherwise.
            let leave_deadline = announcer
                .deadline()
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));

            tokio::select! {
                received = link.recv() => {
                    let received = match received {
                        Ok(received) => received,
                        // Once the intent is written, the relay closing this link
                        // is the expected confirmation it processed the leave, not
                        // a link failure — `absorb_link_close` turns it into a
                        // clean stop; before that it is a real failure.
                        Err(error) => return announcer.absorb_link_close(Err(error.into())),
                    };
                    // Only a payload-bearing packet needs an ack in return; owing one
                    // for the relay's ack-only flush would just bounce ack-only packets
                    // back and forth on an otherwise idle link.
                    if received.carried_payloads {
                        acks_owed = true;
                    }
                    for payload in received.fresh {
                        // A slot id past `u8` range names no real slot; a
                        // truncating cast would alias it onto `slot % 256` and
                        // corrupt another player's turn stream. Drop it (defensive
                        // — the wire values are validated upstream).
                        let Ok(slot_id) = u8::try_from(payload.slot) else {
                            tracing::warn!(
                                slot = payload.slot,
                                "received turn names a slot id out of range; dropping it",
                            );
                            continue;
                        };
                        let slot = SlotId(slot_id);
                        let slot_next = next_seq.entry(slot).or_insert(0);
                        if payload.seq >= *slot_next {
                            pending
                                .entry(slot)
                                .or_default()
                                .insert(payload.seq, payload);
                        }
                    }
                    match release_ready(next_seq, pending, inbound) {
                        Release::Delivered => {}
                        Release::GameClosed => return Ok(()),
                        Release::GameStalled => return Err(DriverError::GameStalled),
                    }
                    flush_delivered_cursors(link, &mut beacon_send, &mut last_beacon_sent, next_seq)
                        .await;
                    if check_cap(link.payloads_in_flight()) {
                        return Err(DriverError::UnackedWindowExhausted {
                            in_flight: link.payloads_in_flight(),
                            cap: UNACKED_WINDOW_CAP,
                        });
                    }
                    // An ack folded into the manager above may be the last one
                    // a pending leave intent was waiting on.
                    announcer.maybe_send(&mut control_send, outbound, link).await?;
                }
                // An oversize turn from the relay, delivered over the reliable
                // control stream because no datagram could carry it. Folding it
                // through the link's dedup keeps the two delivery paths one
                // stream: the per-slot delivered cursor advances across it and
                // a copy that somehow arrived both ways collapses to one
                // delivery. It then joins the same per-slot reorder buffer, so
                // the game sees one ordered stream regardless of which path
                // each turn took.
                received = control_rx.recv() => {
                    match received {
                        // A relay-pushed synced leave: hand it to the game's leave
                        // tracker. This is the delivery path a drop needs — the turn
                        // stream has stalled, but the reliable control stream still
                        // flows. Correctness-critical: a lost leave strands lockstep
                        // on a slot that will never send another turn, so a game
                        // that stopped draining these is a stall, not a skip.
                        Some(ControlInbound::Leave(leave)) => match push_to_game(leaves, leave) {
                            GamePush::Sent => {}
                            GamePush::Full => {
                                tracing::warn!("game stopped draining synced leaves");
                                return Err(DriverError::GameStalled);
                            }
                            GamePush::Closed => return Ok(()),
                        },
                        // A client only ever *sends* a leave intent up; it never
                        // receives one back (the relay is the only recipient).
                        // Ignore a stray one, mirroring how the relay edge
                        // ignores a stray client-sent `Leave`.
                        Some(ControlInbound::LeaveIntent) => {
                            tracing::warn!(
                                "ignoring unexpected relay-sent leave-intent control frame"
                            );
                        }
                        // Likewise a result report only ever travels client → relay;
                        // a client never receives one back, so ignore a stray one.
                        Some(ControlInbound::GameResult(_)) => {
                            tracing::warn!(
                                "ignoring unexpected relay-sent game-result control frame"
                            );
                        }
                        // A drop request only ever travels client → relay; a client
                        // never receives one back, so ignore a stray one.
                        Some(ControlInbound::RequestDrop(_)) => {
                            tracing::warn!(
                                "ignoring unexpected relay-sent drop-request control frame"
                            );
                        }
                        // A lobby command another member authored, relay-stamped
                        // with the author's slot. Hand it to the game tagged with
                        // that slot so it applies the bytes to that member's lobby
                        // turn. Replayed earlier commands and live ones arrive on
                        // this one path, in order. Correctness-critical: a lost
                        // setup command leaves a member's pre-game state
                        // incomplete, so a game that stopped draining these is a
                        // stall, not a skip.
                        Some(ControlInbound::Lobby(command)) => {
                            // A slot id past `u8` range names no real member; a
                            // truncating cast would misattribute the command. Drop
                            // it (defensive — the relay stamps a real slot).
                            let Ok(slot_id) = u8::try_from(command.slot) else {
                                tracing::warn!(
                                    slot = command.slot,
                                    "lobby command names a slot id out of range; dropping it",
                                );
                                continue;
                            };
                            match push_to_game(
                                lobby_in,
                                (SlotId(slot_id), command.payload.to_vec()),
                            ) {
                                GamePush::Sent => {}
                                GamePush::Full => {
                                    tracing::warn!("game stopped draining lobby commands");
                                    return Err(DriverError::GameStalled);
                                }
                                GamePush::Closed => return Ok(()),
                            }
                        }
                        // An in-game chat message another member authored,
                        // relay-stamped with the author's slot — the mid-game
                        // counterpart to the lobby branch above. No replay here
                        // (chat keeps no log): every message that arrives on
                        // this path is live. Best-effort: a full buffer just
                        // drops the message — chat has no state a lost line
                        // could corrupt, and it must never stall the turns.
                        Some(ControlInbound::Chat(chat)) => {
                            // As above: a slot id past `u8` range names no real
                            // member; drop it rather than misattribute it.
                            let Ok(slot_id) = u8::try_from(chat.slot) else {
                                tracing::warn!(
                                    slot = chat.slot,
                                    "game-chat message names a slot id out of range; dropping it",
                                );
                                continue;
                            };
                            let out = ChatOut {
                                target_kind: chat.target_kind,
                                target_slot: chat.target_slot,
                                text: chat.text,
                            };
                            match push_to_game(chat_in, (SlotId(slot_id), out)) {
                                GamePush::Sent => {}
                                GamePush::Full => {
                                    tracing::debug!(
                                        "dropping game-chat message; the game is not draining chat"
                                    );
                                }
                                GamePush::Closed => return Ok(()),
                            }
                        }
                        // The relay-driven session-start directive: every expected
                        // slot has connected, so the game may begin. Hand it to the
                        // game thread; a repeat (a re-push on late register or an
                        // authority handoff) is idempotent for the game.
                        // Correctness-critical: a game waiting on a start it never
                        // hears waits forever, so a full buffer here is a stall.
                        Some(ControlInbound::SessionStart) => {
                            // The game has started: from here a dead home relay may
                            // escalate to coordinator-mediated failover. Latched, and
                            // kept across reconnects via the persistent state.
                            *game_started = true;
                            match push_to_game(session_start, ()) {
                                GamePush::Sent => {}
                                GamePush::Full => {
                                    tracing::warn!(
                                        "game stopped draining session-start directives"
                                    );
                                    return Err(DriverError::GameStalled);
                                }
                                GamePush::Closed => return Ok(()),
                            }
                        }
                        // A relay-pushed slot-connectivity change: a member's link
                        // died or (re)registered. Hand it to the game thread tagged
                        // with the slot; the game drives its "player X disconnected"
                        // display off it, independent of the synced leave. Best-
                        // effort — an unknown slot is the game's no-op, and a full
                        // buffer just drops the change (a stale display beats a
                        // stalled session; the synced leave rides its own path).
                        Some(ControlInbound::Connectivity(change)) => {
                            // A slot id past `u8` range names no real member; a
                            // truncating cast would misattribute the change. Drop it
                            // (defensive — the relay stamps a real slot).
                            let Ok(slot_id) = u8::try_from(change.slot) else {
                                tracing::warn!(
                                    slot = change.slot,
                                    "slot-connectivity names a slot id out of range; dropping it",
                                );
                                continue;
                            };
                            match push_to_game(connectivity, (SlotId(slot_id), change.connected)) {
                                GamePush::Sent => {}
                                GamePush::Full => {
                                    tracing::debug!(
                                        "dropping connectivity change; the game is not draining them"
                                    );
                                }
                                GamePush::Closed => return Ok(()),
                            }
                        }
                        Some(ControlInbound::OversizeTurn(payload)) => {
                            // As on the datagram path: a slot id past `u8` range
                            // names no real slot, and a truncating cast would alias
                            // it onto another player's stream. Drop it rather than
                            // deliver it.
                            let Ok(slot_id) = u8::try_from(payload.slot) else {
                                tracing::warn!(
                                    slot = payload.slot,
                                    "oversize turn names a slot id out of range; dropping it",
                                );
                                continue;
                            };
                            let slot = SlotId(slot_id);
                            if link.deliver_external(slot, payload.seq)? {
                                next_seq.entry(slot).or_insert(0);
                                pending
                                    .entry(slot)
                                    .or_default()
                                    .insert(payload.seq, payload);
                                match release_ready(next_seq, pending, inbound) {
                                    Release::Delivered => {}
                                    Release::GameClosed => return Ok(()),
                                    Release::GameStalled => return Err(DriverError::GameStalled),
                                }
                                flush_delivered_cursors(
                                    link,
                                    &mut beacon_send,
                                    &mut last_beacon_sent,
                                    next_seq,
                                )
                                .await;
                            }
                        }
                        // The reader task ended: a one-sided stream reset, an
                        // over-cap frame, a decode failure, or a clean EOF. This
                        // is the only channel a synced `LeaveDirective`,
                        // `SessionStart`, and `SlotConnectivity` ever arrive on
                        // — unlike the beacon side-channel (a pure one-way
                        // cursor feed a real link failure surfaces separately
                        // via `link.recv()`), nothing else in this loop will
                        // ever notice this is gone. So this ends the session
                        // rather than disarming and limping on: treated as a
                        // link failure, the reconnect loop re-dials and
                        // `session` re-spawns a fresh control reader from
                        // scratch on the rebound link. `absorb_link_close`
                        // still applies — the connection may be closing for
                        // the very reason this reader ended (e.g. right after
                        // our own leave intent was processed), in which case
                        // this becomes the same clean stop `link.recv()`'s
                        // error arm would have produced.
                        None => {
                            tracing::info!("control stream reader ended");
                            return announcer
                                .absorb_link_close(Err(DriverError::ControlStreamLost));
                        }
                    }
                }
                outgoing = outbound.recv() => {
                    match outgoing {
                        // A turn the game produced. It goes out carrying our acks; if it
                        // also re-carried unacked turns, recovery is riding the stream,
                        // so push the flush out. If it carried none (a near-MTU turn that
                        // filled the datagram), leave the timer so the flush retransmits.
                        Some(mut payload) => {
                            // Assign this turn its origin seq and slot — the client
                            // is the sole authority for both its own slot's identity
                            // and its production order. The embedder leaves `slot` at
                            // 0 on every outbound turn (as it does `seq`); stamping
                            // our authorized slot here keys the AckManager's unacked
                            // window under the same `own_slot` the resume anchor and
                            // ack-beacon retirement use, so an in-flight turn is not
                            // stranded under a phantom slot-0 key across a reconnect.
                            payload.seq = *next_outbound_seq;
                            payload.slot = u32::from(own_slot.0);
                            *next_outbound_seq += 1;
                            // Retain a copy for a possible re-home re-injection before
                            // the turn is handed to the link (which moves it).
                            retain_sent(retention, retention_bytes, &payload);
                            if link.payload_fits(&payload)? {
                                let carried_redundancy = match send_packet(link, Some(payload)) {
                                    Ok(carried_redundancy) => carried_redundancy,
                                    // The connection went down while sending this
                                    // turn. If we already announced our leave, the
                                    // relay closing the link out from under this
                                    // send is the expected confirmation, not a
                                    // failure.
                                    Err(error) => {
                                        return announcer.absorb_link_close(Err(error));
                                    }
                                };
                                acks_owed = false;
                                if carried_redundancy {
                                    flush_deadline = Instant::now() + FLUSH_INTERVAL;
                                }
                                if check_cap(link.payloads_in_flight()) {
                                    return Err(DriverError::UnackedWindowExhausted {
                                        in_flight: link.payloads_in_flight(),
                                        cap: UNACKED_WINDOW_CAP,
                                    });
                                }
                            } else {
                                // Too large for any datagram: divert to the
                                // reliable control stream, whose QUIC-level
                                // reliability replaces redundancy for this turn
                                // — it never enters the unacked window and no
                                // ack retires it. A write failure is normally
                                // fatal (nothing re-carries this turn, and
                                // dropping it would desync lockstep) — but once
                                // the leave intent is out, the relay closing the
                                // stream under this write is the expected
                                // confirmation, not a failure.
                                if let Err(error) = send_control_turn(&mut control_send, payload).await
                                {
                                    return announcer
                                        .absorb_link_close(Err(DriverError::from(error)));
                                }
                            }
                            // The turn just sent may have been the last one
                            // outstanding, in which case a pending leave intent
                            // is now ready to go out.
                            announcer.maybe_send(&mut control_send, outbound, link).await?;
                        }
                        // The game dropped its sender: a clean stop.
                        None => return Ok(()),
                    }
                }
                // The game signaling its own clean departure (F10 quit, game
                // over). This branch only arms the announcer — it never sends the
                // frame itself, since the relay must still see every turn this
                // client already produced. The announcer's `maybe_send` below (and
                // after every other branch that can change drain state) does the
                // actual write once the outbound queue and unacked window are both
                // empty, and the safety-timeout branch below covers the case where
                // they never drain. Disarmed after this
                // resolves once, whether or not the game actually signaled —
                // the game signals at most once, so there is nothing further to
                // receive either way, and leaving the branch armed on a `None`
                // (the sender dropped without signaling) would spin the loop on
                // an always-ready `None`.
                signal = leave_intent.recv(), if leave_intent_alive => {
                    leave_intent_alive = false;
                    if signal.is_some() {
                        announcer.arm(LEAVE_INTENT_TIMEOUT);
                        announcer.maybe_send(&mut control_send, outbound, link).await?;
                    }
                    // A `None` (the game dropped its sender without ever
                    // signaling — an unclean teardown) needs no further action:
                    // the driver keeps running exactly as if leave-intent
                    // didn't exist, and the relay falls back to detecting the
                    // eventual link death itself.
                }
                // The game handed over its end-of-game result report. Send it up
                // the control stream immediately — mid-game, over a fully live
                // link — rather than waiting for any turn drain: a defeat report
                // must go out while the link is still up. At most one is sent; a
                // second payload, or one arriving after the leave intent already
                // went out, is dropped. Disarmed on the channel's first
                // resolution (the payload, or the sender dropping without one),
                // like the leave-intent branch.
                payload = result.recv(), if result_alive => {
                    match payload {
                        Some(payload) => {
                            if announcer.result_sent() {
                                tracing::debug!(
                                    "dropping extra game-result payload; one already sent"
                                );
                            } else if announcer.sent() {
                                tracing::debug!(
                                    "dropping game-result payload arriving after leave intent"
                                );
                            } else {
                                // A best-effort report: a failed send is not worth
                                // tearing the driver down over — the link may still
                                // be live for play (a mid-game defeat report leaves
                                // the game running), and the relay reasons the
                                // outcome from the departure that follows. Latch it
                                // as sent regardless, so the leave-intent hold
                                // releases and no retry piles up.
                                if let Err(error) =
                                    send_control_game_result(&mut control_send, payload.into())
                                        .await
                                {
                                    tracing::debug!(
                                        %error,
                                        "game-result send failed; dropping the report"
                                    );
                                }
                                announcer.note_result_sent();
                                // Sending the result may have been the last thing
                                // a pending leave intent was holding for.
                                announcer.maybe_send(&mut control_send, outbound, link).await?;
                            }
                        }
                        // The game dropped its result sender without ever handing
                        // one over: nothing to send, and the leave-intent hold is
                        // still bounded by the safety timeout.
                        None => result_alive = false,
                    }
                }
                // A lobby command the game authored during setup. Send it up the
                // reliable control stream at once — setup runs before any turn
                // barrier exists, so there is nothing to drain behind. The relay
                // stamps this client's authenticated slot (the `0` here is
                // ignored) and fans it to the other members. Disarmed when the
                // game drops its sender (setup finished). A send failure means the
                // stream (and almost certainly the connection) is gone; a dropped
                // setup command would leave a member's pre-game state incomplete,
                // so it is the same reconnect trigger as an undeliverable oversize
                // turn — except once our leave intent is out, the relay closing
                // the stream under this write is the expected confirmation.
                //
                // Unlike an oversize turn, a lobby command is never retained for
                // redelivery on a resume: `LobbyCommand` carries no seq or other
                // origin identity, and the relay's lobby log neither dedups nor
                // rejects a byte-identical repeat — it is simply appended and
                // fanned out again as a second, indistinguishable command. Ever
                // resending one (even only the "recent tail") risks silently
                // corrupting setup state (a double-applied slot/color/ready
                // toggle), which is worse than the narrow gap this leaves: a
                // drop between this write succeeding locally and the relay
                // actually processing it, on a same-relay resume, can still lose
                // a lobby command with no retry. Known and intentionally out of
                // scope until lobby commands carry real delivery confirmation.
                bytes = lobby_out.recv(), if lobby_out_alive => {
                    match bytes {
                        Some(bytes) => {
                            let command = LobbyCommand {
                                slot: 0,
                                payload: bytes.into(),
                            };
                            if let Err(error) =
                                send_control_lobby(&mut control_send, command).await
                            {
                                return announcer
                                    .absorb_link_close(Err(DriverError::from(error)));
                            }
                        }
                        None => lobby_out_alive = false,
                    }
                }
                // A chat message the game authored — the mid-game counterpart to
                // the lobby branch above. Sent at once, same as a lobby command:
                // chat has no turn barrier or drain to wait behind either. Unlike
                // a lobby command, though, a send failure here is NOT treated as
                // a link failure: chat has no pre-game state a lost message
                // could leave incomplete, so this is best-effort like a
                // `GameResult` send — log it and keep the driver running rather
                // than tearing the session down over a dropped chat line.
                // Disarmed only when the game drops its sender (chat streams for
                // the whole game, unlike lobby).
                chat = chat_out.recv(), if chat_out_alive => {
                    match chat {
                        Some(ChatOut { target_kind, target_slot, text }) => {
                            let message = GameChat {
                                slot: 0,
                                target_kind,
                                target_slot,
                                text,
                            };
                            if let Err(error) = send_control_chat(&mut control_send, message).await
                            {
                                tracing::debug!(
                                    %error,
                                    "game-chat send failed; dropping the message"
                                );
                            }
                        }
                        None => chat_out_alive = false,
                    }
                }
                // A manual drop request the game authored: the survivor asked to
                // drop a disconnected member. Send it up the reliable control stream
                // at once — no drain to wait behind, like chat — naming the target
                // slot; the relay stamps this client's authenticated slot as the
                // requester. Best-effort, exactly like chat: a send failure is
                // logged and swallowed rather than treated as a link failure, since
                // a lost request is not correctness-critical — the survivor can
                // simply click again, and the `LeaveDirective` for the target is the
                // only confirmation. Disarmed only when the game drops its sender.
                target = request_drop.recv(), if request_drop_alive => {
                    match target {
                        Some(target) => {
                            if let Err(error) =
                                send_control_request_drop(&mut control_send, u32::from(target.0))
                                    .await
                            {
                                tracing::debug!(
                                    %error,
                                    target = target.0,
                                    "drop-request send failed; dropping the request"
                                );
                            }
                        }
                        None => request_drop_alive = false,
                    }
                }
                // Safety timeout: the game signaled its departure but the
                // outbound queue or unacked window hadn't drained within
                // `LEAVE_INTENT_TIMEOUT`. If acks aren't coming the link is
                // effectively dead and the ordinary drop path (idle timeout)
                // covers it regardless; sending here anyway is harmless even if
                // the link is fine — the relay stops forwarding this slot's
                // turns the moment it sees the intent, so a few turns still
                // technically unacked changes nothing.
                _ = sleep_until(leave_deadline), if announcer.deadline().is_some() => {
                    announcer.force_send(&mut control_send).await?;
                }
                // The peer pushed a per-slot delivered-through cursor over the beacon
                // stream. The reader task already assembled the complete frame off a
                // cancel-safe path, so receiving here can never be a partial read.
                // `mpsc::Receiver::recv` is cancel-safe in select!. The
                // `if beacon_alive` precondition disables this branch once the reader
                // task ends — otherwise `recv()` returns `None` on every poll, an
                // always-ready future that would spin the loop at 100% CPU (the
                // connection may still be up, so `link.recv()` wouldn't surface it).
                received = beacon_rx.recv(), if beacon_alive => {
                    match received {
                        Some((slot, cursor)) => {
                            link.retire_through(slot, cursor);
                            if check_cap(link.payloads_in_flight()) {
                                return Err(DriverError::UnackedWindowExhausted {
                                    in_flight: link.payloads_in_flight(),
                                    cap: UNACKED_WINDOW_CAP,
                                });
                            }
                            // The beacon force-retiring turns may have just
                            // emptied the unacked window a pending leave intent
                            // was waiting on.
                            announcer.maybe_send(&mut control_send, outbound, link).await?;
                        }
                        // The reader task ended (peer's beacon stream closed or
                        // errored). Stop polling it: the real link failure, if any,
                        // surfaces via `link.recv()`; a beacon-only stream reset must
                        // not spin the loop. The cap still bounds the window without
                        // beacons — the driver just stops force-advancing.
                        None => beacon_alive = false,
                    }
                }
                // The game dropped its receiver. This is its own branch so the stop
                // is noticed even on a quiet link with nothing to deliver — without
                // it, the closure would surface only on the next `try_send`, leaving
                // the connection (and the relay slot) open indefinitely.
                _ = inbound.closed() => return Ok(()),
                _ = sleep_until(flush_deadline) => {
                    // The maintenance flush, reached because the outbound stream
                    // stopped re-carrying unacked turns (near-MTU) or went idle. When
                    // a turn is unacked or we owe acks, send an ack-only packet: it
                    // re-carries unacked turns oldest-first (its full budget has room
                    // the near-MTU fresh packets did not) and folds in any acks owed.
                    // It stays silent when nothing is unacked and nothing is owed.
                    if acks_owed || link.payloads_in_flight() > 0 {
                        match send_packet(link, None) {
                            Ok(_) => {}
                            // Post-announce, the relay closing the link under this
                            // flush is the expected confirmation, not a failure.
                            Err(error) => return announcer.absorb_link_close(Err(error)),
                        }
                        acks_owed = false;
                    }
                    flush_deadline = Instant::now() + FLUSH_INTERVAL;
                }
            }
        }
    }
}

/// Sends one packet, returning whether it re-carried any still-unacked turn — if so,
/// retransmission is already riding the outbound stream and the flush can rest.
///
/// A refused datagram (`PayloadTooLarge`) here is a *bundle* that outgrew a
/// path-MTU shrink between sizing and sending — a recoverable loss the next,
/// smaller bundle re-carries, so it is not an error. It can never be a lone
/// turn too big for the path: the caller pre-checks with
/// [`Link::payload_fits`] and diverts those to the control stream before they
/// reach here (and the link itself refuses one pre-registration as a second
/// line of defense).
fn send_packet(link: &mut Link, payload: Option<Payload>) -> Result<bool, DriverError> {
    match link.send(payload) {
        Ok(redundant) => Ok(redundant > 0),
        Err(LinkError::PayloadTooLarge { needed, budget }) => {
            tracing::debug!(
                needed,
                budget,
                "datagram refused by a shrunken path; will re-carry"
            );
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

/// What [`release_ready`] observed while handing released turns to the game.
enum Release {
    /// Every releasable turn was handed off (possibly none).
    Delivered,
    /// The game dropped its receiver: a clean stop.
    GameClosed,
    /// The game stopped draining and the inbound buffer filled.
    GameStalled,
}

/// Releases each slot's contiguous run of pending turns to the game, holding
/// the rest. Hands off without ever awaiting: blocking on a full channel would
/// park the whole driver — no acks, no outbound turns, no link-failure
/// detection — behind a stalled consumer. Shared by the datagram and
/// control-stream delivery paths, so a turn is released the same way no matter
/// which path delivered it.
fn release_ready(
    next_seq: &mut HashMap<SlotId, u64>,
    pending: &mut HashMap<SlotId, BTreeMap<u64, Payload>>,
    inbound: &mpsc::Sender<Payload>,
) -> Release {
    for (slot, slot_next) in next_seq.iter_mut() {
        let Some(slot_pending) = pending.get_mut(slot) else {
            continue;
        };
        while let Some(payload) = slot_pending.remove(slot_next) {
            match inbound.try_send(payload) {
                Ok(()) => *slot_next += 1,
                Err(mpsc::error::TrySendError::Full(payload)) => {
                    // Put the held turn back before surfacing the stall.
                    slot_pending.insert(*slot_next, payload);
                    return Release::GameStalled;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return Release::GameClosed,
            }
        }
    }
    Release::Delivered
}

/// Pushes each slot's delivered-through cursor to the peer so it can
/// force-advance its unacked window past turns it now knows we received.
/// `flush_beacon` pushes only cursors that advanced past `last_sent`, so a
/// static cursor (a genuine forward gap) sends nothing — the cap handles that.
async fn flush_delivered_cursors(
    link: &Link,
    beacon_send: &mut quinn::SendStream,
    last_sent: &mut HashMap<SlotId, u64>,
    next_seq: &HashMap<SlotId, u64>,
) {
    let cursors: HashMap<SlotId, u64> = next_seq
        .keys()
        .filter_map(|&slot| link.delivered_through(slot).map(|c| (slot, c)))
        .collect();
    if !cursors.is_empty() {
        flush_beacon(beacon_send, last_sent, cursors).await;
    }
}

/// Returns `true` if the unacked window has crossed the hard cap — the
/// sustained forward-loss case the beacon cannot rescue (the peer is genuinely
/// behind, not just ack-starved). The caller surfaces
/// [`DriverError::UnackedWindowExhausted`], which the reconnect loop treats as
/// terminal rather than re-dialing (see [`is_link_failure`]).
fn check_cap(in_flight: usize) -> bool {
    in_flight > UNACKED_WINDOW_CAP
}

/// The first reconnect backoff delay, doubled each attempt up to
/// [`RECONNECT_BACKOFF_CAP`].
const RECONNECT_BACKOFF_INITIAL: Duration = Duration::from_millis(500);

/// The ceiling on the reconnect backoff delay.
const RECONNECT_BACKOFF_CAP: Duration = Duration::from_secs(5);

/// Per-attempt bound on one reconnect dial. Short enough that several attempts fit
/// well inside the window before a survivor could request the drop, so a
/// recoverable drop reconnects before the slot could be decided departed.
const RECONNECT_DIAL_TIMEOUT: Duration = Duration::from_secs(3);

/// Ceiling on turns buffered while the link is down. Under lockstep the game stalls
/// within a couple turns of losing the link — it can't advance without its peers'
/// turns — so this is a safety bound, not a tuned depth; past it the oldest buffered
/// turn is dropped (with a warning) rather than let the buffer grow without bound.
const OUTAGE_OUTBOUND_BUFFER_CAP: usize = 256;

/// How many of this client's own recently-sent turns the retention ring keeps for
/// re-injection after a re-home. Independent of ack retirement — a turn the old
/// relay acked is dropped from the unacked window but kept here — so the ring can
/// re-carry it to a replacement relay whose turn ring is empty. A few times the
/// deepest realistic latency buffer; the byte cap ([`RETENTION_BYTE_CAP`]) bounds it
/// too, so an oversize turn can't blow the memory budget.
const RETENTION_TURN_CAP: usize = 512;

/// The byte ceiling on the retention ring, enforced alongside
/// [`RETENTION_TURN_CAP`] so a run of large turns can't grow it past this even
/// under the turn cap. 256 KiB comfortably holds 512 ordinary (tens-of-bytes)
/// turns and still bounds a pathological run of near-MTU ones.
const RETENTION_BYTE_CAP: usize = 256 * 1024;

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
const ESCALATE_AFTER: Duration = Duration::from_secs(10);

/// How often the driver re-escalates while the provider keeps answering
/// `Unavailable` (no relay can take the session over yet) or a re-home dial keeps
/// failing — the coordinator may gain a relay, so the driver re-asks on this
/// cadence while continuing its same-relay backoff in between. Kept below the ~45s
/// BW native stall-drop budget (see [`ESCALATE_AFTER`]) so a transiently-unavailable
/// coordinator is re-asked at least twice before the game would give up on the slot.
const ESCALATE_RETRY: Duration = Duration::from_secs(15);

/// The driver's own bound on one [`RehomeProvider::rehome`] ask. The provider is
/// embedder code doing an app-server/coordinator round-trip and is expected to
/// enforce its own HTTP timeout well under this — the driver's bound exists so a
/// provider that hangs anyway (a stuck app-server call, a lost response) cannot
/// freeze reconnection, teardown observation, and the outage-buffer cap with it.
/// A timed-out ask is treated exactly as [`RehomeOutcome::Unavailable`]: resume
/// the same-relay backoff and re-ask on the [`ESCALATE_RETRY`] cadence. Sized to
/// fit the ~45s BW stall-drop budget ([`ESCALATE_AFTER`]'s doc): 10s to the first
/// escalation + this bound + a ≤3s dial still leaves budget for one retry ask.
const REHOME_PROVIDER_DEADLINE: Duration = Duration::from_secs(20);

/// The driver's half of the game seam: the channels a [`LinkDriver`] owns to
/// exchange turns and control with the game thread. Bundled so a session runs over
/// them by reference and they outlive a reconnect that swaps the underlying link.
struct GameSeam {
    outbound: mpsc::Receiver<Payload>,
    inbound: mpsc::Sender<Payload>,
    leaves: mpsc::Sender<LeaveDirective>,
    leave_intent: mpsc::Receiver<()>,
    result: mpsc::Receiver<Vec<u8>>,
    lobby_out: mpsc::Receiver<Vec<u8>>,
    lobby_in: mpsc::Sender<(SlotId, Vec<u8>)>,
    chat_out: mpsc::Receiver<ChatOut>,
    chat_in: mpsc::Sender<(SlotId, ChatOut)>,
    request_drop: mpsc::Receiver<SlotId>,
    session_start: mpsc::Sender<()>,
    connectivity: mpsc::Sender<(SlotId, bool)>,
}

/// The driver state that must persist across a reconnect so a re-dialed session
/// resumes rather than restarts.
struct LoopState {
    /// Per peer slot, the lowest seq not yet handed to the game — the reorder
    /// cursor. This *is* the authoritative per-slot delivery high-water mark: it is
    /// the top of the contiguous run delivered to the game, and thus the "next
    /// needed" seq presented as the resume cursor on a reconnect, so the relay
    /// replays exactly the turns missed and the reorder buffer/dedup absorb any
    /// overlap the replay carries.
    next_seq: HashMap<SlotId, u64>,
    /// Per peer slot, turns that arrived ahead of `next_seq`, held until the gap
    /// below them fills. Preserved across a reconnect so turns received but not yet
    /// released aren't re-asked-for or lost.
    pending: HashMap<SlotId, BTreeMap<u64, Payload>>,
    /// The client's own outbound payload seq counter. An origin identity every hop
    /// honors, so it is monotonic across reconnects and never rewinds.
    next_outbound_seq: u64,
    /// The client's clean-departure announcer, persisted so a leave signaled before
    /// a drop is still honored after the reconnect.
    announcer: LeaveAnnouncer,
    /// Turns the game produced while the link was down, flushed in order when the
    /// next session comes up.
    outbound_buffer: VecDeque<Payload>,
    /// Whether the relay's `SessionStart` directive has passed through the driver —
    /// the game has started. Gates escalation to coordinator-mediated failover: the
    /// driver only ever re-homes an in-game session, never a still-forming lobby.
    /// Latched once and kept across reconnects.
    game_started: bool,
    /// A ring of this client's own recently-sent turns, retained for re-injection
    /// after a **re-home** so a replacement relay's empty turn ring still fans them
    /// out to peers. Bounded by [`RETENTION_TURN_CAP`] and [`RETENTION_BYTE_CAP`],
    /// drop-oldest — independent of ack retirement (a turn the old relay acked is
    /// dropped from the unacked window but stays here). Persisted across reconnects.
    retention: VecDeque<Payload>,
    /// The running encoded-byte total of [`retention`](Self::retention), so the
    /// byte cap is enforced without re-summing the ring on every push.
    retention_bytes: usize,
    /// Retained turns a **re-home** deferred to the fresh connection's reliable
    /// control stream: turns too large to ride any datagram, staged here by
    /// [`reinject_retention`] because re-injecting them into the unacked window
    /// would strand them there forever (the redundancy pass always skips a payload
    /// that can't fit a lone packet). [`session`](Driver::session) drains this onto
    /// the control stream it opens on the new connection — the same divert path an
    /// oversize turn takes when first sent. Empty on a same-relay resume (which
    /// keeps the old relay's reliable-stream state) and after each drain.
    pending_control_redivert: Vec<Payload>,
}

impl LoopState {
    fn new(result_expected: Arc<AtomicBool>) -> Self {
        Self {
            next_seq: HashMap::new(),
            pending: HashMap::new(),
            next_outbound_seq: 0,
            announcer: LeaveAnnouncer::new(result_expected),
            outbound_buffer: VecDeque::new(),
            game_started: false,
            retention: VecDeque::new(),
            retention_bytes: 0,
            pending_control_redivert: Vec::new(),
        }
    }
}

/// Records one of this client's own sent turns into the retention ring, evicting
/// the oldest turns until both the turn-count and byte caps hold. Called for every
/// turn the driver sends for its own slot (datagram or diverted), so a re-home can
/// re-inject them onto a replacement relay whose turn ring is empty.
fn retain_sent(retention: &mut VecDeque<Payload>, retention_bytes: &mut usize, payload: &Payload) {
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
fn retained_size(payload: &Payload) -> usize {
    payload.commands.len() + 32
}

/// The embedder's answer to "where should this session re-home?" — the outcome a
/// [`RehomeProvider`] returns when the driver escalates a dead home relay to
/// coordinator-mediated failover.
///
/// The embedder does the coordinator round-trip and the cert pinning; the driver
/// never touches certs. A [`NewTarget`](Self::NewTarget) hands back a fresh
/// [`ClientEndpoint`] whose trust roots pin the *new* relay's cert — the driver
/// just dials it with the same identity and resume cursors.
pub enum RehomeOutcome {
    /// Move the session to a new relay: dial `endpoint` at `relay_addr` (TLS
    /// `server_name`) with the same identity and resume cursors. The embedder built
    /// `endpoint` with the replacement relay's pinned cert.
    NewTarget {
        /// The replacement relay's id. The driver adopts this as its current relay
        /// id only on a *successful* replacement dial, so the id it next passes to
        /// [`RehomeProvider::rehome`] always names the relay the driver is actually
        /// homed on — never a relay it merely tried and failed to reach.
        relay_id: u64,
        /// The endpoint to dial the replacement relay from — its trust roots pin the
        /// new relay's cert.
        endpoint: ClientEndpoint,
        /// The replacement relay's address.
        relay_addr: SocketAddr,
        /// The replacement relay's TLS server name.
        server_name: String,
    },
    /// The coordinator says the named relay is in fact still live: keep dialing it,
    /// resuming the same-relay backoff (the escalation window resets).
    Stay,
    /// No live relay can take the session over yet (or the session is unknown to the
    /// coordinator). Keep the same-relay backoff and let the driver re-ask on the
    /// `ESCALATE_RETRY` cadence.
    Unavailable,
}

/// A boxed future a [`RehomeProvider::rehome`] returns — the manual async-trait
/// shape, so the crate needs no proc-macro dependency and the DLL implements the
/// trait with a plain `Box::pin(async move { … })`.
pub type RehomeFuture<'a> = Pin<Box<dyn Future<Output = RehomeOutcome> + Send + 'a>>;

/// An embedder-supplied hook the driver calls when its home relay looks dead and
/// reconnection should escalate to coordinator-mediated failover.
///
/// The driver calls [`rehome`](Self::rehome) only once the game has started (it
/// tracks the relay's `SessionStart` directive itself) and only after same-relay
/// re-dials have failed long enough — immediately on a cert/pin rejection (a
/// restarted relay serving a fresh cert), otherwise after `ESCALATE_AFTER`. The
/// implementation is where the embedder enforces "only once the game has started"
/// as well, does the coordinator `POST /session/rehome` round-trip, and — for a
/// [`RehomeOutcome::NewTarget`] — builds the fresh [`ClientEndpoint`] pinning the
/// replacement relay's cert. The driver never constructs certs.
pub trait RehomeProvider: Send + Sync {
    /// Resolves where the session should re-home, given the id of the relay the
    /// driver believes is dead. The **driver owns** this id — it is the relay the
    /// driver is currently homed on, seeded from [`Reconnect::relay_id`] and advanced
    /// only on a successful re-home dial — so the embedder names it to the
    /// coordinator verbatim rather than guessing its own current relay. Called at
    /// most on the escalation cadence, never on the hot path.
    fn rehome(&self, dead_relay_id: u64) -> RehomeFuture<'_>;
}

/// What a [`LinkDriver`] needs to re-dial its home relay itself, so
/// [`run_reconnecting`](LinkDriver::run_reconnecting) can resume a dropped session
/// without tearing the game seam down.
pub struct Reconnect {
    /// The endpoint to re-dial from — the one that made the initial connection, its
    /// UDP socket held open for the session's life. If it is also dialing other
    /// slots, clone the caller's via [`ClientEndpoint::from_endpoint`].
    pub endpoint: ClientEndpoint,
    /// The home relay's address.
    pub relay_addr: SocketAddr,
    /// The relay's TLS server name, checked against its certificate.
    pub server_name: String,
    /// The home relay's id — seeds the reconnect target's current relay id. The
    /// driver owns this id from here on, passing it to [`RehomeProvider::rehome`] as
    /// the dead relay and advancing it only on a successful re-home dial, so the
    /// provider never has to guess which relay the driver is homed on.
    pub relay_id: u64,
    /// The credentials to re-authorize with. Its token names this client's slot (the
    /// subject of the self-connectivity signal) and bounds how long reconnection is
    /// attempted — an expired token ends the loop.
    pub identity: Identity,
    /// The coordinator-mediated failover hook. `None` disables re-home escalation:
    /// the driver only ever retries the *same* relay (the pre-failover behavior).
    /// `Some` enables escalation to a replacement relay when the home relay stays
    /// unreachable (see [`RehomeProvider`]).
    pub rehome: Option<Arc<dyn RehomeProvider>>,
    /// How long same-relay re-dials must keep failing before the driver escalates to
    /// the re-home provider. `None` uses `ESCALATE_AFTER`; set it only to tune the
    /// escalation aggressiveness (or shorten it in a test). A cert/pin rejection
    /// escalates immediately regardless.
    pub escalate_after: Option<Duration>,
    /// How often the driver re-escalates while the provider answers `Unavailable` or
    /// a re-home dial keeps failing. `None` uses `ESCALATE_RETRY`.
    pub escalate_retry: Option<Duration>,
}

/// The current re-dial target, mutable across sessions so a successful re-home
/// updates where subsequent drops reconnect to (the old relay is dead). The
/// identity and the [`RehomeProvider`] stay fixed for the driver's life; only the
/// endpoint/address/name move.
struct ReconnectTarget {
    endpoint: ClientEndpoint,
    relay_addr: SocketAddr,
    server_name: String,
    /// The id of the relay this target dials — the driver's current relay id, passed
    /// to [`RehomeProvider::rehome`] as the dead relay. Seeded from
    /// [`Reconnect::relay_id`] and updated only on a successful re-home dial (never a
    /// failed one), so it always names the relay the driver is actually homed on.
    relay_id: u64,
}

/// The reconnect machinery [`run_reconnecting`](LinkDriver::run_reconnecting) owns
/// across a session's life: the current (mutable) re-dial target plus the fixed
/// credentials, re-home hook, and escalation timing. Bundled so `reconnect_link`
/// takes it as one argument.
struct ReconnectDriver {
    target: ReconnectTarget,
    identity: Identity,
    rehome: Option<Arc<dyn RehomeProvider>>,
    escalate_after: Duration,
    escalate_retry: Duration,
}

/// The per-slot resume cursors to present on a reconnect: for each peer slot the
/// driver has received from, the seq it next needs (`next_seq`). The relay replays
/// every recorded turn at or past the cursor and nothing below it, and the client's
/// dedup absorbs any overlap. An empty map (no peer turns yet) asks for no replay,
/// exactly like a fresh dial.
fn resume_cursors(next_seq: &HashMap<SlotId, u64>) -> Vec<(SlotId, u64)> {
    next_seq.iter().map(|(&slot, &next)| (slot, next)).collect()
}

/// Whether a session ended on a link/stream failure the reconnect loop should
/// re-dial through, as opposed to a terminal condition (a stalled game, an
/// exhausted window, a relay refusal) reconnecting cannot fix.
fn is_link_failure(error: &DriverError) -> bool {
    matches!(
        error,
        DriverError::Link(_) | DriverError::ControlStream(_) | DriverError::ControlStreamLost
    )
}

/// Whether the identity's authorization token has expired against the wall clock —
/// the relay would reject any re-dial, so reconnection stops. Matches the relay's
/// boundary: the expiry instant itself counts as expired.
fn token_expired(identity: &Identity) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    now >= identity.token().claims.expires_at.0
}

/// The outcome of the reconnect loop for one dropped link.
enum Reconnected {
    /// The relay accepted the re-dial and the link was rebound in place; the caller
    /// resumes the session over it.
    Resumed,
    /// Reconnection can't proceed (the slot departed, or the token expired); the
    /// caller ends the driver with this error.
    Terminal(DriverError),
    /// The game tore down its seam during the outage; end cleanly.
    GameGone,
}

/// Re-dials until the link is re-established, the game leaves, or a terminal
/// refusal — retrying the same relay, and escalating to coordinator-mediated
/// failover (the [`RehomeProvider`]) when it stays unreachable.
///
/// Backs off between attempts (buffering any turns the game produces meanwhile and
/// noticing a teardown), presents the resume cursors, and on success rebinds `link`
/// in place so the receive dedup and unacked window carry over. A slot-departed
/// refusal or an expired token ends it terminally; every other dial failure is
/// retried under a growing backoff.
///
/// **Escalation.** Once the game has started (`state.game_started`) and a
/// [`RehomeProvider`] is configured, a run of failed same-relay dials escalates to
/// the provider — immediately on a cert/pin rejection (a restarted relay serving a
/// fresh cert, which no same-relay retry can pass), otherwise after
/// [`ESCALATE_AFTER`]. [`RehomeOutcome::Stay`] resumes the same-relay backoff and
/// resets the window; [`RehomeOutcome::Unavailable`] keeps it and re-escalates on
/// the [`ESCALATE_RETRY`] cadence; [`RehomeOutcome::NewTarget`] dials the
/// replacement relay with the same identity and cursors, and on success rebinds,
/// re-injects the retained turns, and updates `target` so subsequent drops
/// reconnect there.
async fn reconnect_link(
    rc: &mut ReconnectDriver,
    link: &mut Link,
    seam: &mut GameSeam,
    state: &mut LoopState,
    backoff: &mut Backoff,
) -> Reconnected {
    // This client's own slot, from its token — the slot whose receive window every
    // re-dial anchors on the (always fresh) relay-side link: the same-relay dial
    // below anchors from the oldest-unacked seq, the re-home dial from the retention
    // ring's front (see the NewTarget branch).
    let own_slot = rc.identity.token().claims.slot;
    // When escalation to the re-home provider is next due. It starts one window out
    // and is pulled to now on the first cert/pin rejection; each escalation advances
    // it, so continuous failures escalate on a bounded cadence, not every attempt.
    let mut next_escalate_at = Instant::now() + rc.escalate_after;
    let mut escalated_once = false;

    loop {
        // An expired token can never re-authorize: stop before wasting a dial.
        if token_expired(&rc.identity) {
            return Reconnected::Terminal(DriverError::TokenExpired);
        }
        match wait_backoff(backoff, seam, state).await {
            WaitOutcome::Elapsed => {}
            WaitOutcome::GameGone => return Reconnected::GameGone,
            WaitOutcome::BufferExhausted => {
                return Reconnected::Terminal(DriverError::OutageBufferExhausted {
                    buffered: state.outbound_buffer.len(),
                    cap: OUTAGE_OUTBOUND_BUFFER_CAP,
                });
            }
        }
        let cursors = resume_cursors(&state.next_seq);
        // The relay builds a brand-new receive dedup on *every* re-dial (a fresh
        // `Link` per connection), so a same-relay resume must anchor our own slot's
        // window too — otherwise a game past ~4096 turns re-dials into an
        // out-of-window rejection that closes the link. The anchor is the oldest seq
        // we will actually re-send: the AckManager's oldest still-unacked seq, which
        // the redundancy pass re-carries oldest-first over the rebound connection.
        // With nothing unacked, it is the next seq we will produce (the buffered/live
        // turns that flush on resume). NOT the retention ring's front — a same-relay
        // resume does not re-inject that ring, so a lower anchor would strand a
        // permanent prefix gap. (`cursors` stays peer-only; the re-home dial builds
        // its own set below with the retention-front anchor, which it *does* re-inject.)
        let same_relay_anchor = link
            .oldest_unacked_seq(own_slot)
            .unwrap_or(state.next_outbound_seq);
        let mut same_relay_cursors = cursors.clone();
        if same_relay_anchor > 0 {
            same_relay_cursors.push((own_slot, same_relay_anchor));
        }
        match rc
            .target
            .endpoint
            .reconnect_with_timeout(
                rc.target.relay_addr,
                &rc.target.server_name,
                &rc.identity,
                &same_relay_cursors,
                RECONNECT_DIAL_TIMEOUT,
            )
            .await
        {
            Ok(fresh) => {
                // A same-relay resume: the old link's receive dedup and unacked
                // window carry over, and the datagram/ack path needs no
                // retention re-injection — the same relay still holds this
                // session's turn ring, and `same_relay_anchor` above already
                // covers the unacked tail. An OVERSIZE turn is different: it
                // never rode the datagram/ack path at all (there is no
                // per-turn acknowledgment for a control-stream write), so a
                // drop between the local `write_all` succeeding and the relay
                // actually processing it is invisible to everything else here
                // — re-divert every still-retained oversize turn onto the
                // fresh connection's control stream, exactly as a re-home
                // does. See `redivert_oversize_retention_on_same_relay_resume`
                // for why this is safe to run unconditionally. Checked after
                // rebind, against the fresh connection's own datagram budget
                // — mirroring the re-home path's own rebind-then-reinject
                // order — though an oversize turn is definitionally oversize
                // on any realistic path.
                link.rebind(fresh.connection().clone());
                redivert_oversize_retention_on_same_relay_resume(link, state);
                backoff.reset();
                return Reconnected::Resumed;
            }
            // The game moved on without us: no dial can bring the slot back.
            Err(DialError::SlotDeparted) => {
                return Reconnected::Terminal(DriverError::SlotDeparted);
            }
            // A transient same-relay failure. Retry, and — for an in-game session
            // with a provider — escalate to coordinator-mediated failover when the
            // relay stays unreachable.
            Err(error) => {
                // Clone the provider handle out so the escalation block can mutate
                // `rc.target` without holding a borrow of `rc.rehome` across it.
                let provider = rc.rehome.clone();
                if let Some(provider) = provider
                    && state.game_started
                {
                    // A cert/pin rejection can never be cured by a same-relay retry,
                    // so escalate at once rather than waiting out the timed window.
                    if !escalated_once && is_cert_rejection(&error) {
                        next_escalate_at = Instant::now();
                    }
                    if Instant::now() >= next_escalate_at {
                        escalated_once = true;
                        // The driver owns the current relay id: name the relay it is
                        // actually homed on as the dead one, never a guess. The ask
                        // runs under the driver's own deadline with the seam still
                        // serviced (see `await_rehome`), so a hung provider cannot
                        // freeze reconnection with it.
                        let answer = await_rehome(
                            &provider,
                            rc.target.relay_id,
                            REHOME_PROVIDER_DEADLINE,
                            seam,
                            state,
                        )
                        .await;
                        match answer {
                            EscalationWait::GameGone => return Reconnected::GameGone,
                            EscalationWait::BufferExhausted => {
                                return Reconnected::Terminal(DriverError::OutageBufferExhausted {
                                    buffered: state.outbound_buffer.len(),
                                    cap: OUTAGE_OUTBOUND_BUFFER_CAP,
                                });
                            }
                            EscalationWait::TimedOut => {
                                next_escalate_at = Instant::now() + rc.escalate_retry;
                                tracing::info!(
                                    "re-home escalation: provider deadline elapsed; re-asking later",
                                );
                            }
                            EscalationWait::Answered(outcome) => match outcome {
                                RehomeOutcome::Stay => {
                                    // The relay is live after all: resume same-relay
                                    // backoff, resetting the escalation window.
                                    next_escalate_at = Instant::now() + rc.escalate_after;
                                    tracing::info!("re-home escalation: coordinator says stay");
                                }
                                RehomeOutcome::Unavailable => {
                                    next_escalate_at = Instant::now() + rc.escalate_retry;
                                    tracing::info!(
                                        "re-home escalation: no relay available yet; re-asking later",
                                    );
                                }
                                RehomeOutcome::NewTarget {
                                    relay_id,
                                    endpoint,
                                    relay_addr,
                                    server_name,
                                } => {
                                    // The replacement relay has never seen this client, so
                                    // its receive-side dedup for our own slot would base at
                                    // seq 0 and reject our resumed (already high) seq stream
                                    // once it passed the window — dropping the link, and with
                                    // every re-homed slot crossing the window together, the
                                    // whole group. Declare our own-slot resume anchor at the
                                    // oldest seq we will actually re-send, so the relay bases
                                    // the window there and the resumed stream is accepted. Two
                                    // sources feed that re-send: the rebound link keeps its
                                    // unacked window (the redundancy pass re-carries it) and
                                    // `reinject_retention` re-adds the retained ring, so the
                                    // anchor is the lower of the oldest-unacked seq and the
                                    // retention front (see `rehome_own_slot_anchor`). No source
                                    // means nothing to re-send, so no anchor is needed (the
                                    // window bases at 0, correct for a slot that never sent).
                                    let mut rehome_cursors = cursors.clone();
                                    if let Some(anchor) = rehome_own_slot_anchor(
                                        link.oldest_unacked_seq(own_slot),
                                        state.retention.front().map(|turn| turn.seq),
                                    ) {
                                        rehome_cursors.push((own_slot, anchor));
                                    }
                                    match endpoint
                                        .reconnect_with_timeout(
                                            relay_addr,
                                            &server_name,
                                            &rc.identity,
                                            &rehome_cursors,
                                            RECONNECT_DIAL_TIMEOUT,
                                        )
                                        .await
                                    {
                                        Ok(fresh) => {
                                            // A re-home resume onto a fresh relay: rebind, then
                                            // re-inject the retained turns so the new relay's
                                            // empty ring re-carries them to peers. Only now —
                                            // on a *successful* dial — does the driver adopt
                                            // the new relay id, so a failed dial never leaves
                                            // it naming a relay it isn't homed on.
                                            link.rebind(fresh.connection().clone());
                                            reinject_retention(link, state);
                                            rc.target = ReconnectTarget {
                                                endpoint,
                                                relay_addr,
                                                server_name,
                                                relay_id,
                                            };
                                            backoff.reset();
                                            tracing::info!(
                                                relay = %relay_addr,
                                                "re-homed onto a replacement relay",
                                            );
                                            return Reconnected::Resumed;
                                        }
                                        Err(DialError::SlotDeparted) => {
                                            return Reconnected::Terminal(
                                                DriverError::SlotDeparted,
                                            );
                                        }
                                        Err(new_error) => {
                                            next_escalate_at = Instant::now() + rc.escalate_retry;
                                            tracing::info!(
                                                %new_error,
                                                "re-home dial failed; retrying the old relay meanwhile",
                                            );
                                        }
                                    }
                                }
                            },
                        }
                    }
                }
                tracing::info!(%error, "re-dial attempt failed; backing off");
            }
        }
    }
}

/// Re-carries the retained turns onto a freshly re-homed link so the replacement
/// relay's empty turn ring re-delivers them to peers (each deduping by origin
/// `(slot, seq)`). Only ever called on a re-home — a same-relay resume keeps the
/// old relay's ring, so there is nothing to re-carry.
///
/// A turn that still fits a datagram goes back into the unacked window, where the
/// next packet's redundancy pass re-carries it. A turn too large for any datagram
/// cannot go there: [`AckManager::build_outgoing`] skips a payload that can't fit a
/// lone packet on every pass, so a re-injected oversize turn would sit in the
/// window forever — never re-delivered (inflating `payloads_in_flight`) and, worse,
/// leaving a peer that never received it from the dead relay stalled on its seq.
/// Those are staged in [`LoopState::pending_control_redivert`] instead, which
/// [`session`](Driver::session) drains onto the new connection's reliable control
/// stream — the same divert path an oversize turn takes when first sent. A path
/// that can't currently size a datagram is treated as oversize, so the turn is
/// re-carried reliably rather than risk being lost.
/// Drains the retained oversize turns a re-home staged for the fresh connection's
/// control stream onto `control_send`, oldest-first — the same divert path an
/// oversize turn takes when first sent.
///
/// Each turn is removed from `pending` only *after* its send succeeds, so if the
/// stream fails partway (the fresh connection dropped again) the unsent remainder
/// stays staged and the next session over the re-dialed link retries it. Draining
/// with a `mem::take` up front would instead move the whole batch out and drop the
/// unsent tail on a mid-batch failure — and a later same-relay resume does not
/// re-run [`reinject_retention`], so those oversize turns would be lost for good,
/// permanently stalling a peer that never received them from the dead relay on that
/// seq. The clone is cheap next to that risk (these turns are rare and the batch
/// tiny), and paid only while turns remain to send.
async fn redivert_pending_control(
    control_send: &mut quinn::SendStream,
    pending: &mut Vec<Payload>,
) -> Result<(), ControlSendError> {
    while let Some(turn) = pending.first().cloned() {
        send_control_turn(control_send, turn).await?;
        pending.remove(0);
    }
    Ok(())
}

/// The own-slot receive-window anchor a re-home dial presents to the fresh relay:
/// the oldest seq the client will actually re-send once it resumes there. Two
/// sources feed that re-send and the anchor must cover the lower of them —
///
/// - the rebound link keeps its unacked window (`reset_connection` preserves it and
///   the redundancy pass re-carries it oldest-first), whose oldest seq is
///   `oldest_unacked`; and
/// - [`reinject_retention`] re-adds the retained ring, whose oldest seq is
///   `retention_front` (this can sit *below* `oldest_unacked` when the oldest turns
///   were already acked — retention keeps them, the unacked window does not).
///
/// Anchoring at only the retention front (as this once did) strands the unacked tail
/// below it whenever own-slot in-flight has outgrown the retention cap —
/// [`UNACKED_WINDOW_CAP`] is twice [`RETENTION_TURN_CAP`], so 513..=1024 turns in
/// flight is reachable under sustained forward-path loss (a relay degrading, then
/// dying). Those turns are re-carried but the relay buries them below the window and
/// never fans them to peers, permanently gapping the game — a comparator-visible
/// desync at turn 1. `None` means neither source will re-send anything (a slot that
/// never sent a turn), so the window correctly bases at 0 and no anchor is declared.
fn rehome_own_slot_anchor(
    oldest_unacked: Option<u64>,
    retention_front: Option<u64>,
) -> Option<u64> {
    match (oldest_unacked, retention_front) {
        (Some(unacked), Some(front)) => Some(unacked.min(front)),
        (Some(unacked), None) => Some(unacked),
        (None, front) => front,
    }
}

fn reinject_retention(link: &mut Link, state: &mut LoopState) {
    let LoopState {
        retention,
        pending_control_redivert,
        ..
    } = state;
    for turn in retention.iter() {
        if matches!(link.payload_fits(turn), Ok(true)) {
            link.reinject_unacked(turn.clone());
        } else {
            pending_control_redivert.push(turn.clone());
        }
    }
}

/// Re-divert this session's still-retained OVERSIZE turns onto a same-relay
/// resume's control stream — the same-connection counterpart of
/// [`reinject_retention`]'s oversize half.
///
/// A same-relay resume deliberately does NOT touch the datagram/unacked
/// window at all: the old relay's own turn ring is still intact for
/// ordinary-sized turns, and `reconnect_link`'s `same_relay_anchor` already
/// covers the unacked tail via the rebound link's own redundancy. Re-injecting
/// the retention ring's ordinary-sized turns on top of that — as a re-home
/// does — would risk a permanent prefix gap (see the `same_relay_anchor`
/// comment in `reconnect_link`); that risk is real and this function does not
/// touch it.
///
/// An oversize turn is different in kind, not just size: it never rode the
/// datagram/ack path in the first place (there is no acknowledgment for a
/// control-stream write to check against), so there is no equivalent gap risk
/// here — a turn the relay already fanned out is simply deduped again on
/// arrival (the relay's ingress dedup keys on origin `(slot, seq)` regardless
/// of which path delivered it, exactly as a datagram-delivered turn would
/// be), and one the relay never received before the drop is finally
/// delivered. Safe and cheap to run unconditionally on every same-relay
/// resume, not gated on anything provably missing — there is no
/// acknowledgment to check in the first place. A turn already staged (from a
/// prior resume whose own redivert only partially drained before failing
/// again) is not re-staged, so a run of same-relay failures doesn't grow the
/// pending list without bound.
fn redivert_oversize_retention_on_same_relay_resume(link: &Link, state: &mut LoopState) {
    let LoopState {
        retention,
        pending_control_redivert,
        ..
    } = state;
    for turn in retention.iter() {
        if matches!(link.payload_fits(turn), Ok(false))
            && !pending_control_redivert
                .iter()
                .any(|staged| staged.slot == turn.slot && staged.seq == turn.seq)
        {
            pending_control_redivert.push(turn.clone());
        }
    }
}

/// Best-effort classification of a dial failure as a TLS certificate / pin
/// rejection — a relay that restarted with a fresh keypair, which no same-relay
/// retry can ever get past, so escalation need not wait out the timed window. It
/// inspects the crypto-handshake markers quinn/rustls surface; a miss only defers
/// escalation to the [`ESCALATE_AFTER`] fallback rather than breaking it, so the
/// classifier is deliberately conservative.
fn is_cert_rejection(error: &DialError) -> bool {
    if !matches!(error, DialError::Connection(_)) {
        return false;
    }
    let text = error.to_string().to_lowercase();
    text.contains("certificate")
        || text.contains("crypto")
        || text.contains("tls")
        || text.contains("handshake")
        || text.contains("unknownissuer")
        || text.contains("bad_certificate")
}

/// How a non-blocking driver → game push resolved. Every driver → game delivery
/// besides the ordered turn stream goes through [`push_to_game`]: the driver's
/// one loop also carries turns and acks, so it must never park on an embedder
/// channel — a retained-but-undrained receiver would stall the whole session
/// with it. What a `Full` buffer means is the caller's policy: a
/// correctness-critical delivery (a synced leave, a lobby command, the
/// session-start directive) surfaces [`DriverError::GameStalled`], exactly as
/// the turn path does, while a best-effort one (chat, a connectivity display
/// change) is simply dropped.
enum GamePush {
    /// The value is in the channel's buffer.
    Sent,
    /// The channel's buffer is full — the game has stopped draining it (the
    /// depths are sized generously past each channel's real traffic).
    Full,
    /// The game dropped its receiver: a clean stop.
    Closed,
}

/// Offers `value` to a driver → game channel without ever awaiting.
fn push_to_game<T>(tx: &mpsc::Sender<T>, value: T) -> GamePush {
    match tx.try_send(value) {
        Ok(()) => GamePush::Sent,
        Err(mpsc::error::TrySendError::Full(_)) => GamePush::Full,
        Err(mpsc::error::TrySendError::Closed(_)) => GamePush::Closed,
    }
}

/// The outcome of a backoff wait between reconnect attempts.
enum WaitOutcome {
    /// The backoff delay elapsed; time to (re)dial.
    Elapsed,
    /// The game tore down its seam; abandon reconnection.
    GameGone,
    /// The outage buffer crossed [`OUTAGE_OUTBOUND_BUFFER_CAP`]; the driver
    /// stops rather than silently drop a game-produced turn.
    BufferExhausted,
}

/// Waits the next backoff delay before a reconnect attempt, while still servicing
/// the game's outbound turns — buffering them (bounded) so a resumed session can
/// flush them — and watching for the game tearing down (its outbound sender or
/// inbound receiver dropped). Other game→driver channels park in their own buffers
/// during the brief outage and are drained when the session resumes.
///
/// A turn produced past [`OUTAGE_OUTBOUND_BUFFER_CAP`] is not dropped: dropping it
/// here would be silent (the resumed session assigns the survivors gapless origin
/// seqs, so no peer could ever detect the loss), so the caller ends the driver
/// instead — see [`DriverError::OutageBufferExhausted`].
async fn wait_backoff(
    backoff: &mut Backoff,
    seam: &mut GameSeam,
    state: &mut LoopState,
) -> WaitOutcome {
    let deadline = Instant::now() + backoff.next_delay();
    loop {
        tokio::select! {
            _ = sleep_until(deadline) => return WaitOutcome::Elapsed,
            // The game dropped its inbound receiver: a teardown.
            _ = seam.inbound.closed() => return WaitOutcome::GameGone,
            produced = seam.outbound.recv() => match produced {
                Some(turn) => {
                    state.outbound_buffer.push_back(turn);
                    if state.outbound_buffer.len() > OUTAGE_OUTBOUND_BUFFER_CAP {
                        return WaitOutcome::BufferExhausted;
                    }
                }
                // The game dropped its outbound sender: a teardown.
                None => return WaitOutcome::GameGone,
            },
        }
    }
}

/// The outcome of awaiting the re-home provider while the seam stays serviced.
enum EscalationWait {
    /// The provider answered.
    Answered(RehomeOutcome),
    /// The provider did not answer within the deadline; the caller treats this
    /// exactly as [`RehomeOutcome::Unavailable`] (the pending ask is dropped —
    /// the next escalation asks afresh).
    TimedOut,
    /// The game tore down its seam; abandon reconnection.
    GameGone,
    /// The outage buffer crossed [`OUTAGE_OUTBOUND_BUFFER_CAP`]; the driver
    /// stops rather than silently drop a game-produced turn.
    BufferExhausted,
}

/// Awaits one [`RehomeProvider::rehome`] ask under `deadline`, servicing the
/// game seam exactly as [`wait_backoff`] does — buffering outbound turns
/// (bounded) and watching for the game tearing down. The provider is embedder
/// code awaiting an app-server round-trip; without this the whole reconnect
/// loop would be parked on that future, blind to game teardown and to the
/// outage-buffer cap for as long as it takes — forever, if it hangs.
async fn await_rehome(
    provider: &Arc<dyn RehomeProvider>,
    dead_relay_id: u64,
    deadline: Duration,
    seam: &mut GameSeam,
    state: &mut LoopState,
) -> EscalationWait {
    let deadline = Instant::now() + deadline;
    let mut ask = provider.rehome(dead_relay_id);
    loop {
        tokio::select! {
            outcome = &mut ask => return EscalationWait::Answered(outcome),
            _ = sleep_until(deadline) => return EscalationWait::TimedOut,
            // The game dropped its inbound receiver: a teardown.
            _ = seam.inbound.closed() => return EscalationWait::GameGone,
            produced = seam.outbound.recv() => match produced {
                Some(turn) => {
                    state.outbound_buffer.push_back(turn);
                    if state.outbound_buffer.len() > OUTAGE_OUTBOUND_BUFFER_CAP {
                        return EscalationWait::BufferExhausted;
                    }
                }
                // The game dropped its outbound sender: a teardown.
                None => return EscalationWait::GameGone,
            },
        }
    }
}

/// Capped exponential backoff with jitter for the reconnect dial.
///
/// The base schedule doubles from [`RECONNECT_BACKOFF_INITIAL`] to
/// [`RECONNECT_BACKOFF_CAP`]; each delay is then jittered down into `[base/2, base]`
/// so many clients that dropped together don't re-dial in lockstep. The base
/// schedule is a pure function of the attempt count, so its shape is unit-testable
/// independently of the jitter.
struct Backoff {
    attempt: u32,
    rng: u64,
}

impl Backoff {
    fn new() -> Self {
        // Seed the jitter PRNG from the clock; only that separate clients diverge
        // matters, not the exact value. Force non-zero for the xorshift.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            | 1;
        Self {
            attempt: 0,
            rng: seed,
        }
    }

    /// Resets to the initial delay after a successful reconnect.
    fn reset(&mut self) {
        self.attempt = 0;
    }

    /// The base (un-jittered) delay for `attempt`: the initial delay doubled
    /// `attempt` times, capped. Pure, so the schedule shape is unit-testable.
    fn base_delay(attempt: u32) -> Duration {
        let factor = 1u32.checked_shl(attempt).unwrap_or(u32::MAX);
        RECONNECT_BACKOFF_INITIAL
            .saturating_mul(factor)
            .min(RECONNECT_BACKOFF_CAP)
    }

    /// The next delay: the current attempt's base jittered into `[base/2, base]`,
    /// advancing the attempt counter (saturating, so it stays at the cap).
    fn next_delay(&mut self) -> Duration {
        let base = Self::base_delay(self.attempt).as_millis() as u64;
        self.attempt = self.attempt.saturating_add(1);
        let half = base / 2;
        let jitter = if half == 0 {
            0
        } else {
            self.next_rand() % (half + 1)
        };
        Duration::from_millis(base - jitter)
    }

    /// One xorshift64 step — a tiny PRNG for jitter, with no external dependency.
    fn next_rand(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::Ordering;

    use rally_point_proto::beacon;
    use rally_point_transport::quic::{client_config, server_config};
    use rally_point_transport::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rally_point_transport::{quinn, rustls};

    use super::*;

    fn self_signed() -> (
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        CertificateDer<'static>,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
        (vec![cert_der.clone()], key, cert_der)
    }

    /// Brings up a loopback QUIC connection and wraps each end in a [`Link`]. The
    /// endpoints are returned so the caller keeps them alive for the test.
    async fn connected_links() -> (Link, Link, quinn::Endpoint, quinn::Endpoint) {
        let (chain, key, ca) = self_signed();
        let server_cfg = server_config(chain, key).unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let client_cfg = client_config(roots).unwrap();

        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let server = quinn::Endpoint::server(server_cfg, bind).unwrap();
        let server_addr = server.local_addr().unwrap();
        let mut client = quinn::Endpoint::client(bind).unwrap();
        client.set_default_client_config(client_cfg);

        let accept = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() })
        };
        let client_conn = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let server_conn = accept.await.unwrap();

        (
            Link::new(client_conn),
            Link::new(server_conn),
            client,
            server,
        )
    }

    fn turn(seq: u64, bytes: &[u8]) -> Payload {
        Payload {
            // The sending client assigns the origin seq; a raw link send honors
            // it verbatim, while the driver stamps its own counter (so the value
            // here is ignored on the driver-send path).
            seq,
            slot: 0,
            commands: bytes.to_vec().into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn carries_turns_from_one_driver_to_the_other() {
        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let (driver_b, chan_b) = LinkDriver::new(link_b);
        let task_a = tokio::spawn(driver_a.run());
        let task_b = tokio::spawn(driver_b.run());

        // Three turns pushed into A's seam arrive in order, bytes intact, on B's.
        for i in 0..3u8 {
            chan_a.outbound.send(turn(0, &[i])).await.unwrap();
        }
        let mut inbound_b = chan_b.inbound;
        let mut got = Vec::new();
        while got.len() < 3 {
            got.push(inbound_b.recv().await.unwrap());
        }
        let bytes: Vec<u8> = got.iter().map(|p| p.commands[0]).collect();
        assert_eq!(bytes, vec![0, 1, 2]);

        // Dropping both senders stops both drivers cleanly.
        drop(chan_a.outbound);
        drop(chan_b.outbound);
        assert!(task_a.await.unwrap().is_ok());
        assert!(task_b.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn an_over_mtu_turn_is_delivered_via_the_control_stream() {
        // A turn far larger than any datagram can never ride the datagram path
        // — no bundle could carry it, and no redundancy could recover it. The
        // driver must divert it to the reliable control stream, and the peer's
        // driver must fold it back into the ordered turn stream, interleaved
        // correctly with ordinary datagram turns around it.
        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let (driver_b, chan_b) = LinkDriver::new(link_b);
        let task_a = tokio::spawn(driver_a.run());
        let task_b = tokio::spawn(driver_b.run());

        // An ordinary turn, then the oversize one, then another ordinary one:
        // the oversize turn takes a different path but must arrive in seq
        // order between its neighbors.
        chan_a.outbound.send(turn(0, &[0x01])).await.unwrap();
        chan_a
            .outbound
            .send(turn(0, &vec![0x42; 4096]))
            .await
            .unwrap();
        chan_a.outbound.send(turn(0, &[0x03])).await.unwrap();

        let mut inbound_b = chan_b.inbound;
        let mut got = Vec::new();
        while got.len() < 3 {
            let payload = tokio::time::timeout(Duration::from_secs(5), inbound_b.recv())
                .await
                .expect("the oversize turn never arrived")
                .expect("driver b closed early");
            got.push(payload);
        }
        assert_eq!(got[0].commands[0], 0x01);
        assert_eq!(
            got[1].commands.len(),
            4096,
            "the oversize turn arrives whole"
        );
        assert_eq!(got[1].commands[0], 0x42);
        assert_eq!(got[2].commands[0], 0x03);
        assert_eq!(
            got.iter().map(|p| p.seq).collect::<Vec<_>>(),
            vec![0, 1, 2],
            "one ordered stream regardless of delivery path",
        );

        drop(chan_a.outbound);
        drop(chan_b.outbound);
        let _ = task_a.await;
        let _ = task_b.await;
    }

    #[tokio::test]
    async fn a_dead_control_stream_reader_surfaces_as_a_link_failure_while_the_connection_stays_up()
    {
        // The bug this guards: the control stream is the only channel a synced
        // `LeaveDirective`, `SessionStart`, and `SlotConnectivity` ever arrive on.
        // If its reader task ends while the connection is otherwise healthy (a
        // one-sided reset, an over-cap frame, a decode failure, or here a clean
        // EOF), the old code just disarmed the branch and limped on with
        // datagrams alone -- silently losing all three for the rest of the
        // session. The fix treats it as a link failure the same way
        // `link.recv()`'s own error arm does.
        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let (mut link, mut seam, mut state) = into_session_parts(driver_a);

        // The peer opens its outbound control stream -- mirroring the relay's own
        // `open_bi()` in `routing::run_slot_link` -- then immediately finishes it:
        // a clean EOF with the connection itself left fully alive, exactly the
        // "control stream dead, link fine" split this bug is about.
        let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();
        let _ = peer_control_send.finish();

        let result = LinkDriver::session(&mut link, &mut seam, &mut state, SlotId(0)).await;
        assert!(
            matches!(result, Err(DriverError::ControlStreamLost)),
            "expected ControlStreamLost, got {result:?}",
        );
        assert!(
            is_link_failure(result.as_ref().unwrap_err()),
            "a dead control stream must be reconnect-eligible, like a broken link",
        );

        // The connection itself was never closed by `session` -- proof this is
        // a control-stream-only death, not a whole-link failure in disguise.
        // The close is the caller's job, after classification:
        // `run_reconnecting` closes it before re-dialing (see the test below),
        // and closing it in here instead would destroy the very distinction
        // this asserts.
        assert!(
            link.connection().close_reason().is_none(),
            "the underlying connection must stay alive; only the control stream died",
        );

        // Held for the whole test so the game-facing channel halves stay open
        // throughout `session()` -- nothing here exercises them, but a premature
        // drop would close `seam`'s peers and risk a different, unrelated exit.
        drop(chan_a);
    }

    /// A token-shaped identity for driving `run_reconnecting` against fakes: the
    /// signature is never presented to a verifier here, so a zeroed one is fine —
    /// the driver itself only reads the claims (its own slot, the expiry).
    fn fake_identity(slot: SlotId) -> crate::identity::Identity {
        use rally_point_proto::control::TenantId;
        use rally_point_proto::ids::SessionId;
        use rally_point_proto::token::{
            ClientPublicKey, ExpiresAt, KeyId, Signature, SignedToken, TokenClaims,
        };

        let pkcs8 =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap();
        let claims = TokenClaims::new(
            TenantId("test".to_owned()),
            SessionId(1),
            slot,
            ExpiresAt(u64::MAX),
            ClientPublicKey([0; 32]),
        );
        let token = SignedToken {
            kid: KeyId::new("test-key".to_owned()).unwrap(),
            claims,
            signature: Signature([0; 64]),
        };
        crate::identity::Identity::from_pkcs8(token, pkcs8.as_ref()).unwrap()
    }

    #[tokio::test]
    async fn a_classified_link_failure_closes_the_old_connection_before_the_re_dial() {
        // The relay's slot-liveness signal is the connection, not the client's
        // local stream state: after a control-stream-only death the old
        // connection is still fully alive relay-side, holding the roster seat.
        // Unless the reconnect loop closes it once the failure is classified,
        // the immediate re-dial bounces off SLOT_TAKEN until the relay's QUIC
        // idle timeout finally notices. The peer here stands in for the relay:
        // it must observe a deliberate application close, promptly.
        let (link_a, link_b, ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);

        // The re-dial target is unreachable on purpose: this test is about the
        // OLD connection's fate at classification time, not the re-dial (whose
        // own success paths the resume/re-home tests cover).
        let reconnect = Reconnect {
            endpoint: crate::dial::ClientEndpoint::from_endpoint(ea.clone()),
            relay_addr: (Ipv4Addr::LOCALHOST, 1).into(),
            server_name: "localhost".to_owned(),
            relay_id: 7,
            identity: fake_identity(SlotId(0)),
            rehome: None,
            escalate_after: None,
            escalate_retry: None,
        };
        let task = tokio::spawn(driver_a.run_reconnecting(reconnect));

        // The peer opens its control stream (as the relay does) and finishes it
        // at once: control stream dead, connection alive — the split that
        // classifies as a reconnect-eligible link failure.
        let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();
        let _ = peer_control_send.finish();

        let closed = tokio::time::timeout(Duration::from_secs(5), link_b.connection().closed())
            .await
            .expect("the old connection was never closed after classification");
        assert!(
            matches!(closed, quinn::ConnectionError::ApplicationClosed(_)),
            "closed deliberately by the reconnect loop, not lost: {closed:?}",
        );

        // The driver is now parked re-dialing the unreachable target; the
        // re-dial paths themselves are covered elsewhere.
        task.abort();
        drop(chan_a);
    }

    /// A provider whose ask never resolves — the embedder's app-server call
    /// hanging — with a signal for when the driver actually asked.
    struct HangingProvider {
        asked: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    }

    impl HangingProvider {
        fn new() -> (Arc<Self>, tokio::sync::oneshot::Receiver<()>) {
            let (tx, rx) = tokio::sync::oneshot::channel();
            (
                Arc::new(Self {
                    asked: std::sync::Mutex::new(Some(tx)),
                }),
                rx,
            )
        }
    }

    impl RehomeProvider for HangingProvider {
        fn rehome(&self, _dead_relay_id: u64) -> RehomeFuture<'_> {
            if let Some(tx) = self.asked.lock().unwrap().take() {
                let _ = tx.send(());
            }
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn a_hung_provider_ask_times_out_and_is_treated_as_unavailable() {
        let (link_a, _link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let (_link, mut seam, mut state) = into_session_parts(driver_a);
        let (provider, _asked) = HangingProvider::new();
        let provider: Arc<dyn RehomeProvider> = provider;

        let waited = tokio::time::timeout(
            Duration::from_secs(5),
            await_rehome(
                &provider,
                7,
                Duration::from_millis(50),
                &mut seam,
                &mut state,
            ),
        )
        .await
        .expect("the ask must be bounded by the driver's own deadline");
        assert!(
            matches!(waited, EscalationWait::TimedOut),
            "a hung ask times out rather than parking the loop",
        );
        drop(chan_a);
    }

    #[tokio::test]
    async fn game_teardown_is_observed_while_a_provider_ask_is_pending() {
        let (link_a, _link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let (_link, mut seam, mut state) = into_session_parts(driver_a);
        let (provider, _asked) = HangingProvider::new();
        let provider: Arc<dyn RehomeProvider> = provider;

        // The game tears down mid-ask: drop its half of the seam shortly after
        // the await starts.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(chan_a);
        });
        let waited = tokio::time::timeout(
            Duration::from_secs(5),
            await_rehome(&provider, 7, Duration::from_secs(60), &mut seam, &mut state),
        )
        .await
        .expect("teardown must be observable while the ask is pending");
        assert!(
            matches!(waited, EscalationWait::GameGone),
            "the seam stays serviced during the ask",
        );
    }

    #[tokio::test]
    async fn a_hung_rehome_provider_does_not_freeze_the_reconnect_loop() {
        // End to end through `run_reconnecting`: the home relay dies mid-game,
        // escalation asks a provider that never answers, and the game then
        // tears down. The driver must end cleanly — observing the teardown
        // through the pending ask — instead of parking on the embedder's
        // future forever.
        use rally_point_transport::control::send_control_session_start;

        let (link_a, link_b, ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let (provider, asked) = HangingProvider::new();

        let reconnect = Reconnect {
            endpoint: crate::dial::ClientEndpoint::from_endpoint(ea.clone()),
            // Unreachable: every same-relay re-dial fails, so escalation is
            // reached on the first attempt (the zero window below).
            relay_addr: (Ipv4Addr::LOCALHOST, 1).into(),
            server_name: "localhost".to_owned(),
            relay_id: 7,
            identity: fake_identity(SlotId(0)),
            rehome: Some(provider),
            escalate_after: Some(Duration::ZERO),
            escalate_retry: Some(Duration::from_millis(100)),
        };
        let task = tokio::spawn(driver_a.run_reconnecting(reconnect));

        // The peer plays the relay far enough to start the game (escalation is
        // gated on `SessionStart`), then its connection dies — a link failure.
        let (mut peer_control_send, _peer_recv) = link_b.connection().open_bi().await.unwrap();
        send_control_session_start(&mut peer_control_send)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        link_b.connection().close(0u32.into(), b"relay died");

        // Wait until the driver is actually parked on the provider, then tear
        // the game down. Without the seam staying serviced through the ask,
        // the teardown would never be observed and the driver would hang.
        tokio::time::timeout(Duration::from_secs(15), asked)
            .await
            .expect("escalation never asked the provider")
            .unwrap();
        drop(chan_a);

        let joined = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("the driver stayed frozen on the hung provider")
            .unwrap();
        assert!(
            joined.is_ok(),
            "a game teardown during the ask ends the driver cleanly: {joined:?}",
        );
    }

    #[tokio::test]
    async fn an_undrained_leave_channel_surfaces_a_stall_instead_of_parking() {
        // The driver's one loop carries turns and acks; a send into a
        // correctness-critical game channel whose receiver is retained but
        // never drained must surface as a stall, not park the loop (and the
        // whole session with it) on the wedged consumer.
        use rally_point_transport::control::send_control_leave;

        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        // Push more synced leaves than the channel holds, with the receiver
        // (inside `chan_a`) alive but never drained.
        let (mut ctrl_send, _our_recv) = link_b.connection().open_bi().await.unwrap();
        for i in 0..(LEAVE_CHANNEL_CAPACITY as u32 + 4) {
            send_control_leave(
                &mut ctrl_send,
                LeaveDirective {
                    slot: i,
                    reason: 0,
                    apply_at_frame: 0,
                    leave_seq: i + 1,
                },
            )
            .await
            .unwrap();
        }

        let joined = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the driver parked on the wedged leave consumer")
            .unwrap();
        assert!(
            matches!(joined, Err(DriverError::GameStalled)),
            "a wedged correctness-critical consumer is a stall: {joined:?}",
        );
        drop(chan_a);
    }

    #[tokio::test]
    async fn undrained_best_effort_channels_drop_instead_of_stalling_turns() {
        // Chat and connectivity are best-effort: a receiver that is retained
        // but never drained costs only the overflowing messages — the turn
        // stream (and the driver's acks with it) must keep flowing.
        use rally_point_proto::messages::GameChat;
        use rally_point_transport::control::send_control_chat;

        let (link_a, mut link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());
        // Hold every game-side channel half open; only `inbound` is drained.
        let TurnChannels {
            outbound: _outbound,
            mut inbound,
            result_expected: _result_expected,
            leaves: _leaves,
            leave_intent: _leave_intent,
            result: _result,
            lobby_out: _lobby_out,
            lobby_in: _lobby_in,
            chat_out: _chat_out,
            chat_in: _chat_in,
            request_drop: _request_drop,
            session_start: _session_start,
            connectivity: _connectivity,
        } = chan_a;

        // Flood chat far past its buffer with nothing draining it.
        let (mut ctrl_send, _our_recv) = link_b.connection().open_bi().await.unwrap();
        for i in 0..(CHAT_CHANNEL_CAPACITY + 50) {
            send_control_chat(
                &mut ctrl_send,
                GameChat {
                    slot: 1,
                    target_kind: 0,
                    target_slot: 0,
                    text: format!("m{i}"),
                },
            )
            .await
            .unwrap();
        }

        // A turn sent after the flood still reaches the game: the overflow was
        // dropped, not parked on.
        link_b.send(Some(turn(0, &[0xAB]))).unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), inbound.recv())
            .await
            .expect("turns must still flow past a wedged chat consumer")
            .expect("the driver must still be running");
        assert_eq!(got.commands[0], 0xAB);

        drop(inbound);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    #[test]
    fn rehome_anchor_covers_the_unacked_tail_below_the_retention_front() {
        // The bug this guards: on a re-home the rebound link keeps its unacked window
        // AND re-injects the retention ring, so the oldest re-sent seq is the lower of
        // the two. When own-slot in-flight has outgrown the retention cap the oldest
        // unacked seq sits BELOW the retention front; anchoring at the front would
        // strand every turn between them (re-carried, but buried below the fresh
        // relay's window — a comparator-visible desync).
        assert_eq!(
            rehome_own_slot_anchor(Some(4300), Some(4788)),
            Some(4300),
            "in-flight past the retention cap: anchor at the oldest unacked, not the front",
        );
        // The mirror case: the oldest turns were already acked (dropped from the
        // window) but retention still holds them to re-supply, so the retention front
        // is the lower — and load-bearing — bound.
        assert_eq!(
            rehome_own_slot_anchor(Some(5000), Some(4788)),
            Some(4788),
            "acked-then-retained old turns: anchor at the retention front",
        );
        // Equal bounds are a no-op either way.
        assert_eq!(rehome_own_slot_anchor(Some(4788), Some(4788)), Some(4788));
        // A single source: fall back to whichever will re-send.
        assert_eq!(rehome_own_slot_anchor(None, Some(4788)), Some(4788));
        assert_eq!(rehome_own_slot_anchor(Some(4300), None), Some(4300));
        // Nothing to re-send: no anchor, the fresh relay's window bases at 0.
        assert_eq!(rehome_own_slot_anchor(None, None), None);
    }

    #[tokio::test]
    async fn reinject_retention_defers_oversize_turns_to_the_control_stream() {
        // On a re-home, a retained turn that still fits a datagram re-enters the
        // unacked window for the redundancy pass to re-carry. One too big for any
        // datagram must not: build_outgoing skips it on every pass, so it would sit
        // in the window forever — never re-delivered and stalling a peer that never
        // got it from the dead relay. Such a turn is staged for the fresh control
        // stream instead, and it genuinely crosses that stream whole.
        let (mut link_a, link_b, _ea, _eb) = connected_links().await;
        let mut state = LoopState::new(Arc::new(AtomicBool::new(false)));

        state.retention.push_back(turn(0, &[0x01]));
        state.retention.push_back(turn(1, &vec![0x42; 4096]));

        reinject_retention(&mut link_a, &mut state);

        // The datagram-sized turn re-entered the window; the oversize one did not.
        assert_eq!(
            link_a.payloads_in_flight(),
            1,
            "only the datagram-sized turn re-enters the unacked window",
        );
        assert_eq!(state.pending_control_redivert.len(), 1);
        assert_eq!(
            state.pending_control_redivert[0].seq, 1,
            "the oversize turn is staged for the control stream, not the window",
        );

        // The staged turn is carriable on the control stream: sent over a fresh
        // bi-stream it crosses whole, and the peer's control reader folds it back as
        // an oversize turn — exactly the divert path a first-time oversize turn takes.
        let mut control_rx = spawn_control_reader(link_b.connection().clone());
        let (mut control_send, _recv) = link_a.connection().open_bi().await.unwrap();
        let staged = state.pending_control_redivert.remove(0);
        send_control_turn(&mut control_send, staged).await.unwrap();
        let delivered = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
            .await
            .expect("the deferred oversize turn never crossed the control stream")
            .expect("control reader closed early");
        match delivered {
            ControlInbound::OversizeTurn(payload) => {
                assert_eq!(payload.seq, 1);
                assert_eq!(
                    payload.commands.len(),
                    4096,
                    "the oversize turn arrives whole"
                );
            }
            other => panic!("expected an oversize turn on the control stream, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn same_relay_resume_redivers_only_the_oversize_retained_turns() {
        // On a SAME-relay resume (unlike a re-home), ordinary-sized retained
        // turns must NOT be touched at all — the old
        // relay's own turn ring already covers them, and re-injecting them
        // into the datagram window risks the permanent prefix gap
        // `reconnect_link`'s own `same_relay_anchor` comment describes. Only
        // the oversize subset — which never rode the datagram/ack path and so
        // carries no such risk — gets staged for the resumed connection's
        // control stream.
        let (link_a, _link_b, _ea, _eb) = connected_links().await;
        let mut state = LoopState::new(Arc::new(AtomicBool::new(false)));

        state.retention.push_back(turn(0, &[0x01])); // datagram-sized
        state.retention.push_back(turn(1, &vec![0x42; 4096])); // oversize

        redivert_oversize_retention_on_same_relay_resume(&link_a, &mut state);

        assert_eq!(
            link_a.payloads_in_flight(),
            0,
            "same-relay resume never touches the datagram/unacked window",
        );
        assert_eq!(state.pending_control_redivert.len(), 1);
        assert_eq!(state.pending_control_redivert[0].seq, 1);

        // A second call (mirroring a run of failed same-relay resumes before
        // one finally succeeds) does not re-stage an already-staged turn.
        redivert_oversize_retention_on_same_relay_resume(&link_a, &mut state);
        assert_eq!(
            state.pending_control_redivert.len(),
            1,
            "an already-staged oversize turn is not duplicated on a later resume",
        );
    }

    /// End-to-end proof that a same-relay resume actually redelivers a
    /// retained oversize turn: drives a real session that sends one, then
    /// simulates the resume path directly (mirroring what `reconnect_link`
    /// does on `Ok(fresh)`) and confirms the peer receives it on the fresh
    /// connection's control stream — a drop between the local `write_all`
    /// and the relay's own processing is now recovered rather than silently
    /// losing the turn.
    #[tokio::test]
    async fn a_same_relay_resume_redelivers_an_oversize_turn_the_relay_never_got() {
        let (link_a, _link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);

        // The oversize turn is sent once (mirroring the driver's own one-time
        // control-stream write) and retained, but — simulating a drop right
        // after that write — never actually reaches a peer control reader on
        // the original connection (none is spawned for it here).
        let oversize = turn(0, &vec![0x42; 4096]);
        chan_a.outbound.send(oversize.clone()).await.unwrap();
        drop(chan_a.outbound);
        let (mut link, mut seam, mut state) = into_session_parts(driver_a);
        LinkDriver::session(&mut link, &mut seam, &mut state, SlotId(0))
            .await
            .expect("session stops cleanly once the outbound seam closes");
        assert_eq!(
            state.retention.len(),
            1,
            "the oversize turn was retained when it was first sent",
        );

        // The same-relay resume: rebind (a fresh connection to keep the test
        // self-contained; a real same-relay resume rebinds the SAME relay's
        // address, but the mechanics under test — retention staging and the
        // control-stream redeliver — don't depend on which address it is),
        // then redivert.
        let (fresh_a, fresh_b, _fea, _feb) = connected_links().await;
        link.rebind(fresh_a.connection().clone());
        redivert_oversize_retention_on_same_relay_resume(&link, &mut state);
        assert_eq!(state.pending_control_redivert.len(), 1);

        // `session`'s own top-of-function drain (the existing
        // `redivert_pending_control` call) is what a real resume relies on;
        // exercise it directly here to prove the staged turn actually crosses
        // the wire.
        let mut control_rx = spawn_control_reader(fresh_b.connection().clone());
        let (mut control_send, _recv) = link.connection().open_bi().await.unwrap();
        redivert_pending_control(&mut control_send, &mut state.pending_control_redivert)
            .await
            .unwrap();

        let delivered = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
            .await
            .expect("the retained oversize turn never crossed the resumed control stream")
            .expect("control reader closed early");
        match delivered {
            ControlInbound::OversizeTurn(payload) => {
                assert_eq!(payload.seq, oversize.seq);
                assert_eq!(payload.commands.len(), 4096);
            }
            other => panic!("expected an oversize turn on the control stream, got {other:?}"),
        }
    }

    /// Splits a [`LinkDriver`] into the pieces [`session`](LinkDriver::session)
    /// takes directly, so a test can drive exactly one session on an explicit
    /// `own_slot` and then inspect the link and loop state afterward — state that
    /// `run`/`run_reconnecting` consume and drop.
    fn into_session_parts(driver: LinkDriver) -> (Link, GameSeam, LoopState) {
        let LinkDriver {
            link,
            outbound,
            inbound,
            leaves,
            leave_intent,
            result,
            result_expected,
            lobby_out,
            lobby_in,
            chat_out,
            chat_in,
            request_drop,
            session_start,
            connectivity,
        } = driver;
        let seam = GameSeam {
            outbound,
            inbound,
            leaves,
            leave_intent,
            result,
            lobby_out,
            lobby_in,
            chat_out,
            chat_in,
            request_drop,
            session_start,
            connectivity,
        };
        let state = LoopState::new(result_expected);
        (link, seam, state)
    }

    /// A turn produced past [`OUTAGE_OUTBOUND_BUFFER_CAP`] during an outage
    /// must not be silently dropped: `wait_backoff` surfaces
    /// `WaitOutcome::BufferExhausted` the moment the buffer crosses the cap,
    /// with every turn up to and including the one that tipped it over still
    /// in `state.outbound_buffer` (nothing discarded on the way).
    #[tokio::test]
    async fn wait_backoff_reports_buffer_exhausted_once_the_outage_buffer_overflows() {
        let (link_a, _link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let (_link, mut seam, mut state) = into_session_parts(driver_a);
        let mut backoff = Backoff::new();

        // Fill to exactly the cap, then one more to tip it over. `wait_backoff`
        // processes queued turns one at a time in its own loop, so pre-filling
        // the channel is equivalent to a real caller producing them one by one
        // during the outage.
        for i in 0..=OUTAGE_OUTBOUND_BUFFER_CAP {
            chan_a
                .outbound
                .send(turn(0, &[(i % 256) as u8]))
                .await
                .unwrap();
        }

        match wait_backoff(&mut backoff, &mut seam, &mut state).await {
            WaitOutcome::BufferExhausted => {}
            WaitOutcome::Elapsed => panic!("expected BufferExhausted, got Elapsed"),
            WaitOutcome::GameGone => panic!("expected BufferExhausted, got GameGone"),
        }
        assert_eq!(
            state.outbound_buffer.len(),
            OUTAGE_OUTBOUND_BUFFER_CAP + 1,
            "nothing was dropped on the way to the trip -- every produced turn is \
             still buffered, proving the exhaustion is reported, not silently eaten",
        );
    }

    /// Drives one session on `own_slot`, feeding it one small datagram turn per
    /// entry in `turns` and then closing the outbound seam so the session returns.
    /// The peer link is never driven, so nothing acks: every sent turn stays in the
    /// returned link's unacked window — the in-flight shape a reconnect anchors on.
    /// The peer link and endpoints are returned so the caller keeps the connection
    /// alive for any post-session wire inspection.
    async fn drive_unacked_session(
        own_slot: SlotId,
        turns: &[&[u8]],
    ) -> (Link, LoopState, Link, quinn::Endpoint, quinn::Endpoint) {
        let (link_a, link_b, ea, eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        // Buffer every turn (channel depth is ample) and then drop the sender, so
        // the session drains them all and returns Ok on the closed-seam `None`.
        for bytes in turns {
            chan_a.outbound.send(turn(0, bytes)).await.unwrap();
        }
        drop(chan_a.outbound);
        let (mut link, mut seam, mut state) = into_session_parts(driver_a);
        // `session_body`, not `session`: this helper's whole contract (see its
        // doc above) is inspecting the connection after the session ends, and
        // `session`'s own clean-exit close would race that inspection over
        // the unreliable datagram path -- exactly the hazard closing on a
        // clean exit is supposed to be safe to do in production, just not
        // compatible with a test that wants to keep reading afterward.
        LinkDriver::session_body(&mut link, &mut seam, &mut state, own_slot)
            .await
            .expect("session stops cleanly once the outbound seam closes");
        (link, state, link_b, ea, eb)
    }

    #[tokio::test]
    async fn driver_sends_key_the_unacked_window_under_the_authorized_slot() {
        // The embedder leaves every outbound turn's slot at 0; the driver stamps its
        // own authorized slot at send. Without that stamp a client on slot 1 keys its
        // in-flight turns under a phantom slot 0, so `oldest_unacked_seq(SlotId(1))`
        // (what a same-relay resume anchors on) sees nothing. Stamped, the unacked
        // window keys under slot 1 and the anchor query finds the in-flight seqs.
        let (link, state, _peer, _ea, _eb) =
            drive_unacked_session(SlotId(1), &[&[0x01], &[0x02], &[0x03]]).await;

        assert_eq!(state.next_outbound_seq, 3, "three turns were produced");
        assert_eq!(
            link.oldest_unacked_seq(SlotId(1)),
            Some(0),
            "the in-flight window keys under the authorized slot",
        );
        assert_eq!(
            link.oldest_unacked_seq(SlotId(0)),
            None,
            "nothing is stranded under the wire-claim slot 0",
        );
        assert_eq!(link.payloads_in_flight(), 3);
    }

    #[tokio::test]
    async fn outbound_turns_carry_the_authorized_slot_on_the_wire() {
        // The end-to-end counterpart to the keying unit: the stamped slot rides the
        // datagram, so an undriven peer reading the raw link sees the authorized slot
        // on the turn, not the embedder's 0.
        let (link, _state, mut peer, _ea, _eb) = drive_unacked_session(SlotId(1), &[&[0xAB]]).await;
        // Hold the sending link so the connection stays up for the peer's read.
        let _keep_alive = link;

        let received = loop {
            let received = tokio::time::timeout(Duration::from_secs(5), peer.recv())
                .await
                .expect("the stamped turn never reached the peer")
                .expect("peer link errored");
            if !received.fresh.is_empty() {
                break received;
            }
        };
        assert_eq!(received.fresh[0].slot, 1, "the wire turn carries slot 1");
        assert_eq!(received.fresh[0].commands[0], 0xAB);
    }

    #[tokio::test]
    async fn same_relay_resume_anchors_at_the_oldest_in_flight_seq_for_a_nonzero_slot() {
        // The live deadlock's shape: a client on slot 1 leaves a turn in flight, the
        // link drops, and the same-relay re-dial must present an own-slot anchor at
        // the oldest still-unacked seq so the relay's fresh receive window admits the
        // re-carried turn. Before the slot stamp the anchor fell through to
        // `next_outbound_seq` (one past the in-flight turn), and the relay classified
        // the re-carried turn as already-delivered and dropped it — a permanent stall.
        let (link, state, _peer, _ea, _eb) =
            drive_unacked_session(SlotId(1), &[&[0x01], &[0x02]]).await;

        // The exact computation `reconnect_link` performs for the same-relay anchor.
        let own_slot = SlotId(1);
        let anchor = link
            .oldest_unacked_seq(own_slot)
            .unwrap_or(state.next_outbound_seq);

        assert_eq!(
            anchor, 0,
            "the anchor is the oldest in-flight seq, not next_outbound",
        );
        assert_ne!(
            anchor, state.next_outbound_seq,
            "the bug regressed: the anchor skipped past the in-flight turn",
        );
    }

    #[tokio::test]
    async fn beacon_retirement_prunes_driver_sends_for_a_nonzero_slot() {
        // The relay's ack-beacon names the authorized slot. Retiring under it must
        // actually prune this client's driver-sent turns — which only holds once the
        // send path keys the unacked window under that same slot. Under the old
        // slot-0 keying `retire_through(own_slot, ..)` matched nothing and the window
        // grew unbounded on beacon retirement alone.
        let (mut link, _state, _peer, _ea, _eb) =
            drive_unacked_session(SlotId(1), &[&[0x01], &[0x02], &[0x03]]).await;
        assert_eq!(link.payloads_in_flight(), 3);

        // A beacon naming the wire-claim slot 0 prunes nothing — the turns aren't
        // keyed there.
        assert_eq!(
            link.retire_through(SlotId(0), 2),
            0,
            "no driver-sent turn is keyed under slot 0",
        );

        // A beacon naming the authorized slot retires the confirmed prefix (seqs 0
        // and 1), leaving only seq 2 in flight.
        assert_eq!(
            link.retire_through(SlotId(1), 1),
            2,
            "the authorized-slot cursor retires the driver's confirmed turns",
        );
        assert_eq!(link.oldest_unacked_seq(SlotId(1)), Some(2));
        assert_eq!(link.payloads_in_flight(), 1);
    }

    #[tokio::test]
    async fn staged_oversize_turns_survive_a_control_stream_send_failure_and_deliver_on_retry() {
        // A re-home stages oversize retained turns for the fresh connection's control
        // stream. If that connection drops again mid-drain, the unsent turns must not
        // be lost: `redivert_pending_control` keeps each staged until its send
        // succeeds, so a failed attempt leaves them all in place and the next session
        // retries them. Without this, a peer that never got an oversize turn from the
        // dead relay would stall forever on that seq.
        let oversize = |seq: u64, byte: u8| turn(seq, &vec![byte; 4096]);
        let mut pending = vec![oversize(0, 0x11), oversize(1, 0x22)];

        // Attempt 1: a connection closed before the send, so `write_all` fails. Every
        // staged turn must remain — none dropped on the failure.
        {
            let (link_a, _link_b, _ea, _eb) = connected_links().await;
            let (mut control_send, _recv) = link_a.connection().open_bi().await.unwrap();
            link_a
                .connection()
                .close(quinn::VarInt::from_u32(0), b"boom");
            let result = redivert_pending_control(&mut control_send, &mut pending).await;
            assert!(result.is_err(), "a send over a dead connection must fail");
            assert_eq!(
                pending.len(),
                2,
                "a failed control-stream send loses no staged turn",
            );
        }

        // Attempt 2: a fresh connection whose peer reads its control stream. Both
        // staged turns cross, in seq order, and the staging drains empty.
        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let mut control_rx = spawn_control_reader(link_b.connection().clone());
        let (mut control_send, _recv) = link_a.connection().open_bi().await.unwrap();
        redivert_pending_control(&mut control_send, &mut pending)
            .await
            .expect("the retry over a live connection delivers the staged turns");
        assert!(
            pending.is_empty(),
            "every staged turn was sent on the retry"
        );

        for expected_seq in [0u64, 1] {
            let delivered = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
                .await
                .expect("a staged oversize turn never crossed on the retry")
                .expect("control reader closed early");
            match delivered {
                ControlInbound::OversizeTurn(payload) => {
                    assert_eq!(payload.seq, expected_seq);
                    assert_eq!(
                        payload.commands.len(),
                        4096,
                        "the oversize turn arrives whole"
                    );
                }
                other => panic!("expected an oversize turn on the control stream, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn delivers_reordered_payloads_to_the_game_in_seq_order() {
        use prost::Message;
        use rally_point_proto::messages::Packet;

        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());
        let mut inbound = chan_a.inbound;

        // Hand-build two single-payload packets and deliver the higher payload seq
        // first; the driver must hold it until the lower seq arrives.
        let raw = |pkt_seq: u32, payload_seq: u64, byte: u8| {
            Packet {
                seq: pkt_seq,
                ack: None,
                ack_bits: 0,
                payloads: vec![Payload {
                    seq: payload_seq,
                    slot: 0,
                    commands: vec![byte].into(),
                    ..Default::default()
                }],
            }
            .encode_to_vec()
        };
        let conn = link_b.connection();
        conn.send_datagram(raw(0, 1, 0xB1).into()).unwrap();

        // Seq 1 must be held while seq 0 is missing — nothing reaches the game yet.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), inbound.recv())
                .await
                .is_err(),
            "seq 1 was delivered before the missing seq 0"
        );

        // Once seq 0 arrives, both drain in seq order.
        conn.send_datagram(raw(1, 0, 0xB0).into()).unwrap();
        let first = inbound.recv().await.unwrap();
        let second = inbound.recv().await.unwrap();
        assert_eq!((first.seq, first.commands[0]), (0, 0xB0));
        assert_eq!((second.seq, second.commands[0]), (1, 0xB1));

        drop(chan_a.outbound);
        let _ = task.await;
    }

    #[tokio::test]
    async fn a_datagram_turn_with_an_out_of_range_slot_ends_the_link_as_a_failure() {
        use prost::Message;
        use rally_point_proto::messages::Packet;

        // A payload whose slot id overflows `u8` names no real slot; a truncating
        // cast would alias it onto `slot % 256` and corrupt that player's turn
        // stream. The transport layer refuses the whole packet rather than risk
        // that aliasing, which surfaces here as a link failure -- reconnect-
        // eligible, not a turn silently dropped while the link limps on.
        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());
        let mut inbound = chan_a.inbound;

        let raw = Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: vec![Payload {
                seq: 0,
                slot: 256,
                commands: vec![0xEE].into(),
                ..Default::default()
            }],
        }
        .encode_to_vec();
        link_b.connection().send_datagram(raw.into()).unwrap();

        // Nothing is ever delivered to the game...
        assert!(
            tokio::time::timeout(Duration::from_millis(300), inbound.recv())
                .await
                .unwrap()
                .is_none(),
            "an out-of-range inbound slot must not be delivered to the game",
        );
        // ...because the link itself ended as a failure, not a clean stop.
        match task.await.unwrap() {
            Err(DriverError::Link(_)) => {}
            other => panic!("expected a link failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_oversize_turn_with_an_out_of_range_slot_is_dropped() {
        // The control-stream divert path has its own guard, independent of the
        // datagram path's transport-layer rejection: a payload arriving this
        // way is already past `Link`'s dedup (this stream carries no dedup key
        // of its own), so the driver itself must reject an out-of-range slot
        // here rather than alias it onto a different player's turn stream.
        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());
        let mut inbound = chan_a.inbound;

        let (mut control_send, _recv) = link_b.connection().open_bi().await.unwrap();
        send_control_turn(
            &mut control_send,
            Payload {
                seq: 0,
                slot: 256,
                commands: vec![0xEE].into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(300), inbound.recv())
                .await
                .is_err(),
            "an out-of-range oversize-turn slot must not be delivered to the game",
        );

        drop(chan_a.outbound);
        let _ = task.await;
    }

    #[tokio::test]
    async fn envelope_metadata_survives_delivery_to_the_game() {
        use rally_point_proto::messages::BufferDirective;

        let (link_a, mut link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());
        let mut inbound = chan_a.inbound;

        // A relay-forwarded turn carries more than its command bytes: the frame
        // annotation and any latency-buffer directive the authority stamped ride
        // the envelope. The driver must hand the payload to the game whole — the
        // envelope is the game's only channel for the buffer directive, so a
        // driver that rebuilt payloads and dropped it would silently break buffer
        // changes for this client. (Leaves ride the control stream, not the
        // envelope — see the control-stream leave test.)
        let stamped = Payload {
            seq: 0,
            slot: 0,
            commands: vec![0x0C].into(),
            game_frame_count: Some(41),
            buffer_directive: Some(BufferDirective {
                buffer_turns: 4,
                apply_at_frame: 64,
                decision_seq: 1,
                authority_relay_id: None,
            }),
        };
        link_b.send(Some(stamped.clone())).unwrap();

        let delivered = inbound.recv().await.unwrap();
        assert_eq!(delivered, stamped);

        drop(chan_a.outbound);
        let _ = task.await;
    }

    #[tokio::test]
    async fn retransmits_an_unacked_turn_during_outbound_silence() {
        let (link_a, mut link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        // One turn, then silence: the game produces nothing more and the peer never
        // acks. The driver still has it in flight.
        chan_a.outbound.send(turn(0, &[0x42])).await.unwrap();

        // Drop the first datagram carrying it, simulating loss on the wire, so the
        // peer's dedup never sees the original.
        let _lost = link_b.connection().read_datagram().await.unwrap();

        // Recovery depends on a later packet re-carrying the unacked turn. With no
        // further turn and no peer traffic, the idle flush is the only thing that
        // re-sends it — it must arrive on a subsequent packet.
        let delivered = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let payloads = link_b.recv().await.unwrap().fresh;
                if !payloads.is_empty() {
                    return payloads;
                }
            }
        })
        .await
        .expect("the dropped turn was never retransmitted");
        assert_eq!(delivered[0].commands[0], 0x42);

        drop(chan_a);
        let _ = task.await;
    }

    #[tokio::test]
    async fn retransmits_a_dropped_turn_under_continuous_near_mtu_traffic() {
        let (link_a, mut link_b, _ea, _eb) = connected_links().await;
        let budget = link_b
            .connection()
            .max_datagram_size()
            .expect("loopback supports datagrams");
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        // Near-MTU turns: each fresh turn nearly fills a datagram, so a packet has no
        // room to also re-carry an older unacked turn as redundancy.
        let big = move || turn(0, &vec![0x7u8; budget * 3 / 4]);

        // Turn 0 goes out, but its datagram is dropped on the wire.
        chan_a.outbound.send(big()).await.unwrap();
        let _lost = link_b.connection().read_datagram().await.unwrap();

        // A steady stream of further near-MTU turns follows with no idle gap. Their
        // packets have no room to re-carry turn 0 as redundancy, so they don't reset
        // the flush timer; it fires and retransmits turn 0 even with the link never
        // idle — proof recovery doesn't depend on outbound silence here.
        let sender = {
            let outbound = chan_a.outbound.clone();
            tokio::spawn(async move {
                for _ in 0..12 {
                    if outbound.send(big()).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            })
        };

        // Turn 0 (seq 0) must reach the peer despite the unbroken fresh stream.
        let got_zero = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if link_b
                    .recv()
                    .await
                    .unwrap()
                    .fresh
                    .iter()
                    .any(|p| p.seq == 0)
                {
                    return;
                }
            }
        })
        .await;
        assert!(
            got_zero.is_ok(),
            "dropped turn 0 was never retransmitted under continuous traffic"
        );

        sender.abort();
        drop(chan_a.outbound);
        let _ = task.await;
    }

    #[tokio::test]
    async fn an_idle_link_goes_quiet_after_a_turn_is_acked() {
        let (link_a, mut link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        // A sends one turn; the peer receives and acks it.
        chan_a.outbound.send(turn(0, &[0x55])).await.unwrap();
        let got = link_b.recv().await.unwrap();
        assert_eq!(got.fresh[0].commands[0], 0x55);
        link_b.send(None).unwrap();

        // The peer then sends a second ack-only packet — its own maintenance flush.
        // The driver must not treat that as something to ack, or the two would trade
        // ack-only packets forever.
        link_b.send(None).unwrap();

        // With the turn retired and only ack-only packets left, the link must fall
        // silent: the driver sends nothing across the several flushes in this window.
        let quiet = tokio::time::timeout(
            Duration::from_millis(600),
            link_b.connection().read_datagram(),
        )
        .await;
        assert!(
            quiet.is_err(),
            "driver kept sending on an idle link: {quiet:?}"
        );

        drop(chan_a);
        let _ = task.await;
    }

    #[tokio::test]
    async fn a_stalled_game_consumer_surfaces_instead_of_hanging() {
        // A depth-1 inbound buffer and a receiver that never drains: once it fills,
        // the driver must report the stall, not block its whole loop on the wedged
        // consumer (which would also freeze acks and link-failure detection).
        let (link_a, mut link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::with_capacity(link_a, 1);
        let task = tokio::spawn(driver_a.run());

        // Hold the inbound receiver open without ever draining it.
        let _inbound = chan_a.inbound;

        // Several turns from the peer: with a depth-1 buffer and no draining, the
        // driver fills it and then has nowhere to put the next one.
        for i in 0..4u8 {
            link_b.send(Some(turn(i as u64, &[i]))).unwrap();
        }

        match tokio::time::timeout(Duration::from_secs(5), task).await {
            Ok(joined) => assert!(matches!(joined.unwrap(), Err(DriverError::GameStalled))),
            Err(_) => panic!("driver hung on a stalled consumer instead of surfacing it"),
        }

        // A terminal error ends the driver, and the ended driver must not keep
        // holding its relay-side slot: the peer sees a deliberate close, not a
        // connection lingering until the QUIC idle timeout.
        let closed = tokio::time::timeout(Duration::from_secs(5), link_b.connection().closed())
            .await
            .expect("the ended driver never closed its connection");
        assert!(
            matches!(closed, quinn::ConnectionError::ApplicationClosed(_)),
            "closed deliberately by the driver, not lost: {closed:?}",
        );
    }

    #[tokio::test]
    async fn stops_cleanly_when_the_game_drops_its_sender() {
        let (link_a, _link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        // No turns ever sent; dropping the seam is the game tearing down.
        drop(chan_a.outbound);
        drop(chan_a.inbound);
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn stops_cleanly_when_the_game_drops_its_receiver() {
        let (link_a, _link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        // The game drops only its receiver on a quiet link: no turn is ever delivered
        // through which a failed send could surface the closure, so the driver must
        // notice it on its own and stop — otherwise the connection (and relay slot)
        // would leak. The sender is kept alive to the end so the stop is via the
        // dropped receiver, not the dropped sender.
        drop(chan_a.inbound);

        match tokio::time::timeout(Duration::from_secs(5), task).await {
            Ok(joined) => assert!(joined.unwrap().is_ok()),
            Err(_) => panic!("driver kept running after its receiver was dropped"),
        }
        drop(chan_a.outbound);
    }

    /// A clean driver exit actually closes the connection, rather than
    /// leaving it open until QUIC's own idle timeout. `link_a` itself is
    /// moved into the spawned driver task and unobservable afterward, so
    /// this checks the one place the close is externally visible: the
    /// peer's own connection sees it end. Before the fix, this timed out —
    /// the beacon and control-stream reader tasks each held their own
    /// `connection.clone()` parked on `accept_*`, so nothing ever told the
    /// peer the link was actually done.
    #[tokio::test]
    async fn a_clean_stop_closes_the_connection_so_the_peer_observes_it_end() {
        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let peer_connection = link_b.connection().clone();
        let task = tokio::spawn(driver_a.run());

        drop(chan_a.outbound);
        drop(chan_a.inbound);
        assert!(task.await.unwrap().is_ok());

        match tokio::time::timeout(Duration::from_secs(5), peer_connection.closed()).await {
            Ok(_reason) => {}
            Err(_) => panic!(
                "the peer never observed the connection end -- the driver's clean exit \
                 did not actually close it"
            ),
        }
    }

    #[tokio::test]
    async fn the_beacon_retires_acked_turns_under_reverse_path_loss() {
        // Reverse-path loss: the peer *receives* the turns (redundancy keeps up),
        // but the acks riding the datagrams back are lost. Without the beacon, the
        // driver would re-carry these turns forever and `payloads_in_flight` would
        // grow past the cap. The beacon pushes the peer's `delivered_through`
        // cursor, the driver force-retires through it, and the window stays
        // bounded — the normal recovery path.
        //
        // This is the inversion of `forward_path_sustained_loss_trips_the_unacked_window_cap`:
        // there the peer never receives, so the beacon can't retire and the cap trips.
        // Here the peer *does* receive and pushes its cursor, so the beacon retires
        // and the driver stays alive past the cap — proving the force-advance works.
        // A regression in flush_beacon → stream → reader → retire_through would let
        // in_flight grow past the cap and trip UnackedWindowExhausted here.
        //
        // The observable is a count, not a timing sleep: a tripped driver stops
        // sending, so "the peer received all CAP+256 turns" deterministically proves
        // the driver sent past the cap without tripping — i.e., the beacon retired.
        // A fixed sleep can't reach that: at any point before the cap is stressed
        // in_flight is small whether the beacon works or not.
        let (link_a, mut link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        // The peer opens its outbound beacon uni-stream and pushes its
        // delivered_through cursor as it receives turns. This is what a real
        // relay/client does via flush_beacon; here we do it by hand since link_b
        // is a raw Link (no driver).
        let mut peer_beacon = link_b.connection().open_uni().await.unwrap();
        let total = (UNACKED_WINDOW_CAP + 256) as u32;

        let peer = tokio::spawn(async move {
            let mut last_pushed: Option<u64> = None;
            while let Ok(r) = link_b.recv().await {
                // The peer received these turns: its delivered_through advanced.
                // Push the new cursor to the driver. All turns here are slot 0.
                if let Some(cursor) = link_b.delivered_through(SlotId(0))
                    && !matches!(last_pushed, Some(p) if p >= cursor)
                {
                    let frame = beacon::encode_frame(SlotId(0), cursor);
                    if peer_beacon.write_all(&frame).await.is_ok() {
                        last_pushed = Some(cursor);
                    }
                }
                let _ = r; // drain; the count isn't the observable here
            }
        });

        // No ack datagrams are ever sent back — 100% reverse-path loss. The only
        // way the driver's window stays bounded is the beacon retiring through the
        // peer's pushed cursor. Flood past the cap: a working beacon retires as it
        // goes and the driver sends every turn (the flood completes); a broken
        // beacon lets in_flight hit the cap, the driver trips UnackedWindowExhausted,
        // and the outbound channel send fails early (the flood does NOT complete).
        //
        // The observable is whether the flood sent all `total` turns: that's
        // deterministic and race-free — a tripped driver stops sending, so a
        // broken beacon can't send past the cap no matter how long you wait.
        let flood = {
            let outbound = chan_a.outbound.clone();
            tokio::spawn(async move {
                let mut sent = 0u32;
                for i in 0..total {
                    if outbound.send(turn(0, &[(i & 0xFF) as u8])).await.is_err() {
                        break; // Driver tripped or closed.
                    }
                    sent += 1;
                    // A tiny pace lets the peer's recv + beacon push keep up, so
                    // this is genuine reverse-path loss (turns arrive, acks
                    // don't), not forward-path loss (peer can't receive fast
                    // enough).
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                sent
            })
        };

        // Wait for the flood to finish (all turns sent, or the driver tripped and
        // the send broke). It returns the count it actually sent.
        let sent = tokio::time::timeout(Duration::from_secs(30), flood)
            .await
            .expect("the flood never completed — the driver or peer stalled")
            .expect("the flood task panicked");

        // The driver must have sent well past the cap without tripping — i.e., the
        // beacon retired the turns the peer confirmed it received. A broken beacon
        // lets in_flight hit the cap and the driver trips after ~CAP+1 turns (the
        // check is `in_flight > CAP`, so one more send crosses it), so the flood
        // stalls near CAP. The threshold sits at the midpoint between broken
        // (~CAP+1) and working (~CAP+256), giving margin against a few in-flight
        // datagrams dropped on the trip/close.
        assert!(
            sent > (UNACKED_WINDOW_CAP + 128) as u32,
            "driver tripped the cap under reverse-path loss — the beacon did not \
             retire the peer's confirmed-delivered turns (the flood sent only \
             {sent} turns before the driver stopped; a working beacon keeps the \
             driver sending past the {UNACKED_WINDOW_CAP}-turn cap)"
        );

        // And the driver must still be alive (not tripped) — the flood completed
        // because the beacon kept the window bounded, not because the channel
        // broke for another reason.
        assert!(
            !task.is_finished(),
            "driver task ended after the flood — it should still be alive with a \
             working beacon"
        );

        drop(chan_a.outbound);
        peer.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn forward_path_sustained_loss_trips_the_unacked_window_cap() {
        // Forward-path sustained loss: the peer genuinely receives slower than the
        // client produces — redundancy can't keep up, so `payloads_in_flight` grows
        // without bound. The beacon can only retire what the peer *got*, never what
        // it never received, so the window still grows past the cap. The driver must
        // trip `UnackedWindowExhausted` rather than let seqs race ahead until the
        // peer's receive window rejects them and drops the link (the status-quo
        // unbounded-growth failure this mechanism exists to prevent). This is the test
        // that catches a missing cap — a beacon-only design passes every other test
        // but fails here.
        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        // The peer never receives: drain its datagrams but never call `recv()`, so
        // its `delivered_through` never advances and the beacon can't retire
        // anything. Meanwhile the driver keeps producing turns. Each goes out and
        // stays unacked — genuine forward-path loss.
        //
        // We must drain the raw datagrams off the wire or quinn's datagram buffer
        // fills and the connection stalls before the cap is reached. But we never
        // feed them to `link_b.recv()`, so no delivered_through advances.
        let drainer = {
            let conn = link_b.connection().clone();
            tokio::spawn(async move {
                // Drain datagrams without processing them — the peer "receives" at
                // the transport level but never advances its delivered cursor.
                loop {
                    if conn.read_datagram().await.is_err() {
                        break;
                    }
                }
            })
        };

        // Flood turns past the cap. The driver sends each one; none are acked and
        // the beacon can't retire them (delivered_through is stuck at None). When
        // in_flight exceeds UNACKED_WINDOW_CAP the driver trips.
        let flood = {
            let outbound = chan_a.outbound.clone();
            tokio::spawn(async move {
                for i in 0..(UNACKED_WINDOW_CAP + 64) as u16 {
                    if outbound.send(turn(0, &[(i & 0xFF) as u8])).await.is_err() {
                        break;
                    }
                    // Don't pace: the goal is to outrun the peer, which never
                    // processes anything.
                }
            })
        };

        // The driver must surface UnackedWindowExhausted, not hang.
        match tokio::time::timeout(Duration::from_secs(10), task).await {
            Ok(joined) => assert!(
                matches!(
                    joined.unwrap(),
                    Err(DriverError::UnackedWindowExhausted { in_flight, cap })
                        if in_flight > cap && cap == UNACKED_WINDOW_CAP
                ),
                "expected UnackedWindowExhausted"
            ),
            Err(_) => {
                panic!("driver hung under forward-path sustained loss instead of tripping the cap")
            }
        }

        drainer.abort();
        flood.abort();
    }

    #[tokio::test]
    async fn leave_intent_is_sent_immediately_when_nothing_is_outstanding() {
        // With no turns ever produced, the outbound queue and unacked window
        // are already empty: the intent must go out the moment the game
        // signals, without waiting on anything to drain.
        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        // Watch the control stream the way the relay does.
        let mut control_rx = spawn_control_reader(link_b.connection().clone());

        chan_a.leave_intent.send(()).await.unwrap();

        let frame = tokio::time::timeout(Duration::from_secs(1), control_rx.recv())
            .await
            .expect("leave intent never arrived")
            .expect("control reader ended early");
        assert!(matches!(frame, ControlInbound::LeaveIntent));

        drop(chan_a.outbound);
        drop(chan_a.inbound);
        let _ = task.await;
    }

    #[tokio::test]
    async fn leave_intent_waits_for_unacked_turns_to_drain_before_sending() {
        // A turn is still unacked when the game signals its departure: the
        // intent must not go out until the fake relay acks it — the driver
        // holds off announcing until the relay's view of our last turn is
        // final.
        let (link_a, mut link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        let mut control_rx = spawn_control_reader(link_b.connection().clone());

        // One turn goes out and the fake relay sees it, but deliberately
        // never acks it yet.
        chan_a.outbound.send(turn(0, &[0x11])).await.unwrap();
        let received = link_b.recv().await.unwrap();
        assert_eq!(
            received.fresh[0].commands[0], 0x11,
            "the relay saw the turn"
        );

        // Signal departure now, while that turn is still unacked.
        chan_a.leave_intent.send(()).await.unwrap();

        // The intent must not arrive while anything is unacked.
        assert!(
            tokio::time::timeout(Duration::from_millis(300), control_rx.recv())
                .await
                .is_err(),
            "leave intent sent before its last turn was acked"
        );

        // The fake relay's ack-only flush retires it.
        link_b.send(None).unwrap();

        let frame = tokio::time::timeout(Duration::from_millis(500), control_rx.recv())
            .await
            .expect("leave intent never arrived after the ack")
            .expect("control reader ended early");
        assert!(matches!(frame, ControlInbound::LeaveIntent));

        drop(chan_a.outbound);
        drop(chan_a.inbound);
        let _ = task.await;
    }

    #[tokio::test]
    async fn leave_intent_is_sent_after_the_safety_timeout_if_acks_never_arrive() {
        // The fake relay sees a turn but never acks it. The driver must not
        // wait on the drain condition forever once the game has signaled
        // departure — the safety timeout fires and the intent goes out
        // anyway.
        let (link_a, mut link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        let mut control_rx = spawn_control_reader(link_b.connection().clone());

        chan_a.outbound.send(turn(0, &[0x22])).await.unwrap();
        let _received = link_b.recv().await.unwrap(); // seen, never acked

        let before = tokio::time::Instant::now();
        chan_a.leave_intent.send(()).await.unwrap();

        let frame = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
            .await
            .expect("leave intent never arrived")
            .expect("control reader ended early");
        assert!(matches!(frame, ControlInbound::LeaveIntent));
        assert!(
            before.elapsed() >= LEAVE_INTENT_TIMEOUT,
            "intent went out before the safety timeout elapsed"
        );

        drop(chan_a.outbound);
        drop(chan_a.inbound);
        let _ = task.await;
    }

    #[tokio::test]
    async fn run_returns_ok_when_the_link_closes_after_the_leave_intent() {
        // Once the intent has gone out, the relay closing the link is the
        // expected confirmation it processed the leave: `run` must return
        // `Ok`, not surface a `DriverError`.
        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        let mut control_rx = spawn_control_reader(link_b.connection().clone());
        chan_a.leave_intent.send(()).await.unwrap();
        let frame = tokio::time::timeout(Duration::from_secs(1), control_rx.recv())
            .await
            .expect("leave intent never arrived")
            .expect("control reader ended early");
        assert!(matches!(frame, ControlInbound::LeaveIntent));

        // The relay's confirmation is closing the link once it has processed
        // the intent — simulate that directly rather than the game dropping
        // its channels.
        link_b
            .connection()
            .close(quinn::VarInt::from_u32(0), b"leave processed");

        match tokio::time::timeout(Duration::from_secs(5), task).await {
            Ok(joined) => assert!(
                joined.unwrap().is_ok(),
                "run() must return Ok after the link closes post-intent"
            ),
            Err(_) => panic!("driver never noticed the post-intent link close"),
        }
    }

    #[tokio::test]
    async fn dropping_the_leave_intent_sender_without_signaling_does_not_affect_the_driver() {
        // An unclean teardown (the process dying, or a caller that never wires
        // leave-intent up) drops the sender without ever signaling. The driver
        // must keep running exactly as if leave-intent didn't exist — proven
        // here by still forwarding a turn afterward.
        let (link_a, mut link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        drop(chan_a.leave_intent);

        chan_a.outbound.send(turn(0, &[0x33])).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(5), link_b.recv())
            .await
            .expect("driver stopped forwarding turns after its leave-intent sender was dropped")
            .unwrap();
        assert_eq!(received.fresh[0].commands[0], 0x33);

        drop(chan_a.outbound);
        drop(chan_a.inbound);
        let _ = task.await;
    }

    #[tokio::test]
    async fn a_result_is_sent_immediately_over_a_live_link() {
        // A result report goes out the moment the game hands it over — mid-game,
        // with nothing draining and no leave signalled — not after any wind-down.
        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        // Watch the control stream the way the relay does.
        let mut control_rx = spawn_control_reader(link_b.connection().clone());

        chan_a.result.send(vec![0x0A, 0x0B, 0x0C]).await.unwrap();

        let frame = tokio::time::timeout(Duration::from_secs(1), control_rx.recv())
            .await
            .expect("the result frame never arrived")
            .expect("control reader ended early");
        match frame {
            ControlInbound::GameResult(payload) => {
                assert_eq!(payload.as_ref(), &[0x0A, 0x0B, 0x0C])
            }
            other => panic!("expected a result frame, got {other:?}"),
        }

        drop(chan_a.outbound);
        drop(chan_a.inbound);
        let _ = task.await;
    }

    #[tokio::test]
    async fn a_result_is_written_before_the_leave_intent_when_both_are_signalled() {
        // The ordering invariant: with a result expected, the game hands over the
        // payload and signals its departure; the driver must write the result
        // frame ahead of the leave-intent frame on the one ordered control stream,
        // regardless of which channel it services first.
        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        let mut control_rx = spawn_control_reader(link_b.connection().clone());

        // The game marks a result expected before it can signal a leave, hands
        // over the payload, then signals its departure.
        chan_a.result_expected.store(true, Ordering::Relaxed);
        chan_a.result.send(vec![0xAA, 0xBB]).await.unwrap();
        chan_a.leave_intent.send(()).await.unwrap();

        let first = tokio::time::timeout(Duration::from_secs(2), control_rx.recv())
            .await
            .expect("the result frame never arrived")
            .expect("control reader ended early");
        match first {
            ControlInbound::GameResult(payload) => assert_eq!(payload.as_ref(), &[0xAA, 0xBB]),
            other => panic!("expected the result frame first, got {other:?}"),
        }

        let second = tokio::time::timeout(Duration::from_secs(2), control_rx.recv())
            .await
            .expect("the leave intent never arrived")
            .expect("control reader ended early");
        assert!(
            matches!(second, ControlInbound::LeaveIntent),
            "the leave intent must follow the result on the wire",
        );

        drop(chan_a.outbound);
        drop(chan_a.inbound);
        let _ = task.await;
    }

    #[tokio::test]
    async fn the_leave_intent_still_goes_out_after_the_timeout_when_no_result_arrives() {
        // The game marked a result expected but never hands one over. The intent
        // must not be held forever — the leave-intent safety timeout fires and it
        // goes out anyway, since a missing or late result is harmless.
        let (link_a, link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        let mut control_rx = spawn_control_reader(link_b.connection().clone());

        chan_a.result_expected.store(true, Ordering::Relaxed);
        let before = tokio::time::Instant::now();
        chan_a.leave_intent.send(()).await.unwrap();

        let frame = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
            .await
            .expect("leave intent never arrived")
            .expect("control reader ended early");
        assert!(matches!(frame, ControlInbound::LeaveIntent));
        assert!(
            before.elapsed() >= LEAVE_INTENT_TIMEOUT,
            "the intent went out before the result-hold timeout elapsed",
        );

        drop(chan_a.outbound);
        drop(chan_a.inbound);
        let _ = task.await;
    }

    /// Mirrors the driver's datagram-branch inbound ingest for a single slot:
    /// buffer a turn only at or above the next-needed seq, then release the
    /// contiguous prefix to the game. This is the exact bookkeeping the resume
    /// cursor is read from.
    fn ingest_turn(
        slot: SlotId,
        seq: u64,
        next_seq: &mut HashMap<SlotId, u64>,
        pending: &mut HashMap<SlotId, BTreeMap<u64, Payload>>,
        inbound: &mpsc::Sender<Payload>,
    ) {
        let slot_next = *next_seq.entry(slot).or_insert(0);
        if seq >= slot_next {
            pending
                .entry(slot)
                .or_default()
                .insert(seq, turn(seq, &[seq as u8]));
        }
        assert!(matches!(
            release_ready(next_seq, pending, inbound),
            Release::Delivered
        ));
    }

    #[tokio::test]
    async fn resume_cursor_is_the_contiguous_high_water_and_absorbs_replayed_turns() {
        // The reconnect path derives its resume cursor from `next_seq` — the top of
        // the contiguous run delivered to the game, per slot. Drive the driver's
        // exact inbound ingest and confirm the cursor tracks that high-water and
        // that a replayed already-delivered turn neither advances it nor re-reaches
        // the game (the reorder buffer dedups the overlap a replay carries).
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<Payload>(64);
        let mut next_seq: HashMap<SlotId, u64> = HashMap::new();
        let mut pending: HashMap<SlotId, BTreeMap<u64, Payload>> = HashMap::new();
        let slot = SlotId(0);

        ingest_turn(slot, 0, &mut next_seq, &mut pending, &inbound_tx);
        ingest_turn(slot, 1, &mut next_seq, &mut pending, &inbound_tx);
        // A gap at 2: seq 3 is held, so the cursor stays at the next-needed 2.
        ingest_turn(slot, 3, &mut next_seq, &mut pending, &inbound_tx);
        assert_eq!(resume_cursors(&next_seq), vec![(slot, 2)]);

        // A replay of an already-delivered turn (seq 1 < cursor 2) is dropped: the
        // cursor is unchanged and nothing new reaches the game.
        ingest_turn(slot, 1, &mut next_seq, &mut pending, &inbound_tx);
        assert_eq!(resume_cursors(&next_seq), vec![(slot, 2)]);

        // Seq 2 fills the gap: 2 and the held 3 both release, the cursor jumps to 4.
        ingest_turn(slot, 2, &mut next_seq, &mut pending, &inbound_tx);
        assert_eq!(resume_cursors(&next_seq), vec![(slot, 4)]);

        // The game saw 0,1,2,3 once each, in order — no duplicate from the replay.
        let mut delivered = Vec::new();
        while let Ok(payload) = inbound_rx.try_recv() {
            delivered.push((payload.seq, payload.commands[0]));
        }
        assert_eq!(delivered, vec![(0, 0), (1, 1), (2, 2), (3, 3)]);
    }

    #[test]
    fn resume_cursors_map_every_received_peer_slot_to_its_next_needed_seq() {
        let mut next_seq = HashMap::new();
        next_seq.insert(SlotId(0), 5);
        next_seq.insert(SlotId(2), 0);
        let mut cursors = resume_cursors(&next_seq);
        cursors.sort();
        assert_eq!(cursors, vec![(SlotId(0), 5), (SlotId(2), 0)]);

        // No peer turns received yet → no cursors → the relay replays nothing, the
        // same as a fresh dial.
        assert!(resume_cursors(&HashMap::new()).is_empty());
    }

    #[test]
    fn backoff_base_schedule_doubles_from_the_initial_delay_then_caps() {
        assert_eq!(Backoff::base_delay(0), RECONNECT_BACKOFF_INITIAL);
        assert_eq!(Backoff::base_delay(1), Duration::from_secs(1));
        assert_eq!(Backoff::base_delay(2), Duration::from_secs(2));
        assert_eq!(Backoff::base_delay(3), Duration::from_secs(4));
        // 500ms << 4 = 8s would exceed the 5s cap, so it clamps there.
        assert_eq!(Backoff::base_delay(4), RECONNECT_BACKOFF_CAP);
        assert_eq!(Backoff::base_delay(5), RECONNECT_BACKOFF_CAP);
        // A far-out attempt saturates at the cap rather than overflowing the shift.
        assert_eq!(Backoff::base_delay(1_000), RECONNECT_BACKOFF_CAP);
    }

    #[test]
    fn backoff_next_delay_jitters_within_half_of_base_and_advances_each_attempt() {
        let mut backoff = Backoff::new();
        // `next_delay` uses the current attempt's base then advances, so the base for
        // attempt N is what the Nth draw must fall within.
        for attempt in 0..8u32 {
            let base = Backoff::base_delay(attempt);
            let delay = backoff.next_delay();
            assert!(
                delay <= base,
                "attempt {attempt}: {delay:?} exceeds its base {base:?}"
            );
            assert!(
                delay >= base / 2,
                "attempt {attempt}: {delay:?} is below half its base {base:?}"
            );
        }

        // A reset returns to the initial delay's jitter band.
        backoff.reset();
        let first = backoff.next_delay();
        assert!(first >= RECONNECT_BACKOFF_INITIAL / 2 && first <= RECONNECT_BACKOFF_INITIAL);
    }
}
