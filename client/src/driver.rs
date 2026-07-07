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

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{GameChat, LeaveDirective, LobbyCommand, Payload};
use rally_point_transport::beacon::{flush_beacon, spawn_beacon_reader};
use rally_point_transport::control::{
    ControlInbound, ControlSendError, send_control_chat, send_control_game_result,
    send_control_lobby, send_control_turn, spawn_control_reader,
};
use rally_point_transport::{Link, LinkError, quinn};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};

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
/// failure). Surfacing the condition is the buildable half; the resync it
/// triggers is gated on the open failover design (D11).
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
    /// The game stopped draining received turns and the inbound buffer filled, so
    /// the relay's turns have nowhere to go. The driver surfaces this instead of
    /// blocking on the handoff — parking there would also stall its acks and
    /// outbound turns — so the caller can tear down or resync.
    #[error("game stopped draining received turns; inbound buffer full")]
    GameStalled,
    /// The unacked window crossed [`UNACKED_WINDOW_CAP`] even after the beacon
    /// side-channel retired everything the peer confirmed it received — the
    /// peer is genuinely behind, not just ack-starved. This is the sustained
    /// forward-loss case redundancy cannot cover: turns are being produced
    /// faster than the peer can receive them. Surfacing it is the buildable
    /// half; the resync it triggers (reconnect + replay-from-cursor) is gated
    /// on the open failover design (D11). Dropping further turns to keep the
    /// window bounded would desync lockstep, so the driver stops instead.
    #[error("unacked window exhausted: {in_flight} payloads in flight exceeds the {cap}-turn cap")]
    UnackedWindowExhausted { in_flight: usize, cap: usize },
}

impl LinkDriver {
    /// Wraps a connected [`Link`] in a driver, returning it with the game thread's
    /// [`TurnChannels`]. Uses [`TURN_CHANNEL_CAPACITY`] for each direction.
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
        };
        (driver, channels)
    }

    /// Runs the link until the game seam closes (a clean stop → `Ok`) or the link
    /// fails (→ [`DriverError`], the signal for the reconnect path to re-dial).
    ///
    /// Multiplexes over one task: receiving the client's peers' turns and handing
    /// them to the game, sending the turns the game produced, flushing ack-only
    /// packets during outbound silence, driving the ack-beacon side-channel that
    /// keeps the unacked window bounded under loss, sending the game's
    /// end-of-game result report the moment it arrives, and — once the game
    /// signals its own departure — announcing that leave to the relay after the
    /// outbound queue and unacked window have drained (and the result, if one was
    /// expected, has been sent).
    /// The beacon is two uni-streams — one each direction — and its read half runs
    /// in a dedicated task so a partial stream read is never dropped mid-frame
    /// inside a `select!` branch (which would desync the framing and hand a
    /// garbage `(slot, cursor)` to `retire_through`); the task forwards each
    /// complete `(slot, cursor)` over an mpsc channel, whose `recv` *is*
    /// cancel-safe.
    pub async fn run(self) -> Result<(), DriverError> {
        let Self {
            mut link,
            mut outbound,
            inbound,
            leaves,
            mut leave_intent,
            mut result,
            result_expected,
            mut lobby_out,
            lobby_in,
            mut chat_out,
            chat_in,
        } = self;

        // The ack-beacon side-channel. The client opens its outbound uni-stream
        // (open_uni completes locally, no peer round-trip); the peer's stream is
        // accepted lazily inside the reader task, so a one-way-traffic link that
        // never sends a beacon doesn't block the dial on an accept that never
        // completes. The reader decodes complete frames and forwards each
        // `(slot, cursor)` over an mpsc channel — cursors are per-slot, so they
        // don't subsume each other across slots and can't collapse to one latest.
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
        // Mirrors `beacon_alive`: once the reader task ends, its channel is an
        // always-ready `None` that would spin the loop, so the branch disarms.
        let mut control_alive = true;
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
        // The client's own outbound payload seq counter. Under the origin-identity
        // model the client assigns the seq for its own slot's turn stream — it alone
        // knows production order — and every hop honors it untouched. Monotonic from
        // 0, one counter since the client sends a single slot.
        let mut next_outbound_seq: u64 = 0;

        // Each peer slot carries its own monotonic seq space starting at 0, so
        // the per-slot reorder buffer restores game order independently per slot.
        // `next_seq[slot]` is the lowest seq not yet handed to the game for that
        // slot; `pending[slot]` holds turns that arrived ahead of it until the gaps
        // below them fill, so the game is handed a strictly in-order stream per slot
        // — the lockstep contract — rather than raw arrival order. The receive
        // window bounds how far ahead a seq can be, so each stays small.
        let mut next_seq: HashMap<SlotId, u64> = HashMap::new();
        let mut pending: HashMap<SlotId, BTreeMap<u64, Payload>> = HashMap::new();

        // Owns this client's clean-departure announcement: it stays dormant until
        // the game signals its own leave, then holds the `LeaveIntent` frame until
        // the outbound queue and unacked window have drained (and any expected
        // result has been sent) or a safety timeout fires, and classifies the
        // relay's subsequent link close as the expected confirmation rather than a
        // failure. It also latches whether the result report has been written, so
        // a second result payload is dropped.
        let mut announcer = LeaveAnnouncer::new(result_expected);
        // Mirrors `beacon_alive`/`control_alive`: the game signals at most once, so
        // this disarms on the channel's first resolution (the real signal, or the
        // sender dropping without one) rather than only on `None` — either way
        // there is nothing further to receive, and leaving the branch armed past
        // that would either spin on a closed channel or just poll a channel that
        // will never produce anything else.
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
                    match release_ready(&mut next_seq, &mut pending, &inbound) {
                        Release::Delivered => {}
                        Release::GameClosed => return Ok(()),
                        Release::GameStalled => return Err(DriverError::GameStalled),
                    }
                    flush_delivered_cursors(&link, &mut beacon_send, &mut last_beacon_sent, &next_seq)
                        .await;
                    if check_cap(link.payloads_in_flight()) {
                        return Err(DriverError::UnackedWindowExhausted {
                            in_flight: link.payloads_in_flight(),
                            cap: UNACKED_WINDOW_CAP,
                        });
                    }
                    // An ack folded into the manager above may be the last one
                    // a pending leave intent was waiting on.
                    announcer.maybe_send(&mut control_send, &outbound, &link).await?;
                }
                // An oversize turn from the relay, delivered over the reliable
                // control stream because no datagram could carry it. Folding it
                // through the link's dedup keeps the two delivery paths one
                // stream: the per-slot delivered cursor advances across it and
                // a copy that somehow arrived both ways collapses to one
                // delivery. It then joins the same per-slot reorder buffer, so
                // the game sees one ordered stream regardless of which path
                // each turn took.
                received = control_rx.recv(), if control_alive => {
                    match received {
                        // A relay-pushed synced leave: hand it to the game's leave
                        // tracker. This is the delivery path a drop needs — the turn
                        // stream has stalled, but the reliable control stream still
                        // flows. Dropping it (game gone) is a clean shutdown.
                        Some(ControlInbound::Leave(leave)) => {
                            if leaves.send(leave).await.is_err() {
                                return Ok(());
                            }
                        }
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
                        // A lobby command another member authored, relay-stamped
                        // with the author's slot. Hand it to the game tagged with
                        // that slot so it applies the bytes to that member's lobby
                        // turn. Replayed earlier commands and live ones arrive on
                        // this one path, in order. Dropping it (game gone) is a
                        // clean shutdown.
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
                            if lobby_in
                                .send((SlotId(slot_id), command.payload.to_vec()))
                                .await
                                .is_err()
                            {
                                return Ok(());
                            }
                        }
                        // An in-game chat message another member authored,
                        // relay-stamped with the author's slot — the mid-game
                        // counterpart to the lobby branch above. No replay here
                        // (chat keeps no log): every message that arrives on
                        // this path is live. Dropping it (game gone) is a clean
                        // shutdown.
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
                            if chat_in.send((SlotId(slot_id), out)).await.is_err() {
                                return Ok(());
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
                                match release_ready(&mut next_seq, &mut pending, &inbound) {
                                    Release::Delivered => {}
                                    Release::GameClosed => return Ok(()),
                                    Release::GameStalled => return Err(DriverError::GameStalled),
                                }
                                flush_delivered_cursors(
                                    &link,
                                    &mut beacon_send,
                                    &mut last_beacon_sent,
                                    &next_seq,
                                )
                                .await;
                            }
                        }
                        // The reader task ended (stream closed or a framing
                        // violation). Not itself fatal — the link may be fine
                        // and most sessions never see an oversize turn — but
                        // one that later needs the stream will stall, so it is
                        // worth a log line before the branch disarms.
                        None => {
                            tracing::info!("control stream reader ended");
                            control_alive = false;
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
                            // Assign this turn its origin seq — the client is the
                            // sole authority for its own slot's production order.
                            payload.seq = next_outbound_seq;
                            next_outbound_seq += 1;
                            if link.payload_fits(&payload)? {
                                let carried_redundancy = match send_packet(&mut link, Some(payload)) {
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
                            announcer.maybe_send(&mut control_send, &outbound, &link).await?;
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
                        announcer.maybe_send(&mut control_send, &outbound, &link).await?;
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
                                announcer.maybe_send(&mut control_send, &outbound, &link).await?;
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
                            announcer.maybe_send(&mut control_send, &outbound, &link).await?;
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
                        match send_packet(&mut link, None) {
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
/// [`DriverError::UnackedWindowExhausted`]; the resync it triggers is gated on
/// the open failover design (D11).
fn check_cap(in_flight: usize) -> bool {
    in_flight > UNACKED_WINDOW_CAP
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
    async fn an_inbound_turn_with_an_out_of_range_slot_is_dropped() {
        use prost::Message;
        use rally_point_proto::messages::Packet;

        // A payload whose slot id overflows `u8` names no real slot; a truncating
        // cast would alias it onto `slot % 256` and corrupt that player's turn
        // stream. The driver must drop it, handing the game nothing — this covers
        // both inbound paths' guard by exercising the datagram one.
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

        assert!(
            tokio::time::timeout(Duration::from_millis(300), inbound.recv())
                .await
                .is_err(),
            "an out-of-range inbound slot must not be delivered to the game"
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
}
