//! The game thread's half of the seam: the channel bundle a running driver
//! hands back, plus the chat message shape that rides one of those channels.
//! Kept beside the driver that owns the other end of every channel here.

use super::*;

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
    /// Signals that the game's loop has begun running — the match data is loaded
    /// and the simulation is stepping. A caller may signal without tracking
    /// whether it already did: the driver retains the fact for the session and
    /// writes one `GameStarted` control frame per connection, so a signal that
    /// raced a link drop (or arrived while the driver was re-dialing) still
    /// reaches the relay on the next one. Best-effort: a failed write is logged
    /// and retried on the next connection, and the driver keeps running
    /// regardless, since the frame only feeds the tenant's load attribution.
    /// Dropping this sender without ever signaling is harmless — nothing is sent
    /// and nothing waits on it.
    pub game_started: mpsc::Sender<()>,
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
    /// This game's own cosmetic-skin blob, to broadcast to the other members near
    /// game start. The driver wraps the bytes in a `PlayerSkin` and writes it up
    /// the reliable control stream at once — no drain to wait behind, unlike a
    /// turn — and the relay stamps the authoring slot, so the caller leaves that
    /// to the relay and just hands over the opaque bytes. Like
    /// [`chat_out`](Self::chat_out) a send failure is best-effort: the driver logs
    /// it and continues rather than surfacing a [`DriverError`], since a skin is
    /// cosmetic and non-synced — a lost blob costs only a wrong cosmetic.
    pub skin_out: mpsc::Sender<Vec<u8>>,
    /// Cosmetic-skin blobs other members authored, as the relay fanned them down
    /// the reliable control stream, each tagged with its authoring slot. Unlike
    /// [`chat_in`](Self::chat_in) the relay keeps a latest-blob-per-slot map and
    /// replays it when this client registers, so a member whose stream comes up
    /// late or that reconnects still receives every other member's current blob —
    /// which also means a blob can arrive more than once (a replay overlapping a
    /// live one across a reconnect), so the game applies each idempotently. The
    /// relay never echoes this client's own blob back (the game already has it).
    pub skin_in: mpsc::Receiver<(SlotId, Vec<u8>)>,
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
    /// slot has connected somewhere in the session's mesh. The driver forwards the
    /// directive's payload here each time the relay pushes a `SessionStart` down
    /// the reliable control stream; the game begins on the first and treats any
    /// repeat as a no-op (the relay may re-deliver on a late slot's register or an
    /// authority handoff). The payload is the session's computed initial
    /// latency-buffer depth: `Some(turns)` when the authoring relay sized one (the
    /// game applies it before the first frame), `None` when it sized none (an
    /// authority that predates the field, or a resumed re-home re-push), where the
    /// game keeps the depth it already seeded. The game applies a depth only from
    /// its single pre-start receive, so a re-delivery never resizes a running game.
    pub session_start: mpsc::Receiver<Option<u32>>,
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
    /// The session's relay → region labels, each entry pairing a relay id with
    /// the region that relay serves from. A game that knows which relay each
    /// member homes on can name that member's region from this — which is why the
    /// relay does not send it at dial: the labels place every member
    /// geographically, so a client holding them early could read its opponents'
    /// regions and abandon the match while it had barely begun. The relay withholds
    /// them until a stretch of real gameplay has elapsed on its own clock, and this
    /// channel simply stays silent until then. A game that ends sooner never
    /// receives them at all, which is the intended outcome. Nothing this client
    /// sends brings the release forward, so an embedder cannot ask for them early.
    ///
    /// Each message is the **complete** map as the relay currently knows it, so
    /// the game replaces whatever it held rather than merging. It can arrive more
    /// than once — the release fan-out, a direct push when this client connects
    /// after the release, a re-send when a re-home changes which relays serve the
    /// session — so the game applies each idempotently. Best-effort like
    /// [`connectivity`](Self::connectivity): a full buffer drops the map rather
    /// than stalling the turn stream, and a later map carries the whole thing
    /// again.
    pub region_labels: mpsc::Receiver<Vec<(u64, String)>>,
    /// The driver's current send-phase state: the wire-handoff delay it is
    /// applying to outbound turns under the relay's `PhaseDirective`s, and the
    /// target it is slewing toward. Purely informational — the driver applies
    /// directives on its own and the game cannot influence them from here —
    /// but a netstat-style overlay can read this to show that (and how far)
    /// the client's sends are currently being held. A watch channel rather
    /// than a queue: the newest state is the only interesting one, so the
    /// game samples `borrow()` whenever it redraws and never needs to drain.
    /// Both fields sit at zero until a directive first arrives (most sessions:
    /// phases already aligned within the relay's dead-band are never
    /// corrected).
    pub phase_status: watch::Receiver<PhaseStatus>,
}
