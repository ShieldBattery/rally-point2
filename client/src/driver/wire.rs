//! One connection's side-channels and the bookkeeping that lives and dies with
//! it: the beacon and control send halves, whether a flush or an ack is owed,
//! what this stream has already carried, and which seam arms are still armed.
//!
//! Everything here is per-connection — a reconnect throws it away and opens a
//! fresh one, which is exactly what separates it from [`LoopState`], the state
//! a resumed session must carry across. The link itself is deliberately *not*
//! in here: the session loop's `select!` borrows it (and the two reader
//! receivers below) directly, so they cannot sit behind a struct the arm
//! bodies also take by `&mut`.

use rally_point_transport::beacon::{BeaconCursors, BeaconWriter, spawn_beacon_reader};
use rally_point_transport::control::{ControlInbound, spawn_control_reader};
use rally_point_transport::{Link, LinkError, noq};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::reorder::SlotReorder;
use super::{DriverError, DriverTiming};

/// The receiving halves of this connection's two side-channels. Handed back
/// beside the [`Wire`] rather than stored in it because the session loop's
/// `select!` polls them directly.
pub(super) struct WireReaders {
    pub(super) beacon: BeaconCursors,
    pub(super) control: mpsc::Receiver<ControlInbound>,
}

/// The writing halves of this connection's side-channels, and the per-link
/// facts the session loop keeps beside them.
pub(super) struct Wire {
    /// The reliable control stream this client writes on — the divert path for
    /// a turn too large to ever ride a datagram, and the carrier for every
    /// frame the game authors.
    pub(super) control_send: noq::SendStream,
    /// The ack-beacon side-channel this client writes delivered-through
    /// cursors on.
    beacon_send: noq::SendStream,
    /// Pushes only advancing cursors and reuses one batch buffer for the life
    /// of this link.
    beacon_writer: BeaconWriter,
    /// Whether we've received from the relay since we last sent it a packet.
    /// Every packet we send folds in the latest acks, so any outgoing turn
    /// clears this too; the flush only needs to carry acks when no turn has.
    pub(super) acks_owed: bool,
    /// The next maintenance flush. Pushed out whenever an outbound turn
    /// re-carries unacked turns (recovery is riding the stream, so no flush is
    /// due); left to fire when a send carries no redundancy or the link is
    /// idle, so a turn the fresh packets can't re-carry is still retransmitted.
    pub(super) flush_deadline: Instant,
    /// Whether the game's "my loop is running" announcement has actually been
    /// written on THIS stream. Tracked separately from the retained fact in
    /// [`LoopState::game_started_announced`]: a relay fence probe answers the
    /// question "is anything this client owes still unwritten here", which a
    /// re-assertion whose write failed leaves as yes.
    pub(super) game_started_on_stream: bool,
    /// Whether the inbound beacon reader task is still feeding cursors. Once it
    /// ends (the peer's beacon uni-stream closed or errored), `recv()` returns
    /// `None` immediately on every poll — an always-ready future that would
    /// spin the loop at 100% CPU. Disabling the branch on the first `None`
    /// keeps the driver asleep; the real link failure surfaces separately via
    /// `link.recv()`.
    pub(super) beacon_alive: bool,
    /// Whether the leave-intent branch is still armed. The game signals at most
    /// once, so it disarms on the channel's first resolution (the real signal,
    /// or the sender dropping without one) rather than only on `None` — either
    /// way there is nothing further to receive, and leaving the branch armed
    /// past that would either spin on a closed channel or just poll a channel
    /// that will never produce anything else.
    pub(super) leave_intent_alive: bool,
    /// Mirrors [`leave_intent_alive`](Self::leave_intent_alive): the game
    /// announces its loop starting at most once, so the branch is disarmed on
    /// the channel's first resolution to keep an always-ready `None` from
    /// spinning the loop.
    pub(super) game_started_alive: bool,
    /// Mirrors [`leave_intent_alive`](Self::leave_intent_alive): the game hands
    /// over a result at most once, so this disarms on the channel's first
    /// resolution — the payload, or the sender dropping without one — rather
    /// than spinning on a closed channel.
    pub(super) result_alive: bool,
    /// Whether the game's lobby-command sender is still live. Unlike the
    /// single-shot channels above, lobby commands stream during setup, so this
    /// disarms only on the sender dropping (a `None`) — the game finished
    /// authoring lobby commands (the game started, or it left) — after which
    /// `recv()` is an always-ready `None` that would spin the loop.
    pub(super) lobby_out_alive: bool,
    /// Whether the game's chat sender is still live. Unlike lobby, chat streams
    /// for the whole game, not just pre-game setup, but the disarm rule is the
    /// same: only on the sender dropping (a `None`), after which `recv()` is an
    /// always-ready `None` that would spin the loop.
    pub(super) chat_out_alive: bool,
    /// Whether the game's skin sender is still live. Skin blobs flow near game
    /// start (and on the relay's reconnect replays), with the same disarm rule
    /// as chat: only on the sender dropping (a `None`), after which `recv()` is
    /// an always-ready `None` that would spin the loop.
    pub(super) skin_out_alive: bool,
    /// Whether the game's drop-request sender is still live. Like chat it
    /// streams for the whole game, with the same disarm rule: only on the
    /// sender dropping (a `None`), after which `recv()` is an always-ready
    /// `None` that would spin the loop.
    pub(super) request_drop_alive: bool,
    /// The recv half of our own control stream, unused by convention (the relay
    /// writes on the stream *it* opened) and held only so it stays open for the
    /// life of the connection.
    _our_control_recv: noq::RecvStream,
}

impl Wire {
    /// Opens this connection's beacon and control streams and spawns the two
    /// reader tasks, handing back the writing halves plus the receivers the
    /// session loop polls.
    ///
    /// The client opens its outbound beacon uni-stream (`open_uni` completes
    /// locally, no peer round-trip); the peer's stream is accepted lazily
    /// inside the reader task, so a one-way-traffic link that never sends a
    /// beacon doesn't block the dial on an accept that never completes. The
    /// reader decodes complete frames and folds each `(slot, cursor)` into a
    /// per-slot latest-value cell — a cursor is cumulative within its slot, so
    /// the newest is all the session loop needs, and the final cursor before
    /// traffic stops survives however slowly that loop drains (see
    /// [`BeaconCursors`]).
    ///
    /// The reliable control stream is the divert path for a turn too large to
    /// ever ride a datagram. Each side opens one bidirectional stream and
    /// writes on it alone; the peer reads the stream it accepted. Our send half
    /// exists from here on (`open_bi` completes locally); the relay's frames
    /// arrive via the reader task, which accepts lazily so a session that never
    /// sees an oversize turn parks it harmlessly.
    pub(super) async fn open(
        link: &Link,
        timing: DriverTiming,
    ) -> Result<(Self, WireReaders), DriverError> {
        let beacon_send = link
            .connection()
            .open_uni()
            .await
            .map_err(|error| DriverError::Link(LinkError::from(error)))?;
        let beacon = spawn_beacon_reader(link.connection().clone());

        let (control_send, our_control_recv) = link
            .connection()
            .open_bi()
            .await
            .map_err(|error| DriverError::Link(LinkError::from(error)))?;
        let control = spawn_control_reader(link.connection().clone());

        let wire = Self {
            control_send,
            beacon_send,
            beacon_writer: BeaconWriter::new(),
            acks_owed: false,
            flush_deadline: Instant::now() + timing.flush_interval,
            game_started_on_stream: false,
            beacon_alive: true,
            leave_intent_alive: true,
            game_started_alive: true,
            result_alive: true,
            lobby_out_alive: true,
            chat_out_alive: true,
            skin_out_alive: true,
            request_drop_alive: true,
            _our_control_recv: our_control_recv,
        };
        Ok((wire, WireReaders { beacon, control }))
    }

    /// Pushes each slot's delivered-through cursor to the peer so it can
    /// force-advance its unacked window past turns it now knows we received.
    /// [`BeaconWriter`] pushes only cursors that advanced past its last-sent
    /// state, so a static cursor (a genuine forward gap) sends nothing — the
    /// unacked-window cap handles that.
    pub(super) async fn flush_delivered_cursors(&mut self, link: &Link, reorder: &SlotReorder) {
        self.beacon_writer
            .flush(
                &mut self.beacon_send,
                reorder
                    .slots()
                    .filter_map(|slot| link.delivered_through(slot).map(|c| (slot, c))),
            )
            .await;
    }
}
