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
use std::time::Duration;

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::Payload;
use rally_point_transport::beacon::{flush_beacon, spawn_beacon_reader};
use rally_point_transport::control::{ControlSendError, send_control_turn, spawn_control_reader};
use rally_point_transport::{Link, LinkError, quinn};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};

/// Default depth of each turn channel between the game thread and the driver.
/// Turns are small and drained every tick, so this is a generous backstop against
/// a brief scheduling hiccup rather than a tuned buffer; a real backpressure model
/// is future work.
const TURN_CHANNEL_CAPACITY: usize = 1024;

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
        let driver = Self {
            link,
            outbound: outbound_rx,
            inbound: inbound_tx,
        };
        let channels = TurnChannels {
            outbound: outbound_tx,
            inbound: inbound_rx,
        };
        (driver, channels)
    }

    /// Runs the link until the game seam closes (a clean stop → `Ok`) or the link
    /// fails (→ [`DriverError`], the signal for the reconnect path to re-dial).
    ///
    /// Multiplexes four things over one task: receiving the client's peers' turns
    /// and handing them to the game, sending the turns the game produced, flushing
    /// ack-only packets during outbound silence, and driving the ack-beacon
    /// side-channel that keeps the unacked window bounded under loss. The beacon
    /// is two uni-streams — one each direction — and its read half runs in a
    /// dedicated task so a partial stream read is never dropped mid-frame inside a
    /// `select!` branch (which would desync the framing and hand a garbage
    /// `(slot, cursor)` to `retire_through`); the task forwards each complete
    /// `(slot, cursor)` over an mpsc channel, whose `recv` *is* cancel-safe.
    pub async fn run(self) -> Result<(), DriverError> {
        let Self {
            mut link,
            mut outbound,
            inbound,
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

        loop {
            tokio::select! {
                received = link.recv() => {
                    let received = received?;
                    // Only a payload-bearing packet needs an ack in return; owing one
                    // for the relay's ack-only flush would just bounce ack-only packets
                    // back and forth on an otherwise idle link.
                    if received.carried_payloads {
                        acks_owed = true;
                    }
                    for payload in received.fresh {
                        let slot = SlotId(payload.slot as u8);
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
                        Some(payload) => {
                            let slot = SlotId(payload.slot as u8);
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
                                let carried_redundancy = send_packet(&mut link, Some(payload))?;
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
                                // ack retires it. A write failure is fatal
                                // (`?`): unlike a lost datagram, nothing
                                // re-carries this turn, and dropping it would
                                // desync lockstep.
                                send_control_turn(&mut control_send, payload).await?;
                            }
                        }
                        // The game dropped its sender: a clean stop.
                        None => return Ok(()),
                    }
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
                        send_packet(&mut link, None)?;
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
        // driver that rebuilt payloads and dropped it would silently break
        // buffer changes for this client.
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
}
