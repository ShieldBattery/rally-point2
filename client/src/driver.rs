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
//! surfaces a turn too large to fit a datagram as a hard error (the tiny turns of a
//! lockstep game never produce one, but it is not silently dropped); and flushes
//! acks for a quiet or one-way link so the peer still retires what it has sent.
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

use std::collections::BTreeMap;
use std::time::Duration;

use rally_point_proto::messages::Payload;
use rally_point_transport::beacon::{flush_beacon, spawn_beacon_reader};
use rally_point_transport::{Link, LinkError};
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
    /// A turn did not fit a datagram, so it can be delivered in no packet. With the
    /// tiny turns of a lockstep game this should never happen; the driver surfaces it
    /// (rather than silently stalling the stream) and stops, since dropping the turn
    /// would desync lockstep. An oversize turn ultimately belongs on the reliable
    /// control stream (not built yet).
    #[error("turn of {needed} bytes exceeds the {budget}-byte datagram budget")]
    TurnTooLarge { needed: usize, budget: usize },
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
    /// `select!` branch (which would desync the framing and hand a garbage cursor
    /// to `retire_through`); the task forwards each complete cursor over a
    /// `watch` channel, whose `recv` *is* cancel-safe.
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
        // completes. The reader decodes complete 8-byte frames and forwards the
        // latest cursor over a watch channel — non-blocking, so the reader never
        // stalls on a full channel, and the driver drains it in one
        // `borrow_and_update` since monotonic cursors subsume their predecessors.
        let mut beacon_send = link
            .connection()
            .open_uni()
            .await
            .map_err(|error| DriverError::Link(LinkError::from(error)))?;
        let mut beacon_rx = spawn_beacon_reader(link.connection().clone());
        // The highest cursor the client has pushed to the peer. Push only on
        // advance so a healthy link with a static receive prefix sends nothing.
        let mut last_beacon_sent: Option<u64> = None;
        // Whether the inbound beacon reader task is still feeding cursors. Once it
        // ends (the peer's beacon uni-stream closed or errored), `changed()` returns
        // `Err` immediately on every poll — an always-ready future that would spin
        // the loop at 100% CPU. Disabling this branch on the first `Err` keeps the
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

        // The relay assigns a gapless transport seq to every forwarded turn, but the
        // datagrams carrying them can arrive out of order. `pending` holds turns that
        // arrived ahead of `next_seq` until the gaps below them fill, so the game is
        // handed a strictly in-order stream — the lockstep contract — rather than raw
        // arrival order. The receive window bounds how far ahead a seq can be, so this
        // stays small.
        let mut next_seq: u64 = 0;
        let mut pending: BTreeMap<u64, Payload> = BTreeMap::new();

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
                        if payload.seq >= next_seq {
                            pending.insert(payload.seq, payload);
                        }
                    }
                    // Release the contiguous run starting at `next_seq`, holding the
                    // rest. Hand off without ever awaiting: blocking on a full channel
                    // would park the whole driver — no acks, no outbound turns, no
                    // link-failure detection — behind a stalled consumer.
                    while let Some(payload) = pending.remove(&next_seq) {
                        match inbound.try_send(payload) {
                            Ok(()) => next_seq += 1,
                            // The game stopped draining and the buffer filled: it is
                            // hopelessly behind. Keep the turn and surface the stall
                            // rather than block on it.
                            Err(mpsc::error::TrySendError::Full(payload)) => {
                                pending.insert(next_seq, payload);
                                return Err(DriverError::GameStalled);
                            }
                            // The game dropped its receiver: a clean stop.
                            Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
                        }
                    }
                    // Push the advanced delivered-through cursor to the peer so it can
                    // force-advance its unacked window past turns it now knows we
                    // received. Push only on advance; a static cursor (genuine forward
                    // gap) sends nothing — the cap handles that.
                    flush_beacon(&mut beacon_send, &mut last_beacon_sent, link.delivered_through()).await;
                    if check_cap(link.payloads_in_flight()) {
                        return Err(DriverError::UnackedWindowExhausted {
                            in_flight: link.payloads_in_flight(),
                            cap: UNACKED_WINDOW_CAP,
                        });
                    }
                }
                outgoing = outbound.recv() => {
                    match outgoing {
                        // A turn the game produced. It goes out carrying our acks; if it
                        // also re-carried unacked turns, recovery is riding the stream,
                        // so push the flush out. If it carried none (a near-MTU turn that
                        // filled the datagram), leave the timer so the flush retransmits.
                        Some(payload) => {
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
                        }
                        // The game dropped its sender: a clean stop.
                        None => return Ok(()),
                    }
                }
                // The peer pushed a delivered-through cursor over the beacon stream.
                // The reader task already assembled the complete frame off a
                // cancel-safe path, so receiving here can never be a partial read.
                // `watch::Receiver::changed` is cancel-safe in select!. The
                // `if beacon_alive` precondition disables this branch once the reader
                // task ends — otherwise `changed()` returns `Err` on every poll, an
                // always-ready future that would spin the loop at 100% CPU (the
                // connection may still be up, so `link.recv()` wouldn't surface it).
                result = beacon_rx.changed(), if beacon_alive => {
                    match result {
                        Ok(()) => {
                            // `borrow_and_update` fetches the latest cursor and marks
                            // it seen, so a burst of cursors collapses to one retire.
                            if let Some(cursor) = *beacon_rx.borrow_and_update() {
                                link.retire_through(cursor);
                            }
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
                        Err(_) => beacon_alive = false,
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
/// A turn too large to fit a datagram (which the tiny turns of a lockstep game never
/// produce) and a genuine link failure are both returned as a [`DriverError`].
fn send_packet(link: &mut Link, payload: Option<Payload>) -> Result<bool, DriverError> {
    match link.send(payload) {
        Ok(redundant) => Ok(redundant > 0),
        // A turn too big for a datagram. It can't be dropped silently (that desyncs
        // lockstep), so surface it and stop rather than retry it forever.
        Err(LinkError::PayloadTooLarge { needed, budget }) => {
            Err(DriverError::TurnTooLarge { needed, budget })
        }
        Err(error) => Err(error.into()),
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

    fn turn(bytes: &[u8]) -> Payload {
        Payload {
            seq: 0,  // assigned by the sending link
            slot: 0, // rebound by the relay; irrelevant on a bare link
            commands: bytes.to_vec().into(),
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
            chan_a.outbound.send(turn(&[i])).await.unwrap();
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
    async fn an_over_mtu_turn_fails_fast_instead_of_dropping_silently() {
        let (link_a, _link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        // A turn far larger than any datagram can never be delivered. The driver
        // must surface that as a hard error rather than silently drop it from the
        // lockstep stream — or treat it as a loss it could never actually recover.
        chan_a.outbound.send(turn(&[0u8; 4096])).await.unwrap();

        match tokio::time::timeout(Duration::from_secs(5), task).await {
            Ok(joined) => assert!(matches!(
                joined.unwrap(),
                Err(DriverError::TurnTooLarge { .. })
            )),
            Err(_) => panic!("driver hung on an oversize turn instead of failing fast"),
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
    async fn retransmits_an_unacked_turn_during_outbound_silence() {
        let (link_a, mut link_b, _ea, _eb) = connected_links().await;
        let (driver_a, chan_a) = LinkDriver::new(link_a);
        let task = tokio::spawn(driver_a.run());

        // One turn, then silence: the game produces nothing more and the peer never
        // acks. The driver still has it in flight.
        chan_a.outbound.send(turn(&[0x42])).await.unwrap();

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
        let big = move || turn(&vec![0x7u8; budget * 3 / 4]);

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
        chan_a.outbound.send(turn(&[0x55])).await.unwrap();
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
            link_b.send(Some(turn(&[i]))).unwrap();
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
                // Push the new cursor to the driver.
                if let Some(cursor) = link_b.delivered_through()
                    && !matches!(last_pushed, Some(p) if p >= cursor)
                {
                    let frame = beacon::encode_frame(cursor);
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
                    if outbound.send(turn(&[(i & 0xFF) as u8])).await.is_err() {
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
                    if outbound.send(turn(&[(i & 0xFF) as u8])).await.is_err() {
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
