//! One transport link: a QUIC connection married to its [`AckManager`].
//!
//! A `Link` is the unit both the client and relay instantiate per connection
//! (client ↔ home relay, relay ↔ relay across the mesh). It drives the
//! redundancy/ack state over real QUIC datagrams: [`send`](Link::send) builds a
//! packet sized to the live datagram budget and puts it on the wire, and
//! [`recv`](Link::recv) decodes an incoming packet, folds its acks into the
//! manager, and returns the payloads not seen before.
//!
//! Dedup is the link's job. netcode v2 removes Storm's transport layer, which
//! used to drop the redundant copies; redundancy means the same payload arrives
//! in several packets, so [`recv`](Link::recv) returns each payload exactly once.
//! A payload's identity is `(slot, seq)` — its origin identity, assigned by the
//! sending client and preserved end-to-end — so dedup tracks the contiguous run
//! of delivered seqs *per slot* plus a bounded set of out-of-order ones above
//! it, so a fresh high seq never masks an older redundant one that simply hasn't
//! arrived yet. Each call returns a packet's new payloads in seq order, but
//! successive calls follow packet arrival, so the delivered stream isn't
//! globally ordered — true in-order reassembly (holding a seq until the gap below
//! it fills, as Storm did) is a layer above this.
//!
//! The link also exposes the two halves of the ack-beacon side-channel the
//! driver wires: [`delivered_through`](Link::delivered_through) is the per-slot
//! cursor the driver pushes to the peer over a reliable uni-stream, and
//! [`retire_through`](Link::retire_through) force-advances one slot's unacked
//! window when the peer's cursor arrives. The link owns no stream I/O — the
//! driver opens the streams and runs the cancel-safe read loop — but it does
//! guard `retire_through` monotonically (per slot) so a desynced cursor can't
//! retire turns the peer never confirmed.

use std::collections::{BTreeSet, HashMap};

use prost::Message;
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{Packet, Payload};

use crate::ack_manager::{AckError, AckManager};

/// How far ahead of the contiguous delivered prefix a peer's payload seq may be
/// before the link is treated as broken. The redundancy stream keeps that prefix
/// advancing, so legitimately reaching this bound means the low seqs have been
/// lost for a long run (minutes at the turn rate) — a dead link, not reorder. It
/// also bounds the out-of-order set to at most this many entries per slot.
const RECEIVE_WINDOW: u64 = 4096;

/// A single transport link over one QUIC connection.
pub struct Link {
    connection: quinn::Connection,
    acks: AckManager,
    dedup: Dedup,
}

/// A send or receive on a link failed.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// The peer never advertised QUIC datagram support, so this link can't carry
    /// turns at all — a configuration/peer mismatch, not a transient failure.
    #[error("peer does not support QUIC datagrams")]
    DatagramsUnsupported,
    /// The QUIC connection ended.
    #[error("QUIC connection lost: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// A datagram could not be queued for sending.
    #[error("sending datagram failed: {0}")]
    Send(#[from] quinn::SendDatagramError),
    /// A datagram did not fit the path's current budget, so it was refused. With the
    /// tiny turns of a lockstep game this should never happen; it is surfaced (rather
    /// than retried forever) so the caller fails fast — an undeliverable turn can't
    /// simply be dropped.
    #[error("datagram of {needed} bytes exceeds the {budget}-byte path budget")]
    PayloadTooLarge { needed: usize, budget: usize },
    /// A received datagram was not a well-formed packet.
    #[error("decoding incoming packet failed: {0}")]
    Decode(#[from] prost::DecodeError),
    /// A payload's seq was further ahead of our contiguous delivered prefix than
    /// the receive window allows — the peer is racing too far ahead (a dead link
    #[error("payload (slot {}, seq {seq}) is beyond the receive window", slot.0)]
    PayloadOutOfWindow { slot: SlotId, seq: u64 },
    /// A received packet's acks were internally inconsistent. Attacker-facing
    /// callers (the relay) typically drop the peer on this.
    #[error(transparent)]
    Ack(#[from] AckError),
}

impl Link {
    /// Wraps an established QUIC connection as a transport link.
    pub fn new(connection: quinn::Connection) -> Self {
        Self {
            connection,
            acks: AckManager::new(),
            dedup: Dedup::new(),
        }
    }

    /// The underlying QUIC connection.
    pub fn connection(&self) -> &quinn::Connection {
        &self.connection
    }

    /// Rebinds this link to a freshly dialed connection after the previous one
    /// failed, resuming the same session rather than starting a new one.
    ///
    /// The per-connection send/ack state resets (see
    /// [`AckManager::reset_connection`](crate::ack_manager::AckManager::reset_connection)),
    /// but the still-unacked payloads carry over so redundancy re-delivers any turn
    /// that was in flight when the link dropped. The receive-side dedup is preserved
    /// whole: its per-slot delivered prefix keeps anchoring the receive window — so
    /// the relay's post-reconnect replay of mid-game seqs is not rejected as beyond
    /// the window that a fresh dedup, starting from seq 0, would impose — and it
    /// dedups that replay against turns already delivered. Payload seqs are origin
    /// identities carried end-to-end, so the dedup keyed on them stays valid across
    /// the connection swap.
    pub fn rebind(&mut self, connection: quinn::Connection) {
        self.connection = connection;
        self.acks.reset_connection();
        // dedup preserved: it is what makes the reconnect a resume, not a restart.
    }

    /// Payloads sent but not yet known-delivered — the in-flight depth, and the
    /// overflow signal the driver watches under sustained loss.
    pub fn payloads_in_flight(&self) -> usize {
        self.acks.payloads_in_flight()
    }

    /// The top of the contiguous run of payloads this link has delivered to its
    /// consumer for `slot` (the highest seq such that every seq up to it has been
    /// delivered for that slot), or `None` before the first payload for that slot
    /// arrives. This is the per-slot cursor the beacon side-channel pushes to the
    /// peer so it can force-advance its unacked window past turns it now knows
    /// were received.
    pub fn delivered_through(&self, slot: SlotId) -> Option<u64> {
        self.dedup.delivered_through(slot)
    }

    /// Force-retires every unacked payload in `slot` up to `through_seq`,
    /// returning how many were dropped, *unless* `through_seq` is not strictly
    /// greater than the last cursor applied for that slot. A monotonic guard:
    /// the beacon stream is reliable-ordered, so cursors arrive in order, but a
    /// stream framing desync (partial read handed to the codec) could produce a
    /// garbage `u64` — retiring turns the peer never confirmed would desync
    /// lockstep silently. Rejecting anything not strictly advancing turns such a
    /// desync into a harmless no-op rather than a desync.
    ///
    /// For the guard to hold, the reader must assemble complete frames off a
    /// cancel-safe path (a dedicated read-loop task forwarding over a channel),
    /// never a `read_exact` dropped mid-frame inside a `select!`.
    pub fn retire_through(&mut self, slot: SlotId, through_seq: u64) -> usize {
        if self.dedup.advance_retired_through(slot, through_seq) {
            self.acks.retire_payloads_through(slot, through_seq)
        } else {
            0
        }
    }

    /// Whether `payload` can ever ride a datagram on this link's current path:
    /// a packet carrying it alone, under worst-case header state, fits the live
    /// `max_datagram_size()`. The caller's pre-check for the divert-to-stream
    /// path — a payload this returns `false` for must go over the reliable
    /// control stream, never into [`send`](Self::send) (which would refuse it
    /// anyway, but by then the caller has lost the payload to the move).
    pub fn payload_fits(&self, payload: &Payload) -> Result<bool, LinkError> {
        let budget = self
            .connection
            .max_datagram_size()
            .ok_or(LinkError::DatagramsUnsupported)?;
        Ok(crate::ack_manager::lone_packet_len(payload) <= budget)
    }

    /// Folds a payload that arrived *outside* the datagram path — the reliable
    /// control stream, where oversize turns ride — into this link's receive
    /// state: the same per-slot dedup and delivered-prefix bookkeeping a
    /// datagram delivery runs, with no ack-state change (QUIC's stream
    /// reliability already guarantees the delivery; there is nothing to ack or
    /// retire). Keeping the two paths on one `Dedup` is what lets the
    /// delivered-through cursor advance across a stream-delivered seq —
    /// otherwise the beacon would stall at the gap forever — and what makes a
    /// duplicate (a turn somehow sent both ways) collapse to one delivery.
    ///
    /// Returns whether the payload is new (`true`) or an already-delivered
    /// duplicate (`false`). A seq beyond the receive window is an error, as on
    /// the datagram path.
    pub fn deliver_external(&mut self, slot: SlotId, seq: u64) -> Result<bool, LinkError> {
        match self.dedup.accept(slot, seq) {
            Delivery::New => Ok(true),
            Delivery::Duplicate => Ok(false),
            Delivery::OutOfWindow => Err(LinkError::PayloadOutOfWindow { slot, seq }),
        }
    }

    /// Builds the next packet — `payload` plus redundant unacked ones, or
    /// ack-only when `payload` is `None` — sends it as one QUIC datagram, and
    /// returns how many still-unacked turns it re-carried as redundancy (the fresh
    /// turn, if any, is not counted).
    ///
    /// That count lets a caller tell whether retransmission is already riding the
    /// outbound stream (redundancy carried) or whether it must schedule a standalone
    /// flush — a near-MTU turn fills the datagram and re-carries nothing.
    ///
    /// The bundle is sized to the connection's live `max_datagram_size()`, so it
    /// tracks path-MTU changes. A datagram that does not fit the path is surfaced as
    /// [`PayloadTooLarge`](LinkError::PayloadTooLarge) — with the tiny turns of a
    /// lockstep game this should never happen, but it is reported (not retried
    /// forever) so the caller fails fast instead of silently stalling the stream.
    pub fn send(&mut self, payload: Option<Payload>) -> Result<usize, LinkError> {
        let budget = self
            .connection
            .max_datagram_size()
            .ok_or(LinkError::DatagramsUnsupported)?;
        let had_fresh = payload.is_some();

        // A payload that can never ride any datagram is refused *before* it is
        // registered as unacked. Registered, it would poison recovery: every
        // rebuilt bundle would try and fail to carry it, and its seq would hold
        // a permanent gap in the peer's delivered prefix. Refused here, the
        // caller diverts it (the reliable control stream) or fails fast. This
        // is distinct from a *bundle* that outgrew a shrunken path below —
        // that payload fit when checked, is registered, and its refusal is a
        // recoverable loss the next (smaller) bundle re-carries.
        if let Some(p) = &payload {
            let needed = crate::ack_manager::lone_packet_len(p);
            if needed > budget {
                return Err(LinkError::PayloadTooLarge { needed, budget });
            }
        }

        let packet = self.acks.build_outgoing(payload, budget);
        // Everything in the packet except the fresh turn is a redundant re-carry.
        let redundant = packet.payloads.len() - usize::from(had_fresh);
        let encoded = packet.encode_to_vec();
        let datagram_len = encoded.len();
        match self.connection.send_datagram(encoded.into()) {
            Ok(()) => Ok(redundant),
            Err(quinn::SendDatagramError::TooLarge) => Err(LinkError::PayloadTooLarge {
                needed: datagram_len,
                budget,
            }),
            Err(error) => Err(error.into()),
        }
    }

    /// Awaits the next datagram, folds its acks into the manager, and returns what
    /// it delivered: the payloads not seen before (redundant copies dropped, in
    /// ascending seq order within each slot) plus whether the packet carried any
    /// payloads at all.
    pub async fn recv(&mut self) -> Result<Received, LinkError> {
        let datagram = self.connection.read_datagram().await?;
        let packet = Packet::decode(datagram)?;
        self.process_incoming(packet)
    }

    /// Folds a decoded packet's acks into the manager and returns its delivery.
    /// Split out from [`recv`](Link::recv) so the dedup is exercised without a live
    /// connection.
    fn process_incoming(&mut self, mut packet: Packet) -> Result<Received, LinkError> {
        self.acks.handle_incoming(&packet)?;

        // Whether the peer is waiting on an ack for delivered turns: a packet that
        // carried payloads (even all-redundant ones) needs an ack back so the peer
        // can retire them, while an ack-only packet does not — acking it would only
        // provoke another ack-only packet in return, forever.
        let carried_payloads = !packet.payloads.is_empty();

        // Process payloads low-seq first within each slot. A packet leads with its
        // fresh (highest) seq per slot, so without this a deep-loss packet's high
        // seq could shut the window on the older redundant seqs it carries
        // alongside.
        packet.payloads.sort_by_key(|p| (p.slot, p.seq));

        let mut fresh = Vec::new();
        for payload in packet.payloads {
            let slot = SlotId(payload.slot as u8);
            match self.dedup.accept(slot, payload.seq) {
                Delivery::New => fresh.push(payload),
                Delivery::Duplicate => {}
                Delivery::OutOfWindow => {
                    return Err(LinkError::PayloadOutOfWindow {
                        slot,
                        seq: payload.seq,
                    });
                }
            }
        }
        Ok(Received {
            fresh,
            carried_payloads,
        })
    }
}

/// What one [`recv`](Link::recv) delivered.
#[derive(Debug)]
pub struct Received {
    /// Payloads delivered for the first time, ascending by `(slot, seq)`;
    /// redundant copies of already-delivered payloads are dropped.
    pub fresh: Vec<Payload>,
    /// Whether the packet carried any payload elements (new or redundant). An
    /// ack-only packet carried none, and the peer is not waiting for it to be acked —
    /// so the receiver must not schedule an ack in return, or two idle links would
    /// ack each other's acks forever.
    pub carried_payloads: bool,
}

/// The outcome of offering a received payload `(slot, seq)` to the dedup state.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Delivery {
    /// First time this `(slot, seq)` has been delivered — hand it to the caller.
    New,
    /// Already delivered (at/below the contiguous prefix, or seen out of order).
    Duplicate,
    /// Beyond the receive window — the peer is racing too far ahead.
    OutOfWindow,
}

/// Receive-side payload dedup, per slot.
///
/// Each slot has its own contiguous delivered prefix (`delivered_through`) plus
/// an `ahead` set of delivered seqs above it waiting for the gaps below to fill,
/// because each slot carries its own monotonic seq space starting at 0 — a
/// single global cursor would conflate one slot's progress with another's. A seq
/// is a duplicate only if it's within that slot's known-delivered state — never
/// merely because a higher seq arrived first — so a redundant low seq is never
/// mistaken for one that aged out.
///
/// Shared by the client-edge [`Link`] and the mesh `MeshLink`: both own one
/// instance per connection and feed it received payloads, so `(slot, seq)` is
/// unambiguous within an instance. The client edge has one game per connection
/// by nature; the mesh shares one connection across sessions but gives each its
/// own instance, so the session never enters the key.
pub(crate) struct Dedup {
    /// Per-slot dedup state.
    slots: HashMap<SlotId, SlotDedup>,
    /// The highest per-slot cursor force-retired via [`Link::retire_through`], so
    /// a desynced or replayed cursor can't retire turns the peer never confirmed.
    /// Inbound cursors are applied only when strictly greater than this; anything
    /// else is a no-op. Without it, a stream framing desync handing a garbage
    /// `u64` to `retire_through` could retire turns the peer never received —
    /// silent lockstep desync, worse than a crash.
    retired_through: HashMap<SlotId, u64>,
    /// How far above the prefix a seq may sit before it's rejected.
    window: u64,
}

/// One slot's receive-side dedup state.
struct SlotDedup {
    /// Top of the contiguous delivered prefix; `None` until seq 0 is delivered.
    delivered_through: Option<u64>,
    /// Delivered seqs above the prefix, kept until the gaps below them fill.
    ahead: BTreeSet<u64>,
}

impl Dedup {
    pub(crate) fn new() -> Self {
        Self::with_window(RECEIVE_WINDOW)
    }

    pub(crate) fn with_window(window: u64) -> Self {
        Self {
            slots: HashMap::new(),
            retired_through: HashMap::new(),
            window,
        }
    }

    /// The top of the contiguous delivered prefix for `slot`, or `None` before
    /// the slot's first payload arrives.
    pub(crate) fn delivered_through(&self, slot: SlotId) -> Option<u64> {
        self.slots.get(&slot).and_then(|s| s.delivered_through)
    }

    /// Records `(slot, seq)` as delivered and reports whether it's new, a
    /// duplicate, or out of the receive window.
    pub(crate) fn accept(&mut self, slot: SlotId, seq: u64) -> Delivery {
        let state = self.slots.entry(slot).or_insert_with(|| SlotDedup {
            delivered_through: None,
            ahead: BTreeSet::new(),
        });

        // The lowest seq not yet part of the contiguous delivered prefix.
        let base = state.delivered_through.map_or(0, |t| t + 1);

        if seq < base {
            return Delivery::Duplicate;
        }
        if seq - base >= self.window {
            return Delivery::OutOfWindow;
        }
        if !state.ahead.insert(seq) {
            return Delivery::Duplicate;
        }

        // Absorb any now-contiguous run into the delivered prefix.
        let mut next = base;
        while state.ahead.remove(&next) {
            state.delivered_through = Some(next);
            next += 1;
        }
        Delivery::New
    }

    /// Advances the per-slot retired-through guard, returning whether the cursor
    /// was strictly greater than the last one applied for `slot` (so the caller
    /// should retire). A cursor not strictly advancing is a no-op.
    pub(crate) fn advance_retired_through(&mut self, slot: SlotId, through_seq: u64) -> bool {
        if matches!(self.retired_through.get(&slot), Some(prev) if *prev >= through_seq) {
            false
        } else {
            self.retired_through.insert(slot, through_seq);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use super::*;
    use crate::quic::{client_config, server_config};

    #[test]
    fn dedup_returns_each_seq_once_per_slot() {
        let mut dedup = Dedup::with_window(8);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::Duplicate);
        assert_eq!(dedup.accept(SlotId(0), 1), Delivery::New);
        assert_eq!(dedup.accept(SlotId(0), 1), Delivery::Duplicate);
    }

    #[test]
    fn dedup_keeps_slots_independent() {
        // Two slots both have seq 0; both are new — the identity is (slot, seq).
        let mut dedup = Dedup::with_window(8);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New);
        assert_eq!(dedup.accept(SlotId(1), 0), Delivery::New);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::Duplicate);
        assert_eq!(dedup.accept(SlotId(1), 0), Delivery::Duplicate);
    }

    #[test]
    fn dedup_handles_out_of_order_within_window() {
        let mut dedup = Dedup::with_window(8);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New);
        assert_eq!(dedup.accept(SlotId(0), 3), Delivery::New); // gap at 1, 2
        assert_eq!(dedup.accept(SlotId(0), 3), Delivery::Duplicate);
        assert_eq!(dedup.accept(SlotId(0), 1), Delivery::New);
        assert_eq!(dedup.accept(SlotId(0), 2), Delivery::New); // closes the gap; 3 folds in
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::Duplicate); // below the prefix now
    }

    #[test]
    fn dedup_does_not_drop_a_low_seq_after_a_high_one() {
        // The regression: a high seq arriving first must not push an older, not
        // yet delivered seq out as "too old". Both are new deliveries.
        let mut dedup = Dedup::with_window(8);
        assert_eq!(dedup.accept(SlotId(0), 7), Delivery::New);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New);
    }

    #[test]
    fn dedup_rejects_seq_beyond_window() {
        let mut dedup = Dedup::with_window(8);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New); // prefix top = 0, base = 1
        assert_eq!(dedup.accept(SlotId(0), 9), Delivery::OutOfWindow); // 9 - 1 >= 8
        assert_eq!(dedup.accept(SlotId(0), 8), Delivery::New); // 8 - 1 < 8, still in window
    }

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

    fn turn(slot: u8, seq: u64, byte: u8) -> Payload {
        Payload {
            seq,
            slot: u32::from(slot),
            commands: vec![byte].into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn delivers_each_payload_once_and_retires_on_ack() {
        let (mut client, mut server, _client_ep, _server_ep) = connected_links().await;

        for i in 0..5u8 {
            client.send(Some(turn(0, i as u64, i))).unwrap();
        }
        assert_eq!(client.payloads_in_flight(), 5);

        // Each packet re-carries earlier unacked payloads, but every payload is
        // returned exactly once, in order, with its bytes intact.
        let mut delivered = Vec::new();
        while delivered.len() < 5 {
            delivered.extend(server.recv().await.unwrap().fresh);
        }
        let seqs: Vec<u64> = delivered.iter().map(|p| p.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4]);
        let bytes: Vec<u8> = delivered.iter().map(|p| p.commands[0]).collect();
        assert_eq!(bytes, vec![0, 1, 2, 3, 4]);

        // The server's ack-only reply retires everything the client had in flight.
        server.send(None).unwrap();
        client.recv().await.unwrap();
        assert_eq!(client.payloads_in_flight(), 0);
    }

    #[tokio::test]
    async fn preserves_game_frame_count_across_send_and_recv() {
        // The frame is a consensus annotation, not a transport key: the link
        // dedups and retires by (slot, seq) and must carry the frame through
        // verbatim so the relay and decision-maker can key on it. A None (lobby
        // turn) survives too — absent is a valid state, not zero.
        let (mut client, mut server, _client_ep, _server_ep) = connected_links().await;

        client
            .send(Some(Payload {
                seq: 0,
                slot: 0,
                game_frame_count: Some(1337),
                commands: vec![0x05].into(),
                ..Default::default()
            }))
            .unwrap();
        client
            .send(Some(Payload {
                seq: 1,
                slot: 0,
                commands: vec![0x05].into(),
                ..Default::default()
            }))
            .unwrap();

        let mut delivered = Vec::new();
        while delivered.len() < 2 {
            delivered.extend(server.recv().await.unwrap().fresh);
        }
        delivered.sort_by_key(|p| p.seq);
        assert_eq!(delivered[0].game_frame_count, Some(1337));
        assert_eq!(delivered[1].game_frame_count, None);
    }

    #[tokio::test]
    async fn preserves_buffer_directive_across_send_and_recv() {
        // A relay-authored buffer change rides the Payload envelope, so the link
        // must carry it through verbatim like any other payload field — it is not
        // a transport key (dedup and retirement stay on (slot, seq)), just metadata
        // the game applies out of band. Absent is the common case and survives too.
        use rally_point_proto::messages::BufferDirective;
        let (mut client, mut server, _client_ep, _server_ep) = connected_links().await;

        client
            .send(Some(Payload {
                seq: 0,
                slot: 0,
                game_frame_count: Some(500),
                buffer_directive: Some(BufferDirective {
                    buffer_turns: 6,
                    apply_at_frame: 512,
                    decision_seq: 3,
                }),
                commands: vec![0x0C].into(),
            }))
            .unwrap();
        client
            .send(Some(Payload {
                seq: 1,
                slot: 0,
                game_frame_count: Some(501),
                commands: vec![0x0C].into(),
                ..Default::default()
            }))
            .unwrap();

        let mut delivered = Vec::new();
        while delivered.len() < 2 {
            delivered.extend(server.recv().await.unwrap().fresh);
        }
        delivered.sort_by_key(|p| p.seq);
        assert_eq!(
            delivered[0].buffer_directive,
            Some(BufferDirective {
                buffer_turns: 6,
                apply_at_frame: 512,
                decision_seq: 3,
            }),
        );
        assert_eq!(delivered[1].buffer_directive, None);
    }

    #[tokio::test]
    async fn delivers_each_slot_independently() {
        // Two slots' turns interleave on the wire; each is dedup'd by (slot, seq).
        let (mut client, mut server, _client_ep, _server_ep) = connected_links().await;

        client.send(Some(turn(0, 0, 0xA0))).unwrap();
        client.send(Some(turn(1, 0, 0xB0))).unwrap();
        client.send(Some(turn(0, 1, 0xA1))).unwrap();
        client.send(Some(turn(1, 1, 0xB1))).unwrap();

        let mut delivered = Vec::new();
        while delivered.len() < 4 {
            delivered.extend(server.recv().await.unwrap().fresh);
        }

        // Slot 0's turns and slot 1's turns each arrive in their own seq order;
        // the two streams are independent.
        let slot0: Vec<u8> = delivered
            .iter()
            .filter(|p| p.slot == 0)
            .map(|p| p.commands[0])
            .collect();
        let slot1: Vec<u8> = delivered
            .iter()
            .filter(|p| p.slot == 1)
            .map(|p| p.commands[0])
            .collect();
        assert_eq!(slot0, vec![0xA0, 0xA1]);
        assert_eq!(slot1, vec![0xB0, 0xB1]);
    }

    #[tokio::test]
    async fn delivers_a_redundant_low_seq_carried_after_a_high_fresh_one() {
        let (client, mut server, _client_ep, _server_ep) = connected_links().await;

        // A deep-loss packet leads with a high fresh seq and re-carries an older
        // unacked one. Both must be delivered — the low seq is not dropped.
        let packet = Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: vec![
                Payload {
                    seq: RECEIVE_WINDOW,
                    slot: 0,
                    commands: vec![0xAA].into(),
                    ..Default::default()
                },
                Payload {
                    seq: 0,
                    slot: 0,
                    commands: vec![0xBB].into(),
                    ..Default::default()
                },
            ],
        };
        client
            .connection()
            .send_datagram(packet.encode_to_vec().into())
            .unwrap();

        let delivered = server.recv().await.unwrap().fresh;
        let seqs: Vec<u64> = delivered.iter().map(|p| p.seq).collect();
        assert_eq!(seqs, vec![0, RECEIVE_WINDOW]);
    }

    #[tokio::test]
    async fn rejects_payload_seq_beyond_the_window() {
        let (client, mut server, _client_ep, _server_ep) = connected_links().await;

        // A seq racing far past our contiguous progress must be rejected, not
        // panic the receiver.
        let malformed = Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: vec![Payload {
                seq: u64::MAX,
                slot: 0,
                commands: vec![1].into(),
                ..Default::default()
            }],
        };
        client
            .connection()
            .send_datagram(malformed.encode_to_vec().into())
            .unwrap();

        match server.recv().await {
            Err(LinkError::PayloadOutOfWindow { slot, seq }) => {
                assert_eq!(slot, SlotId(0));
                assert_eq!(seq, u64::MAX);
            }
            other => panic!("expected PayloadOutOfWindow, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn surfaces_a_turn_too_large_for_a_datagram() {
        let (mut client, _server, _client_ep, _server_ep) = connected_links().await;

        let budget = client
            .connection()
            .max_datagram_size()
            .expect("loopback supports datagrams");

        // A turn whose own bytes dwarf the datagram budget can ride no datagram, so
        // send surfaces it as an error rather than silently stalling. With the tiny
        // turns of a lockstep game this never happens.
        let oversize = Payload {
            seq: 0,
            slot: 0,
            commands: vec![0u8; budget + 1].into(),
            ..Default::default()
        };
        match client.send(Some(oversize)) {
            Err(LinkError::PayloadTooLarge {
                needed,
                budget: reported,
            }) => {
                assert_eq!(reported, budget);
                assert!(needed > budget);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }
}
