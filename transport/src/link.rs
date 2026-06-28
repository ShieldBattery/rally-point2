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
//! It tracks the contiguous run of delivered seqs plus a bounded set of
//! out-of-order ones above it, so a fresh high seq never masks an older
//! redundant one that simply hasn't arrived yet. Each call returns a packet's
//! new payloads in seq order, but successive calls follow packet arrival, so the
//! delivered stream isn't globally ordered — true in-order reassembly (holding a
//! seq until the gap below it fills, as Storm did) is a layer above this.

use std::collections::BTreeSet;

use prost::Message;
use rally_point_proto::messages::{Packet, Payload};

use crate::ack_manager::{AckError, AckManager};

/// How far ahead of the contiguous delivered prefix a peer's payload seq may be
/// before the link is treated as broken. The redundancy stream keeps that prefix
/// advancing, so legitimately reaching this bound means the low seqs have been
/// lost for a long run (minutes at the turn rate) — a dead link, not reorder. It
/// also bounds the out-of-order set to at most this many entries.
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
    /// or a malicious one). The caller should drop it.
    #[error("payload seq {seq} is beyond the receive window")]
    PayloadOutOfWindow { seq: u64 },
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

    /// Payloads sent but not yet known-delivered — the in-flight depth, and the
    /// overflow signal the driver watches under sustained loss.
    pub fn payloads_in_flight(&self) -> usize {
        self.acks.payloads_in_flight()
    }

    /// Retires every unacked payload up to `through_seq`, returning how many were
    /// dropped. For use when a reliable side-channel has confirmed cumulative
    /// delivery and the unacked window needs force-advancing.
    pub fn retire_through(&mut self, through_seq: u64) -> usize {
        self.acks.retire_payloads_through(through_seq)
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
    /// ascending seq order) plus whether the packet carried any payloads at all.
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

        // Process payloads low-seq first. A packet leads with its fresh (highest)
        // seq, so without this a deep-loss packet's high seq could shut the window
        // on the older redundant seqs it carries alongside.
        packet.payloads.sort_by_key(|p| p.seq);

        let mut fresh = Vec::new();
        for payload in packet.payloads {
            match self.dedup.accept(payload.seq) {
                Delivery::New => fresh.push(payload),
                Delivery::Duplicate => {}
                Delivery::OutOfWindow => {
                    return Err(LinkError::PayloadOutOfWindow { seq: payload.seq });
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
    /// Payloads delivered for the first time, ascending by seq; redundant copies of
    /// already-delivered payloads are dropped.
    pub fresh: Vec<Payload>,
    /// Whether the packet carried any payload elements (new or redundant). An
    /// ack-only packet carried none, and the peer is not waiting for it to be acked —
    /// so the receiver must not schedule an ack in return, or two idle links would
    /// ack each other's acks forever.
    pub carried_payloads: bool,
}

/// The outcome of offering a received payload seq to the dedup state.
#[derive(Debug, PartialEq, Eq)]
enum Delivery {
    /// First time this seq has been delivered — hand it to the caller.
    New,
    /// Already delivered (at/below the contiguous prefix, or seen out of order).
    Duplicate,
    /// Beyond the receive window — the peer is racing too far ahead.
    OutOfWindow,
}

/// Receive-side payload dedup.
///
/// Tracks `delivered_through`, the top of the contiguous run of delivered seqs,
/// plus `ahead`, the delivered seqs above it that are waiting for the gaps below
/// them to fill. A seq is a duplicate only if it's within that known-delivered
/// state — never merely because a higher seq arrived first — so a redundant low
/// seq is never mistaken for one that aged out.
struct Dedup {
    /// Top of the contiguous delivered prefix; `None` until seq 0 is delivered.
    delivered_through: Option<u64>,
    /// Delivered seqs above the prefix, kept until the gaps below them fill.
    ahead: BTreeSet<u64>,
    /// How far above the prefix a seq may sit before it's rejected.
    window: u64,
}

impl Dedup {
    fn new() -> Self {
        Self::with_window(RECEIVE_WINDOW)
    }

    fn with_window(window: u64) -> Self {
        Self {
            delivered_through: None,
            ahead: BTreeSet::new(),
            window,
        }
    }

    /// Records `seq` as delivered and reports whether it's new, a duplicate, or
    /// out of the receive window.
    fn accept(&mut self, seq: u64) -> Delivery {
        // The lowest seq not yet part of the contiguous delivered prefix.
        let base = self.delivered_through.map_or(0, |t| t + 1);

        if seq < base {
            return Delivery::Duplicate;
        }
        if seq - base >= self.window {
            return Delivery::OutOfWindow;
        }
        if !self.ahead.insert(seq) {
            return Delivery::Duplicate;
        }

        // Absorb any now-contiguous run into the delivered prefix.
        let mut next = base;
        while self.ahead.remove(&next) {
            self.delivered_through = Some(next);
            next += 1;
        }
        Delivery::New
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use super::*;
    use crate::quic::{client_config, server_config};

    #[test]
    fn dedup_returns_each_seq_once() {
        let mut dedup = Dedup::with_window(8);
        assert_eq!(dedup.accept(0), Delivery::New);
        assert_eq!(dedup.accept(0), Delivery::Duplicate);
        assert_eq!(dedup.accept(1), Delivery::New);
        assert_eq!(dedup.accept(1), Delivery::Duplicate);
    }

    #[test]
    fn dedup_handles_out_of_order_within_window() {
        let mut dedup = Dedup::with_window(8);
        assert_eq!(dedup.accept(0), Delivery::New);
        assert_eq!(dedup.accept(3), Delivery::New); // gap at 1, 2
        assert_eq!(dedup.accept(3), Delivery::Duplicate);
        assert_eq!(dedup.accept(1), Delivery::New);
        assert_eq!(dedup.accept(2), Delivery::New); // closes the gap; 3 folds in
        assert_eq!(dedup.accept(0), Delivery::Duplicate); // below the prefix now
    }

    #[test]
    fn dedup_does_not_drop_a_low_seq_after_a_high_one() {
        // The regression: a high seq arriving first must not push an older, not
        // yet delivered seq out as "too old". Both are new deliveries.
        let mut dedup = Dedup::with_window(8);
        assert_eq!(dedup.accept(7), Delivery::New);
        assert_eq!(dedup.accept(0), Delivery::New);
    }

    #[test]
    fn dedup_rejects_seq_beyond_window() {
        let mut dedup = Dedup::with_window(8);
        assert_eq!(dedup.accept(0), Delivery::New); // prefix top = 0, base = 1
        assert_eq!(dedup.accept(9), Delivery::OutOfWindow); // 9 - 1 >= 8
        assert_eq!(dedup.accept(8), Delivery::New); // 8 - 1 < 8, still in window
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

    fn turn(byte: u8) -> Payload {
        Payload {
            seq: 0, // assigned by the sending link
            slot: 0,
            commands: vec![byte].into(),
        }
    }

    #[tokio::test]
    async fn delivers_each_payload_once_and_retires_on_ack() {
        let (mut client, mut server, _client_ep, _server_ep) = connected_links().await;

        for i in 0..5u8 {
            client.send(Some(turn(i))).unwrap();
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
                },
                Payload {
                    seq: 0,
                    slot: 0,
                    commands: vec![0xBB].into(),
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
            }],
        };
        client
            .connection()
            .send_datagram(malformed.encode_to_vec().into())
            .unwrap();

        match server.recv().await {
            Err(LinkError::PayloadOutOfWindow { seq }) => assert_eq!(seq, u64::MAX),
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
