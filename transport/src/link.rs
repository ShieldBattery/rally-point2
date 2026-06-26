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
//! in several packets, so [`recv`](Link::recv) tracks delivered payload seqs and
//! returns each exactly once. Delivery is in arrival order — in-order
//! reassembly (waiting on a missing seq, as Storm did) is a layer above this.

use prost::Message;
use rally_point_proto::messages::{Packet, Payload};

use crate::ack_manager::{AckError, AckManager};
use crate::sequence_buffer::{MAX_SEQUENCE, SequenceBuffer};

/// How many recently-delivered payload seqs to remember for dedup. A payload is
/// re-sent only until it's acked, and receiving it is what produces that ack, so
/// a window this far behind the newest delivered seq always covers anything the
/// peer could still be re-sending — well beyond its redundancy reach even under
/// heavy loss.
const DELIVERED_WINDOW: usize = 4096;

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
    /// A received datagram was not a well-formed packet.
    #[error("decoding incoming packet failed: {0}")]
    Decode(#[from] prost::DecodeError),
    /// A received payload carried a seq outside the trackable range (its top bit
    /// is reserved). Only a malformed or malicious peer sends these.
    #[error("payload seq {seq} is out of range")]
    InvalidPayloadSeq { seq: u64 },
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
    /// ack-only when `payload` is `None` — and sends it as one QUIC datagram.
    ///
    /// The bundle is sized to the connection's live `max_datagram_size()`, so it
    /// tracks path-MTU changes. A failed send still leaves the payload tracked as
    /// unacked, so the next packet simply re-carries it.
    pub fn send(&mut self, payload: Option<Payload>) -> Result<(), LinkError> {
        let budget = self
            .connection
            .max_datagram_size()
            .ok_or(LinkError::DatagramsUnsupported)?;
        let packet = self.acks.build_outgoing(payload, budget);
        self.connection
            .send_datagram(packet.encode_to_vec().into())?;
        Ok(())
    }

    /// Awaits the next datagram, folds its acks into the manager, and returns the
    /// payloads not delivered before (redundant copies dropped), in arrival
    /// order.
    pub async fn recv(&mut self) -> Result<Vec<Payload>, LinkError> {
        let datagram = self.connection.read_datagram().await?;
        let packet = Packet::decode(datagram)?;
        self.process_incoming(packet)
    }

    /// Folds a decoded packet's acks into the manager and returns its
    /// not-yet-delivered payloads. Split out from [`recv`](Link::recv) so the
    /// validation and dedup are exercised without a live connection.
    fn process_incoming(&mut self, packet: Packet) -> Result<Vec<Payload>, LinkError> {
        // Reject out-of-range payload seqs before any state is touched: they are
        // attacker-controlled, and the dedup buffer reserves the top sequence bit
        // (feeding it a larger value would panic).
        for payload in &packet.payloads {
            if payload.seq > MAX_SEQUENCE {
                return Err(LinkError::InvalidPayloadSeq { seq: payload.seq });
            }
        }

        self.acks.handle_incoming(&packet)?;

        let mut fresh = Vec::new();
        for payload in packet.payloads {
            if self.dedup.accept(payload.seq) {
                fresh.push(payload);
            }
        }
        Ok(fresh)
    }
}

/// Receive-side payload dedup: remembers recently delivered payload seqs so the
/// redundant copies that ride later packets are dropped.
struct Dedup {
    delivered: SequenceBuffer<()>,
}

impl Dedup {
    fn new() -> Self {
        Self::with_window(DELIVERED_WINDOW)
    }

    fn with_window(capacity: usize) -> Self {
        Self {
            delivered: SequenceBuffer::with_capacity(capacity),
        }
    }

    /// Records `seq` as delivered, returning whether this is the first time it's
    /// been seen. Returns `false` for any seq already delivered — whether it's
    /// still inside the dedup window or has fallen out of it. The caller must
    /// ensure `seq <= MAX_SEQUENCE`.
    fn accept(&mut self, seq: u64) -> bool {
        if self.delivered.exists(seq) {
            return false;
        }
        // `insert` returns `None` when `seq` is too old to track — meaning it was
        // delivered before falling out of the window — so that is a duplicate
        // too, not a new delivery.
        self.delivered.insert(seq, ()).is_some()
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
        let mut dedup = Dedup::with_window(4);
        assert!(dedup.accept(0));
        assert!(!dedup.accept(0)); // duplicate still inside the window
        assert!(dedup.accept(1));
        assert!(!dedup.accept(1));
    }

    #[test]
    fn dedup_does_not_redeliver_evicted_seqs() {
        let mut dedup = Dedup::with_window(4);
        for seq in 0..=4 {
            assert!(dedup.accept(seq));
        }
        // Seq 0 has been pushed out of the 4-slot window; a redundant copy of it
        // must still count as a duplicate, not a fresh delivery.
        assert!(!dedup.accept(0));
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
            delivered.extend(server.recv().await.unwrap());
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
    async fn rejects_out_of_range_payload_seq() {
        let (client, mut server, _client_ep, _server_ep) = connected_links().await;

        // Inject a packet whose payload seq sets the reserved top bit, bypassing
        // the sending link's ack manager. The receiver must reject it, not panic.
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
            Err(LinkError::InvalidPayloadSeq { seq }) => assert_eq!(seq, u64::MAX),
            other => panic!("expected InvalidPayloadSeq, got {other:?}"),
        }
    }
}
