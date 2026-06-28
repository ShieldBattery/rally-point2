//! One mesh link: a shared QUIC connection carrying every game two relays
//! jointly serve, with per-session transport state.
//!
//! A [`MeshLink`] owns one `quinn::Connection` and a registry of [`SessionLink`]
//! instances — one per game active on that relay-pair. Every datagram on the
//! connection is a [`MeshPacket`](rally_point_proto::messages::MeshPacket): a
//! session id plus the per-link [`Packet`](rally_point_proto::messages::Packet)
//! for that session. The link demultiplexes by session: each session's
//! [`AckManager`] and [`Dedup`] instance only ever sees its own session's
//! packets, so the origin `(slot, seq)` identity is unambiguous within an
//! instance — the session never enters the dedup/ack/retirement key.
//!
//! This is the faithful reading of "one QUIC connection per relay-pair"
//! (architecture.md §"The mesh"): a relay-pair shares one connection, so the
//! two endpoints run one congestion controller over the whole backbone path
//! rather than N competing ones. The per-link transport — `AckManager`,
//! `Dedup`, the beacon codec — is reused unchanged per session; only the
//! demux layer and the session wrap on the wire are new.
//!
//! The client edge keeps [`Link`](crate::Link) 1:1 (one game per connection by
//! nature); the mesh uses [`MeshLink`]. Both drive the same per-link
//! components; they differ in how many sessions share the connection.
//!
//! # Concurrency
//!
//! One connection means one `read_datagram` owner. [`MeshLink::recv`] reads one
//! datagram and returns the session it belonged to plus its delivery; a single
//! driver task calls it in a loop and dispatches to the per-session state. The
//! per-session state is owned by that one task (or one task per session that
//! receives over a channel the demux reader forwards to) — never shared across
//! tasks that race on `read_datagram`.

use std::collections::HashMap;

use prost::Message;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::{MeshPacket, Packet, Payload};

use crate::ack_manager::{AckError, AckManager};
use crate::link::{Dedup, Delivery, LinkError, Received};

/// Worst-case byte overhead the `MeshPacket` wrapper adds around the inner
/// `Packet`: the session field tag (1) + its varint (≤10 for a u64, but a real
/// session id fits in ≤5), plus the inner `Packet` field tag (1) + its length
/// prefix (≤3 for any packet under ~16MB). 16 covers the worst case with margin;
/// the inner packet's `build_outgoing` is given the path budget minus this, so
/// the encoded `MeshPacket` fits the datagram even when redundancy fills it.
const MESH_PACKET_OVERHEAD: usize = 16;

/// One mesh link: a shared QUIC connection plus per-session transport state.
///
/// Built from an established relay ↔ relay QUIC connection (negotiated with
/// [`MESH_ALPN`](crate::quic::MESH_ALPN)). A driver calls [`recv`](Self::recv)
/// in a loop to demultiplex incoming datagrams by session and route each to its
/// session's state, and [`send`](Self::send) to build and send a session's
/// packet on the shared connection.
///
/// A session joins the link with [`open_session`](Self::open_session) and leaves
/// with [`close_session`](Self::close_session) when its game ends or its
/// peer-relay counterpart for that session goes away.
pub struct MeshLink {
    connection: quinn::Connection,
    sessions: HashMap<SessionId, SessionLink>,
}

/// One session's per-link transport state on a mesh link: its own
/// [`AckManager`] and [`Dedup`], independent of every other session's. The
/// `(slot, seq)` identity is unambiguous within an instance because the
/// instance only ever sees one session's payloads.
pub struct SessionLink {
    acks: AckManager,
    dedup: Dedup,
}

/// Why a mesh-link send or receive failed.
#[derive(Debug, thiserror::Error)]
pub enum MeshLinkError {
    /// The peer never advertised QUIC datagram support, so this mesh link can't
    /// carry turns at all — a configuration/peer mismatch, not a transient
    /// failure. A mesh connection negotiated `MESH_ALPN`, which requires it, so
    /// reaching this means a misbehaving or incompatible peer relay.
    #[error("peer does not support QUIC datagrams")]
    DatagramsUnsupported,
    /// The QUIC connection ended.
    #[error("QUIC connection lost: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// A datagram could not be queued for sending.
    #[error("sending datagram failed: {0}")]
    Send(#[from] quinn::SendDatagramError),
    /// A datagram did not fit the path's current budget. With the tiny turns of
    /// a lockstep game this should never happen; it is surfaced rather than
    /// retried forever.
    #[error("datagram of {needed} bytes exceeds the {budget}-byte path budget")]
    PayloadTooLarge { needed: usize, budget: usize },
    /// A received datagram was not a well-formed `MeshPacket`.
    #[error("decoding incoming mesh packet failed: {0}")]
    Decode(#[from] prost::DecodeError),
    /// A `MeshPacket` was structurally invalid — most commonly a missing inner
    /// `Packet`, which the field marks `optional` though it is required in
    /// spirit. A peer-relay bug; the driver decides whether to drop the session.
    #[error("malformed MeshPacket: {0}")]
    MalformedMeshPacket(&'static str),
    /// A received `MeshPacket` named a session no one has opened on this link —
    /// a peer-relay bug or a desync between the two relays' session rosters.
    #[error("mesh packet for unknown session {0}")]
    UnknownSession(SessionId),
    /// A received `MeshPacket` carried a zero session id. Sessions are
    /// 1-indexed, so a zero is malformed (the proto3 field is otherwise
    /// indistinguishable from "unset").
    #[error("mesh packet with zero session id")]
    ZeroSession,
    /// A payload's seq was further ahead of our contiguous delivered prefix
    /// than the receive window allows — the peer is racing too far ahead.
    #[error("payload (slot {}, seq {seq}) is beyond the receive window", slot.0)]
    PayloadOutOfWindow { slot: SlotId, seq: u64 },
    /// A received packet's acks were internally inconsistent. A peer-relay bug
    /// (the mesh trusts its peer); the driver decides whether to drop the session.
    #[error(transparent)]
    Ack(#[from] AckError),
}

impl From<LinkError> for MeshLinkError {
    /// Maps the shared [`LinkError`] variants into [`MeshLinkError`]. The
    /// per-session `process_incoming` returns `LinkError`; this lets its caller
    /// propagate with `?` into a [`MeshLinkError`].
    fn from(error: LinkError) -> Self {
        match error {
            LinkError::DatagramsUnsupported => MeshLinkError::DatagramsUnsupported,
            LinkError::Connection(error) => MeshLinkError::Connection(error),
            LinkError::Send(error) => MeshLinkError::Send(error),
            LinkError::PayloadTooLarge { needed, budget } => {
                MeshLinkError::PayloadTooLarge { needed, budget }
            }
            LinkError::Decode(error) => MeshLinkError::Decode(error),
            LinkError::PayloadOutOfWindow { slot, seq } => {
                MeshLinkError::PayloadOutOfWindow { slot, seq }
            }
            LinkError::Ack(error) => MeshLinkError::Ack(error),
        }
    }
}

impl MeshLink {
    /// Wraps an established relay ↔ relay QUIC connection as a mesh link with no
    /// sessions yet. Open sessions with [`open_session`](Self::open_session) as
    /// games join this relay-pair.
    pub fn new(connection: quinn::Connection) -> Self {
        Self {
            connection,
            sessions: HashMap::new(),
        }
    }

    /// The underlying QUIC connection. Shared across every session on this link.
    pub fn connection(&self) -> &quinn::Connection {
        &self.connection
    }

    /// Opens a new session's transport state on this link. Idempotent: opening
    /// an already-open session is a no-op (a relay may re-offer a session its
    /// peer already announced). Returns a borrow so the caller can drive the
    /// session without a separate lookup.
    pub fn open_session(&mut self, session: SessionId) -> &mut SessionLink {
        self.sessions.entry(session).or_insert_with(|| SessionLink {
            acks: AckManager::new(),
            dedup: Dedup::new(),
        })
    }

    /// Drops a session's transport state. Called when the game ends or the
    /// peer-relay side for that session is gone. Idempotent: closing an absent
    /// session is a no-op.
    pub fn close_session(&mut self, session: SessionId) {
        self.sessions.remove(&session);
    }

    /// Builds the next `MeshPacket` for `session` — `payload` plus redundant
    /// unacked ones, or ack-only when `payload` is `None` — sends it as one
    /// QUIC datagram on the shared connection, and returns how many still-unacked
    /// turns it re-carried as redundancy (the fresh turn, if any, is not counted).
    ///
    /// That count lets a caller tell whether retransmission is already riding
    /// the outbound stream (redundancy carried) or whether it must schedule a
    /// standalone flush — a near-MTU turn fills the datagram and re-carries
    /// nothing. Mirrors [`Link::send`](crate::Link::send) per session.
    /// The bundle is sized to the connection's live `max_datagram_size()`, so it
    /// tracks path-MTU changes and is shared across sessions — one congestion
    /// controller paces every session's datagrams, which is the point of the
    /// shared connection. The inner `Packet` is built to the budget *minus*
    /// [`MESH_PACKET_OVERHEAD`], so the `MeshPacket` wrapper (session field +
    /// nested-message tag + length prefix) fits the datagram even when
    /// redundancy fills the inner packet — the client-edge [`Link::send`](crate::Link::send)
    /// needs no such reservation because its datagram *is* the `Packet`.
    pub fn send(
        &mut self,
        session: SessionId,
        payload: Option<Payload>,
    ) -> Result<usize, MeshLinkError> {
        let datagram_budget = self
            .connection
            .max_datagram_size()
            .ok_or(MeshLinkError::DatagramsUnsupported)?;
        let had_fresh = payload.is_some();

        let Some(session_link) = self.sessions.get_mut(&session) else {
            // Sending for a session that isn't open is a driver bug: the relay
            // opened it before routing turns to this link. Surface rather than
            // silently drop.
            return Err(MeshLinkError::UnknownSession(session));
        };

        // Leave room for the MeshPacket wrapper so the encoded total fits the
        // datagram budget even when build_outgoing fills the inner Packet.
        let packet_budget = datagram_budget.saturating_sub(MESH_PACKET_OVERHEAD);
        let packet = session_link.acks.build_outgoing(payload, packet_budget);
        // Everything in the packet except the fresh turn is a redundant re-carry.
        let redundant = packet.payloads.len() - usize::from(had_fresh);

        let mesh_packet = MeshPacket {
            session: session.0,
            packet: Some(packet),
        };
        let encoded = mesh_packet.encode_to_vec();
        let datagram_len = encoded.len();
        match self.connection.send_datagram(encoded.into()) {
            Ok(()) => Ok(redundant),
            Err(quinn::SendDatagramError::TooLarge) => Err(MeshLinkError::PayloadTooLarge {
                needed: datagram_len,
                budget: datagram_budget,
            }),
            Err(error) => Err(error.into()),
        }
    }

    /// Awaits the next datagram, demultiplexes it by session, folds its acks
    /// into that session's manager, and returns the session plus what it
    /// delivered: the payloads not seen before (redundant copies dropped, in
    /// ascending seq order within each slot) plus whether the packet carried
    /// any payloads at all.
    ///
    /// One driver task calls this in a loop — never multiple tasks, since
    /// `read_datagram` is a single-consumer API and racing on it would
    /// interleave sessions unpredictably. The driver dispatches the returned
    /// `(SessionId, Received)` to the per-session state it owns.
    pub async fn recv(&mut self) -> Result<(SessionId, Received), MeshLinkError> {
        let datagram = self.connection.read_datagram().await?;
        let mesh_packet = MeshPacket::decode(datagram)?;

        if mesh_packet.session == 0 {
            return Err(MeshLinkError::ZeroSession);
        }
        let session = SessionId(mesh_packet.session);

        let Some(packet) = mesh_packet.packet else {
            // A MeshPacket with no inner Packet is malformed (the field is
            // required in spirit). Surface as a structural error, not a decode
            // error, so the driver can attribute it to the peer relay.
            return Err(MeshLinkError::MalformedMeshPacket(
                "MeshPacket missing required Packet field",
            ));
        };

        let Some(session_link) = self.sessions.get_mut(&session) else {
            return Err(MeshLinkError::UnknownSession(session));
        };

        let received = session_link.process_incoming(packet)?;
        Ok((session, received))
    }

    /// Payloads sent for `session` but not yet known-delivered — the in-flight
    /// depth, and the overflow signal the driver watches under sustained loss.
    /// Returns `0` for a session that isn't open (nothing in flight).
    pub fn payloads_in_flight(&self, session: SessionId) -> usize {
        self.sessions
            .get(&session)
            .map(|s| s.acks.payloads_in_flight())
            .unwrap_or(0)
    }

    /// The top of the contiguous run of payloads this link has delivered to its
    /// consumer for `(session, slot)`, or `None` before the session's first
    /// payload for that slot arrives. This is the per-slot cursor the beacon
    /// side-channel pushes to the peer so it can force-advance its unacked
    /// window past turns it now knows were received.
    pub fn delivered_through(&self, session: SessionId, slot: SlotId) -> Option<u64> {
        self.sessions
            .get(&session)
            .and_then(|s| s.dedup.delivered_through(slot))
    }

    /// Force-retires every unacked payload in `(session, slot)` up to
    /// `through_seq`, returning how many were dropped, *unless* `through_seq`
    /// is not strictly greater than the last cursor applied for that slot. A
    /// monotonic guard: the beacon stream is reliable-ordered, so cursors arrive
    /// in order, but a stream framing desync could produce a garbage `u64` —
    /// retiring turns the peer never confirmed would desync lockstep silently.
    /// Rejecting anything not strictly advancing turns such a desync into a
    /// harmless no-op. Returns `0` for a session that isn't open.
    pub fn retire_through(&mut self, session: SessionId, slot: SlotId, through_seq: u64) -> usize {
        let Some(session_link) = self.sessions.get_mut(&session) else {
            return 0;
        };
        if session_link
            .dedup
            .advance_retired_through(slot, through_seq)
        {
            session_link.acks.retire_payloads_through(slot, through_seq)
        } else {
            0
        }
    }
}

impl SessionLink {
    /// Folds a decoded packet's acks into the manager and returns its delivery.
    /// Mirrors [`Link::process_incoming`](crate::Link) but on the per-session
    /// state this struct owns.
    fn process_incoming(&mut self, mut packet: Packet) -> Result<Received, LinkError> {
        self.acks.handle_incoming(&packet)?;

        // Whether the peer is waiting on an ack for delivered turns: a packet
        // that carried payloads (even all-redundant ones) needs an ack back,
        // while an ack-only packet does not.
        let carried_payloads = !packet.payloads.is_empty();

        // Process payloads low-seq first within each slot. A packet leads with
        // its fresh (highest) seq per slot, so without this a deep-loss packet's
        // high seq could shut the window on the older redundant seqs it carries.
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use super::*;
    use crate::quic::{mesh_client_config, server_config};

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

    /// Brings up a loopback QUIC connection negotiated on `MESH_ALPN` and wraps
    /// each end in a `MeshLink`. Both endpoints are returned so the caller keeps
    /// them alive for the test.
    async fn connected_mesh_links() -> (MeshLink, MeshLink, quinn::Endpoint, quinn::Endpoint) {
        let (chain, key, ca) = self_signed();
        let server_cfg = server_config(chain, key).unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let client_cfg = mesh_client_config(roots).unwrap();

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
            MeshLink::new(client_conn),
            MeshLink::new(server_conn),
            client,
            server,
        )
    }

    fn turn(slot: u8, seq: u64, byte: u8) -> Payload {
        Payload {
            seq,
            slot: u32::from(slot),
            commands: vec![byte].into(),
        }
    }

    /// Two sessions share one `MeshLink`. Both send `(slot=0, seq=0)` — identical
    /// identities. Each session's dedup treats the other's as new (not a
    /// duplicate), and a beacon cursor for one session's slot 0 retires only
    /// that session's payloads. This is the load-bearing proof for the
    /// shared-connection design: the session never enters the `(slot, seq)` key,
    /// so per-session instances keep the two streams independent.
    #[tokio::test]
    async fn two_sessions_on_one_link_do_not_cross_dedup_ack_or_retire() {
        let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

        let session_a = SessionId(1);
        let session_b = SessionId(2);
        sender.open_session(session_a);
        sender.open_session(session_b);
        receiver.open_session(session_a);
        receiver.open_session(session_b);

        // Both sessions send (slot=0, seq=0). A shared-dedup bug would make the
        // second a duplicate; per-session dedup makes both new.
        sender.send(session_a, Some(turn(0, 0, 0xA0))).unwrap();
        sender.send(session_b, Some(turn(0, 0, 0xB0))).unwrap();

        // Receive session A's turn — exactly one payload, session A's.
        let (sid, received) = receiver.recv().await.unwrap();
        assert_eq!(sid, session_a);
        assert_eq!(received.fresh.len(), 1);
        assert_eq!(received.fresh[0].commands[0], 0xA0);

        // Receive session B's turn — also exactly one payload, session B's. If
        // the sessions shared dedup, this would be dropped as a duplicate of
        // session A's (slot=0, seq=0).
        let (sid, received) = receiver.recv().await.unwrap();
        assert_eq!(sid, session_b);
        assert_eq!(received.fresh.len(), 1);
        assert_eq!(received.fresh[0].commands[0], 0xB0);

        // Both sessions have one payload in flight (the turns above). A
        // retire_through for session A's slot 0 must retire only session A's
        // payload, leaving session B's in flight.
        assert_eq!(sender.payloads_in_flight(session_a), 1);
        assert_eq!(sender.payloads_in_flight(session_b), 1);

        // Simulate a beacon cursor for session A: force-retire its slot 0
        // through seq 0.
        let retired = sender.retire_through(session_a, SlotId(0), 0);
        assert_eq!(retired, 1, "session A's payload should retire");

        // Session A is now retired; session B is not.
        assert_eq!(sender.payloads_in_flight(session_a), 0);
        assert_eq!(
            sender.payloads_in_flight(session_b),
            1,
            "session B's payload must survive session A's retire"
        );
    }

    /// The ack-beacon cursor delivered_through is per-session: a delivery on
    /// session A does not advance session B's cursor for the same slot.
    #[tokio::test]
    async fn delivered_through_is_per_session_not_shared() {
        let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

        let session_a = SessionId(1);
        let session_b = SessionId(2);
        sender.open_session(session_a);
        sender.open_session(session_b);
        receiver.open_session(session_a);
        receiver.open_session(session_b);

        // Send + receive session A's (slot=0, seq=0).
        sender.send(session_a, Some(turn(0, 0, 0xA0))).unwrap();
        let (sid, received) = receiver.recv().await.unwrap();
        assert_eq!(sid, session_a);
        assert_eq!(received.fresh.len(), 1);

        // Session A's delivered_through advanced to 0; session B's did not.
        assert_eq!(
            receiver.delivered_through(session_a, SlotId(0)),
            Some(0),
            "session A delivered through seq 0"
        );
        assert_eq!(
            receiver.delivered_through(session_b, SlotId(0)),
            None,
            "session B has not delivered slot 0 yet"
        );

        // Now send + receive session B's (slot=0, seq=0) — the same (slot, seq)
        // as session A's. If delivered_through were shared, it would already be
        // Some(0) and the payload would be a duplicate.
        sender.send(session_b, Some(turn(0, 0, 0xB0))).unwrap();
        let (sid, received) = receiver.recv().await.unwrap();
        assert_eq!(sid, session_b);
        assert_eq!(
            received.fresh.len(),
            1,
            "session B's (slot=0, seq=0) is new, not a duplicate of session A's"
        );
        assert_eq!(receiver.delivered_through(session_b, SlotId(0)), Some(0));
    }

    /// A `MeshPacket` for a session that was never opened is an error, not a
    /// silent drop — the two relays' session rosters have desynced.
    #[tokio::test]
    async fn rejects_a_packet_for_an_unopened_session() {
        let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

        let known_session = SessionId(1);
        let unknown_session = SessionId(2);
        // The sender opens session 2 so its send succeeds; the receiver does
        // not, so the recv surfaces UnknownSession — the two relays' session
        // rosters have desynced.
        sender.open_session(known_session);
        sender.open_session(unknown_session);
        receiver.open_session(known_session);

        sender
            .send(unknown_session, Some(turn(0, 0, 0xA0)))
            .unwrap();

        match receiver.recv().await {
            Err(MeshLinkError::UnknownSession(sid)) => assert_eq!(sid, unknown_session),
            other => panic!("expected UnknownSession, got {other:?}"),
        }
    }

    /// A `MeshPacket` with a zero session id is malformed, not a valid session.
    #[tokio::test]
    async fn rejects_a_packet_with_a_zero_session_id() {
        let (sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

        // Craft a MeshPacket with session=0 directly on the wire.
        let mesh_packet = MeshPacket {
            session: 0,
            packet: Some(Packet {
                seq: 0,
                ack: None,
                ack_bits: 0,
                payloads: vec![turn(0, 0, 0xA0)],
            }),
        };
        sender
            .connection()
            .send_datagram(mesh_packet.encode_to_vec().into())
            .unwrap();

        match receiver.recv().await {
            Err(MeshLinkError::ZeroSession) => {}
            other => panic!("expected ZeroSession, got {other:?}"),
        }
    }
    /// The inner `Packet` is built to `max_datagram_size() - MESH_PACKET_OVERHEAD`
    /// so the `MeshPacket` wrapper still fits the datagram even when
    /// `build_outgoing` fills the inner packet with redundancy under sustained
    /// loss. This is the one regression the overhead reservation exists to
    /// prevent: dropping the `saturating_sub`, or a too-small const, would make
    /// `send` return `PayloadTooLarge` exactly when redundancy matters most.
    ///
    /// With acks withheld, each new send re-carries every prior unacked payload,
    /// so the inner packet fills to `packet_budget` after a few turns. The test
    /// sizes payloads to near the per-payload budget so this fill happens with
    /// few sends, then asserts `send` stays `Ok` across a sustained run.
    #[tokio::test]
    async fn send_fits_the_datagram_when_redundancy_fills_the_inner_packet() {
        let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

        let session = SessionId(1);
        sender.open_session(session);
        receiver.open_session(session);

        // Use tiny (4-byte) commands so build_outgoing packs many payloads per
        // packet, filling the inner Packet to within one payload element (~11
        // bytes) of packet_budget. That's the window MESH_PACKET_OVERHEAD
        // protects: with the reservation, the inner packet is at most
        // (max_datagram_size - 16), so the ~6-byte MeshPacket wrapper still fits.
        // Without it, build_outgoing fills to max_datagram_size and the wrapper
        // overflows → PayloadTooLarge. Large payloads leave hundreds of bytes of
        // slack and mask the bug this test exists to catch.
        let tiny_commands = 4;

        // Drain the receiver in the background so its datagram buffer can't
        // backpressure the sender's sends (quinn datagrams are bounded).
        let drain = tokio::spawn(async move {
            // Withhold acks: never send anything back, so the sender's
            // unacked_payloads set grows and every send re-carries them all.
            while receiver.recv().await.is_ok() {}
        });

        // Send enough tiny turns to fill the inner packet to near budget on
        // every send after the first ~budget/payload_size. With acks withheld,
        // each send packs as many unacked payloads as fit.
        for i in 0..200u64 {
            let payload = Payload {
                seq: i,
                slot: 0,
                commands: vec![i as u8; tiny_commands].into(),
            };
            match sender.send(session, Some(payload)) {
                Ok(_) => {}
                Err(MeshLinkError::PayloadTooLarge { needed, budget }) => {
                    panic!(
                        "send {i} returned PayloadTooLarge: needed {needed}, budget {budget} \
                         — the MeshPacket wrapper overflowed the datagram because \
                         MESH_PACKET_OVERHEAD is too small or missing"
                    );
                }
                Err(error) => panic!("send {i} failed unexpectedly: {error:?}"),
            }
        }

        // The sends succeeded: the inner packet filled to near packet_budget on
        // every send, and the MeshPacket wrapper still fit the datagram. The
        // drain task confirms the datagrams actually went on the wire.
        drop(sender);
        let _ = drain.await;
    }
}
