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
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::{LinkConditions, MeshPacket, Packet, Payload};

use crate::ack_manager::{AckError, AckManager};
use crate::link::{Dedup, Delivery, LinkError, Received};

/// Worst-case byte overhead a `MeshPacket` adds around the inner `Packet` when
/// the wrapper carries no conditions sidecar: the session field tag (1) + its
/// varint (≤10 for a u64, but a real session id fits in ≤5), plus the inner
/// `Packet` field tag (1) + its length prefix (≤3 for any packet under ~16MB).
/// 16 covers the worst case with margin.
///
/// When conditions are attached, [`MeshLink::send`] measures their exact wire
/// cost with a prost `encoded_len` probe rather than reserving a fixed worst
/// case, so the redundancy budget that defends lockstep latency is never stolen
/// by a reservation for conditions that may be small or absent (ack-only
/// flushes carry none at all). The inner `Packet` field's own tag + length
/// prefix is the one part that can't be probed without the packet itself, so it
/// stays in this const — it is bounded and small.
const MESH_PACKET_OVERHEAD: usize = 16;

/// Whether this relay should be the one to dial `peer_id` on the mesh, given
/// its own `our_id`.
///
/// Mesh links are one connection per relay-pair. Without a tie-break, both
/// relays could dial each other at once and two connections would complete —
/// one redundant, torn down after. The rule is "lower id dials higher": each
/// side compares its own id to the peer's and dials only when it is the lower.
/// The higher id stays in its accept loop and lets the dial arrive, so exactly
/// one side connects and there is no race to resolve on the wire.
///
/// This is a *pre-connect* local decision: the peer's id must already be known
/// (from the coordinator-assigned topology) before either side dials. A
/// post-connect id exchange cannot decide the dial — by the time it could run,
/// the dial has already happened. Two relays with the same id is a
/// misconfiguration; this returns `false` so neither dials rather than both.
pub fn should_dial_mesh(our_id: RelayId, peer_id: RelayId) -> bool {
    our_id < peer_id
}

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
    /// A payload's wire slot does not fit in a [`SlotId`] (0..=255) — a
    /// malformed or hostile packet. See
    /// [`LinkError::MalformedSlot`](crate::link::LinkError::MalformedSlot).
    #[error("payload names slot {0}, out of range for a SlotId (0..=255)")]
    MalformedSlot(u32),
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
            LinkError::MalformedSlot(slot) => MeshLinkError::MalformedSlot(slot),
            LinkError::Ack(error) => MeshLinkError::Ack(error),
        }
    }
}
/// What one [`MeshLink::recv`] delivered for a session, plus the per-client
/// conditions the peer relay attached to this datagram (if any).
///
/// `conditions` is the sidecar the peer relay gathered from its own home-client
/// links on this datagram. The mesh-link driver forwards it to whatever store
/// the decision-maker reads; the transport itself does not interpret it.
#[derive(Debug)]
pub struct MeshReceived {
    /// The session this datagram belonged to.
    pub session: SessionId,
    /// What the inner `Packet` delivered (new payloads, deduped) plus whether
    /// it carried payloads at all.
    pub delivery: Received,
    /// Per-client conditions the peer relay observed on its home clients this
    /// datagram, or `None` when the peer sent no conditions (an ack-only
    /// flush, or it has no local clients). See
    /// [`LinkConditions`](rally_point_proto::messages::LinkConditions).
    pub conditions: Option<LinkConditions>,
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
    /// shared connection.
    ///
    /// `conditions` carries the sender relay's home-client link stats for the
    /// latency-buffer decision-maker. When present, its exact wire cost is
    /// measured with a prost `encoded_len` probe and subtracted from the packet
    /// budget — so the redundancy budget that defends lockstep latency is never
    /// stolen by a fixed worst-case reservation, and ack-only flushes (which
    /// carry no conditions) keep their full budget. The inner `Packet` is then
    /// built to the budget *minus* [`MESH_PACKET_OVERHEAD`] (the inner-Packet
    /// field tag + length prefix that can't be probed without the packet
    /// itself), so the `MeshPacket` wrapper fits the datagram even when
    /// redundancy fills the inner packet — the client-edge [`Link::send`](crate::Link::send)
    /// needs no such reservation because its datagram *is* the `Packet`.
    pub fn send(
        &mut self,
        session: SessionId,
        payload: Option<Payload>,
        conditions: Option<LinkConditions>,
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
        // Measure the conditions sidecar's exact wire cost so the redundancy
        // budget that defends lockstep latency is never stolen by a fixed
        // worst-case reservation. A small or absent sidecar leaves the budget
        // intact; a large one reserves exactly what it needs. `encoded_len` on
        // the optional message field counts its tag + length prefix + body, so
        // no separate framing allowance is needed.
        let conditions_overhead = conditions.as_ref().map(|c| c.encoded_len()).unwrap_or(0);
        // The inner Packet's own field tag + varint length prefix can't be
        // probed without the packet itself, so MESH_PACKET_OVERHEAD covers it —
        // bounded (≤3 bytes for any packet under ~16MB) and small.
        let packet_budget = datagram_budget
            .saturating_sub(conditions_overhead)
            .saturating_sub(MESH_PACKET_OVERHEAD);
        // A payload that can never ride any datagram is refused *before* it is
        // registered as unacked (mirroring `Link::send`): registered, every
        // rebuilt bundle would try and fail to carry it while its seq holds a
        // permanent gap in the peer's delivered prefix. This is the second line
        // of defense — the caller pre-checks with
        // [`payload_fits`](Self::payload_fits) and diverts oversize turns to the
        // mesh control stream before ever calling `send`.
        if let Some(p) = &payload {
            let needed = crate::ack_manager::lone_packet_len(p);
            if needed > packet_budget {
                return Err(MeshLinkError::PayloadTooLarge {
                    needed,
                    budget: packet_budget,
                });
            }
        }
        let packet = session_link.acks.build_outgoing(payload, packet_budget);
        // Everything in the packet except the fresh turn is a redundant re-carry.
        let redundant = packet.payloads.len() - usize::from(had_fresh);

        let mesh_packet = MeshPacket {
            session: session.0,
            packet: Some(packet),
            conditions,
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

    /// Whether `payload` can ever ride a mesh datagram on this connection's
    /// current path, sized against the same budget [`send`](Self::send) applies:
    /// the live `max_datagram_size()` minus the exact wire cost of the
    /// `conditions` sidecar that would accompany it and the `MeshPacket`
    /// wrapper's own overhead. The caller's pre-check for the divert path — a
    /// payload this returns `false` for must go over the mesh control stream,
    /// never into `send` (which would refuse it anyway, but by then the caller
    /// has lost the payload to the move). Mirrors
    /// [`Link::payload_fits`](crate::Link::payload_fits) on the client edge;
    /// takes the conditions because the mesh budget, unlike the client edge's,
    /// varies with the sidecar attached to each send.
    pub fn payload_fits(
        &self,
        payload: &Payload,
        conditions: Option<&LinkConditions>,
    ) -> Result<bool, MeshLinkError> {
        let datagram_budget = self
            .connection
            .max_datagram_size()
            .ok_or(MeshLinkError::DatagramsUnsupported)?;
        let conditions_overhead = conditions.map(|c| c.encoded_len()).unwrap_or(0);
        let packet_budget = datagram_budget
            .saturating_sub(conditions_overhead)
            .saturating_sub(MESH_PACKET_OVERHEAD);
        Ok(crate::ack_manager::lone_packet_len(payload) <= packet_budget)
    }

    /// Awaits the next datagram, demultiplexes it by session, folds its acks
    /// into that session's manager, and returns what it delivered: the session,
    /// the payloads not seen before (redundant copies dropped, in ascending seq
    /// order within each slot), whether the packet carried any payloads at all,
    /// and the per-client conditions the peer relay attached (if any).
    ///
    /// One driver task calls this in a loop — never multiple tasks, since
    /// `read_datagram` is a single-consumer API and racing on it would
    /// interleave sessions unpredictably. The driver dispatches the returned
    /// [`MeshReceived`] to the per-session state it owns.
    pub async fn recv(&mut self) -> Result<MeshReceived, MeshLinkError> {
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

        let delivery = session_link.process_incoming(packet)?;
        Ok(MeshReceived {
            session,
            delivery,
            conditions: mesh_packet.conditions,
        })
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

    /// Every slot's delivered-through cursor for `session`, for slots that
    /// have delivered at least one payload on this link. Empty (never an
    /// error) for a session that isn't open. This is the source the mesh
    /// ack-cursor push reads: the driver has no independent list of which
    /// remote slots a session carries, so it reads back exactly what this
    /// link's own receive state has actually seen.
    pub fn delivered_through_all(&self, session: SessionId) -> Vec<(SlotId, u64)> {
        self.sessions
            .get(&session)
            .map(|s| s.dedup.delivered_through_all())
            .unwrap_or_default()
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
            // A truncating cast would alias an out-of-range wire slot onto a
            // different, valid slot's dedup key — corrupting that slot's
            // window instead of merely rejecting the malformed one.
            let Ok(slot) = u8::try_from(payload.slot).map(SlotId) else {
                return Err(LinkError::MalformedSlot(payload.slot));
            };
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
            ..Default::default()
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
        sender
            .send(session_a, Some(turn(0, 0, 0xA0)), None)
            .unwrap();
        sender
            .send(session_b, Some(turn(0, 0, 0xB0)), None)
            .unwrap();

        // Receive session A's turn — exactly one payload, session A's.
        let received = receiver.recv().await.unwrap();
        assert_eq!(received.session, session_a);
        assert_eq!(received.delivery.fresh.len(), 1);
        assert_eq!(received.delivery.fresh[0].commands[0], 0xA0);

        // Receive session B's turn — also exactly one payload, session B's. If
        // the sessions shared dedup, this would be dropped as a duplicate of
        // session A's (slot=0, seq=0).
        let received = receiver.recv().await.unwrap();
        assert_eq!(received.session, session_b);
        assert_eq!(received.delivery.fresh.len(), 1);
        assert_eq!(received.delivery.fresh[0].commands[0], 0xB0);

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
        sender
            .send(session_a, Some(turn(0, 0, 0xA0)), None)
            .unwrap();
        let received = receiver.recv().await.unwrap();
        assert_eq!(received.session, session_a);
        assert_eq!(received.delivery.fresh.len(), 1);

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
        sender
            .send(session_b, Some(turn(0, 0, 0xB0)), None)
            .unwrap();
        let received = receiver.recv().await.unwrap();
        assert_eq!(received.session, session_b);
        assert_eq!(
            received.delivery.fresh.len(),
            1,
            "session B's (slot=0, seq=0) is new, not a duplicate of session A's"
        );
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
            .send(unknown_session, Some(turn(0, 0, 0xA0)), None)
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
            conditions: None,
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
                ..Default::default()
            };
            match sender.send(session, Some(payload), None) {
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

    /// Conditions attached to a `MeshPacket` round-trip: the sender attaches
    /// per-client link stats, the receiver gets them back on `MeshReceived`.
    /// This is the transport-level proof that conditions cross the mesh — the
    /// relay E2E is not needed because the transport carries them, not stored
    /// relay state.
    #[tokio::test]
    async fn conditions_round_trip_through_send_and_recv() {
        let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

        let session = SessionId(1);
        sender.open_session(session);
        receiver.open_session(session);

        // Two home-client link stats, the shape a relay would gather from its
        // own quinn connections: slot 0 at 12ms RTT with 3/1000 lost; slot 1
        // at 45ms with 10/500 lost.
        let conditions = LinkConditions {
            slots: vec![
                rally_point_proto::messages::SlotConditions {
                    slot: 0,
                    rtt_us: 12_000,
                    lost_packets: 3,
                    sent_packets: 1000,
                },
                rally_point_proto::messages::SlotConditions {
                    slot: 1,
                    rtt_us: 45_000,
                    lost_packets: 10,
                    sent_packets: 500,
                },
            ],
        };

        sender
            .send(session, Some(turn(0, 0, 0xA0)), Some(conditions.clone()))
            .unwrap();

        let received = receiver.recv().await.unwrap();
        assert_eq!(received.session, session);
        assert_eq!(received.delivery.fresh.len(), 1);
        let got = received
            .conditions
            .as_ref()
            .expect("conditions should be present on the received MeshPacket");
        assert_eq!(got.slots.len(), 2);
        assert_eq!(got.slots[0].slot, 0);
        assert_eq!(got.slots[0].rtt_us, 12_000);
        assert_eq!(got.slots[0].lost_packets, 3);
        assert_eq!(got.slots[0].sent_packets, 1000);
        assert_eq!(got.slots[1].slot, 1);
        assert_eq!(got.slots[1].rtt_us, 45_000);
        assert_eq!(got.slots[1].lost_packets, 10);
        assert_eq!(got.slots[1].sent_packets, 500);
    }

    /// An ack-only flush carries no conditions, and the dynamic overhead probe
    /// leaves the redundancy budget intact when conditions are absent — so the
    /// existing budget regression (`send_fits_the_datagram_when_redundancy_fills_the_inner_packet`)
    /// still holds with `None` conditions. This is the load-bearing property:
    /// ack-only flushes must not steal redundancy budget for a conditions
    /// reservation they don't use.
    #[tokio::test]
    async fn ack_only_flush_with_no_conditions_keeps_full_budget() {
        let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

        let session = SessionId(1);
        sender.open_session(session);
        receiver.open_session(session);

        // Fill the unacked window with tiny turns (acks withheld), then send an
        // ack-only flush with no conditions. The flush must fit the datagram
        // even when the inner packet is packed with redundant re-carries — the
        // dynamic probe reserves zero for absent conditions.
        let drain = tokio::spawn(async move { while receiver.recv().await.is_ok() {} });

        for i in 0..200u64 {
            let payload = Payload {
                seq: i,
                slot: 0,
                commands: vec![i as u8; 4].into(),
                ..Default::default()
            };
            match sender.send(session, Some(payload), None) {
                Ok(_) => {}
                Err(MeshLinkError::PayloadTooLarge { needed, budget }) => {
                    panic!(
                        "send {i} returned PayloadTooLarge: needed {needed}, budget {budget} \
                         — absent conditions should reserve zero overhead"
                    );
                }
                Err(error) => panic!("send {i} failed unexpectedly: {error:?}"),
            }
        }

        // An explicit ack-only flush (None payload) with no conditions: the
        // inner packet re-carries every unacked payload, and must still fit.
        match sender.send(session, None, None) {
            Ok(_) => {}
            Err(MeshLinkError::PayloadTooLarge { needed, budget }) => {
                panic!(
                    "ack-only flush returned PayloadTooLarge: needed {needed}, budget {budget} \
                     — None conditions must not reserve overhead"
                );
            }
            Err(error) => panic!("ack-only flush failed unexpectedly: {error:?}"),
        }

        drop(sender);
        let _ = drain.await;
    }

    /// A large conditions sidecar reserves exactly its wire cost — not a fixed
    /// worst case — so the redundancy budget shrinks by the sidecar's actual
    /// size and no more. This is the property the dynamic `encoded_len` probe
    /// exists for: a fixed worst-case reservation would steal budget that
    /// defends lockstep latency.
    #[tokio::test]
    async fn large_conditions_reserve_their_exact_wire_cost_not_a_worst_case() {
        let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

        let session = SessionId(1);
        sender.open_session(session);
        receiver.open_session(session);

        // A conditions sidecar with all 8 slots filled — the largest a real
        // game (≤8 players) produces. Small enough that even with redundancy
        // packed alongside it, the datagram fits — which is what we assert.
        let conditions = LinkConditions {
            slots: (0..8u32)
                .map(|slot| rally_point_proto::messages::SlotConditions {
                    slot,
                    rtt_us: 20_000,
                    lost_packets: 5,
                    sent_packets: 2000,
                })
                .collect(),
        };

        // Send with conditions + sustained unacked redundancy (acks withheld).
        // The dynamic probe subtracts the sidecar's exact wire cost, so the
        // inner packet is sized to fit alongside it — no PayloadTooLarge.
        let drain = tokio::spawn(async move { while receiver.recv().await.is_ok() {} });

        for i in 0..100u64 {
            let payload = Payload {
                seq: i,
                slot: 0,
                commands: vec![i as u8; 4].into(),
                ..Default::default()
            };
            match sender.send(session, Some(payload), Some(conditions.clone())) {
                Ok(_) => {}
                Err(MeshLinkError::PayloadTooLarge { needed, budget }) => {
                    panic!(
                        "send {i} with conditions returned PayloadTooLarge: needed {needed}, \
                         budget {budget} — the dynamic probe should reserve exact wire cost, \
                         not a worst case that over-reserves"
                    );
                }
                Err(error) => panic!("send {i} failed unexpectedly: {error:?}"),
            }
        }

        drop(sender);
        let _ = drain.await;
    }

    /// `payload_fits` sizes against the same budget `send` applies: a routine
    /// turn fits (with or without a conditions sidecar), a turn beyond any
    /// datagram budget does not — the caller's cue to divert it to the mesh
    /// control stream instead of losing it to a refused `send`.
    #[tokio::test]
    async fn payload_fits_mirrors_the_send_budget() {
        let (mut sender, _receiver, _client_ep, _server_ep) = connected_mesh_links().await;
        let session = SessionId(1);
        sender.open_session(session);

        let small = turn(0, 0, 0xA0);
        assert!(sender.payload_fits(&small, None).unwrap());

        // A full 8-slot conditions sidecar shrinks the budget but not enough to
        // evict a routine turn.
        let conditions = LinkConditions {
            slots: (0..8u32)
                .map(|slot| rally_point_proto::messages::SlotConditions {
                    slot,
                    rtt_us: 20_000,
                    lost_packets: 5,
                    sent_packets: 2000,
                })
                .collect(),
        };
        assert!(sender.payload_fits(&small, Some(&conditions)).unwrap());

        // A turn far past any datagram budget must be diverted, and `send`
        // agrees: it refuses the same payload the pre-check rejected.
        let oversize = Payload {
            seq: 1,
            slot: 0,
            commands: vec![0xAB; 5000].into(),
            ..Default::default()
        };
        assert!(!sender.payload_fits(&oversize, None).unwrap());
        assert!(matches!(
            sender.send(session, Some(oversize), None),
            Err(MeshLinkError::PayloadTooLarge { .. })
        ));
    }

    /// `delivered_through_all` is the mesh ack-cursor push's source: it must
    /// report every slot that has actually delivered something (not just the
    /// one a caller happens to ask `delivered_through` for), stay empty for a
    /// session with nothing delivered yet, and never see slots or sessions it
    /// isn't asked about.
    #[tokio::test]
    async fn delivered_through_all_reflects_every_slot_with_a_delivered_prefix() {
        let (mut sender, mut receiver, _client_ep, _server_ep) = connected_mesh_links().await;

        let session_a = SessionId(1);
        let session_b = SessionId(2);
        sender.open_session(session_a);
        sender.open_session(session_b);
        receiver.open_session(session_a);
        receiver.open_session(session_b);

        // Nothing delivered yet: empty, not an error.
        assert_eq!(receiver.delivered_through_all(session_a), Vec::new());

        // Each slot needs its own contiguous prefix from seq 0 to register a
        // delivered-through cursor at all (an isolated high seq just sits in
        // the out-of-order `ahead` set) -- so slot 2 gets seqs 0..=5 while
        // slot 0 gets only seq 0, proving the two cursors are independent.
        sender
            .send(session_a, Some(turn(0, 0, 0xA0)), None)
            .unwrap();
        for seq in 0..=5u64 {
            let payload = Payload {
                seq,
                slot: 2,
                commands: vec![0xA1].into(),
                ..Default::default()
            };
            sender.send(session_a, Some(payload), None).unwrap();
        }
        for _ in 0..7 {
            receiver.recv().await.unwrap();
        }

        let mut cursors = receiver.delivered_through_all(session_a);
        cursors.sort_by_key(|&(slot, _)| slot.0);
        assert_eq!(cursors, vec![(SlotId(0), 0), (SlotId(2), 5)]);

        // Session B never received anything, so it stays empty even though
        // session A (sharing the same connection) has state now -- the
        // session must not enter the reported set.
        assert_eq!(receiver.delivered_through_all(session_b), Vec::new());
    }

    /// The physics `MESH_UNACKED_WINDOW_CAP` (relay crate) exists to bound:
    /// under genuine forward-path loss -- the peer never receives anything at
    /// all, so its own acks and any ack-cursor push it might send both never
    /// arrive -- a session's unacked window on this link grows without bound
    /// as the sender keeps producing. Mirrors the client edge's own
    /// `forward_path_sustained_loss_trips_the_unacked_window_cap`
    /// (`client::driver`) at `MeshLink` granularity: the peer's connection
    /// drains raw datagrams (so quinn's own buffer can't stall the sender)
    /// but never turns them into a `MeshLink`, so nothing is ever sent back.
    #[tokio::test]
    async fn sustained_forward_loss_grows_a_sessions_unacked_window_without_a_beacon_to_rescue_it()
     {
        let (mut sender, receiver, _client_ep, _server_ep) = connected_mesh_links().await;
        let session = SessionId(1);
        sender.open_session(session);

        let drainer = {
            let conn = receiver.connection().clone();
            tokio::spawn(async move {
                // "Receives" at the transport level (so the sender's datagrams
                // don't back up) but never becomes a MeshLink -- no dedup
                // advances, so nothing is ever sent back to the sender.
                while conn.read_datagram().await.is_ok() {}
            })
        };

        for i in 0..300u64 {
            let payload = Payload {
                seq: i,
                slot: 0,
                commands: vec![i as u8; 4].into(),
                ..Default::default()
            };
            sender.send(session, Some(payload), None).unwrap();
        }

        assert_eq!(
            sender.payloads_in_flight(session),
            300,
            "with nothing ever received back, every sent turn stays unacked -- \
             unbounded growth under sustained forward loss, exactly what the \
             relay's hard cap exists to catch",
        );

        drop(sender);
        drainer.abort();
    }

    #[test]
    fn should_dial_mesh_is_true_when_our_id_is_lower() {
        // The lower id dials the higher: this side connects, the peer accepts.
        assert!(should_dial_mesh(RelayId(1), RelayId(2)));
    }

    #[test]
    fn should_dial_mesh_is_false_when_our_id_is_higher() {
        // The higher id waits to accept — it does not dial back.
        assert!(!should_dial_mesh(RelayId(2), RelayId(1)));
    }

    #[test]
    fn should_dial_mesh_is_false_for_equal_ids() {
        // Two relays with the same id is a misconfiguration: neither dials
        // rather than both racing to connect.
        assert!(!should_dial_mesh(RelayId(5), RelayId(5)));
    }
}
