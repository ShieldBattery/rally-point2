//! One mesh link: a shared QUIC connection carrying every game two relays
//! jointly serve, with per-session transport state.
//!
//! A [`MeshLink`] owns one `noq::Connection` and a registry of [`SessionLink`]
//! instances — one per game active on that relay-pair. Every datagram on the
//! connection is a [`MeshPacket`]: a
//! session id (plus an optional tenant) and the per-link [`Packet`] for that
//! session. The link demultiplexes by [`MeshSessionKey`] — the session id
//! alone when a datagram carries no tenant, or the full `(session, tenant)`
//! pair when it does, so two sessions that happen to share a numeric id under
//! different tenants get independent transport state instead of colliding.
//! Each key's own [`AckManager`] and `Dedup` instance only ever sees its own
//! session's packets, so the origin `(slot, seq)` identity is unambiguous
//! within an instance — neither the session nor the tenant ever enters the
//! dedup/ack/retirement key itself.
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
//!
//! [`Packet`]: rally_point_proto::messages::Packet

mod error;
mod session_link;
mod sizing;

#[cfg(test)]
mod tests;

pub use error::MeshLinkError;
pub use session_link::SessionLink;

use std::collections::HashMap;

use prost::Message;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::{LinkConditions, MeshPacket, Payload};

use crate::ack_manager::AckManager;
use crate::link::{Dedup, Delivery, Received};
use sizing::{
    MESH_PACKET_OVERHEAD, conditions_element_len, packet_admission_floor, tenant_element_len,
};

/// A mesh link's per-session key: the bare session id a `MeshPacket` always
/// carries, plus the tenant it optionally stamps.
///
/// `MeshPacket.tenant` is additive on the wire (a sender that predates it, or
/// one with nothing to scope by, sends none), so this key mirrors that shape:
/// `None` groups with every other tenant-less registration under the same
/// bare id — the legacy path every pre-tenant caller keeps working through —
/// while `Some(tenant)` scopes a session to exactly that tenant, so two
/// sessions that happen to share a numeric id under different tenants get
/// wholly independent per-link transport state (their own [`AckManager`] +
/// `Dedup`) instead of colliding.
///
/// `MeshLink` never interprets the tenant string itself: validation,
/// uniqueness, and the tenant type's own invariants are
/// `rally_point_proto::control::TenantId`'s job, one layer up — this crate
/// doesn't depend on that control-plane type, so a plain `String` (not the
/// newtype) is what keeps this key transport-local. It only needs something
/// `Eq + Hash` to key its per-session map.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MeshSessionKey {
    /// The session id.
    pub session: SessionId,
    /// The tenant the key is scoped to, or `None` for the legacy (tenant-less)
    /// path.
    pub tenant: Option<String>,
}

impl MeshSessionKey {
    /// A tenant-scoped session key.
    pub fn new(session: SessionId, tenant: impl Into<String>) -> Self {
        Self {
            session,
            tenant: Some(tenant.into()),
        }
    }
}

impl From<SessionId> for MeshSessionKey {
    /// The legacy, tenant-less key. Lets a caller that predates tenant
    /// scoping (or genuinely has none to offer, like most of this module's
    /// own tests) keep calling `MeshLink`'s per-session methods with a bare
    /// `SessionId`, since they all accept `impl Into<MeshSessionKey>`.
    fn from(session: SessionId) -> Self {
        Self {
            session,
            tenant: None,
        }
    }
}

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
    connection: noq::Connection,
    sessions: HashMap<MeshSessionKey, SessionLink>,
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
    /// The tenant the sender stamped on this datagram, or `None` when it
    /// carried none — exactly what decided which session's transport state
    /// this datagram demultiplexed to (see [`MeshSessionKey`]), so a caller
    /// that needs the full identity back (rather than re-deriving it) can read
    /// it straight off here instead of the bare `session`.
    pub tenant: Option<String>,
    /// What the inner `Packet` delivered (new payloads, deduped) plus whether
    /// it carried payloads at all.
    pub delivery: Received,
    /// Per-client conditions the peer relay observed on its home clients this
    /// datagram, or `None` when the peer sent no conditions (an ack-only
    /// flush, or it has no local clients). See
    /// [`LinkConditions`].
    pub conditions: Option<LinkConditions>,
}

impl MeshLink {
    /// Wraps an established relay ↔ relay QUIC connection as a mesh link with no
    /// sessions yet. Open sessions with [`open_session`](Self::open_session) as
    /// games join this relay-pair.
    pub fn new(connection: noq::Connection) -> Self {
        Self {
            connection,
            sessions: HashMap::new(),
        }
    }

    /// The underlying QUIC connection. Shared across every session on this link.
    pub fn connection(&self) -> &noq::Connection {
        &self.connection
    }

    /// Opens a new session's transport state on this link. Idempotent: opening
    /// an already-open session (the same key) is a no-op (a relay may re-offer
    /// a session its peer already announced). Returns a borrow so the caller
    /// can drive the session without a separate lookup.
    ///
    /// `key` accepts a bare `SessionId` (the legacy, tenant-less path) or an
    /// explicit [`MeshSessionKey`] (tenant-scoped) — see that type's doc for
    /// what distinguishes them.
    pub fn open_session(&mut self, key: impl Into<MeshSessionKey>) -> &mut SessionLink {
        self.sessions
            .entry(key.into())
            .or_insert_with(|| SessionLink {
                acks: AckManager::new(),
                // Forward-collapsing rather than strict: a session enters a mesh
                // link mid-stream whenever a link redials or a relay joins a
                // running session, so its slots' seqs start wherever the game
                // currently is — a from-zero strict window would reject the live
                // stream forever, resetting the link in a loop. The mesh peer is
                // an authenticated relay, so the collapse's trust is warranted;
                // see `Dedup::with_forward_collapse`.
                dedup: Dedup::with_forward_collapse(),
            })
    }

    /// Anchors this link's receive window for `(key, slot)` to `anchor`,
    /// treating every seq below `anchor` as already delivered — the per-session
    /// twin of [`Link::anchor_receive_window`](crate::Link::anchor_receive_window).
    ///
    /// A session joins a mesh link mid-stream whenever the link redials (or the
    /// relay joins a running session), so the caller anchors each slot at the
    /// seq it actually still needs — its session-level forwarded-to-locals
    /// cursor — rather than leaving the window based at 0. The collapsing
    /// window (see [`open_session`](Self::open_session)) would recover from an
    /// unanchored base on its own, but only by walking the prefix forward
    /// through window pressure; the anchor starts it in the right place, so the
    /// delivered-through cursors this link reports to its peer are truthful
    /// from the first datagram.
    ///
    /// Only meaningful on a pristine slot (nothing received on this link yet);
    /// it never rewinds a prefix already forming. A no-op for a session (or
    /// key) that isn't open — callers anchor right after
    /// [`open_session`](Self::open_session).
    pub fn anchor_receive_window(
        &mut self,
        key: impl Into<MeshSessionKey>,
        slot: SlotId,
        anchor: u64,
    ) {
        if let Some(session_link) = self.sessions.get_mut(&key.into()) {
            session_link.dedup.anchor(slot, anchor);
        }
    }

    /// Folds a payload that arrived *outside* the datagram path — the reliable
    /// mesh control stream, where oversize turns ride — into `(key, slot)`'s
    /// receive state: the same per-slot dedup and delivered-prefix bookkeeping
    /// a datagram delivery runs, with no ack-state change (QUIC's stream
    /// reliability already guarantees the delivery). The per-session twin of
    /// [`Link::deliver_external`](crate::Link::deliver_external), and just as
    /// load-bearing here: a stream-delivered seq the dedup never learns about
    /// would hold a permanent gap in the slot's delivered prefix, stalling the
    /// ack-cursor push and pinning the peer's unacked window until the receive
    /// window collapses over it.
    ///
    /// Returns whether the payload is new (`true`) or an already-delivered
    /// duplicate (`false`). Sending for a session that isn't open is a driver
    /// bug, surfaced as [`UnknownSession`](MeshLinkError::UnknownSession) like
    /// [`send`](Self::send).
    pub fn deliver_external(
        &mut self,
        key: impl Into<MeshSessionKey>,
        slot: SlotId,
        seq: u64,
    ) -> Result<bool, MeshLinkError> {
        let key = key.into();
        let Some(session_link) = self.sessions.get_mut(&key) else {
            return Err(MeshLinkError::UnknownSession(key.session));
        };
        match session_link.dedup.accept(slot, seq) {
            Delivery::New => Ok(true),
            Delivery::Duplicate => Ok(false),
            Delivery::OutOfWindow => Err(MeshLinkError::PayloadOutOfWindow { slot, seq }),
        }
    }

    /// Drops a session's transport state. Called when the game ends or the
    /// peer-relay side for that session is gone. Idempotent: closing an absent
    /// session (or key) is a no-op.
    pub fn close_session(&mut self, key: impl Into<MeshSessionKey>) {
        self.sessions.remove(&key.into());
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
    /// `key` accepts a bare `SessionId` (the legacy, tenant-less path) or an
    /// explicit [`MeshSessionKey`] (tenant-scoped) — see that type's doc. When
    /// `key` carries a tenant, it is stamped onto the outgoing `MeshPacket` so
    /// the peer can demultiplex it against the right session even if another
    /// tenant happens to share the same numeric session id.
    ///
    /// `conditions` carries the sender relay's home-client link stats for the
    /// latency-buffer decision-maker. When present, its exact wire cost is
    /// measured with a prost `encoded_len` probe and subtracted from the packet
    /// budget — so the redundancy budget that defends lockstep latency is never
    /// stolen by a fixed worst-case reservation, and ack-only flushes (which
    /// carry no conditions) keep their full budget. A tenant-scoped `key` gets
    /// the same exact-cost treatment (a tag + length-prefix + body probe),
    /// since a tenant id can run far past a fixed margin. The inner `Packet` is then
    /// built to what's left of the budget *minus* `MESH_PACKET_OVERHEAD` (the
    /// inner-Packet field tag + length prefix that can't be probed without the
    /// packet itself), so the `MeshPacket` wrapper fits the datagram even when
    /// redundancy fills the inner packet — the client-edge [`Link::send`](crate::Link::send)
    /// needs no such reservation because its datagram *is* the `Packet`.
    pub fn send(
        &mut self,
        key: impl Into<MeshSessionKey>,
        payload: Option<Payload>,
        conditions: Option<LinkConditions>,
    ) -> Result<usize, MeshLinkError> {
        let key = key.into();
        let datagram_budget = self
            .connection
            .max_datagram_size()
            .ok_or(MeshLinkError::DatagramsUnsupported)?;
        let had_fresh = payload.is_some();

        let Some(session_link) = self.sessions.get_mut(&key) else {
            // Sending for a session that isn't open is a driver bug: the relay
            // opened it before routing turns to this link. Surface rather than
            // silently drop.
            return Err(MeshLinkError::UnknownSession(key.session));
        };
        // Measure the conditions sidecar's exact wire cost so the redundancy
        // budget that defends lockstep latency is never stolen by a fixed
        // worst-case reservation. A small or absent sidecar leaves the budget
        // intact; a large one reserves exactly what it needs. See
        // `conditions_element_len` for why this is the field's tag + length
        // prefix + body, not `encoded_len` alone.
        let conditions_overhead = conditions.as_ref().map(conditions_element_len).unwrap_or(0);
        // Same exact-cost treatment for the tenant this key carries, if any —
        // see `tenant_element_len`.
        let tenant_overhead = key.tenant.as_deref().map(tenant_element_len).unwrap_or(0);
        // The inner Packet's own field tag + varint length prefix can't be
        // probed without the packet itself, so MESH_PACKET_OVERHEAD covers it —
        // bounded (≤3 bytes for any packet under ~16MB) and small.
        let packet_budget = datagram_budget
            .saturating_sub(conditions_overhead)
            .saturating_sub(tenant_overhead)
            .saturating_sub(MESH_PACKET_OVERHEAD);
        // A payload that can never ride this session's datagrams is refused
        // *before* it is registered as unacked (mirroring `Link::send`) —
        // against the session's stable admission floor, and deliberately NOT
        // this send's conditions-bearing budget. The floor's inputs are
        // connection-lifetime constants, but `packet_budget` re-samples the
        // live datagram size, which noq's connection driver can shrink
        // between the caller's `payload_fits` preflight and this guard even
        // with no await between them — and the callers consume a refusal here
        // as a recoverable race, dropping the fresh turn outright. A
        // floor-admitted payload whose current envelope (a full conditions
        // sidecar atop a path-MTU fallback) has outgrown the datagram instead
        // registers below and fails the *datagram* send — unrecorded, so the
        // next sidecar-free flush re-carries it: a genuinely recoverable
        // bundle race rather than a lost turn. This stays the second line of
        // defense — the caller pre-checks with
        // [`payload_fits`](Self::payload_fits) and diverts oversize turns to
        // the mesh control stream before ever calling `send`.
        if let Some(p) = &payload {
            // A wire slot that doesn't fit a `SlotId` can't be tracked without
            // narrowing it onto a different, valid slot's bookkeeping, so it is
            // refused whole before any send-side state is built for it — the
            // outbound mirror of the ingress path's rejection of an out-of-range
            // received slot.
            if u8::try_from(p.slot).is_err() {
                return Err(MeshLinkError::MalformedSlot(p.slot));
            }
            let needed = crate::ack_manager::lone_packet_len(p);
            let admission = packet_admission_floor(datagram_budget, key.tenant.as_deref());
            if needed > admission {
                return Err(MeshLinkError::PayloadTooLarge {
                    needed,
                    budget: admission,
                });
            }
        }
        let packet = session_link.acks.build_outgoing(payload, packet_budget)?;
        // Everything in the packet except the fresh turn is a redundant re-carry.
        let redundant = packet.payloads.len() - usize::from(had_fresh);

        let mesh_packet = MeshPacket {
            session: key.session.0,
            packet: Some(packet),
            conditions,
            tenant: key.tenant.clone(),
        };
        let encoded = mesh_packet.encode_to_vec();
        let datagram_len = encoded.len();
        match self.connection.send_datagram(encoded.into()) {
            // Carry bookkeeping describes what reached the wire (see
            // `Link::send`): recorded on acceptance, never for a refused send.
            Ok(()) => {
                if let Some(session_link) = self.sessions.get_mut(&key) {
                    let packet = mesh_packet.packet.as_ref().expect("set above");
                    session_link.acks.record_sent(packet);
                }
                Ok(redundant)
            }
            Err(noq::SendDatagramError::TooLarge) => Err(MeshLinkError::PayloadTooLarge {
                needed: datagram_len,
                budget: datagram_budget,
            }),
            Err(error) => Err(error.into()),
        }
    }

    /// Whether `payload` can ride mesh datagrams for the rest of this
    /// connection's life: sized against the smaller of the send-time budget
    /// (the live `max_datagram_size()` minus the exact wire cost of the
    /// `conditions` sidecar and the `tenant` string that would accompany it,
    /// and the `MeshPacket` wrapper's own overhead) and the session's
    /// packet admission floor (`packet_admission_floor`). The floor is what keeps an admitted payload
    /// re-carryable forever: the live budget shrinks when noq's black-hole
    /// detector reacts to loss, and a payload admitted against a discovered
    /// budget could out-size every later packet (see
    /// [`GUARANTEED_DATAGRAM_BUDGET`](crate::ack_manager::GUARANTEED_DATAGRAM_BUDGET)).
    /// The caller's pre-check for the divert path — a payload this returns
    /// `false` for must go over the mesh control stream, never into `send`
    /// (which would refuse it anyway, but by then the caller has lost the
    /// payload to the move). Mirrors
    /// [`Link::payload_fits`](crate::Link::payload_fits) on the client edge;
    /// takes the conditions and tenant because the mesh send-time budget,
    /// unlike the client edge's, varies with what's attached to each send.
    pub fn payload_fits(
        &self,
        payload: &Payload,
        conditions: Option<&LinkConditions>,
        tenant: Option<&str>,
    ) -> Result<bool, MeshLinkError> {
        let datagram_budget = self
            .connection
            .max_datagram_size()
            .ok_or(MeshLinkError::DatagramsUnsupported)?;
        let conditions_overhead = conditions.map(conditions_element_len).unwrap_or(0);
        let tenant_overhead = tenant.map(tenant_element_len).unwrap_or(0);
        let packet_budget = datagram_budget
            .saturating_sub(conditions_overhead)
            .saturating_sub(tenant_overhead)
            .saturating_sub(MESH_PACKET_OVERHEAD)
            .min(packet_admission_floor(datagram_budget, tenant));
        Ok(crate::ack_manager::lone_packet_len(payload) <= packet_budget)
    }

    /// Awaits the next datagram, demultiplexes it by session (and, when
    /// present, tenant — see [`MeshSessionKey`]), folds its acks into that
    /// session's manager, and returns what it delivered: the session, the
    /// tenant the sender stamped (if any), the payloads not seen before
    /// (redundant copies dropped, in ascending seq order within each slot),
    /// whether the packet carried any payloads at all, and the per-client
    /// conditions the peer relay attached (if any).
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

        // The wire's own tenant (or its absence) decides the lookup key: a
        // tenant-stamped packet demuxes only against the matching tenant-scoped
        // session; a tenant-less one demuxes against the legacy bare-session
        // entry. This is never a fuzzy or fallback match — see `MeshSessionKey`.
        let key = MeshSessionKey {
            session,
            tenant: mesh_packet.tenant.clone(),
        };
        let Some(session_link) = self.sessions.get_mut(&key) else {
            return Err(MeshLinkError::UnknownSession(session));
        };

        let delivery = session_link.process_incoming(packet)?;
        Ok(MeshReceived {
            session,
            tenant: mesh_packet.tenant,
            delivery,
            conditions: mesh_packet.conditions,
        })
    }

    /// Payloads sent for `key` but not yet known-delivered — the in-flight
    /// depth, and the overflow signal the driver watches under sustained loss.
    /// Returns `0` for a session (or key) that isn't open (nothing in flight).
    pub fn payloads_in_flight(&self, key: impl Into<MeshSessionKey>) -> usize {
        self.sessions
            .get(&key.into())
            .map(|s| s.acks.payloads_in_flight())
            .unwrap_or(0)
    }

    /// The top of the contiguous run of payloads this link has delivered to its
    /// consumer for `(key, slot)`, or `None` before the session's first payload
    /// for that slot arrives. This is the per-slot cursor the beacon
    /// side-channel pushes to the peer so it can force-advance its unacked
    /// window past turns it now knows were received.
    pub fn delivered_through(&self, key: impl Into<MeshSessionKey>, slot: SlotId) -> Option<u64> {
        self.sessions
            .get(&key.into())
            .and_then(|s| s.dedup.delivered_through(slot))
    }

    /// Every slot's delivered-through cursor for `session`, for slots that
    /// have delivered at least one payload on this link. Empty (never an
    /// error) for a session that isn't open. This is the source the mesh
    /// ack-cursor push reads: the driver has no independent list of which
    /// remote slots a session carries, so it reads back exactly what this
    /// link's own receive state has actually seen.
    pub fn delivered_through_all(&self, key: impl Into<MeshSessionKey>) -> Vec<(SlotId, u64)> {
        self.sessions
            .get(&key.into())
            .map(|s| s.dedup.delivered_through_all())
            .unwrap_or_default()
    }

    /// Force-retires every unacked payload in `(key, slot)` up to
    /// `through_seq`, returning how many were dropped, *unless* `through_seq`
    /// is not strictly greater than the last cursor applied for that slot. A
    /// monotonic guard: the beacon stream is reliable-ordered, so cursors arrive
    /// in order, but a stream framing desync could produce a garbage `u64` —
    /// retiring turns the peer never confirmed would desync lockstep silently.
    /// Rejecting anything not strictly advancing turns such a desync into a
    /// harmless no-op. Returns `0` for a session (or key) that isn't open.
    pub fn retire_through(
        &mut self,
        key: impl Into<MeshSessionKey>,
        slot: SlotId,
        through_seq: u64,
    ) -> usize {
        let Some(session_link) = self.sessions.get_mut(&key.into()) else {
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
