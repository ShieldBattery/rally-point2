//! The one error type a mesh-link send or receive fails with, plus the
//! conversion that lifts the shared per-link error into it.
//!
//! Kept apart from the link itself so the failure vocabulary a driver matches
//! on reads end to end without the transport logic in between.

use rally_point_proto::ids::{SessionId, SlotId};

use crate::ack_manager::{AckError, PacketSeqExhausted};
use crate::link::LinkError;

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
    Connection(#[from] noq::ConnectionError),
    /// A datagram could not be queued for sending.
    #[error("sending datagram failed: {0}")]
    Send(#[from] noq::SendDatagramError),
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
    /// [`LinkError::MalformedSlot`].
    #[error("payload names slot {0}, out of range for a SlotId (0..=255)")]
    MalformedSlot(u32),
    /// A received packet's acks were internally inconsistent. A peer-relay bug
    /// (the mesh trusts its peer); the driver decides whether to drop the session.
    #[error(transparent)]
    Ack(#[from] AckError),
    /// The session's `u32` packet sequence space is exhausted — see
    /// [`LinkError::PacketSeqExhausted`].
    #[error(transparent)]
    PacketSeqExhausted(#[from] PacketSeqExhausted),
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
            LinkError::PacketSeqExhausted(error) => MeshLinkError::PacketSeqExhausted(error),
        }
    }
}
