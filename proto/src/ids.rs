//! Typed turn coordinates and ids used across the netcode v2 logic layers.
//!
//! These are the *domain* types the client, transport, relay, and coordinator
//! code pass around. The on-wire protobuf messages (which use raw integers) live
//! in [`crate::messages`]; convert at the boundary.

use serde::{Deserialize, Serialize};

/// The shared turn coordinate: SC:R's `game_frame_count`.
///
/// Runtime latency/leave consensus is keyed on this value — not on a
/// transport-local sequence number — so the relay, every mesh peer, and the
/// client all agree on *which* turn a decision applies to. SC:R advances it at
/// 24 turns/sec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GameFrameCount(pub u32);

/// A player's 0-based slot within a game.
///
/// The relay binds each submitted turn to the slot carried by the sender's token
/// to prevent slot-spoofing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SlotId(pub u8);

/// Identifies one game session, assigned by the coordinator at session setup.
///
/// One axis of the `tenant/session/slot/turn` observability correlation key.
/// Carried in the authorization token as a little-endian u64 (8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identifies one relay in the mesh, assigned by the coordinator.
///
/// The mesh link-establishment tie-break is a *pre-connect* local decision:
/// when two relays could each dial the other, exactly one must, or both
/// connections complete and one is torn down as redundant. The rule is
/// "the lower id dials the higher" — each side compares its own id to the
/// peer's *configured* id and connects only if it is the lower. The higher
/// id stays in its accept loop and lets the dial arrive, so there is no race
/// to resolve on the wire. The tie-break therefore needs the peer's id known
/// ahead of time (from the coordinator-assigned topology, Phase 3), not
/// discovered by exchanging ids over a stream — by the time such an exchange
/// could run, the dial that needed deciding has already happened.
///
/// Real relay-to-relay authentication and tenant binding land with the
/// coordinator (Phase 3); the id is the ordering key that establishment needs
/// before that, and nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RelayId(pub u64);

impl std::fmt::Display for RelayId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
