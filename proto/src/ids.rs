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
// TODO: pin the width/representation alongside the token layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);
