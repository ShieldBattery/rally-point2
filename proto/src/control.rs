//! Control-plane messages.
//!
//! Reliable, lower-frequency messages that never ride the turn-datagram hot
//! path:
//!
//! - **coordinator ⇄ relay** — authenticated phone-home registry, session
//!   descriptors, and consensus *policy* (bounds/rates).
//! - **coordinator ⇄ app server** — session requests, token + home/backup relay
//!   handoff, per-tenant quotas.
//!
//! Consensus *decisions* are deliberately **not** here: the relay/mesh executes
//! per-turn latency/leave consensus keyed on [`crate::ids::GameFrameCount`], so
//! a coordinator outage never stalls a running game. What lives here is the
//! *policy* the coordinator sets at setup ([`BufferBounds`]) — the bounds the
//! relay's decision-maker clamps to — not the per-turn decision itself.
//!
//! Everything crossing a component boundary is defined here first, before the
//! coordinator logic modules that produce or consume it.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::ids::{RelayId, SessionId, SlotId};
use crate::token::ClientPublicKey;
use crate::version::ProtocolVersion;

// ---------------------------------------------------------------------------
// Tenancy
// ---------------------------------------------------------------------------

/// Identifies a coordinator tenant — prod, staging, or a specific developer.
///
/// Every tenant has its own signing key and quotas; this id scopes
/// registry entries, tokens, and observability data. Prod is an isolated
/// deployment with its own coordinator + key + fleet.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(pub String);

impl TenantId {
    /// Construct a tenant id, rejecting strings longer than
    /// [`crate::token::MAX_STRING_LEN`]. The token's wire format uses a `u8`
    /// length prefix, so a tenant id longer than 255 bytes cannot be encoded.
    pub fn new(s: impl Into<String>) -> Result<Self, crate::token::TokenError> {
        let s = s.into();
        if s.len() > crate::token::MAX_STRING_LEN {
            return Err(crate::token::TokenError::StringTooLong);
        }
        Ok(Self(s))
    }
}

impl From<TenantId> for String {
    fn from(tid: TenantId) -> String {
        tid.0
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Relay registry (coordinator ⇄ relay)
// ---------------------------------------------------------------------------

/// The first message a relay sends when it phones home to its coordinator.
///
/// The relay presents its coordinator-assigned id, its listen address (where
/// clients and peer relays reach it), and the protocol version it implements;
/// the coordinator records these in its registry and uses them to build
/// session descriptors and mesh topology.
///
/// Phone-home authentication (a coordinator-injected bootstrap secret) is
/// not yet enforced — the enroll endpoint is open for dev/loopback today.
///
/// `relay_addr` is the public address clients and peer relays connect to. It
/// serializes as the familiar `"ip:port"` string via serde's built-in
/// `SocketAddr` impl, which also validates the address at deserialize time
/// rather than deferring a parse failure into the logic layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RelayHello {
    /// The coordinator-assigned id for this relay. Stable across restarts of
    /// the same relay instance; unique within a fleet.
    pub relay_id: RelayId,
    /// Where clients and peer relays reach this relay (a direct public IP,
    /// not behind an anycast layer).
    pub relay_addr: SocketAddr,
    /// Protocol version the relay implements, for negotiation checking.
    pub protocol: ProtocolVersion,
}

impl RelayHello {
    /// Constructs a relay phone-home message.
    ///
    /// Provided because `RelayHello` is `#[non_exhaustive]`: future fields
    /// (e.g. capabilities, region) can be added without breaking external
    /// callers that construct it.
    pub fn new(relay_id: RelayId, relay_addr: SocketAddr, protocol: ProtocolVersion) -> Self {
        Self {
            relay_id,
            relay_addr,
            protocol,
        }
    }
}

/// One entry in the coordinator's relay registry: everything the coordinator
/// knows about a relay that has phoned home.
///
/// This is the coordinator's internal record, not a wire message — but it is
/// the source of the [`RelayPeer`] entries a session descriptor carries, and
/// of the relay topology the coordinator pushes. Defined here because the
/// fields it exposes cross the coordinator→relay boundary inside session
/// descriptors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEntry {
    /// The relay's coordinator-assigned id.
    pub relay_id: RelayId,
    /// Where clients and peer relays reach it.
    pub relay_addr: SocketAddr,
    /// Protocol version the relay reported at phone-home.
    pub protocol: ProtocolVersion,
}

impl From<&RelayEntry> for RelayPeer {
    fn from(e: &RelayEntry) -> Self {
        RelayPeer {
            relay_id: e.relay_id,
            relay_addr: e.relay_addr,
        }
    }
}

/// A peer relay in a session's mesh topology: the id and address a relay
/// needs to dial or accept a mesh connection from.
///
/// Carried inside a [`SessionDescriptor`] so each relay in a session learns
/// the lower-id side of each pair dials the higher (the `should_dial_mesh`
/// tie-break),
/// so the coordinator just lists the peers and each relay decides locally
/// which to dial — it needs the peer's id *before* connecting, which is why
/// the id rides here rather than being exchanged post-connect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPeer {
    /// The peer relay's coordinator-assigned id.
    pub relay_id: RelayId,
    /// Where the peer relay is reached.
    pub relay_addr: SocketAddr,
}

// ---------------------------------------------------------------------------
// Consensus policy (coordinator → relay, at session setup)
// ---------------------------------------------------------------------------

/// The latency-buffer bounds the coordinator sets at setup. The relay's
/// decision-maker stays within these; the coordinator only sets policy and
/// makes no per-adjustment decision, so a running game is unaffected by a
/// coordinator outage.
///
/// `min` is the floor (never below — StarCraft's `builtin_turn_latency` plus
/// a minimum user cushion); `max` is the ceiling (the coordinator's
/// provisioning budget / worst-case tolerance). The decision-maker clamps its
/// output to this range.
///
/// This type crosses the coordinator→relay boundary (the coordinator produces
/// it at session setup, the relay consumes it in its decision-maker), so it is
/// defined here — the relay re-exports it from `consensus` for callers that
/// reach it through that module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferBounds {
    /// The minimum buffer (in turns) the decision-maker may set.
    pub min: u32,
    /// The maximum buffer (in turns) the decision-maker may set.
    pub max: u32,
}

impl BufferBounds {
    /// Construct bounds, rejecting an empty or inverted range.
    ///
    /// `min` must be ≤ `max`. An empty range (`min == max`) is allowed: it
    /// pins the buffer to a fixed size, disabling the decision-maker's
    /// adjustments — a valid policy for a fixed-latency game.
    pub fn new(min: u32, max: u32) -> Result<Self, PolicyError> {
        if min > max {
            return Err(PolicyError::InvertedBounds { min, max });
        }
        Ok(Self { min, max })
    }

    /// Clamp `value` into `[min, max]`.
    pub fn clamp(&self, value: u32) -> u32 {
        value.clamp(self.min, self.max)
    }
}

/// A policy the coordinator sets is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The buffer bounds have `min > max`.
    #[error("buffer bounds inverted: min {min} > max {max}")]
    InvertedBounds { min: u32, max: u32 },
}

// ---------------------------------------------------------------------------
// Session setup (app server → coordinator → relay)
// ---------------------------------------------------------------------------

/// One player's handoff to the coordinator: the slot the app assigned and the
/// client's per-session Ed25519 public key (generated by the app before game
/// launch, so token issuance is off the game-startup critical path).
///
/// The coordinator mints a token binding this pubkey to the slot and session,
/// and returns it in the [`SessionResponse`] for the app to hand to the game
/// DLL at launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayerHandoff {
    /// The slot this player occupies in the game (0-based, matches the slot
    /// the relay binds every submitted turn to).
    pub slot: SlotId,
    /// The client's ephemeral Ed25519 public key, embedded in the token so
    /// the relay can verify the connection-binding challenge.
    pub client_pubkey: ClientPublicKey,
}

/// A request from an app server to stand up a game session: which tenant, how
/// many players, and each player's client pubkey.
///
/// The app server has already formed the lobby (matchmaking stays in the app
/// server, not the coordinator). The coordinator assigns home + backup relays,
/// mints one connection-bound token per player, and returns a
/// [`SessionResponse`] the app uses to hand each player `{token, relay_addr}`
/// at game launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRequest {
    /// The tenant requesting the session — its signing key will sign the
    /// tokens.
    pub tenant: TenantId,
    /// The players in the session, one per slot.
    pub players: Vec<PlayerHandoff>,
}

/// One player's completed handoff: the token the coordinator minted and the
/// relay address the client connects to.
///
/// The app passes `{token, private_key, relay_addr}` to the game DLL at
/// launch. The private key is the counterpart to the `client_pubkey` the app
/// already generated and sent in the [`PlayerHandoff`]; it never left the
/// trusted local process, so it is not carried here — the app held onto it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlayerToken {
    /// The slot this token authorizes.
    pub slot: SlotId,
    /// The connection-bound, per-tenant authorization token. Encoded as the
    /// [`SignedToken`](crate::token::SignedToken) wire format (length-prefixed
    /// binary, not protobuf) so the client presents it verbatim to the relay.
    #[serde(with = "serde_bytes")]
    pub token: Vec<u8>,
}

/// The coordinator's response to a session request: the session id, the
/// relay topology, the per-player tokens, and the consensus policy bounds.
///
/// The relay topology drives the mesh edge: each relay in the session
/// receives a [`SessionDescriptor`] naming its peers, and the lower-id side
/// of each pair dials. The home relay is the one clients connect to; the
/// backup is the failover target (the failover mechanism is still open).
/// The policy bounds are pushed to each relay's decision-maker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResponse {
    /// The coordinator-assigned session id (unique within the tenant).
    pub session: SessionId,
    /// The relay clients connect to.
    pub home_relay: RelayPeer,
    /// The backup relay for failover (may equal `home_relay` if only one
    /// relay is available — degraded single-relay operation).
    pub backup_relay: RelayPeer,
    /// One token per player, matching the slots in the request.
    pub tokens: Vec<PlayerToken>,
    /// The latency-buffer bounds the relay's decision-maker clamps to.
    pub bounds: BufferBounds,
}

/// The descriptor a coordinator pushes to each relay serving a session: the
/// session id, the tenant, the relay's mesh peers for this session, and the
/// consensus policy bounds.
///
/// This is what drives `MeshCommand::Join` in production: the coordinator
/// pushes a descriptor to each relay serving a session, and the relay joins
/// that session on the mesh link to each listed peer. The relay's
/// decision-maker is created with `bounds` and (for the home relay)
/// `Authority::SelfRelay`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDescriptor {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The coordinator-assigned session id.
    pub session: SessionId,
    /// The relay's mesh peers for this session — the other relays serving
    /// the same game. Each relay dials the lower-id side of each pair.
    pub peers: Vec<RelayPeer>,
    /// The latency-buffer bounds the relay's decision-maker clamps to.
    pub bounds: BufferBounds,
}

/// serde helper for opaque byte slices (token wire bytes).
mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(d)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use crate::ids::{RelayId, SessionId, SlotId};
    use crate::token::ClientPublicKey;

    #[test]
    fn buffer_bounds_new_rejects_inverted() {
        assert!(BufferBounds::new(5, 3).is_err());
    }

    #[test]
    fn buffer_bounds_new_allows_empty_range() {
        // min == max pins the buffer (fixed-latency game).
        let b = BufferBounds::new(3, 3).unwrap();
        assert_eq!(b.clamp(0), 3);
        assert_eq!(b.clamp(99), 3);
    }

    #[test]
    fn buffer_bounds_clamp() {
        let b = BufferBounds::new(2, 8).unwrap();
        assert_eq!(b.clamp(0), 2);
        assert_eq!(b.clamp(5), 5);
        assert_eq!(b.clamp(99), 8);
    }

    #[test]
    fn relay_hello_roundtrips_json() {
        let hello = RelayHello {
            relay_id: RelayId(7),
            relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            protocol: ProtocolVersion::CURRENT,
        };
        let json = serde_json::to_string(&hello).unwrap();
        let back: RelayHello = serde_json::from_str(&json).unwrap();
        assert_eq!(back, hello);
    }

    #[test]
    fn session_descriptor_roundtrips_json() {
        let desc = SessionDescriptor {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
            peers: vec![RelayPeer {
                relay_id: RelayId(2),
                relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
            }],
            bounds: BufferBounds::new(1, 6).unwrap(),
        };
        let json = serde_json::to_string(&desc).unwrap();
        let back: SessionDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(back, desc);
    }

    #[test]
    fn session_response_roundtrips_json() {
        let resp = SessionResponse {
            session: SessionId(1),
            home_relay: RelayPeer {
                relay_id: RelayId(1),
                relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            },
            backup_relay: RelayPeer {
                relay_id: RelayId(2),
                relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
            },
            tokens: vec![PlayerToken {
                slot: SlotId(0),
                token: vec![0xAB, 0xCD],
            }],
            bounds: BufferBounds::new(1, 6).unwrap(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: SessionResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn player_handoff_carries_pubkey() {
        let h = PlayerHandoff {
            slot: SlotId(3),
            client_pubkey: ClientPublicKey([0x42; 32]),
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: PlayerHandoff = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
    }
}
