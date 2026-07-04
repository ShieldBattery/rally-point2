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

/// The first frame a relay sends on its control connection, enrolling it into
/// the coordinator's registry (wrapped in [`RelayToCoordinator::Hello`]).
///
/// The relay presents its coordinator-assigned id, its advertised address (where
/// clients and peer relays reach it), the protocol version it implements, and
/// the TLS leaf certificate clients pin to connect to it; the coordinator
/// records these in its registry and uses them to build session responses,
/// session descriptors, and mesh topology.
///
/// The control connection that carries this is authenticated by a
/// coordinator-issued bootstrap secret (fail-closed: the coordinator refuses to
/// serve it unauthenticated without an explicit insecure opt-in). The relay id
/// here is still an unverified claim — binding the connection to a relay identity
/// is deferred to the relay-identity / mTLS work.
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
    /// DER encoding of the TLS leaf certificate the relay serves on its client
    /// edge. The coordinator forwards it in session responses so clients pin
    /// exactly this cert — self-signed relay certs stay trusted without any
    /// out-of-band cert distribution.
    #[serde(with = "serde_bytes")]
    pub cert_der: Vec<u8>,
}

impl RelayHello {
    /// Constructs a relay phone-home message.
    ///
    /// Provided because `RelayHello` is `#[non_exhaustive]`: future fields
    /// (e.g. capabilities, region) can be added without breaking external
    /// callers that construct it.
    pub fn new(
        relay_id: RelayId,
        relay_addr: SocketAddr,
        protocol: ProtocolVersion,
        cert_der: Vec<u8>,
    ) -> Self {
        Self {
            relay_id,
            relay_addr,
            protocol,
            cert_der,
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
    /// DER of the TLS leaf certificate the relay reported at phone-home —
    /// what clients pin to connect to it (carried in session responses).
    #[serde(with = "serde_bytes")]
    pub cert_der: Vec<u8>,
}

impl From<&RelayEntry> for RelayPeer {
    fn from(e: &RelayEntry) -> Self {
        RelayPeer {
            relay_id: e.relay_id,
            relay_addr: e.relay_addr,
            cert_der: e.cert_der.clone(),
        }
    }
}

/// A client-facing relay endpoint in a session response: where clients connect
/// and the TLS leaf certificate they pin to do it.
///
/// This is the app-server's (and ultimately the game client's) view of a relay
/// — unlike [`RelayPeer`], which rides in session *descriptors* for
/// relay-to-relay meshing (and pins the same enrolled cert for the mesh dial).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEndpoint {
    /// The relay's coordinator-assigned id.
    pub relay_id: RelayId,
    /// Where clients reach the relay.
    pub relay_addr: SocketAddr,
    /// DER of the TLS leaf certificate the relay serves; clients pin exactly
    /// this cert, so self-signed relay certs work without out-of-band
    /// distribution.
    #[serde(with = "serde_bytes")]
    pub cert_der: Vec<u8>,
}

impl From<&RelayEntry> for RelayEndpoint {
    fn from(e: &RelayEntry) -> Self {
        RelayEndpoint {
            relay_id: e.relay_id,
            relay_addr: e.relay_addr,
            cert_der: e.cert_der.clone(),
        }
    }
}

/// A peer relay in a session's mesh topology: the id, address, and pinned
/// certificate a relay needs to dial (or accept) a mesh connection.
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
    /// DER of the TLS leaf certificate the peer relay reported at enrollment —
    /// the same cert clients pin from a session response. The dialing relay
    /// pins exactly this cert for the mesh connection, so independently
    /// self-signed relay certs trust each other with no out-of-band
    /// distribution (mirroring [`RelayEndpoint::cert_der`] on the client edge).
    /// Defaults to empty on a descriptor from a coordinator that predates the
    /// field; the dialer then falls back to its configured mesh roots.
    #[serde(default, with = "serde_bytes")]
    pub cert_der: Vec<u8>,
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
    /// The relay clients connect to, including the cert they pin.
    pub home_relay: RelayEndpoint,
    /// The backup relay for failover (may equal `home_relay` if only one
    /// relay is available — degraded single-relay operation).
    pub backup_relay: RelayEndpoint,
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
/// decision-maker is created with `bounds`, and its authority verdict follows
/// `authority_order` plus the live presence the relays exchange among
/// themselves.
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
    /// The coordinator-assigned buffer-authority priority order: every relay
    /// serving this session (including the one this descriptor is for), most
    /// preferred first. The first relay in the order still serving live
    /// players is the session's decision-maker, and authority falls to the
    /// next as relays' players leave — a presence-driven handoff the relays
    /// run among themselves, with no coordinator round-trip. The coordinator
    /// only *ranks* the relays (home relay first, since it was chosen for the
    /// session's latency profile); it plays no part in the live verdict.
    ///
    /// Defaults empty for descriptors from a coordinator that predates the
    /// field; a relay falls back to relay-id order over the session's relay
    /// set — the interim rule this order replaces.
    #[serde(default)]
    pub authority_order: Vec<RelayId>,
}

// ---------------------------------------------------------------------------
// Persistent control connection (coordinator ⇄ relay)
// ---------------------------------------------------------------------------

/// A message the coordinator sends down the persistent control connection a
/// relay holds open to it.
///
/// The connection is the relay's single, authenticated control channel: the
/// coordinator pushes mesh topology down it, and (as the control plane grows)
/// the relay reports liveness up it. This enum is the **down** direction. It is
/// tagged so the channel can carry new message kinds without a wire break — a
/// relay and coordinator deploy independently, so during a rolling deploy a newer
/// coordinator may send a message kind an older relay does not know. The
/// [`Unknown`](Self::Unknown) catch-all makes that a *skip* rather than a parse
/// error: an unrecognized `type` deserializes to `Unknown` instead of failing, so
/// an older relay ignores the new message and keeps its connection rather than
/// churning it.
///
/// The descriptor set is **declarative current state**, not a stream of deltas:
/// the coordinator sends the relay's whole current set on connect (so a
/// reconnecting relay re-syncs) and again whenever it changes, and the relay
/// applies it idempotently. Re-sending the same set is a no-op on the relay, so
/// the channel never has to guarantee exactly-once delivery — losing a message
/// to a dropped connection just means the next one (on reconnect) carries the
/// current truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoordinatorToRelay {
    /// The relay's full current session-descriptor set — every session this
    /// relay should serve, each naming that session's mesh peers. The relay
    /// joins the named peers' links and leaves any session no longer present.
    Descriptors {
        /// The descriptors, one per session this relay currently serves.
        descriptors: Vec<SessionDescriptor>,
    },
    /// A message kind this build does not recognize — a newer coordinator sent
    /// one this relay's protocol version predates. An unknown `type` decodes here
    /// (rather than erroring), so the relay skips it and keeps the connection. The
    /// payload is intentionally dropped: a relay can't act on a message it doesn't
    /// understand, only refrain from breaking on it.
    #[serde(other)]
    Unknown,
}

/// A message a relay sends **up** the persistent control connection it holds to
/// the coordinator — the counterpart to [`CoordinatorToRelay`].
///
/// The first frame a relay sends is its [`Hello`](Self::Hello): it enrolls the
/// relay into the coordinator's registry over the same authenticated connection
/// that then carries descriptor pushes back down, so a relay has one channel to
/// the coordinator rather than a separate phone-home. After enrolling, the relay
/// sends a periodic [`Heartbeat`](Self::Heartbeat) so the coordinator can tell a
/// live relay from one whose connection has silently died. Tagged and
/// forward-compatible the same way as the down direction — a message kind a newer
/// relay sends that an older coordinator predates decodes to
/// [`Unknown`](Self::Unknown) and is skipped rather than tearing the connection
/// down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayToCoordinator {
    /// The relay's identity and reachable address, sent as the first frame to
    /// enroll into the coordinator's registry.
    Hello(RelayHello),
    /// A periodic presence ping proving the control connection is still alive.
    ///
    /// The coordinator resets a per-connection liveness deadline on each one;
    /// when enough are missed — a relay that crashed, or a TCP connection that
    /// died without ever sending a close — the deadline lapses, the coordinator
    /// drops the connection and deregisters the relay. It carries no payload:
    /// presence is the whole signal. Richer periodic status (session count, load)
    /// can ride a later frame, which the forward-compatible envelope already
    /// accommodates without a wire break.
    Heartbeat,
    /// A message kind this coordinator does not recognize (a newer relay). Decodes
    /// here so the coordinator skips it rather than dropping the connection.
    #[serde(other)]
    Unknown,
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
            cert_der: vec![0x30, 0x82, 0xAA, 0xBB],
        };
        let json = serde_json::to_string(&hello).unwrap();
        let back: RelayHello = serde_json::from_str(&json).unwrap();
        assert_eq!(back, hello);
    }

    #[test]
    fn coordinator_to_relay_descriptors_roundtrips_json() {
        let message = CoordinatorToRelay::Descriptors {
            descriptors: vec![SessionDescriptor {
                tenant: TenantId("sb-staging".to_owned()),
                session: SessionId(42),
                peers: vec![RelayPeer {
                    relay_id: RelayId(2),
                    relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
                    cert_der: vec![0x30, 0x82, 0xCC, 0xDD],
                }],
                bounds: BufferBounds::new(1, 6).unwrap(),
                authority_order: vec![RelayId(1), RelayId(2)],
            }],
        };
        let json = serde_json::to_string(&message).unwrap();
        // The tagged frame is self-describing: a `type` discriminator names the
        // variant so the channel can grow new message kinds.
        assert!(json.contains("\"type\":\"descriptors\""));
        let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn coordinator_to_relay_unknown_type_decodes_to_unknown_not_an_error() {
        // Forward compatibility: a message kind a newer coordinator added, which
        // this build predates, must decode to `Unknown` rather than failing — so
        // an older relay skips it instead of tearing down its control connection.
        let json = r#"{"type":"some_future_message","extra":123}"#;
        let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, CoordinatorToRelay::Unknown);
    }

    #[test]
    fn relay_to_coordinator_hello_roundtrips_json() {
        let message = RelayToCoordinator::Hello(RelayHello::new(
            RelayId(3),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            ProtocolVersion::CURRENT,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        ));
        let json = serde_json::to_string(&message).unwrap();
        // The Hello's fields ride alongside the tag (internally tagged).
        assert!(json.contains("\"type\":\"hello\""));
        assert!(json.contains("\"relay_id\""));
        let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn relay_to_coordinator_heartbeat_roundtrips_json() {
        let message = RelayToCoordinator::Heartbeat;
        let json = serde_json::to_string(&message).unwrap();
        // A payload-free presence ping: just the tag, no other fields.
        assert_eq!(json, r#"{"type":"heartbeat"}"#);
        let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn relay_to_coordinator_unknown_type_decodes_to_unknown_not_an_error() {
        // The up direction is forward-compatible too: a frame a newer relay sends
        // that an older coordinator predates decodes to `Unknown`, not an error.
        let json = r#"{"type":"future_up_frame","x":1}"#;
        let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, RelayToCoordinator::Unknown);
    }

    #[test]
    fn session_descriptor_roundtrips_json() {
        let desc = SessionDescriptor {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
            peers: vec![RelayPeer {
                relay_id: RelayId(2),
                relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
                cert_der: vec![0x30, 0x82, 0xCC, 0xDD],
            }],
            bounds: BufferBounds::new(1, 6).unwrap(),
            authority_order: vec![RelayId(1), RelayId(2)],
        };
        let json = serde_json::to_string(&desc).unwrap();
        let back: SessionDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(back, desc);
    }

    #[test]
    fn session_descriptor_without_authority_order_decodes_to_empty() {
        // A descriptor from a coordinator that predates the authority order —
        // and the peer cert — must still decode (the relay falls back to
        // relay-id order, and to its configured mesh roots for the dial) rather
        // than tearing down the control connection over a missing field.
        let json = r#"{
            "tenant":"sb-staging","session":42,
            "peers":[{"relay_id":2,"relay_addr":"127.0.0.1:14901"}],
            "bounds":{"min":1,"max":6}
        }"#;
        let back: SessionDescriptor = serde_json::from_str(json).unwrap();
        assert!(back.authority_order.is_empty());
        assert!(
            back.peers[0].cert_der.is_empty(),
            "a peer without a cert decodes to an empty pin (mesh-roots fallback)",
        );
    }

    #[test]
    fn session_response_roundtrips_json() {
        let resp = SessionResponse {
            session: SessionId(1),
            home_relay: RelayEndpoint {
                relay_id: RelayId(1),
                relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
                cert_der: vec![0x30, 0x82, 0x01, 0x02],
            },
            backup_relay: RelayEndpoint {
                relay_id: RelayId(2),
                relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
                cert_der: vec![0x30, 0x82, 0x03, 0x04],
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
