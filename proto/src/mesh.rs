//! Sans-I/O codec for the relay↔relay mesh-link identity hello.
//!
//! When two relays establish a mesh connection, the lower-id side dials and the
//! higher-id side accepts. Which side dials is a *pre-connect* local decision
//! made from configured (later coordinator-pushed) topology — the dialer already
//! knows whom it dialed. The acceptor does not: it sees only an inbound QUIC
//! connection arriving from an ephemeral source port, with no way to tell *which*
//! peer relay just connected. So immediately after the connection completes, the
//! dialer announces itself with a [`MeshHello`], and the acceptor reads it to
//! label the established link with the peer's id.
//!
//! That label is what lets a relay target a session join to the specific link
//! serving that session's peer, rather than broadcasting to every link it holds.
//! This is purely a *labeling* exchange — it does not decide which side dials
//! (that was already settled before connecting) and carries no authority; a
//! peer's claimed id is trusted only as far as the connection's certificate
//! already is (relay-to-relay authentication is a separate, later concern).
//!
//! The hello is a fixed [`MESH_HELLO_LEN`]-byte frame — an 8-byte little-endian
//! relay id followed by a 2-byte little-endian protocol version — so the reader
//! takes exactly that many bytes with no length prefix to bound. The stream
//! reads and writes stay with the caller; this module only frames and unframes,
//! so neither async I/O nor a QUIC backend leaks in here (mirroring the
//! authorization [`handshake`](crate::handshake) codec).
//!
//! The same streams then carry **presence**: each relay tells its peer how many
//! live home clients it serves per session ([`MeshPresence`]), which is what
//! drives buffer-authority handoff when the deciding relay's players all leave.
//! Presence rides a reliable stream rather than the datagram path because the
//! transition it reports is exactly when the sender's datagrams dry up: a relay
//! whose players have all left originates no turns and re-carries nothing, so a
//! datagram sidecar would stop flowing at the one moment it matters. The dialer
//! keeps its hello stream open and appends presence frames after the hello; the
//! acceptor opens its own unidirectional stream carrying presence frames alone.
//! Each side thus opens exactly one uni-stream, so the reader never has to
//! guess a stream's kind.

use crate::ids::{RelayId, SessionId};
use crate::version::ProtocolVersion;

/// The identity a dialing relay announces to the relay that accepted its mesh
/// connection: its coordinator-assigned id and the protocol version it speaks.
///
/// The acceptor uses `relay_id` to label the link (so a later session join can
/// target it) and `protocol` to spot a version skew between independently
/// deployed relays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshHello {
    /// The announcing relay's coordinator-assigned id.
    pub relay_id: RelayId,
    /// The protocol version the announcing relay implements.
    pub protocol: ProtocolVersion,
}

/// Size of the fixed mesh-hello wire frame: an 8-byte relay id plus a 2-byte
/// protocol version, both little-endian. The reader takes exactly this many
/// bytes — there is no length prefix because every field is fixed-width.
pub const MESH_HELLO_LEN: usize = 8 + 2;

impl MeshHello {
    /// Constructs a mesh hello announcing `relay_id` at `protocol`.
    pub fn new(relay_id: RelayId, protocol: ProtocolVersion) -> Self {
        Self { relay_id, protocol }
    }

    /// Encodes the hello as its fixed-size wire frame. The dialer writes the
    /// returned bytes to a freshly opened unidirectional stream.
    pub fn encode(&self) -> [u8; MESH_HELLO_LEN] {
        let mut frame = [0u8; MESH_HELLO_LEN];
        frame[..8].copy_from_slice(&self.relay_id.0.to_le_bytes());
        frame[8..].copy_from_slice(&self.protocol.0.to_le_bytes());
        frame
    }

    /// Decodes a hello from its fixed-size wire frame. Infallible: the frame is
    /// a fixed-width array the acceptor fills with one `read_exact`, so there is
    /// no length to validate and no allocation driven by peer-supplied bytes.
    pub fn decode(frame: [u8; MESH_HELLO_LEN]) -> Self {
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&frame[..8]);
        let mut protocol_bytes = [0u8; 2];
        protocol_bytes.copy_from_slice(&frame[8..]);
        Self {
            relay_id: RelayId(u64::from_le_bytes(id_bytes)),
            protocol: ProtocolVersion(u16::from_le_bytes(protocol_bytes)),
        }
    }
}

/// One relay's live home-client count for one session, announced to a mesh
/// peer whenever it changes (and re-announced when a link or session join is
/// (re)established, so a fresh stream starts from a known state).
///
/// This is the presence signal buffer-authority handoff keys on: the relays sit
/// in a coordinator-assigned priority order, and the first one still serving
/// live players is the decision-maker — so each relay must know, per session,
/// whether its peers still serve anyone. A count rather than a boolean so the
/// signal stays useful to consumers that care how many (debug UIs, future
/// presence reporting); the authority rule only reads "zero or not".
///
/// Within one stream, frames for the same session supersede each other in
/// stream order — the reliable stream gives that ordering for free, which is
/// why presence does not need a sequence number of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshPresence {
    /// The session the count belongs to, scoped by the mesh link's tenant
    /// context exactly like a `MeshPacket`'s bare session id.
    pub session: SessionId,
    /// How many live home clients the announcing relay currently serves for
    /// this session. Zero means the relay is no longer serving players — the
    /// handoff trigger.
    pub live_players: u32,
}

/// Size of the fixed presence wire frame: an 8-byte session id plus a 4-byte
/// live-player count, both little-endian. Like the hello, every field is
/// fixed-width so the reader takes exactly this many bytes with no length
/// prefix to validate.
pub const MESH_PRESENCE_LEN: usize = 8 + 4;

impl MeshPresence {
    /// Encodes the announcement as its fixed-size wire frame.
    pub fn encode(&self) -> [u8; MESH_PRESENCE_LEN] {
        let mut frame = [0u8; MESH_PRESENCE_LEN];
        frame[..8].copy_from_slice(&self.session.0.to_le_bytes());
        frame[8..].copy_from_slice(&self.live_players.to_le_bytes());
        frame
    }

    /// Decodes an announcement from its fixed-size wire frame. Infallible for
    /// the same reason as [`MeshHello::decode`]: fixed-width fields, no
    /// peer-driven allocation.
    pub fn decode(frame: [u8; MESH_PRESENCE_LEN]) -> Self {
        let mut session_bytes = [0u8; 8];
        session_bytes.copy_from_slice(&frame[..8]);
        let mut live_bytes = [0u8; 4];
        live_bytes.copy_from_slice(&frame[8..]);
        Self {
            session: SessionId(u64::from_le_bytes(session_bytes)),
            live_players: u32::from_le_bytes(live_bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_round_trips_through_its_fixed_frame() {
        let hello = MeshHello::new(RelayId(0x0102_0304_0506_0708), ProtocolVersion(0x0A0B));
        assert_eq!(MeshHello::decode(hello.encode()), hello);
    }

    #[test]
    fn frame_is_little_endian_id_then_version() {
        let hello = MeshHello::new(RelayId(1), ProtocolVersion::CURRENT);
        let frame = hello.encode();
        assert_eq!(&frame[..8], &1u64.to_le_bytes());
        assert_eq!(&frame[8..], &ProtocolVersion::CURRENT.0.to_le_bytes());
        assert_eq!(frame.len(), MESH_HELLO_LEN);
    }

    #[test]
    fn decodes_max_values_without_panicking() {
        let hello = MeshHello::new(RelayId(u64::MAX), ProtocolVersion(u16::MAX));
        assert_eq!(MeshHello::decode(hello.encode()), hello);
    }

    #[test]
    fn presence_round_trips_through_its_fixed_frame() {
        let presence = MeshPresence {
            session: SessionId(0x0102_0304_0506_0708),
            live_players: 0x0A0B_0C0D,
        };
        assert_eq!(MeshPresence::decode(presence.encode()), presence);
        // Zero live players — the handoff trigger — must survive verbatim.
        let empty = MeshPresence {
            session: SessionId(u64::MAX),
            live_players: 0,
        };
        assert_eq!(MeshPresence::decode(empty.encode()), empty);
    }

    #[test]
    fn presence_frame_is_little_endian_session_then_count() {
        let presence = MeshPresence {
            session: SessionId(7),
            live_players: 3,
        };
        let frame = presence.encode();
        assert_eq!(&frame[..8], &7u64.to_le_bytes());
        assert_eq!(&frame[8..], &3u32.to_le_bytes());
        assert_eq!(frame.len(), MESH_PRESENCE_LEN);
    }
}
