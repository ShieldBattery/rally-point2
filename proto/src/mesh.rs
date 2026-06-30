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

use crate::ids::RelayId;
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
}
