//! Protocol versioning + negotiation.
//!
//! netcode v2 components are deployed independently — the game DLL, the relay
//! fleet, and the coordinator each ship on their own cadence — so every
//! connection settles a protocol version before exchanging anything else. The
//! data-plane edges (client↔relay, relay↔relay QUIC) carry the version in their
//! ALPN strings, where a mismatch fails the TLS handshake outright. On top of
//! that, [`negotiate`] is enforced at two hello seams, where a *window* (or a
//! future graceful downgrade) is possible in a way an all-or-nothing ALPN string
//! is not:
//!
//! - **The relay control connection.** A relay's enroll `Hello` advertises its
//!   `[min_protocol, protocol]` window, and the coordinator negotiates before
//!   enrolling it — refusing an incompatible relay with a WebSocket close carrying
//!   [`CONTROL_CLOSE_PROTOCOL_MISMATCH`] rather than registering a relay it cannot
//!   drive.
//! - **The mesh identity hello.** The dialing relay's `MeshHello` names the single
//!   version it speaks (a degenerate window — the fixed frame has no room for two),
//!   and the *acceptor* negotiates before spawning the link driver — closing an
//!   incompatible connection with [`MESH_CLOSE_PROTOCOL_MISMATCH`]. The hello is
//!   one-way (dialer→acceptor) and every relay-pair has exactly one acceptor, so
//!   one side enforcing covers the pair.

use serde::{Deserialize, Serialize};

/// A netcode v2 wire-protocol version.
///
/// Bumped on any breaking change to [`crate::messages`], [`crate::control`], or
/// [`crate::token`] framing. Negotiation always selects the highest version
/// both peers support (see [`negotiate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    /// The version implemented by this build.
    ///
    /// `2` folds a TLS channel binding into the connection-binding challenge
    /// proof, which a v1 peer can neither produce nor verify.
    pub const CURRENT: ProtocolVersion = ProtocolVersion(2);

    /// The oldest version this build can still interoperate with.
    ///
    /// Held equal to [`Self::CURRENT`]: v2's proof change is a security fix —
    /// v1's challenge proof was replayable — so v1 is intentionally not
    /// interoperable. This drops below `CURRENT` only once we ship a wire version
    /// we *do* commit to interoperating with.
    pub const MIN_SUPPORTED: ProtocolVersion = ProtocolVersion(2);
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Negotiate the protocol version to use with a peer.
///
/// Given the peer's advertised `[peer_min, peer_max]` support window, returns
/// the highest version that both this build and the peer support, or
/// [`NegotiationError`] if the windows do not overlap.
pub fn negotiate(
    peer_min: ProtocolVersion,
    peer_max: ProtocolVersion,
) -> Result<ProtocolVersion, NegotiationError> {
    let chosen = peer_max.min(ProtocolVersion::CURRENT);
    let floor = peer_min.max(ProtocolVersion::MIN_SUPPORTED);
    if chosen >= floor {
        Ok(chosen)
    } else {
        Err(NegotiationError {
            local_min: ProtocolVersion::MIN_SUPPORTED,
            local_max: ProtocolVersion::CURRENT,
            peer_min,
            peer_max,
        })
    }
}

/// WebSocket close code the coordinator sends when it refuses a relay's control
/// connection because [`negotiate`] found no common version between the relay's
/// advertised window and its own. In the private-use close-code range
/// (4000–4999), so no WebSocket library or intermediary assigns it a meaning.
///
/// A cross-component contract: the coordinator sends it (with a reason naming
/// both windows — [`NegotiationError`]'s Display) *instead of enrolling*, and the
/// relay's coordinator client recognizes it to back off far longer than a normal
/// reconnect — a version mismatch is fixed by a deploy, not a redial.
pub const CONTROL_CLOSE_PROTOCOL_MISMATCH: u16 = 4001;

/// WebSocket close code the coordinator sends when it refuses a relay's control
/// connection because the relay enrolled tagged with a region the coordinator's
/// configuration does not list — including the case where the coordinator has no
/// region config at all. In the same private-use range (4000–4999) as
/// [`CONTROL_CLOSE_PROTOCOL_MISMATCH`], the sibling refusal that happens at the
/// same enroll seam.
///
/// A cross-component contract: the coordinator sends it (with a reason naming the
/// offered region) *instead of enrolling*, since a typo'd region tag that
/// silently serves nobody is worse than a failed enroll. The relay's coordinator
/// client recognizes it and backs off far longer than a normal reconnect — like a
/// version mismatch, the fix is a config/deploy change, not a redial.
pub const CONTROL_CLOSE_UNKNOWN_REGION: u16 = 4002;

/// QUIC application close code a mesh *acceptor* uses to refuse a dialing relay
/// whose advertised protocol version does not [`negotiate`] against its own.
/// Sent before the link driver is ever spawned, so an incompatible pair never
/// half-establishes. Outside the client-edge close-code space (`0x01`–`0x06`) so
/// a trace never reads one connection type's code through the other's table.
///
/// The dial side's reconnect supervision treats the closure like any failed
/// connection (redial on its ordinary delay); this code only lets it *name* the
/// refusal in its logs — mesh topology is coordinator-pushed, so a mismatched
/// pair stops being asked to connect once the fleet converges.
pub const MESH_CLOSE_PROTOCOL_MISMATCH: u32 = 0x10;

/// The local and peer protocol-version support windows have no version in common.
#[derive(Debug, Clone, thiserror::Error)]
#[error(
    "no common protocol version: local supports {local_min}..={local_max}, \
     peer supports {peer_min}..={peer_max}"
)]
pub struct NegotiationError {
    /// Lowest version this build supports.
    pub local_min: ProtocolVersion,
    /// Highest version this build supports.
    pub local_max: ProtocolVersion,
    /// Lowest version the peer advertised.
    pub peer_min: ProtocolVersion,
    /// Highest version the peer advertised.
    pub peer_max: ProtocolVersion,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiates_highest_common_version() {
        // Peer supports a wide window that includes ours.
        let v = negotiate(ProtocolVersion(1), ProtocolVersion(5)).unwrap();
        assert_eq!(v, ProtocolVersion::CURRENT);
    }

    #[test]
    fn rejects_disjoint_windows() {
        // Peer only speaks future versions this build doesn't support yet.
        assert!(negotiate(ProtocolVersion(7), ProtocolVersion(9)).is_err());
    }
}
