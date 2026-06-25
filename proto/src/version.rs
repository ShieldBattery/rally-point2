//! Protocol versioning + negotiation.
//!
//! netcode v2 components are deployed independently — the game DLL, the relay
//! fleet, and the coordinator each ship on their own cadence — so every
//! connection negotiates a protocol version before exchanging turns.

use serde::{Deserialize, Serialize};

/// A netcode v2 wire-protocol version.
///
/// Bumped on any breaking change to [`crate::wire`], [`crate::control`], or
/// [`crate::token`] framing. Negotiation always selects the highest version
/// both peers support (see [`negotiate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    /// The version implemented by this build.
    pub const CURRENT: ProtocolVersion = ProtocolVersion(1);

    /// The oldest version this build can still interoperate with.
    ///
    /// Held equal to [`Self::CURRENT`] until we ship a second wire version and
    /// commit to backward compatibility; it then drops to the oldest supported.
    pub const MIN_SUPPORTED: ProtocolVersion = ProtocolVersion(1);
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
