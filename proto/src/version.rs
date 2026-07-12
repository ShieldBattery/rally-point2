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
    /// `3` adds proof-of-possession to relay enrollment: after the enroll
    /// `Hello` and version negotiation, the coordinator challenges the relay
    /// with a random nonce
    /// ([`CoordinatorToRelay::IdentityChallenge`](crate::control::CoordinatorToRelay::IdentityChallenge))
    /// and the relay must answer with a signature made by the TLS private key
    /// matching `Hello.cert_der`
    /// ([`RelayToCoordinator::IdentityProof`](crate::control::RelayToCoordinator::IdentityProof)),
    /// proving it actually holds that key rather than having copied a cert it
    /// observed elsewhere. See [`Self::ENROLL_POP_MIN`] for exactly when the
    /// coordinator challenges.
    ///
    /// `2` folds a TLS channel binding into the connection-binding challenge
    /// proof, which a v1 peer can neither produce nor verify.
    pub const CURRENT: ProtocolVersion = ProtocolVersion(3);

    /// The oldest version this build can still interoperate with.
    ///
    /// Stays at `2`, *below* [`Self::CURRENT`] — unlike the `1`→`2` bump (a
    /// security fix with no backward-compatible form, so `MIN_SUPPORTED`
    /// tracked `CURRENT` up to drop `1`), enroll proof-of-possession is
    /// enforceable additively: the coordinator only challenges a relay whose
    /// *negotiated* version reaches [`Self::ENROLL_POP_MIN`], so a relay
    /// advertising only `2` still enrolls exactly as it did before `3`
    /// existed. There is no reason to force an upgrade for a check that a
    /// relay predating it simply never receives.
    pub const MIN_SUPPORTED: ProtocolVersion = ProtocolVersion(2);

    /// The lowest *negotiated* version at which the coordinator runs the
    /// enroll proof-of-possession exchange (see [`Self::CURRENT`]'s `3` entry).
    /// A relay whose advertised window caps the negotiated result below this —
    /// an old relay, or a new relay against an old coordinator that has never
    /// heard of `3` — enrolls unchallenged, today's behavior. Named
    /// separately from [`Self::CURRENT`] so a later bump for an unrelated
    /// reason (say `4`) does not silently change when this specific check
    /// applies.
    pub const ENROLL_POP_MIN: ProtocolVersion = ProtocolVersion(3);
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

/// WebSocket close code the coordinator sends when it refuses a relay's control
/// connection because the relay's enroll proof-of-possession failed: it never
/// answered [`CoordinatorToRelay::IdentityChallenge`](crate::control::CoordinatorToRelay::IdentityChallenge)
/// within the hello-timeout window, answered with something other than
/// [`RelayToCoordinator::IdentityProof`](crate::control::RelayToCoordinator::IdentityProof),
/// or answered with a signature that does not verify against `Hello.cert_der`.
/// Only sent when the negotiated version reaches
/// [`ProtocolVersion::ENROLL_POP_MIN`] — see that constant for when the
/// exchange runs at all.
///
/// A cross-component contract: the coordinator sends it *instead of enrolling*,
/// and the relay's coordinator client recognizes it and backs off far longer
/// than a normal reconnect — an unproven identity is a config/implementation
/// fault (a mismatched key, a broken signer), not a transient condition a redial
/// fixes, exactly like [`CONTROL_CLOSE_PROTOCOL_MISMATCH`].
pub const CONTROL_CLOSE_IDENTITY_UNPROVEN: u16 = 4003;

/// WebSocket close code the coordinator sends when a relay's (proof-of-possession
/// verified) `Hello` claims a `relay_id` the registry already holds a *live*
/// entry for, under a *different* certificate fingerprint. Two distinct relay
/// processes cannot legitimately share one id — this refuses the second one
/// rather than silently evicting the first, which the shared bootstrap secret's
/// per-relay-id ambiguity would otherwise allow. A `Hello` proving possession of
/// the *same* certificate as the live entry is the same relay reconnecting
/// (its control connection dropped and redialed) and replaces the entry as
/// always. Only checked when the negotiated version reaches
/// [`ProtocolVersion::ENROLL_POP_MIN`] — an unproven identity has nothing
/// trustworthy to compare a fingerprint against, so an older relay keeps
/// today's unconditional-replace behavior.
///
/// A cross-component contract: the coordinator sends it *instead of enrolling*.
/// Unlike [`CONTROL_CLOSE_IDENTITY_UNPROVEN`], the relay backs off on its
/// *ordinary* (short) reconnect delay — a crashed predecessor's stale registry
/// entry ages out on its own once the coordinator's liveness deadline lapses,
/// so simply retrying converges to a successful enroll rather than needing a
/// deploy or config fix.
pub const CONTROL_CLOSE_DUPLICATE_RELAY_ID: u16 = 4004;

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

/// QUIC application close code a mesh acceptor uses to refuse a dialing peer
/// that completed the TLS handshake without presenting a client certificate,
/// while peer-identity enforcement is active (the coordinator's fleet-peer set
/// is non-empty, or the relay was started with `--require-mesh-peer-auth`).
/// Sent after hello + version negotiation, before the link driver ever spawns.
pub const MESH_CLOSE_NO_CLIENT_CERT: u32 = 0x11;

/// QUIC application close code a mesh acceptor uses to refuse a dialing peer
/// whose identity hello claims a relay id absent from the coordinator's
/// fleet-peer set, while peer-identity enforcement is active. Also the code an
/// acceptor started with `--require-mesh-peer-auth` sends for *every* dial
/// while the fleet set is still empty (nothing it could claim would be
/// present), so a peer-auth-required relay never serves an unauthenticated
/// mesh accept even during its brief startup window before the coordinator's
/// first push lands.
pub const MESH_CLOSE_UNKNOWN_PEER: u32 = 0x12;

/// QUIC application close code a mesh acceptor uses to refuse a dialing peer
/// whose claimed relay id is enrolled and whose certificate was presented, but
/// whose certificate's SHA-256 fingerprint does not match the one the
/// coordinator recorded for that relay id at enroll — the fleet-set pin
/// mismatched. Sent while peer-identity enforcement is active.
pub const MESH_CLOSE_CERT_MISMATCH: u32 = 0x13;

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

    #[test]
    fn an_old_relays_window_negotiates_below_the_pop_threshold() {
        // A relay that predates proof-of-possession advertises a window topping
        // out at MIN_SUPPORTED (2) — this build's CURRENT (3) never enters the
        // negotiation, so the result stays below ENROLL_POP_MIN and the
        // coordinator must not challenge it.
        let negotiated = negotiate(
            ProtocolVersion::MIN_SUPPORTED,
            ProtocolVersion::MIN_SUPPORTED,
        )
        .expect("an old relay's window still overlaps MIN_SUPPORTED");
        assert!(
            negotiated < ProtocolVersion::ENROLL_POP_MIN,
            "an old relay's negotiated version must stay below the PoP threshold",
        );
    }

    #[test]
    fn a_current_relays_window_negotiates_at_the_pop_threshold() {
        // A relay advertising this build's own window negotiates exactly at
        // CURRENT, which is also ENROLL_POP_MIN — the coordinator challenges it.
        let negotiated = negotiate(ProtocolVersion::MIN_SUPPORTED, ProtocolVersion::CURRENT)
            .expect("a current relay's window overlaps");
        assert_eq!(negotiated, ProtocolVersion::CURRENT);
        assert!(negotiated >= ProtocolVersion::ENROLL_POP_MIN);
    }

    #[test]
    fn min_supported_stays_below_current_for_additive_pop_compat() {
        // Unlike the 1->2 bump (MIN_SUPPORTED tracked CURRENT up), the 2->3 bump
        // widens the window: proof-of-possession is enforceable additively, so
        // an old (2-only) relay must remain interoperable.
        assert!(ProtocolVersion::MIN_SUPPORTED < ProtocolVersion::CURRENT);
        assert_eq!(ProtocolVersion::CURRENT, ProtocolVersion::ENROLL_POP_MIN);
    }
}
