//! Relay registry: what the coordinator learns about a phoned-home relay,
//! and the client/mesh-facing shapes built from it.
//!
//! [`RelayHello`] is a relay's phone-home; [`RelayEntry`] is the
//! coordinator's own registry record built from it; [`RelayEndpoint`] and
//! [`RelayPeer`] are the client-facing and mesh-facing views handed out in
//! session responses and descriptors, respectively.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::ids::RelayId;
use crate::version::ProtocolVersion;

use super::RegionId;

// ---------------------------------------------------------------------------
// Relay registry (coordinator ⇄ relay)
// ---------------------------------------------------------------------------

/// The [`RelayHello::capabilities`] tag for home-side drop finalization: the
/// relay understands the `FinalizeDrop` handshake, strips unproven dropped
/// counts at every ingress, and honors a descriptor's `finalized_drops` flag.
/// The coordinator enables finalized drops only for sessions whose every
/// assigned relay (rehome targets included) advertises this — and, during a
/// mixed-fleet transition, never places relays with and without it in one
/// session, since a relay without it can still author the historical unsound
/// counted-drop behavior.
pub const CAPABILITY_FINALIZED_DROP_V1: &str = "finalized_drop_v1";

/// The fleet-wide ceiling on a player token's lifetime, in seconds (24 hours).
///
/// A shared contract, not a tuning knob: the coordinator clamps its configured
/// `player_token_lifetime` to this before minting, and the relay sizes its
/// retired-session tombstone retention to outlast it. The pairing is what
/// keeps a retired session terminal — a token can never outlive the tombstone
/// that refuses its stale re-dial, no matter how the coordinator is
/// configured. Raising this without also revisiting the relay's
/// retired-gate retention would silently reopen that gap.
pub const MAX_PLAYER_TOKEN_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// The first frame a relay sends on its control connection, enrolling it into
/// the coordinator's registry (wrapped in [`super::RelayToCoordinator::Hello`]).
///
/// The relay presents its coordinator-assigned id, its advertised address (where
/// clients and peer relays reach it), the protocol version it implements, and
/// the TLS leaf certificate clients pin to connect to it; the coordinator
/// records these in its registry and uses them to build session responses,
/// session descriptors, and mesh topology.
///
/// The control connection that carries this is authenticated by a
/// coordinator-issued bootstrap secret (fail-closed: the coordinator refuses to
/// serve it unauthenticated without an explicit insecure opt-in). How the
/// claimed `relay_id` is bound to an identity depends on whether the coordinator
/// runs a provisioning ledger. A ledger-backed coordinator mints each id with a
/// one-time [`enroll_token`](Self::enroll_token) and binds the id to the
/// certificate presented here at first enroll — the token is consumed, and every
/// later reconnect must re-present the same certificate; an id it never minted,
/// or one it has retired, cannot enroll at all. A coordinator with no ledger
/// (dev / loopback) accepts the id claim as presented, resting on the enroll
/// proof-of-possession alone to prove the relay holds the private key behind the
/// certificate it names.
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
    /// The newest protocol version the relay implements — the top of its
    /// negotiation window. The coordinator negotiates against
    /// `[min_protocol.unwrap_or(protocol), protocol]` before enrolling, and
    /// refuses the connection (close code
    /// [`CONTROL_CLOSE_PROTOCOL_MISMATCH`](crate::version::CONTROL_CLOSE_PROTOCOL_MISMATCH))
    /// when the windows do not overlap.
    pub protocol: ProtocolVersion,
    /// DER encoding of the TLS leaf certificate the relay serves on its client
    /// edge. The coordinator forwards it in session responses so clients pin
    /// exactly this cert — self-signed relay certs stay trusted without any
    /// out-of-band cert distribution.
    #[serde(with = "super::serde_bytes")]
    pub cert_der: Vec<u8>,
    /// The oldest protocol version the relay still speaks — the bottom of its
    /// negotiation window, letting a newer relay downgrade to an older
    /// coordinator's version instead of being refused. Absent (a relay that
    /// predates the field) the window collapses to the single version in
    /// [`protocol`](Self::protocol), which is exactly how such a relay behaves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_protocol: Option<ProtocolVersion>,
    /// The optional protocol capabilities this relay build implements, as
    /// free-form tags (see [`CAPABILITY_FINALIZED_DROP_V1`]). Orthogonal to
    /// the protocol-version window: a capability changes what the coordinator
    /// may enable per session (and how it places sessions), not whether the
    /// relay can enroll. Defaults empty for a relay that predates the field;
    /// an old coordinator ignores the field entirely.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// The relay's **complete** advertised address set, in the relay's own
    /// preference order — a dual-stack relay advertises both its v4 and v6
    /// endpoints here. When non-empty it *includes*
    /// [`relay_addr`](Self::relay_addr), which stays the primary/back-compat
    /// address every existing consumer keeps working against; empty means a
    /// single-address relay reachable only at `relay_addr` (and the field stays
    /// off the wire, keeping the single-address hello byte-identical to the
    /// pre-dual-stack form).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_addrs: Vec<SocketAddr>,
    /// The region this relay serves, if it was launched with one. The
    /// coordinator validates it against its configured region list at enroll and
    /// refuses the connection ([`crate::version::CONTROL_CLOSE_UNKNOWN_REGION`])
    /// for a region it does not recognize — a typo'd tag silently serving nobody
    /// is worse than a failed enroll. Absent means an untagged relay (dev /
    /// loopback, or a fleet with no region config): it enrolls unconditionally
    /// and is only ever the region-blind fallback pick. Additive, so an untagged
    /// hello stays byte-identical to the pre-region form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<RegionId>,
    /// A one-time enrollment token, presented on a relay's first enroll against a
    /// coordinator that runs a provisioning ledger. The coordinator mints it when
    /// it launches the relay's task and hands it to the relay out of band (its
    /// launch environment); at first enroll the coordinator consumes it and binds
    /// this relay id to the certificate the hello carries, after which the bound
    /// certificate alone authorizes reconnects — a token re-presented on a later
    /// enroll (the relay's environment keeps supplying it across redials) is
    /// simply ignored. Absent for a relay enrolling against a coordinator with no
    /// ledger (dev / loopback), which accepts the id claim as presented.
    /// Additive, so a tokenless hello stays byte-identical to the pre-token form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enroll_token: Option<String>,
    /// A random value the relay chooses **once per process** and repeats on every
    /// hello that process sends — its process identity, distinct from the stable
    /// `relay_id` an operator assigns.
    ///
    /// It exists so the coordinator can tell a control connection redialing (the
    /// same process, whose in-memory state is intact) from a relay that restarted
    /// (a fresh process, whose retained per-session state is gone). Only the latter
    /// is a break in what the relay can still vouch for. Absent from a relay build
    /// that predates the field, which is indistinguishable from a restart — a
    /// coordinator reading an absent value can never conclude memory survived, so
    /// it must assume it did not. Additive, so a hello without one stays
    /// byte-identical to the pre-boot-id form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<u64>,
}

impl RelayHello {
    /// Constructs a relay phone-home message advertising the single version
    /// `protocol` (no `min_protocol` — a one-version negotiation window; widen it
    /// with [`with_min_protocol`](Self::with_min_protocol)) and the single
    /// address `relay_addr` (widen to a dual-stack set with
    /// [`with_relay_addrs`](Self::with_relay_addrs)).
    ///
    /// Provided because `RelayHello` is `#[non_exhaustive]`: future fields
    /// (e.g. capabilities) can be added without breaking external callers that
    /// construct it.
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
            min_protocol: None,
            capabilities: Vec::new(),
            relay_addrs: Vec::new(),
            region: None,
            enroll_token: None,
            boot_id: None,
        }
    }

    /// Sets the optional protocol capabilities this relay build implements
    /// (see [`RelayHello::capabilities`]). The relay's real enroll passes
    /// every capability tag its build supports.
    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Sets the oldest protocol version the relay still speaks, widening the
    /// negotiation window from the single version [`new`](Self::new) advertises to
    /// `[min, protocol]`. The relay's real enroll passes
    /// [`ProtocolVersion::MIN_SUPPORTED`].
    pub fn with_min_protocol(mut self, min: ProtocolVersion) -> Self {
        self.min_protocol = Some(min);
        self
    }

    /// Sets the complete advertised address set (which must include the primary
    /// `relay_addr`), in the relay's preference order — the dual-stack advertise.
    pub fn with_relay_addrs(mut self, relay_addrs: Vec<SocketAddr>) -> Self {
        self.relay_addrs = relay_addrs;
        self
    }

    /// Tags this hello with the region the relay serves, so the coordinator homes
    /// region-matching session slots on it. Left unset (via [`new`](Self::new)),
    /// the relay is untagged — it enrolls unconditionally and is only ever the
    /// region-blind fallback pick.
    pub fn with_region(mut self, region: RegionId) -> Self {
        self.region = Some(region);
        self
    }

    /// Attaches the one-time enrollment token the coordinator minted for this
    /// relay id, presented so a ledger-backed coordinator can bind the id to this
    /// hello's certificate at first enroll. Left unset (via [`new`](Self::new)),
    /// the hello carries no token — the form a relay uses against a coordinator
    /// with no ledger. A relay launched with a token keeps presenting it on every
    /// enroll; once its certificate is bound the coordinator ignores the token.
    pub fn with_enroll_token(mut self, token: String) -> Self {
        self.enroll_token = Some(token);
        self
    }

    /// Stamps this hello with the relay process's own identity (see
    /// [`boot_id`](Self::boot_id)). The value must be drawn once at process start
    /// and repeated on every hello that process sends: a value that changed while
    /// the process lived would read to the coordinator as a restart, and one that
    /// survived a restart would falsely claim the relay's memory did.
    pub fn with_boot_id(mut self, boot_id: u64) -> Self {
        self.boot_id = Some(boot_id);
        self
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
    /// Where clients and peer relays reach it — the primary/back-compat address.
    pub relay_addr: SocketAddr,
    /// Protocol version the relay reported at phone-home.
    pub protocol: ProtocolVersion,
    /// DER of the TLS leaf certificate the relay reported at phone-home —
    /// what clients pin to connect to it (carried in session responses).
    #[serde(with = "super::serde_bytes")]
    pub cert_der: Vec<u8>,
    /// The relay's complete advertised address set, in its preference order,
    /// as enrolled. Non-empty means the complete set (including `relay_addr`);
    /// empty means a single-address relay reachable only at `relay_addr` —
    /// the same semantics as [`RelayHello::relay_addrs`], carried through so
    /// every endpoint/peer built from this entry advertises the full set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_addrs: Vec<SocketAddr>,
    /// The capability tags the relay enrolled with (from
    /// [`RelayHello::capabilities`]). Placement reads them to keep every
    /// session's relay set capability-homogeneous and to decide per-session
    /// features like [`super::SessionDescriptor::finalized_drops`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// The region this relay enrolled tagged with (from [`RelayHello::region`]),
    /// or `None` for an untagged relay. The coordinator reads it when placing a
    /// session's slots — a slot requesting this region homes here — and when a
    /// re-home prefers the dead relay's region for the replacement pick.
    ///
    /// It is deliberately *not* on the [`RelayPeer`]/[`RelayEndpoint`] a
    /// descriptor or session response carries. Regions reach a session's relays
    /// only as the whole-session label map in
    /// [`super::SessionDescriptor::relay_regions`], and reach a *client* only as the
    /// [`RegionLabels`](crate::messages::RegionLabels) frame its home relay
    /// releases once that relay's own clock says a stretch of real gameplay has
    /// elapsed. That ordering is the point: the labels place every member
    /// geographically, so a client able to read them before the game was properly
    /// underway could see its opponents' regions and abandon the match while it
    /// had barely begun. Nothing a client receives at dial or during lobby setup
    /// carries a region, and nothing a client sends can bring the release
    /// forward.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<RegionId>,
}

impl From<&RelayEntry> for RelayPeer {
    fn from(e: &RelayEntry) -> Self {
        RelayPeer {
            relay_id: e.relay_id,
            relay_addr: e.relay_addr,
            cert_der: e.cert_der.clone(),
            relay_addrs: e.relay_addrs.clone(),
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
    /// Where clients reach the relay — the primary/back-compat address.
    pub relay_addr: SocketAddr,
    /// DER of the TLS leaf certificate the relay serves; clients pin exactly
    /// this cert, so self-signed relay certs work without out-of-band
    /// distribution.
    #[serde(with = "super::serde_bytes")]
    pub cert_der: Vec<u8>,
    /// The relay's complete advertised address set, in the relay's preference
    /// order (see [`RelayHello::relay_addrs`] for the non-empty-includes-primary
    /// / empty-means-single-address contract). Which family a *game client*
    /// dials is the embedder's choice — it knows the client's connectivity; the
    /// app server picks per client when its infra work lands — via
    /// [`addrs`](Self::addrs) / [`addr_for_family`](Self::addr_for_family).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_addrs: Vec<SocketAddr>,
}

impl RelayEndpoint {
    /// The candidate connect addresses in advertised order — the relay's own
    /// preference. The complete set when one was advertised, else just the
    /// primary. A consumer that knows its connectivity picks a family
    /// ([`addr_for_family`](Self::addr_for_family)); one that doesn't walks
    /// this list in order.
    pub fn addrs(&self) -> Vec<SocketAddr> {
        candidate_addrs(self.relay_addr, &self.relay_addrs)
    }

    /// The first advertised address of the given family, or `None` when the
    /// relay advertises none — the caller then falls back to walking
    /// [`addrs`](Self::addrs).
    pub fn addr_for_family(&self, is_ipv6: bool) -> Option<SocketAddr> {
        addr_for_family(self.relay_addr, &self.relay_addrs, is_ipv6)
    }
}

impl From<&RelayEntry> for RelayEndpoint {
    fn from(e: &RelayEntry) -> Self {
        RelayEndpoint {
            relay_id: e.relay_id,
            relay_addr: e.relay_addr,
            cert_der: e.cert_der.clone(),
            relay_addrs: e.relay_addrs.clone(),
        }
    }
}

/// A peer relay in a session's mesh topology: the id, address, and pinned
/// certificate a relay needs to dial (or accept) a mesh connection.
///
/// Carried inside a [`super::SessionDescriptor`] so each relay in a session learns
/// the lower-id side of each pair dials the higher (the `should_dial_mesh`
/// tie-break),
/// so the coordinator just lists the peers and each relay decides locally
/// which to dial — it needs the peer's id *before* connecting, which is why
/// the id rides here rather than being exchanged post-connect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPeer {
    /// The peer relay's coordinator-assigned id.
    pub relay_id: RelayId,
    /// Where the peer relay is reached — the primary/back-compat address.
    pub relay_addr: SocketAddr,
    /// DER of the TLS leaf certificate the peer relay reported at enrollment —
    /// the same cert clients pin from a session response. The dialing relay
    /// pins exactly this cert for the mesh connection, so independently
    /// self-signed relay certs trust each other with no out-of-band
    /// distribution (mirroring [`RelayEndpoint::cert_der`] on the client edge).
    /// Defaults to empty on a descriptor from a coordinator that predates the
    /// field; the dialer then falls back to its configured mesh roots.
    #[serde(default, with = "super::serde_bytes")]
    pub cert_der: Vec<u8>,
    /// The peer relay's complete advertised address set, in its preference
    /// order (see [`RelayHello::relay_addrs`] for the non-empty-includes-primary
    /// / empty-means-single-address contract). The mesh dialer walks
    /// [`addrs`](Self::addrs) in order until a candidate connects, so a
    /// dual-stack pair meshes over whichever family reaches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_addrs: Vec<SocketAddr>,
}

impl RelayPeer {
    /// The candidate dial addresses in advertised order — the peer relay's own
    /// preference. See [`RelayEndpoint::addrs`]; the same selection contract.
    pub fn addrs(&self) -> Vec<SocketAddr> {
        candidate_addrs(self.relay_addr, &self.relay_addrs)
    }

    /// The first advertised address of the given family, or `None`. See
    /// [`RelayEndpoint::addr_for_family`].
    pub fn addr_for_family(&self, is_ipv6: bool) -> Option<SocketAddr> {
        addr_for_family(self.relay_addr, &self.relay_addrs, is_ipv6)
    }
}

/// The shared selection contract behind [`RelayEndpoint::addrs`] and
/// [`RelayPeer::addrs`]: the advertised set when one exists (its order is the
/// relay's preference), else the single primary address.
fn candidate_addrs(relay_addr: SocketAddr, relay_addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    if relay_addrs.is_empty() {
        vec![relay_addr]
    } else {
        relay_addrs.to_vec()
    }
}

/// The first candidate of the requested family, in advertised order — the
/// pick for a consumer that knows its own connectivity. `None` when the relay
/// advertises no address of that family (the caller falls back to walking the
/// candidates).
fn addr_for_family(
    relay_addr: SocketAddr,
    relay_addrs: &[SocketAddr],
    is_ipv6: bool,
) -> Option<SocketAddr> {
    candidate_addrs(relay_addr, relay_addrs)
        .into_iter()
        .find(|addr| addr.is_ipv6() == is_ipv6)
}
