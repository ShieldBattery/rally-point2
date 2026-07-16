//! Control-plane messages.
//!
//! Reliable, lower-frequency messages that never ride the turn-datagram hot
//! path:
//!
//! - **coordinator ⇄ relay** — authenticated phone-home registry, session
//!   descriptors, and consensus *policy* (bounds/rates).
//! - **coordinator ⇄ app server** — session requests, token + home relay
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
use crate::token::{ClientPublicKey, KeyId};
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

/// Identifies a coordinator-configured relay region — an opaque placement label,
/// deliberately *not* an AWS region name so a non-AWS region stays expressible.
///
/// A relay enrolls tagged with the region it serves; the coordinator validates
/// that tag against its configured region list (an unknown one is refused,
/// [`crate::version::CONTROL_CLOSE_UNKNOWN_REGION`]). A session slot names the
/// region the player wants their home relay in, and the coordinator homes the
/// slot on a relay enrolled in that region — falling back to a region-blind pick
/// when the region names no live relay. The string is the wire name everywhere
/// (`"us-east"`, not `us-east-1`); its allowed shape (charset, length) is
/// enforced where the coordinator loads its region config, not by this type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionId(pub String);

impl From<RegionId> for String {
    fn from(rid: RegionId) -> String {
        rid.0
    }
}

impl AsRef<str> for RegionId {
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
    #[serde(with = "serde_bytes")]
    pub cert_der: Vec<u8>,
    /// The oldest protocol version the relay still speaks — the bottom of its
    /// negotiation window, letting a newer relay downgrade to an older
    /// coordinator's version instead of being refused. Absent (a relay that
    /// predates the field) the window collapses to the single version in
    /// [`protocol`](Self::protocol), which is exactly how such a relay behaves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_protocol: Option<ProtocolVersion>,
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
            relay_addrs: Vec::new(),
            region: None,
            enroll_token: None,
        }
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
    #[serde(with = "serde_bytes")]
    pub cert_der: Vec<u8>,
    /// The relay's complete advertised address set, in its preference order,
    /// as enrolled. Non-empty means the complete set (including `relay_addr`);
    /// empty means a single-address relay reachable only at `relay_addr` —
    /// the same semantics as [`RelayHello::relay_addrs`], carried through so
    /// every endpoint/peer built from this entry advertises the full set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_addrs: Vec<SocketAddr>,
    /// The region this relay enrolled tagged with (from [`RelayHello::region`]),
    /// or `None` for an untagged relay. The coordinator reads it when placing a
    /// session's slots — a slot requesting this region homes here — and when a
    /// re-home prefers the dead relay's region for the replacement pick. It is
    /// deliberately *not* propagated into the [`RelayPeer`]/[`RelayEndpoint`] a
    /// descriptor or session response carries: a relay never needs to know its
    /// peers' regions, and a client never needs its relay's, so the region stays
    /// coordinator-side placement state.
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
    #[serde(with = "serde_bytes")]
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
    /// Where the peer relay is reached — the primary/back-compat address.
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
///
/// **Depth and the relay's desync comparator.** The relay's
/// `consensus::SyncTracker` reconstructs a slot's absolute sync ordinal from a
/// 4-bit ring nibble. Its steady-state placement corrects each report
/// relative to that same slot's own last-known ordinal, so its accuracy
/// depends only on transport-level reordering (comfortably under the ±7 the
/// nibble math tolerates) — never on `max`. A slot's first-ever report (a
/// join, or an authority promotion mid-stream) instead anchors on the
/// reporting turn's `game_frame_count`: lockstep keeps every client's frame
/// for the same simulated interval within a couple of turns of each other
/// regardless of buffer depth (the depth is a session-wide constant that
/// cancels out across clients), so the frame estimate — refined by the same
/// nibble correction — stays accurate at any realistic `max`. The
/// comparator's evaluation margin scales with `max` instead (see
/// `consensus::sync_eval_margin`), so a deeper buffer costs only a longer wait
/// before an ordinal retires, not a correctness risk. Only a `max` at or
/// above `consensus::SYNC_ABSURD_BUFFER_MAX` — a defensive backstop far above
/// any real policy, not a live constraint — disables desync detection
/// outright.
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
    ///
    /// `new` rejects an inverted range, but these bounds can also reach here
    /// straight off the wire (`BufferBounds` derives `Deserialize` for the
    /// coordinator→relay descriptor/response payloads, bypassing `new`'s
    /// validation entirely), so a corrupted or malicious coordinator could
    /// hand this an inverted `min > max` — which `u32::clamp` panics on. Treat
    /// the bounds as swapped rather than trust their field order, so a caller
    /// never has to re-validate before calling this.
    pub fn clamp(&self, value: u32) -> u32 {
        let (min, max) = if self.min <= self.max {
            (self.min, self.max)
        } else {
            (self.max, self.min)
        };
        value.clamp(min, max)
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
    /// The tenant's own identifier for this player (ShieldBattery sets a
    /// stringified `SbUserId`). The coordinator stores it per slot and echoes
    /// it in a departure webhook so the notification is self-describing —
    /// nothing on the tenant side has to keep a session→user map. Optional so a
    /// peer that predates the field still interops; the control protos don't
    /// `deny_unknown_fields`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    /// Whether this player is an observer rather than a competitor. Observers do
    /// not reliably emit the game's per-turn sync command, so a slot flagged here
    /// is excluded from the relay's desync checksum cross-check (requiring a
    /// checksum a slot never sends would stall the comparison for everyone). The
    /// coordinator gathers the observer-flagged slots into
    /// [`SessionDescriptor::observer_slots`] so every relay serving the session
    /// learns them. Defaults to `false` (a competitor) so a tenant that predates
    /// the field still interops, exactly like `external_ref`'s optionality.
    #[serde(default)]
    pub observer: bool,
    /// The tenant's assertion of which configured region this player wants their
    /// home relay in. The coordinator homes the slot on a relay enrolled in this
    /// region when one is live, else falls back to its region-blind pick — the
    /// region is a preference, not a requirement, so an unrecognized or unserved
    /// region degrades to the fallback rather than failing the session. Absent
    /// means no preference (the fallback pick outright). Additive: a handoff that
    /// predates the field carries no region, and the control protos don't
    /// `deny_unknown_fields`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<RegionId>,
}

/// A request from an app server to stand up a game session: which tenant, how
/// many players, and each player's client pubkey.
///
/// The app server has already formed the lobby (matchmaking stays in the app
/// server, not the coordinator). The coordinator assigns each player a home
/// relay, mints one connection-bound token per player, and returns a
/// [`SessionResponse`] the app uses to hand each player `{token, relay_addr}`
/// at game launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRequest {
    /// The tenant requesting the session — its signing key will sign the
    /// tokens.
    pub tenant: TenantId,
    /// The players in the session, one per slot.
    pub players: Vec<PlayerHandoff>,
    /// The tenant's own identifier for this session (ShieldBattery sets its
    /// `gameId`). The coordinator stores it and echoes it in a departure
    /// webhook, so the notification names the game without the tenant keeping a
    /// session→game map. Optional so a peer that predates the field still
    /// interops; the control protos don't `deny_unknown_fields`.
    ///
    /// Also the create endpoint's idempotency key: a create naming an
    /// `external_id` that already has a live session returns that session's
    /// original response rather than minting a duplicate, so an ordinary
    /// tenant HTTP retry inside the signed-request's replay window is safe.
    /// A request that omits `external_id` gets no such protection — there is
    /// nothing to key a replay on — so a retried create with none always
    /// mints a fresh session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// The tenant's estimate of the worst pairwise **one-way** path latency (in
    /// milliseconds) across the session's players, computed app-side from each
    /// player's region and measured RTT against the region backbone table. The
    /// coordinator forwards it verbatim on every serving relay's
    /// [`SessionDescriptor::latency_estimate_ms`], where the session's authority
    /// relay folds it into the initial latency-buffer depth it stamps onto
    /// [`crate::messages::SessionStart`] — a fallback for the pre-start window the
    /// relay's own link measurements cannot see (a client that has only just
    /// dialed contributes little more than its handshake RTT). Absent when the
    /// tenant supplied none; the relay then sizes the depth from its own
    /// observations alone. Additive, so a request that predates the field still
    /// interops (the control protos don't `deny_unknown_fields`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_estimate_ms: Option<u32>,
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

/// A per-slot home-relay override in a [`SessionResponse`]: a slot that homes on
/// a relay other than the session's primary [`SessionResponse::home_relay`].
///
/// A single-region (or single-relay) session produces none — every slot homes on
/// the primary. These appear for a genuine cross-region session, where each
/// player's home relay is in their own region. Multi-relay redundancy is
/// per-player home relays plus the mesh: a relay named here always homes at
/// least one slot, so it is never assigned to a session it serves no player in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotHome {
    /// The slot this override applies to.
    pub slot: SlotId,
    /// The relay this slot homes on, with the cert the client pins to reach it.
    pub relay: RelayEndpoint,
}

/// The coordinator's response to a session request: the session id, the
/// relay topology, the per-player tokens, and the consensus policy bounds.
///
/// The home relay is the one clients connect to. A same-region session is
/// single-relay (every slot homes on `home_relay`); `slot_homes` overrides the
/// home for individual slots — a cross-region session's per-player home relays.
/// Multi-relay redundancy is per-player home relays plus the mesh: a relay that
/// serves a session always homes at least one of its slots. The relay topology
/// drives the mesh edge — each serving relay receives a [`SessionDescriptor`]
/// naming its peers, and the lower-id side of each pair dials. The policy
/// bounds are pushed to each relay's decision-maker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionResponse {
    /// The coordinator-assigned session id (unique within the tenant).
    pub session: SessionId,
    /// The relay clients connect to, including the cert they pin. Every slot
    /// homes here except those overridden in `slot_homes`.
    pub home_relay: RelayEndpoint,
    /// Per-slot home overrides: slots that home on a relay other than
    /// `home_relay`. Empty for a same-region (single-relay) session; populated for
    /// a cross-region session (each slot's home in its own region).
    #[serde(default)]
    pub slot_homes: Vec<SlotHome>,
    /// One token per player, matching the slots in the request.
    pub tokens: Vec<PlayerToken>,
    /// The latency-buffer bounds the relay's decision-maker clamps to.
    pub bounds: BufferBounds,
}

/// One slot's tenant-assigned correlation id, as carried in a
/// [`SessionDescriptor`]. A `Vec` of pairs rather than a map: JSON object keys
/// must be strings, and `SlotId` is numeric on the wire — the same reasoning
/// that keeps [`PlayerHandoff::external_ref`] per-player rather than in a map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotExternalRef {
    /// The slot this ref names.
    pub slot: SlotId,
    /// The tenant's own id for the player in this slot — mirrors
    /// [`PlayerHandoff::external_ref`] at session-request time.
    pub external_ref: String,
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
    /// The tenant's own id for the session (ShieldBattery's `gameId`), echoed
    /// from the [`SessionRequest`] that created it. Carried all the way down to
    /// every relay serving the session — not just kept coordinator-side — so a
    /// relay can stamp it into a [`DepartureNotice`] without the notification
    /// depending on the coordinator's in-memory session-refs store, which a
    /// coordinator restart wipes. Optional: absent when the app server's
    /// request carried none, or the descriptor is from a coordinator that
    /// predates the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// The tenant's own id for the player in each slot, mirroring
    /// [`PlayerHandoff::external_ref`] at session-request time. Only slots whose
    /// handoff carried a ref appear. Defaults empty for a descriptor from a
    /// coordinator that predates the field.
    #[serde(default)]
    pub slot_refs: Vec<SlotExternalRef>,
    /// The slots the coordinator flagged as observers (gathered from the
    /// observer-flagged handoffs in the [`SessionRequest`]). The relay's desync
    /// comparator excludes these slots: observers do not reliably emit the
    /// per-turn sync command, so requiring their checksums would stall the
    /// cross-check. Carried down to every relay serving the session — like
    /// `slot_refs`, and surviving the same persistence/restart paths — so a relay
    /// knows observer-ness without a separate lookup. Defaults empty for a
    /// descriptor from a coordinator that predates the field.
    #[serde(default)]
    pub observer_slots: Vec<SlotId>,
    /// The slots the coordinator expects to connect before the session may
    /// start — every player and observer in the [`SessionRequest`]. The
    /// session's authority relay accumulates the slots that have registered
    /// anywhere in the mesh (its own plus peers' presence announcements) and,
    /// once they cover this set, emits the one session-start directive to every
    /// client — the relay-driven replacement for an out-of-band start signal.
    /// Empty disables the feature: a descriptor from a coordinator that predates
    /// the field (or a session that opts out) never triggers a start directive,
    /// exactly like `observer_slots`. Defaults empty for backward compatibility.
    #[serde(default)]
    pub expected_slots: Vec<SlotId>,
    /// The slots the coordinator has assigned to home on **this** relay. A
    /// relay refuses a client's admission for a slot authorized in its token
    /// but absent from this set — a token binds tenant/session/slot/key but not
    /// the relay, so without this a misrouted (or malicious) client could
    /// register the same slot on two relays serving a true multi-relay
    /// session, feeding each a different turn at the same `(slot, seq)`; the
    /// mesh's topological dedup would then suppress each side's view of the
    /// other, silently diverging the two relays' client populations.
    ///
    /// **Empty means unenforced** — not "no slot may register here." This is
    /// the legacy/dev default: a coordinator that predates this field, and any
    /// dev harness that injects a descriptor by hand (most of this codebase's
    /// tests), decodes/constructs an empty set, and admission proceeds exactly
    /// as before the field existed. Enforcement activates only once the
    /// coordinator populates a genuinely non-empty set for a session — which a
    /// production multi-relay descriptor always does (every player slot is
    /// assigned a home relay by construction), so real cross-relay traffic is
    /// covered without disturbing single-relay or dev-injected sessions.
    #[serde(default)]
    pub homed_slots: Vec<SlotId>,
    /// Whether this descriptor re-homes an **already-running** session onto the
    /// relay (coordinator-mediated failover). A relay that receives a `resumed`
    /// descriptor treats the session as already started: it seeds the started
    /// latch rather than waiting for the full [`expected_slots`](Self::expected_slots)
    /// set to connect, so it never stalls on a departed slot that will never dial
    /// and never re-fires the session-start machinery session-wide. A fresh
    /// (non-rehome) descriptor leaves this `false`, so the normal start-on-coverage
    /// path runs unchanged. Defaults `false` for a descriptor from a coordinator
    /// that predates the field.
    #[serde(default)]
    pub resumed: bool,
    /// The slots the coordinator already knows have departed this session, each
    /// with the relay's left-vs-dropped classification. Carried only on a
    /// rehome-rebuilt descriptor (see [`resumed`](Self::resumed)): a fresh relay
    /// taking over a running session has no mesh peer to replay `SlotDeparted`
    /// records from, so the coordinator seeds the already-decided departures here.
    /// The relay records each as a decided leave, so its comparator, coverage
    /// check, and promotion re-broadcast all treat a coordinator-seeded departure
    /// exactly like a mesh-learned one. Defaults empty for a non-rehome descriptor
    /// (or a coordinator that predates the field).
    #[serde(default)]
    pub departed_slots: Vec<DepartedSlot>,
    /// The tenant's worst-pairwise one-way path-latency estimate (milliseconds)
    /// for the session, forwarded verbatim from the [`SessionRequest`] that
    /// created it. The session's authority relay folds it into the initial
    /// latency-buffer depth it stamps onto [`crate::messages::SessionStart`] — a
    /// fallback for the pre-start conditions its own link measurements cannot see.
    /// Carried on every serving relay's descriptor, including a rehome-rebuilt one
    /// (harmless there: a resumed relay never re-stamps an initial depth). Absent
    /// when the request carried none, or the descriptor is from a coordinator that
    /// predates the field. Additive, so an old descriptor still parses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_estimate_ms: Option<u32>,
}

/// One slot the coordinator has recorded as departed, carried in a rehome-rebuilt
/// [`SessionDescriptor::departed_slots`] so a fresh relay taking over a running
/// session can seed the already-decided departure. Mirrors [`SlotExternalRef`]'s
/// shape (a slot plus one datum) rather than a bare tuple, so the wire form stays
/// a self-describing JSON object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepartedSlot {
    /// The slot that departed.
    pub slot: SlotId,
    /// The relay's left-vs-dropped classification for the departure.
    pub kind: DepartureKind,
}

// ---------------------------------------------------------------------------
// Persistent control connection (coordinator ⇄ relay)
// ---------------------------------------------------------------------------

/// One relay's mesh-peer identity as the coordinator distributes it to the whole
/// fleet: the relay's id paired with the SHA-256 fingerprint of the TLS leaf
/// certificate it enrolled with.
///
/// A relay serves its client edge and its mesh edge with a single self-signed
/// certificate, so that certificate's fingerprint *is* the relay's identity. The
/// mesh acceptor pins a dialing peer's TLS client certificate against the
/// fingerprint carried here: a peer claiming a relay id present in the fleet set
/// must present the certificate whose fingerprint the set records for it. This
/// makes independently self-signed relay certs trust each other with no
/// certificate authority and no out-of-band distribution — the same fingerprint
/// clients pin from a session response and dialers pin from a descriptor, here
/// pinned by the *accepting* relay instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshPeerIdentity {
    /// The peer relay's coordinator-assigned id.
    pub relay_id: RelayId,
    /// The SHA-256 digest of the DER-encoded TLS leaf certificate the relay
    /// enrolled with — the same certificate clients pin from a session response
    /// and peers pin from a [`RelayPeer`] in a descriptor.
    pub cert_sha256: [u8; 32],
}

/// One tenant's token-verifying key, as the coordinator distributes it to relays:
/// the `kid` that names the signing key, the tenant that owns it, and the
/// [`PUBLIC_KEY_LEN`](crate::token::PUBLIC_KEY_LEN)-byte Ed25519 public key that
/// verifies tokens signed with it.
///
/// The private signing half never leaves the coordinator; the relay holds only
/// this public half and verifies against it, so the `kid → tenant` binding here is
/// the authority a forged tenant claim in a token is checked against (mirroring the
/// relay's own registry — a valid signature proves only that `kid` signed the
/// claims, never that the claimed tenant owns that key). Carried in a
/// [`CoordinatorToRelay::TenantKeys`] push.
///
/// `verifying_key` is a byte string, the same encoding the neighboring relay frames
/// give their certificate DER; the relay checks its length before trusting it, so a
/// wrong-length key is skipped rather than misread.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantVerifyingKey {
    /// The key id (`kid`) a token carries so the relay knows which key verifies it.
    pub kid: KeyId,
    /// The tenant that owns the signing key — authoritative, cross-checked against
    /// the token's own tenant claim.
    pub tenant: TenantId,
    /// The Ed25519 public (verifying) key,
    /// [`PUBLIC_KEY_LEN`](crate::token::PUBLIC_KEY_LEN) bytes when well-formed.
    #[serde(with = "serde_bytes")]
    pub verifying_key: Vec<u8>,
}

/// One region's ping beacon, as the coordinator distributes it to relays: the
/// region id paired with the `host:port` of that region's always-up UDP ping
/// beacon — the target a relay measures a backbone round-trip to.
///
/// Named after the coordinator region registry's own `beacon` field, whose value
/// this carries; the beacon is a `host:port` **string** (a DNS hostname the relay
/// resolves at ping time), not a pre-resolved socket address, mirroring the
/// registry where the same endpoint is the client-facing measurement target.
/// Carried in a [`CoordinatorToRelay::RegionBeacons`] push.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionBeaconTarget {
    /// The region this beacon belongs to — the wire name a relay reports its
    /// measured round-trip against.
    pub region: RegionId,
    /// `host:port` of the region's always-up ping beacon, the target a relay
    /// measures the backbone round-trip to. A DNS hostname resolved at ping time,
    /// not a pre-resolved socket address.
    pub beacon: String,
}

/// One region's measured backbone round-trip, as a relay reports it up its
/// control connection: the region id paired with the relay's latest measured
/// median round-trip to that region's ping beacon, in milliseconds.
///
/// Carried in [`RelayToCoordinator::Heartbeat`]'s `region_rtts`. Declarative like
/// the beat's session roster — the relay repeats its whole current set of
/// measured medians on every beat, so a lost or reordered beat is corrected by
/// the next one. A region the relay has not yet measured (or one whose last sweep
/// found no reachable beacon) is simply absent from the set, never reported as a
/// zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionRttReport {
    /// The region this measurement is for — the wire name matching the
    /// [`RegionBeaconTarget::region`] the coordinator pushed the relay.
    pub region: RegionId,
    /// The relay's latest measured median round-trip to that region's beacon,
    /// in milliseconds.
    pub rtt_ms: u32,
}

/// The fixed prefix signed (and verified) in the enroll proof-of-possession
/// exchange: the relay signs `ENROLL_POP_CONTEXT ++ nonce` — never the bare
/// nonce — so a signature produced for this purpose can never be replayed as
/// a valid signature for some unrelated protocol that also happens to sign
/// 32-byte messages. Versioned in the literal (`v1`) the same way the
/// connection-binding challenge's own signed contexts are, so a future change
/// to what gets signed is a new, distinguishable prefix rather than a silent
/// reinterpretation of old signatures.
pub const ENROLL_POP_CONTEXT: &[u8] = b"rp2-enroll-pop-v1:";

/// A message the coordinator sends down the persistent control connection a
/// relay holds open to it.
///
/// The connection is the relay's single, authenticated control channel: the
/// coordinator pushes mesh topology down it, and the relay reports liveness (and
/// a drain request) up it. This enum is the **down** direction — descriptor
/// pushes, reap directives, and the [`DrainAck`](Self::DrainAck) that answers a
/// relay's coordinated-drain request. It is
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
    /// A reap directive: close the named slots' links so their normal link-death
    /// path (a synced leave, a departure notice) runs. The coordinator arms this
    /// when a session's accounting stalls — a holdout slot silent on a live link,
    /// or reported-but-still-linked stragglers after everyone is accounted. A
    /// relay fires each named slot's own shutdown signal; a slot it does not
    /// currently home or hold is a no-op, so the coordinator can name every slot
    /// without tracking which relay holds which.
    CloseSlot {
        /// The tenant the session belongs to.
        tenant: TenantId,
        /// The session whose slots to close.
        session: SessionId,
        /// The slots to close. A slot this relay does not hold is ignored.
        slots: Vec<SlotId>,
    },
    /// Acknowledges a relay's [`Draining`](RelayToCoordinator::Draining) request:
    /// the coordinator has marked the relay ineligible for new session assignments
    /// **and**, immediately before this frame, pushed the relay's current
    /// descriptor set down the same socket. That ordering is load-bearing — the set
    /// arrives before the ack — so a relay that sees an *empty* descriptor set at
    /// ack time knows it is provably unassigned and can exit at once, while a relay
    /// still holding sessions waits them out (up to its drain timeout) rather than
    /// abandoning a client mid-connect. Payload-free: the acknowledgement is the
    /// whole signal. Sent only when the mark applied under a current connection
    /// generation; a stale connection's Draining draws no ack (its live successor
    /// runs its own drain exchange).
    DrainAck,
    /// The fleet's currently-enrolled mesh peers — every relay the coordinator
    /// holds enrolled, each with the SHA-256 fingerprint of the certificate it
    /// enrolled with. The relay consumes this at mesh-accept time to pin a
    /// dialing peer's TLS client certificate: a peer claiming a relay id in this
    /// set must present the certificate whose fingerprint the set records for it.
    ///
    /// The coordinator sends the whole set on the control connection's start and
    /// again whenever fleet membership changes, and the relay replaces its stored
    /// set wholesale on each push — declarative complete state, exactly like
    /// [`Descriptors`](Self::Descriptors). Re-sending an unchanged set is a
    /// harmless no-op, and a relay that reconnects re-syncs the full current set,
    /// so the channel never has to guarantee exactly-once delivery. A draining
    /// relay stays in the set: it still serves live sessions and holds mesh links,
    /// and the set governs only which peers may open a *new* mesh link.
    MeshPeers {
        /// The complete set of currently-enrolled fleet peers.
        peers: Vec<MeshPeerIdentity>,
    },
    /// The tenant token-verifying keys the relay checks client authorization
    /// tokens against — the full current set as a declarative replacement, one
    /// entry per tenant signing key.
    ///
    /// The coordinator holds every tenant's signing key and pushes the public
    /// (verifying) halves here, so a relay verifies client tokens with no tenant
    /// key material in its own environment. The set is sent once when the control
    /// connection starts, ahead of the first session descriptor — a descriptor
    /// must never reach a relay that cannot yet verify its clients' tokens — and
    /// the relay replaces its stored set wholesale on the push (declarative
    /// complete state, exactly like [`MeshPeers`](Self::MeshPeers) and
    /// [`Descriptors`](Self::Descriptors)). A relay that reconnects re-syncs the
    /// full set, so the channel never has to guarantee exactly-once delivery.
    TenantKeys {
        /// The complete set of tenant verifying keys.
        keys: Vec<TenantVerifyingKey>,
    },
    /// The region ping beacons a relay measures backbone round-trips against —
    /// one entry per region in the coordinator's registry, each naming the
    /// region's always-up UDP ping beacon.
    ///
    /// The coordinator sends the whole set once when the control connection
    /// starts, ahead of the first session descriptor, and the relay replaces its
    /// stored set wholesale on the push — declarative complete state, exactly like
    /// [`MeshPeers`](Self::MeshPeers) and [`TenantKeys`](Self::TenantKeys). The
    /// region registry is immutable per coordinator process, so this is a one-time
    /// connect-time push; a relay that reconnects re-syncs the full set. The set
    /// names every configured region, **including the one the receiving relay
    /// serves** — the relay drops its own before measuring, since a region's
    /// round-trip to itself is zero by definition. A coordinator with no regions
    /// configured omits this frame entirely, so a relay on a region-blind fleet
    /// receives no targets and measures nothing.
    RegionBeacons {
        /// The complete set of region ping beacon targets.
        beacons: Vec<RegionBeaconTarget>,
    },
    /// A random challenge proving the relay holds the private key matching the
    /// certificate its `Hello` presented (enroll proof-of-possession): the
    /// relay must answer with
    /// [`RelayToCoordinator::IdentityProof`], a signature over
    /// [`ENROLL_POP_CONTEXT`] `++ nonce` made with that key. Sent once, after
    /// `Hello` and version negotiation succeed and before the coordinator
    /// enrolls the relay — never on an already-enrolled connection — on every
    /// accepted connection: negotiation refuses any relay advertising a version
    /// below
    /// [`ProtocolVersion::ENROLL_POP_MIN`](crate::version::ProtocolVersion::ENROLL_POP_MIN)
    /// before the challenge, so no un-challenged enroll path exists.
    /// Closes `Hello.cert_der`'s gap: without this, a bootstrap-secret holder
    /// could copy a victim relay's public certificate into its own `Hello` and
    /// enroll as it, since the certificate alone is payload, not proof of
    /// holding the matching key.
    IdentityChallenge {
        /// A fresh random value, unique per connection attempt.
        nonce: [u8; 32],
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
/// live relay from one whose connection has silently died, and — once it has
/// received its shutdown signal — a [`Draining`](Self::Draining) frame asking the
/// coordinator to stop assigning it new sessions. Tagged and
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
    /// The answer to a [`CoordinatorToRelay::IdentityChallenge`]: a signature
    /// over [`ENROLL_POP_CONTEXT`] `++` the challenge's nonce, made with the
    /// private key matching the certificate this connection's `Hello`
    /// presented — proof-of-possession of that key, not just knowledge of the
    /// certificate's public bytes. Sent statelessly the moment a challenge
    /// arrives; the relay tracks no handshake-phase state of its own, since the
    /// coordinator alone decides when to challenge and when to give up waiting.
    IdentityProof {
        /// The signature, in the format the key's algorithm produces (an
        /// ECDSA P-256 signature is ASN.1 DER; an Ed25519 signature is the raw
        /// 64 bytes) — the coordinator tries each algorithm it supports against
        /// `Hello.cert_der`'s public key, so the wire form doesn't need to name
        /// which one this is.
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    },
    /// A periodic presence ping proving the control connection is still alive,
    /// carrying the relay's live roster.
    ///
    /// The coordinator resets a per-connection liveness deadline on each one;
    /// when enough are missed — a relay that crashed, or a TCP connection that
    /// died without ever sending a close — the deadline lapses, the coordinator
    /// drops the connection and deregisters the relay.
    ///
    /// `sessions` piggybacks the relay's **connected slots** on the beat the relay
    /// already sends: each entry names one session and the slots whose clients are
    /// connected right now, the whole current truth every time (declarative, so a
    /// lost or reordered beat is corrected by the next one). The coordinator feeds
    /// it into its active-player presence store, which tenant app servers query to
    /// block an in-game player from re-queueing. An idle relay's beat carries no
    /// entries and serializes exactly as the payload-free ping always did, so an
    /// older coordinator reads it unchanged.
    ///
    /// The frame carries only tenant/session/slot — **never user identity**: the
    /// relay stays PII-free, and slots are resolved to the tenant's own user refs
    /// on the coordinator, which already holds them from session creation.
    Heartbeat {
        /// The relay's live roster: one entry per session it currently holds a
        /// connected slot for. Empty (and omitted from the wire) on an idle relay.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        sessions: Vec<SessionPresence>,
        /// The relay's latest measured backbone round-trips: one entry per region
        /// it has a median for, declarative like `sessions` — the relay repeats
        /// its whole current set of measured medians on every beat, so a lost or
        /// reordered beat is corrected by the next one. Empty (and omitted from the
        /// wire) until the relay has measured anything, which is also exactly what a
        /// relay build that predates the measurement sends, so an older coordinator
        /// reads the beat unchanged.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        region_rtts: Vec<RegionRttReport>,
    },
    /// The relay has received its shutdown signal and asks the coordinator to
    /// **stop assigning it new sessions**. The control connection itself identifies
    /// the relay, so it carries no payload.
    ///
    /// The coordinator marks the relay ineligible for assignment, then answers with
    /// [`DrainAck`](CoordinatorToRelay::DrainAck) after pushing the relay's current
    /// descriptor set (set-before-ack: an empty set at ack time means provably
    /// unassigned). A re-enroll clears the coordinator-side flag, so a relay that
    /// reconnects mid-drain re-sends this frame right after its `Hello`. Idempotent:
    /// re-sending it just draws a fresh set-plus-ack.
    Draining,
    /// A player permanently departed a running game: a synced leave for the slot
    /// just first entered this relay's consensus cache. The relay reports it so
    /// the coordinator can forward the "player X left vs. was dropped" fact to
    /// the tenant. Every relay serving the session reports independently and the
    /// coordinator dedups by `(tenant, session, slot)`, so a single relay's
    /// coordinator link being down never loses the notice.
    Departure(DepartureNotice),
    /// The relay's desync comparator found two live slots whose per-turn sync
    /// checksums disagreed at the same sync ordinal — the two clients' simulations
    /// have diverged. Only the session's authority relay compares, so (unlike a
    /// departure) exactly one relay reports each event; the coordinator still
    /// dedups by `(tenant, session, sync_ordinal)` because at-least-once delivery
    /// can re-send one. The relay forwards it so the coordinator can tell the
    /// tenant "this game desynced at ordinal N; these slots diverged", which the
    /// tenant uses to void or re-adjudicate the result.
    Desync(DesyncNotice),
    /// A client reported its end-of-game result: the relay received the opaque
    /// bytes on its control stream, stamped their arrival against its own timeline,
    /// and forwards them here without parsing. Only the reporting slot's home relay
    /// sends it (results never cross the mesh), and the relay dedups one report per
    /// slot; the coordinator dedups again by `(tenant, session, slot)` because
    /// at-least-once delivery can re-send one. The coordinator relays the bytes to
    /// the tenant as a webhook.
    Result(ResultNotice),
    /// The relay tore down its last local state for a session — every slot it
    /// homed or held is gone. The coordinator, which assigned the session's
    /// serving relay set, waits for every serving relay to report this and then
    /// emits the final `sessionClosed` webhook. Because a relay fires it only
    /// after its own departures went up the same ordered channel, and the
    /// coordinator's per-session dispatch drains in order, a delivered
    /// `sessionClosed` guarantees no earlier notice for the session is still in
    /// flight.
    SessionClosed {
        /// The tenant the session belongs to.
        tenant: TenantId,
        /// The session this relay closed.
        session: SessionId,
    },
    /// A flushed flight recording the relay ships for the coordinator to persist —
    /// one session's full observability blob, sent when the session closes or the
    /// relay drains. The relay holds no durable-store credentials, so the recording
    /// travels up this same authenticated control connection rather than to storage
    /// directly.
    ///
    /// Carries no relay id: the coordinator keys the stored blob on **this
    /// connection's enrolled relay identity**, so a relay can never name another
    /// relay's identity in the object key. Additive, so an older coordinator decodes
    /// it as [`Unknown`](Self::Unknown) and skips it — the blob is simply lost
    /// against a coordinator that predates this variant, consistent with the
    /// deploy-order rule that coordinator images ship ahead of relay images.
    FlightRecording(FlightRecordingNotice),
    /// A message kind this coordinator does not recognize (a newer relay). Decodes
    /// here so the coordinator skips it rather than dropping the connection.
    #[serde(other)]
    Unknown,
}

/// One session's connected slots on one relay, as carried in a
/// [`RelayToCoordinator::Heartbeat`]'s roster.
///
/// A slot appears exactly while its client's link is registered on the relay —
/// the same liveness the relay's own drain path keys on — so the coordinator's
/// presence store tracks "connected to a relay now", nothing softer. Deliberately
/// slot-granular and PII-free: the relay never learns user identity, and the
/// coordinator resolves slots to the tenant's own user refs from the session
/// request it already holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPresence {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session with connected slots on the reporting relay.
    pub session: SessionId,
    /// The slots whose clients are connected to the reporting relay right now.
    pub slots: Vec<SlotId>,
}

/// Whether a departing player left cleanly or was dropped, classified by the
/// relay from the synced leave's native reason. Rides the departure webhook as
/// `"left"` / `"dropped"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepartureKind {
    /// A clean departure — the player quit (native `strPLAYER_LEFT`).
    Left,
    /// An unclean drop — the player's link died (native `strPLAYER_WAS_DROPPED`).
    Dropped,
}

/// The end-of-game result a departing slot reported before it left, echoed into
/// a [`DepartureNotice`] so a departure webhook is atomic terminal truth: the
/// player left/dropped, and here is the result — or there provably never was one
/// (`None`). The relay's home for the departing slot authors it from the result
/// it retained; the standalone [`ResultNotice`] still fires early at dialog time,
/// so this embedded copy is a redundant delivery, not the only one.
///
/// The stamps mirror [`ResultNotice`]'s: `arrival_ms` is relay wall-clock at
/// receipt, `session_frame` the session's consensus coordinate then, `slot_frame`
/// the reporting slot's own newest frame. `payload` is the tenant's opaque bytes,
/// forwarded byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultEcho {
    /// The tenant's opaque serialized result, forwarded byte-for-byte.
    pub payload: Vec<u8>,
    /// Relay wall-clock at receipt, unix epoch milliseconds.
    pub arrival_ms: u64,
    /// The session's consensus frame when the report arrived. `None` before any
    /// slot produced a framed turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_frame: Option<u32>,
    /// The reporting slot's own newest observed frame when the report arrived.
    /// `None` before that slot produced a framed turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot_frame: Option<u32>,
}

/// A relay's report that a player permanently departed a running game, sent up
/// the relay control connection ([`RelayToCoordinator::Departure`]).
///
/// It carries its own `tenant`/`session`/`slot` because one relay control
/// connection serves many sessions, so the frame must name which one. `kind` is
/// the relay's left-vs-dropped classification; `reason` is the raw native leave
/// reason it was classified from (kept for debugging); `leave_seq` is the
/// deciding relay's own ordering number for the leave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepartureNotice {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session the player departed from.
    pub session: SessionId,
    /// The slot that departed.
    pub slot: SlotId,
    /// The left-vs-dropped classification the relay derived from `reason`.
    pub kind: DepartureKind,
    /// The raw native `pending_leave_reason` value the relay decided
    /// (`0x40000006` dropped, else left), carried alongside `kind` for
    /// debugging.
    pub reason: u32,
    /// The deciding relay's ordering number for this leave. Not a dedup key on
    /// its own (the coordinator dedups by slot); useful telemetry.
    pub leave_seq: u32,
    /// The tenant's own id for the session, stamped by the relay from its
    /// stored [`SessionDescriptor`] if it has one. `None` when the relay never
    /// received the correlation ids — a standalone relay, a descriptor from a
    /// coordinator that predates them, or a departure decided before any
    /// descriptor carrying them arrived. The coordinator falls back to its own
    /// stored session refs when this is absent (which a coordinator restart may
    /// have forgotten — the descriptor-carried copy is what survives that).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// The tenant's own id for the departed player's slot. Same source and
    /// fallback as `external_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    /// The result this slot reported before departing, if any — embedded so the
    /// departure webhook carries terminal truth in one delivery. `None` when the
    /// slot departed without ever reporting; a result can never arrive after the
    /// departure (reports ride only the live link, which the departure closes),
    /// so an embedded result is final. The standalone [`ResultNotice`] still
    /// fires separately, so this is a redundant copy. Optional so a relay that
    /// predates the field still interops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ResultEcho>,
}

/// One slot the relay's desync comparator found on the losing side of a checksum
/// mismatch — a diverged member of the minority. Mirrors [`SlotExternalRef`]'s
/// shape (a slot plus its optional tenant ref) rather than a bare slot, so the
/// desync webhook can name the diverged player in the tenant's own terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergedSlot {
    /// The slot whose checksum diverged from the agreeing majority.
    pub slot: SlotId,
    /// The tenant's own id for the player in this slot, stamped by the relay from
    /// its stored [`SessionDescriptor`]. Same source and fallback as
    /// [`DepartureNotice::external_ref`]; `None` when the relay never received the
    /// correlation ids for the slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
}

/// A relay's report that a game desynced — two live slots' per-turn sync
/// checksums disagreed at the same sync ordinal, so their simulations diverged.
/// Sent up the relay control connection ([`RelayToCoordinator::Desync`]).
///
/// Like [`DepartureNotice`], it carries its own `tenant`/`session` because one
/// control connection serves many sessions, and stamps its own correlation ids
/// from the relay's stored [`SessionDescriptor`] so the notification is
/// self-describing across a coordinator restart.
///
/// The event is identified by `sync_ordinal` (the count of sync commands the
/// diverging slots had each emitted), not a relay-assigned sequence number:
/// authority promotion restarts the comparator from scratch, and keying the
/// event on the ordinal means a re-detection after a promotion lands at a
/// distinct, later ordinal rather than colliding with an earlier report. The
/// coordinator dedups on `(tenant, session, sync_ordinal)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesyncNotice {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session that desynced.
    pub session: SessionId,
    /// The per-slot sync ordinal at which the mismatch was observed — the number
    /// of sync commands each diverging slot had emitted. The event identity; the
    /// coordinator's dedup key alongside tenant + session.
    pub sync_ordinal: u64,
    /// The `game_frame_count` of the turn whose sync command confirmed the
    /// mismatch — a human-meaningful interval to correlate against replays and
    /// results. `None` when that turn carried no frame (it shouldn't in practice —
    /// sync commands flow only in-game — but the field is honest about it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub game_frame: Option<u32>,
    /// Relay wall-clock at detection, unix epoch milliseconds. Records when the
    /// relay observed the divergence, independent of when the webhook is delivered
    /// (which retries may delay).
    pub detected_at_ms: u64,
    /// Set when no strict majority of compared slots shared one checksum value (a
    /// 1v1 disagreement, or an even split), so which side is authoritative cannot
    /// be determined from the relay's view alone. `diverged` is then empty — the
    /// tenant must not infer the minority from topology. When `false`, `diverged`
    /// names exactly the minority slots.
    pub no_majority: bool,
    /// The slots that diverged from the agreeing majority (the minority). Empty
    /// when `no_majority` is set.
    pub diverged: Vec<DivergedSlot>,
    /// The tenant's own id for the session, stamped by the relay from its stored
    /// [`SessionDescriptor`]. Same source and fallback as
    /// [`DepartureNotice::external_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

/// A relay's forward of a client's end-of-game result report, sent up the relay
/// control connection ([`RelayToCoordinator::Result`]).
///
/// Like [`DepartureNotice`], it carries its own `tenant`/`session`/`slot` because
/// one control connection serves many sessions. `payload` is the tenant's opaque
/// serialized result, forwarded byte-for-byte — the relay never parses it, the
/// same boundary that keeps `external_ref` an opaque correlation string. `slot`
/// is the authenticated connection's slot the report arrived on, never a value
/// from the bytes. It stamps its own correlation ids from the relay's stored
/// [`SessionDescriptor`] so the notice is self-describing across a coordinator
/// restart, exactly as the departure and desync notices do.
///
/// The frame stamps are the relay's own view of *when* the report landed in the
/// game's timeline: `arrival_ms` is relay wall-clock at receipt, `session_frame`
/// the session's consensus coordinate (the slowest slot's progress) then, and
/// `slot_frame` the reporting slot's own newest observed frame. Each is `None`
/// when the relay had no such value yet (a report before any framed turn).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultNotice {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session the result is for.
    pub session: SessionId,
    /// The slot that reported — the authenticated connection's slot, never a
    /// value carried in the payload.
    pub slot: SlotId,
    /// The tenant's own id for the session, stamped by the relay from its stored
    /// [`SessionDescriptor`]. Same source and fallback as
    /// [`DepartureNotice::external_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// The tenant's own id for the reporting slot's player. Same source and
    /// fallback as `external_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ref: Option<String>,
    /// The tenant's opaque serialized result, forwarded byte-for-byte.
    pub payload: Vec<u8>,
    /// Relay wall-clock at receipt, unix epoch milliseconds. Records when the
    /// relay observed the report, independent of when the webhook is delivered.
    pub arrival_ms: u64,
    /// The session's consensus coordinate (the slowest slot's observed frame)
    /// when the report arrived. `None` before any slot produced a framed turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_frame: Option<u32>,
    /// The reporting slot's own newest observed frame when the report arrived.
    /// `None` before that slot produced a framed turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot_frame: Option<u32>,
}

/// A relay's shipment of one flushed flight recording, sent up the relay control
/// connection ([`RelayToCoordinator::FlightRecording`]).
///
/// Like [`DepartureNotice`], it carries its own `tenant`/`session` because one
/// control connection serves many sessions. It deliberately does **not** carry a
/// relay id: the coordinator keys the stored blob on the connection's enrolled
/// relay identity, so a relay cannot claim another's identity in the object key
/// (the same connection-scoped authority the notice-serving check already relies
/// on).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlightRecordingNotice {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The coordinator-assigned session id the recording covers.
    pub session: SessionId,
    /// Whether this recording's events contain a confirmed desync — the shipping
    /// relay scans its own events at flush. The coordinator combines this with its
    /// own desync-notice record to choose the stored blob's retention class; the
    /// flag matters when the coordinator's in-memory record was lost to a restart.
    pub desynced: bool,
    /// The serialized flight blob (JSON), opaque to the coordinator. Carried as
    /// bytes-of-JSON rather than a typed structure so a coordinator built against
    /// an older blob shape stores newer relays' recordings verbatim instead of
    /// silently dropping fields it does not know.
    pub payload: String,
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
    use crate::token::{ClientPublicKey, PUBLIC_KEY_LEN};

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
    fn buffer_bounds_clamp_does_not_panic_on_an_inverted_range() {
        // `new` rejects `min > max`, but `Deserialize` is derived and bypasses
        // it entirely -- a corrupted or malicious coordinator payload can still
        // hand `clamp` an inverted range. `u32::clamp` panics if `min > max`;
        // `BufferBounds::clamp` must not, regardless of how the value reached
        // it.
        let inverted = BufferBounds { min: 8, max: 2 };
        assert_eq!(inverted.clamp(0), 2, "swapped bounds treat 2 as the floor");
        assert_eq!(inverted.clamp(5), 5, "5 already falls within [2, 8]");
        assert_eq!(
            inverted.clamp(99),
            8,
            "swapped bounds treat 8 as the ceiling"
        );
    }

    #[test]
    fn buffer_bounds_with_inverted_fields_decodes_and_still_clamps_safely() {
        // `Deserialize` is derived directly on `BufferBounds` (it crosses the
        // coordinator/relay wire boundary), so it never runs `new`'s
        // validation -- an inverted `min > max` from a corrupted or malicious
        // coordinator decodes without error. The clamp call downstream must
        // still not panic.
        let json = r#"{"min":8,"max":2}"#;
        let decoded: BufferBounds = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, BufferBounds { min: 8, max: 2 });
        assert_eq!(decoded.clamp(99), 8);
    }

    #[test]
    fn relay_hello_roundtrips_json() {
        let hello = RelayHello {
            relay_id: RelayId(7),
            relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            protocol: ProtocolVersion::CURRENT,
            cert_der: vec![0x30, 0x82, 0xAA, 0xBB],
            min_protocol: None,
            relay_addrs: vec![],
            region: None,
            enroll_token: None,
        };
        let json = serde_json::to_string(&hello).unwrap();
        // An unset window bottom stays off the wire (a one-version window).
        assert!(!json.contains("min_protocol"));
        let back: RelayHello = serde_json::from_str(&json).unwrap();
        assert_eq!(back, hello);
    }

    #[test]
    fn relay_hello_with_an_enroll_token_roundtrips_json() {
        let hello = RelayHello::new(
            RelayId(7),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            ProtocolVersion::CURRENT,
            vec![0xAA; 4],
        )
        .with_enroll_token("s3cr3t-token".to_owned());
        let json = serde_json::to_string(&hello).unwrap();
        assert!(json.contains("\"enroll_token\":\"s3cr3t-token\""));
        let back: RelayHello = serde_json::from_str(&json).unwrap();
        assert_eq!(back, hello);
        assert_eq!(back.enroll_token.as_deref(), Some("s3cr3t-token"));
    }

    #[test]
    fn a_tokenless_hello_serializes_byte_identical_to_the_pre_token_form() {
        // A hello with no enroll token keeps the field off the wire entirely, so a
        // relay enrolling against a coordinator with no ledger (and every reconnect
        // once a certificate is bound) emits exactly the shape a pre-token peer
        // would — the additive-field byte-identical guarantee.
        let tokenless = RelayHello::new(
            RelayId(7),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            ProtocolVersion::CURRENT,
            vec![0xAA; 4],
        );
        let json = serde_json::to_string(&tokenless).unwrap();
        assert!(!json.contains("enroll_token"));
        // The same bytes a tokenless hello has always produced: adding
        // `with_enroll_token` and then clearing it back to `None` round-trips to
        // the identical wire form.
        let back: RelayHello = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tokenless);
        assert!(back.enroll_token.is_none());
    }

    #[test]
    fn relay_hello_with_min_protocol_roundtrips_json() {
        let hello = RelayHello::new(
            RelayId(7),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            ProtocolVersion(3),
            vec![0x30, 0x82, 0xAA, 0xBB],
        )
        .with_min_protocol(ProtocolVersion(2));
        let json = serde_json::to_string(&hello).unwrap();
        assert!(json.contains("\"min_protocol\":2"));
        let back: RelayHello = serde_json::from_str(&json).unwrap();
        assert_eq!(back, hello);
        assert_eq!(back.min_protocol, Some(ProtocolVersion(2)));
    }

    #[test]
    fn relay_hello_without_min_protocol_decodes_to_none() {
        // A hello from a relay that predates the window field must still decode —
        // `min_protocol` defaults to None, which the coordinator reads as a
        // one-version window at `protocol`.
        let json = r#"{
            "relay_id":7,
            "relay_addr":"127.0.0.1:14900",
            "protocol":2,
            "cert_der":[1,2,3]
        }"#;
        let back: RelayHello = serde_json::from_str(json).unwrap();
        assert_eq!(back.min_protocol, None);
        assert_eq!(back.protocol, ProtocolVersion(2));
    }

    #[test]
    fn relay_hello_with_region_roundtrips_and_omits_when_absent() {
        // A tagged relay carries its region on the wire; an untagged one keeps the
        // field off entirely, so an untagged hello stays byte-identical to the
        // pre-region form.
        let tagged = RelayHello::new(
            RelayId(7),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            ProtocolVersion::CURRENT,
            vec![0xAA; 4],
        )
        .with_region(RegionId("us-east".to_owned()));
        let json = serde_json::to_string(&tagged).unwrap();
        assert!(json.contains("\"region\":\"us-east\""));
        assert_eq!(serde_json::from_str::<RelayHello>(&json).unwrap(), tagged);

        let untagged = RelayHello::new(
            RelayId(7),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            ProtocolVersion::CURRENT,
            vec![0xAA; 4],
        );
        assert!(!serde_json::to_string(&untagged).unwrap().contains("region"));
    }

    #[test]
    fn player_handoff_region_is_omitted_when_absent_and_decodes_to_none() {
        // An untagged handoff keeps `region` off the wire, and a handoff from an app
        // server that predates the field decodes with `region` defaulting to None
        // (no preference, the coordinator's fallback pick).
        let handoff = PlayerHandoff {
            slot: SlotId(0),
            client_pubkey: ClientPublicKey([0xAA; 32]),
            external_ref: None,
            observer: false,
            region: None,
        };
        let json = serde_json::to_string(&handoff).unwrap();
        assert!(!json.contains("region"));
        let back: PlayerHandoff = serde_json::from_str(&json).unwrap();
        assert_eq!(back.region, None);

        let tagged = PlayerHandoff {
            region: Some(RegionId("us-west".to_owned())),
            ..handoff
        };
        let json = serde_json::to_string(&tagged).unwrap();
        assert!(json.contains("\"region\":\"us-west\""));
        assert_eq!(
            serde_json::from_str::<PlayerHandoff>(&json).unwrap(),
            tagged
        );
    }

    #[test]
    fn relay_hello_with_a_dual_stack_set_roundtrips_json() {
        let v4: SocketAddr = "203.0.113.7:14900".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::7]:14900".parse().unwrap();
        let hello = RelayHello::new(RelayId(7), v4, ProtocolVersion::CURRENT, vec![0xAA; 4])
            .with_relay_addrs(vec![v4, v6]);
        let json = serde_json::to_string(&hello).unwrap();
        assert!(json.contains("\"relay_addrs\""));
        let back: RelayHello = serde_json::from_str(&json).unwrap();
        assert_eq!(back, hello);
        assert_eq!(back.relay_addr, v4, "the primary is unchanged");
        assert_eq!(
            back.relay_addrs,
            vec![v4, v6],
            "the complete set rides along"
        );
    }

    #[test]
    fn a_single_address_hello_keeps_the_field_off_the_wire_and_absent_decodes_empty() {
        // Back-compat both directions: this build's single-address hello stays
        // byte-stable (no `relay_addrs` key for an old consumer to trip on)...
        let hello = RelayHello::new(
            RelayId(7),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            ProtocolVersion::CURRENT,
            vec![0xAA; 4],
        );
        let json = serde_json::to_string(&hello).unwrap();
        assert!(!json.contains("relay_addrs"));

        // ...and an old relay's hello (no field at all) decodes with an empty
        // set, which every consumer reads as "single address at relay_addr".
        let old = r#"{
            "relay_id":7,
            "relay_addr":"127.0.0.1:14900",
            "protocol":2,
            "cert_der":[1,2,3]
        }"#;
        let back: RelayHello = serde_json::from_str(old).unwrap();
        assert!(back.relay_addrs.is_empty());
    }

    #[test]
    fn addr_selection_walks_the_advertised_order_and_falls_back_to_the_primary() {
        let v4: SocketAddr = "203.0.113.7:14900".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::7]:14900".parse().unwrap();

        // A dual-stack endpoint: the candidates are the set, in advertised order
        // (the relay's preference), and family selection picks within it.
        let dual = RelayEndpoint {
            relay_id: RelayId(1),
            relay_addr: v4,
            cert_der: vec![],
            relay_addrs: vec![v6, v4], // the relay prefers v6
        };
        assert_eq!(dual.addrs(), vec![v6, v4], "advertised order is preserved");
        assert_eq!(dual.addr_for_family(true), Some(v6));
        assert_eq!(dual.addr_for_family(false), Some(v4));

        // A single-address peer: the candidates collapse to the primary, and a
        // family it doesn't serve yields None (the caller walks the candidates).
        let single = RelayPeer {
            relay_id: RelayId(2),
            relay_addr: v4,
            cert_der: vec![],
            relay_addrs: vec![],
        };
        assert_eq!(single.addrs(), vec![v4]);
        assert_eq!(single.addr_for_family(false), Some(v4));
        assert_eq!(single.addr_for_family(true), None);
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
                    relay_addrs: vec![],
                }],
                bounds: BufferBounds::new(1, 6).unwrap(),
                authority_order: vec![RelayId(1), RelayId(2)],
                external_id: None,
                slot_refs: vec![],
                observer_slots: vec![],
                expected_slots: vec![],
                homed_slots: vec![],
                resumed: false,
                departed_slots: vec![],
                latency_estimate_ms: Some(45),
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
    fn session_request_latency_estimate_defaults_absent_and_omits_from_the_wire() {
        // A request that predates the field parses with the estimate absent — the
        // control protos don't `deny_unknown_fields`, and the field defaults.
        let old = r#"{
            "tenant":"sb-staging",
            "players":[]
        }"#;
        let back: SessionRequest = serde_json::from_str(old).unwrap();
        assert_eq!(back.latency_estimate_ms, None);

        // An absent estimate stays off the wire (byte-identical to the pre-field
        // form), while a present one round-trips.
        let request = SessionRequest {
            tenant: TenantId("sb-staging".to_owned()),
            players: vec![],
            external_id: None,
            latency_estimate_ms: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains("latency_estimate_ms"));
        assert_eq!(
            serde_json::from_str::<SessionRequest>(&json).unwrap(),
            request
        );

        let with_estimate = SessionRequest {
            latency_estimate_ms: Some(72),
            ..request
        };
        let json = serde_json::to_string(&with_estimate).unwrap();
        assert!(json.contains("\"latency_estimate_ms\":72"));
        assert_eq!(
            serde_json::from_str::<SessionRequest>(&json).unwrap(),
            with_estimate
        );
    }

    #[test]
    fn session_descriptor_latency_estimate_defaults_absent() {
        // A descriptor from a coordinator that predates the field parses with the
        // estimate absent, exactly like `observer_slots`/`expected_slots` do.
        let old = r#"{
            "tenant":"sb-staging",
            "session":42,
            "peers":[],
            "bounds":{"min":1,"max":6}
        }"#;
        let back: SessionDescriptor = serde_json::from_str(old).unwrap();
        assert_eq!(back.latency_estimate_ms, None);
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
    fn coordinator_to_relay_close_slot_roundtrips_json() {
        let message = CoordinatorToRelay::CloseSlot {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
            slots: vec![SlotId(1), SlotId(3)],
        };
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("\"type\":\"close_slot\""));
        let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn close_slot_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
        // Forward compatibility: a `CloseSlot` down-frame decoded by the
        // up-direction `RelayToCoordinator` (which has no such variant) folds
        // into `Unknown` rather than erroring — an older relay build's path.
        let json = r#"{"type":"close_slot","tenant":"sb-staging","session":42,"slots":[1]}"#;
        let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, RelayToCoordinator::Unknown);
    }

    #[test]
    fn coordinator_to_relay_mesh_peers_roundtrips_json() {
        let message = CoordinatorToRelay::MeshPeers {
            peers: vec![
                MeshPeerIdentity {
                    relay_id: RelayId(1),
                    cert_sha256: [0x11; 32],
                },
                MeshPeerIdentity {
                    relay_id: RelayId(2),
                    cert_sha256: [0x22; 32],
                },
            ],
        };
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("\"type\":\"mesh_peers\""));
        let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
        // The fingerprint survives the round trip intact — the acceptor pins on it.
        let CoordinatorToRelay::MeshPeers { peers } = back else {
            panic!("expected a mesh_peers frame");
        };
        assert_eq!(peers[0].cert_sha256, [0x11; 32]);
        assert_eq!(peers[1].relay_id, RelayId(2));
    }

    #[test]
    fn mesh_peers_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
        // Forward compatibility: a `MeshPeers` down-frame decoded by a build whose
        // `CoordinatorToRelay` predates the variant (modeled by the up-direction
        // `RelayToCoordinator`, which has no such variant) folds into `Unknown`
        // rather than erroring — a coordinator that pushes the set to an older relay
        // is skipped, not fatal.
        let json = r#"{"type":"mesh_peers","peers":[]}"#;
        let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, RelayToCoordinator::Unknown);
    }

    #[test]
    fn coordinator_to_relay_tenant_keys_roundtrips_json() {
        let message = CoordinatorToRelay::TenantKeys {
            keys: vec![
                TenantVerifyingKey {
                    kid: KeyId("staging-key-1".to_owned()),
                    tenant: TenantId("sb-staging".to_owned()),
                    verifying_key: vec![0x11; PUBLIC_KEY_LEN],
                },
                TenantVerifyingKey {
                    kid: KeyId("dev-key-1".to_owned()),
                    tenant: TenantId("sb-dev".to_owned()),
                    verifying_key: vec![0x22; PUBLIC_KEY_LEN],
                },
            ],
        };
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("\"type\":\"tenant_keys\""));
        let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
        // The verifying key survives the round trip intact — the relay verifies
        // client tokens against exactly these bytes.
        let CoordinatorToRelay::TenantKeys { keys } = back else {
            panic!("expected a tenant_keys frame");
        };
        assert_eq!(keys[0].verifying_key, vec![0x11; PUBLIC_KEY_LEN]);
        assert_eq!(keys[1].tenant, TenantId("sb-dev".to_owned()));
    }

    #[test]
    fn tenant_keys_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
        // Forward compatibility, mirroring `mesh_peers`: a `TenantKeys` down-frame
        // decoded by a build whose `CoordinatorToRelay` predates the variant
        // (modeled by the up-direction `RelayToCoordinator`, which has no such
        // variant) folds into `Unknown` rather than erroring — a coordinator that
        // pushes the set to an older relay is skipped, not fatal.
        let json = r#"{"type":"tenant_keys","keys":[]}"#;
        let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, RelayToCoordinator::Unknown);
    }

    #[test]
    fn coordinator_to_relay_identity_challenge_roundtrips_json() {
        let message = CoordinatorToRelay::IdentityChallenge { nonce: [0x7A; 32] };
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("\"type\":\"identity_challenge\""));
        let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn identity_challenge_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
        // Same forward-compatibility shape as `mesh_peers`: a build that predates
        // this variant (modeled by `RelayToCoordinator`, which has no such variant)
        // skips an IdentityChallenge it doesn't understand rather than erroring, so
        // the wire format stays forward-safe.
        let json = r#"{"type":"identity_challenge","nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#;
        let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, RelayToCoordinator::Unknown);
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
    fn relay_to_coordinator_identity_proof_roundtrips_json() {
        let message = RelayToCoordinator::IdentityProof {
            signature: vec![0x30, 0x45, 0x02, 0x21, 0x00],
        };
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("\"type\":\"identity_proof\""));
        let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn identity_proof_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
        // Forward compatibility, mirroring the down-direction IdentityChallenge
        // test: decoded by `CoordinatorToRelay` (no such variant), an
        // IdentityProof folds into `Unknown` rather than erroring.
        let json = r#"{"type":"identity_proof","signature":[1,2,3]}"#;
        let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, CoordinatorToRelay::Unknown);
    }

    #[test]
    fn relay_to_coordinator_heartbeat_roundtrips_json() {
        let message = RelayToCoordinator::Heartbeat {
            sessions: vec![],
            region_rtts: vec![],
        };
        let json = serde_json::to_string(&message).unwrap();
        // An idle, un-measured relay's beat is byte-identical to the historical
        // payload-free ping: just the tag, both the empty roster and the empty
        // RTT set omitted from the wire — so an older coordinator reads it
        // unchanged.
        assert_eq!(json, r#"{"type":"heartbeat"}"#);
        let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn a_bare_heartbeat_decodes_with_an_empty_roster() {
        // A beat from a relay that predates the presence roster (or the backbone
        // RTT set) carries neither field; it must decode with both empty, not
        // error.
        let json = r#"{"type":"heartbeat"}"#;
        let back: RelayToCoordinator = serde_json::from_str(json).unwrap();
        assert_eq!(
            back,
            RelayToCoordinator::Heartbeat {
                sessions: vec![],
                region_rtts: vec![],
            },
        );
    }

    #[test]
    fn a_presence_bearing_heartbeat_roundtrips_json() {
        let message = RelayToCoordinator::Heartbeat {
            sessions: vec![SessionPresence {
                tenant: TenantId("sb-staging".to_owned()),
                session: SessionId(42),
                slots: vec![SlotId(0), SlotId(3)],
            }],
            region_rtts: vec![],
        };
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("\"type\":\"heartbeat\""));
        assert!(json.contains("\"sessions\""));
        let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn an_rtt_bearing_heartbeat_roundtrips_and_omits_an_empty_set() {
        // A beat carrying measured backbone RTTs serializes the field; the same
        // beat with an empty set omits it entirely (byte-identical to a beat that
        // never measured anything), so an older coordinator reads either unchanged.
        let with_rtts = RelayToCoordinator::Heartbeat {
            sessions: vec![],
            region_rtts: vec![
                RegionRttReport {
                    region: RegionId("eu-central".to_owned()),
                    rtt_ms: 87,
                },
                RegionRttReport {
                    region: RegionId("us-east".to_owned()),
                    rtt_ms: 42,
                },
            ],
        };
        let json = serde_json::to_string(&with_rtts).unwrap();
        assert!(json.contains("\"region_rtts\""));
        let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
        assert_eq!(back, with_rtts);

        let empty = RelayToCoordinator::Heartbeat {
            sessions: vec![],
            region_rtts: vec![],
        };
        let empty_json = serde_json::to_string(&empty).unwrap();
        assert!(
            !empty_json.contains("region_rtts"),
            "an empty RTT set stays off the wire",
        );
    }

    #[test]
    fn an_rtt_bearing_heartbeat_decodes_on_a_pre_rtt_decoder() {
        // A coordinator whose Heartbeat variant predates `region_rtts` ignores the
        // unrecognized field rather than erroring, so a newer relay's measured beat
        // still reads as a liveness signal + its roster.
        #[derive(Debug, PartialEq, Deserialize)]
        #[serde(tag = "type", rename_all = "snake_case")]
        enum PreRttRelayToCoordinator {
            Heartbeat {
                #[serde(default)]
                sessions: Vec<SessionPresence>,
            },
            #[serde(other)]
            Unknown,
        }

        let json = serde_json::to_string(&RelayToCoordinator::Heartbeat {
            sessions: vec![],
            region_rtts: vec![RegionRttReport {
                region: RegionId("us-west".to_owned()),
                rtt_ms: 13,
            }],
        })
        .unwrap();
        let decoded: PreRttRelayToCoordinator = serde_json::from_str(&json).unwrap();
        assert_eq!(
            decoded,
            PreRttRelayToCoordinator::Heartbeat { sessions: vec![] },
        );
    }

    #[test]
    fn a_presence_bearing_heartbeat_decodes_on_a_pre_presence_decoder() {
        // A newer relay's roster-bearing beat read by a coordinator whose enum
        // still has the payload-free unit variant: internally-tagged serde ignores
        // the unrecognized `sessions` field, so the old build reads a plain
        // heartbeat rather than erroring — the beat stays a liveness signal.
        #[derive(Debug, PartialEq, Deserialize)]
        #[serde(tag = "type", rename_all = "snake_case")]
        enum PrePresenceRelayToCoordinator {
            Heartbeat,
            #[serde(other)]
            #[allow(dead_code)]
            Unknown,
        }
        let json =
            r#"{"type":"heartbeat","sessions":[{"tenant":"sb-staging","session":42,"slots":[0]}]}"#;
        let decoded: PrePresenceRelayToCoordinator = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, PrePresenceRelayToCoordinator::Heartbeat);
    }

    #[test]
    fn relay_to_coordinator_draining_roundtrips_json() {
        let message = RelayToCoordinator::Draining;
        let json = serde_json::to_string(&message).unwrap();
        // A payload-free drain request: just the tag, like a heartbeat.
        assert_eq!(json, r#"{"type":"draining"}"#);
        let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn coordinator_to_relay_drain_ack_roundtrips_json() {
        let message = CoordinatorToRelay::DrainAck;
        let json = serde_json::to_string(&message).unwrap();
        // A payload-free acknowledgement: just the tag.
        assert_eq!(json, r#"{"type":"drain_ack"}"#);
        let back: CoordinatorToRelay = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn draining_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
        // Forward compatibility: a `Draining` up-frame decoded by the down-direction
        // `CoordinatorToRelay` (which has no such variant) folds into `Unknown`
        // rather than erroring — an older coordinator's path against a newer relay.
        let json = r#"{"type":"draining"}"#;
        let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, CoordinatorToRelay::Unknown);
    }

    #[test]
    fn drain_ack_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
        // Forward compatibility: a `DrainAck` down-frame decoded by the up-direction
        // `RelayToCoordinator` (which has no such variant) folds into `Unknown`
        // rather than erroring — an older relay's path against a newer coordinator.
        let json = r#"{"type":"drain_ack"}"#;
        let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, RelayToCoordinator::Unknown);
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
    fn relay_to_coordinator_session_closed_roundtrips_json() {
        let message = RelayToCoordinator::SessionClosed {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
        };
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("\"type\":\"session_closed\""));
        let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn session_closed_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
        // Forward compatibility: a `SessionClosed` up-frame decoded by the
        // down-direction `CoordinatorToRelay` (which has no such variant) folds
        // into `Unknown` rather than erroring — an older coordinator's path.
        let json = r#"{"type":"session_closed","tenant":"sb-staging","session":42}"#;
        let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, CoordinatorToRelay::Unknown);
    }

    #[test]
    fn relay_to_coordinator_flight_recording_roundtrips_json() {
        let message = RelayToCoordinator::FlightRecording(FlightRecordingNotice {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
            desynced: true,
            payload: r#"{"version":1,"session":42,"events":[]}"#.to_owned(),
        });
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("\"type\":\"flight_recording\""));
        let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
        // The opaque payload survives the round trip byte-for-byte — the
        // coordinator stores exactly what the relay shipped.
        let RelayToCoordinator::FlightRecording(notice) = back else {
            panic!("expected a flight_recording frame");
        };
        assert_eq!(notice.payload, r#"{"version":1,"session":42,"events":[]}"#);
        assert!(notice.desynced);
    }

    #[test]
    fn flight_recording_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
        // Forward compatibility: a `FlightRecording` up-frame decoded by the
        // down-direction `CoordinatorToRelay` (which has no such variant) folds
        // into `Unknown` rather than erroring — a coordinator that predates the
        // variant skips the shipment (the blob is lost) instead of tearing the
        // connection down.
        let json = r#"{"type":"flight_recording","tenant":"sb-staging","session":42,"desynced":false,"payload":"{}"}"#;
        let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, CoordinatorToRelay::Unknown);
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
                relay_addrs: vec![],
            }],
            bounds: BufferBounds::new(1, 6).unwrap(),
            authority_order: vec![RelayId(1), RelayId(2)],
            external_id: Some("game-99".to_owned()),
            slot_refs: vec![SlotExternalRef {
                slot: SlotId(0),
                external_ref: "sb-user-7".to_owned(),
            }],
            observer_slots: vec![SlotId(1)],
            expected_slots: vec![SlotId(0), SlotId(1)],
            homed_slots: vec![SlotId(0)],
            resumed: true,
            departed_slots: vec![DepartedSlot {
                slot: SlotId(2),
                kind: DepartureKind::Dropped,
            }],
            latency_estimate_ms: Some(30),
        };
        let json = serde_json::to_string(&desc).unwrap();
        let back: SessionDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(back, desc);
    }

    #[test]
    fn session_descriptor_without_rehome_fields_decodes_to_defaults() {
        // A descriptor from a coordinator that predates the rehome fields must
        // still decode: `resumed` defaults false and `departed_slots` empty, so
        // the normal start-on-coverage path runs unchanged.
        let json = r#"{
            "tenant":"sb-staging","session":42,
            "peers":[],
            "bounds":{"min":1,"max":6}
        }"#;
        let back: SessionDescriptor = serde_json::from_str(json).unwrap();
        assert!(
            !back.resumed,
            "a descriptor that predates rehome is not resumed"
        );
        assert!(back.departed_slots.is_empty());
    }

    #[test]
    fn session_descriptor_with_rehome_fields_decodes_them() {
        // A rehome-rebuilt descriptor: `resumed` and the seeded departed slots
        // round-trip verbatim so a fresh relay taking over the session can seed
        // its consensus with the already-decided departures.
        let json = r#"{
            "tenant":"sb-staging","session":42,
            "peers":[],
            "bounds":{"min":1,"max":6},
            "resumed":true,
            "departed_slots":[{"slot":1,"kind":"left"},{"slot":3,"kind":"dropped"}]
        }"#;
        let back: SessionDescriptor = serde_json::from_str(json).unwrap();
        assert!(back.resumed);
        assert_eq!(
            back.departed_slots,
            vec![
                DepartedSlot {
                    slot: SlotId(1),
                    kind: DepartureKind::Left,
                },
                DepartedSlot {
                    slot: SlotId(3),
                    kind: DepartureKind::Dropped,
                },
            ],
        );
    }

    #[test]
    fn session_descriptor_omits_absent_correlation_ids_on_the_wire() {
        // `skip_serializing_if` keeps an unset session id off the wire (matching
        // `SessionRequest`'s style); `slot_refs` has no such attribute (it mirrors
        // `authority_order`'s plain `#[serde(default)]`), so an empty Vec still
        // serializes as `[]`, not omitted.
        let desc = SessionDescriptor {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(1),
            peers: vec![],
            bounds: BufferBounds::new(1, 6).unwrap(),
            authority_order: vec![],
            external_id: None,
            slot_refs: vec![],
            observer_slots: vec![],
            expected_slots: vec![],
            homed_slots: vec![],
            resumed: false,
            departed_slots: vec![],
            latency_estimate_ms: None,
        };
        let json = serde_json::to_string(&desc).unwrap();
        assert!(!json.contains("external_id"));
        assert!(!json.contains("latency_estimate_ms"));
        assert!(json.contains("\"slot_refs\":[]"));
        assert!(json.contains("\"observer_slots\":[]"));
        assert!(json.contains("\"expected_slots\":[]"));
        assert!(json.contains("\"homed_slots\":[]"));
    }

    #[test]
    fn session_descriptor_without_authority_order_decodes_to_empty() {
        // A descriptor from a coordinator that predates the authority order —
        // the peer cert, and the correlation ids — must still decode (the relay
        // falls back to relay-id order, and to its configured mesh roots for the
        // dial) rather than tearing down the control connection over a missing
        // field.
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
        assert!(back.external_id.is_none());
        assert!(
            back.slot_refs.is_empty(),
            "a descriptor from a coordinator that predates the correlation ids \
             decodes to no external_id and no slot_refs, not a decode error",
        );
        assert!(
            back.observer_slots.is_empty(),
            "a descriptor that predates the observer field decodes to no \
             observer_slots, not a decode error",
        );
        assert!(
            back.expected_slots.is_empty(),
            "a descriptor that predates the expected-slots field decodes to no \
             expected_slots, not a decode error — the start directive is simply off",
        );
        assert!(
            back.homed_slots.is_empty(),
            "a descriptor that predates the homed-slots field decodes to no \
             homed_slots, not a decode error — home-relay binding is simply unenforced",
        );
    }

    #[test]
    fn session_descriptor_with_homed_slots_decodes_the_set() {
        // A descriptor from a coordinator that carries the homed-slot set: the
        // slots assigned to this relay decode back verbatim, so the relay's
        // admission check can enforce against it.
        let json = r#"{
            "tenant":"sb-staging","session":42,
            "peers":[],
            "bounds":{"min":1,"max":6},
            "homed_slots":[0,2]
        }"#;
        let back: SessionDescriptor = serde_json::from_str(json).unwrap();
        assert_eq!(back.homed_slots, vec![SlotId(0), SlotId(2)]);
    }

    #[test]
    fn session_descriptor_with_expected_slots_decodes_the_set() {
        // A descriptor from a coordinator that carries the expected-slot set:
        // every player and observer that must connect before the session starts
        // decodes back verbatim, so the relay's authority can size its coverage
        // check against it.
        let json = r#"{
            "tenant":"sb-staging","session":42,
            "peers":[],
            "bounds":{"min":1,"max":6},
            "expected_slots":[0,1,2]
        }"#;
        let back: SessionDescriptor = serde_json::from_str(json).unwrap();
        assert_eq!(back.expected_slots, vec![SlotId(0), SlotId(1), SlotId(2)]);
    }

    #[test]
    fn session_response_roundtrips_json() {
        let resp = SessionResponse {
            session: SessionId(1),
            home_relay: RelayEndpoint {
                relay_id: RelayId(1),
                relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
                cert_der: vec![0x30, 0x82, 0x01, 0x02],
                relay_addrs: vec![],
            },
            slot_homes: vec![SlotHome {
                slot: SlotId(1),
                relay: RelayEndpoint {
                    relay_id: RelayId(2),
                    relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14901)),
                    cert_der: vec![0x30, 0x82, 0x03, 0x04],
                    relay_addrs: vec![],
                },
            }],
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
    fn session_response_without_slot_homes_decodes_to_empty() {
        // A production session (and a response from a coordinator that predates the
        // field) carries no slot homes: the field defaults to empty rather than
        // failing to decode, so every slot homes on `home_relay`.
        let json = r#"{
            "session":1,
            "home_relay":{"relay_id":1,"relay_addr":"127.0.0.1:14900","cert_der":[48,130,1,2]},
            "tokens":[{"slot":0,"token":[171,205]}],
            "bounds":{"min":1,"max":6}
        }"#;
        let back: SessionResponse = serde_json::from_str(json).unwrap();
        assert!(back.slot_homes.is_empty());
    }

    #[test]
    fn player_handoff_carries_pubkey() {
        let h = PlayerHandoff {
            slot: SlotId(3),
            client_pubkey: ClientPublicKey([0x42; 32]),
            external_ref: Some("sb-user-77".to_owned()),
            observer: false,
            region: None,
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: PlayerHandoff = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn session_request_without_external_id_decodes() {
        // A request from an app server that predates the correlation ids must
        // still decode — the field is optional and defaults to `None`, so old
        // and new peers interop (the control protos don't `deny_unknown_fields`).
        let json = r#"{
            "tenant":"sb-staging",
            "players":[{"slot":0,"client_pubkey":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32]}]
        }"#;
        let back: SessionRequest = serde_json::from_str(json).unwrap();
        assert!(back.external_id.is_none());
        assert!(
            back.players[0].external_ref.is_none(),
            "a player handoff without external_ref decodes to None too",
        );
        assert!(
            !back.players[0].observer,
            "a player handoff without the observer field decodes to a competitor",
        );
    }

    #[test]
    fn session_request_omits_absent_correlation_ids_on_the_wire() {
        // `skip_serializing_if` keeps an unset id off the wire, so a new
        // encoder talking to an old decoder emits exactly the old shape.
        let req = SessionRequest {
            tenant: TenantId("sb-staging".to_owned()),
            players: vec![PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0x11; 32]),
                external_ref: None,
                observer: false,
                region: None,
            }],
            external_id: None,
            latency_estimate_ms: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("external_id"));
        assert!(!json.contains("external_ref"));
        assert!(!json.contains("latency_estimate_ms"));
        // `observer` is a plain `#[serde(default)]` bool with no
        // `skip_serializing_if`, so a competitor still serializes as
        // `"observer":false` — an old decoder just ignores it.
        assert!(json.contains("\"observer\":false"));
    }

    #[test]
    fn departure_roundtrips_json() {
        let notice = DepartureNotice {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
            slot: SlotId(2),
            kind: DepartureKind::Dropped,
            reason: 0x4000_0006,
            leave_seq: 1,
            external_id: Some("game-99".to_owned()),
            external_ref: Some("sb-user-7".to_owned()),
            result: Some(ResultEcho {
                payload: vec![0xDE, 0xAD],
                arrival_ms: 1_700_000_000_000,
                session_frame: Some(4200),
                slot_frame: Some(4242),
            }),
        };
        let message = RelayToCoordinator::Departure(notice.clone());
        let json = serde_json::to_string(&message).unwrap();
        // The notice's fields ride alongside the tag (internally tagged), and
        // the kind serializes snake_case.
        assert!(json.contains("\"type\":\"departure\""));
        assert!(json.contains("\"kind\":\"dropped\""));
        // The embedded result rides along.
        assert!(json.contains("\"result\""));
        let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn departure_without_correlation_ids_decodes_to_none() {
        // A notice from a relay that never received (or predates) the
        // correlation ids must still decode — the fields are optional and
        // default to `None`, so the coordinator's own session-refs fallback
        // kicks in rather than a decode error.
        let json = r#"{"type":"departure","tenant":"sb-staging","session":42,"slot":2,"kind":"dropped","reason":1073741830,"leave_seq":1}"#;
        let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
        let RelayToCoordinator::Departure(notice) = decoded else {
            panic!("decodes to the Departure variant");
        };
        assert!(notice.external_id.is_none());
        assert!(notice.external_ref.is_none());
        assert!(
            notice.result.is_none(),
            "a departure from a relay that predates the embedded result decodes to None",
        );
    }

    #[test]
    fn departure_omits_absent_correlation_ids_on_the_wire() {
        let notice = DepartureNotice {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(1),
            slot: SlotId(0),
            kind: DepartureKind::Left,
            reason: 3,
            leave_seq: 1,
            external_id: None,
            external_ref: None,
            result: None,
        };
        let json = serde_json::to_string(&notice).unwrap();
        assert!(!json.contains("external_id"));
        assert!(!json.contains("external_ref"));
        assert!(
            !json.contains("result"),
            "an absent embedded result is omitted, not sent as null",
        );
    }

    #[test]
    fn departure_kind_left_serializes_snake_case() {
        let json = serde_json::to_string(&DepartureKind::Left).unwrap();
        assert_eq!(json, r#""left""#);
    }

    #[test]
    fn desync_roundtrips_json() {
        let notice = DesyncNotice {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
            sync_ordinal: 137,
            game_frame: Some(4242),
            detected_at_ms: 1_700_000_000_000,
            no_majority: false,
            diverged: vec![DivergedSlot {
                slot: SlotId(2),
                external_ref: Some("sb-user-7".to_owned()),
            }],
            external_id: Some("game-99".to_owned()),
        };
        let message = RelayToCoordinator::Desync(notice.clone());
        let json = serde_json::to_string(&message).unwrap();
        // The notice's fields ride alongside the tag (internally tagged).
        assert!(json.contains("\"type\":\"desync\""));
        assert!(json.contains("\"sync_ordinal\":137"));
        let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn desync_omits_absent_optionals_on_the_wire() {
        // A no-majority (1v1) desync: no game frame, no correlation ids, and an
        // empty diverged set. The optional fields are omitted (not `null`); the
        // always-present ones (detected_at_ms, no_majority, diverged) still
        // serialize.
        let notice = DesyncNotice {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(1),
            sync_ordinal: 5,
            game_frame: None,
            detected_at_ms: 123,
            no_majority: true,
            diverged: vec![],
            external_id: None,
        };
        let json = serde_json::to_string(&notice).unwrap();
        assert!(!json.contains("game_frame"));
        assert!(!json.contains("external_id"));
        assert!(json.contains("\"no_majority\":true"));
        assert!(json.contains("\"diverged\":[]"));
    }

    #[test]
    fn desync_without_optionals_decodes() {
        // A notice from a relay that carried no game frame or correlation ids
        // must still decode — the optional fields default, so the coordinator's
        // own fallbacks apply rather than a decode error.
        let json = r#"{"type":"desync","tenant":"sb-staging","session":42,"sync_ordinal":9,"detected_at_ms":7,"no_majority":false,"diverged":[{"slot":3}]}"#;
        let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
        let RelayToCoordinator::Desync(notice) = decoded else {
            panic!("decodes to the Desync variant");
        };
        assert!(notice.game_frame.is_none());
        assert!(notice.external_id.is_none());
        assert_eq!(notice.diverged.len(), 1);
        assert!(notice.diverged[0].external_ref.is_none());
    }

    #[test]
    fn desync_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
        // Forward compatibility: a `Desync` up-frame decoded by the down-direction
        // `CoordinatorToRelay` (which has no such variant) folds into `Unknown`
        // rather than erroring — the "old peer sees a new frame" path.
        let json = r#"{"type":"desync","tenant":"sb-staging","session":42,"sync_ordinal":9,"detected_at_ms":7,"no_majority":false,"diverged":[]}"#;
        let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, CoordinatorToRelay::Unknown);
    }

    #[test]
    fn departure_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
        // Forward compatibility, made concrete: `Departure` is an up-frame the
        // relay sends. A decoder that predates it — here the *down*-direction
        // `CoordinatorToRelay`, which has no `Departure` — must fold the frame
        // into its `Unknown` catch-all rather than erroring, exactly as an older
        // coordinator build would. This is the "old peer sees a new frame" path.
        let json = r#"{"type":"departure","tenant":"sb-staging","session":42,"slot":2,"kind":"dropped","reason":1073741830,"leave_seq":1}"#;
        let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, CoordinatorToRelay::Unknown);
    }

    #[test]
    fn result_roundtrips_json() {
        let notice = ResultNotice {
            tenant: TenantId("sb-staging".to_owned()),
            session: SessionId(42),
            slot: SlotId(1),
            external_id: Some("game-99".to_owned()),
            external_ref: Some("sb-user-7".to_owned()),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            arrival_ms: 1_700_000_000_000,
            session_frame: Some(4200),
            slot_frame: Some(4242),
        };
        let message = RelayToCoordinator::Result(notice.clone());
        let json = serde_json::to_string(&message).unwrap();
        // The notice's fields ride alongside the tag (internally tagged).
        assert!(json.contains("\"type\":\"result\""));
        assert!(json.contains("\"arrival_ms\":1700000000000"));
        let back: RelayToCoordinator = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }

    #[test]
    fn result_without_optionals_decodes() {
        // A notice from a relay that carried no correlation ids or frame stamps
        // must still decode — the optional fields default, so the coordinator's
        // own fallbacks apply rather than a decode error. The payload and
        // arrival stamp are always present.
        let json = r#"{"type":"result","tenant":"sb-staging","session":42,"slot":0,"payload":[1,2,3],"arrival_ms":7}"#;
        let decoded: RelayToCoordinator = serde_json::from_str(json).unwrap();
        let RelayToCoordinator::Result(notice) = decoded else {
            panic!("decodes to the Result variant");
        };
        assert!(notice.external_id.is_none());
        assert!(notice.external_ref.is_none());
        assert!(notice.session_frame.is_none());
        assert!(notice.slot_frame.is_none());
        assert_eq!(notice.payload, vec![1, 2, 3]);
    }

    #[test]
    fn result_frame_decodes_to_unknown_on_a_decoder_without_the_variant() {
        // Forward compatibility: a `Result` up-frame decoded by the
        // down-direction `CoordinatorToRelay` (which has no such variant) folds
        // into `Unknown` rather than erroring — the "old peer sees a new frame"
        // path an older coordinator build would take.
        let json = r#"{"type":"result","tenant":"sb-staging","session":42,"slot":0,"payload":[1,2,3],"arrival_ms":7}"#;
        let decoded: CoordinatorToRelay = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, CoordinatorToRelay::Unknown);
    }
}
