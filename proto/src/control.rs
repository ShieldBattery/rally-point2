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
    /// The tenant's own identifier for this session (ShieldBattery sets its
    /// `gameId`). The coordinator stores it and echoes it in a departure
    /// webhook, so the notification names the game without the tenant keeping a
    /// session→game map. Optional so a peer that predates the field still
    /// interops; the control protos don't `deny_unknown_fields`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
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
    /// A message kind this coordinator does not recognize (a newer relay). Decodes
    /// here so the coordinator skips it rather than dropping the connection.
    #[serde(other)]
    Unknown,
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
                external_id: None,
                slot_refs: vec![],
                observer_slots: vec![],
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
            external_id: Some("game-99".to_owned()),
            slot_refs: vec![SlotExternalRef {
                slot: SlotId(0),
                external_ref: "sb-user-7".to_owned(),
            }],
            observer_slots: vec![SlotId(1)],
        };
        let json = serde_json::to_string(&desc).unwrap();
        let back: SessionDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(back, desc);
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
        };
        let json = serde_json::to_string(&desc).unwrap();
        assert!(!json.contains("external_id"));
        assert!(json.contains("\"slot_refs\":[]"));
        assert!(json.contains("\"observer_slots\":[]"));
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
            external_ref: Some("sb-user-77".to_owned()),
            observer: false,
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
            }],
            external_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("external_id"));
        assert!(!json.contains("external_ref"));
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
        };
        let message = RelayToCoordinator::Departure(notice.clone());
        let json = serde_json::to_string(&message).unwrap();
        // The notice's fields ride alongside the tag (internally tagged), and
        // the kind serializes snake_case.
        assert!(json.contains("\"type\":\"departure\""));
        assert!(json.contains("\"kind\":\"dropped\""));
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
        };
        let json = serde_json::to_string(&notice).unwrap();
        assert!(!json.contains("external_id"));
        assert!(!json.contains("external_ref"));
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
