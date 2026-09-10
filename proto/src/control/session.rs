//! Session setup and the coordinator's per-session config pushed to relays.
//!
//! Covers three groups that travel together through a session's lifetime:
//! the consensus-policy bounds ([`BufferBounds`]), the app-server-facing
//! request/response shapes ([`SessionRequest`], [`SessionResponse`]) and the
//! [`SessionDescriptor`] built from them for each serving relay, and the
//! fleet-wide registry data ([`MeshPeerIdentity`], [`TenantVerifyingKey`],
//! [`RegionBeaconTarget`], [`RegionRttReport`]) the coordinator distributes
//! over the same persistent control connection.

use serde::{Deserialize, Serialize};

use crate::ids::{RelayId, SessionId, SlotId};
use crate::token::{ClientPublicKey, KeyId};

use super::{DepartureKind, RegionId, RelayEndpoint, RelayPeer, TenantId};

// ---------------------------------------------------------------------------
// Consensus policy (coordinator → relay, at session setup)
// ---------------------------------------------------------------------------

/// The deepest latency buffer (in turns) the game's own sync validation
/// tolerates. This is a property of StarCraft, not a policy choice: the game
/// validates every sync command a client executes against a 16-entry ring of
/// locally recorded snapshots, addressed by a 4-bit ring index carried in the
/// command itself — with no sequence number and no wraparound detection. A
/// sync executed 16 or more turns after its snapshot was recorded silently
/// aliases onto a newer entry, fails validation, and the game drops the
/// *sender* — deterministically on every client at once, so a session that
/// crosses the boundary collapses rather than degrades. Buffer fills (the
/// session-start seed, a directive raising the depth) are the sharpest edge:
/// the game issues all injected turns within one step, so they share one
/// snapshot whose ring slot expires together.
///
/// In live games the fatal depth is 15 — one turn of skew between issue and
/// execution puts the effective delivery delay at depth + 1 — which leaves 14
/// as the structural ceiling, validating with zero margin. Policy should stay
/// below this ceiling, not at it (the game's own networking never ran deeper
/// than 12).
pub const GAME_SYNC_SAFE_BUFFER_MAX: u32 = 14;

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
///
/// **Depth and the game's own sync validation.** The relay tolerates any
/// depth; the *game* does not. `max` must never exceed
/// [`GAME_SYNC_SAFE_BUFFER_MAX`] — past that ceiling the game's native sync
/// validation mass-drops players deterministically (see the constant's docs).
/// The coordinator enforces this when it loads its tenant registry, so an
/// over-deep `max` fails startup rather than killing sessions.
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
    #[serde(with = "super::serde_bytes")]
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
    /// Each serving relay's region at pick time, keyed by relay id — the same
    /// per-relay data [`SessionDescriptor::relay_regions`] carries to a relay, mirrored onto this
    /// tenant-facing response for the tenant's own operator-facing tooling (e.g. a game-history
    /// or debugging view). Only relays the coordinator tagged with a region appear; an untagged
    /// relay, or a coordinator run without a region catalog, has no entry.
    ///
    /// This travels the control-plane response the app server receives, not the client-facing
    /// [`super::RelayEndpoint`]/[`super::RelayPeer`] shapes a game client ultimately dials — see
    /// [`super::RelayEntry::region`] for why region is withheld from those until a relay's own
    /// gameplay-elapsed release. A tenant must not thread this list into anything it hands a game
    /// client before that release would have disclosed the same information.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_regions: Vec<RelayRegionLabel>,
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
    /// only *ranks* the relays (home relay first: the unique plurality home, or
    /// a session-id rotation among equally populated homes); it plays no part
    /// in the live verdict.
    ///
    /// Defaults empty for descriptors from a coordinator that predates the
    /// field; a relay falls back to relay-id order over the session's relay
    /// set — the interim rule this order replaces.
    #[serde(default)]
    pub authority_order: Vec<RelayId>,
    /// The tenant's own id for the session (ShieldBattery's `gameId`), echoed
    /// from the [`SessionRequest`] that created it. Carried all the way down to
    /// every relay serving the session — not just kept coordinator-side — so a
    /// relay can stamp it into a [`super::DepartureNotice`] without the notification
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
    /// Whether home-side drop finalization is enabled for this session: every
    /// relay ever assigned to it advertises
    /// [`super::CAPABILITY_FINALIZED_DROP_V1`], so an honored drop request runs the
    /// `FinalizeDrop` handshake and a dropped leave may carry a finalized
    /// exact count. **Immutable for the session's lifetime** — decided at
    /// create, preserved verbatim through every rebuild (rehome included),
    /// and a session created without it stays without it until retirement.
    /// Defaults `false` for a descriptor from a coordinator that predates the
    /// field.
    #[serde(default)]
    pub finalized_drops: bool,
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
    /// Every relay serving this session paired with the region it enrolled in —
    /// the whole session's map, not just this relay's own entry, since a relay
    /// releases the complete map to its clients. Relays the coordinator never
    /// tagged with a region are omitted entirely, so an absent entry means
    /// "unlabeled" rather than "labeled with nothing".
    ///
    /// This is the only path a region reaches a relay — and, through it, a game
    /// client. [`SessionResponse::relay_regions`] carries the same per-relay data
    /// to the tenant's app server for its own operator-facing tooling, but that is
    /// a separate, tenant-only echo never released to a client on its own. A
    /// relay holds this map until its own clock says a stretch of real
    /// gameplay has elapsed, then releases it to its local clients as a
    /// [`RegionLabels`](crate::messages::RegionLabels) frame — see
    /// [`super::RelayEntry::region`] for why the labels are withheld until gameplay has
    /// genuinely elapsed. Re-issued on every descriptor push, so a re-home's
    /// replacement relay and its new region reach every serving relay through
    /// the same rebuild that updates the peer set. Defaults empty for a
    /// descriptor from a coordinator that predates the field, which simply means
    /// the relay has no labels to release.
    #[serde(default)]
    pub relay_regions: Vec<RelayRegionLabel>,
}

/// One relay's region label within a [`SessionDescriptor::relay_regions`] map.
/// Mirrors [`SlotExternalRef`]'s shape (an id plus one datum) rather than a bare
/// tuple, so the wire form stays a self-describing JSON object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRegionLabel {
    /// The relay the label describes.
    pub relay_id: RelayId,
    /// The region that relay enrolled in. Only relays the coordinator tagged
    /// appear in the map at all, so this is never an empty placeholder.
    pub region: RegionId,
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
    /// The exact turn count the original leave directive carried
    /// ([`super::DepartureNotice::final_turn_count`], retained by the coordinator), so
    /// the fresh relay's seeded directive schedules the leave's application at
    /// the same simulation step the original did — a survivor that never
    /// received the original directive picks it up from the seeded one on
    /// reconnect. `None` when the original carried no count (the seeded
    /// directive then falls back to frame scheduling, like any count-less
    /// leave) or the coordinator predates the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_turn_count: Option<u64>,
    /// Whether the retained count was home-finalized (see
    /// [`super::DepartureNotice::finalized`]) — carried through so the fresh relay's
    /// seed applies the same clean-leaves-or-finalized acceptance rule as
    /// every other count ingress. Defaults `false` for a coordinator that
    /// predates the field.
    #[serde(default)]
    pub finalized: bool,
}

/// Identifies one session's descriptor within a relay's set — the `(tenant,
/// session)` pair a [`SessionDescriptor`] is keyed by. Session ids are unique only
/// within a tenant, so the tenant is part of the key, mirroring the relay's own
/// routing key.
///
/// A [`super::CoordinatorToRelay::DescriptorDelta`] names one of these per session it
/// removes, and the coordinator diffs a relay's descriptor set by this key to
/// decide what a delta carries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DescriptorKey {
    /// The tenant the session belongs to.
    pub tenant: TenantId,
    /// The session, unique only within `tenant`.
    pub session: SessionId,
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
    /// and peers pin from a [`super::RelayPeer`] in a descriptor.
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
/// [`super::CoordinatorToRelay::TenantKeys`] push.
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
    #[serde(with = "super::serde_bytes")]
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
/// Carried in a [`super::CoordinatorToRelay::RegionBeacons`] push.
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
/// Carried in [`super::RelayToCoordinator::Heartbeat`]'s `region_rtts`. Declarative like
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
