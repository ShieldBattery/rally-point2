//! Session setup: take an app-server session request, assign each player a home
//! relay, mint one connection-bound token per player, and return the session
//! response the app server hands to the game DLLs at launch.
//!
//! This is the coordinator's primary production action. The app server has
//! already formed the lobby (matchmaking stays in the app server); the
//! coordinator finds relays and mints tokens. The response carries:
//!
//! - The session id (coordinator-assigned, unique within the tenant).
//! - The home relay (where clients connect). A session is single-relay by
//!   default — every slot homes there — but a dev-forced cross-relay split can
//!   move individual slots onto a secondary relay, listed per slot in
//!   `slot_homes`. Multi-relay redundancy is per-player home relays plus the
//!   mesh: a relay that serves a session always homes at least one of its slots.
//! - One token per player, each binding the player's client pubkey to its
//!   slot and session.
//! - The latency-buffer bounds the relay's decision-maker clamps to.
//!
//! The coordinator also builds a [`SessionDescriptor`](rally_point_proto::control::SessionDescriptor) per relay — what drives
//! `MeshCommand::Join` in production. `create_session` records which relays
//! serve which session; `descriptor_for` reads that membership to build the
//! per-relay mesh-peer list. `create_session` both returns the response for the
//! app server *and* stages each relay's descriptor in the
//! [outbox](crate::descriptors), which the relay's descriptor-fetch endpoint
//! delivers to the running relay.

mod create;
mod descriptor;
mod gate;
mod placement;
mod rehome;
mod setup;

pub use create::{create_or_provision_session, create_or_provision_session_at, create_session};
pub use descriptor::{build_descriptor, descriptor_for, relay_region_for, session_refs};
pub use gate::ProvisionGate;
pub use rehome::{recorded_rehome, rehome, rehome_evicting, rehome_with_assignment_commit};
pub use setup::SessionSetup;

pub(crate) use rehome::{refresh_resumed_descriptors, session_capable_cohort};

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rally_point_proto::control::{RegionId, RelayEndpoint, SessionResponse};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};

/// The relay ids serving one session, keyed by `(tenant, session)`.
///
/// This is the session→relay membership the coordinator records at
/// `create_session` time and `descriptor_for` reads. Without it, the
/// coordinator couldn't distinguish "peers in this session" from "all
/// registered relays" — a multi-relay fleet would tell a relay to mesh with
/// peers outside its session.
type SessionRelays =
    Arc<Mutex<HashMap<(rally_point_proto::control::TenantId, SessionId), Vec<RelayId>>>>;

/// The tenant's own correlation ids for a session and its players, keyed by
/// `(tenant, session)`. Recorded at `create_session` from the request and read
/// when a departure notice arrives, so the webhook names the game + player in
/// the tenant's own terms without the coordinator (or the tenant) keeping any
/// other session map.
type SessionRefsStore =
    Arc<Mutex<HashMap<(rally_point_proto::control::TenantId, SessionId), SessionRefs>>>;

/// The correlation ids a tenant attached to one session: the session's own id
/// and the per-slot player ids. Both are optional — a request from an app server
/// that predates the fields carries neither, and the webhook simply omits them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionRefs {
    /// The tenant's own id for the session (ShieldBattery's `gameId`).
    pub external_id: Option<String>,
    /// Whether this session runs home-side drop finalization
    /// ([`SessionDescriptor::finalized_drops`](rally_point_proto::control::SessionDescriptor::finalized_drops)): its cohort is capable AND
    /// the coordinator's finalized-drops feature switch was on at create.
    /// Decided once at create and immutable — every descriptor rebuild
    /// (rehome, late-departure refresh) reads the flag from here.
    pub finalized_drops: bool,
    /// Whether every relay in this session's capability-homogeneous cohort
    /// advertises
    /// [`CAPABILITY_FINALIZED_DROP_V1`](rally_point_proto::control::CAPABILITY_FINALIZED_DROP_V1)
    /// — the session's BUILD
    /// class, distinct from `finalized_drops` (the feature can be switched
    /// off while cohorts still exist). Rehome replacement picks and
    /// enrollment-time cohort eviction key on THIS, never on the feature
    /// flag: a session must never mix relays across the capability boundary
    /// regardless of whether the handshake is enabled, because the two build
    /// classes deliver dropped-leave counts differently and mixing them
    /// hands different clients different leave schedules.
    pub capable_cohort: bool,
    /// The tenant's own id for the player in each slot (a stringified
    /// `SbUserId`). Only slots whose handoff carried an `external_ref` appear.
    pub slots: HashMap<SlotId, String>,
    /// The slots the request flagged as observers. Carried into every relay's
    /// [`SessionDescriptor::observer_slots`](rally_point_proto::control::SessionDescriptor::observer_slots) so the relay's desync comparator
    /// excludes them. Recorded here, alongside the correlation ids, so it
    /// survives the same restart/persistence paths those do.
    pub observers: Vec<SlotId>,
    /// Every slot the request listed — players and observers alike. Carried into
    /// every relay's [`SessionDescriptor::expected_slots`](rally_point_proto::control::SessionDescriptor::expected_slots) so the session's
    /// authority relay knows the full set that must connect before it fires the
    /// session-start directive. Recorded here, alongside the other correlation
    /// state, so it survives the same restart/persistence paths.
    pub expected: Vec<SlotId>,
    /// Every slot's assigned home relay — the per-relay-per-slot data
    /// [`SessionDescriptor::homed_slots`](rally_point_proto::control::SessionDescriptor::homed_slots) is filtered from
    /// ([`build_descriptor`] keeps only the entries matching the relay a
    /// descriptor is being built for). A `BTreeMap`, not a `HashMap`, so the
    /// filtered `homed_slots` a descriptor carries is in a deterministic
    /// (ascending slot) order rather than hash order — descriptors are
    /// compared in tests, and a relay's admission check reads the set
    /// unordered anyway, but nothing is served by leaving the order to chance.
    /// [`rehome`] reassigns the dead relay's entries onto the replacement
    /// before rebuilding descriptors, so this always reflects current
    /// membership, not just the session's original assignment.
    pub homes: std::collections::BTreeMap<SlotId, RelayId>,
    /// The SHA-256 fingerprint of the DER certificate each serving relay's
    /// clients currently pin, keyed by relay id. Recorded at session creation
    /// for every serving relay, and updated for the replacement relay on every
    /// re-home (including a same-id restart, where
    /// it captures the relay's fresh cert under its unchanged id). A relay
    /// restart mints a new cert under the same id, so this — not the relay's
    /// enroll generation, which also bumps on a benign reconnect of an
    /// unchanged cert — is what tells a stay-or-move decision apart from a
    /// false alarm: the id being enrolled is not enough, the cert its clients
    /// hold must still be the one currently live.
    pub relay_certs: std::collections::BTreeMap<RelayId, [u8; 32]>,
    /// Each serving relay's region at the time it was picked, keyed by relay id
    /// (`None` for an untagged relay). Recorded at session creation and updated
    /// for the replacement relay on every re-home, alongside `relay_certs`, so a
    /// re-home can prefer a live relay in the *dead* relay's region for the
    /// replacement — keeping a re-homed slot near where it was placed — before
    /// falling back to a region-blind pick. A `BTreeMap` for the same
    /// deterministic-order reason as `homes`.
    pub relay_regions: std::collections::BTreeMap<RelayId, Option<RegionId>>,
    /// The tenant's worst-pairwise one-way path-latency estimate (milliseconds)
    /// for the session, from the [`SessionRequest`](rally_point_proto::control::SessionRequest). Carried into every serving
    /// relay's `SessionDescriptor::latency_estimate_ms` so the authority relay
    /// folds it into the initial buffer depth it sizes.
    /// Recorded here, alongside the other correlation state, so it survives the
    /// same restart/persistence paths and is carried by a rehome-rebuilt descriptor
    /// too (harmless there: a resumed relay never re-stamps a depth). `None` when
    /// the request carried no estimate.
    pub latency_estimate_ms: Option<u32>,
}

/// The outcome of [`create_session`]: the response to hand the app server, and
/// whether it was replayed from the create-idempotency cache rather than freshly
/// minted.
///
/// `replayed` lets the api handler tell a fresh create from an idempotent retry:
/// a fresh create arms the session's lifecycle accounting, while a replay must
/// **not** — the original create already registered it, and re-registering would
/// reset the live session's never-started clock and overwrite its serving-relay
/// set with a possibly-stale one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedSession {
    /// The session response the app server hands to its clients.
    pub response: SessionResponse,
    /// Whether `response` was replayed from the idempotency cache (a retry of a
    /// create for an `external_id` already bound to a live session) rather than
    /// freshly minted.
    pub replayed: bool,
}

/// The default warm-demand TTL a coordinator with no provisioning loop stamps on
/// its (unread) warm store. Nothing consumes that store, so the exact value is
/// immaterial — it only has to be positive; a provisioning-enabled coordinator
/// overrides it from its configured warm TTL.
const DEFAULT_WARM_TTL: Duration = Duration::from_secs(600);

/// The floor on how long an abandoned pending-create anchor is kept before a
/// consult prunes it, used when ten hold caps would be shorter. Ten minutes is
/// far longer than any live create's retry span, so a create that polls within
/// the cap is never pruned out from under itself.
const PENDING_PRUNE_MIN_SLACK: Duration = Duration::from_secs(600);

/// The outcome of a hold-until-ready create: either a session to hand back, or a
/// signal that a requested region has no relay yet and the create is being held.
///
/// A [`Provisioning`](Self::Provisioning) outcome mints nothing — no session, no
/// idempotency entry, no descriptors, no lifecycle state. It means the
/// coordinator has warmed the listed regions and is holding the create; the
/// caller re-sends the byte-identical signed request until the region's relay
/// enrolls (the retry then places in-region and returns
/// [`Created`](Self::Created)) or the coordinator's hold cap elapses (the retry
/// then falls back to region-blind placement and also returns `Created`). The
/// held request never changes, so its idempotency fingerprint is undisturbed
/// across the retries.
pub enum CreateOutcome {
    /// A minted or replayed session — the app-server response plus whether it was
    /// an idempotent replay (see [`CreatedSession`]).
    Created(CreatedSession),
    /// The listed regions have no available relay; the coordinator warmed them and
    /// is holding the create. No session was minted.
    Provisioning {
        /// The still-unlit requested regions being warmed.
        regions: Vec<RegionId>,
    },
}

/// Whether a create consults the provisioning gate.
enum CreatePolicy {
    /// Place immediately, falling back to region-blind placement for an unlit
    /// region — never warming or holding. This is the behavior of
    /// [`create_session`].
    Immediate,
    /// Consult the provisioning gate: a request naming an unlit region on a
    /// provisioning-enabled coordinator warms it and holds (returns
    /// [`CreateOutcome::Provisioning`]) until the region's relay enrolls or the
    /// hold cap — measured against `now`, Unix seconds — elapses. A `now` of
    /// `u64::MAX` marks an unusable clock, on which a create never holds.
    HoldUntilReady { now: u64 },
}

/// The outcome of a coordinator-mediated re-home request (`POST /session/rehome`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RehomeOutcome {
    /// The named relay is still live in the registry — the client should keep
    /// dialing it rather than move, resuming its same-relay reconnect backoff.
    Stay,
    /// No live relay could take the session over (none registered, or the session
    /// is unknown to this coordinator lifetime). The client keeps its same-relay
    /// backoff and re-asks later.
    Unavailable,
    /// The relay the whole homed group should move to, with the cert the client
    /// pins to reach it. The client keeps its token and re-dials this endpoint.
    NewTarget(RelayEndpoint),
}

/// The maximum slot id (11: BW supports 12 network participants — 8 players
/// plus 4 observers). `pub(crate)` so a heartbeat's reported slot list — which
/// arrives with no shape validation of its own — can be capped against the
/// same ceiling a session's own slots are validated against.
pub(crate) const MAX_SLOT: u8 = 11;

#[cfg(test)]
mod tests;
