//! Create-idempotency fingerprinting and the provisioning gate.
//!
//! Two small pieces of create-time policy that are independent of placement:
//! the canonical form a create request is reduced to so a replay can be told
//! from an `external_id` collision, and the warm-demand store plus hold cap a
//! create consults when a requested region has no relay yet.

use std::time::Duration;

use rally_point_proto::control::{RegionId, SessionRequest, SessionResponse};
use rally_point_proto::ids::SlotId;
use rally_point_proto::token::ClientPublicKey;

use crate::provision::WarmTargets;

use super::DEFAULT_WARM_TTL;

/// A create request reduced to the fields that shape the session it mints,
/// normalized so two requests that would produce the same session compare
/// equal. This is the canonical form the create-idempotency cache checks an
/// incoming replay against: a retry of the same logical create reproduces an
/// identical fingerprint, whereas a second create that reuses the same
/// `external_id` for a *different* game does not, and is refused rather than
/// silently handed the first game's tokens (see
/// [`SessionSetupError::IdempotentCreateMismatch`]).
///
/// The idempotency key is `(tenant, external_id)`, so those two are equal by
/// construction on any cache hit and are deliberately **excluded** here. Every
/// other field of the [`SessionRequest`] that changes the minted response or
/// the session state the coordinator records is included:
///
/// - each player's `slot` and `client_pubkey` — the token minted for a slot
///   binds that pubkey, so a differing roster mints non-interchangeable tokens.
/// - each player's `observer` flag — it selects the slot into the session's
///   observer set ([`SessionDescriptor::observer_slots`]) and the lifecycle's
///   player/observer split, shaping recorded state even though it alters no
///   token.
/// - each player's `external_ref` — stored per slot and echoed into
///   departure/result webhooks, so replaying the first roster's refs for a
///   different roster would mislabel the players.
/// - each player's `region` — selects the slot's home relay, so the same
///   `external_id` retried with different per-slot regions reads as a genuine
///   roster mismatch (a `409`), not a replay.
/// - the request's `latency_estimate_ms` — recorded into the session's
///   correlation state and carried into every serving relay's descriptor,
///   where the authority relay sizes the initial buffer from it, so replaying
///   a cached response for a request naming a different estimate would bind
///   the wrong depth input to the session.
///
/// Equality is plain struct equality ([`PartialEq`]), never a hash: a hash
/// collision must not be able to bind two genuinely different rosters to one
/// cached response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CreateFingerprint {
    /// The request's players, sorted by slot so request order does not matter.
    /// A request cannot name a slot twice (`validate_request` rejects a
    /// duplicate), so the slot totally orders this list.
    players: Vec<FingerprintPlayer>,
    /// The request's worst-pairwise one-way path-latency estimate.
    latency_estimate_ms: Option<u32>,
}

/// One player's contribution to a [`CreateFingerprint`]: the fields of a
/// [`PlayerHandoff`](rally_point_proto::control::PlayerHandoff) that shape the
/// session (its slot, the pubkey its token binds, whether it is an observer,
/// its tenant correlation ref, and its requested region).
#[derive(Debug, Clone, PartialEq, Eq)]
struct FingerprintPlayer {
    slot: SlotId,
    client_pubkey: ClientPublicKey,
    observer: bool,
    external_ref: Option<String>,
    region: Option<RegionId>,
}

impl CreateFingerprint {
    /// Reduces a request to its canonical fingerprint, sorting the players by
    /// slot so two semantically identical requests that differ only in
    /// ordering still compare equal.
    pub(super) fn from_request(request: &SessionRequest) -> Self {
        let mut players: Vec<FingerprintPlayer> = request
            .players
            .iter()
            .map(|p| FingerprintPlayer {
                slot: p.slot,
                client_pubkey: p.client_pubkey,
                observer: p.observer,
                external_ref: p.external_ref.clone(),
                region: p.region.clone(),
            })
            .collect();
        players.sort_by_key(|p| p.slot);
        Self {
            players,
            latency_estimate_ms: request.latency_estimate_ms,
        }
    }
}

/// A recorded create-idempotency entry: the response a matching replay returns,
/// and the [`CreateFingerprint`] of the request that produced it. The
/// fingerprint is what distinguishes an honest retry (same roster → replay the
/// response) from an `external_id` collision (different roster → refuse).
#[derive(Debug, Clone)]
pub(super) struct CachedCreate {
    /// The fingerprint of the request that created the cached session.
    pub(super) fingerprint: CreateFingerprint,
    /// The exact response a matching replay returns.
    pub(super) response: SessionResponse,
}

/// The provisioning knobs and the shared warm-demand store the coordinator
/// consults when a session names a region with no live relay.
///
/// The `warm` store is written by `POST /regions/warm` and by a hold-until-ready
/// create, and read by the reconcile loop, which holds a clone of the same map.
/// `create_hold` is `Some` only on a coordinator whose provisioning loop is
/// running — that presence is what turns on hold-until-ready create. A
/// coordinator with no loop holds a **dormant** gate: an orphan warm store the
/// warm endpoint still writes but nothing reads, and `create_hold: None`, so
/// every create falls back to region-blind placement immediately.
#[derive(Clone)]
pub struct ProvisionGate {
    /// Per-region warm demand, shared with the reconcile loop.
    pub(super) warm: WarmTargets,
    /// How long each warm keeps a region warm.
    pub(super) warm_ttl: Duration,
    /// The per-create hold cap: how long a create naming an unlit region is held
    /// — warmed and answered [`CreateOutcome::Provisioning`] — before it falls
    /// back to region-blind placement. `None` on a coordinator with no
    /// provisioning loop, which never holds a create.
    pub(super) create_hold: Option<Duration>,
}

impl ProvisionGate {
    /// The gate for a coordinator with a running provisioning loop. `warm` is the
    /// store the loop reconciles against, `warm_ttl` is how long each warm lasts,
    /// and `create_hold` bounds how long a create naming an unlit region holds
    /// before falling back.
    pub fn provisioning(warm: WarmTargets, warm_ttl: Duration, create_hold: Duration) -> Self {
        Self {
            warm,
            warm_ttl,
            create_hold: Some(create_hold),
        }
    }

    /// The dormant gate for a coordinator with no provisioning loop: a warm store
    /// the endpoint writes but nothing reads, and no create hold.
    pub(super) fn dormant() -> Self {
        Self {
            warm: WarmTargets::new(),
            warm_ttl: DEFAULT_WARM_TTL,
            create_hold: None,
        }
    }

    /// The shared warm-demand store — what `POST /regions/warm` writes and the
    /// reconcile loop reads.
    pub fn warm(&self) -> &WarmTargets {
        &self.warm
    }

    /// How long each warm keeps a region warm.
    pub fn warm_ttl(&self) -> Duration {
        self.warm_ttl
    }
}
