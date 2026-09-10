//! Read-only tenant + client views: presence, stored flight recordings, region
//! warming, a tenant's verifying key, and the region list.
//!
//! Grouped because none of them mutates a session's assignment or lifecycle —
//! they answer questions over state the rest of the coordinator maintains.

use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, Uri, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId};
use serde::{Deserialize, Serialize};

use crate::flight_store;
use crate::pair_rtts::PairRttEntry;
use crate::presence;
use crate::regions::Region;
use crate::session;
use crate::tenant;

use super::CoordinatorState;
use super::request_auth::{TenantAccess, verify_tenant_request};

/// The most user refs one presence query may ask about, so a caller cannot make
/// the coordinator resolve an unbounded list. A matchmaking check asks about one
/// user (or one party's few), so this is generous headroom — the same posture as
/// [`MAX_LIVENESS_SESSIONS`].
pub(super) const MAX_PRESENCE_USERS: usize = 64;

/// Request body for `POST /presence/query`: a tenant and the user refs to probe —
/// the tenant's own player ids, the same `external_ref` values it attached to
/// each slot at session creation.
#[derive(Debug, Deserialize)]
struct PresenceQueryRequest {
    tenant: TenantId,
    users: Vec<String>,
}

/// Response body for `POST /presence/query`: one answer per queried user, in
/// request order.
#[derive(Debug, Serialize)]
pub(super) struct PresenceQueryResponse {
    users: Vec<UserPresence>,
}

/// One queried user's presence verdict.
#[derive(Debug, Serialize)]
struct UserPresence {
    /// The queried ref, echoed back.
    user: String,
    /// Whether any relay currently reports a slot mapped to this user connected.
    in_game: bool,
    /// The sessions the user is present in (the coordinator's tenant-scoped ids,
    /// which this tenant already knows from its own session responses). Included
    /// for observability; empty when `in_game` is false.
    sessions: Vec<u64>,
}

/// Active-player presence query: which of the given users are connected to a
/// relay in a live game right now — what a tenant's matchmaker consults to block
/// an in-game player from re-queueing.
///
/// Same tenant request-signature auth as `POST /session/create` (see the module
/// docs); the `tenant` in the body must match the tenant the signature verifies
/// under. As live-game machinery this is refused (`403`) only for a revoked
/// tenant, not a suspended one. Rejects an over-cap user list rather than resolve
/// it.
///
/// **Fail-open, by design.** Absence of evidence answers `in_game: false`. The
/// presence store is in-memory truth fed by relay heartbeats: a coordinator
/// restart wipes it (the next round of beats repopulates it within one ~10s
/// interval), a relay's control-connection flap clears that relay's entries, and
/// an expired TTL reads as absent. In every one of those unavailable states the
/// endpoint must NOT lock players out of matchmaking — letting an in-game player
/// queue briefly is today's status quo, while locking out a legitimate player is
/// strictly worse. Callers should treat `true` as authoritative and `false` as
/// "no evidence".
///
/// **Semantics, honestly:** presence means "connected to a relay now". A
/// just-created session whose clients have not dialed yet is the tenant's own
/// knowledge (it created it); it does not read as presence here until the
/// clients connect.
///
/// Resolution is coordinator-side only: relays report tenant/session/slot, and
/// slots map to user refs through the session refs the tenant supplied at
/// creation — no user identity ever reaches a relay.
pub(super) async fn presence_query(
    State(state): State<CoordinatorState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PresenceQueryResponse>, StatusCode> {
    let request: PresenceQueryRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    verify_tenant_request(
        &state.setup,
        &request.tenant,
        &method,
        &uri,
        &headers,
        &body,
        TenantAccess::LiveGame,
    )?;

    if request.users.len() > MAX_PRESENCE_USERS {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    // Snapshot the tenant's fresh presence and resolve each (session, slot) to
    // the tenant's user ref through the stored session refs. A session with no
    // stored refs (created before a restart wiped them, or with no external_refs
    // supplied) resolves to no users — fail-open.
    let fresh = presence::fresh_slots(
        state.setup.presence(),
        &request.tenant,
        std::time::Instant::now(),
    );
    let mut sessions_by_user: std::collections::HashMap<String, std::collections::BTreeSet<u64>> =
        std::collections::HashMap::new();
    let mut refs_by_session: std::collections::HashMap<SessionId, Option<session::SessionRefs>> =
        std::collections::HashMap::new();
    for (session_id, slot) in fresh {
        let refs = refs_by_session
            .entry(session_id)
            .or_insert_with(|| session::session_refs(&state.setup, &request.tenant, session_id));
        if let Some(refs) = refs
            && let Some(user) = refs.slots.get(&slot)
        {
            sessions_by_user
                .entry(user.clone())
                .or_default()
                .insert(session_id.0);
        }
    }

    let users = request
        .users
        .into_iter()
        .map(|user| {
            let sessions: Vec<u64> = sessions_by_user
                .get(&user)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default();
            UserPresence {
                in_game: !sessions.is_empty(),
                user,
                sessions,
            }
        })
        .collect();
    Ok(Json(PresenceQueryResponse { users }))
}

/// Request body for `POST /flight/blobs`: the session whose stored recordings to
/// list. Tenant-authenticated (snake_case control-plane surface, like
/// [`SessionRequest`]); `tenant` must match the tenant the request signature verifies
/// under, and is the only tenant whose blobs the request can name.
#[derive(Debug, Deserialize)]
struct FlightBlobsRequest {
    /// The tenant the app server is acting for — must match the request signature.
    tenant: TenantId,
    /// The session, in the coordinator's `(tenant, session)` id space.
    session: u64,
}

/// Response body for `POST /flight/blobs`: one entry per relay that stored a recording
/// for the session, deduped by relay id (a pinned copy wins). camelCase, the tenant's
/// own forensics-tooling surface.
#[derive(Debug, Serialize)]
pub(super) struct FlightBlobsResponse {
    /// The session's stored recordings, one per relay.
    blobs: Vec<FlightBlobInfo>,
}

/// One stored recording in a [`FlightBlobsResponse`]: which relay produced it, whether
/// it is pinned (the desynced-session retention class), and its size and last-modified
/// stamp. camelCase field names (`relayId`, `lastModifiedMs`) match the tenant-facing
/// forensics surface that consumes this.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FlightBlobInfo {
    /// The relay whose recording this is.
    relay_id: u64,
    /// Whether the recording is in the pinned (desynced) retention class.
    pinned: bool,
    /// The stored recording's size in bytes — the *compressed* (zstd) size, not the
    /// size of the JSON a fetch of it returns.
    size: u64,
    /// The recording's last-modified time, unix-epoch milliseconds.
    last_modified_ms: i64,
}

impl From<flight_store::RecordingListing> for FlightBlobInfo {
    fn from(listing: flight_store::RecordingListing) -> Self {
        Self {
            relay_id: listing.relay_id,
            pinned: listing.pinned,
            size: listing.size,
            last_modified_ms: listing.last_modified_ms,
        }
    }
}

/// Request body for `POST /flight/blob`: one relay's recording of one session to fetch.
/// Same tenant-authentication and tenant-scoping as [`FlightBlobsRequest`].
#[derive(Debug, Deserialize)]
struct FlightBlobRequest {
    /// The tenant the app server is acting for — must match the request signature.
    tenant: TenantId,
    /// The session, in the coordinator's `(tenant, session)` id space.
    session: u64,
    /// The relay whose recording to fetch.
    relay_id: u64,
}

/// Lists a session's stored flight recordings.
///
/// **A POST, not a GET, with the tenant in the signed body** — the same shape every
/// other tenant endpoint uses. The request signature (see the module docs) covers the
/// body, so the `tenant` it names is bound by the signature: a body naming another
/// tenant fails verification against this tenant's keys. The blobs are keyed on the
/// authenticated tenant, and the path never names a tenant, so a request can only ever
/// reach its own tenant's recordings. As forensics on past games, this is live-game
/// machinery — refused (`403`) only for a revoked tenant, not a suspended one.
///
/// With no store configured the response is an empty list rather than an error: there
/// is simply nothing stored. A store error is a `500`.
pub(super) async fn flight_blobs(
    State(state): State<CoordinatorState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<FlightBlobsResponse>, StatusCode> {
    let request: FlightBlobsRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    verify_tenant_request(
        &state.setup,
        &request.tenant,
        &method,
        &uri,
        &headers,
        &body,
        TenantAccess::LiveGame,
    )?;

    let Some(store) = state.flight_store.as_ref() else {
        return Ok(Json(FlightBlobsResponse { blobs: Vec::new() }));
    };
    match flight_store::list_recordings(&**store, &request.tenant, SessionId(request.session)).await
    {
        Ok(listings) => Ok(Json(FlightBlobsResponse {
            blobs: listings.into_iter().map(FlightBlobInfo::from).collect(),
        })),
        Err(error) => {
            tracing::warn!(
                tenant = request.tenant.as_ref(),
                session = request.session,
                %error,
                "listing flight recordings failed",
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Fetches one relay's stored flight recording for a session, decompressing the stored
/// zstd blob into the recording's JSON and returning it (`application/json`), or `404`
/// when neither retention class holds it.
///
/// A stored blob is zstd-compressed JSON (the encoding the relay uploads), so
/// [`flight_store::fetch_recording`] decompresses it — bounded against a decompression
/// bomb — before it is served, keeping this endpoint's contract ready-to-use JSON. A
/// blob that fails to decompress or expands past the read cap is a store-integrity
/// error, served as a `500` (the store-error path below), never as the raw bytes.
///
/// Authenticated and tenant-scoped exactly like [`flight_blobs`]: the tenant comes from
/// the signed body, the key is built from that authenticated tenant, and the path names
/// no tenant — so a request can never reach another tenant's recording. Live-game tier
/// (refused only for a revoked tenant). With no store configured every blob reads as
/// absent, so the answer is `404`.
pub(super) async fn flight_blob(
    State(state): State<CoordinatorState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let request: FlightBlobRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    verify_tenant_request(
        &state.setup,
        &request.tenant,
        &method,
        &uri,
        &headers,
        &body,
        TenantAccess::LiveGame,
    )?;

    let Some(store) = state.flight_store.as_ref() else {
        return Err(StatusCode::NOT_FOUND);
    };
    match flight_store::fetch_recording(
        &**store,
        &request.tenant,
        SessionId(request.session),
        RelayId(request.relay_id),
    )
    .await
    {
        Ok(Some(bytes)) => Ok(([(CONTENT_TYPE, "application/json")], bytes).into_response()),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(error) => {
            tracing::warn!(
                tenant = request.tenant.as_ref(),
                session = request.session,
                relay_id = request.relay_id,
                %error,
                "fetching a flight recording failed",
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Request body for `POST /regions/warm`: a tenant and the regions it wants kept
/// warm. Tenant-authenticated (snake_case control-plane surface, like
/// [`SessionRequest`]); `tenant` must match the tenant the request signature
/// verifies under.
#[derive(Debug, Deserialize)]
struct WarmRequest {
    /// The tenant the app server is acting for — must match the request signature.
    tenant: TenantId,
    /// The regions to keep warm.
    regions: Vec<rally_point_proto::control::RegionId>,
}

/// Response body for `POST /regions/warm`: which requested regions were warmed and
/// which were not recognized. A region the coordinator does not configure lands in
/// `unknown` rather than failing the request, so a stale region list on the tenant
/// still warms the valid remainder.
#[derive(Debug, Serialize)]
pub(super) struct WarmResponse {
    /// The requested regions the coordinator configures — warmed (their demand
    /// raised and TTL extended) when a provisioning loop is running.
    warmed: Vec<rally_point_proto::control::RegionId>,
    /// The requested regions the coordinator does not configure. Reported, not an
    /// error.
    unknown: Vec<rally_point_proto::control::RegionId>,
}

/// Keeps the named regions warm: raises each configured region's warm demand and
/// pushes its TTL out, so the reconcile loop provisions (or holds) a relay there
/// ahead of a create that needs it. Idempotent — the app server re-sends this on an
/// interval to hold a region warm, and stops simply by going quiet (the demand
/// lapses at its TTL).
///
/// Same tenant request-signature auth as `POST /session/create` (see the module
/// docs); the `tenant` in the body must match the tenant the signature verifies
/// under. A region the coordinator does not configure is reported in `unknown`
/// (and logged at debug) rather than failing the whole request, so a stale region
/// list still warms its valid regions. No rate limit: the only callers are
/// tenant-signed app servers.
///
/// On a coordinator with **no provisioning loop**, the gate is dormant: known
/// regions are still acknowledged in `warmed` and unknown ones still reported, but
/// nothing consumes warm demand, so no relay is actually held warm. The response
/// shape is the same, so a caller sees the known/unknown split either way.
pub(super) async fn warm_regions(
    State(state): State<CoordinatorState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<WarmResponse>, StatusCode> {
    let request: WarmRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    verify_tenant_request(
        &state.setup,
        &request.tenant,
        &method,
        &uri,
        &headers,
        &body,
        TenantAccess::NewGame,
    )?;

    let gate = state.setup.provision();
    let mut warmed = Vec::new();
    let mut unknown = Vec::new();
    for region in request.regions {
        if state.regions.contains(&region) {
            gate.warm().warm(region.clone(), gate.warm_ttl());
            warmed.push(region);
        } else {
            tracing::debug!(
                region = region.as_ref(),
                "warm request named a region the coordinator does not configure",
            );
            unknown.push(region);
        }
    }
    Ok(Json(WarmResponse { warmed, unknown }))
}

/// Response body for `GET /tenant/:tenant/pubkey`.
///
/// camelCase (not the control plane's snake_case): this is tenant-facing
/// surface, like the departure webhook body, not coordinator↔relay wire.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TenantPubkeyResponse {
    /// The `kid` naming this key — the same value a departure webhook's
    /// signature was made under, so a consumer can key its own verifying-key
    /// cache by it.
    kid: String,
    /// The raw 32-byte Ed25519 verifying key, as 64 lowercase hex characters.
    public_key: String,
}

/// Fetches a tenant's Ed25519 verifying key, so an app server can validate
/// departure-webhook signatures ([`crate::tenant::sign_webhook`]'s
/// counterpart) without pinning the key in its own env config.
///
/// No auth: this hands out public key material only, the same trust posture
/// as `/session/create` handing out relay certs. 404s for a tenant that isn't
/// enrolled (never provisioned, or removed). A revoked tenant is treated as
/// absent — a `404` — since a revoked tenant delivers no webhooks, so there is
/// no signature for a consumer to validate against its key.
pub(super) async fn tenant_pubkey(
    State(state): State<CoordinatorState>,
    Path(tenant): Path<String>,
) -> Result<Json<TenantPubkeyResponse>, StatusCode> {
    let tenant = TenantId(tenant);
    if matches!(
        tenant::tenant_state(state.setup.tenants(), &tenant),
        Some(tenant::TenantState::Revoked)
    ) {
        return Err(StatusCode::NOT_FOUND);
    }
    let (kid, public_key) =
        tenant::verifying_key(state.setup.tenants(), &tenant).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(TenantPubkeyResponse {
        kid: kid.0,
        public_key: hex::encode(public_key),
    }))
}

/// The `GET /regions` response body: the coordinator's configured region list plus
/// the live backbone-RTT table it has aggregated from relay heartbeats.
///
/// A superset of the bare `{"regions": [...]}` the config alone serves: `backbone_rtts`
/// is a sibling list of measured region-pair round-trips, canonical (`a <= b`) and
/// sorted, and is **omitted entirely** when no pair has been measured — so a
/// coordinator serving no measurements returns byte-for-byte the shape it always has.
/// Built at response time from the config's region list and a store snapshot, leaving
/// [`RegionsConfig`]'s own serialization untouched.
#[derive(Serialize)]
pub(super) struct RegionsResponse {
    /// The configured regions, in file (display) order — the same shape and order
    /// [`RegionsConfig`] serves on its own.
    regions: Vec<Region>,
    /// The measured backbone round-trips, canonical and sorted; omitted when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    backbone_rtts: Vec<PairRttEntry>,
}

/// Serves the coordinator's configured region list plus the measured backbone-RTT
/// table as `{"regions": [...], "backbone_rtts": [...]}` — the region list in file
/// (display) order, the pair list canonical (`a <= b`) and sorted. `backbone_rtts` is
/// omitted entirely when no pair has been measured, leaving the exact `{"regions":
/// [...]}` shape.
///
/// **Unauthenticated GET**, following the `GET /tenant/:tenant/pubkey`
/// precedent: the request-signature scheme covers body-carrying mutations, and
/// this list is client-public by design — the SB server forwards it verbatim to
/// every game client. An empty body (`{"regions": []}`) is the honest answer for
/// a coordinator with no `--regions` config.
pub(super) async fn regions(State(state): State<CoordinatorState>) -> Json<RegionsResponse> {
    Json(RegionsResponse {
        regions: state.regions.regions().to_vec(),
        backbone_rtts: state.pair_rtts.snapshot(),
    })
}
