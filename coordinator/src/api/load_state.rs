//! The session load-progress read and the attestation round behind it.
//!
//! `POST /session/load-state` is an exchange, not a lookup: the handler asks
//! every relay serving the session what it holds and merges the answers, so a
//! complete set of answers is what licenses reading a slot's absence as evidence.

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header::RETRY_AFTER},
    response::{IntoResponse, Response},
};
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId};
use serde::{Deserialize, Serialize};

use crate::attest::LOAD_STATE_ATTEST_TIMEOUT;

use super::CoordinatorState;
use super::request_auth::{TenantAccess, verify_tenant_request};

/// Request body for `POST /session/load-state`: the session whose load progress
/// to read, in the coordinator's `(tenant, session)` id space.
#[derive(Debug, Deserialize)]
struct SessionLoadStateRequest {
    /// The tenant the app server is acting for — must match the request signature.
    tenant: TenantId,
    /// The session, in the coordinator's `(tenant, session)` id space.
    session: u64,
}

/// Response body for `POST /session/load-state`: what the coordinator knows about
/// the session's load progress. camelCase, the tenant's own convention (like the
/// webhook bodies), unlike the snake_case control-plane request above.
///
/// `connectedSlots` / `startedSlots` / `startedAtMs` are always whatever the
/// coordinator has accumulated, `known` or not: they are positive evidence, and the
/// tenant merges them with its own regardless. Both slot sets are always present,
/// empty when nothing is known. `known` gates only the *negative* inference —
/// reading a slot's **absence** from the sets as proof that player never got there.
///
/// `known: true` means every relay serving the session produced a snapshot **after
/// this request reached it**, that each of those relays had **fenced** the session
/// against its own clients when it did, and that the coordinator has held the
/// session since it created it with no break in the relay memory covering it. So
/// everything that had happened by the time the caller sent this request is in the
/// sets, and an absent slot may be read as a player who never arrived. No clock on
/// either side takes part in that claim: it rests on the ordering of the exchange,
/// not on comparing timestamps across hosts.
///
/// `known: false` is "no information about who is missing" — never "nobody
/// arrived". A relay that did not answer in time, a relay with no live control
/// connection, a relay that could not fence one of its slots, a coordinator that
/// restarted, a reaped session, and a session whose serving relays changed under it
/// (a re-home, or a relay that restarted its process — either destroys memory
/// nothing later can reconstruct) all read that way. The answer is cheap to repeat,
/// so a caller with time left may simply read again; one whose deadline has passed
/// decides on the positive facts alone.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionLoadStateResponse {
    known: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at_ms: Option<u64>,
    connected_slots: Vec<u8>,
    started_slots: Vec<u8>,
}

/// Session load-progress read: which slots ever connected, which ever reported
/// their game loop running, and when the session started.
///
/// The tenant consults this when its **own** load deadline expires and it must
/// decide whom to blame for a game that never got going. The `slotConnected` /
/// `sessionStarted` / `slotStarted` webhooks carry the same facts as they happen,
/// but they are an optimization feed — best-effort, at-least-once, droppable —
/// so this pull is the correctness signal for load attribution: it reads the
/// coordinator's accumulated state directly rather than trusting that every
/// notification arrived.
///
/// Both slot lists are **ever**-sets, ascending: a slot that connected and then
/// dropped still appears, because the question is who got here at all, not who is
/// here now (`POST /presence/query` answers the latter).
///
/// The read is an **exchange**, not a lookup of whatever happened to have arrived.
/// The coordinator asks every relay serving the session, over the control
/// connection each already holds, what it holds for that session; each relay
/// snapshots and answers with the request's own correlation id. A snapshot is built
/// after the request reached the relay, so anything the relay had observed before
/// the caller sent this read is in it — which is what makes a complete set of
/// answers evidence about *absence*, with no clock comparison anywhere. Every
/// snapshot that arrives is merged whether or not the set completes, so a silent
/// relay costs the completeness claim and never the facts its peers reported. A
/// relay silent past [`LOAD_STATE_ATTEST_TIMEOUT`], or holding no control
/// connection at all, simply did not answer.
///
/// The read is **rate-limited per tenant** ([`LoadStateLimiter`]), because the cost
/// it imposes is fleet-wide rather than per-session: each read questions every relay
/// serving the named session and holds a fence open on each while it answers. A
/// refused read is a `429` carrying `Retry-After`. Concurrent reads of the *same*
/// session share one round of questions, so a caller with several requests in flight
/// for one session multiplies nothing.
///
/// Same tenant request-signature auth as `POST /session/create` (see the module
/// docs); the `tenant` in the body must match the tenant the signature verifies
/// under. As live-game machinery this is refused only for a revoked tenant, not a
/// suspended one — a suspended tenant's running games still need adjudicating.
pub(super) async fn session_load_state(
    State(state): State<CoordinatorState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let request: SessionLoadStateRequest =
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
    let limiter = state.setup.load_state_limiter();
    if !limiter.check(&request.tenant) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [(RETRY_AFTER, limiter.retry_after_secs().to_string())],
        )
            .into_response());
    }
    let session = SessionId(request.session);

    // The coordinator holds nothing at all for the session: never created here and
    // no notice or beat has arrived for it, or it has been reaped. Nobody to ask,
    // and nothing to answer with.
    let Some(before) = state.lifecycle.load_state(&request.tenant, session) else {
        return Ok(Json(SessionLoadStateResponse {
            known: false,
            started_at_ms: None,
            connected_slots: Vec::new(),
            started_slots: Vec::new(),
        })
        .into_response());
    };

    let round = attest_round(&state, &request.tenant, session, &before.serving_relays).await;
    // Re-read after the exchange so the answer carries whatever the snapshots added.
    // A session retired while the relays were answering leaves nothing to re-read,
    // and the snapshots that landed went into a record that no longer exists — so
    // the pre-exchange facts are answered with, and no claim is made over them.
    let Some(after) = state.lifecycle.load_state(&request.tenant, session) else {
        return Ok(Json(SessionLoadStateResponse {
            known: false,
            started_at_ms: before.started_at_ms,
            connected_slots: before.connected_slots.iter().map(|s| s.0).collect(),
            started_slots: before.started_slots.iter().map(|s| s.0).collect(),
        })
        .into_response());
    };
    // A session with no serving relays has nobody who could attest, so it can never
    // complete — the same reason a state no registration built cannot. Membership in
    // `fenced` implies membership in `attested`, so this one check covers both:
    // every serving relay answered, and every answer ruled out a report still queued
    // in one of that relay's clients.
    let every_relay_fenced = !before.serving_relays.is_empty()
        && before
            .serving_relays
            .iter()
            .all(|relay| round.fenced.contains(relay));
    Ok(Json(SessionLoadStateResponse {
        known: after.created_here && after.attestable && every_relay_fenced,
        started_at_ms: after.started_at_ms,
        connected_slots: after.connected_slots.iter().map(|s| s.0).collect(),
        started_slots: after.started_slots.iter().map(|s| s.0).collect(),
    })
    .into_response())
}

/// Obtains an attestation round covering this read: leads a fresh one, or shares the
/// round already running for the session (see [`crate::attest::shared_round`] for
/// why sharing is sound and what a joiner has to check).
async fn attest_round(
    state: &CoordinatorState,
    tenant: &TenantId,
    session: SessionId,
    serving: &[RelayId],
) -> crate::attest::AttestRound {
    crate::attest::shared_round(state.setup.attest(), tenant, session, || {
        attest_serving_relays(state, tenant, session, serving)
    })
    .await
}

/// Asks every relay in `serving` for its snapshot of the session and reports which
/// of them answered, and which of those fenced. Each answer is merged where it is
/// received, so this only has to record who produced one.
///
/// Every request goes out before any answer is waited on, and all of them share one
/// absolute deadline, so the whole exchange costs at most
/// [`LOAD_STATE_ATTEST_TIMEOUT`] however many relays serve the session and however
/// many of them are slow. A relay that cannot be reached at all — no live control
/// connection, or a control connection whose question queue is full — is never asked
/// and counts exactly like one that stayed silent: it did not attest.
async fn attest_serving_relays(
    state: &CoordinatorState,
    tenant: &TenantId,
    session: SessionId,
    serving: &[RelayId],
) -> crate::attest::AttestRound {
    // Taken BEFORE the first question is queued, so it is a lower bound on every
    // snapshot this round collects. Stamping it after the fan-out instead would let
    // it postdate a read that arrived after the earliest-asked relay had already
    // snapshotted, and that read would then accept a round blind to the interval it
    // asked about.
    let started_before_any_request = tokio::time::Instant::now();
    let mut pending: Vec<_> = serving
        .iter()
        .filter_map(|&relay| {
            state
                .setup
                .attest()
                .request(relay, tenant, session)
                .map(|waiter| (relay, waiter))
        })
        .collect();
    let deadline = tokio::time::Instant::now() + LOAD_STATE_ATTEST_TIMEOUT;
    let mut attested = std::collections::HashSet::new();
    let mut fenced = std::collections::HashSet::new();
    for (relay, waiter) in &mut pending {
        if let Ok(Some(snapshot)) = tokio::time::timeout_at(deadline, waiter.recv()).await {
            attested.insert(*relay);
            if snapshot.fenced {
                fenced.insert(*relay);
            }
        }
    }
    crate::attest::AttestRound {
        started_before_any_request,
        attested: std::sync::Arc::new(attested),
        fenced: std::sync::Arc::new(fenced),
    }
}
