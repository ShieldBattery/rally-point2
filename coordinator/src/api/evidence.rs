//! Cached observations for background recovery, without a relay attestation round.

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header::RETRY_AFTER},
    response::{IntoResponse, Response},
};
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::SessionId;
use serde::{Deserialize, Serialize};

use super::CoordinatorState;
use super::request_auth::{TenantAccess, verify_tenant_request};

#[derive(Deserialize)]
struct EvidenceRequest {
    tenant: TenantId,
    session: u64,
}

#[derive(Serialize)]
struct EvidenceResponse {
    evidence: Vec<crate::notify::SlotEvidencePayload>,
}

pub(super) async fn session_evidence(
    State(state): State<CoordinatorState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, StatusCode> {
    let request: EvidenceRequest =
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
    if !state.evidence_limiter.check(&request.tenant) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [(
                RETRY_AFTER,
                state.evidence_limiter.retry_after_secs().to_string(),
            )],
        )
            .into_response());
    }
    // Retained observations are positive facts. This read neither claims completeness nor asks
    // relays to fence clients, and cannot spend the load-attribution endpoint's rate budget.
    let evidence = state
        .lifecycle
        .load_state(&request.tenant, SessionId(request.session))
        .map(|snapshot| snapshot.evidence.into_iter().map(Into::into).collect())
        .unwrap_or_default();
    Ok(Json(EvidenceResponse { evidence }).into_response())
}
