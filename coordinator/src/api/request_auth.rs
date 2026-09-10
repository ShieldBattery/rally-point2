//! Inbound authentication: the relay control endpoint's bearer check and the
//! tenant request-signature scheme every tenant-scoped endpoint runs.
//!
//! The signature verification and the tenant-state gate are deliberately one
//! call, so a tenant-authenticated endpoint cannot be wired up without choosing
//! which tenant states may reach it.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, Method, StatusCode, Uri, header::AUTHORIZATION};
use rally_point_proto::control::TenantId;
use ring::signature::{ED25519, UnparsedPublicKey};

use crate::session::SessionSetup;
use crate::tenant;

use super::ControlAuth;

/// Whether a request may open the control connection under `auth`. `Open` admits
/// any caller; `Secret` requires the matching bearer token.
pub(super) fn control_auth_ok(headers: &HeaderMap, auth: &ControlAuth) -> bool {
    match auth {
        ControlAuth::Open => true,
        ControlAuth::Secret(expected) => bearer_matches(headers, expected),
    }
}

/// Whether the request's `Authorization` header carries exactly `expected` as a
/// bearer token. The comparison is constant-time so the secret isn't probed a
/// byte at a time via response timing.
fn bearer_matches(headers: &HeaderMap, expected: &str) -> bool {
    let Some(presented) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

/// Constant-time byte-slice equality, so a secret comparison leaks no timing
/// signal that would let it be brute-forced a byte at a time. Differing lengths
/// short-circuit (a length mismatch is already a non-match), then equal-length
/// inputs are compared with no data-dependent branch.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The domain-separation prefix on a tenant request signature, the mirror of
/// the webhook's `rp2-webhook-v1:`. Binds a signature to the request-auth
/// scheme so it can never be confused with a webhook signature (opposite
/// direction) or a player-token signature made by a different key.
const REQUEST_SIG_DOMAIN: &str = "rp2-request-v1:";
/// Header carrying the request signing timestamp: unix epoch *seconds*, decimal
/// (the webhook direction uses milliseconds; these are independent schemes).
pub(super) const REQUEST_TIMESTAMP_HEADER: &str = "x-rp2-timestamp";
/// Header carrying the Ed25519 request signature: lowercase hex of the 64-byte
/// signature over the domain-separated, method+path-bound, timestamped message.
pub(super) const REQUEST_SIGNATURE_HEADER: &str = "x-rp2-signature";
/// How far a request's `x-rp2-timestamp` may drift from now (in either
/// direction) before it is rejected as stale/replayed. Matches the consumer
/// window the app server enforces on webhook timestamps.
pub(super) const REQUEST_TIMESTAMP_WINDOW_SECS: u64 = 5 * 60;

/// The bytes a tenant request signature covers: `rp2-request-v1:<ts>:<METHOD>:
/// <path>:<raw body>`. The method (uppercased — `Method::as_str` already yields
/// the canonical uppercase form for standard methods) and the path-as-sent are
/// bound in so a captured, validly-signed body cannot be replayed against a
/// different endpoint or verb.
pub(super) fn build_request_message(
    timestamp: &str,
    method: &Method,
    path: &str,
    body: &[u8],
) -> Vec<u8> {
    let method = method.as_str();
    let mut message = Vec::with_capacity(
        REQUEST_SIG_DOMAIN.len() + timestamp.len() + method.len() + path.len() + body.len() + 3,
    );
    message.extend_from_slice(REQUEST_SIG_DOMAIN.as_bytes());
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b':');
    message.extend_from_slice(method.as_bytes());
    message.push(b':');
    message.extend_from_slice(path.as_bytes());
    message.push(b':');
    message.extend_from_slice(body);
    message
}

/// The least tenant state a tenant-authenticated endpoint accepts, passed to
/// [`verify_tenant_request`] as a required argument. Making it required is the
/// point: a tenant-authenticated endpoint cannot be wired up without calling
/// [`verify_tenant_request`], and it cannot call that without choosing which
/// tenant states may reach it — so the suspended/revoked gate can never be
/// silently omitted for a future endpoint.
#[derive(Clone, Copy, Debug)]
pub(super) enum TenantAccess {
    /// New-game machinery — only an active tenant. A suspended or revoked tenant
    /// is refused with `403`. For the operations that begin or prepare a
    /// brand-new game (session create, region warming), which suspension halts.
    NewGame,
    /// Live-game machinery — any tenant that is not revoked (active or
    /// suspended). Only a revoked tenant is refused with `403`. For the
    /// operations a game already in progress relies on (failover re-home, the
    /// liveness probe, the presence query), which suspension must not strand.
    LiveGame,
}

/// Verifies a tenant-scoped request's signature and then enforces the tenant's
/// state against `access`, so signature verification and the state gate are one
/// inseparable step every tenant-authenticated endpoint performs.
///
/// A signature problem fails closed with `401` — a missing/unparseable
/// timestamp, a stale timestamp (outside [`REQUEST_TIMESTAMP_WINDOW_SECS`]), a
/// missing/non-hex signature, a tenant with no enrolled verification key, or a
/// signature that verifies against none of the tenant's keys. Every one maps to
/// the same `UNAUTHORIZED` so the response never reveals which check failed;
/// `ring`'s `verify` is itself constant-time. A tenant may list more than one
/// verification key (for zero-downtime request-key rotation); a signature is
/// accepted if it verifies against ANY of them.
///
/// The state gate runs only *after* a good signature, and a state refusal is a
/// distinct `403`: the tenant is proven before its state can shape the outcome,
/// so an unauthenticated caller learns nothing about the tenant's state. A
/// revoked tenant is refused by every `access`; a suspended tenant is refused
/// only [`TenantAccess::NewGame`]. The refusal names only its class in the
/// server log and carries no detail on the wire beyond the status code.
///
/// The signed message binds the request method and the path as sent (see
/// [`build_request_message`]); `path` uses the full path-and-query so a future
/// query-carrying endpoint signs what is on the wire (today's endpoints carry
/// none).
pub(super) fn verify_tenant_request(
    setup: &SessionSetup,
    tenant: &TenantId,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    access: TenantAccess,
) -> Result<(), StatusCode> {
    let timestamp = headers
        .get(REQUEST_TIMESTAMP_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let ts_secs: u64 = timestamp.parse().map_err(|_| StatusCode::UNAUTHORIZED)?;
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now_secs.abs_diff(ts_secs) > REQUEST_TIMESTAMP_WINDOW_SECS {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let signature = headers
        .get(REQUEST_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|hex_str| hex::decode(hex_str).ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let client_pubkeys = tenant::client_pubkeys(setup.tenants(), tenant);
    if client_pubkeys.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| uri.path());
    let message = build_request_message(timestamp, method, path, body);

    let verified = client_pubkeys.iter().any(|key| {
        UnparsedPublicKey::new(&ED25519, key.as_ref())
            .verify(&message, &signature)
            .is_ok()
    });
    if !verified {
        return Err(StatusCode::UNAUTHORIZED);
    }

    enforce_tenant_state(setup, tenant, access)
}

/// Enforces an authenticated tenant's state against what `access` requires,
/// mapping a refusal to `403` and logging its class. Called only from
/// [`verify_tenant_request`], after the signature is proven — a revoked tenant is
/// refused by every endpoint, a suspended tenant by the new-game ones. A tenant
/// that vanished between the signature check and here reads as `None` and is
/// refused as unauthorized.
fn enforce_tenant_state(
    setup: &SessionSetup,
    tenant: &TenantId,
    access: TenantAccess,
) -> Result<(), StatusCode> {
    let state = tenant::tenant_state(setup.tenants(), tenant).ok_or(StatusCode::UNAUTHORIZED)?;
    let permitted = match access {
        TenantAccess::NewGame => matches!(state, tenant::TenantState::Active),
        TenantAccess::LiveGame => !matches!(state, tenant::TenantState::Revoked),
    };
    if permitted {
        Ok(())
    } else {
        tracing::warn!(
            tenant = tenant.as_ref(),
            state = ?state,
            access = ?access,
            "tenant request refused: the tenant's state does not permit this endpoint",
        );
        Err(StatusCode::FORBIDDEN)
    }
}
