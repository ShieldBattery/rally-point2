//! HTTP control-plane API: relay phone-home + session setup endpoints.
//!
//! Exposes a [`router`] function that builds the axum [`Router`] over the
//! coordinator's shared state. The binary binds a TCP listener and serves it;
//! the library owns the routing + handlers so they're testable without a
//! socket (via `tower::ServiceExt::oneshot`).
//!
//! # Endpoints
//!
//! - `POST /relay/enroll` — a relay phones home. Body: [`RelayHello`];
//!   response: the [`RelayEntry`] the coordinator now holds.
//! - `POST /session/create` — an app server requests a session. Body:
//!   [`SessionRequest`]; response: [`SessionResponse`] with per-player tokens
//!   and the relay topology.
//!
//! Both endpoints are JSON over HTTP/1.1. Auth (relay bootstrap secret,
//! app-server per-tenant credential) is not yet enforced — the API is open
//! for dev/loopback today.

use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use rally_point_proto::control::{RelayEntry, RelayHello, SessionRequest, SessionResponse};

use crate::registry;
use crate::session::{self, SessionSetup};

/// The shared state the HTTP handlers operate over: the coordinator's
/// session-setup context (which bundles the relay registry + tenant store).
/// Cloned cheaply (each field is an `Arc`-backed shared mutex), so axum's
/// per-request `State` clone shares one set of registries.
#[derive(Clone)]
pub struct CoordinatorState {
    /// The session-setup context — relay registry, tenant store, and
    /// session→relay membership, bundled for `create_session` and
    /// `descriptor_for`.
    pub setup: SessionSetup,
}

/// Builds the coordinator's HTTP router over `state`.
pub fn router(state: CoordinatorState) -> Router {
    Router::new()
        .route("/relay/enroll", post(enroll_relay))
        .route("/session/create", post(create_session))
        .with_state(state)
}

/// Enrolls a relay that has phoned home.
async fn enroll_relay(
    State(state): State<CoordinatorState>,
    Json(hello): Json<RelayHello>,
) -> Json<RelayEntry> {
    let entry = registry::enroll(state.setup.registry(), hello);
    tracing::info!(
        relay_id = %entry.relay_id,
        addr = %entry.relay_addr,
        "relay enrolled"
    );
    Json(entry)
}

/// Creates a game session: assigns relays, mints tokens.
///
/// Token expiry is set to `u64::MAX` for now (dev/loopback). Production sets
/// it to the game session lifetime plus margin.
async fn create_session(
    State(state): State<CoordinatorState>,
    Json(request): Json<SessionRequest>,
) -> Result<Json<SessionResponse>, StatusCode> {
    let resp = session::create_session(
        &state.setup,
        request,
        rally_point_proto::token::ExpiresAt(u64::MAX),
    )
    .map_err(|e| {
        tracing::warn!(error = %e, "session setup failed");
        match e {
            registry::SessionSetupError::NoRelaysAvailable
            | registry::SessionSetupError::NotEnoughRelays { .. } => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            registry::SessionSetupError::TenantNotFound(_)
            | registry::SessionSetupError::SlotOutOfRange(_)
            | registry::SessionSetupError::NoPlayers => StatusCode::BAD_REQUEST,
        }
    })?;

    tracing::info!(
        session = %resp.session,
        home_relay = %resp.home_relay.relay_id,
        players = resp.tokens.len(),
        "session created"
    );
    Ok(Json(resp))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use rally_point_proto::control::{
        BufferBounds, PlayerHandoff, RelayHello, SessionRequest, TenantId,
    };
    use rally_point_proto::ids::{RelayId, SlotId};
    use rally_point_proto::token::{ClientPublicKey, KeyId};
    use rally_point_proto::version::ProtocolVersion;
    use tower::ServiceExt;

    fn state_with_relay_and_tenant() -> CoordinatorState {
        let reg = registry::new_registry();
        registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(1),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
                ProtocolVersion::CURRENT,
            ),
        );
        let tenants = crate::tenant::new_store();
        crate::tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let setup = crate::session::SessionSetup::new(reg, tenants);
        CoordinatorState { setup }
    }

    fn two_players() -> Vec<PlayerHandoff> {
        vec![
            PlayerHandoff {
                slot: SlotId(0),
                client_pubkey: ClientPublicKey([0xAA; 32]),
            },
            PlayerHandoff {
                slot: SlotId(1),
                client_pubkey: ClientPublicKey([0xBB; 32]),
            },
        ]
    }

    #[tokio::test]
    async fn enroll_relay_endpoint_returns_entry() {
        let state = CoordinatorState {
            setup: crate::session::SessionSetup::new(
                registry::new_registry(),
                crate::tenant::new_store(),
            ),
        };
        let app = router(state);

        let hello = RelayHello::new(
            RelayId(7),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
            ProtocolVersion::CURRENT,
        );
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/relay/enroll")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&hello).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let entry: RelayEntry = serde_json::from_slice(&body).unwrap();
        assert_eq!(entry.relay_id, RelayId(7));
    }

    #[tokio::test]
    async fn create_session_endpoint_returns_tokens() {
        let state = state_with_relay_and_tenant();
        let app = router(state);

        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
        };
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/session/create")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let session: SessionResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(session.tokens.len(), 2);
        assert_eq!(session.home_relay.relay_id, RelayId(1));
    }

    #[tokio::test]
    async fn create_session_no_relays_returns_503() {
        let state = CoordinatorState {
            setup: crate::session::SessionSetup::new(
                registry::new_registry(),
                crate::tenant::new_store(),
            ),
        };
        let app = router(state);

        let req = SessionRequest {
            tenant: TenantId("sb-test".to_owned()),
            players: two_players(),
        };
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/session/create")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn create_session_unenrolled_tenant_returns_400() {
        let state = state_with_relay_and_tenant();
        let app = router(state);

        let req = SessionRequest {
            tenant: TenantId("not-enrolled".to_owned()),
            players: two_players(),
        };
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/session/create")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
