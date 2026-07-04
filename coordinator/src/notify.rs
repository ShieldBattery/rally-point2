//! Departure webhooks: the coordinator → tenant leg of the player-departure
//! notification.
//!
//! A relay reports a mid-game departure up its control connection
//! ([`rally_point_proto::control::RelayToCoordinator::Departure`]); the api layer
//! hands each notice here. Every relay serving the session reports the same
//! departure independently (redundancy against any one relay's coordinator link
//! being down), so the first thing this module does is **dedup** by
//! `(tenant, session, slot)`. On the first sight it enriches the notice with the
//! session's stored correlation ids and the tenant's notify config, then POSTs a
//! webhook to the tenant, retrying with capped backoff.
//!
//! The webhook is an *optimization feed*, not a correctness signal: the consumer
//! (the app server) already holds a game's terminal result once it is decided and
//! ignores a departure for a game+player it has a result for, so a webhook that
//! is never delivered simply degrades to the consumer's result-based behavior.
//! That is why give-up-after-retries is acceptable, and why delivery is
//! at-least-once (a coordinator restart forgets the dedup set; the consumer is
//! idempotent).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use parking_lot::Mutex;
use rally_point_proto::control::{DepartureKind, DepartureNotice, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};
use serde::Serialize;

use crate::session::{self, SessionSetup};
use crate::tenant::{self, NotifyConfig};

/// Departures already handled, keyed by `(tenant, session, slot)`. Shared across
/// every relay control connection so the redundant reports of one leave collapse
/// to a single webhook. In-memory only: a coordinator restart forgets it, which
/// at worst re-fires a webhook the idempotent consumer discards.
pub type DepartureDedup = Arc<Mutex<HashSet<(TenantId, SessionId, SlotId)>>>;

/// Creates an empty departure dedup set.
pub fn new_dedup() -> DepartureDedup {
    Arc::new(Mutex::new(HashSet::new()))
}

/// How many webhook attempts before giving up. With [`BACKOFF_START`] doubling to
/// [`BACKOFF_CAP`], six attempts span roughly a minute of retries.
const MAX_ATTEMPTS: u32 = 6;
/// The first retry backoff; doubles each attempt up to [`BACKOFF_CAP`].
const BACKOFF_START: Duration = Duration::from_secs(2);
/// The retry-backoff ceiling.
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// The JSON body POSTed to the tenant. camelCase, matching the *consumer's*
/// API conventions rather than the relay control plane's snake_case — the
/// webhook lands on the tenant's own HTTP surface, so its style wins. `kind`
/// serializes `"left"` / `"dropped"`. The correlation ids are **omitted** (not
/// sent as `null`) when the session carried none: the consumer validates them
/// as optional strings, and a literal JSON `null` fails that validation rather
/// than reading as "absent".
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DepartureWebhook {
    tenant: String,
    session: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
    slot: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_ref: Option<String>,
    kind: DepartureKind,
    reason: u32,
    leave_seq: u32,
}

/// Handles one relay's departure notice.
///
/// First sight of a `(tenant, session, slot)` enriches it with the session's
/// stored correlation ids and the tenant's notify config and spawns a webhook
/// dispatch. A duplicate (another relay reporting the same leave), a tenant with
/// no notify config, or a session with no record are each a debug-logged drop —
/// the notification is best-effort, so silence there is correct, not an error.
///
/// The dedup entry is claimed before the config/session lookups, so those
/// terminal drops are not re-processed by a later duplicate either.
pub fn handle_departure(setup: &SessionSetup, dedup: &DepartureDedup, notice: DepartureNotice) {
    if !dedup
        .lock()
        .insert((notice.tenant.clone(), notice.session, notice.slot))
    {
        tracing::debug!(
            tenant = notice.tenant.as_ref(),
            session = notice.session.0,
            slot = notice.slot.0,
            "duplicate departure notice; already handled",
        );
        return;
    }

    let Some(config) = tenant::notify_config(setup.tenants(), &notice.tenant) else {
        tracing::debug!(
            tenant = notice.tenant.as_ref(),
            session = notice.session.0,
            slot = notice.slot.0,
            "no notify config for tenant; dropping departure",
        );
        return;
    };

    let Some(refs) = session::session_refs(setup, &notice.tenant, notice.session) else {
        tracing::debug!(
            tenant = notice.tenant.as_ref(),
            session = notice.session.0,
            slot = notice.slot.0,
            "no session record; dropping departure",
        );
        return;
    };

    let payload = DepartureWebhook {
        tenant: notice.tenant.as_ref().to_owned(),
        session: notice.session.0,
        external_id: refs.external_id,
        slot: notice.slot.0,
        external_ref: refs.slots.get(&notice.slot).cloned(),
        kind: notice.kind,
        reason: notice.reason,
        leave_seq: notice.leave_seq,
    };

    tokio::spawn(dispatch(config, payload));
}

/// POSTs the webhook, retrying non-2xx responses and connect errors with capped
/// backoff, then giving up with a `warn!`. Success is any 2xx.
async fn dispatch(config: NotifyConfig, payload: DepartureWebhook) {
    let body = match serde_json::to_vec(&payload) {
        Ok(bytes) => Bytes::from(bytes),
        Err(error) => {
            tracing::error!(%error, "serializing a departure webhook failed; dropping");
            return;
        }
    };

    // Plain-HTTP client. An `https://` notify URL would need a rustls (ring)
    // connector wired in here (a `HttpsConnector`); the dev notify flow uses
    // `http://`, so that is a prod TODO rather than a blocker.
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

    let mut backoff = BACKOFF_START;
    for attempt in 1..=MAX_ATTEMPTS {
        let request = match build_request(&config, body.clone()) {
            Ok(request) => request,
            Err(error) => {
                // A malformed URL/header is deterministic — retrying can't fix
                // it, so give up now rather than burning the whole budget.
                tracing::warn!(url = %config.url, %error, "departure webhook request is unbuildable; dropping");
                return;
            }
        };

        match client.request(request).await {
            Ok(response) => {
                let status = response.status().as_u16();
                // Drain the body so the connection returns to the pool cleanly.
                let _ = response.into_body().collect().await;
                if (200..300).contains(&status) {
                    tracing::debug!(url = %config.url, status, "departure webhook delivered");
                    return;
                }
                tracing::debug!(url = %config.url, status, attempt, "departure webhook non-2xx; retrying");
            }
            Err(error) => {
                tracing::debug!(url = %config.url, %error, attempt, "departure webhook attempt failed; retrying");
            }
        }

        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_CAP);
        }
    }

    tracing::warn!(
        url = %config.url,
        attempts = MAX_ATTEMPTS,
        "gave up delivering a departure webhook; the consumer's result-based fallback covers it",
    );
}

/// Builds one webhook request: `POST` to the notify URL with the JSON body and,
/// when a secret is configured, the `Authorization: Bearer <secret>` header.
fn build_request(
    config: &NotifyConfig,
    body: Bytes,
) -> Result<hyper::Request<Full<Bytes>>, hyper::http::Error> {
    let mut builder = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(&config.url)
        .header(hyper::header::CONTENT_TYPE, "application/json");
    if let Some(secret) = &config.secret {
        builder = builder.header(hyper::header::AUTHORIZATION, format!("Bearer {secret}"));
    }
    builder.body(Full::new(body))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use axum::Router;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header::AUTHORIZATION};
    use axum::routing::post;
    use rally_point_proto::control::{
        BufferBounds, DepartureKind, PlayerHandoff, RelayHello, SessionRequest, TenantId,
    };
    use rally_point_proto::ids::{RelayId, SlotId};
    use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId};
    use rally_point_proto::version::ProtocolVersion;
    use tokio::sync::mpsc;
    use tokio::time::{Duration, timeout};

    use super::*;
    use crate::registry;

    /// One webhook the stand-in tenant received.
    #[derive(Clone)]
    struct Received {
        authorization: Option<String>,
        body: serde_json::Value,
    }

    /// A stand-in tenant receiver: an axum server that records each POST it gets
    /// (its `Authorization` header and JSON body) onto a channel. Returns the
    /// hook URL and the receive end.
    async fn spawn_receiver(status: StatusCode) -> (String, mpsc::UnboundedReceiver<Received>) {
        let (tx, rx) = mpsc::unbounded_channel::<Received>();
        let app = Router::new()
            .route(
                "/hook",
                post(
                    move |State(tx): State<mpsc::UnboundedSender<Received>>,
                          headers: HeaderMap,
                          body: axum::body::Bytes| async move {
                        let authorization = headers
                            .get(AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            .map(str::to_owned);
                        let body = serde_json::from_slice(&body).unwrap();
                        let _ = tx.send(Received {
                            authorization,
                            body,
                        });
                        status
                    },
                ),
            )
            .with_state(tx);
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/hook"), rx)
    }

    /// A session-setup with one relay and a tenant enrolled, plus a created
    /// session carrying the given correlation ids. Returns the setup and session.
    fn setup_with_session(
        external_id: Option<&str>,
        slot0_ref: Option<&str>,
    ) -> (SessionSetup, SessionId) {
        let reg = registry::new_registry();
        registry::enroll(
            &reg,
            RelayHello::new(
                RelayId(1),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
                ProtocolVersion::CURRENT,
                vec![0xC1; 4],
            ),
        );
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let setup = SessionSetup::new(reg, tenants);
        let resp = session::create_session(
            &setup,
            SessionRequest {
                tenant: TenantId("sb-test".to_owned()),
                players: vec![PlayerHandoff {
                    slot: SlotId(0),
                    client_pubkey: ClientPublicKey([0xAA; 32]),
                    external_ref: slot0_ref.map(str::to_owned),
                }],
                external_id: external_id.map(str::to_owned),
            },
            ExpiresAt(u64::MAX),
        )
        .unwrap();
        (setup, resp.session)
    }

    fn notice(session: SessionId, slot: u8, kind: DepartureKind, reason: u32) -> DepartureNotice {
        DepartureNotice {
            tenant: TenantId("sb-test".to_owned()),
            session,
            slot: SlotId(slot),
            kind,
            reason,
            leave_seq: 1,
        }
    }

    #[tokio::test]
    async fn a_departure_posts_one_webhook_with_body_and_auth_and_dedups_relays() {
        let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
        let (setup, session) = setup_with_session(Some("game-99"), Some("sb-user-7"));
        tenant::set_notify(
            setup.tenants(),
            &TenantId("sb-test".to_owned()),
            Some(NotifyConfig {
                url,
                secret: Some("hook-secret".to_owned()),
            }),
        );
        let dedup = new_dedup();

        // Two relays report the same departure; the coordinator must webhook once.
        handle_departure(
            &setup,
            &dedup,
            notice(session, 0, DepartureKind::Dropped, 0x4000_0006),
        );
        handle_departure(
            &setup,
            &dedup,
            notice(session, 0, DepartureKind::Dropped, 0x4000_0006),
        );

        let got = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a webhook is delivered")
            .expect("the receiver got it");

        assert_eq!(got.authorization.as_deref(), Some("Bearer hook-secret"));
        assert_eq!(got.body["tenant"], "sb-test");
        assert_eq!(got.body["session"], session.0);
        assert_eq!(got.body["externalId"], "game-99");
        assert_eq!(got.body["slot"], 0);
        assert_eq!(got.body["externalRef"], "sb-user-7");
        assert_eq!(got.body["kind"], "dropped");
        assert_eq!(got.body["reason"], 0x4000_0006u32);
        assert_eq!(got.body["leaveSeq"], 1);

        // No second webhook: the duplicate relay report was deduped.
        assert!(
            timeout(Duration::from_millis(400), rx.recv())
                .await
                .is_err(),
            "duplicate departures from multiple relays webhook exactly once",
        );
    }

    #[tokio::test]
    async fn a_clean_leave_is_classified_left_in_the_webhook() {
        let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
        let (setup, session) = setup_with_session(None, None);
        tenant::set_notify(
            setup.tenants(),
            &TenantId("sb-test".to_owned()),
            Some(NotifyConfig { url, secret: None }),
        );
        let dedup = new_dedup();

        handle_departure(&setup, &dedup, notice(session, 0, DepartureKind::Left, 3));

        let got = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a webhook is delivered")
            .unwrap();
        assert_eq!(got.body["kind"], "left");
        // No secret configured → no Authorization header.
        assert_eq!(got.authorization, None);
        // Absent correlation ids are omitted entirely, not sent as `null` — the
        // consumer validates them as optional *strings*, and a literal `null`
        // would fail that validation. `Value::index` on a missing key also
        // returns `Null`, so `.get(..).is_none()` is the check that actually
        // proves omission rather than passing either way.
        assert!(got.body.get("externalId").is_none());
        assert!(got.body.get("externalRef").is_none());
    }

    #[tokio::test]
    async fn no_notify_config_is_a_silent_no_op() {
        // A receiver exists, but the tenant has no notify config, so nothing is
        // ever sent to it.
        let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
        let (setup, session) = setup_with_session(Some("game-1"), Some("sb-user-1"));
        // Deliberately do NOT point the tenant's notify config at `url`.
        let _ = url;
        let dedup = new_dedup();

        handle_departure(
            &setup,
            &dedup,
            notice(session, 0, DepartureKind::Dropped, 0x4000_0006),
        );

        assert!(
            timeout(Duration::from_millis(400), rx.recv())
                .await
                .is_err(),
            "a tenant with no notify config sends no webhook",
        );
    }

    #[tokio::test]
    async fn an_unknown_session_is_a_silent_no_op() {
        let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
        let (setup, _session) = setup_with_session(Some("game-1"), Some("sb-user-1"));
        tenant::set_notify(
            setup.tenants(),
            &TenantId("sb-test".to_owned()),
            Some(NotifyConfig { url, secret: None }),
        );
        let dedup = new_dedup();

        // A session the coordinator never created has no stored refs → dropped.
        handle_departure(
            &setup,
            &dedup,
            notice(SessionId(999_999), 0, DepartureKind::Dropped, 0x4000_0006),
        );

        assert!(
            timeout(Duration::from_millis(400), rx.recv())
                .await
                .is_err(),
            "a departure for an unknown session sends no webhook",
        );
    }
}
