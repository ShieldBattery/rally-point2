//! Departure webhooks: the coordinator → tenant leg of the player-departure
//! notification.
//!
//! A relay reports a mid-game departure up its control connection
//! ([`rally_point_proto::control::RelayToCoordinator::Departure`]); the api layer
//! hands each notice here. Every relay serving the session reports the same
//! departure independently (redundancy against any one relay's coordinator link
//! being down), so the first thing this module does is **dedup** by
//! `(tenant, session, slot)`. On the first sight it resolves the correlation
//! ids — preferring whatever the relay itself stamped into the notice (from the
//! coordinator descriptor it applied), falling back per-field to this
//! coordinator's own in-memory session-refs store — and the tenant's notify
//! config, then POSTs a webhook to the tenant, retrying with capped backoff.
//! Preferring the notice-carried refs is what makes a departure webhook survive
//! a coordinator restart: the in-memory session-refs store is wiped, but a
//! relay's already-applied descriptor is not.
//!
//! The webhook is an *optimization feed*, not a correctness signal: the consumer
//! (the app server) already holds a game's terminal result once it is decided and
//! ignores a departure for a game+player it has a result for, so a webhook that
//! is never delivered simply degrades to the consumer's result-based behavior.
//! That is why give-up-after-retries is acceptable, and why delivery is
//! at-least-once (a coordinator restart forgets the dedup set; the consumer is
//! idempotent).
//!
//! # Authentication — signed, not shared-secret
//!
//! Each POST carries `x-rp2-timestamp` (unix epoch milliseconds, decimal) and
//! `x-rp2-signature` (standard base64 of a 64-byte Ed25519 signature), signed
//! with the tenant's own signing key — the same key `tenant::mint_token`
//! already uses, not a second secret to provision and rotate. The signed
//! message is `rp2-webhook-v1:` + the timestamp string + `:` + the exact body
//! bytes; the `rp2-webhook-v1:` prefix domain-separates it from a player-token
//! signature made by the same key. Signing happens fresh on every delivery
//! attempt (not once, cached) because the timestamp must be current — the
//! consumer enforces a bounded replay window on it, so a retry with a stale
//! timestamp would be rejected before the consumer even reaches its own
//! dedup/idempotency check.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use parking_lot::Mutex;
use rally_point_proto::control::{DepartureKind, DepartureNotice, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};
use serde::Serialize;

use crate::session::{self, SessionSetup};
use crate::tenant::{self, NotifyConfig, TenantStore};

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
/// First sight of a `(tenant, session, slot)` resolves its correlation ids and
/// the tenant's notify config and spawns a webhook dispatch. A duplicate
/// (another relay reporting the same leave), a tenant with no notify config, or
/// a departure with no gameId ref from any source are each a debug-logged drop
/// — the notification is best-effort, so silence there is correct, not an error.
///
/// **Correlation ids: notice-carried first, the stored session as fallback.**
/// The relay stamps `external_id`/`external_ref` into the notice itself (from
/// the coordinator descriptor it applied), so those survive a coordinator
/// restart that wipes the in-memory session-refs store — this is the case the
/// fallback exists to fix: a restarted coordinator with an empty session store
/// still delivers a correct webhook as long as the notice carries its own refs.
/// Each field falls back independently to the stored session (for a notice
/// from a relay that predates the fields, or one whose descriptor never carried
/// them) rather than requiring the whole pair from one source. Unlike the
/// previous behavior, an unresolved *session* is no longer a hard drop on its
/// own — only the absence of a `gameId` (`external_id`) from *both* sources is,
/// since a webhook naming no game is useless to the consumer regardless of
/// whether a player ref is available.
///
/// The dedup entry is claimed before the later lookups, so those terminal
/// drops are not re-processed by a later duplicate either.
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

    let stored = session::session_refs(setup, &notice.tenant, notice.session);
    let external_id = notice
        .external_id
        .clone()
        .or_else(|| stored.as_ref().and_then(|refs| refs.external_id.clone()));
    let external_ref = notice.external_ref.clone().or_else(|| {
        stored
            .as_ref()
            .and_then(|refs| refs.slots.get(&notice.slot).cloned())
    });

    let Some(external_id) = external_id else {
        tracing::debug!(
            tenant = notice.tenant.as_ref(),
            session = notice.session.0,
            slot = notice.slot.0,
            "no gameId ref from the notice or a stored session; dropping departure",
        );
        return;
    };

    let payload = DepartureWebhook {
        tenant: notice.tenant.as_ref().to_owned(),
        session: notice.session.0,
        external_id: Some(external_id),
        slot: notice.slot.0,
        external_ref,
        kind: notice.kind,
        reason: notice.reason,
        leave_seq: notice.leave_seq,
    };

    // The tenant store is cheap to clone (Arc-backed) and carried into the
    // spawned task so `dispatch` can sign fresh on every attempt — a detached
    // task otherwise has no path back to the tenant's signing key.
    tokio::spawn(dispatch(
        setup.tenants().clone(),
        notice.tenant,
        config,
        payload,
    ));
}

/// The domain-separation prefix on the signed message, so a webhook signature
/// can never be confused with a player-token signature made by the same
/// tenant key (which signs an unrelated canonical message with no such
/// prefix).
const WEBHOOK_SIG_DOMAIN: &str = "rp2-webhook-v1:";

/// Header carrying the signing timestamp: unix epoch milliseconds, decimal.
/// The consumer enforces a bounded (±5 minute) replay window on it.
const TIMESTAMP_HEADER: &str = "x-rp2-timestamp";
/// Header carrying the Ed25519 signature: standard (padded) base64 of the
/// 64-byte signature over the domain-separated, timestamped message.
const SIGNATURE_HEADER: &str = "x-rp2-signature";

/// POSTs the webhook, retrying non-2xx responses and connect errors with capped
/// backoff, then giving up with a `warn!`. Success is any 2xx.
///
/// `tenants` + `tenant` are what let a detached task sign the request itself —
/// `handle_departure` resolves them before spawning, since the private key
/// stays behind `tenant::sign_webhook`'s narrow interface rather than being
/// handed out as an `Arc<Ed25519KeyPair>`.
async fn dispatch(
    tenants: TenantStore,
    tenant: TenantId,
    config: NotifyConfig,
    payload: DepartureWebhook,
) {
    let body = match serde_json::to_vec(&payload) {
        Ok(bytes) => Bytes::from(bytes),
        Err(error) => {
            tracing::error!(%error, "serializing a departure webhook failed; dropping");
            return;
        }
    };

    // An http/https-capable client: the connector negotiates rustls (ring
    // provider, webpki public-CA roots) for an `https://` notify URL and
    // falls through to plain HTTP for `http://` (the dev/loopback flow).
    // Webpki roots are sufficient because the prod app server sits behind an
    // HTTPS reverse proxy with a publicly-trusted certificate, not a
    // private/internal CA — no custom root store to provision.
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(https);

    let mut backoff = BACKOFF_START;
    for attempt in 1..=MAX_ATTEMPTS {
        let request = match build_request(&tenants, &tenant, &config, body.clone()) {
            Ok(Some(request)) => request,
            Ok(None) => {
                // The tenant's signing key is gone (removed/never enrolled) —
                // nothing to sign with, and that won't change on a retry.
                tracing::warn!(
                    tenant = tenant.as_ref(),
                    url = %config.url,
                    "tenant has no signing key; giving up on the departure webhook",
                );
                return;
            }
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

/// Builds one webhook request: `POST` to the notify URL with the JSON body,
/// signed fresh with `tenant`'s Ed25519 key. Returns `Ok(None)` if the tenant
/// has no signing key to sign with (distinct from a malformed-request `Err`:
/// there is nothing wrong with the request, just nothing to authenticate it
/// with).
///
/// Signs on every call rather than once and reusing the result: the signed
/// message embeds the current timestamp, and the consumer enforces a replay
/// window on it, so a retry must carry a fresh timestamp (and therefore a
/// fresh signature) or it would be rejected as stale.
fn build_request(
    tenants: &TenantStore,
    tenant: &TenantId,
    config: &NotifyConfig,
    body: Bytes,
) -> Result<Option<hyper::Request<Full<Bytes>>>, hyper::http::Error> {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let timestamp = timestamp_ms.to_string();

    let mut message =
        Vec::with_capacity(WEBHOOK_SIG_DOMAIN.len() + timestamp.len() + 1 + body.len());
    message.extend_from_slice(WEBHOOK_SIG_DOMAIN.as_bytes());
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b':');
    message.extend_from_slice(&body);

    let Some(signature) = tenant::sign_webhook(tenants, tenant, &message) else {
        return Ok(None);
    };
    let signature_b64 = BASE64_STANDARD.encode(signature);

    hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(&config.url)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(TIMESTAMP_HEADER, timestamp)
        .header(SIGNATURE_HEADER, signature_b64)
        .body(Full::new(body))
        .map(Some)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::Router;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use base64::Engine as _;
    use rally_point_proto::control::{
        BufferBounds, DepartureKind, PlayerHandoff, RelayHello, SessionRequest, TenantId,
    };
    use rally_point_proto::ids::{RelayId, SlotId};
    use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId};
    use rally_point_proto::version::ProtocolVersion;
    use ring::signature::{ED25519, UnparsedPublicKey};
    use tokio::sync::mpsc;
    use tokio::time::{Duration, timeout};

    use super::*;
    use crate::registry;

    /// One webhook the stand-in tenant received: the two signature headers
    /// (raw strings, unvalidated — verification is the test's job) plus the
    /// exact body bytes (needed to reconstruct the signed message) and the
    /// body parsed as JSON (for the usual field assertions).
    #[derive(Clone)]
    struct Received {
        timestamp: Option<String>,
        signature: Option<String>,
        raw_body: Vec<u8>,
        body: serde_json::Value,
    }

    /// A stand-in tenant receiver: an axum server that records each POST it gets
    /// (its signature headers, raw body, and parsed JSON body) onto a channel.
    /// Returns the hook URL and the receive end.
    async fn spawn_receiver(status: StatusCode) -> (String, mpsc::UnboundedReceiver<Received>) {
        let (tx, rx) = mpsc::unbounded_channel::<Received>();
        let app = Router::new()
            .route(
                "/hook",
                post(
                    move |State(tx): State<mpsc::UnboundedSender<Received>>,
                          headers: HeaderMap,
                          raw_body: axum::body::Bytes| async move {
                        let header = |name: &str| {
                            headers
                                .get(name)
                                .and_then(|value| value.to_str().ok())
                                .map(str::to_owned)
                        };
                        let body = serde_json::from_slice(&raw_body).unwrap();
                        let _ = tx.send(Received {
                            timestamp: header(TIMESTAMP_HEADER),
                            signature: header(SIGNATURE_HEADER),
                            raw_body: raw_body.to_vec(),
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

    /// Asserts a received webhook is properly signed: the timestamp header
    /// parses as a decimal unix-epoch-milliseconds value that is current-ish
    /// (within a generous minute of "now" — a loose sanity check, not the
    /// consumer's own ±5 minute replay window), and the signature verifies
    /// against `tenant`'s enrolled public key over the exact domain-separated
    /// message (`rp2-webhook-v1:<timestamp>:<raw body bytes>`). No
    /// `Authorization` header is asserted anywhere: the bearer-secret scheme
    /// it belonged to is gone.
    fn assert_signed(setup: &SessionSetup, tenant: &str, received: &Received) {
        let timestamp_str = received
            .timestamp
            .as_deref()
            .expect("x-rp2-timestamp header is present");
        let timestamp_ms: u128 = timestamp_str
            .parse()
            .expect("x-rp2-timestamp is a decimal integer");
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        assert!(
            now_ms.abs_diff(timestamp_ms) < 60_000,
            "timestamp {timestamp_ms} is not current-ish (now is {now_ms})",
        );

        let signature_b64 = received
            .signature
            .as_deref()
            .expect("x-rp2-signature header is present");
        let signature = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .expect("x-rp2-signature is valid standard base64");

        let mut message = Vec::new();
        message.extend_from_slice(WEBHOOK_SIG_DOMAIN.as_bytes());
        message.extend_from_slice(timestamp_str.as_bytes());
        message.push(b':');
        message.extend_from_slice(&received.raw_body);

        let (_, pubkey) =
            tenant::verifying_key(setup.tenants(), &TenantId(tenant.to_owned())).unwrap();
        UnparsedPublicKey::new(&ED25519, pubkey)
            .verify(&message, &signature)
            .expect("the signature verifies against the tenant's enrolled public key");
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

    /// A departure notice with no correlation ids of its own — the relay-predates-
    /// the-field case, which relies entirely on the coordinator's stored session.
    fn notice(session: SessionId, slot: u8, kind: DepartureKind, reason: u32) -> DepartureNotice {
        DepartureNotice {
            tenant: TenantId("sb-test".to_owned()),
            session,
            slot: SlotId(slot),
            kind,
            reason,
            leave_seq: 1,
            external_id: None,
            external_ref: None,
        }
    }

    #[tokio::test]
    async fn a_departure_posts_one_webhook_with_body_and_signature_and_dedups_relays() {
        let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
        let (setup, session) = setup_with_session(Some("game-99"), Some("sb-user-7"));
        tenant::set_notify(
            setup.tenants(),
            &TenantId("sb-test".to_owned()),
            Some(NotifyConfig { url }),
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

        assert_signed(&setup, "sb-test", &got);
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
        // A gameId is present (so the departure isn't dropped for lacking one),
        // but no per-slot player ref — the webhook must still deliver, just
        // omitting `externalRef`.
        let (setup, session) = setup_with_session(Some("game-42"), None);
        tenant::set_notify(
            setup.tenants(),
            &TenantId("sb-test".to_owned()),
            Some(NotifyConfig { url }),
        );
        let dedup = new_dedup();

        handle_departure(&setup, &dedup, notice(session, 0, DepartureKind::Left, 3));

        let got = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a webhook is delivered")
            .unwrap();
        assert_eq!(got.body["kind"], "left");
        assert_signed(&setup, "sb-test", &got);
        assert_eq!(got.body["externalId"], "game-42");
        // Absent correlation ids are omitted entirely, not sent as `null` — the
        // consumer validates them as optional *strings*, and a literal `null`
        // would fail that validation. `Value::index` on a missing key also
        // returns `Null`, so `.get(..).is_none()` is the check that actually
        // proves omission rather than passing either way.
        assert!(
            got.body.get("externalRef").is_none(),
            "no per-slot ref was stored, so it's omitted rather than sent as null",
        );
    }

    #[tokio::test]
    async fn a_notice_carrying_its_own_refs_delivers_even_with_no_stored_session() {
        // The coordinator-restart scenario this fallback exists to fix: the
        // tenant's signing key is (re-)enrolled (it can be persisted, e.g. via
        // --tenant-key), but the in-memory session-refs map is empty because
        // create_session was never called this coordinator lifetime for this
        // session. A notice that carries its own refs (the relay stamped them
        // from its own stored descriptor, independent of the coordinator's
        // process lifetime) must still deliver a correct webhook.
        let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
        let reg = registry::new_registry();
        let tenants = tenant::new_store();
        tenant::enroll(
            &tenants,
            KeyId("test-key-1".to_owned()),
            TenantId("sb-test".to_owned()),
            BufferBounds::new(1, 6).unwrap(),
        )
        .unwrap();
        let setup = SessionSetup::new(reg, tenants);
        tenant::set_notify(
            setup.tenants(),
            &TenantId("sb-test".to_owned()),
            Some(NotifyConfig { url }),
        );
        let dedup = new_dedup();

        // No `create_session` call at all — the session store has nothing for
        // this (or any) session id.
        let mut restart_notice = notice(SessionId(777), 0, DepartureKind::Dropped, 0x4000_0006);
        restart_notice.external_id = Some("game-restart".to_owned());
        restart_notice.external_ref = Some("sb-user-restart".to_owned());

        handle_departure(&setup, &dedup, restart_notice);

        let got = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a webhook is delivered even with no stored session for it")
            .unwrap();
        assert_eq!(got.body["externalId"], "game-restart");
        assert_eq!(got.body["externalRef"], "sb-user-restart");
        assert_eq!(got.body["kind"], "dropped");
    }

    #[tokio::test]
    async fn no_gameid_ref_from_either_source_is_a_silent_no_op() {
        // Neither the notice nor the stored session (which itself was created
        // with no external_id) has a gameId ref — a webhook with no game to
        // attach to is useless to the consumer, so this stays a drop.
        let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
        let (setup, session) = setup_with_session(None, None);
        tenant::set_notify(
            setup.tenants(),
            &TenantId("sb-test".to_owned()),
            Some(NotifyConfig { url }),
        );
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
            "no gameId ref from the notice or the stored session -> dropped",
        );
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
            Some(NotifyConfig { url }),
        );
        let dedup = new_dedup();

        // A session the coordinator never created has no stored refs, and the
        // (refless) notice carries none either -> no gameId from any source,
        // so this still drops even though the "no session record" branch
        // itself is no longer a hard stop.
        handle_departure(
            &setup,
            &dedup,
            notice(SessionId(999_999), 0, DepartureKind::Dropped, 0x4000_0006),
        );

        assert!(
            timeout(Duration::from_millis(400), rx.recv())
                .await
                .is_err(),
            "a departure for an unknown session, with no notice-carried refs, sends no webhook",
        );
    }
}
