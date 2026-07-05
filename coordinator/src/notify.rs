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
use rally_point_proto::control::{
    DepartureKind, DepartureNotice, DesyncNotice, ResultNotice, TenantId,
};
use rally_point_proto::ids::{SessionId, SlotId};
use serde::Serialize;

use crate::session::{self, SessionSetup};
use crate::tenant::{self, NotifyConfig, TenantStore};

/// Departures already handled, keyed by `(tenant, session, slot)`. Shared across
/// every relay control connection so the redundant reports of one leave collapse
/// to a single webhook. In-memory only: a coordinator restart forgets it, which
/// at worst re-fires a webhook the idempotent consumer discards.
pub type DepartureDedup = Arc<Mutex<HashSet<(TenantId, SessionId, SlotId)>>>;

/// Desyncs already handled, keyed by `(tenant, session, sync_ordinal)` — the
/// sibling of [`DepartureDedup`]. The sync ordinal is the event identity (a
/// re-detection after an authority promotion lands at a distinct later ordinal),
/// so it dedups the at-least-once redeliveries of one event without collapsing
/// two genuinely separate divergences.
pub type DesyncDedup = Arc<Mutex<HashSet<(TenantId, SessionId, u64)>>>;

/// Results already handled, keyed by `(tenant, session, slot)` — one report per
/// slot, the sibling of [`DepartureDedup`] with the same key shape (a slot
/// reports at most one result). Collapses the at-least-once redeliveries of one
/// report to a single webhook.
pub type ResultDedup = Arc<Mutex<HashSet<(TenantId, SessionId, SlotId)>>>;

/// The notice dedup sets a coordinator holds, bundled so the api layer
/// threads one value rather than several through its control-connection handlers.
#[derive(Clone)]
pub struct NoticeDedup {
    /// Departure dedup by `(tenant, session, slot)`.
    pub departures: DepartureDedup,
    /// Desync dedup by `(tenant, session, sync_ordinal)`.
    pub desyncs: DesyncDedup,
    /// Result dedup by `(tenant, session, slot)`.
    pub results: ResultDedup,
}

/// Creates an empty notice dedup set (departures + desyncs + results).
pub fn new_dedup() -> NoticeDedup {
    NoticeDedup {
        departures: Arc::new(Mutex::new(HashSet::new())),
        desyncs: Arc::new(Mutex::new(HashSet::new())),
        results: Arc::new(Mutex::new(HashSet::new())),
    }
}

/// How many webhook attempts before giving up. With [`BACKOFF_START`] doubling to
/// [`BACKOFF_CAP`], six attempts span roughly a minute of retries.
const MAX_ATTEMPTS: u32 = 6;
/// The first retry backoff; doubles each attempt up to [`BACKOFF_CAP`].
const BACKOFF_START: Duration = Duration::from_secs(2);
/// The retry-backoff ceiling.
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// The JSON body POSTed to the tenant for a departure. camelCase, matching the
/// *consumer's* API conventions rather than the relay control plane's snake_case
/// — the webhook lands on the tenant's own HTTP surface, so its style wins.
/// `kind` serializes `"left"` / `"dropped"`. The `event` discriminator lets the
/// consumer's one webhook endpoint fan the body out by kind (a desync body
/// carries `"event":"desync"`). The correlation ids are **omitted** (not sent as
/// `null`) when the session carried none: the consumer validates them as optional
/// strings, and a literal JSON `null` fails that validation rather than reading
/// as "absent".
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DepartureWebhook {
    event: &'static str,
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

/// One diverged slot in a desync webhook body: the slot plus its optional tenant
/// ref, camelCase like the rest of the body. The `externalRef` is omitted when
/// absent, never `null`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DivergedSlotWebhook {
    slot: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_ref: Option<String>,
}

/// The JSON body POSTed to the tenant for a desync. Same camelCase convention and
/// same `event` discriminator as the departure body. Optional fields
/// (`externalId`, `gameFrame`) are omitted when absent, never `null`. `diverged`
/// is always present (possibly empty, when `noMajority`).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesyncWebhook {
    event: &'static str,
    tenant: String,
    session: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
    sync_ordinal: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    game_frame: Option<u32>,
    detected_at_ms: u64,
    no_majority: bool,
    diverged: Vec<DivergedSlotWebhook>,
}

/// The JSON body POSTed to the tenant for a result report. Same camelCase
/// convention and `event` discriminator as the other bodies. `payload` is the
/// tenant's opaque result bytes as a standard-base64 string (the relay and
/// coordinator never parse them). Optional fields (`externalId`, `externalRef`,
/// `sessionFrame`, `slotFrame`) are omitted when absent, never `null`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultWebhook {
    event: &'static str,
    tenant: String,
    session: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_id: Option<String>,
    slot: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_ref: Option<String>,
    payload: String,
    arrival_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_frame: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slot_frame: Option<u32>,
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
        event: "departure",
        tenant: notice.tenant.as_ref().to_owned(),
        session: notice.session.0,
        external_id: Some(external_id),
        slot: notice.slot.0,
        external_ref,
        kind: notice.kind,
        reason: notice.reason,
        leave_seq: notice.leave_seq,
    };

    spawn_dispatch(setup, notice.tenant, config, &payload, "departure");
}

/// Handles one relay's desync notice.
///
/// A sibling of [`handle_departure`]: first sight of a
/// `(tenant, session, sync_ordinal)` resolves the session's `external_id` and the
/// tenant's notify config, then spawns a signed webhook. A duplicate (an
/// at-least-once redelivery of the same event), a tenant with no notify config,
/// or a desync with no `gameId` ref from any source are each a debug-logged drop.
///
/// Correlation ids come notice-first, stored-session as fallback — the same rule
/// as departures, so a coordinator restart that wiped the session store still
/// delivers a correct webhook from the notice's self-stamped refs. Each diverged
/// slot's `externalRef` resolves independently (notice ref, else the stored
/// per-slot ref), so a partially-ref'd notice still names whom it can.
pub fn handle_desync(setup: &SessionSetup, dedup: &DesyncDedup, notice: DesyncNotice) {
    if !dedup
        .lock()
        .insert((notice.tenant.clone(), notice.session, notice.sync_ordinal))
    {
        tracing::debug!(
            tenant = notice.tenant.as_ref(),
            session = notice.session.0,
            sync_ordinal = notice.sync_ordinal,
            "duplicate desync notice; already handled",
        );
        return;
    }

    let Some(config) = tenant::notify_config(setup.tenants(), &notice.tenant) else {
        tracing::debug!(
            tenant = notice.tenant.as_ref(),
            session = notice.session.0,
            sync_ordinal = notice.sync_ordinal,
            "no notify config for tenant; dropping desync",
        );
        return;
    };

    let stored = session::session_refs(setup, &notice.tenant, notice.session);
    let external_id = notice
        .external_id
        .clone()
        .or_else(|| stored.as_ref().and_then(|refs| refs.external_id.clone()));

    let Some(external_id) = external_id else {
        tracing::debug!(
            tenant = notice.tenant.as_ref(),
            session = notice.session.0,
            sync_ordinal = notice.sync_ordinal,
            "no gameId ref from the notice or a stored session; dropping desync",
        );
        return;
    };

    let diverged = notice
        .diverged
        .iter()
        .map(|d| DivergedSlotWebhook {
            slot: d.slot.0,
            external_ref: d.external_ref.clone().or_else(|| {
                stored
                    .as_ref()
                    .and_then(|refs| refs.slots.get(&d.slot).cloned())
            }),
        })
        .collect();

    let payload = DesyncWebhook {
        event: "desync",
        tenant: notice.tenant.as_ref().to_owned(),
        session: notice.session.0,
        external_id: Some(external_id),
        sync_ordinal: notice.sync_ordinal,
        game_frame: notice.game_frame,
        detected_at_ms: notice.detected_at_ms,
        no_majority: notice.no_majority,
        diverged,
    };

    spawn_dispatch(setup, notice.tenant, config, &payload, "desync");
}

/// Handles one relay's result notice.
///
/// A sibling of [`handle_departure`]: first sight of a `(tenant, session, slot)`
/// resolves the reporting slot's correlation ids and the tenant's notify config,
/// base64-encodes the opaque payload, then spawns a signed webhook. A duplicate
/// (an at-least-once redelivery, or a second relay that somehow saw the report),
/// a tenant with no notify config, or a result with no `gameId` ref from any
/// source are each a debug-logged drop — the notification is best-effort.
///
/// Correlation ids come notice-first, stored-session as fallback — the same rule
/// as departures, so a coordinator restart that wiped the session store still
/// delivers a correct webhook from the notice's self-stamped refs. The payload
/// bytes are never parsed here; they are relayed straight through as base64.
pub fn handle_result(setup: &SessionSetup, dedup: &ResultDedup, notice: ResultNotice) {
    if !dedup
        .lock()
        .insert((notice.tenant.clone(), notice.session, notice.slot))
    {
        tracing::debug!(
            tenant = notice.tenant.as_ref(),
            session = notice.session.0,
            slot = notice.slot.0,
            "duplicate result notice; already handled",
        );
        return;
    }

    let Some(config) = tenant::notify_config(setup.tenants(), &notice.tenant) else {
        tracing::debug!(
            tenant = notice.tenant.as_ref(),
            session = notice.session.0,
            slot = notice.slot.0,
            "no notify config for tenant; dropping result",
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
            "no gameId ref from the notice or a stored session; dropping result",
        );
        return;
    };

    let payload = ResultWebhook {
        event: "result",
        tenant: notice.tenant.as_ref().to_owned(),
        session: notice.session.0,
        external_id: Some(external_id),
        slot: notice.slot.0,
        external_ref,
        payload: BASE64_STANDARD.encode(&notice.payload),
        arrival_ms: notice.arrival_ms,
        session_frame: notice.session_frame,
        slot_frame: notice.slot_frame,
    };

    spawn_dispatch(setup, notice.tenant, config, &payload, "result");
}

/// Serializes `payload` and spawns its webhook dispatch. The tenant store is
/// cheap to clone (Arc-backed) and carried into the spawned task so `dispatch`
/// can sign fresh on every attempt — a detached task otherwise has no path back
/// to the tenant's signing key. `kind` labels the delivery in logs.
fn spawn_dispatch(
    setup: &SessionSetup,
    tenant: TenantId,
    config: NotifyConfig,
    payload: &impl Serialize,
    kind: &'static str,
) {
    let body = match serde_json::to_vec(payload) {
        Ok(bytes) => Bytes::from(bytes),
        Err(error) => {
            tracing::error!(%error, kind, "serializing a webhook body failed; dropping");
            return;
        }
    };
    tokio::spawn(dispatch(
        setup.tenants().clone(),
        tenant,
        config,
        body,
        kind,
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

/// POSTs the webhook body, retrying non-2xx responses and connect errors with
/// capped backoff, then giving up with a `warn!`. Success is any 2xx. `kind`
/// labels the delivery in logs (departure vs. desync); `body` is the already
/// serialized JSON.
///
/// `tenants` + `tenant` are what let a detached task sign the request itself —
/// the caller resolves them before spawning, since the private key stays behind
/// `tenant::sign_webhook`'s narrow interface rather than being handed out as an
/// `Arc<Ed25519KeyPair>`.
async fn dispatch(
    tenants: TenantStore,
    tenant: TenantId,
    config: NotifyConfig,
    body: Bytes,
    kind: &'static str,
) {
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
                    kind,
                    "tenant has no signing key; giving up on the webhook",
                );
                return;
            }
            Err(error) => {
                // A malformed URL/header is deterministic — retrying can't fix
                // it, so give up now rather than burning the whole budget.
                tracing::warn!(url = %config.url, %error, kind, "webhook request is unbuildable; dropping");
                return;
            }
        };

        match client.request(request).await {
            Ok(response) => {
                let status = response.status().as_u16();
                // Drain the body so the connection returns to the pool cleanly.
                let _ = response.into_body().collect().await;
                if (200..300).contains(&status) {
                    tracing::debug!(url = %config.url, status, kind, "webhook delivered");
                    return;
                }
                tracing::debug!(url = %config.url, status, attempt, kind, "webhook non-2xx; retrying");
            }
            Err(error) => {
                tracing::debug!(url = %config.url, %error, attempt, kind, "webhook attempt failed; retrying");
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
        kind,
        "gave up delivering a webhook; the consumer's result-based fallback covers it",
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
        BufferBounds, DepartureKind, DivergedSlot, PlayerHandoff, RelayHello, ResultNotice,
        SessionRequest, TenantId,
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
                    observer: false,
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
            &dedup.departures,
            notice(session, 0, DepartureKind::Dropped, 0x4000_0006),
        );
        handle_departure(
            &setup,
            &dedup.departures,
            notice(session, 0, DepartureKind::Dropped, 0x4000_0006),
        );

        let got = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a webhook is delivered")
            .expect("the receiver got it");

        assert_signed(&setup, "sb-test", &got);
        assert_eq!(got.body["event"], "departure");
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

        handle_departure(
            &setup,
            &dedup.departures,
            notice(session, 0, DepartureKind::Left, 3),
        );

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

        handle_departure(&setup, &dedup.departures, restart_notice);

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
            &dedup.departures,
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
            &dedup.departures,
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
            &dedup.departures,
            notice(SessionId(999_999), 0, DepartureKind::Dropped, 0x4000_0006),
        );

        assert!(
            timeout(Duration::from_millis(400), rx.recv())
                .await
                .is_err(),
            "a departure for an unknown session, with no notice-carried refs, sends no webhook",
        );
    }

    // -- Desync webhooks --

    /// A desync notice carrying its own gameId and a diverged slot with a ref, so
    /// a webhook delivers without depending on the coordinator's stored session.
    fn desync(session: SessionId, sync_ordinal: u64, no_majority: bool) -> DesyncNotice {
        DesyncNotice {
            tenant: TenantId("sb-test".to_owned()),
            session,
            sync_ordinal,
            game_frame: Some(4242),
            detected_at_ms: 1_700_000_000_000,
            no_majority,
            diverged: if no_majority {
                vec![]
            } else {
                vec![DivergedSlot {
                    slot: SlotId(2),
                    external_ref: Some("sb-user-diverged".to_owned()),
                }]
            },
            external_id: Some("game-desync".to_owned()),
        }
    }

    #[tokio::test]
    async fn a_desync_posts_one_signed_webhook_and_dedups_by_sync_ordinal() {
        let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
        // A tenant enrolled (for the signing key) but no session created this
        // lifetime: the notice's self-stamped refs carry the webhook.
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

        // Two at-least-once redeliveries of the same event webhook once.
        handle_desync(&setup, &dedup.desyncs, desync(SessionId(7), 91, false));
        handle_desync(&setup, &dedup.desyncs, desync(SessionId(7), 91, false));

        let got = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a desync webhook is delivered")
            .expect("the receiver got it");
        assert_signed(&setup, "sb-test", &got);
        assert_eq!(got.body["event"], "desync");
        assert_eq!(got.body["tenant"], "sb-test");
        assert_eq!(got.body["session"], 7);
        assert_eq!(got.body["externalId"], "game-desync");
        assert_eq!(got.body["syncOrdinal"], 91);
        assert_eq!(got.body["gameFrame"], 4242);
        assert_eq!(got.body["detectedAtMs"], 1_700_000_000_000u64);
        assert_eq!(got.body["noMajority"], false);
        assert_eq!(got.body["diverged"][0]["slot"], 2);
        assert_eq!(got.body["diverged"][0]["externalRef"], "sb-user-diverged");

        assert!(
            timeout(Duration::from_millis(400), rx.recv())
                .await
                .is_err(),
            "a redelivery of the same (tenant, session, sync_ordinal) webhooks once",
        );
    }

    #[tokio::test]
    async fn a_no_majority_desync_omits_absent_optionals_and_carries_an_empty_diverged() {
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

        // A no-majority desync with no game frame — gameFrame must be omitted, not
        // null, and diverged is an empty array.
        let mut notice = desync(SessionId(8), 5, true);
        notice.game_frame = None;
        handle_desync(&setup, &dedup.desyncs, notice);

        let got = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a desync webhook is delivered")
            .unwrap();
        assert_eq!(got.body["event"], "desync");
        assert_eq!(got.body["noMajority"], true);
        assert_eq!(got.body["diverged"].as_array().unwrap().len(), 0);
        assert!(
            got.body.get("gameFrame").is_none(),
            "an absent game frame is omitted, not sent as null",
        );
    }

    #[tokio::test]
    async fn a_desync_with_no_gameid_from_any_source_is_a_silent_no_op() {
        let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
        let (setup, session) = setup_with_session(None, None);
        tenant::set_notify(
            setup.tenants(),
            &TenantId("sb-test".to_owned()),
            Some(NotifyConfig { url }),
        );
        let dedup = new_dedup();

        // Neither the notice nor the stored session has a gameId.
        let mut notice = desync(session, 1, false);
        notice.external_id = None;
        handle_desync(&setup, &dedup.desyncs, notice);

        assert!(
            timeout(Duration::from_millis(400), rx.recv())
                .await
                .is_err(),
            "no gameId from the notice or the stored session -> dropped",
        );
    }

    // -- Result webhooks --

    /// A result notice carrying its own gameId and player ref plus opaque bytes,
    /// so a webhook delivers without depending on the coordinator's stored
    /// session. `refs_from_notice` controls whether the correlation ids ride the
    /// notice (self-describing) or are left to the stored-session fallback.
    fn result(session: SessionId, slot: u8, refs_from_notice: bool) -> ResultNotice {
        ResultNotice {
            tenant: TenantId("sb-test".to_owned()),
            session,
            slot: SlotId(slot),
            external_id: refs_from_notice.then(|| "game-result".to_owned()),
            external_ref: refs_from_notice.then(|| "sb-user-result".to_owned()),
            payload: vec![0x01, 0x02, 0x03, 0x04],
            arrival_ms: 1_700_000_000_123,
            session_frame: Some(4200),
            slot_frame: Some(4242),
        }
    }

    #[tokio::test]
    async fn a_result_posts_one_signed_webhook_with_base64_payload_and_dedups_by_slot() {
        let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
        // A tenant enrolled (for the signing key) but no session created this
        // lifetime: the notice's self-stamped refs carry the webhook.
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

        // Two at-least-once redeliveries of the same slot's report webhook once.
        handle_result(&setup, &dedup.results, result(SessionId(7), 1, true));
        handle_result(&setup, &dedup.results, result(SessionId(7), 1, true));

        let got = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a result webhook is delivered")
            .expect("the receiver got it");
        assert_signed(&setup, "sb-test", &got);
        assert_eq!(got.body["event"], "result");
        assert_eq!(got.body["tenant"], "sb-test");
        assert_eq!(got.body["session"], 7);
        assert_eq!(got.body["externalId"], "game-result");
        assert_eq!(got.body["slot"], 1);
        assert_eq!(got.body["externalRef"], "sb-user-result");
        // The opaque payload rides as standard base64 of the raw bytes.
        assert_eq!(
            got.body["payload"],
            base64::engine::general_purpose::STANDARD.encode([0x01, 0x02, 0x03, 0x04]),
        );
        assert_eq!(got.body["arrivalMs"], 1_700_000_000_123u64);
        assert_eq!(got.body["sessionFrame"], 4200);
        assert_eq!(got.body["slotFrame"], 4242);

        assert!(
            timeout(Duration::from_millis(400), rx.recv())
                .await
                .is_err(),
            "a redelivery of the same (tenant, session, slot) webhooks once",
        );
    }

    #[tokio::test]
    async fn a_result_with_no_notice_refs_falls_back_to_the_stored_session() {
        // The notice carries no correlation ids of its own; the coordinator's
        // stored session (from create_session) supplies both the gameId and the
        // player ref — the refs-fallback path.
        let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
        let (setup, session) = setup_with_session(Some("game-stored"), Some("sb-user-stored"));
        tenant::set_notify(
            setup.tenants(),
            &TenantId("sb-test".to_owned()),
            Some(NotifyConfig { url }),
        );
        let dedup = new_dedup();

        handle_result(&setup, &dedup.results, result(session, 0, false));

        let got = timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("a result webhook is delivered from the stored session refs")
            .unwrap();
        assert_eq!(got.body["externalId"], "game-stored");
        assert_eq!(got.body["externalRef"], "sb-user-stored");
    }

    #[tokio::test]
    async fn a_result_with_no_gameid_from_any_source_is_a_silent_no_op() {
        let (url, mut rx) = spawn_receiver(StatusCode::OK).await;
        let (setup, session) = setup_with_session(None, None);
        tenant::set_notify(
            setup.tenants(),
            &TenantId("sb-test".to_owned()),
            Some(NotifyConfig { url }),
        );
        let dedup = new_dedup();

        // Neither the notice nor the stored session has a gameId.
        handle_result(&setup, &dedup.results, result(session, 0, false));

        assert!(
            timeout(Duration::from_millis(400), rx.recv())
                .await
                .is_err(),
            "no gameId from the notice or the stored session -> dropped",
        );
    }
}
