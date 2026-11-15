//! Webhook delivery: retry/backoff over one signed POST attempt. Split out of
//! `handlers` because this layer knows nothing about notice kinds — it just
//! takes a tenant, a config, and an already-serialized body and gets it
//! delivered (or gives up), reusing [`super::WEBHOOK_CLIENT`] and
//! [`super::DISPATCH_PERMITS`] across lifecycle notices and tenants. Periodic
//! samples reuse request signing and bounded attempts with their own gate.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use rally_point_proto::control::TenantId;
use rally_point_proto::time::unix_millis;

use super::*;
use crate::tenant::{self, NotifyConfig, TenantStore};

/// The domain-separation prefix on the signed message, so a webhook signature
/// can never be confused with a player-token signature made by the same
/// tenant key (which signs an unrelated canonical message with no such
/// prefix).
pub(super) const WEBHOOK_SIG_DOMAIN: &str = "rp2-webhook-v1:";

/// Header carrying the signing timestamp: unix epoch milliseconds, decimal.
/// The consumer enforces a bounded (±5 minute) replay window on it.
pub(super) const TIMESTAMP_HEADER: &str = "x-rp2-timestamp";
/// Header carrying the Ed25519 signature: standard (padded) base64 of the
/// 64-byte signature over the domain-separated, timestamped message.
pub(super) const SIGNATURE_HEADER: &str = "x-rp2-signature";

/// POSTs the webhook body, retrying non-2xx responses and connect errors with
/// capped backoff, then giving up with a `warn!`. Success is any 2xx. `kind`
/// labels the delivery in logs (departure vs. desync); `body` is the already
/// serialized JSON.
///
/// When a non-2xx response carries a `Retry-After` delay, the wait before the
/// next attempt is the larger of the exponential backoff and that delay, with
/// the delay capped at the backoff cap (see `retry_wait`). `session` is only
/// for log correlation.
///
/// `tenants` + `tenant` are what let a detached task sign the request itself —
/// the caller resolves them before spawning, since the private key stays behind
/// `tenant::sign_webhook`'s narrow interface rather than being handed out as an
/// `Arc<Ed25519KeyPair>`.
pub(crate) async fn dispatch(
    tenants: TenantStore,
    tenant: TenantId,
    session: SessionId,
    config: NotifyConfig,
    body: Bytes,
    kind: &'static str,
) {
    let mut backoff = BACKOFF_START;
    let mut last_failure = None;
    for attempt in 1..=MAX_ATTEMPTS {
        let request = match build_request(&tenants, &tenant, &config, body.clone()) {
            Ok(Some(request)) => request,
            Ok(None) => {
                // The tenant's signing key is gone (removed/never enrolled) —
                // nothing to sign with, and that won't change on a retry.
                crate::metrics::webhook_delivered(&tenant, "gave_up");
                tracing::warn!(
                    tenant = tenant.as_ref(),
                    session = session.0,
                    url = %config.url,
                    kind,
                    "tenant has no signing key; giving up on the webhook",
                );
                return;
            }
            Err(error) => {
                // A malformed URL/header is deterministic — retrying can't fix
                // it, so give up now rather than burning the whole budget.
                crate::metrics::webhook_delivered(&tenant, "gave_up");
                tracing::warn!(
                    tenant = tenant.as_ref(),
                    session = session.0,
                    url = %config.url,
                    %error,
                    kind,
                    "webhook request is unbuildable; dropping",
                );
                return;
            }
        };

        // Acquired fresh for this attempt alone, released before the backoff
        // sleep below (the permit's scope ends with this block) — a slow or
        // failing dispatch must not also hold a fleet-wide concurrency slot
        // idle through its own backoff, which would starve unrelated sessions'
        // dispatches for no reason (the endpoint isn't even being asked
        // anything during backoff). The semaphore is a `static` that is never
        // closed, so acquiring it can only be interrupted by the task itself
        // being cancelled — which would drop this future before `expect` ever
        // runs.
        let outcome = {
            let _permit = DISPATCH_PERMITS
                .acquire()
                .await
                .expect("DISPATCH_PERMITS is never closed");
            send_attempt(request, ATTEMPT_TIMEOUT).await
        };
        let mut retry_after = None;
        match outcome {
            Ok(AttemptResponse {
                status,
                retry_after: server_delay,
            }) => {
                if (200..300).contains(&status) {
                    crate::metrics::webhook_delivered(&tenant, "ok");
                    tracing::debug!(url = %config.url, status, kind, "webhook delivered");
                    return;
                }
                tracing::debug!(
                    url = %config.url,
                    status,
                    retry_after = ?server_delay,
                    attempt,
                    kind,
                    "webhook non-2xx; retrying",
                );
                retry_after = server_delay;
                last_failure = Some(AttemptFailure::Status(status));
            }
            Err(AttemptError::TimedOut) => {
                tracing::debug!(
                    url = %config.url,
                    attempt,
                    kind,
                    timeout = ?ATTEMPT_TIMEOUT,
                    "webhook attempt timed out; retrying",
                );
                last_failure = Some(AttemptFailure::TimedOut);
            }
            Err(AttemptError::BodyTooLarge) => {
                tracing::debug!(
                    url = %config.url,
                    attempt,
                    kind,
                    cap = MAX_RESPONSE_BODY_BYTES,
                    "webhook response body exceeded the cap; retrying",
                );
                last_failure = Some(AttemptFailure::BodyTooLarge);
            }
            Err(AttemptError::Transport(error)) => {
                tracing::debug!(url = %config.url, %error, attempt, kind, "webhook attempt failed; retrying");
                last_failure = Some(AttemptFailure::Transport(error.to_string()));
            }
        }

        // Only a failed attempt reaches here — a 2xx delivery returned above — so
        // every non-2xx status, timeout, oversize response, and transport error is
        // counted once as a failed attempt.
        crate::metrics::webhook_attempt_failed(&tenant);

        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(retry_wait(backoff, retry_after)).await;
            backoff = (backoff * 2).min(BACKOFF_CAP);
        }
    }

    crate::metrics::webhook_delivered(&tenant, "gave_up");
    tracing::warn!(
        tenant = tenant.as_ref(),
        session = session.0,
        url = %config.url,
        attempts = MAX_ATTEMPTS,
        last_failure = %last_failure
            .as_ref()
            .map_or_else(|| "none".to_owned(), ToString::to_string),
        kind,
        "gave up delivering a webhook; the consumer's result-based fallback covers it",
    );
}

/// How long to wait before the next attempt: the larger of the current
/// exponential `backoff` and the server's `Retry-After` delay (if any), with the
/// server's delay capped at [`BACKOFF_CAP`]. The cap matters because the
/// session's ordered queue is blocked while this notice waits, so an endpoint
/// must not be able to park it for an arbitrary time.
pub(super) fn retry_wait(backoff: Duration, retry_after: Option<Duration>) -> Duration {
    backoff.max(retry_after.map_or(Duration::ZERO, |delay| delay.min(BACKOFF_CAP)))
}

/// Parses a `Retry-After` response header in its delta-seconds form (a
/// non-negative decimal integer number of seconds). The HTTP-date form, a
/// missing header, and anything else unparseable (including negative numbers)
/// yield `None`. Values too large for a `u64` saturate.
pub(super) fn parse_retry_after(headers: &hyper::HeaderMap) -> Option<Duration> {
    let value = headers
        .get(hyper::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(Duration::from_secs(value.parse().unwrap_or(u64::MAX)))
}

/// A usable response to one webhook attempt.
#[derive(Debug)]
pub(super) struct AttemptResponse {
    /// The HTTP status code.
    pub(super) status: u16,
    /// The server's `Retry-After` delay, when it sent one in delta-seconds form.
    pub(super) retry_after: Option<Duration>,
}

/// Why the most recent attempt did not deliver, for the give-up log line.
#[derive(Debug)]
pub(super) enum AttemptFailure {
    /// The endpoint answered with a non-2xx status.
    Status(u16),
    /// The attempt exceeded [`ATTEMPT_TIMEOUT`].
    TimedOut,
    /// The response body exceeded [`MAX_RESPONSE_BODY_BYTES`].
    BodyTooLarge,
    /// A transport-level error, as its display text.
    Transport(String),
}

impl std::fmt::Display for AttemptFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(status) => write!(f, "HTTP status {status}"),
            Self::TimedOut => write!(f, "attempt timed out"),
            Self::BodyTooLarge => write!(f, "response body over the size cap"),
            Self::Transport(error) => write!(f, "transport error: {error}"),
        }
    }
}

/// Why one webhook attempt produced no usable response. Both variants are
/// treated identically by the caller (a failed attempt, retried like a
/// non-2xx status) but are logged distinctly so a hung endpoint is
/// distinguishable from a refused/reset connection in traces.
#[derive(Debug)]
pub(super) enum AttemptError {
    /// The attempt did not complete — request through full body read — within
    /// [`ATTEMPT_TIMEOUT`].
    TimedOut,
    /// The response body exceeded [`MAX_RESPONSE_BODY_BYTES`] before finishing.
    BodyTooLarge,
    /// A transport-level error below the HTTP response (connect failure,
    /// reset, etc).
    Transport(hyper_util::client::legacy::Error),
}

/// Sends one webhook request on the shared [`WEBHOOK_CLIENT`] and returns its
/// status and `Retry-After` delay, bounding the *whole* attempt — connect
/// through the full body read — by one [`tokio::time::timeout`] and the body
/// by [`MAX_RESPONSE_BODY_BYTES`].
/// Both bounds exist for the same reason: the coordinator never reads the
/// response body's content (only the status matters), so an endpoint that is
/// slow or unbounded on either axis must not be able to hang this session's
/// queue or grow its memory — see each constant's own doc. Split out of
/// `dispatch`'s retry loop so this behavior is unit-testable without waiting
/// out the full multi-attempt retry budget.
pub(super) async fn send_attempt(
    request: hyper::Request<Full<Bytes>>,
    attempt_timeout: Duration,
) -> Result<AttemptResponse, AttemptError> {
    let attempt = async {
        let response = WEBHOOK_CLIENT
            .request(request)
            .await
            .map_err(AttemptError::Transport)?;
        let status = response.status().as_u16();
        let retry_after = parse_retry_after(response.headers());
        // The body is never read for its content, only drained so the
        // connection returns to the client's pool cleanly — capped so an
        // endpoint streaming (or just sending) an oversized body can't grow
        // this indefinitely.
        Limited::new(response.into_body(), MAX_RESPONSE_BODY_BYTES)
            .collect()
            .await
            .map_err(|_| AttemptError::BodyTooLarge)?;
        Ok(AttemptResponse {
            status,
            retry_after,
        })
    };
    match tokio::time::timeout(attempt_timeout, attempt).await {
        Ok(result) => result,
        Err(_elapsed) => Err(AttemptError::TimedOut),
    }
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
pub(super) fn build_request(
    tenants: &TenantStore,
    tenant: &TenantId,
    config: &NotifyConfig,
    body: Bytes,
) -> Result<Option<hyper::Request<Full<Bytes>>>, hyper::http::Error> {
    let timestamp_ms = unix_millis();
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
