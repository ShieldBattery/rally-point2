//! Uploads a compressed flight recording straight to durable object storage using a
//! presigned URL the coordinator mints per upload. The relay holds no long-lived
//! store credentials — only the short-lived URL — so it PUTs the bytes itself rather
//! than shipping them up the control connection.
//!
//! Built on hyper + hyper-util + hyper-rustls on the workspace's ring provider — the
//! same stack the coordinator's webhook client uses, deliberately not reqwest, so the
//! tree grows no second crypto backend. One client is built once and shared: it pools
//! connections and reuses the parsed root store across uploads. An upload runs in a
//! detached task so neither control-connection half blocks on it, retries a small
//! bounded number of times within the grant URL's useful lifetime, and reports its
//! outcome back to the connection's writer — flight data is observability, so a lost
//! recording is acceptable but a wedged upload is not.

use std::sync::LazyLock;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rally_point_proto::ids::RelayId;
use tokio::sync::mpsc;

/// The outcome of an upload (its bounded internal retries included), reported back to
/// the control connection's writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// The object is stored — a PUT returned a 2xx.
    Stored,
    /// Every attempt within the grant's useful lifetime failed; the recording is lost.
    Failed,
}

/// A finished upload reported back to the control connection's writer over the shared
/// completion channel: which request it was for (the writer's per-connection
/// correlation id) and how it ended. The id lets the writer match the report to the
/// one in-flight shipment it belongs to, since many uploads can run at once.
pub struct FlightPutDone {
    /// The correlation id of the request whose upload this reports.
    pub request: u64,
    /// How the upload ended.
    pub outcome: PutOutcome,
}

type UploadClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// One client, built once and shared by every upload. hyper/hyper-util pool
/// connections and are cheap to share (an internal `Arc`); reusing one avoids a fresh
/// TLS handshake and root-store re-parse per upload. The connector negotiates rustls
/// (ring, webpki public-CA roots) for an `https://` presigned URL — what a real object
/// store gives — and falls through to plain HTTP for `http://`, the loopback object
/// store a test stands in with.
static UPLOAD_CLIENT: LazyLock<UploadClient> = LazyLock::new(|| {
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
});

/// How long one upload PUT attempt (connect through the response) may run before it
/// counts as failed. Generous for a multi-megabyte body over a real network, bounded
/// so a hung endpoint cannot pin the attempt forever.
const PUT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(20);

/// How many upload attempts before giving up. Small: the presigned URL expires within
/// minutes, so retries must stay well inside that window, and a lost recording is
/// acceptable where a wedged upload task is not.
const MAX_PUT_ATTEMPTS: u32 = 3;

/// The fixed gap between upload attempts. Short, so three attempts plus their timeouts
/// stay well inside the grant URL's few-minute expiry.
const PUT_RETRY_DELAY: Duration = Duration::from_secs(2);

/// The largest upload response body read before giving up on the attempt. An object
/// store's PUT response is empty or a few bytes; this only bounds memory against an
/// endpoint that streams an unbounded body, since only the status matters.
const MAX_PUT_RESPONSE_BYTES: usize = 64 * 1024;

/// Spawns the upload of `payload` to `url`, reporting the outcome for `request` on the
/// shared `done` channel. Detached so neither control-connection half blocks on the
/// PUT; a dropped `done` receiver (the task outliving a torn-down connection) simply
/// discards the report — the writer re-requests the shipment on the next connection.
pub fn spawn_put(
    url: String,
    payload: Bytes,
    relay_id: RelayId,
    request: u64,
    done: mpsc::UnboundedSender<FlightPutDone>,
) {
    tokio::spawn(async move {
        let outcome = put_with_retry(&url, payload, relay_id).await;
        let _ = done.send(FlightPutDone { request, outcome });
    });
}

/// Uploads `payload`, retrying a failed attempt up to [`MAX_PUT_ATTEMPTS`] times with a
/// fixed gap, and reports whether it ended stored.
async fn put_with_retry(url: &str, payload: Bytes, relay_id: RelayId) -> PutOutcome {
    for attempt in 1..=MAX_PUT_ATTEMPTS {
        match put_once(url, payload.clone()).await {
            Ok(()) => return PutOutcome::Stored,
            Err(error) => {
                tracing::debug!(
                    relay_id = relay_id.0,
                    attempt,
                    %error,
                    "flight recording upload attempt failed",
                );
                if attempt < MAX_PUT_ATTEMPTS {
                    tokio::time::sleep(PUT_RETRY_DELAY).await;
                }
            }
        }
    }
    PutOutcome::Failed
}

/// One upload PUT: the whole attempt (connect through the drained response) bounded by
/// [`PUT_ATTEMPT_TIMEOUT`]. `Full<Bytes>` carries the compressed body with a known
/// length, so the client sets the exact `Content-Length` the presigned URL's signature
/// bound — no extra header the relay must reproduce.
async fn put_once(url: &str, payload: Bytes) -> Result<(), PutError> {
    let request = hyper::Request::builder()
        .method(hyper::Method::PUT)
        .uri(url)
        .body(Full::new(payload))
        .map_err(PutError::Request)?;
    let attempt = async {
        let response = UPLOAD_CLIENT
            .request(request)
            .await
            .map_err(PutError::Transport)?;
        let status = response.status().as_u16();
        // Drain (bounded) so the connection returns to the pool cleanly; the body
        // content is never read.
        let _ = Limited::new(response.into_body(), MAX_PUT_RESPONSE_BYTES)
            .collect()
            .await;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(PutError::Status(status))
        }
    };
    match tokio::time::timeout(PUT_ATTEMPT_TIMEOUT, attempt).await {
        Ok(result) => result,
        Err(_elapsed) => Err(PutError::TimedOut),
    }
}

/// Why one upload attempt failed. Each is retried until the attempt budget is spent.
#[derive(Debug, thiserror::Error)]
enum PutError {
    #[error("building the upload request failed: {0}")]
    Request(hyper::http::Error),
    #[error("the upload transport failed: {0}")]
    Transport(hyper_util::client::legacy::Error),
    #[error("the object store returned status {0}")]
    Status(u16),
    #[error("the upload attempt timed out")]
    TimedOut,
}
