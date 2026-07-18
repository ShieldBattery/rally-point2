//! Signed `POST /session/create` — the app-server request that stands up a
//! session, exactly as the coordinator's inbound-request contract expects it.
//!
//! Built on hyper + hyper-util directly (the same stack the coordinator's own
//! outbound webhook client uses) rather than pulling in a heavier HTTP client.
//! The connector handles both `https://` (a staging/prod coordinator, which
//! terminates TLS itself via in-process ACME) and `http://` (a loopback dev
//! coordinator), mirroring the coordinator's own webhook client
//! (`coordinator::notify::WEBHOOK_CLIENT`). A `202 provisioning` hold is
//! handled by re-sending the identical body after the response's
//! `retry_after_ms` (idempotent on the request's `external_id`), signing fresh
//! each attempt so the replay-window check passes.

use std::time::Instant;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use rally_point_proto::control::SessionResponse;
use ring::signature::Ed25519KeyPair;
use serde::Deserialize;

use crate::signing::{self, SIGNATURE_HEADER, TIMESTAMP_HEADER};

/// The path a session create is signed for and sent to.
const SESSION_CREATE_PATH: &str = "/session/create";
/// A ceiling on provisioning re-sends, so a coordinator that never places the
/// request cannot hold a session task forever.
const MAX_PROVISIONING_HOLDS: u64 = 60;

/// The shared HTTP client the harness posts creates on. Negotiates rustls
/// (ring provider, webpki public-CA roots) for an `https://` coordinator URL
/// and falls through to plain HTTP for `http://` (the loopback dev flow) —
/// the same connector configuration as the coordinator's own webhook client.
pub type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Builds the shared create client.
pub fn build_client() -> HttpClient {
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(hyper_util::rt::TokioExecutor::new()).build(https)
}

/// The outcome of a create attempt.
pub enum CreateOutcome {
    /// The coordinator minted (or idempotently replayed) the session.
    Created {
        response: SessionResponse,
        /// Wall time from the first send to the `200`, including any holds.
        latency_us: u64,
        /// How many `202 provisioning` holds were waited out.
        provisioning_holds: u64,
    },
    /// The create failed: an HTTP error status, or (with `None`) a transport
    /// failure below HTTP.
    Failed { status: Option<u16> },
}

/// The `202 provisioning` body shape — only the retry delay is needed. The
/// coordinator serializes this camelCase (`retryAfterMs`), so the rename must
/// match or the delay silently deserializes to the default and the retry loop
/// spins through its hold ceiling with ~no waiting between attempts.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProvisioningResponse {
    #[serde(default)]
    retry_after_ms: u64,
}

/// Sends a signed create for `body` and drives it to a terminal outcome,
/// re-sending across provisioning holds.
pub async fn create_session(
    client: &HttpClient,
    coordinator_url: &str,
    signing_key: &Ed25519KeyPair,
    body: Bytes,
) -> CreateOutcome {
    let base = coordinator_url.trim_end_matches('/');
    let url = format!("{base}{SESSION_CREATE_PATH}");
    let started = Instant::now();
    let mut provisioning_holds = 0;

    loop {
        let (timestamp, signature) =
            signing::sign_request(signing_key, "POST", SESSION_CREATE_PATH, &body);
        let request = match Request::builder()
            .method("POST")
            .uri(&url)
            .header("content-type", "application/json")
            .header(TIMESTAMP_HEADER, timestamp)
            .header(SIGNATURE_HEADER, signature)
            .body(Full::new(body.clone()))
        {
            Ok(request) => request,
            Err(err) => {
                tracing::error!(error = %err, "building the create request failed");
                return CreateOutcome::Failed { status: None };
            }
        };

        let response = match client.request(request).await {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(error = %err, "session create transport error");
                return CreateOutcome::Failed { status: None };
            }
        };

        let status = response.status();
        let bytes = match response.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(err) => {
                tracing::warn!(error = %err, "reading the create response body failed");
                return CreateOutcome::Failed { status: None };
            }
        };

        if status.as_u16() == 200 {
            match serde_json::from_slice::<SessionResponse>(&bytes) {
                Ok(response) => {
                    return CreateOutcome::Created {
                        response,
                        latency_us: started.elapsed().as_micros() as u64,
                        provisioning_holds,
                    };
                }
                Err(err) => {
                    tracing::warn!(error = %err, "session response did not parse");
                    return CreateOutcome::Failed { status: Some(200) };
                }
            }
        }

        if status.as_u16() == 202 {
            provisioning_holds += 1;
            if provisioning_holds > MAX_PROVISIONING_HOLDS {
                tracing::warn!("session create held past the provisioning retry ceiling");
                return CreateOutcome::Failed { status: Some(202) };
            }
            let retry_after_ms = serde_json::from_slice::<ProvisioningResponse>(&bytes)
                .map(|body| body.retry_after_ms)
                .unwrap_or(500);
            tokio::time::sleep(std::time::Duration::from_millis(retry_after_ms.max(1))).await;
            continue;
        }

        tracing::warn!(status = status.as_u16(), "session create rejected");
        return CreateOutcome::Failed {
            status: Some(status.as_u16()),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_provisioning_body_parses_the_coordinators_camel_case_delay() {
        let body = br#"{"status":"provisioning","regions":["loop-a"],"retryAfterMs":2000}"#;
        let parsed: ProvisioningResponse = serde_json::from_slice(body).unwrap();
        assert_eq!(parsed.retry_after_ms, 2000);
    }
}
