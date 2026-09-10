//! The real [`FlightStore`] implementation: a thin wrapper over the S3 SDK client
//! pointed at the configured DigitalOcean Spaces bucket. Every method here is glue
//! with no logic a unit test would cover (except presigning, which is an offline
//! signature computation exercised directly in [`tests`](super::tests)).

use super::config::ResolvedFlightStore;
use super::{
    FlightStore, FlightStoreError, MAX_FLIGHT_BLOB_BYTES, ObjectInfo, PRESIGNED_PUT_EXPIRY,
};

/// How long [`S3FlightStore::connect`] waits for its startup reachability probe
/// before treating the bucket as unreachable. Generous against ordinary S3-API
/// latency, but still bounded — a hung probe must not hang coordinator startup
/// indefinitely.
const CONNECT_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The real [`FlightStore`]: a thin wrapper over an S3 SDK client pointed at the
/// configured Spaces bucket. Built once at startup by [`connect`](Self::connect).
pub struct S3FlightStore {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3FlightStore {
    /// Builds the store's S3 client from resolved config and probes the bucket
    /// before returning, so a misconfiguration (wrong bucket name, wrong region,
    /// bad credentials) fails coordinator startup loudly instead of surfacing only
    /// on the first shipped recording — where a failed `put` is just a logged loss
    /// (see [`crate::flight_store`]'s module docs). The HTTPS connector is pinned
    /// to the rustls **ring** provider, matching the workspace's single crypto
    /// backend (no aws-lc-rs). Credentials are the static access/secret pair the
    /// config resolved; the endpoint and region point the SigV4 signer at the
    /// Spaces bucket (Spaces accepts `us-east-1` as the signing region).
    pub async fn connect(resolved: ResolvedFlightStore) -> Result<Self, FlightStoreError> {
        let store = Self::build(resolved).await;
        match tokio::time::timeout(CONNECT_PROBE_TIMEOUT, store.probe_bucket()).await {
            Ok(Ok(())) => Ok(store),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(FlightStoreError(format!(
                "probing bucket {:?} timed out after {:?}",
                store.bucket, CONNECT_PROBE_TIMEOUT
            ))),
        }
    }

    /// Builds the S3 client + store from resolved config **without** the startup
    /// reachability probe. [`connect`](Self::connect) wraps this with the probe;
    /// presign-shape tests (in the sibling `tests` module) use it directly, since
    /// presigning is an offline signature computation that needs no reachable bucket —
    /// hence `pub(super)` rather than private.
    pub(super) async fn build(resolved: ResolvedFlightStore) -> Self {
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https();
        let credentials = aws_sdk_s3::config::Credentials::new(
            resolved.access_key,
            resolved.secret_key,
            None,
            None,
            "FlightStoreConfig",
        );
        let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(resolved.region))
            .http_client(http)
            .credentials_provider(credentials)
            .endpoint_url(resolved.endpoint)
            .load()
            .await;
        // Some S3-compatible stores reject the SDK's default unsolicited
        // flexible-checksum request headers, so checksums are calculated and validated
        // only when an operation actually requires one.
        let config = aws_sdk_s3::config::Builder::from(&shared)
            .request_checksum_calculation(
                aws_sdk_s3::config::RequestChecksumCalculation::WhenRequired,
            )
            .response_checksum_validation(
                aws_sdk_s3::config::ResponseChecksumValidation::WhenRequired,
            )
            .build();
        Self {
            client: aws_sdk_s3::Client::from_conf(config),
            bucket: resolved.bucket,
        }
    }

    /// Presigns a PUT to `key` for exactly `content_length` bytes, returning the URL a
    /// relay uploads a compressed recording to. The byte count is signed into the URL,
    /// so the granted URL can store neither a different object (the key is fixed) nor a
    /// different size; the URL expires in [`PRESIGNED_PUT_EXPIRY`]. No network
    /// round-trip — the signature is computed locally from the client's credentials and
    /// endpoint.
    pub async fn presign_put(
        &self,
        key: &str,
        content_length: u64,
    ) -> Result<String, FlightStoreError> {
        use aws_sdk_s3::error::DisplayErrorContext;
        let config = aws_sdk_s3::presigning::PresigningConfig::expires_in(PRESIGNED_PUT_EXPIRY)
            .map_err(|error| FlightStoreError(format!("building presigning config: {error}")))?;
        let presigned = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_length(content_length as i64)
            .presigned(config)
            .await
            .map_err(|error| FlightStoreError(format!("{}", DisplayErrorContext(&error))))?;
        Ok(presigned.uri().to_string())
    }

    /// Confirms the configured bucket is reachable and addressable with the
    /// resolved credentials — a `HeadBucket` call, cheap and side-effect-free,
    /// unlike a probe `put`/`get` which would leave (or require) an object. Wrapped
    /// in a timeout by [`connect`](Self::connect) so a hung backend cannot hang
    /// startup indefinitely.
    async fn probe_bucket(&self) -> Result<(), FlightStoreError> {
        use aws_sdk_s3::error::DisplayErrorContext;
        self.client
            .head_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .map(|_| ())
            .map_err(|error| FlightStoreError(format!("{}", DisplayErrorContext(&error))))
    }
}

impl FlightStore for S3FlightStore {
    async fn put(&self, key: &str, body: Vec<u8>) -> Result<(), FlightStoreError> {
        use aws_sdk_s3::error::DisplayErrorContext;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(aws_sdk_s3::primitives::ByteStream::from(body))
            .content_type("application/json")
            .send()
            .await
            .map_err(|error| FlightStoreError(format!("{}", DisplayErrorContext(&error))))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, FlightStoreError> {
        use aws_sdk_s3::error::DisplayErrorContext;
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(output) => {
                // Every write this module makes is gated at `MAX_FLIGHT_BLOB_BYTES` by
                // `classify_ingest`, so a well-formed object never exceeds it. Reading
                // the body still walks it chunk-by-chunk with a running cap, rather
                // than collecting it whole, so a bucket object outside that
                // invariant — corrupted, or written by something other than this
                // module — can't be read into an unbounded in-memory buffer.
                let mut body = output.body;
                let mut bytes = Vec::new();
                while let Some(chunk) = body.try_next().await.map_err(|error| {
                    FlightStoreError(format!("reading flight blob body: {error}"))
                })? {
                    bytes.extend_from_slice(&chunk);
                    if bytes.len() > MAX_FLIGHT_BLOB_BYTES {
                        return Err(FlightStoreError(format!(
                            "flight blob at {key:?} exceeds the \
                             {MAX_FLIGHT_BLOB_BYTES}-byte read cap"
                        )));
                    }
                }
                Ok(Some(bytes))
            }
            Err(error) => {
                let service_error = error.into_service_error();
                if service_error.is_no_such_key() {
                    Ok(None)
                } else {
                    Err(FlightStoreError(format!(
                        "{}",
                        DisplayErrorContext(&service_error)
                    )))
                }
            }
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectInfo>, FlightStoreError> {
        use aws_sdk_s3::error::DisplayErrorContext;
        let mut objects = Vec::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix);
            if let Some(token) = continuation {
                request = request.continuation_token(token);
            }
            let output = request
                .send()
                .await
                .map_err(|error| FlightStoreError(format!("{}", DisplayErrorContext(&error))))?;
            for object in output.contents() {
                let Some(key) = object.key() else { continue };
                objects.push(ObjectInfo {
                    key: key.to_owned(),
                    size: object
                        .size()
                        .and_then(|s| u64::try_from(s).ok())
                        .unwrap_or(0),
                    last_modified_ms: object
                        .last_modified()
                        .and_then(|dt| dt.to_millis().ok())
                        .unwrap_or(0),
                });
            }
            match output.next_continuation_token() {
                Some(token) if output.is_truncated().unwrap_or(false) => {
                    continuation = Some(token.to_owned());
                }
                _ => break,
            }
        }
        Ok(objects)
    }

    async fn copy(&self, from: &str, to: &str) -> Result<(), FlightStoreError> {
        use aws_sdk_s3::error::DisplayErrorContext;
        // The copy source is `<bucket>/<key>`; the keys this module writes are ASCII
        // and path-safe, so no additional encoding is needed.
        let source = format!("{}/{}", self.bucket, from);
        self.client
            .copy_object()
            .bucket(&self.bucket)
            .key(to)
            .copy_source(source)
            .send()
            .await
            .map_err(|error| FlightStoreError(format!("{}", DisplayErrorContext(&error))))?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), FlightStoreError> {
        use aws_sdk_s3::error::DisplayErrorContext;
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|error| FlightStoreError(format!("{}", DisplayErrorContext(&error))))?;
        Ok(())
    }
}
