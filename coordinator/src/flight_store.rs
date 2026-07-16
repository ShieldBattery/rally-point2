//! Flight-recording durable sink: the coordinator's DigitalOcean Spaces (S3-API)
//! store for the observability blobs relays ship up their control connections, plus
//! the tenant-authenticated read path over them.
//!
//! A relay holds no object-store credentials; it ships each flushed recording as a
//! [`FlightRecordingNotice`](rally_point_proto::control::FlightRecordingNotice) up
//! its control connection, and the coordinator — the sole credential holder — is what
//! persists it. Blobs are keyed under one of two retention-selecting prefixes,
//! [`FLIGHT_PREFIX`] (the normal class) and [`DESYNC_PREFIX`] (the pinned class),
//! each `<prefix>/<tenant>/<session>/<relay_id>.json`. The bucket's own lifecycle
//! rules expire the two prefixes on different schedules, which is why the retention
//! class is a key prefix rather than object metadata: an S3-compatible store filters
//! a lifecycle rule by key prefix, not by tag, and the two prefixes are disjoint by
//! construction. The tenant-first shape inside each prefix is the read-authorization
//! hook — a read only ever names blobs under the tenant its request signature
//! authenticates as, and the key's relay id is the coordinator's own enrolled id for
//! the shipping connection, so a relay can never write (or a reader reach) under
//! another identity.
//!
//! # Config and secrets
//!
//! The store is configured by a JSON file ([`FlightStoreConfig`]) naming the
//! endpoint, region, bucket, and — like the tenant registry — the NAMES of the
//! environment variables holding the access and secret keys, never the keys
//! themselves. [`from_json`] parses and validates the file without touching the
//! environment; [`FlightStoreConfig::resolve_secrets`] then reads the two named
//! variables (failing closed if either is unset or empty), and
//! [`S3FlightStore::connect`] builds the S3 client from the result.
//!
//! # Testability
//!
//! Every storage decision runs against the [`FlightStore`] trait, so the ingest and
//! read logic is exercised against an in-memory fake with no live object store; the
//! [`S3FlightStore`] SDK wrapper is the only part a unit test does not cover.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId};
use serde::Deserialize;

/// The key prefix for the normal retention class — the bucket lifecycle expires it on
/// the shorter schedule. Disjoint from [`DESYNC_PREFIX`] by construction.
pub const FLIGHT_PREFIX: &str = "flight";
/// The key prefix for the pinned (desynced-session) retention class — the bucket
/// lifecycle expires it on the longer schedule, so a diverged game's recordings
/// survive long enough to adjudicate.
pub const DESYNC_PREFIX: &str = "desync";

/// The largest recording payload the coordinator will store: a defense-in-depth
/// backstop behind the relay's own ship-side cap. A recording over this is dropped
/// rather than uploaded, bounding what a misbehaving relay build can push into the
/// store.
pub const MAX_FLIGHT_BLOB_BYTES: usize = 4 * 1024 * 1024;

/// One stored object as [`FlightStore::list`] reports it: its full key, byte size,
/// and last-modified time in unix-epoch milliseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    /// The object's full key, including its retention prefix.
    pub key: String,
    /// The object's size in bytes.
    pub size: u64,
    /// The object's last-modified time, unix-epoch milliseconds.
    pub last_modified_ms: i64,
}

/// An object-store operation failed. Wraps the backend's message for the operator
/// log; the coordinator never branches on the cause (a failed store is a logged
/// loss, a failed read a `500`), so one opaque variant is enough.
#[derive(Debug, thiserror::Error)]
#[error("flight store operation failed: {0}")]
pub struct FlightStoreError(String);

/// The object-store operations the flight sink drives, behind a trait so the ingest
/// and read logic is testable against an in-memory fake. The real implementation
/// ([`S3FlightStore`]) is a thin wrapper over the S3 SDK client — every method there
/// is glue with no logic a unit test would cover.
pub trait FlightStore: Send + Sync {
    /// Stores `body` at `key` with a JSON content type, overwriting any existing
    /// object. Delivery is at-least-once, so a re-shipped recording idempotently
    /// overwrites its own key.
    fn put(
        &self,
        key: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<(), FlightStoreError>> + Send;

    /// Reads the object at `key`, or `None` when no such object exists.
    fn get(
        &self,
        key: &str,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, FlightStoreError>> + Send;

    /// Lists every object whose key starts with `prefix`.
    fn list(
        &self,
        prefix: &str,
    ) -> impl Future<Output = Result<Vec<ObjectInfo>, FlightStoreError>> + Send;

    /// Copies the object at `from` to `to`, overwriting any object already at `to`.
    fn copy(
        &self,
        from: &str,
        to: &str,
    ) -> impl Future<Output = Result<(), FlightStoreError>> + Send;

    /// Deletes the object at `key`; deleting an absent key is a success.
    fn delete(&self, key: &str) -> impl Future<Output = Result<(), FlightStoreError>> + Send;
}

/// The retention prefix a recording's pinned-ness selects.
fn prefix_for(pinned: bool) -> &'static str {
    if pinned { DESYNC_PREFIX } else { FLIGHT_PREFIX }
}

/// Builds the object key for one relay's recording of one session: the
/// retention-selecting prefix ([`DESYNC_PREFIX`] when `pinned`, else [`FLIGHT_PREFIX`])
/// followed by the ratified `<tenant>/<session>/<relay_id>.json` inner shape.
/// `relay_id` is the coordinator's own enrolled id for the shipping connection, never
/// a relay-supplied value.
pub fn object_key(
    pinned: bool,
    tenant: &TenantId,
    session: SessionId,
    relay_id: RelayId,
) -> String {
    format!(
        "{}/{}/{}/{}.json",
        prefix_for(pinned),
        tenant.as_ref(),
        session.0,
        relay_id.0,
    )
}

/// Builds the key prefix covering every relay's recording of one session under one
/// retention class — the argument to [`FlightStore::list`] when enumerating a
/// session's blobs. Trailing slash included so it matches only that session's keys,
/// never a sibling session whose id shares a numeric prefix.
pub fn session_prefix(pinned: bool, tenant: &TenantId, session: SessionId) -> String {
    format!("{}/{}/{}/", prefix_for(pinned), tenant.as_ref(), session.0,)
}

/// Recovers the relay id from a stored object key by reading its final
/// `<relay_id>.json` segment. `None` for a key whose last segment is not
/// `<digits>.json` — a defensive skip for any object that does not match the shape
/// this module writes.
fn relay_id_from_key(key: &str) -> Option<u64> {
    key.rsplit('/')
        .next()
        .and_then(|name| name.strip_suffix(".json"))
        .and_then(|digits| digits.parse::<u64>().ok())
}

/// Whether a tenant id is safe to embed verbatim as one path segment of an object
/// key: ASCII alphanumerics plus `.`, `_`, and `-`. Tenant ids come from the
/// coordinator's own registry, which bounds only their length — but a key is the one
/// place a stray `/` would change meaning (an id shaped `a/7` would alias tenant
/// `a`'s session-`7` key space, crossing the tenant-first read-authorization
/// boundary). The store therefore **refuses** an id it cannot embed verbatim rather
/// than reshaping it: substitution could collide two distinct ids into one key space,
/// which is worse than storing nothing.
pub fn tenant_key_safe(tenant: &TenantId) -> bool {
    !tenant.as_ref().is_empty()
        && tenant
            .as_ref()
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Why an inbound flight recording is dropped rather than stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlightDrop {
    /// No store is configured — the coordinator was started without `--flight-store`,
    /// so a relay shipping recordings has nowhere to put them.
    NoStore,
    /// The notice names a tenant the coordinator does not hold enrolled.
    UnknownTenant,
    /// The tenant's id cannot be embedded verbatim as an object-key path segment
    /// (see [`tenant_key_safe`]) — such a tenant's recordings are never stored.
    TenantIdNotKeySafe,
    /// The payload exceeds [`MAX_FLIGHT_BLOB_BYTES`].
    TooLarge,
}

/// Applies the ingest gates to an inbound recording, returning `Ok(())` when it
/// should be stored or the reason to drop it. The gates run store-first (an
/// unconfigured store drops everything), then tenant existence, then tenant id key
/// safety, then size — the order that surfaces the operator's most fundamental
/// omission first.
pub fn classify_ingest(
    store_configured: bool,
    tenant_known: bool,
    tenant: &TenantId,
    payload_len: usize,
) -> Result<(), FlightDrop> {
    if !store_configured {
        return Err(FlightDrop::NoStore);
    }
    if !tenant_known {
        return Err(FlightDrop::UnknownTenant);
    }
    if !tenant_key_safe(tenant) {
        return Err(FlightDrop::TenantIdNotKeySafe);
    }
    if payload_len > MAX_FLIGHT_BLOB_BYTES {
        return Err(FlightDrop::TooLarge);
    }
    Ok(())
}

/// Stores one relay's recording under the retention class `pinned` selects, then —
/// when pinned — converges any of the session's blobs already sitting under the
/// normal [`FLIGHT_PREFIX`] into the pinned [`DESYNC_PREFIX`].
///
/// The convergence sweep covers the race where a session's non-authority relays ship
/// their (undesynced) recordings and land under `flight/` before the coordinator
/// learns the authority relay flagged a desync — a coordinator restart can reorder
/// the two, since the blob arrival and the desync notice travel separate channels.
/// Sweeping on every pinned store moves those earlier blobs into the retention class
/// the diverged game needs. It is idempotent (usually an empty list), and safe under
/// concurrent pinned stores of the same session — each blob simply ends up pinned.
pub async fn store_recording<S: FlightStore>(
    store: &S,
    tenant: &TenantId,
    session: SessionId,
    relay_id: RelayId,
    payload: Vec<u8>,
    pinned: bool,
) -> Result<(), FlightStoreError> {
    store
        .put(&object_key(pinned, tenant, session, relay_id), payload)
        .await?;
    if pinned {
        pin_session(store, tenant, session).await?;
    }
    Ok(())
}

/// Moves every object under a session's [`FLIGHT_PREFIX`] to its [`DESYNC_PREFIX`]
/// twin (copy then delete), converging blobs stored before the desync was known into
/// the pinned retention class. A blob's twin is the same key with the prefix swapped,
/// so the move preserves the `<tenant>/<session>/<relay_id>.json` shape.
async fn pin_session<S: FlightStore>(
    store: &S,
    tenant: &TenantId,
    session: SessionId,
) -> Result<(), FlightStoreError> {
    let flight_prefix = format!("{FLIGHT_PREFIX}/");
    for object in store.list(&session_prefix(false, tenant, session)).await? {
        let Some(rest) = object.key.strip_prefix(&flight_prefix) else {
            continue;
        };
        let dest = format!("{DESYNC_PREFIX}/{rest}");
        store.copy(&object.key, &dest).await?;
        store.delete(&object.key).await?;
    }
    Ok(())
}

/// One blob in a session's flight-recording listing: the relay that produced it,
/// whether it is pinned (in the [`DESYNC_PREFIX`] retention class), and its size and
/// last-modified stamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingListing {
    /// The relay whose recording this is (the key's final segment).
    pub relay_id: u64,
    /// Whether the blob is in the pinned (desynced) retention class.
    pub pinned: bool,
    /// The blob's size in bytes.
    pub size: u64,
    /// The blob's last-modified time, unix-epoch milliseconds.
    pub last_modified_ms: i64,
}

/// Lists a session's recordings across both retention prefixes, deduped by relay id
/// with the pinned copy winning when a relay's blob exists under both (the transient
/// state during a convergence sweep, or a store that has not yet deleted the moved
/// original). Ordered by relay id for a stable response.
pub async fn list_recordings<S: FlightStore>(
    store: &S,
    tenant: &TenantId,
    session: SessionId,
) -> Result<Vec<RecordingListing>, FlightStoreError> {
    let mut by_relay: BTreeMap<u64, RecordingListing> = BTreeMap::new();
    for object in store.list(&session_prefix(false, tenant, session)).await? {
        if let Some(relay_id) = relay_id_from_key(&object.key) {
            by_relay.entry(relay_id).or_insert(RecordingListing {
                relay_id,
                pinned: false,
                size: object.size,
                last_modified_ms: object.last_modified_ms,
            });
        }
    }
    for object in store.list(&session_prefix(true, tenant, session)).await? {
        if let Some(relay_id) = relay_id_from_key(&object.key) {
            by_relay.insert(
                relay_id,
                RecordingListing {
                    relay_id,
                    pinned: true,
                    size: object.size,
                    last_modified_ms: object.last_modified_ms,
                },
            );
        }
    }
    Ok(by_relay.into_values().collect())
}

/// Fetches one relay's recording of a session, preferring the pinned [`DESYNC_PREFIX`]
/// copy over the normal [`FLIGHT_PREFIX`] one (they carry the same bytes when both
/// exist, but the pinned one is the surviving copy after a convergence sweep). `None`
/// when neither exists.
pub async fn fetch_recording<S: FlightStore>(
    store: &S,
    tenant: &TenantId,
    session: SessionId,
    relay_id: RelayId,
) -> Result<Option<Vec<u8>>, FlightStoreError> {
    if let Some(bytes) = store
        .get(&object_key(true, tenant, session, relay_id))
        .await?
    {
        return Ok(Some(bytes));
    }
    store
        .get(&object_key(false, tenant, session, relay_id))
        .await
}

/// A validated flight-store configuration: where the bucket lives and the NAMES of the
/// environment variables its credentials are read from. Parsed by [`from_json`]
/// without touching the environment; the credential variables are resolved later by
/// [`resolve_secrets`](Self::resolve_secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlightStoreConfig {
    /// The bucket's S3 endpoint (e.g. `https://nyc3.digitaloceanspaces.com`).
    endpoint: String,
    /// The region the SigV4 signer stamps. Spaces accepts `us-east-1`.
    region: String,
    /// The bucket recordings are stored in.
    bucket: String,
    /// The NAME of the environment variable holding the access key id.
    access_key_env: String,
    /// The NAME of the environment variable holding the secret access key.
    secret_key_env: String,
}

/// The wire shape of the config file, before validation. camelCase keys, and unknown
/// fields rejected so a typo surfaces as a startup error rather than a silently
/// ignored setting.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FlightStoreConfigRaw {
    endpoint: String,
    region: String,
    bucket: String,
    access_key_env: String,
    secret_key_env: String,
}

/// Why a flight-store config could not be loaded or resolved. Every variant fails
/// coordinator startup: a coordinator told to persist recordings but unable to reach
/// its store must not run, exactly like a malformed tenant registry.
#[derive(Debug, thiserror::Error)]
pub enum FlightStoreConfigError {
    /// The config file could not be read.
    #[error("reading flight store config {path}: {source}")]
    Read {
        /// The path that failed to read.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The file was not valid JSON in the expected shape (a bad type, a missing
    /// required field, or an unknown field).
    #[error("parsing flight store config JSON")]
    Parse(#[from] serde_json::Error),
    /// A required config field is empty.
    #[error("flight store config field {field} is empty")]
    EmptyField {
        /// The name of the empty field.
        field: &'static str,
    },
    /// A named credential environment variable is unset or empty. A store the
    /// coordinator cannot authenticate to must fail startup rather than silently drop
    /// every recording.
    #[error("flight store {which} env var {env:?} is unset or empty")]
    MissingEnv {
        /// Which credential the variable holds (`access-key` or `secret-key`).
        which: &'static str,
        /// The environment-variable name that was unset or empty.
        env: String,
    },
}

/// Loads and validates a flight-store config from the JSON file at `path`, without
/// reading any environment variable. [`FlightStoreConfig::resolve_secrets`] does the
/// environment resolution.
pub fn load(path: &Path) -> Result<FlightStoreConfig, FlightStoreConfigError> {
    let contents =
        std::fs::read_to_string(path).map_err(|source| FlightStoreConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
    from_json(&contents)
}

/// Parses and validates a flight-store config from a JSON string — the testable core
/// of [`load`]. Rejects an empty required field, but reads no environment: the
/// credentials are named here, not resolved.
pub fn from_json(json: &str) -> Result<FlightStoreConfig, FlightStoreConfigError> {
    let raw: FlightStoreConfigRaw = serde_json::from_str(json)?;
    Ok(FlightStoreConfig {
        endpoint: require_non_empty(raw.endpoint, "endpoint")?,
        region: require_non_empty(raw.region, "region")?,
        bucket: require_non_empty(raw.bucket, "bucket")?,
        access_key_env: require_non_empty(raw.access_key_env, "accessKeyEnv")?,
        secret_key_env: require_non_empty(raw.secret_key_env, "secretKeyEnv")?,
    })
}

/// Returns `value` when it holds a non-whitespace character, else an
/// [`FlightStoreConfigError::EmptyField`] naming `field`.
fn require_non_empty(value: String, field: &'static str) -> Result<String, FlightStoreConfigError> {
    if value.trim().is_empty() {
        Err(FlightStoreConfigError::EmptyField { field })
    } else {
        Ok(value)
    }
}

impl FlightStoreConfig {
    /// Resolves the access and secret keys from the environment (through `lookup_env`,
    /// so the binary passes `|name| std::env::var(name).ok()` and tests inject their
    /// own), failing closed if either variable is unset or empty. Returns the material
    /// [`S3FlightStore::connect`] builds a client from; reads no environment of its
    /// own beyond `lookup_env`.
    pub fn resolve_secrets(
        &self,
        lookup_env: impl Fn(&str) -> Option<String>,
    ) -> Result<ResolvedFlightStore, FlightStoreConfigError> {
        let access_key = resolve_env(&lookup_env, &self.access_key_env, "access-key")?;
        let secret_key = resolve_env(&lookup_env, &self.secret_key_env, "secret-key")?;
        Ok(ResolvedFlightStore {
            endpoint: self.endpoint.clone(),
            region: self.region.clone(),
            bucket: self.bucket.clone(),
            access_key,
            secret_key,
        })
    }
}

/// Reads `env` through `lookup_env`, trimming it and treating an empty or
/// whitespace-only value as absent — the same fail-closed rule the tenant registry
/// applies to a signing-key variable.
fn resolve_env(
    lookup_env: &impl Fn(&str) -> Option<String>,
    env: &str,
    which: &'static str,
) -> Result<String, FlightStoreConfigError> {
    lookup_env(env)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FlightStoreConfigError::MissingEnv {
            which,
            env: env.to_owned(),
        })
}

/// A flight-store config with its credentials resolved from the environment — the
/// input to [`S3FlightStore::connect`]. Holds the secret access key in memory (the
/// coordinator is the sole credential holder by design), so it deliberately derives
/// no `Debug` that could log it.
pub struct ResolvedFlightStore {
    endpoint: String,
    region: String,
    bucket: String,
    access_key: String,
    secret_key: String,
}

/// The real [`FlightStore`]: a thin wrapper over an S3 SDK client pointed at the
/// configured Spaces bucket. Built once at startup by [`connect`](Self::connect).
pub struct S3FlightStore {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3FlightStore {
    /// Builds the store's S3 client from resolved config. The HTTPS connector is
    /// pinned to the rustls **ring** provider, matching the workspace's single crypto
    /// backend (no aws-lc-rs). Credentials are the static access/secret pair the config
    /// resolved; the endpoint and region point the SigV4 signer at the Spaces bucket
    /// (Spaces accepts `us-east-1` as the signing region).
    pub async fn connect(resolved: ResolvedFlightStore) -> Self {
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
                let bytes = output
                    .body
                    .collect()
                    .await
                    .map_err(|error| {
                        FlightStoreError(format!("reading flight blob body: {error}"))
                    })?
                    .into_bytes()
                    .to_vec();
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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use parking_lot::Mutex;

    use super::*;

    /// An in-memory [`FlightStore`]: a keyed map of stored objects, so the ingest and
    /// read logic runs with no live object store. Keys are ordered, so
    /// [`keys`](Self::keys) and any list are deterministic.
    #[derive(Default)]
    struct FakeFlightStore {
        objects: Mutex<BTreeMap<String, StoredObject>>,
    }

    #[derive(Clone)]
    struct StoredObject {
        body: Vec<u8>,
        last_modified_ms: i64,
    }

    impl FakeFlightStore {
        fn new() -> Self {
            Self::default()
        }

        fn keys(&self) -> Vec<String> {
            self.objects.lock().keys().cloned().collect()
        }

        fn contains(&self, key: &str) -> bool {
            self.objects.lock().contains_key(key)
        }
    }

    impl FlightStore for FakeFlightStore {
        async fn put(&self, key: &str, body: Vec<u8>) -> Result<(), FlightStoreError> {
            self.objects.lock().insert(
                key.to_owned(),
                StoredObject {
                    body,
                    last_modified_ms: 1,
                },
            );
            Ok(())
        }

        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, FlightStoreError> {
            Ok(self
                .objects
                .lock()
                .get(key)
                .map(|object| object.body.clone()))
        }

        async fn list(&self, prefix: &str) -> Result<Vec<ObjectInfo>, FlightStoreError> {
            Ok(self
                .objects
                .lock()
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, object)| ObjectInfo {
                    key: key.clone(),
                    size: object.body.len() as u64,
                    last_modified_ms: object.last_modified_ms,
                })
                .collect())
        }

        async fn copy(&self, from: &str, to: &str) -> Result<(), FlightStoreError> {
            let mut objects = self.objects.lock();
            match objects.get(from).cloned() {
                Some(object) => {
                    objects.insert(to.to_owned(), object);
                    Ok(())
                }
                None => Err(FlightStoreError(format!("copy source not found: {from}"))),
            }
        }

        async fn delete(&self, key: &str) -> Result<(), FlightStoreError> {
            self.objects.lock().remove(key);
            Ok(())
        }
    }

    fn tenant() -> TenantId {
        TenantId("sb-test".to_owned())
    }

    #[test]
    fn object_key_selects_the_prefix_and_preserves_the_tenant_first_shape() {
        assert_eq!(
            object_key(false, &tenant(), SessionId(7), RelayId(3)),
            "flight/sb-test/7/3.json",
        );
        assert_eq!(
            object_key(true, &tenant(), SessionId(7), RelayId(3)),
            "desync/sb-test/7/3.json",
        );
    }

    #[test]
    fn classify_ingest_gates_store_then_tenant_then_key_safety_then_size() {
        assert_eq!(
            classify_ingest(false, true, &tenant(), 0),
            Err(FlightDrop::NoStore)
        );
        assert_eq!(
            classify_ingest(true, false, &tenant(), 0),
            Err(FlightDrop::UnknownTenant)
        );
        assert_eq!(
            classify_ingest(true, true, &TenantId("a/7".to_owned()), 0),
            Err(FlightDrop::TenantIdNotKeySafe),
        );
        assert_eq!(
            classify_ingest(true, true, &tenant(), MAX_FLIGHT_BLOB_BYTES + 1),
            Err(FlightDrop::TooLarge),
        );
        assert_eq!(
            classify_ingest(true, true, &tenant(), MAX_FLIGHT_BLOB_BYTES),
            Ok(())
        );
    }

    #[test]
    fn tenant_key_safety_admits_registry_style_ids_and_refuses_path_metacharacters() {
        for safe in ["shieldbattery", "tec27-dev", "a.b_c-1"] {
            assert!(tenant_key_safe(&TenantId(safe.to_owned())), "{safe}");
        }
        // A `/` would alias another tenant's key space; `..`-capable and non-ASCII
        // segments are refused wholesale rather than reasoned about case by case.
        for unsafe_id in ["", "a/7", "a/../b", "a b", "α", "a\\b"] {
            assert!(
                !tenant_key_safe(&TenantId(unsafe_id.to_owned())),
                "{unsafe_id:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_unpinned_recording_lands_under_the_flight_prefix() {
        let store = FakeFlightStore::new();
        store_recording(
            &store,
            &tenant(),
            SessionId(7),
            RelayId(3),
            b"{}".to_vec(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(store.keys(), vec!["flight/sb-test/7/3.json".to_owned()]);
    }

    #[tokio::test]
    async fn a_pinned_recording_lands_under_the_desync_prefix() {
        let store = FakeFlightStore::new();
        store_recording(
            &store,
            &tenant(),
            SessionId(7),
            RelayId(3),
            b"{}".to_vec(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(store.keys(), vec!["desync/sb-test/7/3.json".to_owned()]);
    }

    #[tokio::test]
    async fn a_late_pin_sweeps_an_earlier_flight_blob_into_the_desync_prefix() {
        let store = FakeFlightStore::new();
        // A non-authority relay's recording lands unpinned first.
        store_recording(
            &store,
            &tenant(),
            SessionId(7),
            RelayId(2),
            b"early".to_vec(),
            false,
        )
        .await
        .unwrap();
        // The authority relay's pinned recording arrives and converges the earlier one.
        store_recording(
            &store,
            &tenant(),
            SessionId(7),
            RelayId(3),
            b"late".to_vec(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            store.keys(),
            vec![
                "desync/sb-test/7/2.json".to_owned(),
                "desync/sb-test/7/3.json".to_owned(),
            ],
        );
        // The moved blob keeps its bytes, and its original is gone.
        assert_eq!(
            fetch_recording(&store, &tenant(), SessionId(7), RelayId(2))
                .await
                .unwrap(),
            Some(b"early".to_vec()),
        );
        assert!(!store.contains("flight/sb-test/7/2.json"));
    }

    #[tokio::test]
    async fn listing_merges_prefixes_and_pinned_wins_the_dedup() {
        let store = FakeFlightStore::new();
        // Relay 2 exists under BOTH prefixes (the transient sweep state); relay 3 only
        // under desync/, relay 4 only under flight/. Written directly so the pinned
        // store's own convergence sweep does not disturb the mixed state.
        store
            .put("flight/sb-test/7/2.json", b"a".to_vec())
            .await
            .unwrap();
        store
            .put("desync/sb-test/7/2.json", b"a".to_vec())
            .await
            .unwrap();
        store
            .put("desync/sb-test/7/3.json", b"bb".to_vec())
            .await
            .unwrap();
        store
            .put("flight/sb-test/7/4.json", b"c".to_vec())
            .await
            .unwrap();

        let listing = list_recordings(&store, &tenant(), SessionId(7))
            .await
            .unwrap();
        assert_eq!(
            listing.iter().map(|l| l.relay_id).collect::<Vec<_>>(),
            vec![2, 3, 4],
        );
        assert!(
            listing[0].pinned,
            "relay 2 exists under both prefixes -> pinned wins"
        );
        assert!(listing[1].pinned, "relay 3 is desync-only");
        assert!(!listing[2].pinned, "relay 4 is flight-only");
    }

    #[tokio::test]
    async fn listing_ignores_a_sibling_session_sharing_a_numeric_prefix() {
        let store = FakeFlightStore::new();
        store
            .put("flight/sb-test/7/1.json", b"a".to_vec())
            .await
            .unwrap();
        // Session 70's key shares the "7" numeric prefix; the trailing slash in the
        // session prefix keeps it out of session 7's listing.
        store
            .put("flight/sb-test/70/1.json", b"b".to_vec())
            .await
            .unwrap();

        let listing = list_recordings(&store, &tenant(), SessionId(7))
            .await
            .unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].relay_id, 1);
    }

    #[tokio::test]
    async fn fetch_prefers_the_pinned_copy_then_flight_then_none() {
        let store = FakeFlightStore::new();
        assert_eq!(
            fetch_recording(&store, &tenant(), SessionId(7), RelayId(3))
                .await
                .unwrap(),
            None,
        );
        store
            .put("flight/sb-test/7/3.json", b"flight".to_vec())
            .await
            .unwrap();
        assert_eq!(
            fetch_recording(&store, &tenant(), SessionId(7), RelayId(3))
                .await
                .unwrap(),
            Some(b"flight".to_vec()),
        );
        store
            .put("desync/sb-test/7/3.json", b"desync".to_vec())
            .await
            .unwrap();
        assert_eq!(
            fetch_recording(&store, &tenant(), SessionId(7), RelayId(3))
                .await
                .unwrap(),
            Some(b"desync".to_vec()),
            "the pinned copy is preferred over the flight copy",
        );
    }

    #[test]
    fn a_valid_config_parses() {
        let json = r#"{
            "endpoint": "https://nyc3.digitaloceanspaces.com",
            "region": "us-east-1",
            "bucket": "sb-rp2-flight",
            "accessKeyEnv": "FLIGHT_STORE_ACCESS_KEY",
            "secretKeyEnv": "FLIGHT_STORE_SECRET_KEY"
        }"#;
        let config = from_json(json).expect("a well-formed config parses");
        assert_eq!(config.bucket, "sb-rp2-flight");
        assert_eq!(config.access_key_env, "FLIGHT_STORE_ACCESS_KEY");
        assert_eq!(config.secret_key_env, "FLIGHT_STORE_SECRET_KEY");
    }

    #[test]
    fn an_empty_field_is_rejected_naming_the_field() {
        let json = r#"{
            "endpoint": "",
            "region": "us-east-1",
            "bucket": "b",
            "accessKeyEnv": "A",
            "secretKeyEnv": "S"
        }"#;
        assert!(matches!(
            from_json(json),
            Err(FlightStoreConfigError::EmptyField { field: "endpoint" }),
        ));
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        let json = r#"{
            "endpoint": "e",
            "region": "r",
            "bucket": "b",
            "accessKeyEnv": "A",
            "secretKeyEnv": "S",
            "extra": 1
        }"#;
        assert!(matches!(
            from_json(json),
            Err(FlightStoreConfigError::Parse(_))
        ));
    }

    #[test]
    fn resolving_secrets_fails_closed_on_a_missing_env_var() {
        let config = from_json(
            r#"{
                "endpoint": "e",
                "region": "r",
                "bucket": "b",
                "accessKeyEnv": "ACCESS",
                "secretKeyEnv": "SECRET"
            }"#,
        )
        .unwrap();

        // Access present, secret absent -> fails, naming the secret variable.
        let env: HashMap<&str, &str> = [("ACCESS", "id")].into_iter().collect();
        // `ResolvedFlightStore` deliberately carries no `Debug` (it holds the secret
        // key), so match each arm rather than debug-print the whole `Result`.
        match config.resolve_secrets(|name| env.get(name).map(|value| (*value).to_owned())) {
            Err(FlightStoreConfigError::MissingEnv { which, env }) => {
                assert_eq!(which, "secret-key");
                assert_eq!(env, "SECRET");
            }
            Err(other) => panic!("expected MissingEnv, got {other:?}"),
            Ok(_) => panic!("expected MissingEnv, got Ok"),
        }

        // Both present -> resolves.
        let env: HashMap<&str, &str> = [("ACCESS", "id"), ("SECRET", "key")].into_iter().collect();
        assert!(
            config
                .resolve_secrets(|name| env.get(name).map(|value| (*value).to_owned()))
                .is_ok(),
        );
    }
}
