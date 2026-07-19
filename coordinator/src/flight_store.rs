//! Flight-recording durable sink: the coordinator's DigitalOcean Spaces (S3-API)
//! store for the observability blobs relays record, plus the tenant-authenticated
//! read path over them.
//!
//! A relay holds no long-lived object-store credentials. It asks the coordinator — the
//! sole credential holder — for a presigned upload URL ([`S3FlightStore::presign_put`])
//! and PUTs each flushed recording, compressed, straight to storage itself; the blob
//! never rides the control connection. Blobs are keyed under one of two
//! retention-selecting prefixes, [`FLIGHT_PREFIX`] (the normal class) and
//! [`DESYNC_PREFIX`] (the pinned class), each
//! `<prefix>/<tenant>/<session>/<relay_id>.json.zst` (the `.zst` marks the
//! zstd-compressed-JSON encoding the relay uploads). The bucket's own lifecycle rules
//! expire the two prefixes on different schedules, which is why the retention class is
//! a key prefix rather than object metadata: an S3-compatible store filters a lifecycle
//! rule by key prefix, not by tag, and the two prefixes are disjoint by construction.
//! The tenant-first shape inside each prefix is the read-authorization hook — a read
//! only ever names blobs under the tenant its request signature authenticates as, and
//! the key's relay id is the coordinator's own enrolled id for the requesting
//! connection (never a relay-supplied value), so a relay can never upload (or a reader
//! reach) under another identity. A pinned-class store also converges the session's
//! already-stored unpinned blobs ([`pin_session`]).
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
use std::time::Duration;

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

/// The largest **compressed** recording the coordinator grants an upload for: a
/// defense-in-depth backstop behind the relay's own ship-side cap. A request whose
/// byte count exceeds this is refused (no upload URL minted), bounding what a
/// misbehaving relay build can push into the store. The byte count the request carries
/// is also bound into the presigned URL, so a granted upload cannot exceed it either.
pub const MAX_FLIGHT_BLOB_BYTES: usize = 4 * 1024 * 1024;

/// How long a minted presigned upload URL stays valid. Short: the relay uploads
/// promptly once its request is granted, and a long-lived URL widens the window for a
/// leaked grant to be reused — but long enough to absorb the relay's bounded upload
/// retries. Also the lifetime the coordinator keeps an outstanding grant awaiting its
/// done, since the URL is dead past this anyway.
pub const PRESIGNED_PUT_EXPIRY: Duration = Duration::from_secs(5 * 60);

/// How long [`S3FlightStore::connect`] waits for its startup reachability probe
/// before treating the bucket as unreachable. Generous against ordinary S3-API
/// latency, but still bounded — a hung probe must not hang coordinator startup
/// indefinitely.
const CONNECT_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

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
/// followed by the ratified `<tenant>/<session>/<relay_id>.json.zst` inner shape (the
/// `.zst` marks the zstd-compressed-JSON encoding the relay uploads). `relay_id` is the
/// coordinator's own enrolled id for the requesting connection, never a relay-supplied
/// value.
pub fn object_key(
    pinned: bool,
    tenant: &TenantId,
    session: SessionId,
    relay_id: RelayId,
) -> String {
    format!(
        "{}/{}/{}/{}.json.zst",
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
/// `<relay_id>.json.zst` segment. `None` for a key whose last segment is not
/// `<digits>.json.zst` — a defensive skip for any object that does not match the shape
/// this module writes.
fn relay_id_from_key(key: &str) -> Option<u64> {
    key.rsplit('/')
        .next()
        .and_then(|name| name.strip_suffix(".json.zst"))
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

/// The object key and retention class a granted flight upload will store under, decided
/// from an inbound upload request. The coordinator presigns a PUT to [`key`](Self::key)
/// and, once the relay reports the upload done, runs the pinned-class convergence
/// ([`pin_session`]) when [`pinned`](Self::pinned) is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlightUploadPlan {
    /// The full object key (retention prefix included) the upload stores under.
    pub key: String,
    /// Whether the recording lands in the pinned (desynced) retention class.
    pub pinned: bool,
}

/// Decides how to grant one inbound flight-upload request: run the ingest gates (a
/// configured store, a known and key-safe tenant, a byte count within the cap), and on
/// success return the object key + retention class the coordinator presigns an upload
/// for. `Err` is the reason to refuse the grant instead. `pinned` is the caller's
/// retention decision (the relay's own desync flag OR a coordinator desync mark);
/// `relay_id` is the connection's enrolled id, never a relay-supplied value.
pub fn plan_flight_upload(
    store_configured: bool,
    tenant_known: bool,
    tenant: &TenantId,
    session: SessionId,
    relay_id: RelayId,
    pinned: bool,
    bytes: u64,
) -> Result<FlightUploadPlan, FlightDrop> {
    classify_ingest(store_configured, tenant_known, tenant, bytes as usize)?;
    Ok(FlightUploadPlan {
        key: object_key(pinned, tenant, session, relay_id),
        pinned,
    })
}

/// Moves every object under a session's [`FLIGHT_PREFIX`] to its [`DESYNC_PREFIX`]
/// twin (copy then delete), converging blobs stored before the desync was known into
/// the pinned retention class. A blob's twin is the same key with the prefix swapped,
/// so the move preserves the `<tenant>/<session>/<relay_id>.json.zst` shape.
///
/// Run when a session's authority relay reports a *pinned* upload done: it covers the
/// race where the session's non-authority relays uploaded their (undesynced) recordings
/// under `flight/` before the coordinator learned of the desync — a coordinator restart
/// can reorder the two, since an upload's completion and the desync notice travel
/// separate channels. It is idempotent (usually an empty list), and safe under
/// concurrent pinned uploads of the same session — each blob simply ends up pinned.
pub async fn pin_session<S: FlightStore>(
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
    /// The stored blob's size in bytes — the *compressed* (zstd) size the object store
    /// reports, not the size of the JSON a fetch decompresses it back to.
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

/// The largest **decompressed** flight recording the read path will materialize. A
/// stored blob is zstd-compressed JSON, bounded at [`MAX_FLIGHT_BLOB_BYTES`] compressed;
/// the recorder's size-capped rings keep a real recording's uncompressed JSON well below
/// this, so it never trips on genuine data. It exists to bound the read path's memory
/// against a hostile or corrupt stored object whose few compressed bytes expand far
/// beyond any real recording (a decompression bomb): the decoder stops just past this
/// rather than inflating an unbounded buffer, and the over-cap object is refused as a
/// store-integrity error rather than served.
pub const MAX_DECOMPRESSED_BLOB_BYTES: usize = 64 * 1024 * 1024;

/// Decompresses a stored recording's zstd bytes into the JSON a read serves, bounded at
/// [`MAX_DECOMPRESSED_BLOB_BYTES`] so a decompression bomb cannot balloon memory. A blob
/// that is not valid zstd, or that expands past the cap, is a store-integrity failure (a
/// corrupt or hostile object) surfaced as an error — the caller serves it as a store
/// error, never the raw bytes.
fn decompress_recording(compressed: &[u8]) -> Result<Vec<u8>, FlightStoreError> {
    use std::io::Read;
    let decoder = zstd::stream::read::Decoder::new(compressed).map_err(|error| {
        FlightStoreError(format!(
            "opening a stored flight blob's zstd decoder: {error}"
        ))
    })?;
    // Read at most one byte past the cap, so an over-cap object is detected without
    // ever materializing the whole (possibly enormous) decompressed stream: the `take`
    // stops the decoder there regardless of how much more it would produce.
    let mut out = Vec::new();
    decoder
        .take(MAX_DECOMPRESSED_BLOB_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|error| {
            FlightStoreError(format!("decompressing a stored flight blob: {error}"))
        })?;
    if out.len() > MAX_DECOMPRESSED_BLOB_BYTES {
        return Err(FlightStoreError(format!(
            "a stored flight blob decompresses past the {MAX_DECOMPRESSED_BLOB_BYTES}-byte cap"
        )));
    }
    Ok(out)
}

/// Fetches one relay's recording of a session and decompresses it into the JSON a read
/// serves, preferring the pinned [`DESYNC_PREFIX`] copy over the normal [`FLIGHT_PREFIX`]
/// one (they carry the same bytes when both exist, but the pinned one is the surviving
/// copy after a convergence sweep). `None` when neither exists.
///
/// A stored blob is zstd-compressed JSON; this decompresses it so the caller serves
/// ready-to-use JSON. A blob that is not valid zstd, or that decompresses past
/// [`MAX_DECOMPRESSED_BLOB_BYTES`], is a store-integrity error, not a `None` — the
/// caller serves it as a store error rather than the raw bytes.
pub async fn fetch_recording<S: FlightStore>(
    store: &S,
    tenant: &TenantId,
    session: SessionId,
    relay_id: RelayId,
) -> Result<Option<Vec<u8>>, FlightStoreError> {
    let compressed = match store
        .get(&object_key(true, tenant, session, relay_id))
        .await?
    {
        Some(bytes) => Some(bytes),
        None => {
            store
                .get(&object_key(false, tenant, session, relay_id))
                .await?
        }
    };
    match compressed {
        Some(bytes) => Ok(Some(decompress_recording(&bytes)?)),
        None => Ok(None),
    }
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
    /// presign-shape tests use it directly, since presigning is an offline signature
    /// computation that needs no reachable bucket.
    async fn build(resolved: ResolvedFlightStore) -> Self {
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

    /// zstd-compresses `bytes` the way the relay does before uploading, so a test can
    /// store a genuine `.json.zst` object the read path decompresses back.
    fn zstd_bytes(bytes: &[u8]) -> Vec<u8> {
        zstd::encode_all(bytes, 0).expect("compressing test bytes")
    }

    #[test]
    fn object_key_selects_the_prefix_and_preserves_the_tenant_first_shape() {
        assert_eq!(
            object_key(false, &tenant(), SessionId(7), RelayId(3)),
            "flight/sb-test/7/3.json.zst",
        );
        assert_eq!(
            object_key(true, &tenant(), SessionId(7), RelayId(3)),
            "desync/sb-test/7/3.json.zst",
        );
    }

    #[test]
    fn plan_flight_upload_gates_then_returns_the_retention_key() {
        // The gates surface as the same drops `classify_ingest` returns.
        assert_eq!(
            plan_flight_upload(false, true, &tenant(), SessionId(7), RelayId(3), false, 0),
            Err(FlightDrop::NoStore),
        );
        assert_eq!(
            plan_flight_upload(true, false, &tenant(), SessionId(7), RelayId(3), false, 0),
            Err(FlightDrop::UnknownTenant),
        );
        assert_eq!(
            plan_flight_upload(
                true,
                true,
                &tenant(),
                SessionId(7),
                RelayId(3),
                false,
                MAX_FLIGHT_BLOB_BYTES as u64 + 1,
            ),
            Err(FlightDrop::TooLarge),
        );
        // An unpinned grant plans the flight-prefix key; a pinned one the desync prefix.
        assert_eq!(
            plan_flight_upload(true, true, &tenant(), SessionId(7), RelayId(3), false, 10),
            Ok(FlightUploadPlan {
                key: "flight/sb-test/7/3.json.zst".to_owned(),
                pinned: false,
            }),
        );
        assert_eq!(
            plan_flight_upload(true, true, &tenant(), SessionId(7), RelayId(3), true, 10),
            Ok(FlightUploadPlan {
                key: "desync/sb-test/7/3.json.zst".to_owned(),
                pinned: true,
            }),
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
    async fn a_late_pin_sweeps_an_earlier_flight_blob_into_the_desync_prefix() {
        let store = FakeFlightStore::new();
        // A non-authority relay uploaded its recording unpinned first (the relay PUTs
        // the compressed bytes straight to the object key; here we write them directly
        // to stand in for that).
        store
            .put(
                &object_key(false, &tenant(), SessionId(7), RelayId(2)),
                zstd_bytes(b"early"),
            )
            .await
            .unwrap();
        // The authority relay's pinned upload lands, and the coordinator's Done
        // bookkeeping converges the earlier one via the pinned sweep.
        store
            .put(
                &object_key(true, &tenant(), SessionId(7), RelayId(3)),
                zstd_bytes(b"late"),
            )
            .await
            .unwrap();
        pin_session(&store, &tenant(), SessionId(7)).await.unwrap();
        assert_eq!(
            store.keys(),
            vec![
                "desync/sb-test/7/2.json.zst".to_owned(),
                "desync/sb-test/7/3.json.zst".to_owned(),
            ],
        );
        // The moved blob keeps its bytes (the read path decompresses them back), and its
        // original is gone.
        assert_eq!(
            fetch_recording(&store, &tenant(), SessionId(7), RelayId(2))
                .await
                .unwrap(),
            Some(b"early".to_vec()),
        );
        assert!(!store.contains("flight/sb-test/7/2.json.zst"));
    }

    #[tokio::test]
    async fn listing_merges_prefixes_and_pinned_wins_the_dedup() {
        let store = FakeFlightStore::new();
        // Relay 2 exists under BOTH prefixes (the transient sweep state); relay 3 only
        // under desync/, relay 4 only under flight/. Written directly so the pinned
        // sweep does not disturb the mixed state.
        store
            .put("flight/sb-test/7/2.json.zst", b"a".to_vec())
            .await
            .unwrap();
        store
            .put("desync/sb-test/7/2.json.zst", b"a".to_vec())
            .await
            .unwrap();
        store
            .put("desync/sb-test/7/3.json.zst", b"bb".to_vec())
            .await
            .unwrap();
        store
            .put("flight/sb-test/7/4.json.zst", b"c".to_vec())
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
            .put("flight/sb-test/7/1.json.zst", b"a".to_vec())
            .await
            .unwrap();
        // Session 70's key shares the "7" numeric prefix; the trailing slash in the
        // session prefix keeps it out of session 7's listing.
        store
            .put("flight/sb-test/70/1.json.zst", b"b".to_vec())
            .await
            .unwrap();

        let listing = list_recordings(&store, &tenant(), SessionId(7))
            .await
            .unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].relay_id, 1);
    }

    #[tokio::test]
    async fn fetch_decompresses_and_prefers_the_pinned_copy_then_flight_then_none() {
        let store = FakeFlightStore::new();
        assert_eq!(
            fetch_recording(&store, &tenant(), SessionId(7), RelayId(3))
                .await
                .unwrap(),
            None,
        );
        // A stored blob is zstd-compressed JSON; a fetch decompresses it back.
        let flight_json = br#"{"version":1,"source":"flight"}"#;
        store
            .put("flight/sb-test/7/3.json.zst", zstd_bytes(flight_json))
            .await
            .unwrap();
        assert_eq!(
            fetch_recording(&store, &tenant(), SessionId(7), RelayId(3))
                .await
                .unwrap(),
            Some(flight_json.to_vec()),
        );
        let desync_json = br#"{"version":1,"source":"desync"}"#;
        store
            .put("desync/sb-test/7/3.json.zst", zstd_bytes(desync_json))
            .await
            .unwrap();
        assert_eq!(
            fetch_recording(&store, &tenant(), SessionId(7), RelayId(3))
                .await
                .unwrap(),
            Some(desync_json.to_vec()),
            "the pinned copy is preferred over the flight copy",
        );
    }

    #[tokio::test]
    async fn fetch_refuses_a_corrupt_non_zstd_stored_object() {
        // An object that is not valid zstd (corruption, or something other than this
        // module wrote it) is a store-integrity error, not a `None` — the caller serves
        // it as a store error, never the raw bytes.
        let store = FakeFlightStore::new();
        store
            .put("desync/sb-test/7/3.json.zst", b"not zstd at all".to_vec())
            .await
            .unwrap();
        assert!(
            fetch_recording(&store, &tenant(), SessionId(7), RelayId(3))
                .await
                .is_err(),
            "a corrupt stored object is refused, not served",
        );
    }

    #[tokio::test]
    async fn fetch_refuses_an_over_cap_decompression_bomb() {
        // A tiny compressed object that expands past the decompressed cap must be
        // refused rather than materialized — the decompression-bomb guard.
        let store = FakeFlightStore::new();
        let bomb = zstd_bytes(&vec![0u8; MAX_DECOMPRESSED_BLOB_BYTES + 1]);
        assert!(
            bomb.len() < 1024 * 1024,
            "the bomb's compressed form is tiny; only its expansion is large",
        );
        store
            .put("desync/sb-test/7/3.json.zst", bomb)
            .await
            .unwrap();
        assert!(
            fetch_recording(&store, &tenant(), SessionId(7), RelayId(3))
                .await
                .is_err(),
            "an over-cap decompression is refused",
        );
    }

    #[tokio::test]
    async fn presign_put_signs_a_bounded_url_for_the_key_and_size() {
        // Build the store offline (no reachability probe) against a Spaces-style
        // endpoint; presigning is a local signature computation, no network.
        let store = S3FlightStore::build(ResolvedFlightStore {
            endpoint: "https://nyc3.digitaloceanspaces.com".to_owned(),
            region: "us-east-1".to_owned(),
            bucket: "sb-rp2-flight".to_owned(),
            access_key: "AKIAEXAMPLE".to_owned(),
            secret_key: "s3cr3texamplekey".to_owned(),
        })
        .await;

        let key = object_key(true, &tenant(), SessionId(7), RelayId(3));
        let url = store.presign_put(&key, 4096).await.unwrap();

        // The host comes from the configured endpoint and the object key is the path.
        assert!(url.starts_with("https://"), "{url}");
        assert!(url.contains("digitaloceanspaces.com"), "{url}");
        assert!(url.contains("desync/sb-test/7/3.json.zst"), "{url}");
        // The SigV4 presign query params: algorithm, the bounded expiry, the signed
        // headers, and the signature — all present, all computed locally.
        assert!(url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"), "{url}");
        assert!(
            url.contains("X-Amz-Expires=300"),
            "expiry is 5 minutes: {url}"
        );
        assert!(url.contains("X-Amz-SignedHeaders="), "{url}");
        assert!(url.contains("X-Amz-Signature="), "{url}");
        // The exact content length is signed into the URL, so it cannot store a
        // different-sized object.
        assert!(
            url.contains("content-length"),
            "the signed headers bind content-length: {url}",
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
