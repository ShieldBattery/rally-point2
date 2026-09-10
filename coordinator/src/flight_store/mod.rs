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
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId};

mod config;
mod s3;
#[cfg(test)]
mod tests;

pub use config::{FlightStoreConfig, FlightStoreConfigError, ResolvedFlightStore, from_json, load};
pub use s3::S3FlightStore;

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
