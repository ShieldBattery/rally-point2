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
