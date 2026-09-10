use std::collections::HashMap;

use ring::signature::Ed25519KeyPair;

use super::*;

/// A base64 PKCS#8 signing key for a config's env var, plus the verifying key
/// it derives (so a test can assert the enrolled tenant carries the same one).
struct SigningKeyFixture {
    base64: String,
    verifying_key: [u8; PUBLIC_KEY_LEN],
}

/// Generates a fresh Ed25519 signing key and returns it base64-encoded (as an
/// env var would hold it) alongside its verifying key.
fn signing_key_fixture() -> SigningKeyFixture {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    use ring::signature::KeyPair as _;
    let verifying_key: [u8; PUBLIC_KEY_LEN] = pair.public_key().as_ref().try_into().unwrap();
    SigningKeyFixture {
        base64: BASE64_STANDARD.encode(pkcs8.as_ref()),
        verifying_key,
    }
}

/// A hex client pubkey derived from `seed` — a value a config's
/// `client_pubkeys` would carry.
fn client_pubkey_hex(seed: &[u8; 32]) -> String {
    hex::encode(tenant::client_pubkey_from_seed(seed).unwrap())
}

/// A one-key `client_pubkeys` JSON array literal carrying a well-formed key,
/// so a test can exercise a *later* field's validation without tripping the
/// pubkey check first.
fn one_valid_pubkey() -> String {
    format!(r#"["{}"]"#, client_pubkey_hex(&[0x01; 32]))
}

#[test]
fn a_valid_config_loads_and_enrolls_with_default_and_explicit_bounds() {
    let key_a = signing_key_fixture();
    let key_b = signing_key_fixture();
    let json = format!(
        r#"{{"tenants": [
            {{
                "id": "tenant-a",
                "state": "active",
                "kid": "kid-a",
                "signing_key_env": "ENV_A",
                "client_pubkeys": ["{pk_a1}", "{pk_a2}"],
                "notify_url": "https://a.example/hook"
            }},
            {{
                "id": "tenant-b",
                "state": "suspended",
                "kid": "kid-b",
                "signing_key_env": "ENV_B",
                "client_pubkeys": ["{pk_b}"],
                "bounds": {{"min": 2, "max": 8}}
            }}
        ]}}"#,
        pk_a1 = client_pubkey_hex(&[0x01; 32]),
        pk_a2 = client_pubkey_hex(&[0x02; 32]),
        pk_b = client_pubkey_hex(&[0x03; 32]),
    );

    let config = from_json(&json).expect("a well-formed registry parses");
    assert_eq!(config.len(), 2);

    let env = HashMap::from([
        ("ENV_A".to_owned(), key_a.base64.clone()),
        ("ENV_B".to_owned(), key_b.base64.clone()),
    ]);
    let store = tenant::new_store();
    enroll_all(&store, &config, |name| env.get(name).cloned()).expect("all tenants enroll");

    let a = TenantId("tenant-a".to_owned());
    let b = TenantId("tenant-b".to_owned());

    // Tenant A: active, default bounds (no override), two client keys, notify.
    assert_eq!(tenant::tenant_state(&store, &a), Some(TenantState::Active));
    assert_eq!(tenant::bounds(&store, &a), Some(default_bounds()));
    assert_eq!(tenant::client_pubkeys(&store, &a).len(), 2);
    assert_eq!(
        tenant::verifying_key(&store, &a).map(|(_, pk)| pk),
        Some(key_a.verifying_key),
    );
    assert!(tenant::notify_config(&store, &a).is_some());

    // Tenant B: suspended, explicit bounds, one client key, no notify.
    assert_eq!(
        tenant::tenant_state(&store, &b),
        Some(TenantState::Suspended)
    );
    assert_eq!(
        tenant::bounds(&store, &b),
        Some(BufferBounds::new(2, 8).unwrap())
    );
    assert_eq!(tenant::client_pubkeys(&store, &b).len(), 1);
    assert_eq!(
        tenant::verifying_key(&store, &b).map(|(_, pk)| pk),
        Some(key_b.verifying_key),
    );
    assert!(tenant::notify_config(&store, &b).is_none());
}

/// A one-tenant registry JSON with the given field substitutions, for the
/// error-path tests. `client_pubkeys` is a JSON array literal, `bounds` a JSON
/// fragment or the empty string to omit it.
fn single_tenant_json(
    state: &str,
    signing_key_env: &str,
    client_pubkeys: &str,
    bounds: &str,
) -> String {
    let bounds_field = if bounds.is_empty() {
        String::new()
    } else {
        format!(", \"bounds\": {bounds}")
    };
    format!(
        r#"{{"tenants": [{{
            "id": "solo",
            "state": "{state}",
            "kid": "kid-solo",
            "signing_key_env": "{signing_key_env}",
            "client_pubkeys": {client_pubkeys}{bounds_field}
        }}]}}"#,
    )
}

#[test]
fn an_unknown_state_is_rejected_naming_the_tenant() {
    let json = single_tenant_json("frozen", "ENV", r#"["aa"]"#, "");
    match from_json(&json) {
        Err(TenantConfigError::UnknownState { tenant, value }) => {
            assert_eq!(tenant, "solo");
            assert_eq!(value, "frozen");
        }
        other => panic!("expected UnknownState, got {other:?}"),
    }
}

#[test]
fn empty_client_pubkeys_is_rejected() {
    let json = single_tenant_json("active", "ENV", "[]", "");
    match from_json(&json) {
        Err(TenantConfigError::NoClientPubkeys { tenant }) => assert_eq!(tenant, "solo"),
        other => panic!("expected NoClientPubkeys, got {other:?}"),
    }
}

#[test]
fn too_many_client_pubkeys_is_rejected() {
    let three = format!(
        r#"["{a}", "{b}", "{c}"]"#,
        a = client_pubkey_hex(&[0x01; 32]),
        b = client_pubkey_hex(&[0x02; 32]),
        c = client_pubkey_hex(&[0x03; 32]),
    );
    let json = single_tenant_json("active", "ENV", &three, "");
    match from_json(&json) {
        Err(TenantConfigError::TooManyClientPubkeys { tenant, count }) => {
            assert_eq!(tenant, "solo");
            assert_eq!(count, 3);
        }
        other => panic!("expected TooManyClientPubkeys, got {other:?}"),
    }
}

#[test]
fn a_malformed_client_pubkey_hex_is_rejected() {
    // Not hex at all.
    let json = single_tenant_json("active", "ENV", r#"["nothex!!"]"#, "");
    match from_json(&json) {
        Err(TenantConfigError::MalformedClientPubkey { tenant, index }) => {
            assert_eq!(tenant, "solo");
            assert_eq!(index, 0);
        }
        other => panic!("expected MalformedClientPubkey, got {other:?}"),
    }

    // Valid hex, but the wrong length (16 bytes, not 32).
    let json = single_tenant_json(
        "active",
        "ENV",
        r#"["aabbccddeeff00112233445566778899"]"#,
        "",
    );
    assert!(matches!(
        from_json(&json),
        Err(TenantConfigError::MalformedClientPubkey { index: 0, .. })
    ));
}

#[test]
fn inverted_bounds_are_rejected() {
    let json = single_tenant_json(
        "active",
        "ENV",
        &one_valid_pubkey(),
        r#"{"min": 10, "max": 3}"#,
    );
    match from_json(&json) {
        Err(TenantConfigError::InvalidBounds { tenant, min, max }) => {
            assert_eq!(tenant, "solo");
            assert_eq!((min, max), (10, 3));
        }
        other => panic!("expected InvalidBounds, got {other:?}"),
    }
}

#[test]
fn bounds_past_the_game_safe_ceiling_are_rejected() {
    let json = single_tenant_json(
        "active",
        "ENV",
        &one_valid_pubkey(),
        r#"{"min": 1, "max": 15}"#,
    );
    match from_json(&json) {
        Err(TenantConfigError::BoundsPastGameSafeMax { tenant, max }) => {
            assert_eq!(tenant, "solo");
            assert_eq!(max, 15);
        }
        other => panic!("expected BoundsPastGameSafeMax, got {other:?}"),
    }

    // The ceiling itself passes — the guard rejects strictly past it.
    let json = single_tenant_json(
        "active",
        "ENV",
        &one_valid_pubkey(),
        &format!(r#"{{"min": 1, "max": {GAME_SYNC_SAFE_BUFFER_MAX}}}"#),
    );
    assert!(from_json(&json).is_ok());
}

#[test]
fn a_duplicate_id_is_rejected() {
    let pk = client_pubkey_hex(&[0x01; 32]);
    let json = format!(
        r#"{{"tenants": [
            {{"id": "dup", "state": "active", "kid": "kid-1", "signing_key_env": "E1", "client_pubkeys": ["{pk}"]}},
            {{"id": "dup", "state": "active", "kid": "kid-2", "signing_key_env": "E2", "client_pubkeys": ["{pk}"]}}
        ]}}"#,
    );
    assert!(matches!(
        from_json(&json),
        Err(TenantConfigError::DuplicateId(id)) if id == "dup"
    ));
}

#[test]
fn a_duplicate_kid_is_rejected() {
    let pk = client_pubkey_hex(&[0x01; 32]);
    let json = format!(
        r#"{{"tenants": [
            {{"id": "t1", "state": "active", "kid": "same", "signing_key_env": "E1", "client_pubkeys": ["{pk}"]}},
            {{"id": "t2", "state": "active", "kid": "same", "signing_key_env": "E2", "client_pubkeys": ["{pk}"]}}
        ]}}"#,
    );
    assert!(matches!(
        from_json(&json),
        Err(TenantConfigError::DuplicateKid(kid)) if kid == "same"
    ));
}

#[test]
fn an_unknown_top_level_field_is_rejected() {
    // A misspelled top-level key (`tenantz` for `tenants`) must fail to parse
    // rather than silently loading an empty registry.
    let pk = client_pubkey_hex(&[0x01; 32]);
    let json = format!(
        r#"{{"tenantz": [
            {{"id": "solo", "state": "active", "kid": "kid-solo", "signing_key_env": "E", "client_pubkeys": ["{pk}"]}}
        ]}}"#,
    );
    assert!(matches!(from_json(&json), Err(TenantConfigError::Parse(_))));
}

#[test]
fn a_missing_env_var_fails_enrollment() {
    let json = single_tenant_json("active", "ABSENT_ENV", &one_valid_pubkey(), "");
    let config = from_json(&json).unwrap();
    let store = tenant::new_store();

    // No entry for ABSENT_ENV — the lookup returns None.
    match enroll_all(&store, &config, |_| None) {
        Err(TenantConfigError::MissingSigningKey { tenant, env }) => {
            assert_eq!(tenant, "solo");
            assert_eq!(env, "ABSENT_ENV");
        }
        other => panic!("expected MissingSigningKey, got {other:?}"),
    }

    // An empty (or whitespace-only) value is treated exactly like an absent one.
    let empty = HashMap::from([("ABSENT_ENV".to_owned(), "   ".to_owned())]);
    assert!(matches!(
        enroll_all(&store, &config, |name| empty.get(name).cloned()),
        Err(TenantConfigError::MissingSigningKey { .. })
    ));
}

#[test]
fn a_non_base64_signing_key_fails_enrollment() {
    let json = single_tenant_json("active", "ENV", &one_valid_pubkey(), "");
    let config = from_json(&json).unwrap();
    let store = tenant::new_store();
    let env = HashMap::from([("ENV".to_owned(), "not valid base64 %%%".to_owned())]);
    assert!(matches!(
        enroll_all(&store, &config, |name| env.get(name).cloned()),
        Err(TenantConfigError::MalformedSigningKeyBase64 { .. })
    ));
}

#[test]
fn base64_of_non_pkcs8_bytes_fails_enrollment() {
    let json = single_tenant_json("active", "ENV", &one_valid_pubkey(), "");
    let config = from_json(&json).unwrap();
    let store = tenant::new_store();
    // Valid base64, but the bytes are not a PKCS#8 keypair.
    let env = HashMap::from([("ENV".to_owned(), BASE64_STANDARD.encode([0u8; 16]))]);
    assert!(matches!(
        enroll_all(&store, &config, |name| env.get(name).cloned()),
        Err(TenantConfigError::InvalidSigningKey { .. })
    ));
}
