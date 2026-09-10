use super::*;
use rally_point_proto::control::{BufferBounds, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::token::{ClientPublicKey, ExpiresAt, KeyId};

#[test]
fn a_pkcs8_v1_document_enrolls_and_derives_the_matching_verifying_key() {
    // The RFC 5208 v1 prefix for an Ed25519 private key, followed by the
    // raw 32-byte seed — the exact document `openssl genpkey -algorithm
    // ed25519` emits (no embedded public key).
    const V1_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let seed = [0x42u8; 32];
    let mut doc = V1_PREFIX.to_vec();
    doc.extend_from_slice(&seed);

    let store = new_store();
    let enrolled = enroll_from_pkcs8(
        &store,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
        &doc,
    )
    .unwrap();

    let expected = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    assert_eq!(enrolled.as_slice(), expected.public_key().as_ref());
}

#[test]
fn non_pkcs8_bytes_still_fail_enrollment() {
    let store = new_store();
    let err = enroll_from_pkcs8(
        &store,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
        b"not a key document",
    )
    .unwrap_err();
    assert!(matches!(err, KeyError::InvalidPkcs8));
}

/// Every enrollment path funnels through `enroll_from_pkcs8`, so bounds past
/// the game-sync-safe ceiling are refused for programmatic tenant sources
/// too — not only the JSON registry loader's own check. A buffer depth past
/// the ceiling deterministically mass-drops the game's players.
#[test]
fn bounds_past_the_game_safe_ceiling_fail_enrollment() {
    use rally_point_proto::control::GAME_SYNC_SAFE_BUFFER_MAX;

    let store = new_store();
    let err = enroll(
        &store,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, GAME_SYNC_SAFE_BUFFER_MAX + 1).unwrap(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        KeyError::BoundsPastGameSafeMax { max } if max == GAME_SYNC_SAFE_BUFFER_MAX + 1
    ));

    // The ceiling itself is the last allowed value.
    enroll(
        &store,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        BufferBounds::new(1, GAME_SYNC_SAFE_BUFFER_MAX).unwrap(),
    )
    .expect("bounds at the ceiling enroll");
}

/// Deserialized bounds bypass `BufferBounds::new`, so an inverted range can
/// reach enrollment — and `{ min: 15, max: 1 }` clamps swap-tolerantly as
/// `1..=15`, smuggling an over-ceiling depth past a max-only check.
/// Enrollment refuses the inversion outright.
#[test]
fn inverted_bounds_fail_enrollment() {
    use rally_point_proto::control::GAME_SYNC_SAFE_BUFFER_MAX;

    let store = new_store();
    let err = enroll(
        &store,
        KeyId("test-key-1".to_owned()),
        TenantId("sb-test".to_owned()),
        // A struct literal, as deserialization would produce it.
        BufferBounds {
            min: GAME_SYNC_SAFE_BUFFER_MAX + 1,
            max: 1,
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        KeyError::InvertedBounds { min, max } if min == GAME_SYNC_SAFE_BUFFER_MAX + 1 && max == 1
    ));
}

fn store_with_tenant() -> (TenantStore, KeyId, TenantId) {
    let store = new_store();
    let kid = KeyId("test-key-1".to_owned());
    let tenant = TenantId("sb-test".to_owned());
    enroll(
        &store,
        kid.clone(),
        tenant.clone(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    (store, kid, tenant)
}

#[test]
fn enroll_then_verifying_key_roundtrips() {
    let (store, kid, tenant) = store_with_tenant();
    let (found_kid, _pubkey) = verifying_key(&store, &tenant).unwrap();
    assert_eq!(found_kid, kid);
    assert!(is_enrolled(&store, &tenant));
}

#[test]
fn mint_token_then_relay_verifies() {
    // The round-trip test: coordinator mints, relay verifies.
    let (store, kid, tenant) = store_with_tenant();
    let (_, pubkey) = verifying_key(&store, &tenant).unwrap();

    let mut relay_registry = rally_point_relay::auth::Registry::new();
    relay_registry.insert(kid, tenant.clone(), pubkey);

    let client_pub = ClientPublicKey([0x42; 32]);
    let token = mint_token(
        &store,
        &tenant,
        SessionId(1),
        SlotId(0),
        client_pub,
        ExpiresAt(u64::MAX),
    )
    .unwrap();

    // The relay verifies the token against the registered key.
    let authorized =
        rally_point_relay::auth::verify_token(&relay_registry, &token, u64::MAX - 1).unwrap();
    assert_eq!(authorized.tenant, tenant);
    assert_eq!(authorized.session, SessionId(1));
    assert_eq!(authorized.slot, SlotId(0));
    assert_eq!(authorized.client_pubkey, client_pub);
}

#[test]
fn mint_token_for_unenrolled_tenant_fails() {
    let store = new_store();
    let result = mint_token(
        &store,
        &TenantId("nope".to_owned()),
        SessionId(1),
        SlotId(0),
        ClientPublicKey([0; 32]),
        ExpiresAt(u64::MAX),
    );
    assert!(matches!(result, Err(KeyError::TenantNotFound(_))));
}

#[test]
fn re_enroll_replaces_key() {
    let store = new_store();
    let kid = KeyId("test-key-1".to_owned());
    let tenant = TenantId("sb-test".to_owned());
    let bounds = BufferBounds::new(1, 6).unwrap();

    let pubkey1 = enroll(&store, kid.clone(), tenant.clone(), bounds).unwrap();
    let pubkey2 = enroll(&store, kid, tenant.clone(), bounds).unwrap();

    // A new key replaces the old one.
    assert_ne!(pubkey1, pubkey2);
    assert_eq!(len(&store), 1);
}

#[test]
fn all_verifying_keys_returns_every_enrolled_tenant() {
    let store = new_store();
    let bounds = BufferBounds::new(1, 6).unwrap();
    let pk_a = enroll(
        &store,
        KeyId("kid-a".to_owned()),
        TenantId("tenant-a".to_owned()),
        bounds,
    )
    .unwrap();
    let pk_b = enroll(
        &store,
        KeyId("kid-b".to_owned()),
        TenantId("tenant-b".to_owned()),
        bounds,
    )
    .unwrap();

    let mut keys = all_verifying_keys(&store);
    keys.sort_by(|l, r| l.kid.as_ref().cmp(r.kid.as_ref()));
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].kid, KeyId("kid-a".to_owned()));
    assert_eq!(keys[0].tenant, TenantId("tenant-a".to_owned()));
    assert_eq!(keys[0].verifying_key, pk_a.to_vec());
    assert_eq!(keys[1].kid, KeyId("kid-b".to_owned()));
    assert_eq!(keys[1].verifying_key, pk_b.to_vec());
}

#[test]
fn all_verifying_keys_is_empty_for_a_store_with_no_tenants() {
    assert!(all_verifying_keys(&new_store()).is_empty());
}

#[test]
fn different_tenants_get_different_keys() {
    let store = new_store();
    let bounds = BufferBounds::new(1, 6).unwrap();
    let pk1 = enroll(
        &store,
        KeyId("kid-a".to_owned()),
        TenantId("tenant-a".to_owned()),
        bounds,
    )
    .unwrap();
    let pk2 = enroll(
        &store,
        KeyId("kid-b".to_owned()),
        TenantId("tenant-b".to_owned()),
        bounds,
    )
    .unwrap();
    assert_ne!(pk1, pk2);
    assert_eq!(len(&store), 2);
}

#[test]
fn bounds_lookup_returns_enrolled_bounds() {
    let (store, _, tenant) = store_with_tenant();
    let b = bounds(&store, &tenant).unwrap();
    assert_eq!(b, BufferBounds::new(1, 6).unwrap());
}

#[test]
fn enroll_generated_pkcs8_re_enrolls_the_same_key() {
    // The dev restart flow: enroll fresh, persist the PKCS#8, re-enroll
    // from it on a new (restarted) store — same verifying key.
    let store = new_store();
    let bounds = BufferBounds::new(1, 6).unwrap();
    let generated = enroll_generated(
        &store,
        KeyId("dev-key-1".to_owned()),
        TenantId("sb-dev".to_owned()),
        bounds,
    )
    .unwrap();

    let restarted = new_store();
    let re_enrolled = enroll_from_pkcs8(
        &restarted,
        KeyId("dev-key-1".to_owned()),
        TenantId("sb-dev".to_owned()),
        bounds,
        &generated.pkcs8,
    )
    .unwrap();

    assert_eq!(re_enrolled, generated.verifying_key);
}

#[test]
fn enroll_from_pkcs8_roundtrips() {
    // Generate a keypair, extract PKCS#8, register from it.
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let expected_pub: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();

    let store = new_store();
    let pub_from_store = enroll_from_pkcs8(
        &store,
        KeyId("pkcs8-key".to_owned()),
        TenantId("sb-pkcs8".to_owned()),
        BufferBounds::new(1, 6).unwrap(),
        pkcs8.as_ref(),
    )
    .unwrap();

    assert_eq!(pub_from_store, expected_pub);
}

#[test]
fn sign_webhook_verifies_against_the_enrolled_verifying_key() {
    let (store, _, tenant) = store_with_tenant();
    let (_, pubkey) = verifying_key(&store, &tenant).unwrap();

    let message = b"rp2-webhook-v1:1700000000000:{\"tenant\":\"sb-test\"}";
    let sig = sign_webhook(&store, &tenant, message).unwrap();

    let verifying = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pubkey);
    assert!(
        verifying.verify(message, &sig).is_ok(),
        "the webhook signature verifies against the tenant's public key",
    );

    // A mutated message (or a wrong key) must not verify.
    assert!(verifying.verify(b"tampered", &sig).is_err());
}

#[test]
fn sign_webhook_for_an_unenrolled_tenant_returns_none() {
    let store = new_store();
    assert!(sign_webhook(&store, &TenantId("nope".to_owned()), b"anything").is_none());
}

// RFC 8032 §7.1 test vector 1: the same seed → public key pair pinned in the
// app-side key tests (app/game/netcode-v2-keys.test.ts) and the game's
// credentials.rs, reused here so the client-key seed derivation is checked
// against a known-answer vector rather than only round-tripping itself.
const RFC8032_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const RFC8032_PUBLIC_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

#[test]
fn client_pubkey_from_seed_matches_the_rfc8032_vector() {
    let derived = client_pubkey_from_seed(&RFC8032_SEED).unwrap();
    assert_eq!(hex::encode(derived), RFC8032_PUBLIC_HEX);
}

#[test]
fn client_pubkey_from_seed_rejects_a_wrong_length_seed() {
    assert!(matches!(
        client_pubkey_from_seed(&[0u8; 31]),
        Err(KeyError::InvalidSeed)
    ));
}

#[test]
fn set_and_get_client_pubkeys_roundtrips() {
    let (store, _, tenant) = store_with_tenant();

    // Empty until set.
    assert!(client_pubkeys(&store, &tenant).is_empty());

    let pubkey = client_pubkey_from_seed(&RFC8032_SEED).unwrap();
    assert!(set_client_pubkeys(&store, &tenant, vec![pubkey]));
    assert_eq!(client_pubkeys(&store, &tenant), vec![pubkey]);

    // A no-op (and no panic) on an unknown tenant.
    assert!(!set_client_pubkeys(
        &store,
        &TenantId("nope".to_owned()),
        vec![pubkey]
    ));
    assert!(client_pubkeys(&store, &TenantId("nope".to_owned())).is_empty());
}

#[test]
fn set_client_pubkeys_holds_two_keys_in_order() {
    // Rotation posture: a tenant can carry two request-verifying keys at once
    // (old + new), both retrievable in the order they were set.
    let (store, _, tenant) = store_with_tenant();
    let first = client_pubkey_from_seed(&[0x11; 32]).unwrap();
    let second = client_pubkey_from_seed(&[0x22; 32]).unwrap();
    assert!(set_client_pubkeys(&store, &tenant, vec![first, second]));
    assert_eq!(client_pubkeys(&store, &tenant), vec![first, second]);
}

#[test]
fn a_freshly_enrolled_tenant_is_active() {
    let (store, _, tenant) = store_with_tenant();
    assert_eq!(tenant_state(&store, &tenant), Some(TenantState::Active));
    // An unknown tenant has no state.
    assert_eq!(tenant_state(&store, &TenantId("nope".to_owned())), None);
}

#[test]
fn set_and_get_state_roundtrips() {
    let (store, _, tenant) = store_with_tenant();
    assert!(set_state(&store, &tenant, TenantState::Suspended));
    assert_eq!(tenant_state(&store, &tenant), Some(TenantState::Suspended));
    assert!(set_state(&store, &tenant, TenantState::Revoked));
    assert_eq!(tenant_state(&store, &tenant), Some(TenantState::Revoked));

    // A no-op on an unknown tenant.
    assert!(!set_state(
        &store,
        &TenantId("nope".to_owned()),
        TenantState::Active
    ));
}

#[test]
fn notify_config_is_withheld_from_a_revoked_tenant() {
    let (store, _, tenant) = store_with_tenant();
    set_notify(
        &store,
        &tenant,
        Some(NotifyConfig {
            url: "http://localhost/hook".to_owned(),
        }),
    );

    // Active and suspended both report the config (a suspended tenant's live
    // games keep delivering webhooks); revoked withholds it entirely.
    assert!(notify_config(&store, &tenant).is_some());
    set_state(&store, &tenant, TenantState::Suspended);
    assert!(notify_config(&store, &tenant).is_some());
    set_state(&store, &tenant, TenantState::Revoked);
    assert!(notify_config(&store, &tenant).is_none());
}

#[test]
fn sign_webhook_refuses_a_revoked_tenant() {
    let (store, _, tenant) = store_with_tenant();
    assert!(sign_webhook(&store, &tenant, b"anything").is_some());
    set_state(&store, &tenant, TenantState::Suspended);
    assert!(
        sign_webhook(&store, &tenant, b"anything").is_some(),
        "a suspended tenant's key still signs its live games' webhooks",
    );
    set_state(&store, &tenant, TenantState::Revoked);
    assert!(sign_webhook(&store, &tenant, b"anything").is_none());
}

#[test]
fn default_bounds_is_one_to_twelve() {
    assert_eq!(default_bounds(), BufferBounds::new(1, 12).unwrap());
}

#[test]
fn generate_client_key_seed_derives_a_valid_pubkey() {
    // A generated seed is a usable Ed25519 seed: it derives a 32-byte key,
    // and two calls differ (the RNG isn't stuck).
    let seed = generate_client_key_seed();
    assert!(client_pubkey_from_seed(&seed).is_ok());
    assert_ne!(seed, generate_client_key_seed());
}
