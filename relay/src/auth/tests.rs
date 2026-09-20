//! Tests for token/challenge verification and the coordinator-pushed
//! `SharedRegistry`: signature/tenant/expiry rejection paths, wholesale
//! registry replacement with stable in-flight snapshots, and the
//! connection-binding challenge's replay and channel-substitution rejections.

use super::*;
use rally_point_proto::token::{ExpiresAt, Signature, TokenClaims};
use ring::signature::{Ed25519KeyPair, KeyPair};

const NOW: u64 = 1_700_000_000;
const KID: &str = "staging-key-1";
const TENANT: &str = "sb-staging";

/// An Ed25519 keypair we can both sign with and read the public key of.
struct TestKey {
    pair: Ed25519KeyPair,
    public: [u8; PUBLIC_KEY_LEN],
}

fn test_key() -> TestKey {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public = pair.public_key().as_ref().try_into().unwrap();
    TestKey { pair, public }
}

impl TestKey {
    fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.pair.sign(message).as_ref().try_into().unwrap()
    }
}

/// Mints a token for `slot` signed by `tenant_key`, with the given claimed
/// tenant and expiry, embedding `client_pub` as the connection-binding key.
fn mint(
    tenant_key: &TestKey,
    kid: &str,
    claimed_tenant: &str,
    slot: SlotId,
    expires_at: u64,
    client_pub: [u8; PUBLIC_KEY_LEN],
) -> SignedToken {
    let claims = TokenClaims::new(
        TenantId(claimed_tenant.to_owned()),
        SessionId(7),
        slot,
        ExpiresAt(expires_at),
        ClientPublicKey(client_pub),
    );
    let mut token =
        SignedToken::from_parts(KeyId(kid.to_owned()), claims, Signature([0; SIGNATURE_LEN]));
    let mut message = Vec::new();
    token.signed_message(&mut message).unwrap();
    token.signature = Signature(tenant_key.sign(&message));
    token
}

fn registry_with(kid: &str, tenant: &str, key: &TestKey) -> Registry {
    let mut registry = Registry::new();
    registry.insert(
        KeyId(kid.to_owned()),
        TenantId(tenant.to_owned()),
        key.public,
    );
    registry
}

/// The preamble every token test shares: the tenant's signing key, the
/// client's connection-binding key, and a registry binding `KID` to `TENANT`.
struct Fixture {
    tenant_key: TestKey,
    client: TestKey,
    registry: Registry,
}

fn fixture() -> Fixture {
    let tenant_key = test_key();
    let registry = registry_with(KID, TENANT, &tenant_key);
    Fixture {
        tenant_key,
        client: test_key(),
        registry,
    }
}

impl Fixture {
    /// A token for `slot`, signed by the fixture's tenant key under `KID`,
    /// claiming `TENANT` and valid for another minute — the well-formed shape
    /// each rejection test perturbs exactly one part of.
    fn mint(&self, slot: SlotId) -> SignedToken {
        mint(
            &self.tenant_key,
            KID,
            TENANT,
            slot,
            NOW + 60,
            self.client.public,
        )
    }
}

/// One `TenantVerifyingKey` entry, as a coordinator `TenantKeys` push carries it.
fn pushed(kid: &str, tenant: &str, verifying_key: Vec<u8>) -> TenantVerifyingKey {
    TenantVerifyingKey {
        kid: KeyId(kid.to_owned()),
        tenant: TenantId(tenant.to_owned()),
        verifying_key,
    }
}

#[test]
fn a_pushed_set_replaces_the_registry_and_a_pushed_key_verifies_a_token() {
    let tenant_key = test_key();
    let client = test_key();
    let shared = SharedRegistry::default();
    let reader = shared.reader();
    // Empty until the first push: a coordinator-driven relay verifies nothing.
    assert!(reader.is_empty());

    shared.apply(vec![pushed(KID, TENANT, tenant_key.public.to_vec())]);

    let registry = reader.current();
    assert_eq!(registry.len(), 1);
    // A token signed by the pushed key verifies against the replaced set.
    let token = mint(&tenant_key, KID, TENANT, SlotId(3), NOW + 60, client.public);
    let authorized = verify_token(&registry, &token, NOW).unwrap();
    assert_eq!(authorized.tenant.as_ref(), TENANT);
    assert_eq!(authorized.slot, SlotId(3));
}

#[test]
fn a_pushed_set_skips_invalid_entries_and_applies_the_rest() {
    let good = test_key();
    let client = test_key();
    let shared = SharedRegistry::default();
    let reader = shared.reader();

    shared.apply(vec![
        // Wrong-length verifying key: skipped.
        pushed("short-key", TENANT, vec![0u8; PUBLIC_KEY_LEN - 1]),
        // Over-long kid: skipped.
        pushed(
            &"k".repeat(MAX_STRING_LEN + 1),
            TENANT,
            good.public.to_vec(),
        ),
        // Over-long tenant: skipped.
        pushed(
            "long-tenant-key",
            &"t".repeat(MAX_STRING_LEN + 1),
            good.public.to_vec(),
        ),
        // Well-formed: applied.
        pushed(KID, TENANT, good.public.to_vec()),
    ]);

    let registry = reader.current();
    assert_eq!(registry.len(), 1, "only the well-formed entry applies");
    let token = mint(&good, KID, TENANT, SlotId(0), NOW + 60, client.public);
    assert!(verify_token(&registry, &token, NOW).is_ok());
}

#[test]
fn a_later_push_replaces_the_set_wholesale() {
    let first_key = test_key();
    let second_key = test_key();
    let client = test_key();
    let shared = SharedRegistry::default();
    let reader = shared.reader();

    shared.apply(vec![pushed("kid-1", TENANT, first_key.public.to_vec())]);
    let with_first = reader.current();
    let first_token = mint(
        &first_key,
        "kid-1",
        TENANT,
        SlotId(0),
        NOW + 60,
        client.public,
    );
    assert!(verify_token(&with_first, &first_token, NOW).is_ok());

    // A later push carrying only kid-2 replaces the set: kid-1 no longer verifies.
    shared.apply(vec![pushed("kid-2", TENANT, second_key.public.to_vec())]);
    let with_second = reader.current();
    assert_eq!(with_second.len(), 1);
    assert!(matches!(
        verify_token(&with_second, &first_token, NOW),
        Err(AuthError::UnknownKey),
    ));
    let second_token = mint(
        &second_key,
        "kid-2",
        TENANT,
        SlotId(0),
        NOW + 60,
        client.public,
    );
    assert!(verify_token(&with_second, &second_token, NOW).is_ok());

    // The snapshot taken before the replacement still verifies kid-1 — an
    // in-flight verification never observes a torn set.
    assert!(verify_token(&with_first, &first_token, NOW).is_ok());
}

#[test]
fn a_fixed_reader_serves_its_seeded_set() {
    let f = fixture();
    let reader = RegistryReader::fixed(Arc::new(registry_with(KID, TENANT, &f.tenant_key)));
    assert!(!reader.is_empty());
    let token = f.mint(SlotId(1));
    assert!(verify_token(&reader.current(), &token, NOW).is_ok());
}

#[test]
fn accepts_a_well_formed_token() {
    let f = fixture();
    let token = f.mint(SlotId(3));

    let authorized = verify_token(&f.registry, &token, NOW).unwrap();
    assert_eq!(authorized.tenant.as_ref(), TENANT);
    assert_eq!(authorized.session, SessionId(7));
    assert_eq!(authorized.slot, SlotId(3));
    assert_eq!(authorized.client_pubkey.0, f.client.public);
}

#[test]
fn rejects_an_unregistered_kid() {
    let f = fixture();
    let token = mint(
        &f.tenant_key,
        "other-key",
        TENANT,
        SlotId(0),
        NOW + 60,
        f.client.public,
    );

    assert!(matches!(
        verify_token(&f.registry, &token, NOW),
        Err(AuthError::UnknownKey)
    ));
}

#[test]
fn rejects_a_signature_from_the_wrong_key() {
    let f = fixture();
    let impostor = test_key();
    // Same kid the registry knows, but signed by a different key.
    let token = mint(&impostor, KID, TENANT, SlotId(0), NOW + 60, f.client.public);

    assert!(matches!(
        verify_token(&f.registry, &token, NOW),
        Err(AuthError::BadSignature)
    ));
}

#[test]
fn rejects_a_tampered_claim() {
    let f = fixture();
    let mut token = f.mint(SlotId(0));
    // Flip the slot after signing; the signature no longer covers it.
    token.claims.slot = SlotId(1);

    assert!(matches!(
        verify_token(&f.registry, &token, NOW),
        Err(AuthError::BadSignature)
    ));
}

#[test]
fn rejects_a_tenant_claim_that_does_not_match_the_key() {
    // The registry binds this key to TENANT; the token, validly signed by the
    // same key, claims to be a different tenant.
    let f = fixture();
    let token = mint(
        &f.tenant_key,
        KID,
        "some-other-tenant",
        SlotId(0),
        NOW + 60,
        f.client.public,
    );

    assert!(matches!(
        verify_token(&f.registry, &token, NOW),
        Err(AuthError::TenantMismatch)
    ));
}

#[test]
fn rejects_an_expired_token() {
    let f = fixture();
    // Expires exactly at NOW — the boundary is treated as expired.
    let token = mint(&f.tenant_key, KID, TENANT, SlotId(0), NOW, f.client.public);

    assert!(matches!(
        verify_token(&f.registry, &token, NOW),
        Err(AuthError::Expired)
    ));
}

const CHANNEL_BINDING: [u8; CHANNEL_BINDING_LEN] = [0x6B; CHANNEL_BINDING_LEN];

#[test]
fn verifies_a_genuine_challenge_response() {
    let client = test_key();
    let challenge = ConnectionChallenge([0x5A; CHALLENGE_LEN]);
    let signature = client.sign(&challenge.signed_message(&CHANNEL_BINDING));

    verify_challenge(
        &ClientPublicKey(client.public),
        &challenge,
        &CHANNEL_BINDING,
        &ChallengeResponse(signature),
    )
    .unwrap();
}

#[test]
fn rejects_a_challenge_response_perturbed_in_any_of_its_three_parts() {
    // A proof of possession covers exactly three things, and each one dropped
    // from the canonical bytes is a different, real fail-open — so each is
    // perturbed on its own here, against an otherwise genuine response.
    let client = test_key();
    let impostor = test_key();
    let issued = ConnectionChallenge([0x5A; CHALLENGE_LEN]);
    let other_challenge = ConnectionChallenge([0x22; CHALLENGE_LEN]);
    let other_channel = [0xC4; CHANNEL_BINDING_LEN];

    let cases = [
        (
            "signed by a key that is not the token's client key",
            impostor.sign(&issued.signed_message(&CHANNEL_BINDING)),
        ),
        (
            "a response to a challenge this relay never issued -- the nonce \
             must be covered, or a captured response replays",
            client.sign(&other_challenge.signed_message(&CHANNEL_BINDING)),
        ),
        (
            "bound to another connection's channel -- the relay-in-the-middle \
             replay, which only the binding being covered refuses",
            client.sign(&issued.signed_message(&other_channel)),
        ),
    ];

    for (perturbation, signature) in cases {
        assert!(
            matches!(
                verify_challenge(
                    &ClientPublicKey(client.public),
                    &issued,
                    &CHANNEL_BINDING,
                    &ChallengeResponse(signature),
                ),
                Err(AuthError::ChallengeFailed)
            ),
            "accepted a response {perturbation}",
        );
    }
}
