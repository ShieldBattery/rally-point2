//! Proof-of-possession verification.
//!
//! The signing helpers below are written here from scratch rather than reused
//! from the relay's own enroll client, and must stay that way. The guarantee is
//! that the coordinator accepts exactly what an independent implementation of
//! the documented scheme produces: if the proof context or the signed message
//! layout ever drifted, and the relay and the coordinator drifted together, an
//! end-to-end enroll test would still pass while these would fail. Sharing the
//! relay's signer would throw that away.

use super::*;

/// A self-signed cert (DER) + the matching PKCS#8 private key, for a given
/// `rcgen` signature algorithm.
fn self_signed_with_alg(alg: &'static rcgen::SignatureAlgorithm) -> (Vec<u8>, Vec<u8>) {
    let key = rcgen::KeyPair::generate_for(alg).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (cert.der().to_vec(), key.serialize_der())
}

/// Signs `message` with an ECDSA P-256 PKCS#8 key.
fn sign_ecdsa_p256(pkcs8: &[u8], message: &[u8]) -> Vec<u8> {
    let rng = ring::rand::SystemRandom::new();
    let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8,
        &rng,
    )
    .unwrap();
    pair.sign(&rng, message).unwrap().as_ref().to_vec()
}

/// Signs `message` with an Ed25519 PKCS#8 key.
fn sign_ed25519(pkcs8: &[u8], message: &[u8]) -> Vec<u8> {
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8).unwrap();
    pair.sign(message).as_ref().to_vec()
}

/// The message a relay signs to prove possession: the enroll context followed
/// by the coordinator's challenge nonce.
fn enroll_message(nonce: &[u8; 32]) -> Vec<u8> {
    let mut message = ENROLL_POP_CONTEXT.to_vec();
    message.extend_from_slice(nonce);
    message
}

#[test]
fn a_correct_ecdsa_p256_signature_verifies() {
    let (cert_der, key_der) = self_signed_with_alg(&rcgen::PKCS_ECDSA_P256_SHA256);
    let nonce = [0x11; 32];
    let signature = sign_ecdsa_p256(&key_der, &enroll_message(&nonce));
    assert!(verify_enroll_proof(&cert_der, &nonce, &signature));
}

#[test]
fn a_correct_ed25519_signature_verifies() {
    let (cert_der, key_der) = self_signed_with_alg(&rcgen::PKCS_ED25519);
    let nonce = [0x22; 32];
    let signature = sign_ed25519(&key_der, &enroll_message(&nonce));
    assert!(verify_enroll_proof(&cert_der, &nonce, &signature));
}

#[test]
fn a_signature_over_the_wrong_nonce_is_refused() {
    let (cert_der, key_der) = self_signed_with_alg(&rcgen::PKCS_ECDSA_P256_SHA256);
    let signed_nonce = [0x33; 32];
    let claimed_nonce = [0x44; 32]; // the coordinator's actual challenge
    let signature = sign_ecdsa_p256(&key_der, &enroll_message(&signed_nonce));
    assert!(!verify_enroll_proof(&cert_der, &claimed_nonce, &signature));
}

#[test]
fn a_signature_from_a_different_key_is_refused() {
    // The classic impostor case this whole exchange exists to catch: a
    // valid signature, but not from the key behind the presented cert.
    let (cert_der, _honest_key) = self_signed_with_alg(&rcgen::PKCS_ECDSA_P256_SHA256);
    let (_, impostor_key) = self_signed_with_alg(&rcgen::PKCS_ECDSA_P256_SHA256);
    let nonce = [0x55; 32];
    let signature = sign_ecdsa_p256(&impostor_key, &enroll_message(&nonce));
    assert!(!verify_enroll_proof(&cert_der, &nonce, &signature));
}

#[test]
fn a_malformed_certificate_is_refused_not_panicking() {
    let nonce = [0x66; 32];
    assert!(!verify_enroll_proof(&[0xDE, 0xAD], &nonce, &[0x01, 0x02]));
}

#[test]
fn an_unusable_signature_is_refused_not_panicking() {
    // Attacker-supplied signature bytes reach the verifier directly, so every
    // shape of nonsense must come back unproven rather than panic: nothing at
    // all, bytes that are not a signature, and a real signature truncated —
    // the one that actually starts to parse before it fails.
    let (cert_der, key_der) = self_signed_with_alg(&rcgen::PKCS_ECDSA_P256_SHA256);
    let nonce = [0x77; 32];
    let mut truncated = sign_ecdsa_p256(&key_der, &enroll_message(&nonce));
    truncated.truncate(truncated.len() / 2);
    for (signature, what) in [
        (Vec::new(), "an empty signature"),
        (vec![0xFF; 8], "garbage bytes"),
        (truncated, "a truncated valid signature"),
    ] {
        assert!(
            !verify_enroll_proof(&cert_der, &nonce, &signature),
            "{what} must be refused",
        );
    }
}
