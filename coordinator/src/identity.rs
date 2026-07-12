//! Enroll proof-of-possession: verifying that a relay actually holds the
//! private key matching the certificate its `Hello` presented.
//!
//! `RelayHello.cert_der` alone is a claim, not proof — a holder of the shared
//! bootstrap secret could copy a victim relay's public certificate into its
//! own `Hello` and enroll as it. The coordinator closes that gap by
//! challenging the relay with a random nonce
//! ([`CoordinatorToRelay::IdentityChallenge`](rally_point_proto::control::CoordinatorToRelay::IdentityChallenge))
//! and verifying the relay's signed answer
//! ([`RelayToCoordinator::IdentityProof`](rally_point_proto::control::RelayToCoordinator::IdentityProof))
//! against the certificate's public key — this module is that verification,
//! called from [`crate::api`]'s control-connection handler. Pure logic: no
//! I/O, no async, no network, so it's testable without a socket.

use rally_point_proto::control::ENROLL_POP_CONTEXT;
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm};
use webpki::EndEntityCert;

/// The signature-verification algorithms this coordinator accepts for a
/// relay's enroll certificate, tried in turn — exactly the algorithms
/// `rally-point-relay`'s certificate loading can produce: ECDSA P-256
/// (`config::self_signed_cert`'s `rcgen` default) and Ed25519 (loadable from a
/// PEM-supplied PKCS#8 key via `config::load_cert`, which places no algorithm
/// restriction of its own on the key it parses). Any other key algorithm —
/// RSA in particular, also technically loadable via PKCS#8 — is refused: a
/// signature made with an unsupported key simply never matches either
/// candidate here, which is [`verify_enroll_proof`]'s only failure signal, so
/// naming exactly these two documents that the refusal is deliberate scope,
/// not an oversight.
const SUPPORTED_ALGORITHMS: &[&dyn SignatureVerificationAlgorithm] =
    &[webpki::ring::ECDSA_P256_SHA256, webpki::ring::ED25519];

/// Verifies that `signature` proves possession of the private key matching
/// `cert_der`'s public key: a valid signature, by one of this module's
/// supported algorithms (ECDSA P-256 or Ed25519), over `ENROLL_POP_CONTEXT ++
/// nonce`.
///
/// Tries each candidate algorithm in turn — the wire form doesn't name which
/// one produced the signature, mirroring how a TLS 1.2 signature is checked
/// against several candidate schemes
/// (`rustls::crypto::verify_tls12_signature`) — so a signature that matches
/// none of them is unproven, exactly like one that matches the right
/// algorithm but the wrong key. `cert_der` failing to parse as a valid X.509
/// certificate is unproven too: there is no key to have signed anything with.
pub fn verify_enroll_proof(cert_der: &[u8], nonce: &[u8; 32], signature: &[u8]) -> bool {
    let cert_der = CertificateDer::from(cert_der);
    let Ok(cert) = EndEntityCert::try_from(&cert_der) else {
        return false;
    };

    let mut message = Vec::with_capacity(ENROLL_POP_CONTEXT.len() + nonce.len());
    message.extend_from_slice(ENROLL_POP_CONTEXT);
    message.extend_from_slice(nonce);

    SUPPORTED_ALGORITHMS
        .iter()
        .any(|alg| cert.verify_signature(*alg, &message, signature).is_ok())
}

#[cfg(test)]
mod tests {
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

    /// Signs `message` with an ECDSA P-256 PKCS#8 key — mirrors
    /// `coordinator_client::sign_enroll_proof`'s ECDSA branch, kept
    /// independent here so this module's tests don't depend on the relay
    /// crate.
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
    fn garbage_signature_bytes_are_refused_not_panicking() {
        let (cert_der, _key_der) = self_signed_with_alg(&rcgen::PKCS_ECDSA_P256_SHA256);
        let nonce = [0x77; 32];
        assert!(!verify_enroll_proof(&cert_der, &nonce, &[0xFF; 8]));
    }

    #[test]
    fn an_empty_signature_is_refused() {
        let (cert_der, _key_der) = self_signed_with_alg(&rcgen::PKCS_ECDSA_P256_SHA256);
        let nonce = [0x88; 32];
        assert!(!verify_enroll_proof(&cert_der, &nonce, &[]));
    }
}
