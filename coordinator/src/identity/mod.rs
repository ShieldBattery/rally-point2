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
mod tests;
