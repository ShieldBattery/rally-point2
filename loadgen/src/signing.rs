//! Signing a session-create request the way the app server does, so the
//! coordinator's inbound-request auth accepts it.
//!
//! The coordinator authenticates a tenant request by an Ed25519 signature over a
//! domain-separated, timestamped, method+path-bound message (see
//! `coordinator/src/api.rs`'s `build_request_message` / `verify_tenant_request`).
//! The signature rides two headers — `x-rp2-timestamp` (unix seconds) and
//! `x-rp2-signature` (lowercase hex) — and the timestamp is bound into the signed
//! bytes and checked against a replay window, so every send (including a
//! provisioning re-send) signs fresh with the current time over the identical
//! body.

use std::time::{SystemTime, UNIX_EPOCH};

use ring::signature::Ed25519KeyPair;

/// The domain-separation prefix on a tenant request signature. Binds the
/// signature to the request-auth scheme so it can never be confused with a
/// webhook or token signature.
const REQUEST_SIG_DOMAIN: &str = "rp2-request-v1:";
/// Header carrying the request signing timestamp: unix epoch seconds, decimal.
pub const TIMESTAMP_HEADER: &str = "x-rp2-timestamp";
/// Header carrying the lowercase-hex Ed25519 request signature.
pub const SIGNATURE_HEADER: &str = "x-rp2-signature";

/// The exact bytes a tenant request signature covers:
/// `rp2-request-v1:<ts>:<METHOD>:<path>:<raw body>`. The method (uppercase) and
/// the path-as-sent are bound in so a captured, validly-signed body cannot be
/// replayed against another endpoint or verb.
pub fn request_message(timestamp: &str, method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        REQUEST_SIG_DOMAIN.len() + timestamp.len() + method.len() + path.len() + body.len() + 3,
    );
    message.extend_from_slice(REQUEST_SIG_DOMAIN.as_bytes());
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b':');
    message.extend_from_slice(method.as_bytes());
    message.push(b':');
    message.extend_from_slice(path.as_bytes());
    message.push(b':');
    message.extend_from_slice(body);
    message
}

/// Signs a request with the tenant's Ed25519 key at the current time, returning
/// the `(x-rp2-timestamp, x-rp2-signature)` header pair.
pub fn sign_request(
    key: &Ed25519KeyPair,
    method: &str,
    path: &str,
    body: &[u8],
) -> (String, String) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string();
    let message = request_message(&timestamp, method, path, body);
    let signature = key.sign(&message);
    (timestamp, hex::encode(signature.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_message_has_the_exact_documented_layout() {
        let message = request_message(
            "1700000000",
            "POST",
            "/session/create",
            b"{\"tenant\":\"sb-dev\"}",
        );
        assert_eq!(
            message,
            b"rp2-request-v1:1700000000:POST:/session/create:{\"tenant\":\"sb-dev\"}"
        );
    }

    #[test]
    fn a_signature_verifies_against_the_signing_seed_public_half() {
        use ring::signature::{self, KeyPair};

        let seed = [0x11u8; 32];
        let key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let body = b"{\"tenant\":\"sb-dev\"}";
        let (ts, sig_hex) = sign_request(&key, "POST", "/session/create", body);

        let message = request_message(&ts, "POST", "/session/create", body);
        let sig = hex::decode(sig_hex).unwrap();
        let public =
            signature::UnparsedPublicKey::new(&signature::ED25519, key.public_key().as_ref());
        assert!(public.verify(&message, &sig).is_ok());
    }
}
