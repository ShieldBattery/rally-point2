//! Signing a session-create request the way the app server does, so the
//! coordinator's inbound-request auth accepts it.
//!
//! The signed layout and the two headers it rides on are
//! `rally_point_proto::request_auth`; what is here is the signing itself. The
//! timestamp is bound into the signed bytes and checked against a replay
//! window, so every send (including a provisioning re-send) signs fresh with
//! the current time over the identical body.

use std::time::{SystemTime, UNIX_EPOCH};

use rally_point_proto::request_auth::request_message;
use ring::signature::Ed25519KeyPair;

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
