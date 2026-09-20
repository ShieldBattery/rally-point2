//! The tenant request-signing contract: what a signature covers and which
//! headers carry it.
//!
//! A tenant (the app server, or a harness standing in for one) authenticates an
//! HTTP request to the coordinator with an Ed25519 signature over a
//! domain-separated, timestamped, method+path-bound message. Signer and verifier
//! must build byte-identical messages or every request fails closed, so the
//! layout lives here rather than once on each side.
//!
//! Sans-I/O and key-agnostic: this builds the bytes, and the caller signs or
//! verifies them with whatever key material it holds. The replay window a
//! verifier enforces on the timestamp is its own policy, not part of the
//! layout.
//!
//! Distinct from the webhook signature the coordinator sends in the other
//! direction, which has its own domain prefix and uses millisecond timestamps.

/// The domain-separation prefix a tenant request signature covers. Binds a
/// signature to the request-auth scheme so it can never be confused with a
/// webhook signature (the opposite direction) or a player-token signature made
/// by a different key.
pub const REQUEST_SIG_DOMAIN: &str = "rp2-request-v1:";

/// Header carrying the request signing timestamp: unix epoch *seconds*,
/// decimal.
pub const TIMESTAMP_HEADER: &str = "x-rp2-timestamp";

/// Header carrying the Ed25519 request signature: lowercase hex of the 64-byte
/// signature over [`request_message`]'s bytes.
pub const SIGNATURE_HEADER: &str = "x-rp2-signature";

/// The exact bytes a tenant request signature covers:
/// `rp2-request-v1:<ts>:<METHOD>:<path>:<raw body>`.
///
/// `method` is the canonical uppercase verb and `path` is the path exactly as
/// sent (including any query), so a captured, validly-signed body cannot be
/// replayed against a different endpoint or verb. `timestamp` is bound in too,
/// which is what lets a verifier bound replay by age.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_message_has_the_exact_documented_layout() {
        assert_eq!(
            request_message(
                "1700000000",
                "POST",
                "/session/create",
                b"{\"tenant\":\"sb-dev\"}",
            ),
            b"rp2-request-v1:1700000000:POST:/session/create:{\"tenant\":\"sb-dev\"}",
        );
    }

    #[test]
    fn an_empty_body_still_carries_every_separator() {
        assert_eq!(
            request_message("1700000000", "GET", "/session/1/presence", b""),
            b"rp2-request-v1:1700000000:GET:/session/1/presence:",
        );
    }
}
