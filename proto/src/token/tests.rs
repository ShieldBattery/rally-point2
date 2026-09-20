use super::*;
use crate::test_support::{sample_claims, sample_token};

#[test]
fn encoded_len_is_exact() {
    let token = sample_token();
    let encoded = token.encode().unwrap();
    assert_eq!(encoded.len(), token.encoded_len().unwrap());
}

#[test]
fn signed_message_excludes_signature() {
    let token = sample_token();
    let encoded = token.encode().unwrap();

    let mut signed_msg = Vec::new();
    token.signed_message(&mut signed_msg).unwrap();

    // The signed message is the encoding minus the trailing signature.
    assert_eq!(signed_msg.len(), encoded.len() - SIGNATURE_LEN);
    assert_eq!(&signed_msg[..], &encoded[..encoded.len() - SIGNATURE_LEN]);
}

#[test]
fn decode_rejects_empty() {
    assert_eq!(
        SignedToken::decode(&[]).unwrap_err(),
        TokenError::Malformed("empty token")
    );
}

#[test]
fn decode_rejects_truncated_signature() {
    let token = sample_token();
    let mut encoded = token.encode().unwrap();
    encoded.truncate(encoded.len() - 1); // drop one signature byte

    assert_eq!(
        SignedToken::decode(&encoded).unwrap_err(),
        TokenError::Malformed("signature too short")
    );
}

#[test]
fn decode_rejects_truncated_claims() {
    let token = sample_token();
    let encoded = token.encode().unwrap();
    // Cut off everything after the version + kid.
    let truncated = &encoded[..1 + 1 + token.kid.0.len()];

    assert!(matches!(
        SignedToken::decode(truncated),
        Err(TokenError::Malformed(_))
    ));
}

#[test]
fn decode_unknown_version_before_structural_parse() {
    // An unknown version byte reports UnsupportedVersion whatever follows it:
    // over a full-length v1 body, and over no body at all. The second case is
    // the one that matters — the version check has to run *before* the
    // structural parse, or a future version's frame comes back as Malformed and
    // the peer learns nothing about why.
    let mut full_body = sample_token().encode().unwrap();
    full_body[0] = 99;

    for bytes in [full_body.as_slice(), &[99u8]] {
        assert_eq!(
            SignedToken::decode(bytes).unwrap_err(),
            TokenError::UnsupportedVersion(99),
            "{} byte(s) after the version",
            bytes.len() - 1,
        );
    }
}

#[test]
fn decode_rejects_non_utf8_string() {
    // Build a token with invalid UTF-8 in the kid field.
    let mut buf = Vec::new();
    buf.push(TOKEN_VERSION);
    buf.push(2); // kid_len = 2
    buf.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
    // Pad with enough bytes to look like a complete token.
    buf.push(0); // tenant_len = 0
    buf.extend_from_slice(&[0u8; 8]); // session
    buf.push(0); // slot
    buf.extend_from_slice(&[0u8; 8]); // expires_at
    buf.extend_from_slice(&[0u8; PUBLIC_KEY_LEN]); // pubkey
    buf.extend_from_slice(&[0u8; SIGNATURE_LEN]); // signature

    assert!(matches!(
        SignedToken::decode(&buf),
        Err(TokenError::Malformed("string field is not valid UTF-8"))
    ));
}

#[test]
fn decode_rejects_trailing_bytes() {
    let token = sample_token();
    let mut encoded = token.encode().unwrap();
    encoded.push(0x00); // extra byte after signature

    assert_eq!(
        SignedToken::decode(&encoded).unwrap_err(),
        TokenError::TrailingBytes
    );
}

#[test]
fn minimal_token_round_trips() {
    // Smallest valid token: empty kid and tenant strings.
    let token = SignedToken::from_parts(
        KeyId(String::new()),
        TokenClaims::new(
            TenantId(String::new()),
            SessionId(0),
            SlotId(0),
            ExpiresAt(0),
            ClientPublicKey([0; PUBLIC_KEY_LEN]),
        ),
        Signature([0; SIGNATURE_LEN]),
    );

    let encoded = token.encode().unwrap();
    // version(1) + kid_len(1) + tenant_len(1) + session(8) + slot(1)
    // + expires(8) + pubkey(32) + sig(64) = 116
    assert_eq!(encoded.len(), 116);

    let decoded = SignedToken::decode(&encoded).unwrap();
    assert_eq!(decoded, token);
}

#[test]
fn encode_to_appends_without_clearing() {
    let token = sample_token();
    let mut buf = vec![0xFF, 0xEE];
    token.encode_to(&mut buf).unwrap();

    // The prefix is preserved.
    assert_eq!(&buf[..2], &[0xFF, 0xEE]);
    // The rest is the token.
    assert_eq!(buf.len(), 2 + token.encoded_len().unwrap());
}

#[test]
fn key_id_new_rejects_oversized() {
    assert!(KeyId::new(String::new()).is_ok());
    assert!(KeyId::new("a".repeat(MAX_STRING_LEN)).is_ok());
    assert_eq!(
        KeyId::new("a".repeat(MAX_STRING_LEN + 1)).unwrap_err(),
        TokenError::StringTooLong
    );
}

#[test]
fn encode_rejects_an_oversized_string_field() {
    // Both length-prefixed strings are gated: a kid or a tenant past
    // MAX_STRING_LEN cannot be expressed in its one-byte prefix, so encoding
    // fails outright rather than emitting a truncated field. `encoded_len` has
    // to agree — a caller sizing a buffer from it must not get a number back for
    // a token that will never encode.
    let long = "a".repeat(MAX_STRING_LEN + 1);

    let oversized_kid = SignedToken::from_parts(
        KeyId(long.clone()),
        sample_claims(),
        Signature([0; SIGNATURE_LEN]),
    );

    let mut long_tenant = sample_claims();
    long_tenant.tenant = TenantId(long);
    let oversized_tenant = SignedToken::from_parts(
        KeyId("ok".to_owned()),
        long_tenant,
        Signature([0; SIGNATURE_LEN]),
    );

    for (field, token) in [("kid", oversized_kid), ("tenant", oversized_tenant)] {
        assert_eq!(
            token.encode().unwrap_err(),
            TokenError::StringTooLong,
            "oversized {field}"
        );
        assert!(token.encoded_len().is_none(), "oversized {field}");
    }
}

// --- Challenge / response tests ---

#[test]
fn challenge_signed_message_has_tag_binding_and_nonce() {
    let challenge = ConnectionChallenge([0x42; CHALLENGE_LEN]);
    let binding = [0x7C; CHANNEL_BINDING_LEN];
    let signed = challenge.signed_message(&binding);

    assert_eq!(signed[0], CHALLENGE_DOMAIN_TAG);
    assert_eq!(&signed[1..1 + CHANNEL_BINDING_LEN], &binding);
    assert_eq!(&signed[1 + CHANNEL_BINDING_LEN..], challenge.as_bytes());
}

#[test]
fn challenge_signed_messages_differ_for_different_channel_bindings() {
    // The same challenge bound to two channels signs differently — the property
    // that stops a proof from being replayed across connections.
    let challenge = ConnectionChallenge([0x55; CHALLENGE_LEN]);
    let cb_a = [0xA1; CHANNEL_BINDING_LEN];
    let cb_b = [0xB2; CHANNEL_BINDING_LEN];
    assert_ne!(
        challenge.signed_message(&cb_a),
        challenge.signed_message(&cb_b)
    );
}

#[test]
fn v1_wire_bytes_match_the_golden_vector() {
    // Fixed bytes captured from the v1 encoder, not derived from it at test
    // time. A round-trip test alone would not catch a change that shifts
    // both `encode` and `decode` the same way (e.g. reordering two fields) --
    // that kind of change breaks every token issued by a coordinator before
    // the change, since relays running older code decode the old layout.
    // If this test needs to change, the wire format changed, which means
    // TOKEN_VERSION must be bumped and decode() extended to still accept the
    // old layout -- do not just update the golden bytes below.
    #[rustfmt::skip]
    const GOLDEN: [u8; 139] = [
        // version
        0x01,
        // kid_len(13) + "staging-key-1"
        0x0D, 0x73, 0x74, 0x61, 0x67, 0x69, 0x6E, 0x67, 0x2D, 0x6B, 0x65, 0x79, 0x2D, 0x31,
        // tenant_len(10) + "sb-staging"
        0x0A, 0x73, 0x62, 0x2D, 0x73, 0x74, 0x61, 0x67, 0x69, 0x6E, 0x67,
        // session = 0xDEAD_BEEF_CAFE_BABE, little-endian
        0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE,
        // slot = 3
        0x03,
        // expires_at = 1_800_000_000, little-endian
        0x00, 0xD2, 0x49, 0x6B, 0x00, 0x00, 0x00, 0x00,
        // client_pubkey = [0xAB; 32]
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
        0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
        // signature = [0xCD; 64]
        0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
        0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
        0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
        0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
        0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
        0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
        0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
        0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
    ];

    let token = sample_token();
    let encoded = token.encode().unwrap();
    assert_eq!(encoded, GOLDEN);

    // The decoder must accept its own golden vector, and produce the same
    // claims that encoded it.
    let decoded = SignedToken::decode(&GOLDEN).unwrap();
    assert_eq!(decoded, token);
}

#[test]
fn the_fixed_width_newtypes_accept_only_their_exact_length() {
    // Every `from_slice` wraps a fixed-size array, so anything but the exact
    // length must come back `None` rather than panicking or padding: these are
    // the constructors that turn attacker-supplied slices into keys,
    // signatures, and challenges.
    /// Whether a newtype's `from_slice` accepted a slice of a given length.
    type Accepts = fn(&[u8]) -> bool;

    let cases: [(&str, Accepts, usize); 4] = [
        (
            "ClientPublicKey",
            |b| ClientPublicKey::from_slice(b).is_some(),
            PUBLIC_KEY_LEN,
        ),
        (
            "Signature",
            |b| Signature::from_slice(b).is_some(),
            SIGNATURE_LEN,
        ),
        (
            "ConnectionChallenge",
            |b| ConnectionChallenge::from_slice(b).is_some(),
            CHALLENGE_LEN,
        ),
        (
            "ChallengeResponse",
            |b| ChallengeResponse::from_slice(b).is_some(),
            SIGNATURE_LEN,
        ),
    ];

    for (name, accepts, len) in cases {
        assert!(accepts(&vec![0; len]), "{name} rejects its own length");
        assert!(!accepts(&[]), "{name} accepts an empty slice");
        assert!(!accepts(&vec![0; len - 1]), "{name} accepts one byte short");
        assert!(!accepts(&vec![0; len + 1]), "{name} accepts one byte long");
    }
}
