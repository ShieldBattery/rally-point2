use super::*;

fn sample_claims() -> TokenClaims {
    TokenClaims::new(
        TenantId("sb-staging".to_owned()),
        SessionId(0xDEAD_BEEF_CAFE_BABE),
        SlotId(3),
        ExpiresAt(1_800_000_000),
        ClientPublicKey([0xAB; PUBLIC_KEY_LEN]),
    )
}

fn sample_token() -> SignedToken {
    SignedToken::from_parts(
        KeyId("staging-key-1".to_owned()),
        sample_claims(),
        Signature([0xCD; SIGNATURE_LEN]),
    )
}

#[test]
fn round_trip_encode_decode() {
    let token = sample_token();
    let encoded = token.encode().unwrap();
    let decoded = SignedToken::decode(&encoded).unwrap();

    assert_eq!(decoded, token);
}

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
fn signed_message_is_stable() {
    // The same token must always produce the same signed bytes.
    let token = sample_token();

    let mut a = Vec::new();
    let mut b = Vec::new();
    token.signed_message(&mut a).unwrap();
    token.signed_message(&mut b).unwrap();

    assert_eq!(a, b);
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
fn decode_rejects_unknown_version() {
    let token = sample_token();
    let mut encoded = token.encode().unwrap();
    encoded[0] = 99; // bogus version

    assert_eq!(
        SignedToken::decode(&encoded).unwrap_err(),
        TokenError::UnsupportedVersion(99)
    );
}

#[test]
fn decode_unknown_version_before_structural_parse() {
    // A token whose version byte is unknown must report UnsupportedVersion,
    // not Malformed — even if the body is too short to parse as v1.
    let bytes = &[99u8]; // version only, no body
    assert_eq!(
        SignedToken::decode(bytes).unwrap_err(),
        TokenError::UnsupportedVersion(99)
    );
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
fn public_key_from_slice_rejects_wrong_length() {
    assert!(ClientPublicKey::from_slice(&[]).is_none());
    assert!(ClientPublicKey::from_slice(&[0; 31]).is_none());
    assert!(ClientPublicKey::from_slice(&[0; 33]).is_none());
    assert!(ClientPublicKey::from_slice(&[0; PUBLIC_KEY_LEN]).is_some());
}

#[test]
fn signature_from_slice_rejects_wrong_length() {
    assert!(Signature::from_slice(&[0; 63]).is_none());
    assert!(Signature::from_slice(&[0; 65]).is_none());
    assert!(Signature::from_slice(&[0; SIGNATURE_LEN]).is_some());
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
fn encode_rejects_oversized_kid() {
    let token = SignedToken::from_parts(
        KeyId("a".repeat(MAX_STRING_LEN + 1)),
        sample_claims(),
        Signature([0; SIGNATURE_LEN]),
    );

    assert_eq!(token.encode().unwrap_err(), TokenError::StringTooLong);
    assert!(token.encoded_len().is_none());
}

#[test]
fn encode_rejects_oversized_tenant() {
    let token = SignedToken::from_parts(
        KeyId("ok".to_owned()),
        TokenClaims::new(
            TenantId("b".repeat(MAX_STRING_LEN + 1)),
            SessionId(0),
            SlotId(0),
            ExpiresAt(0),
            ClientPublicKey([0; PUBLIC_KEY_LEN]),
        ),
        Signature([0; SIGNATURE_LEN]),
    );

    assert_eq!(token.encode().unwrap_err(), TokenError::StringTooLong);
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
fn challenge_signed_message_is_deterministic() {
    let challenge = ConnectionChallenge([0x99; CHALLENGE_LEN]);
    let binding = [0x33; CHANNEL_BINDING_LEN];
    assert_eq!(
        challenge.signed_message(&binding),
        challenge.signed_message(&binding)
    );
}

#[test]
fn challenge_signed_messages_differ_for_different_challenges() {
    let binding = [0x33; CHANNEL_BINDING_LEN];
    let a = ConnectionChallenge([0x11; CHALLENGE_LEN]);
    let b = ConnectionChallenge([0x22; CHALLENGE_LEN]);
    assert_ne!(a.signed_message(&binding), b.signed_message(&binding));
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
fn challenge_from_slice_rejects_wrong_length() {
    assert!(ConnectionChallenge::from_slice(&[]).is_none());
    assert!(ConnectionChallenge::from_slice(&[0; 31]).is_none());
    assert!(ConnectionChallenge::from_slice(&[0; 33]).is_none());
    assert!(ConnectionChallenge::from_slice(&[0; CHALLENGE_LEN]).is_some());
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
fn challenge_response_from_slice_rejects_wrong_length() {
    assert!(ChallengeResponse::from_slice(&[0; 63]).is_none());
    assert!(ChallengeResponse::from_slice(&[0; 65]).is_none());
    assert!(ChallengeResponse::from_slice(&[0; SIGNATURE_LEN]).is_some());
}
