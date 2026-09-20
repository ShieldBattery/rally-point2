//! Request-signature and control-connection auth: the cross-implementation
//! signing vector and the bearer / `ControlAuth` posture checks.

use super::*;

#[test]
fn the_request_signature_message_matches_the_cross_impl_vector() {
    // The cross-implementation test vector, pinned byte-for-byte on both
    // sides: the RFC 8032 §7.1 vector-1 seed, its derived public key, and a
    // Node-produced Ed25519 signature (netcode-v2-service.test.ts pins the
    // identical hex) over a fixed request message. Ed25519 is deterministic,
    // so ring and Node produce the same 64 bytes for the same key+message —
    // a drift in either side's message construction breaks one of the two
    // tests.
    const RFC8032_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const EXPECTED_SIG_HEX: &str = "33a9c1ee42248bc26e7844a880a5c82512cf534b200937b607a2259b3ee8dded4f1cae21671be4f949145ac5888874c845024daae6e1c405dd9a051a12d4f209";

    let pubkey = crate::tenant::client_pubkey_from_seed(&RFC8032_SEED).unwrap();
    assert_eq!(
        hex::encode(pubkey),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    );

    // The exact canonical bytes both sides sign.
    let message = build_request_message(
        "1700000000",
        &Method::POST,
        "/session/create",
        br#"{"tenant":"sb-dev"}"#,
    );
    assert_eq!(
        message,
        b"rp2-request-v1:1700000000:POST:/session/create:{\"tenant\":\"sb-dev\"}",
    );

    // The Node-produced signature verifies under ring.
    let sig = hex::decode(EXPECTED_SIG_HEX).unwrap();
    UnparsedPublicKey::new(&ED25519, pubkey.as_ref())
        .verify(&message, &sig)
        .expect("the cross-impl signature verifies under ring");
}

#[test]
fn control_auth_admits_only_a_matching_bearer_and_open_admits_any_request() {
    let bearer = |value: &str| {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, value.parse().unwrap());
        headers
    };
    let secret = ControlAuth::Secret("s3cret".to_owned());

    for (label, headers, admitted) in [
        ("the matching bearer", bearer("Bearer s3cret"), true),
        ("a wrong secret", bearer("Bearer nope"), false),
        ("no Authorization header at all", HeaderMap::new(), false),
        ("a non-Bearer scheme", bearer("Basic s3cret"), false),
    ] {
        assert_eq!(
            control_auth_ok(&headers, &secret),
            admitted,
            "under a configured secret, {label} decides admission wrongly",
        );
    }

    // Open is the explicit dev/loopback posture: any request (even without a
    // header) is accepted. It is never the default — the binary only builds
    // it under an explicit insecure opt-in.
    assert!(control_auth_ok(&HeaderMap::new(), &ControlAuth::Open));
}

#[test]
fn resolve_control_auth_requires_a_secret_or_an_explicit_open_opt_in() {
    // A secret always wins, and takes precedence even when insecure is also
    // (redundantly) set.
    for allow_insecure in [false, true] {
        let auth = resolve_control_auth(Some("s3cret".to_owned()), allow_insecure).unwrap();
        assert!(matches!(auth, ControlAuth::Secret(s) if s == "s3cret"));
    }

    // With no secret, only the explicit opt-in yields an open endpoint.
    assert!(matches!(
        resolve_control_auth(None, true).unwrap(),
        ControlAuth::Open
    ));
    // The no-ship default: no secret and no explicit insecure flag is a hard
    // error, not a silently open endpoint.
    assert!(resolve_control_auth(None, false).is_err());
}
