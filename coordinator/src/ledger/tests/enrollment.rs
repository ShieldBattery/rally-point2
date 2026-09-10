//! Mint/authorize/retire tests: token binding and reuse, expiry, the
//! broken-clock fail-closed paths, reenroll vs. first-enroll, the retirement
//! tombstone, the expected-peer-IP gate, and the advertise-address roundtrip.

use super::*;

#[test]
fn mint_then_authorize_binds_consumes_and_records_enrolled() {
    let ledger = ledger();
    let minted = ledger.mint_at(1_000, None, DAY).unwrap();

    let outcome = ledger
        .authorize_enroll_at(
            1_100,
            minted.relay_id,
            fingerprint(0xA1),
            Some(&minted.token),
            None,
        )
        .unwrap();
    // Minted at 1_000, first enroll at 1_100 -> a 100-second cold start.
    assert_eq!(
        outcome,
        Authorized::FirstEnroll {
            cold_start_secs: Some(100),
        },
    );

    // The row now records the binding, the consumption, and the enroll time.
    let conn = ledger.conn.lock();
    let (consumed, bound, enrolled): (Option<i64>, Option<Vec<u8>>, Option<i64>) = conn
        .query_row(
            "SELECT token_consumed_at, cert_fingerprint, enrolled_at
             FROM provisioned_relays WHERE relay_id = ?1",
            params![as_i64(minted.relay_id.0)],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(consumed, Some(1_100));
    assert_eq!(enrolled, Some(1_100));
    assert_eq!(bound.as_deref(), Some(fingerprint(0xA1).as_slice()));
}

#[test]
fn the_same_token_binds_at_most_one_fingerprint() {
    // The atomic-UPDATE property: two enrolls presenting the same token with
    // different certificates leave exactly one bound. The first wins; the
    // second finds the id already bound and is refused.
    let ledger = ledger();
    let minted = ledger.mint_at(1_000, None, DAY).unwrap();

    let first = ledger
        .authorize_enroll_at(
            1_010,
            minted.relay_id,
            fingerprint(0xAA),
            Some(&minted.token),
            None,
        )
        .unwrap();
    assert!(matches!(first, Authorized::FirstEnroll { .. }));

    let second = ledger.authorize_enroll_at(
        1_020,
        minted.relay_id,
        fingerprint(0xBB),
        Some(&minted.token),
        None,
    );
    assert!(matches!(second, Err(EnrollRefusal::FingerprintMismatch)));

    // The winner's certificate is the one that stuck.
    let reconnect = ledger
        .authorize_enroll_at(1_030, minted.relay_id, fingerprint(0xAA), None, None)
        .unwrap();
    assert_eq!(reconnect, Authorized::Reenroll);
}

#[test]
fn a_consumed_token_cannot_be_reused_to_bind() {
    // The atomic UPDATE's `token_consumed_at IS NULL` guard: an id whose token
    // was consumed but (contrived here) left unbound refuses a second use of
    // that token with TokenInvalid, never a second bind.
    let ledger = ledger();
    let minted = ledger.mint_at(1_000, None, DAY).unwrap();
    {
        let conn = ledger.conn.lock();
        conn.execute(
            "UPDATE provisioned_relays SET token_consumed_at = 1500
              WHERE relay_id = ?1",
            params![as_i64(minted.relay_id.0)],
        )
        .unwrap();
    }
    let outcome = ledger.authorize_enroll_at(
        1_600,
        minted.relay_id,
        fingerprint(0xC1),
        Some(&minted.token),
        None,
    );
    assert!(matches!(outcome, Err(EnrollRefusal::TokenInvalid)));
}

#[test]
fn a_wrong_token_on_an_unbound_id_is_token_invalid() {
    let ledger = ledger();
    let minted = ledger.mint_at(1_000, None, DAY).unwrap();
    let outcome = ledger.authorize_enroll_at(
        1_010,
        minted.relay_id,
        fingerprint(0xC2),
        Some("not-the-real-token"),
        None,
    );
    assert!(matches!(outcome, Err(EnrollRefusal::TokenInvalid)));
}

#[test]
fn an_expired_token_is_refused() {
    let ledger = ledger();
    // A short-lived token: minted at t=1000 with a 10-second TTL.
    let minted = ledger
        .mint_at(1_000, None, Duration::from_secs(10))
        .unwrap();
    let outcome = ledger.authorize_enroll_at(
        2_000, // well past expiry
        minted.relay_id,
        fingerprint(0xC3),
        Some(&minted.token),
        None,
    );
    assert!(matches!(outcome, Err(EnrollRefusal::TokenInvalid)));
}

#[test]
fn a_broken_clock_refuses_enrollment() {
    // `unix_now` yields u64::MAX on a pre-epoch/errored clock; a `now` of
    // u64::MAX makes every finite expiry read as passed, so enrollment fails
    // closed rather than treating an unverifiable-age token as valid.
    let ledger = ledger();
    let minted = ledger.mint_at(1_000, None, DAY).unwrap();
    let outcome = ledger.authorize_enroll_at(
        u64::MAX,
        minted.relay_id,
        fingerprint(0xC4),
        Some(&minted.token),
        None,
    );
    assert!(matches!(outcome, Err(EnrollRefusal::TokenInvalid)));
}

#[test]
fn a_reenroll_with_the_same_fingerprint_needs_no_token() {
    let ledger = ledger();
    let minted = ledger.mint_at(1_000, None, DAY).unwrap();
    ledger
        .authorize_enroll_at(
            1_010,
            minted.relay_id,
            fingerprint(0xD0),
            Some(&minted.token),
            None,
        )
        .unwrap();

    // A reconnect presents the bound certificate and no token.
    let outcome = ledger
        .authorize_enroll_at(1_020, minted.relay_id, fingerprint(0xD0), None, None)
        .unwrap();
    assert_eq!(outcome, Authorized::Reenroll);
}

#[test]
fn a_reenroll_with_a_different_fingerprint_is_refused() {
    let ledger = ledger();
    let minted = ledger.mint_at(1_000, None, DAY).unwrap();
    ledger
        .authorize_enroll_at(
            1_010,
            minted.relay_id,
            fingerprint(0xD0),
            Some(&minted.token),
            None,
        )
        .unwrap();

    let outcome = ledger.authorize_enroll_at(1_020, minted.relay_id, fingerprint(0xEE), None, None);
    assert!(matches!(outcome, Err(EnrollRefusal::FingerprintMismatch)));
}

#[test]
fn a_retired_id_is_refused_even_with_a_valid_token_and_retire_is_idempotent() {
    let ledger = ledger();
    let minted = ledger.mint_at(1_000, None, DAY).unwrap();
    ledger.retire(minted.relay_id).unwrap();

    let outcome = ledger.authorize_enroll_at(
        1_010,
        minted.relay_id,
        fingerprint(0xF0),
        Some(&minted.token),
        None,
    );
    assert!(matches!(outcome, Err(EnrollRefusal::Retired)));

    // Retiring again is a harmless no-op.
    ledger.retire(minted.relay_id).unwrap();
    let again = ledger.authorize_enroll_at(
        1_020,
        minted.relay_id,
        fingerprint(0xF0),
        Some(&minted.token),
        None,
    );
    assert!(matches!(again, Err(EnrollRefusal::Retired)));
}

#[test]
fn an_unknown_id_is_refused() {
    let ledger = ledger();
    let outcome =
        ledger.authorize_enroll_at(1_000, RelayId(999), fingerprint(0x01), Some("x"), None);
    assert!(matches!(outcome, Err(EnrollRefusal::UnknownId)));
}

#[test]
fn a_tokenless_first_enroll_requires_a_token() {
    let ledger = ledger();
    let minted = ledger.mint_at(1_000, None, DAY).unwrap();
    let outcome = ledger.authorize_enroll_at(1_010, minted.relay_id, fingerprint(0x02), None, None);
    assert!(matches!(outcome, Err(EnrollRefusal::TokenRequired)));
}

#[test]
fn expected_ip_gates_first_and_reenroll() {
    let ledger = ledger();
    let minted = ledger.mint_at(1_000, None, DAY).unwrap();
    let expected: IpAddr = Ipv4Addr::new(203, 0, 113, 7).into();
    let other: IpAddr = Ipv4Addr::new(198, 51, 100, 9).into();
    ledger
        .record_task(minted.relay_id, "arn:aws:ecs:task/abc", &[expected], &[])
        .unwrap();

    // A mismatched peer is refused before the token is even consulted.
    let mismatch = ledger.authorize_enroll_at(
        1_010,
        minted.relay_id,
        fingerprint(0x10),
        Some(&minted.token),
        Some(other),
    );
    assert!(matches!(mismatch, Err(EnrollRefusal::IpMismatch)));
    // An absent peer address (server records none) is likewise refused.
    let absent = ledger.authorize_enroll_at(
        1_010,
        minted.relay_id,
        fingerprint(0x10),
        Some(&minted.token),
        None,
    );
    assert!(matches!(absent, Err(EnrollRefusal::IpMismatch)));

    // The matching peer enrolls.
    let ok = ledger
        .authorize_enroll_at(
            1_010,
            minted.relay_id,
            fingerprint(0x10),
            Some(&minted.token),
            Some(expected),
        )
        .unwrap();
    assert!(matches!(ok, Authorized::FirstEnroll { .. }));

    // The gate still applies on reconnect: a mismatched peer with the bound
    // certificate is refused.
    let reconnect_mismatch =
        ledger.authorize_enroll_at(1_020, minted.relay_id, fingerprint(0x10), None, Some(other));
    assert!(matches!(reconnect_mismatch, Err(EnrollRefusal::IpMismatch)));
    let reconnect_ok = ledger
        .authorize_enroll_at(
            1_020,
            minted.relay_id,
            fingerprint(0x10),
            None,
            Some(expected),
        )
        .unwrap();
    assert_eq!(reconnect_ok, Authorized::Reenroll);
}

#[test]
fn enroll_matches_any_ip_in_the_expected_set() {
    // A dual-stack task records both its public IPv4 and its IPv6; a connection
    // from either address enrolls, and one from neither is refused.
    let ledger = ledger();
    let minted = ledger.mint_at(1_000, None, DAY).unwrap();
    let v4: IpAddr = Ipv4Addr::new(203, 0, 113, 7).into();
    let v6: IpAddr = "2001:db8::7".parse().unwrap();
    let other: IpAddr = Ipv4Addr::new(198, 51, 100, 9).into();
    ledger
        .record_task(minted.relay_id, "arn:aws:ecs:task/dual", &[v4, v6], &[])
        .unwrap();

    // Enroll over IPv6 (binds the cert).
    let over_v6 = ledger
        .authorize_enroll_at(
            1_010,
            minted.relay_id,
            fingerprint(0x20),
            Some(&minted.token),
            Some(v6),
        )
        .unwrap();
    assert!(matches!(over_v6, Authorized::FirstEnroll { .. }));

    // Reconnect over the other family in the set is accepted too.
    let over_v4 = ledger
        .authorize_enroll_at(1_020, minted.relay_id, fingerprint(0x20), None, Some(v4))
        .unwrap();
    assert_eq!(over_v4, Authorized::Reenroll);

    // An address outside the set is refused.
    let outside =
        ledger.authorize_enroll_at(1_030, minted.relay_id, fingerprint(0x20), None, Some(other));
    assert!(matches!(outside, Err(EnrollRefusal::IpMismatch)));
}

#[test]
fn an_empty_expected_set_gates_nothing() {
    // Recording an empty expected set leaves the gate open: any peer, or none,
    // enrolls — the posture for a substrate that resolves no address.
    let ledger = ledger();
    let minted = ledger.mint_at(1_000, None, DAY).unwrap();
    ledger
        .record_task(minted.relay_id, "arn:aws:ecs:task/none", &[], &[])
        .unwrap();
    let any_peer: IpAddr = Ipv4Addr::new(198, 51, 100, 3).into();
    let ok = ledger
        .authorize_enroll_at(
            1_010,
            minted.relay_id,
            fingerprint(0x21),
            Some(&minted.token),
            Some(any_peer),
        )
        .unwrap();
    assert!(matches!(ok, Authorized::FirstEnroll { .. }));
}

#[test]
fn mint_after_retire_yields_a_fresh_id() {
    // AUTOINCREMENT: a retired id's number is never handed out again, so a
    // tombstone can never be shadowed by a reused id.
    let ledger = ledger();
    let first = ledger.mint_at(1_000, None, DAY).unwrap();
    ledger.retire(first.relay_id).unwrap();
    let second = ledger.mint_at(1_001, None, DAY).unwrap();
    assert_ne!(
        first.relay_id, second.relay_id,
        "a mint after a retire must not reuse the retired id",
    );
}

#[test]
fn record_task_and_advertised_addrs_roundtrip() {
    let ledger = ledger();
    let minted = ledger.mint_at(1_000, None, DAY).unwrap();
    // A freshly minted id has no recorded advertise set.
    assert_eq!(ledger.advertised_addrs(minted.relay_id).unwrap(), None);

    let v4: SocketAddr = "203.0.113.7:14900".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::7]:14900".parse().unwrap();
    ledger
        .record_task(minted.relay_id, "arn:aws:ecs:task/xyz", &[], &[v4, v6])
        .unwrap();
    assert_eq!(
        ledger.advertised_addrs(minted.relay_id).unwrap(),
        Some(vec![v4, v6]),
        "the advertise set round-trips in stored order",
    );
}

#[test]
fn a_broken_clock_refuses_minting() {
    // A `now` of u64::MAX (the fail-closed unusable-clock value) must refuse
    // the mint outright: stored as a signed integer it would read back as a
    // never-expiring token, inverting the fail-closed intent.
    let ledger = ledger();
    let outcome = ledger.mint_at(u64::MAX, None, DAY);
    assert!(matches!(outcome, Err(LedgerError::Clock)));
}

#[test]
fn minted_tokens_are_distinct() {
    let ledger = ledger();
    let a = ledger.mint_at(1_000, None, DAY).unwrap();
    let b = ledger.mint_at(1_000, None, DAY).unwrap();
    assert_ne!(a.token, b.token, "each mint draws a fresh random token");
    assert_ne!(a.relay_id, b.relay_id);
}
