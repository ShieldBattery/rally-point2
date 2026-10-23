use super::*;
use crate::control::TenantId;
use crate::handshake::{EvidenceRequest, MAX_EVIDENCE_BODY_LEN, MAX_EVIDENCE_LEN};
use crate::ids::{SessionId, SlotId};
use crate::token::{ClientPublicKey, Signature};

fn context() -> PeriodicEvidenceContext {
    PeriodicEvidenceContext {
        challenge_id: 7,
        nonce: [9; 32],
        assignment_revision: 2,
        check: EvidenceCheck::FullImage,
    }
}

#[test]
fn challenge_layout_round_trip_and_rejections() {
    let value = context();
    let bytes = encode_periodic_challenge(&value).unwrap();
    assert_eq!(&bytes[..8], &7u64.to_le_bytes());
    assert_eq!(&bytes[8..40], &[9; 32]);
    assert_eq!(&bytes[40..48], &2u64.to_le_bytes());
    assert_eq!(bytes[48], 1);
    assert_eq!(decode_periodic_challenge(&bytes).unwrap(), value);
    let mut bad = bytes;
    bad[..8].fill(0);
    assert_eq!(
        decode_periodic_challenge(&bad),
        Err(PeriodicEvidenceError::ZeroChallengeId)
    );
    assert!(
        encode_periodic_challenge(&PeriodicEvidenceContext {
            challenge_id: 0,
            ..value
        })
        .is_err()
    );
    for check in [0, 2, 255] {
        bad = bytes;
        bad[48] = check;
        assert_eq!(
            decode_periodic_challenge(&bad),
            Err(PeriodicEvidenceError::UnknownCheck(check))
        );
    }
}

#[test]
fn response_round_trips_absent_empty_and_maximum_body() {
    let absent = encode_periodic_response(7, None).unwrap();
    assert_eq!(absent.len(), PERIODIC_RESPONSE_HEADER_LEN);
    assert_eq!(
        decode_periodic_response(absent.as_slice().try_into().unwrap(), &[]).unwrap(),
        (7, None)
    );
    for len in [0, 1, MAX_EVIDENCE_BODY_LEN] {
        let evidence = Evidence {
            key_id: 3,
            signature: Signature([4; 64]),
            body: vec![5; len],
        };
        let bytes = encode_periodic_response(7, Some(&evidence)).unwrap();
        let header = bytes[..PERIODIC_RESPONSE_HEADER_LEN].try_into().unwrap();
        assert_eq!(
            decode_periodic_response_header(header).unwrap(),
            (7, 68 + len)
        );
        assert_eq!(
            decode_periodic_response(header, &bytes[PERIODIC_RESPONSE_HEADER_LEN..]).unwrap(),
            (7, Some(evidence))
        );
    }
}

#[test]
fn response_rejects_zero_id_and_every_invalid_header_length_before_reading() {
    assert!(encode_periodic_response(0, None).is_err());
    assert_eq!(
        decode_periodic_response_header(&[0; PERIODIC_RESPONSE_HEADER_LEN]),
        Err(PeriodicEvidenceError::ZeroChallengeId)
    );
    for len in 1..=u16::MAX {
        if (68..=MAX_EVIDENCE_LEN).contains(&usize::from(len)) {
            continue;
        }
        let mut header = [0; PERIODIC_RESPONSE_HEADER_LEN];
        header[..8].copy_from_slice(&7u64.to_le_bytes());
        header[8..].copy_from_slice(&len.to_le_bytes());
        assert!(decode_periodic_response_header(&header).is_err());
    }
    let oversized = Evidence {
        key_id: 3,
        signature: Signature([4; 64]),
        body: vec![0; MAX_EVIDENCE_BODY_LEN + 1],
    };
    assert!(encode_periodic_response(7, Some(&oversized)).is_err());
}

#[test]
fn response_requires_exact_payload_length() {
    let evidence = Evidence {
        key_id: 3,
        signature: Signature([4; 64]),
        body: vec![5],
    };
    let bytes = encode_periodic_response(7, Some(&evidence)).unwrap();
    let header = bytes[..PERIODIC_RESPONSE_HEADER_LEN].try_into().unwrap();
    for len in [0, 68, 70, MAX_EVIDENCE_LEN + 1] {
        assert_eq!(
            decode_periodic_response(header, &vec![0; len]),
            Err(PeriodicEvidenceError::PayloadLength {
                expected: 69,
                actual: len
            })
        );
    }
}

fn request() -> EvidenceRequest {
    EvidenceRequest {
        periodic: Some(context()),
        challenge: [1; 32],
        channel_binding: [2; 32],
        tenant: TenantId("tenant".into()),
        session: SessionId(3),
        slot: SlotId(4),
        client_pubkey: ClientPublicKey([5; 32]),
    }
}

#[test]
fn periodic_signed_layout_keeps_connection_context_and_opaque_body_last() {
    let periodic = request();
    let mut admission = periodic.clone();
    admission.periodic = None;
    let old = admission.signed_message(8, b"body");
    let new = periodic.signed_message(8, b"body");
    let context_start = old.len() - 4 - 4;
    assert_eq!(new[0], 3);
    assert_eq!(old[0], 2);
    assert_eq!(&new[1..context_start], &old[1..context_start]);
    assert_eq!(
        &new[context_start..context_start + PERIODIC_CHALLENGE_LEN],
        &encode_periodic_challenge(&context()).unwrap()
    );
    assert_eq!(
        &new[context_start + PERIODIC_CHALLENGE_LEN..],
        &old[context_start..]
    );
}

#[test]
fn every_periodic_and_connection_field_changes_signed_bytes() {
    let base = request();
    let original = base.signed_message(8, b"body");
    let mut changed = Vec::new();
    let mut next = base.clone();
    next.challenge[0] ^= 1;
    changed.push(next);
    let mut next = base.clone();
    next.channel_binding[0] ^= 1;
    changed.push(next);
    let mut next = base.clone();
    next.tenant.0.push('x');
    changed.push(next);
    let mut next = base.clone();
    next.session.0 += 1;
    changed.push(next);
    let mut next = base.clone();
    next.slot.0 += 1;
    changed.push(next);
    let mut next = base.clone();
    next.client_pubkey.0[0] ^= 1;
    changed.push(next);
    let mut next = base.clone();
    next.periodic.as_mut().unwrap().challenge_id += 1;
    changed.push(next);
    let mut next = base.clone();
    next.periodic.as_mut().unwrap().nonce[0] ^= 1;
    changed.push(next);
    let mut next = base.clone();
    next.periodic.as_mut().unwrap().assignment_revision += 1;
    changed.push(next);
    let mut next = base.clone();
    next.periodic = None;
    changed.push(next);
    for next in changed {
        assert_ne!(next.signed_message(8, b"body"), original);
    }
    assert_ne!(base.signed_message(9, b"body"), original);
    assert_ne!(base.signed_message(8, b"other"), original);
    // FullImage is the only constructible check. Its exact signed discriminant is
    // asserted in the layout test; unknown discriminants are rejected by decoding.
}
