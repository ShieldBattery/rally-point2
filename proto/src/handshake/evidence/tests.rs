use super::*;
use crate::token::CHALLENGE_DOMAIN_TAG;

fn request() -> EvidenceRequest {
    EvidenceRequest {
        challenge: [0x11; 32],
        channel_binding: [0x22; 32],
        tenant: TenantId("ténant".into()),
        session: SessionId(0x0102030405060708),
        slot: SlotId(3),
        client_pubkey: ClientPublicKey([0x44; 32]),
    }
}

#[test]
fn empty_frame_is_none() {
    assert_eq!(encode_evidence_frame(None).unwrap(), [0, 0]);
    assert_eq!(decode_evidence_len([0, 0]).unwrap(), 0);
    assert_eq!(decode_evidence(&[]).unwrap(), None);
}

#[test]
fn payload_round_trips_at_both_bounds() {
    for body_len in [0, 1, MAX_EVIDENCE_BODY_LEN] {
        let evidence = Evidence {
            key_id: 0x01020304,
            body: vec![0xab; body_len],
            signature: Signature([0x55; SIGNATURE_LEN]),
        };
        let frame = encode_evidence_frame(Some(&evidence)).unwrap();
        let len = decode_evidence_len(frame[..2].try_into().unwrap()).unwrap();
        assert_eq!(len, 68 + body_len);
        assert_eq!(frame.len(), 2 + len);
        assert_eq!(&frame[2..6], &[4, 3, 2, 1]);
        assert_eq!(&frame[6..70], &[0x55; SIGNATURE_LEN]);
        assert_eq!(decode_evidence(&frame[2..]).unwrap(), Some(evidence));
    }
}

#[test]
fn rejects_every_truncated_header() {
    for len in 1..68 {
        let error = HandshakeError::MalformedEvidence { len };
        assert_eq!(
            decode_evidence_len((len as u16).to_le_bytes()),
            Err(error.clone())
        );
        assert_eq!(decode_evidence(&vec![0; len]), Err(error));
    }
}

#[test]
fn caps_prefix_payload_and_encoding() {
    for len in [MAX_EVIDENCE_LEN + 1, u16::MAX as usize] {
        let error = HandshakeError::EvidenceTooLong { len };
        assert_eq!(
            decode_evidence_len((len as u16).to_le_bytes()),
            Err(error.clone())
        );
        assert_eq!(decode_evidence(&vec![0; len]), Err(error));
    }
    let evidence = Evidence {
        key_id: 7,
        body: vec![0; MAX_EVIDENCE_BODY_LEN + 1],
        signature: Signature([0; SIGNATURE_LEN]),
    };
    assert_eq!(
        encode_evidence_frame(Some(&evidence)),
        Err(HandshakeError::EvidenceTooLong {
            len: MAX_EVIDENCE_LEN + 1,
        })
    );
}

#[test]
fn canonical_message_layout() {
    let message = request().signed_message(0x11223344, &[0xaa, 0xbb]);
    assert_eq!(message[0], 0x02);
    assert_ne!(message[0], CHALLENGE_DOMAIN_TAG);
    assert_eq!(&message[1..33], &[0x11; 32]);
    assert_eq!(&message[33..65], &[0x22; 32]);
    assert_eq!(&message[65..73], &[7, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&message[73..80], "ténant".as_bytes());
    assert_eq!(&message[80..88], &[8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(message[88], 3);
    assert_eq!(&message[89..121], &[0x44; 32]);
    assert_eq!(&message[121..125], &[0x44, 0x33, 0x22, 0x11]);
    assert_eq!(&message[125..], &[0xaa, 0xbb]);
}

#[test]
fn every_context_field_changes_the_signed_message() {
    let base = request();
    let signed = base.signed_message(5, b"body");
    let mut changes = Vec::new();
    let mut changed = base.clone();
    changed.challenge[0] ^= 1;
    changes.push(changed);
    let mut changed = base.clone();
    changed.channel_binding[0] ^= 1;
    changes.push(changed);
    let mut changed = base.clone();
    changed.tenant.0.push('x');
    changes.push(changed);
    let mut changed = base.clone();
    changed.session.0 += 1;
    changes.push(changed);
    let mut changed = base.clone();
    changed.slot.0 += 1;
    changes.push(changed);
    let mut changed = base.clone();
    changed.client_pubkey.0[0] ^= 1;
    changes.push(changed);
    for changed in changes {
        assert_ne!(changed.signed_message(5, b"body"), signed);
    }
    assert_ne!(base.signed_message(6, b"body"), signed);
    assert_ne!(base.signed_message(5, b"body2"), signed);
}

#[test]
fn tenant_length_separates_context_from_body() {
    let mut first = request();
    first.tenant = TenantId("a".into());
    first.session = SessionId(0);
    first.slot = SlotId(0);
    first.client_pubkey = ClientPublicKey([0; 32]);
    let mut second = first.clone();
    second.tenant.0.push('\0');
    // Without the tenant length these are the same concatenation of bytes.
    assert_ne!(first.signed_message(0, &[0]), second.signed_message(0, &[]));
}
