use super::*;
use rally_point_proto::control::EvidenceKey;
use rally_point_proto::token::Signature;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn fixture() -> (EvidenceRequest, Evidence, EvidenceConfig) {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[9; 32]).unwrap();
    let request = EvidenceRequest {
        challenge: [1; 32],
        channel_binding: [2; 32],
        tenant: TenantId("tenant".into()),
        session: SessionId(3),
        slot: SlotId(4),
        client_pubkey: ClientPublicKey([5; 32]),
    };
    let body = b"opaque".to_vec();
    let evidence = Evidence {
        key_id: 7,
        signature: Signature(
            pair.sign(&request.signed_message(7, &body))
                .as_ref()
                .try_into()
                .unwrap(),
        ),
        body,
    };
    let config = EvidenceConfig {
        keys: vec![EvidenceKey {
            key_id: 7,
            public_key: ClientPublicKey(pair.public_key().as_ref().try_into().unwrap()),
        }],
        required_slots: [SlotId(4)].into_iter().collect(),
        assignments: [(SlotId(4), 11)].into_iter().collect(),
    };
    (request, evidence, config)
}

#[test]
fn only_verified_frames_retain_the_body() {
    let (request, evidence, config) = fixture();
    let valid = verify_evidence(&request, Some(evidence.clone()), &config);
    assert_eq!(valid.verdict, EvidenceVerdict::Valid);
    assert_eq!(valid.assignment_revision, 11);
    assert_eq!(valid.connection_id, request.challenge);
    assert_eq!(valid.key_id, Some(7));
    assert_eq!(valid.body, evidence.body);
    assert_eq!(
        verify_evidence(&request, None, &config).verdict,
        EvidenceVerdict::Missing
    );
    let unknown = verify_evidence(&request, Some(evidence.clone()), &EvidenceConfig::default());
    assert_eq!(unknown.verdict, EvidenceVerdict::UnknownKey);
    assert!(unknown.body.is_empty());
    assert_eq!(unknown.key_id, Some(7));
    let mut bad = evidence;
    bad.signature.0[0] ^= 1;
    let invalid = verify_evidence(&request, Some(bad.clone()), &config);
    assert_eq!(invalid.verdict, EvidenceVerdict::Invalid);
    assert!(invalid.body.is_empty());
    assert_eq!(invalid.key_id, Some(7));
}

#[test]
fn every_connection_field_and_the_body_are_signed() {
    let (request, evidence, config) = fixture();
    let mutations: [fn(&mut EvidenceRequest); 6] = [
        |r| r.challenge[0] ^= 1,
        |r| r.channel_binding[0] ^= 1,
        |r| r.tenant.0.push('x'),
        |r| r.session.0 += 1,
        |r| r.slot.0 += 1,
        |r| r.client_pubkey.0[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = request.clone();
        mutate(&mut changed);
        assert_eq!(
            verify_evidence(&changed, Some(evidence.clone()), &config).verdict,
            EvidenceVerdict::Invalid
        );
    }
    let mut changed = evidence;
    changed.body.push(0);
    assert_eq!(
        verify_evidence(&request, Some(changed), &config).verdict,
        EvidenceVerdict::Invalid
    );
}
