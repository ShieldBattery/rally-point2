use super::*;
use crate::consensus::{Authority, EvidenceConfig, MakerSync, RelayNotice};
use rally_point_proto::control::{BufferBounds, EvidenceVerdict};

fn activation(revision: u64) -> Activation {
    Activation {
        connection_epoch: 1,
        resumed_dial: true,
        evidence: crate::auth::CheckedEvidence {
            connection_id: [1; 32],
            assignment_revision: revision,
            verdict: EvidenceVerdict::Valid,
            key_id: Some(7),
            body: vec![8],
        },
    }
}

#[test]
fn activation_refusals_preserve_the_cause_and_publish_nothing() {
    let mesh = crate::mesh::MeshState::default();
    let key = crate::test_support::session_key(42);
    let makers = &mesh.session.decision_makers;
    makers.require_descriptors();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(tx);
    let _ = makers.sync_maker(
        &key,
        MakerSync {
            evidence: EvidenceConfig {
                assignments: [(SlotId(0), 2)].into_iter().collect(),
                ..Default::default()
            },
            ..MakerSync::new(BufferBounds::new(1, 6).unwrap(), Authority::SelfRelay)
        },
    );
    let refused = with_activation(&mesh, &key, SlotId(0), activation(1), || {
        panic!("stale assignment must not publish activation state")
    })
    .unwrap_err();
    assert_eq!(refused, ActivationRefusal::AssignmentChanged);
    assert_eq!(refused.code(), close_codes::SLOT_NOT_HOMED);
    assert!(makers.retained_load_state(&key).evidence.is_empty());
    assert!(rx.try_recv().is_err());

    let published = std::cell::Cell::new(false);
    assert_eq!(
        with_activation(&mesh, &key, SlotId(0), activation(2), || {
            published.set(true);
        }),
        Ok(())
    );
    assert!(published.get());
    assert!(matches!(
        rx.try_recv().unwrap(),
        RelayNotice::SlotConnected(_)
    ));
    let retained = makers.retained_load_state(&key).evidence;

    mesh.session.gates.retire(&key);
    let refused = with_activation(&mesh, &key, SlotId(0), activation(2), || {
        panic!("retirement must not publish activation state")
    })
    .unwrap_err();
    assert_eq!(refused, ActivationRefusal::Retired);
    assert_eq!(refused.code(), close_codes::SESSION_RETIRED);
    assert_eq!(makers.retained_load_state(&key).evidence, retained);
    assert!(rx.try_recv().is_err());
}
