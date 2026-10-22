use super::*;
use rally_point_proto::control::{EvidenceObservation, EvidenceVerdict, SlotConnectedNotice};

#[tokio::test]
async fn load_state_projects_nonempty_evidence_to_the_tenant_contract() {
    let (setup, session) = SessionFixture::default().build();
    let state = state_over(setup);
    let relay = RelayId(1);
    let generation = state
        .lifecycle
        .enroll_relay_epoch(relay, || {
            Ok::<_, ()>(registry::enroll(
                state.setup.registry(),
                crate::test_support::hello(1, 14901).with_boot_id(7),
            ))
        })
        .unwrap();
    registry::note_boot_id(state.setup.registry(), relay, Some(7));
    state.lifecycle.register_session(
        tenant_id(),
        session,
        vec![relay],
        std::collections::HashSet::from([SlotId(0)]),
        Default::default(),
    );
    state.lifecycle.ingest_notice(
        relay,
        generation,
        crate::lifecycle::SessionNotice::SlotConnected(SlotConnectedNotice {
            tenant: tenant_id(),
            session,
            slot: SlotId(0),
            external_id: None,
            external_ref: None,
            resumed: false,
            connected_at_ms: 1,
            evidence: Some(EvidenceObservation {
                connection_id: [9; 32],
                sequence: 1,
                assignment_revision: 1,
                verdict: EvidenceVerdict::Valid,
                key_id: Some(2),
                body: vec![1, 2, 3],
            }),
        }),
    );
    let body = read_load_state(router(state), session.0).await;
    let response: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        response["evidence"],
        serde_json::json!([{
            "slot": 0,
            "observation": {
                "connectionId": "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=",
                "sequence": 1,
                "assignmentRevision": 1,
                "verdict": "valid",
                "keyId": 2,
                "body": "AQID",
            }
        }])
    );
}
