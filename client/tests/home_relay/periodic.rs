//! Real admission and periodic evidence share the authorization stream while
//! the normal drivers continue forwarding gameplay turns.

use std::time::Duration;

use rally_point_client::LinkDriver;
use rally_point_proto::control::{BufferBounds, EvidenceKey, EvidenceVerdict, TenantId};
use rally_point_proto::handshake::{Evidence, EvidenceCheck};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_proto::token::{ClientPublicKey, Signature};
use rally_point_relay::consensus::{Authority, EvidenceConfig, MakerSync};
use rally_point_relay::key::SessionKey;
use rally_point_relay::mesh::MeshState;
use ring::signature::{Ed25519KeyPair, KeyPair};

use super::helpers::{
    KID, TENANT, client_endpoint, identity_for, make_tenant, recv_turn, registry_for,
    start_relay_killable,
};

#[tokio::test]
async fn signed_periodic_evidence_crosses_the_real_auth_stream_during_turn_traffic() {
    tokio::time::timeout(Duration::from_secs(75), roundtrip())
        .await
        .expect("periodic evidence did not complete within its first sampling interval");
}

async fn roundtrip() {
    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(852);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let signer = Ed25519KeyPair::from_seed_unchecked(&[27; 32]).unwrap();
    let public_key = ClientPublicKey(signer.public_key().as_ref().try_into().unwrap());
    let mesh = MeshState::default();
    let makers = &mesh.session.decision_makers;
    makers.require_descriptors();
    let _ = makers.sync_maker(
        &key,
        MakerSync {
            expected_slots: [SlotId(0), SlotId(1)].into_iter().collect(),
            homed_slots: [SlotId(0), SlotId(1)].into_iter().collect(),
            evidence: EvidenceConfig {
                periodic: true,
                keys: vec![EvidenceKey {
                    key_id: 17,
                    public_key,
                }],
                assignments: [(SlotId(0), 4), (SlotId(1), 6)].into_iter().collect(),
                ..Default::default()
            },
            ..MakerSync::new(BufferBounds::new(0, 20).unwrap(), Authority::SelfRelay)
        },
    );
    let (addr, ca, relay) = start_relay_killable(registry_for(&[&tenant]), mesh.clone());
    let endpoint = client_endpoint(&ca);
    let (requests_tx, mut requests) = tokio::sync::mpsc::unbounded_channel();
    let identity0 =
        identity_for(&tenant, session, SlotId(0)).with_evidence_provider(move |request| {
            let body = if request.periodic.is_some() {
                vec![2, 3, 4]
            } else {
                vec![1]
            };
            let signature = Signature(
                signer
                    .sign(&request.signed_message(17, &body))
                    .as_ref()
                    .try_into()
                    .unwrap(),
            );
            requests_tx.send(request).unwrap();
            Some(Evidence {
                key_id: 17,
                body,
                signature,
            })
        });
    let identity1 = identity_for(&tenant, session, SlotId(1));
    let link0 = endpoint
        .connect(addr, "localhost", &identity0)
        .await
        .unwrap();
    let (driver0, mut channels0) = LinkDriver::new(link0);
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(driver0.run());
    let link1 = endpoint
        .connect(addr, "localhost", &identity1)
        .await
        .unwrap();
    let (driver1, mut channels1) = LinkDriver::new(link1);
    tasks.spawn(driver1.run());
    channels0.session_start.recv().await.unwrap();
    channels1.session_start.recv().await.unwrap();
    let admission_request = requests.recv().await.unwrap();
    assert!(admission_request.periodic.is_none());
    let admission = makers.retained_load_state(&key).evidence;
    let admission0 = &admission
        .iter()
        .find(|entry| entry.slot == SlotId(0))
        .unwrap()
        .observation;
    assert_eq!(admission0.verdict, EvidenceVerdict::Valid);
    assert_eq!(admission0.body, vec![1]);
    channels0.game_started.send(()).await.unwrap();
    channels1.game_started.send(()).await.unwrap();

    let mut turns = 0;
    let periodic = loop {
        // Keep both directions active throughout the real 30-60 second jitter,
        // so silence/drop handling cannot mask the auxiliary stream's behavior.
        let turn = Payload {
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        };
        channels0.outbound.send(turn.clone()).await.unwrap();
        channels1.outbound.send(turn.clone()).await.unwrap();
        let received0 = recv_turn(&mut channels0.inbound).await;
        let received1 = recv_turn(&mut channels1.inbound).await;
        assert_eq!((received0.slot, received1.slot), (1, 0));
        assert_eq!((received0.seq, received1.seq), (turns, turns));
        assert_eq!(received0.commands, turn.commands);
        assert_eq!(received1.commands, turn.commands);
        turns += 1;
        let state = makers.retained_load_state(&key);
        assert_eq!(
            state.evidence, admission,
            "periodic samples must preserve admission"
        );
        if let Some(entry) = state
            .periodic_evidence
            .into_iter()
            .find(|entry| entry.slot == SlotId(0))
        {
            break entry.observation;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert!(turns > 1);
    let request = requests.recv().await.unwrap();
    let context = request.periodic.as_ref().unwrap();
    assert_eq!(context.challenge_id, 1);
    assert_eq!(context.assignment_revision, 4);
    assert_eq!(context.check, EvidenceCheck::FullImage);
    assert_ne!(context.nonce, [0; 32]);
    assert_eq!(request.challenge, admission_request.challenge);
    assert_eq!(request.channel_binding, admission_request.channel_binding);
    assert_eq!(request.tenant, admission_request.tenant);
    assert_eq!(request.session, session);
    assert_eq!(request.slot, SlotId(0));
    assert_eq!(request.client_pubkey, admission_request.client_pubkey);
    assert_eq!(periodic.verdict, EvidenceVerdict::Valid);
    assert_eq!(periodic.key_id, Some(17));
    assert_eq!(periodic.body, vec![2, 3, 4]);
    assert_eq!(periodic.sample_id, context.challenge_id);
    assert_eq!(periodic.assignment_revision, context.assignment_revision);
    assert_eq!(periodic.connection_id, admission_request.challenge);
    assert!(periodic.sequence > admission0.sequence);
    // A verified sample leaves the gameplay transport usable afterward too.
    channels0.outbound.send(Payload::default()).await.unwrap();
    let after = recv_turn(&mut channels1.inbound).await;
    assert_eq!((after.slot, after.seq), (0, turns));
    assert!(after.commands.is_empty());
    relay.close(0u32.into(), b"test complete");
    tasks.shutdown().await;
}
