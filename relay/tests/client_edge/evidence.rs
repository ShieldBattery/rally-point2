use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::close_codes;
use rally_point_proto::control::{EvidenceKey, EvidenceVerdict, SlotEvidenceAssignment, TenantId};
use rally_point_proto::handshake::{self, Evidence, EvidenceRequest};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::{
    CHANNEL_BINDING_EXPORTER_LABEL, ClientPublicKey, ConnectionChallenge, Signature,
};
use rally_point_relay::consensus::RelayNotice;
use rally_point_relay::key::SessionKey;
use rally_point_relay::mesh::{MeshState, control::MeshControl};
use rally_point_transport::{noq, rustls};

fn managed_relay(tenant: &Tenant) -> TestRelay {
    let mesh = MeshState::default();
    mesh.session.decision_makers.require_descriptors();
    start_relay_with_mesh(registry_for_one(tenant), mesh)
}

fn install(relay: &TestRelay, session: SessionId, signer: &Keypair, required: Vec<SlotId>) {
    let mut value = descriptor(TENANT, session);
    value.evidence_keys = vec![EvidenceKey {
        key_id: 7,
        public_key: ClientPublicKey(signer.public),
    }];
    value.required_evidence_slots = required;
    value.evidence_assignments = (0..4)
        .map(|slot| SlotEvidenceAssignment {
            slot: SlotId(slot),
            revision: 1,
        })
        .collect();
    MeshControl::new(RelayId(1), &relay.mesh, relay.sessions.clone()).apply_descriptor(&value);
}

fn key(session: SessionId) -> SessionKey {
    SessionKey {
        tenant: TenantId(TENANT.into()),
        session,
    }
}

async fn present(
    connection: &noq::Connection,
    tenant: &Tenant,
    session: SessionId,
    slot: SlotId,
    frame: impl FnOnce(EvidenceRequest) -> Vec<u8>,
) -> (noq::SendStream, noq::RecvStream) {
    let client_key = keypair();
    let token = mint_token(tenant, session, slot, client_key.public);
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&handshake::encode_token_frame(&token).unwrap())
        .await
        .unwrap();
    let mut challenge = [0; 32];
    recv.read_exact(&mut challenge).await.unwrap();
    let mut channel_binding = [0; 32];
    connection
        .export_keying_material(&mut channel_binding, CHANNEL_BINDING_EXPORTER_LABEL, &[])
        .unwrap();
    send.write_all(
        &client_key.sign(&ConnectionChallenge(challenge).signed_message(&channel_binding)),
    )
    .await
    .unwrap();
    send.write_all(&handshake::encode_resume_cursors(&[]).unwrap())
        .await
        .unwrap();
    if rally_point_transport::quic::supports_evidence(connection) {
        send.write_all(&frame(EvidenceRequest {
            periodic: None,
            challenge,
            channel_binding,
            tenant: token.claims.tenant,
            session,
            slot,
            client_pubkey: token.claims.client_pubkey,
        }))
        .await
        .unwrap();
    }
    (send, recv)
}

fn signed(request: &EvidenceRequest, signer: &Keypair, key_id: u32) -> Vec<u8> {
    let body = vec![1, 2, 3];
    let evidence = Evidence {
        key_id,
        signature: Signature(signer.sign(&request.signed_message(key_id, &body))),
        body,
    };
    handshake::encode_evidence_frame(Some(&evidence)).unwrap()
}

async fn refused(connection: &noq::Connection, recv: &mut noq::RecvStream, code: u32) {
    assert!(recv.read_exact(&mut [0; 1]).await.is_err());
    match connection.closed().await {
        noq::ConnectionError::ApplicationClosed(error) => {
            assert_eq!(u64::from(error.error_code), u64::from(code))
        }
        error => panic!("expected application refusal, got {error:?}"),
    }
}

#[tokio::test]
async fn required_evidence_is_checked_before_registration_and_drop_hold_mutation() {
    let tenant = make_default_tenant();
    let relay = managed_relay(&tenant);
    let endpoint = client_endpoint(&relay.ca);
    let signer = keypair();
    let session = SessionId(701);
    let session_key = key(session);
    install(&relay, session, &signer, vec![SlotId(0)]);
    relay
        .mesh
        .session
        .drop_holds
        .hold(session_key.clone(), SlotId(0));
    for case in 0..3 {
        let connection = endpoint
            .connect(relay.addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let wrong_key = keypair();
        let (_send, mut recv) =
            present(
                &connection,
                &tenant,
                session,
                SlotId(0),
                |request| match case {
                    0 => handshake::encode_evidence_frame(None).unwrap(),
                    1 => signed(&request, &signer, 99),
                    _ => signed(&request, &wrong_key, 7),
                },
            )
            .await;
        refused(
            &connection,
            &mut recv,
            if case == 0 {
                close_codes::EVIDENCE_UNAVAILABLE
            } else {
                close_codes::EVIDENCE_REJECTED
            },
        )
        .await;
        assert!(relay.sessions.lock().get(&session_key).is_none());
        assert!(
            relay
                .mesh
                .session
                .drop_holds
                .is_pending(&session_key, SlotId(0))
        );
    }
    let connection = endpoint
        .connect(relay.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (_send, mut recv) = present(&connection, &tenant, session, SlotId(0), |request| {
        signed(&request, &signer, 7)
    })
    .await;
    let mut ack = [0];
    recv.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack, [handshake::HANDSHAKE_OK]);
}

#[tokio::test]
async fn a_delayed_descriptor_cannot_be_bypassed_by_an_empty_frame() {
    let tenant = make_default_tenant();
    let relay = managed_relay(&tenant);
    let endpoint = client_endpoint(&relay.ca);
    let session = SessionId(702);
    let connection = endpoint
        .connect(relay.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (_send, mut recv) = present(&connection, &tenant, session, SlotId(0), |_| {
        handshake::encode_evidence_frame(None).unwrap()
    })
    .await;
    // The negative interval establishes that completed crypto cannot activate a
    // managed slot before its descriptor supplies the policy.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), recv.read_exact(&mut [0; 1]))
            .await
            .is_err()
    );
    assert!(relay.sessions.lock().get(&key(session)).is_none());
    install(&relay, session, &keypair(), vec![SlotId(0)]);
    refused(&connection, &mut recv, close_codes::EVIDENCE_UNAVAILABLE).await;
    assert!(relay.sessions.lock().get(&key(session)).is_none());
}

#[tokio::test]
async fn optional_verdicts_retain_only_verified_bodies() {
    let tenant = make_default_tenant();
    let relay = managed_relay(&tenant);
    let endpoint = client_endpoint(&relay.ca);
    let session = SessionId(703);
    let signer = keypair();
    install(&relay, session, &signer, vec![]);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    relay.mesh.session.decision_makers.set_notice_notifier(tx);
    let mut connections = Vec::new();
    let mut prior_sequence = 0;
    for (slot, expected) in [
        EvidenceVerdict::Missing,
        EvidenceVerdict::UnknownKey,
        EvidenceVerdict::Invalid,
        EvidenceVerdict::Valid,
    ]
    .into_iter()
    .enumerate()
    {
        let connection = endpoint
            .connect(relay.addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let wrong_key = keypair();
        let (_send, mut recv) = present(
            &connection,
            &tenant,
            session,
            SlotId(slot as u8),
            |request| match slot {
                0 => handshake::encode_evidence_frame(None).unwrap(),
                1 => signed(&request, &signer, 99),
                2 => signed(&request, &wrong_key, 7),
                _ => signed(&request, &signer, 7),
            },
        )
        .await;
        recv.read_exact(&mut [0; 1]).await.unwrap();
        let notice = loop {
            if let RelayNotice::SlotConnected(notice) =
                tokio::time::timeout(Duration::from_secs(5), rx.recv())
                    .await
                    .unwrap()
                    .unwrap()
            {
                break notice;
            }
        };
        let observation = notice.evidence.unwrap();
        assert_eq!(observation.verdict, expected);
        assert_eq!(
            observation.body,
            if expected == EvidenceVerdict::Valid {
                vec![1, 2, 3]
            } else {
                vec![]
            }
        );
        assert!(observation.sequence > prior_sequence);
        prior_sequence = observation.sequence;
        assert_eq!(observation.assignment_revision, 1);
        let retained = relay
            .mesh
            .session
            .decision_makers
            .retained_load_state(&key(session));
        assert_eq!(retained.evidence[slot].observation, observation);
        connections.push(connection);
    }
}

#[tokio::test]
async fn legacy_protocol_still_obeys_the_required_policy() {
    let tenant = make_default_tenant();
    let relay = managed_relay(&tenant);
    let session = SessionId(704);
    install(&relay, session, &keypair(), vec![SlotId(0)]);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay.ca.clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![rally_point_transport::quic::LEGACY_ALPN.to_vec()];
    let endpoint = noq::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    endpoint.set_default_client_config(noq::ClientConfig::new(Arc::new(
        noq::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    )));
    let connection = endpoint
        .connect(relay.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    assert!(!rally_point_transport::quic::supports_evidence(&connection));
    let (_send, mut recv) = present(&connection, &tenant, session, SlotId(0), |_| {
        panic!("legacy never sends a frame")
    })
    .await;
    refused(&connection, &mut recv, close_codes::EVIDENCE_UNAVAILABLE).await;
    let optional_session = SessionId(709);
    install(&relay, optional_session, &keypair(), vec![]);
    let optional = endpoint
        .connect(relay.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (_send, mut recv) = present(&optional, &tenant, optional_session, SlotId(0), |_| {
        panic!("legacy never sends a frame")
    })
    .await;
    let mut ack = [0];
    recv.read_exact(&mut ack).await.unwrap();
    assert_eq!(ack, [handshake::HANDSHAKE_OK]);
}

#[tokio::test]
async fn missing_descriptor_times_out_without_claiming_a_slot() {
    let tenant = make_default_tenant();
    let relay = managed_relay(&tenant);
    let endpoint = client_endpoint(&relay.ca);
    let session = SessionId(705);
    let connection = endpoint
        .connect(relay.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (_send, mut recv) = present(&connection, &tenant, session, SlotId(0), |_| {
        handshake::encode_evidence_frame(None).unwrap()
    })
    .await;
    tokio::time::timeout(
        Duration::from_secs(6),
        refused(&connection, &mut recv, close_codes::AUTH_TIMEOUT),
    )
    .await
    .unwrap();
    assert!(relay.sessions.lock().get(&key(session)).is_none());
    install(&relay, session, &keypair(), vec![]);
    let _link = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(0)).await;
}

#[tokio::test]
async fn oversized_evidence_prefix_is_refused_without_waiting_for_body() {
    let tenant = make_default_tenant();
    let relay = managed_relay(&tenant);
    let endpoint = client_endpoint(&relay.ca);
    let connection = endpoint
        .connect(relay.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (_send, mut recv) = present(&connection, &tenant, SessionId(706), SlotId(0), |_| {
        ((handshake::MAX_EVIDENCE_LEN + 1) as u16)
            .to_le_bytes()
            .to_vec()
    })
    .await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), recv.read_exact(&mut [0; 1]))
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn descriptor_wait_keeps_the_handshake_permit_until_admission() {
    let tenant = make_default_tenant();
    let mesh = MeshState::default();
    mesh.session.decision_makers.require_descriptors();
    let sessions = Arc::default();
    let (chain, private_key, ca) = self_signed();
    let endpoint = noq::Endpoint::server(
        rally_point_transport::quic::server_config(chain, private_key).unwrap(),
        (Ipv4Addr::LOCALHOST, 0).into(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(rally_point_relay::server::serve_with_max_pending(
        endpoint,
        Arc::new(registry_for_one(&tenant)),
        Arc::clone(&sessions),
        mesh.clone(),
        None,
        1,
    ));
    let relay = TestRelay {
        addr,
        ca,
        sessions,
        mesh,
    };
    let endpoint = client_endpoint(&relay.ca);
    let session = SessionId(708);
    let connection = endpoint
        .connect(relay.addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (_send, mut recv) = present(&connection, &tenant, session, SlotId(0), |_| {
        handshake::encode_evidence_frame(None).unwrap()
    })
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), recv.read_exact(&mut [0; 1]))
            .await
            .is_err()
    );
    assert!(
        endpoint
            .connect(relay.addr, "localhost")
            .unwrap()
            .await
            .is_err()
    );
    install(&relay, session, &keypair(), vec![]);
    recv.read_exact(&mut [0; 1]).await.unwrap();
    let _next = connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(1)).await;
}

#[tokio::test]
async fn cached_descriptor_admits_fresh_and_same_relay_reconnect_without_waiting() {
    let tenant = make_default_tenant();
    let relay = managed_relay(&tenant);
    assert!(!relay.mesh.session.provisional_turns.armed());
    let endpoint = client_endpoint(&relay.ca);
    let session = SessionId(710);
    install(&relay, session, &keypair(), vec![]);
    for _attempt in 0..2 {
        let link = tokio::time::timeout(
            Duration::from_secs(1),
            connect_slot(&endpoint, relay.addr, &tenant, session, SlotId(0)),
        )
        .await
        .expect("cached descriptor adds no admission delay");
        wait_until("activation did not complete", || {
            relay
                .mesh
                .session
                .decision_makers
                .retained_load_state(&key(session))
                .ever_connected
                .contains(&SlotId(0))
        })
        .await;
        drop(link);
        wait_until("disconnected slot was not released", || {
            relay
                .sessions
                .lock()
                .get(&key(session))
                .is_none_or(|slots| !slots.contains_key(&SlotId(0)))
        })
        .await;
    }
}

#[tokio::test]
async fn retired_sessions_refuse_before_and_during_a_descriptor_wait() {
    let tenant = make_default_tenant();
    let relay = managed_relay(&tenant);
    let endpoint = client_endpoint(&relay.ca);
    let control = MeshControl::new(RelayId(1), &relay.mesh, relay.sessions.clone());
    for (session, already_retired) in [(SessionId(711), true), (SessionId(712), false)] {
        if already_retired {
            control.end_session(&key(session));
        }
        let connection = endpoint
            .connect(relay.addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (_send, mut recv) = present(&connection, &tenant, session, SlotId(0), |_| {
            handshake::encode_evidence_frame(None).unwrap()
        })
        .await;
        if !already_retired {
            assert!(
                tokio::time::timeout(Duration::from_millis(100), recv.read_exact(&mut [0; 1]),)
                    .await
                    .is_err()
            );
            control.end_session(&key(session));
        }
        tokio::time::timeout(
            Duration::from_secs(1),
            refused(&connection, &mut recv, close_codes::SESSION_RETIRED),
        )
        .await
        .expect("retirement must not wait for the authorization deadline");
        assert!(relay.sessions.lock().get(&key(session)).is_none());
    }
}
