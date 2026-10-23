//! The real client against a peer that implements the authorization stream directly.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rally_point_client::{
    ClientEndpoint, DialError, DriverError, Identity, LinkDriver, Reconnect, RehomeFuture,
    RehomeOutcome, RehomeProvider,
};
use rally_point_proto::close_codes;
use rally_point_proto::control::TenantId;
use rally_point_proto::handshake::{self, Evidence, EvidenceRequest};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::token::{
    CHANNEL_BINDING_EXPORTER_LABEL, ClientPublicKey, ConnectionChallenge, ExpiresAt, KeyId,
    Signature, SignedToken, TokenClaims,
};
use rally_point_transport::test_util::self_signed;
use rally_point_transport::{noq, quic, rustls};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey};

fn identity() -> Identity {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let claims = TokenClaims::new(
        TenantId("test".into()),
        SessionId(7),
        SlotId(0),
        ExpiresAt(u64::MAX),
        ClientPublicKey(key.public_key().as_ref().try_into().unwrap()),
    );
    let token = SignedToken::from_parts(KeyId("test".into()), claims, Signature([0; 64]));
    Identity::from_pkcs8(token, pkcs8.as_ref()).unwrap()
}

fn endpoints(legacy: bool) -> (noq::Endpoint, ClientEndpoint) {
    endpoints_with_alpn(legacy.then_some(quic::LEGACY_ALPN))
}

fn endpoints_with_alpn(alpn: Option<&[u8]>) -> (noq::Endpoint, ClientEndpoint) {
    let (chain, key, ca) = self_signed();
    let config = if let Some(alpn) = alpn {
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
        // This peer offers exactly the selected older protocol.
        tls.alpn_protocols = vec![alpn.to_vec()];
        let crypto = noq::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        noq::ServerConfig::with_crypto(Arc::new(crypto))
    } else {
        quic::server_config(chain, key).unwrap()
    };
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server = noq::Endpoint::server(config, bind).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    (server, ClientEndpoint::bind(roots).unwrap())
}

async fn read_original_handshake(
    server: &noq::Endpoint,
    resume_cursor: Option<u64>,
) -> (
    noq::Connection,
    noq::SendStream,
    noq::RecvStream,
    EvidenceRequest,
) {
    let connection = server.accept().await.unwrap().await.unwrap();
    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
    let mut prefix = [0; 2];
    recv.read_exact(&mut prefix).await.unwrap();
    let mut token = vec![0; usize::from(u16::from_le_bytes(prefix))];
    recv.read_exact(&mut token).await.unwrap();
    let token = SignedToken::decode(&token).unwrap();
    let challenge = [0x31; 32];
    send.write_all(&challenge).await.unwrap();
    let mut response = [0; 64];
    recv.read_exact(&mut response).await.unwrap();
    let mut binding = [0; 32];
    connection
        .export_keying_material(&mut binding, CHANNEL_BINDING_EXPORTER_LABEL, &[])
        .unwrap();
    UnparsedPublicKey::new(&ring::signature::ED25519, token.claims.client_pubkey.0)
        .verify(
            &ConnectionChallenge(challenge).signed_message(&binding),
            &response,
        )
        .unwrap();
    recv.read_exact(&mut prefix).await.unwrap();
    let count = u16::from_le_bytes(prefix);
    assert_eq!(count, u16::from(resume_cursor.is_some()));
    if let Some(cursor) = resume_cursor {
        let mut entry = [0; 9];
        recv.read_exact(&mut entry).await.unwrap();
        assert_eq!(entry[0], 0);
        assert_eq!(&entry[1..], &cursor.to_le_bytes());
    }
    let request = EvidenceRequest {
        periodic: None,
        challenge,
        channel_binding: binding,
        tenant: token.claims.tenant,
        session: token.claims.session,
        slot: token.claims.slot,
        client_pubkey: token.claims.client_pubkey,
    };
    (connection, send, recv, request)
}

#[tokio::test]
async fn legacy_peer_gets_original_framing_and_never_calls_provider() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, client) = endpoints(true);
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = calls.clone();
        let identity = identity().with_evidence_provider(move |_| {
            callback_calls.fetch_add(1, Ordering::Relaxed);
            None
        });
        for resumed in [false, true] {
            let accept = async {
                let (connection, mut send, mut recv, _) =
                    read_original_handshake(&server, resumed.then_some(7)).await;
                assert!(!quic::supports_evidence(&connection));
                send.write_all(&[0x01]).await.unwrap();
                // The original exchange ends immediately after resume cursors. Even a zero
                // evidence length would add two unexpected bytes before the stream's FIN.
                assert!(recv.read_to_end(2).await.unwrap().is_empty());
                connection
            };
            let dial = async {
                let address = server.local_addr().unwrap();
                if resumed {
                    client
                        .reconnect_with_timeout(
                            address,
                            "localhost",
                            &identity,
                            &[(SlotId(0), 7)],
                            Duration::from_secs(3),
                        )
                        .await
                } else {
                    client.connect(address, "localhost", &identity).await
                }
            };
            let (accepted, link) = tokio::join!(accept, dial);
            let link = link.unwrap();
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            link.connection().close(0u32.into(), b"done");
            drop(accepted);
        }
    })
    .await
    .expect("the original handshake must finish without an evidence frame");
}

#[tokio::test]
async fn evidence_policy_close_is_classified_on_fresh_and_resume_dials() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, client) = endpoints(false);
        let identity = identity().with_evidence_provider(|_| {
            Some(Evidence {
                key_id: 7,
                body: vec![],
                signature: Signature([0; 64]),
            })
        });
        for resumed in [false, true] {
            let accept = async {
                let (connection, _send, mut recv, _) =
                    read_original_handshake(&server, resumed.then_some(7)).await;
                assert!(quic::supports_evidence(&connection));
                assert!(read_evidence(&mut recv).await.is_some());
                connection.close(close_codes::EVIDENCE_REJECTED.into(), b"connection refused");
                connection
            };
            let dial = async {
                let address = server.local_addr().unwrap();
                if resumed {
                    client
                        .reconnect_with_timeout(
                            address,
                            "localhost",
                            &identity,
                            &[(SlotId(0), 7)],
                            Duration::from_secs(3),
                        )
                        .await
                } else {
                    client.connect(address, "localhost", &identity).await
                }
            };
            let (_accepted, result) = tokio::join!(accept, dial);
            assert!(matches!(result, Err(DialError::EvidenceRejected)));
        }
    })
    .await
    .expect("an evidence refusal must terminate both kinds of dial");
}

async fn read_evidence(recv: &mut noq::RecvStream) -> Option<Evidence> {
    let mut prefix = [0; 2];
    recv.read_exact(&mut prefix).await.unwrap();
    let mut payload = vec![0; handshake::decode_evidence_len(prefix).unwrap()];
    recv.read_exact(&mut payload).await.unwrap();
    handshake::decode_evidence(&payload).unwrap()
}

fn signed_identity(skip_call: Option<usize>) -> (Identity, Arc<AtomicUsize>, [u8; 32]) {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public = key.public_key().as_ref().try_into().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = calls.clone();
    let identity = identity().with_evidence_provider(move |request| {
        if Some(callback_calls.fetch_add(1, Ordering::Relaxed)) == skip_call {
            return None;
        }
        let body = vec![7, 8, 9];
        Some(Evidence {
            key_id: 7,
            signature: Signature(
                key.sign(&request.signed_message(7, &body))
                    .as_ref()
                    .try_into()
                    .unwrap(),
            ),
            body,
        })
    });
    (identity, calls, public)
}

async fn accept_current(
    server: &noq::Endpoint,
    resume_cursor: Option<u64>,
    key: &[u8; 32],
) -> noq::Connection {
    let (connection, mut send, mut recv, request) =
        read_original_handshake(server, resume_cursor).await;
    let evidence = read_evidence(&mut recv).await.unwrap();
    UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(
            &request.signed_message(evidence.key_id, &evidence.body),
            &evidence.signature.0,
        )
        .unwrap();
    send.write_all(&[0x01]).await.unwrap();
    send.finish().unwrap();
    if quic::supports_periodic_evidence(&connection) {
        // This fixture ends the optional exchange without closing gameplay.
        assert!(recv.read_to_end(0).await.is_err());
    } else {
        assert!(recv.read_to_end(0).await.unwrap().is_empty());
    }
    connection
}

fn reconnect(
    endpoint: ClientEndpoint,
    identity: Identity,
    relay_addr: SocketAddr,
    rehome: Option<Arc<dyn RehomeProvider>>,
) -> Reconnect {
    Reconnect {
        endpoint,
        identity,
        relay_addr,
        fallback_addrs: vec![],
        server_name: "localhost".into(),
        relay_id: 1,
        rehome,
        escalate_after: Some(Duration::ZERO),
        escalate_retry: Some(Duration::ZERO),
        fresh_port_redials: true,
    }
}

#[tokio::test]
async fn reconnect_retries_absent_evidence_and_accepts_the_next_valid_observation() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, client) = endpoints(false);
        let address = server.local_addr().unwrap();
        let (identity, calls, key) = signed_identity(Some(1));
        let (original, link) = tokio::join!(
            accept_current(&server, None, &key),
            client.connect(address, "localhost", &identity),
        );
        let (driver, mut channels) = LinkDriver::new(link.unwrap());
        let task =
            tokio::spawn(driver.run_reconnecting(reconnect(client, identity, address, None)));
        original.close(close_codes::CONTROL_STREAM_LOST.into(), b"reconnect");

        let (missing, _send, mut recv, _) = read_original_handshake(&server, Some(0)).await;
        assert!(read_evidence(&mut recv).await.is_none());
        missing.close(
            close_codes::EVIDENCE_UNAVAILABLE.into(),
            b"connection unavailable",
        );

        let resumed = accept_current(&server, Some(0), &key).await;
        loop {
            if channels.connectivity.recv().await.unwrap() == (SlotId(0), true) {
                break;
            }
        }
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        resumed.close(close_codes::EVIDENCE_REJECTED.into(), b"connection refused");
        assert!(
            matches!(task.await.unwrap(), Err(DriverError::Evicted { code })
            if code == close_codes::EVIDENCE_REJECTED)
        );
    })
    .await
    .expect("missing evidence must allow a later successful reconnect");
}

struct Replacement {
    endpoint: Mutex<Option<ClientEndpoint>>,
    address: SocketAddr,
    calls: AtomicUsize,
}

impl RehomeProvider for Replacement {
    fn rehome(&self, _dead_relay_id: u64) -> RehomeFuture<'_> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let outcome = RehomeOutcome::NewTarget {
            relay_id: 2,
            endpoint: self
                .endpoint
                .lock()
                .unwrap()
                .take()
                .expect("only one rehome ask"),
            relay_addr: self.address,
            // If the terminal refusal is ignored, this address changes the error into
            // a retryable dial failure and the driver asks for another replacement.
            fallback_addrs: vec![(Ipv4Addr::LOCALHOST, 0).into()],
            server_name: "localhost".into(),
        };
        Box::pin(std::future::ready(outcome))
    }
}

#[tokio::test]
async fn rehome_stops_on_rejected_evidence_without_trying_fallback_addresses() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (server, client) = endpoints(false);
        let (replacement_server, replacement_client) = endpoints(false);
        let replacement = Arc::new(Replacement {
            endpoint: Mutex::new(Some(replacement_client)),
            address: replacement_server.local_addr().unwrap(),
            calls: AtomicUsize::new(0),
        });
        let (identity, _, key) = signed_identity(None);
        let (original, link) = tokio::join!(
            accept_current(&server, None, &key),
            client.connect(server.local_addr().unwrap(), "localhost", &identity),
        );
        let (driver, mut channels) = LinkDriver::new(link.unwrap());
        let task = tokio::spawn(driver.run_reconnecting(reconnect(
            client,
            identity,
            (Ipv4Addr::LOCALHOST, 0).into(),
            Some(replacement.clone()),
        )));
        let (mut control, _recv) = original.open_bi().await.unwrap();
        rally_point_transport::control::send_control_session_start(&mut control, None)
            .await
            .unwrap();
        channels.session_start.recv().await.unwrap();
        original.close(close_codes::CONTROL_STREAM_LOST.into(), b"rehome");

        // A replacement needs no own-slot anchor when this client has never sent a turn.
        let (refused, _send, mut recv, _) =
            read_original_handshake(&replacement_server, None).await;
        assert!(read_evidence(&mut recv).await.is_some());
        refused.close(close_codes::EVIDENCE_REJECTED.into(), b"connection refused");
        assert!(matches!(
            task.await.unwrap(),
            Err(DriverError::EvidenceRejected)
        ));
        assert_eq!(replacement.calls.load(Ordering::Relaxed), 1);
    })
    .await
    .expect("rehome evidence rejection must be terminal");
}

#[tokio::test]
async fn admission_only_peer_finishes_the_handshake_stream() {
    let (server, client) = endpoints_with_alpn(Some(quic::EVIDENCE_ALPN));
    let address = server.local_addr().unwrap();
    let identity = identity();
    let dial = client.connect(address, "localhost", &identity);
    let peer = async {
        let (connection, mut send, mut recv, _) = read_original_handshake(&server, None).await;
        let mut length = [0; 2];
        recv.read_exact(&mut length).await.unwrap();
        assert_eq!(length, [0; 2]);
        send.write_all(&[handshake::HANDSHAKE_OK]).await.unwrap();
        assert_eq!(recv.read(&mut [0]).await.unwrap(), None);
        assert!(!quic::supports_periodic_evidence(&connection));
        connection
    };
    let (link, peer) =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(dial, peer) })
            .await
            .unwrap();
    let link = link.unwrap();
    assert!(!quic::supports_periodic_evidence(link.connection()));
    assert!(peer.close_reason().is_none());
}
