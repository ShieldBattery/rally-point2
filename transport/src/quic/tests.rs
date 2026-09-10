use std::net::{Ipv4Addr, SocketAddr};

use super::*;

/// A self-signed cert + key plus the cert on its own (to seed a client's
/// trust roots), for loopback tests.
fn self_signed() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    (vec![cert_der.clone()], key_der, cert_der)
}

/// Proves the pinned noq + rustls + ring stack actually completes a
/// handshake and carries a datagram over loopback — the foundation every
/// link is built on. `client_config` presents no TLS client certificate (a
/// game client never does), so this also proves `RequestClientCert`'s
/// `client_auth_mandatory: false` keeps a certificate-less dialer connecting
/// exactly as `with_no_client_auth` always did.
#[tokio::test]
async fn loopback_connects_and_exchanges_a_datagram() {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let client_cfg = client_config(roots).unwrap();

    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server = noq::Endpoint::server(server_cfg, bind).unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = noq::Endpoint::client(bind).unwrap();
    client.set_default_client_config(client_cfg);

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        conn.read_datagram().await.unwrap()
    });

    let conn = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    conn.send_datagram(prost::bytes::Bytes::from_static(b"hello"))
        .unwrap();

    let received = server_task.await.unwrap();
    assert_eq!(&received[..], b"hello");
}

/// A mesh dial presents its own certificate as its TLS client identity, and
/// the accepting side observes exactly that certificate via
/// `Connection::peer_identity` — the raw material the mesh-accept path's
/// fingerprint pin (built one layer up, in `relay::mesh_edge`) checks
/// against the coordinator's fleet set. This only proves the TLS plumbing
/// carries the certificate through; the pin comparison itself is relay-side.
#[tokio::test]
async fn mesh_dial_presents_its_client_certificate_to_the_acceptor() {
    let (server_chain, server_key, server_ca) = self_signed();
    let server_cfg = server_config(server_chain, server_key).unwrap();

    let (dial_chain, dial_key, _dial_ca) = self_signed();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(server_ca).unwrap();
    let client_cfg = mesh_client_config(roots, dial_chain.clone(), dial_key).unwrap();

    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server = noq::Endpoint::server(server_cfg, bind).unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = noq::Endpoint::client(bind).unwrap();
    client.set_default_client_config(client_cfg);

    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        incoming.await.unwrap()
    });

    let _client_conn = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let server_conn = server_task.await.unwrap();

    let peer_certs = server_conn
        .peer_identity()
        .expect("the mesh dial presented a client certificate")
        .downcast::<Vec<CertificateDer<'static>>>()
        .expect("the rustls backend's peer identity is a cert chain");
    assert_eq!(
        peer_certs.first(),
        dial_chain.first(),
        "the acceptor observes exactly the leaf the dialer presented",
    );
}

/// A peer advertising a mismatched client-edge ALPN is rejected at the TLS
/// handshake instead of connecting and then failing later. This is the
/// rollout gate for any wire-incompatible change: once a bump moves the ALPN,
/// old and new builds simply can't form a connection.
///
/// The server task drives its end of the handshake to completion and the test
/// asserts *both* ends fail, so the client can't pass by failing on a dropped
/// server instead of on ALPN. The matching-ALPN success case is the positive
/// control in [`loopback_connects_and_exchanges_a_datagram`].
#[tokio::test]
async fn rejects_a_peer_with_a_mismatched_alpn() {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();

    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server = noq::Endpoint::server(server_cfg, bind).unwrap();
    let server_addr = server.local_addr().unwrap();

    // Keep the endpoint and the incoming connection alive and drive the
    // server-side handshake to its result, so any client failure is the ALPN
    // rejection, not a server that went away mid-handshake.
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("a connection arrived");
        incoming.await
    });

    // A client identical to the real one except it advertises an ALPN the
    // server doesn't offer (`rp2/0` — no such version exists).
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"rp2/0".to_vec()];
    let mismatched_cfg = noq::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));

    let client = noq::Endpoint::client(bind).unwrap();
    client.set_default_client_config(mismatched_cfg);

    let client_result = client.connect(server_addr, "localhost").unwrap().await;
    let server_result = server_task.await.unwrap();

    assert!(
        client_result.is_err(),
        "a mismatched-ALPN client must fail the handshake"
    );
    assert!(
        server_result.is_err(),
        "the server must reject a mismatched-ALPN handshake"
    );
}

/// A relay advertising a mismatched mesh ALPN is rejected at the handshake by
/// a current relay, rather than connecting and then stalling until the
/// acceptor's hello timeout. The mesh establishment protocol is versioned on
/// its own `rp2-mesh/N` line, so any connection-shape bump is one old and new
/// builds can't negotiate.
///
/// Mirrors [`rejects_a_peer_with_a_mismatched_alpn`] for the mesh edge: the
/// server advertises both current ALPNs, and a dialer offering only a
/// non-current `rp2-mesh/0` matches neither.
#[tokio::test]
async fn rejects_a_mesh_peer_with_a_mismatched_alpn() {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();

    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server = noq::Endpoint::server(server_cfg, bind).unwrap();
    let server_addr = server.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.expect("a connection arrived");
        incoming.await
    });

    // A mesh dialer identical to the real one except it advertises an ALPN
    // the server doesn't offer (`rp2-mesh/0`) — neither current ALPN.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"rp2-mesh/0".to_vec()];
    let mismatched_cfg = noq::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));

    let client = noq::Endpoint::client(bind).unwrap();
    client.set_default_client_config(mismatched_cfg);

    let client_result = client.connect(server_addr, "localhost").unwrap().await;
    let server_result = server_task.await.unwrap();

    assert!(
        client_result.is_err(),
        "a mismatched mesh-ALPN dialer must fail the handshake"
    );
    assert!(
        server_result.is_err(),
        "the server must reject a mismatched mesh-ALPN handshake"
    );
}
