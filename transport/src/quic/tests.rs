use std::net::{Ipv4Addr, SocketAddr};

use super::*;
use crate::test_util::self_signed;

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

/// A peer advertising an ALPN the server does not offer is rejected at the
/// TLS handshake instead of connecting and then failing later (a client edge)
/// or stalling until the acceptor's hello timeout (a mesh edge). This is the
/// rollout gate for any wire-incompatible change: the client edge and the
/// mesh establishment protocol are versioned on their own `rp2/N` and
/// `rp2-mesh/N` lines, so once a bump moves either, old and new builds simply
/// can't form a connection on it.
///
/// The server advertises both current ALPNs and its task drives its end of
/// the handshake to completion, so the test can assert *both* ends fail and
/// the client can't pass by failing on a dropped server instead of on ALPN.
/// The matching-ALPN success case is the positive control in
/// [`loopback_connects_and_exchanges_a_datagram`].
#[tokio::test]
async fn rejects_a_peer_with_a_mismatched_alpn() {
    // Non-current versions of each edge's own ALPN line: neither is offered.
    for alpn in [b"rp2/0".as_slice(), b"rp2-mesh/0".as_slice()] {
        let (chain, key, ca) = self_signed();
        let server_cfg = server_config(chain, key).unwrap();

        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let server = noq::Endpoint::server(server_cfg, bind).unwrap();
        let server_addr = server.local_addr().unwrap();

        // Keep the endpoint and the incoming connection alive and drive the
        // server-side handshake to its result, so any client failure is the
        // ALPN rejection, not a server that went away mid-handshake.
        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("a connection arrived");
            incoming.await
        });

        // A dialer identical to the real one except for the ALPN it offers.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(ring_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![alpn.to_vec()];
        let mismatched_cfg =
            noq::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));

        let client = noq::Endpoint::client(bind).unwrap();
        client.set_default_client_config(mismatched_cfg);

        let client_result = client.connect(server_addr, "localhost").unwrap().await;
        let server_result = server_task.await.unwrap();

        let name = String::from_utf8_lossy(alpn);
        assert!(
            client_result.is_err(),
            "a client offering {name} must fail the handshake",
        );
        assert!(
            server_result.is_err(),
            "the server must reject a handshake offering {name}",
        );
    }
}
