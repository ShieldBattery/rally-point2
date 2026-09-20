//! Loopback fixtures every crate's tests bring a QUIC pair up with: a
//! self-signed certificate and a connected pair of endpoints on either ALPN.
//!
//! Compiled for this crate's own tests and, behind the `test-util` feature, for
//! the dependents' tests (client, relay, coordinator) — so the cert helper and
//! the loopback bring-up live once instead of once per test module.

use std::net::{Ipv4Addr, SocketAddr};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::noq;
use crate::quic::{client_config, mesh_client_config, server_config};

/// A one-command turn for `slot` at `seq`, tagged with `byte` so a test can
/// tell which turn came back. The seq is assigned upstream and carried end to
/// end, so tests set it directly rather than expecting it to be assigned.
#[cfg(test)]
pub(crate) fn turn(slot: u8, seq: u64, byte: u8) -> rally_point_proto::messages::Payload {
    rally_point_proto::messages::Payload {
        seq,
        slot: u32::from(slot),
        commands: vec![byte].into(),
        ..Default::default()
    }
}

/// A fresh self-signed `localhost` certificate: the chain a server presents, its
/// private key, and the certificate alone to seed a dialer's trust roots.
pub fn self_signed() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    (vec![cert_der.clone()], key, cert_der)
}

/// Which link type a loopback pair is negotiated as — the ALPN and whether the
/// dialer presents a certificate of its own (a mesh peer does, a game client
/// never does).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    /// A client ↔ relay link (`quic::ALPN`, no client certificate).
    Client,
    /// A relay ↔ relay link (`quic::MESH_ALPN`, dialer presents a certificate).
    Mesh,
}

/// Brings up a loopback QUIC connection on `edge`: `(dialer, acceptor,
/// dialer_endpoint, acceptor_endpoint)`. The endpoints are returned so the
/// caller keeps them alive for as long as the connections are used.
pub async fn loopback(
    edge: Edge,
) -> (
    noq::Connection,
    noq::Connection,
    noq::Endpoint,
    noq::Endpoint,
) {
    loopback_with(edge, |_| {}).await
}

/// [`loopback`] with the acceptor's datagram receive buffer capped at `limit`
/// bytes, so the dialer's discovered `max_datagram_size` sits near the payloads
/// riding the link — the shape of a small peer limit or a path fallen back to
/// the MTU floor.
pub async fn loopback_with_datagram_limit(
    edge: Edge,
    limit: usize,
) -> (
    noq::Connection,
    noq::Connection,
    noq::Endpoint,
    noq::Endpoint,
) {
    loopback_with(edge, |server_cfg| {
        let mut transport = noq::TransportConfig::default();
        transport.datagram_receive_buffer_size(Some(limit));
        server_cfg.transport_config(std::sync::Arc::new(transport));
    })
    .await
}

async fn loopback_with(
    edge: Edge,
    tune_server: impl FnOnce(&mut noq::ServerConfig),
) -> (
    noq::Connection,
    noq::Connection,
    noq::Endpoint,
    noq::Endpoint,
) {
    let (chain, key, ca) = self_signed();
    let mut server_cfg = server_config(chain, key).unwrap();
    tune_server(&mut server_cfg);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let client_cfg = match edge {
        Edge::Client => client_config(roots).unwrap(),
        Edge::Mesh => {
            let (dial_chain, dial_key, _) = self_signed();
            mesh_client_config(roots, dial_chain, dial_key).unwrap()
        }
    };

    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server = noq::Endpoint::server(server_cfg, bind).unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = noq::Endpoint::client(bind).unwrap();
    client.set_default_client_config(client_cfg);

    let accept = {
        let server = server.clone();
        tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() })
    };
    let client_conn = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let server_conn = accept.await.unwrap();

    (client_conn, server_conn, client, server)
}
