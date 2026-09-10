//! Tests for the transport link, split by subject.
//!
//! This file holds only what the topic modules share: a self-signed loopback
//! QUIC pair in either raw or `Link`-wrapped form, and the tiny turn builder.
//! Each topic module opens with `use super::*;`, inheriting both these
//! fixtures and the link's own items.

use std::net::{Ipv4Addr, SocketAddr};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::*;
use crate::quic::{client_config, server_config};

mod admission;
mod dedup;
mod delivery;
mod ingress;
mod resume;

fn self_signed() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    (vec![cert_der.clone()], key, cert_der)
}

/// Brings up a loopback QUIC connection, returning both raw ends plus the
/// endpoints (kept alive by the caller). The caller wraps each connection as a
/// [`Link`] however the test needs — [`Link::new`] or [`Link::with_ingress_slot`].
async fn connected_connections() -> (
    noq::Connection,
    noq::Connection,
    noq::Endpoint,
    noq::Endpoint,
) {
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

/// Brings up a loopback QUIC connection and wraps each end in a plain [`Link`].
/// The endpoints are returned so the caller keeps them alive for the test.
async fn connected_links() -> (Link, Link, noq::Endpoint, noq::Endpoint) {
    let (client_conn, server_conn, client, server) = connected_connections().await;
    (
        Link::new(client_conn),
        Link::new(server_conn),
        client,
        server,
    )
}

fn turn(slot: u8, seq: u64, byte: u8) -> Payload {
    Payload {
        seq,
        slot: u32::from(slot),
        commands: vec![byte].into(),
        ..Default::default()
    }
}
