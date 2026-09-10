//! Shared fixtures for the mesh-link tests: a loopback QUIC connection wrapped
//! at both ends, plus the payload and conditions builders every topic uses.
//!
//! The tests themselves are split by subject into the submodules below; each
//! pulls these helpers in with `use super::*`.

use std::net::{Ipv4Addr, SocketAddr};

use rally_point_proto::messages::Packet;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use super::*;
use crate::quic::{mesh_client_config, server_config};

mod conditions;
mod demux;
mod dial;
mod receive;
mod send_budget;

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

/// Brings up a loopback QUIC connection negotiated on `MESH_ALPN` and wraps
/// each end in a `MeshLink`. Both endpoints are returned so the caller keeps
/// them alive for the test.
async fn connected_mesh_links() -> (MeshLink, MeshLink, noq::Endpoint, noq::Endpoint) {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let client_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();

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

    (
        MeshLink::new(client_conn),
        MeshLink::new(server_conn),
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

/// size, capping the sender's `max_datagram_size` toward it — a stand-in
/// for any connection whose datagram budget sits near the payloads riding
/// it (a small peer limit, or a path fallen back to the MTU floor).
async fn connected_mesh_links_with_datagram_limit(
    limit: usize,
) -> (MeshLink, MeshLink, noq::Endpoint, noq::Endpoint) {
    let (chain, key, ca) = self_signed();
    let mut server_cfg = server_config(chain, key).unwrap();
    let mut transport = noq::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(limit));
    server_cfg.transport_config(std::sync::Arc::new(transport));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let client_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();

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

    (
        MeshLink::new(client_conn),
        MeshLink::new(server_conn),
        client,
        server,
    )
}

/// The largest conditions sidecar a real game can produce, using the same
/// field values as the relay hot-path benchmark. Each slot has a distinct,
/// stable physical-connection generation, matching production rather than
/// the legacy epoch-less rolling-upgrade shape.
fn full_epoch_conditions() -> LinkConditions {
    LinkConditions {
        slots: (0..8u32)
            .map(|slot| rally_point_proto::messages::SlotConditions {
                slot,
                rtt_us: 25_000 + slot * 7_000,
                lost_packets: u64::from(slot) * 3,
                sent_packets: 10_024,
                connection_epoch: Some(0xC0DE_0000_0000_0000 | u64::from(slot)),
            })
            .collect(),
    }
}
