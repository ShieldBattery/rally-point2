//! Extra client-edge ports: one relay serving several UDP ports is still one
//! relay, and an extra port that cannot bind never keeps the primary from
//! serving.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::helpers::*;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_relay::routing::Sessions;
use rally_point_relay::server;
use rally_point_transport::noq;
use rally_point_transport::quic::server_config;

#[tokio::test]
async fn slots_dialing_different_ports_share_one_session() {
    let tenant = make_default_tenant();
    let (chain, key, ca) = self_signed();
    let cfg = server_config(chain, key).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let primary = noq::Endpoint::server(cfg.clone(), bind).unwrap();
    let extra = noq::Endpoint::server(cfg, bind).unwrap();
    let (primary_addr, extra_addr) = (primary.local_addr().unwrap(), extra.local_addr().unwrap());
    let sessions: Sessions = Arc::default();
    tokio::spawn(server::serve_all(
        vec![primary, extra],
        Arc::new(registry_for_one(&tenant)),
        Arc::clone(&sessions),
        rally_point_relay::mesh::MeshState::default(),
        None,
    ));

    let endpoint = client_endpoint(&ca);
    let session = SessionId(7);
    let mut slot0 = connect_slot(&endpoint, primary_addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, extra_addr, &tenant, session, SlotId(1)).await;

    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            commands: vec![0x05].into(),
            ..Default::default()
        }))
        .unwrap();
    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = slot1.recv().await.unwrap().fresh;
    }
    assert_eq!(
        delivered[0].slot, 0,
        "slot 0's turn crossed to the other port"
    );
}

#[tokio::test]
async fn an_extra_port_that_cannot_bind_is_skipped() {
    let (chain, key, _ca) = self_signed();
    let cfg = server_config(chain, key).unwrap();
    // Hold the extra port for the whole call, so its bind is refused.
    let taken = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let taken_port = taken.local_addr().unwrap().port();

    let endpoints =
        server::bind_endpoints(cfg, (Ipv4Addr::LOCALHOST, 0).into(), &[taken_port]).unwrap();

    assert_eq!(endpoints.len(), 1, "only the primary endpoint is bound");
    assert_ne!(endpoints[0].local_addr().unwrap().port(), taken_port);
}
