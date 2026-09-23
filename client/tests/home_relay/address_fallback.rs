//! Reaching a relay over another of its addresses when the path to one dies: a
//! same-relay re-dial and a re-home dial each move past an address that never
//! answers — a client whose IPv6 path failed mid-game while IPv4 still works — to
//! the relay's next address, instead of re-dialing the dead one until the drop is
//! decided.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use rally_point_client::{ClientEndpoint, LinkDriver, Reconnect, RehomeFuture, RehomeOutcome};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_transport::noq;
use rally_point_transport::rustls::pki_types::CertificateDer;

use super::helpers::{
    KID, TENANT, client_endpoint, identity_for, make_tenant, recv_turn, registry_for,
    seed_session_authority, start_relay_killable, started_session_relay, wait_connectivity,
};

/// A bound UDP socket nothing ever reads: a QUIC dial to it gets no answer and no
/// ICMP rejection, so it runs out its whole dial timeout — the way a dial over a
/// dead IP family fails.
fn black_hole() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = socket.local_addr().unwrap();
    (socket, addr)
}

#[tokio::test]
async fn a_re_dial_moves_past_an_unreachable_address_to_the_relays_next_one() {
    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(100);
    let (addr, ca) = started_session_relay(&tenant, session, &[SlotId(0), SlotId(1)]);
    let endpoint = client_endpoint(&ca);
    let (_hole, dead_addr) = black_hole();

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));

    // Slot 0's first re-dial address stopped answering after the initial connect;
    // the relay itself is still reachable at its other address.
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let conn0 = link0.connection().clone();
    let (driver0, mut chan0) = LinkDriver::new(link0);
    let reconnect0 = Reconnect {
        endpoint: ClientEndpoint::from_endpoint(endpoint.endpoint().clone()),
        relay_addr: dead_addr,
        fallback_addrs: vec![addr],
        server_name: "localhost".to_owned(),
        relay_id: 1,
        identity: id0,
        rehome: None,
        escalate_after: None,
        escalate_retry: None,
    };
    let task0 = tokio::spawn(driver0.run_reconnecting(reconnect0));

    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver1, chan1) = LinkDriver::new(link1);
    let task1 = tokio::spawn(driver1.run());

    tokio::time::timeout(Duration::from_secs(5), chan0.session_start.recv())
        .await
        .expect("session start never fired")
        .expect("slot 0's session-start channel closed");

    conn0.close(noq::VarInt::from_u32(0), b"simulated network drop");
    wait_connectivity(&mut chan0.connectivity, (SlotId(0), false)).await;
    // The first re-dial burns its timeout on the dead address; the next one reaches
    // the relay over its other address.
    wait_connectivity(&mut chan0.connectivity, (SlotId(0), true)).await;

    // The resumed link carries turns again.
    chan1
        .outbound
        .send(Payload {
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(recv_turn(&mut chan0.inbound).await.seq, 0);

    drop(chan0.outbound);
    drop(chan0.inbound);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}

/// A re-home provider handing back a replacement relay whose most-preferred
/// address never answers, with the working one as its fallback.
struct DeadFirstAddress {
    ca: CertificateDer<'static>,
    dead_addr: SocketAddr,
    live_addr: SocketAddr,
}

impl rally_point_client::RehomeProvider for DeadFirstAddress {
    fn rehome(&self, _dead_relay_id: u64) -> RehomeFuture<'_> {
        let ca = self.ca.clone();
        let (dead_addr, live_addr) = (self.dead_addr, self.live_addr);
        Box::pin(async move {
            RehomeOutcome::NewTarget {
                relay_id: 2,
                endpoint: client_endpoint(&ca),
                relay_addr: dead_addr,
                fallback_addrs: vec![live_addr],
                server_name: "localhost".to_owned(),
            }
        })
    }
}

#[tokio::test]
async fn a_re_home_dials_the_replacements_next_address_when_its_first_is_unreachable() {
    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(101);
    let slots = [SlotId(0)];

    let mesh_a = rally_point_relay::mesh::MeshState::default();
    seed_session_authority(&mesh_a, &tenant, session, &slots);
    let (addr_a, ca_a, endpoint_a) = start_relay_killable(registry_for(&[&tenant]), mesh_a);

    // The replacement, seeded as an already-started resumed session.
    let mesh_b = rally_point_relay::mesh::MeshState::default();
    let key = seed_session_authority(&mesh_b, &tenant, session, &slots);
    mesh_b.session.decision_makers.mark_started(&key);
    let (addr_b, ca_b, _endpoint_b) = start_relay_killable(registry_for(&[&tenant]), mesh_b);
    let (_hole, dead_addr) = black_hole();

    let id0 = identity_for(&tenant, session, SlotId(0));
    let ep0 = client_endpoint(&ca_a);
    let link0 = ep0.connect(addr_a, "localhost", &id0).await.unwrap();
    let (driver0, mut chan0) = LinkDriver::new(link0);
    let reconnect0 = Reconnect {
        endpoint: ep0,
        relay_addr: addr_a,
        fallback_addrs: Vec::new(),
        server_name: "localhost".to_owned(),
        relay_id: 1,
        identity: id0,
        rehome: Some(Arc::new(DeadFirstAddress {
            ca: ca_b,
            dead_addr,
            live_addr: addr_b,
        })),
        escalate_after: Some(Duration::from_millis(50)),
        escalate_retry: Some(Duration::from_millis(50)),
    };
    let task0 = tokio::spawn(driver0.run_reconnecting(reconnect0));

    tokio::time::timeout(Duration::from_secs(5), chan0.session_start.recv())
        .await
        .expect("session start never fired")
        .expect("slot 0's session-start channel closed");

    // Relay A dies, so the driver escalates; the replacement's first address burns
    // its dial timeout and the walk moves on to the one that answers.
    endpoint_a.close(noq::VarInt::from_u32(0), b"relay A down");
    wait_connectivity(&mut chan0.connectivity, (SlotId(0), false)).await;
    wait_connectivity(&mut chan0.connectivity, (SlotId(0), true)).await;

    drop(chan0.outbound);
    drop(chan0.inbound);
    let _ = task0.await;
}
