//! A lobby command written onto a link whose path silently died: the write
//! succeeds locally and the connection only times out later, so nothing reports
//! the loss. The driver's re-send on its next connection is what delivers it,
//! paced so that even a relay that has never seen the history admits all of it.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rally_point_client::{ClientEndpoint, LinkDriver, Reconnect};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_transport::quic::client_config;
use rally_point_transport::rustls::pki_types::CertificateDer;
use rally_point_transport::{noq, rustls};
use tokio::net::UdpSocket;

use super::helpers::{
    KID, TENANT, client_endpoint, identity_for, make_tenant, registry_for, start_relay,
    start_relay_killable,
};

/// A UDP forwarder in front of the relay whose path can be cut: while cut, it
/// drops every datagram in both directions, the way a black-holed route does,
/// without either end seeing anything but silence.
struct CuttablePath {
    addr: SocketAddr,
    cut: Arc<AtomicBool>,
}

impl CuttablePath {
    async fn start(relay: SocketAddr) -> Self {
        let front = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let addr = front.local_addr().unwrap();
        let cut = Arc::new(AtomicBool::new(false));
        let cut_in = Arc::clone(&cut);
        tokio::spawn(async move {
            let mut upstreams = std::collections::HashMap::new();
            let mut buf = vec![0u8; 65_536];
            while let Ok((len, source)) = front.recv_from(&mut buf).await {
                let upstream = match upstreams.get(&source) {
                    Some(upstream) => Arc::clone(upstream),
                    None => {
                        let upstream =
                            Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
                        upstream.connect(relay).await.unwrap();
                        upstreams.insert(source, Arc::clone(&upstream));
                        let (reply_front, reply_upstream, cut) = (
                            Arc::clone(&front),
                            Arc::clone(&upstream),
                            Arc::clone(&cut_in),
                        );
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 65_536];
                            while let Ok(len) = reply_upstream.recv(&mut buf).await {
                                if !cut.load(Ordering::Relaxed) {
                                    let _ = reply_front.send_to(&buf[..len], source).await;
                                }
                            }
                        });
                        upstream
                    }
                };
                if !cut_in.load(Ordering::Relaxed) {
                    let _ = upstream.send(&buf[..len]).await;
                }
            }
        });
        Self { addr, cut }
    }

    fn set_cut(&self, cut: bool) {
        self.cut.store(cut, Ordering::Relaxed);
    }
}

/// The next lobby command the peer's game receives, within `within`.
async fn recv_lobby(
    rx: &mut tokio::sync::mpsc::Receiver<(SlotId, Vec<u8>)>,
    within: Duration,
) -> (SlotId, Vec<u8>) {
    tokio::time::timeout(within, rx.recv())
        .await
        .expect("a lobby command never reached the peer")
        .expect("the peer's lobby channel closed")
}

#[tokio::test]
async fn a_lobby_command_written_into_a_dead_path_is_delivered_after_the_reconnect() {
    let tenant = make_tenant(KID, TENANT);
    let (relay_addr, ca) = start_relay(registry_for(&[&tenant]));
    let path = CuttablePath::start(relay_addr).await;
    let session = SessionId(120);

    // The host (slot 0) reaches the relay only through the cuttable path, with
    // reconnection; the peer (slot 1) dials directly.
    let endpoint0 = client_endpoint(&ca);
    let id0 = identity_for(&tenant, session, SlotId(0));
    let link0 = endpoint0
        .connect(path.addr, "localhost", &id0)
        .await
        .unwrap();
    let (driver0, chan0) = LinkDriver::new(link0);
    let reconnect0 = Reconnect {
        endpoint: ClientEndpoint::from_endpoint(endpoint0.endpoint().clone()),
        relay_addr: path.addr,
        fallback_addrs: Vec::new(),
        server_name: "localhost".to_owned(),
        relay_id: 1,
        identity: id0,
        rehome: None,
        escalate_after: None,
        escalate_retry: None,
        fresh_port_redials: false,
    };
    let task0 = tokio::spawn(driver0.run_reconnecting(reconnect0));

    let endpoint1 = client_endpoint(&ca);
    let id1 = identity_for(&tenant, session, SlotId(1));
    let link1 = endpoint1
        .connect(relay_addr, "localhost", &id1)
        .await
        .unwrap();
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let task1 = tokio::spawn(driver1.run());

    chan0.lobby_out.send(vec![0x01]).await.unwrap();
    assert_eq!(
        recv_lobby(&mut chan1.lobby_in, Duration::from_secs(5)).await,
        (SlotId(0), vec![0x01])
    );

    // The path dies under the host's next command: the write succeeds into the
    // host's stream and goes nowhere.
    path.set_cut(true);
    chan0.lobby_out.send(vec![0x02]).await.unwrap();

    // The relay lets go of the silent link at its idle timeout, which the peer
    // sees as the host disconnecting. Then the path heals, and the host's
    // driver re-dials and re-sends everything it authored.
    loop {
        let change = tokio::time::timeout(Duration::from_secs(20), chan1.connectivity.recv())
            .await
            .expect("the relay never dropped the silent link")
            .expect("the peer's connectivity channel closed");
        if change == (SlotId(0), false) {
            break;
        }
    }
    path.set_cut(false);

    assert_eq!(
        recv_lobby(&mut chan1.lobby_in, Duration::from_secs(20)).await,
        (SlotId(0), vec![0x02]),
        "the command lost with the dead link arrives, and the one already delivered is not repeated",
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), chan1.lobby_in.recv())
            .await
            .is_err(),
        "each lobby command reaches the peer's game once",
    );

    drop(chan0);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}

/// A client endpoint trusting both relays' certificates, so one driver can
/// re-dial from one relay to the other.
fn endpoint_trusting(cas: &[&CertificateDer<'static>]) -> ClientEndpoint {
    let mut roots = rustls::RootCertStore::empty();
    for ca in cas {
        roots.add((*ca).clone()).unwrap();
    }
    let endpoint = noq::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    endpoint.set_default_client_config(client_config(roots).unwrap());
    ClientEndpoint::from_endpoint(endpoint)
}

#[tokio::test]
async fn a_history_longer_than_the_relays_burst_reaches_a_fresh_relay_whole() {
    // One more command than the relay's per-slot burst. Written at once, the
    // last would be rate-dropped and reach no one until the next reconnect's
    // re-send. Paced, a relay that has never seen any of them accepts all of
    // them at once: first relay A on the live sends, then relay B, which knows
    // nothing of the session, on the re-send after A dies.
    let history = rally_point_proto::lobby::RATE_BURST as u8 + 1;
    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(121);
    let (addr_a, ca_a, endpoint_a) = start_relay_killable(
        registry_for(&[&tenant]),
        rally_point_relay::mesh::MeshState::default(),
    );
    let (addr_b, ca_b) = start_relay(registry_for(&[&tenant]));
    let endpoint = endpoint_trusting(&[&ca_a, &ca_b]);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let link0 = endpoint.connect(addr_a, "localhost", &id0).await.unwrap();
    let (driver0, chan0) = LinkDriver::new(link0);
    let reconnect0 = Reconnect {
        endpoint: ClientEndpoint::from_endpoint(endpoint.endpoint().clone()),
        relay_addr: addr_a,
        fallback_addrs: vec![addr_b],
        server_name: "localhost".to_owned(),
        relay_id: 1,
        identity: id0,
        rehome: None,
        escalate_after: None,
        escalate_retry: None,
        fresh_port_redials: false,
    };
    let task0 = tokio::spawn(driver0.run_reconnecting(reconnect0));

    let id2 = identity_for(&tenant, session, SlotId(2));
    let link2 = endpoint.connect(addr_a, "localhost", &id2).await.unwrap();
    let (driver2, mut chan2) = LinkDriver::new(link2);
    let task2 = tokio::spawn(driver2.run());

    for byte in 0..history {
        chan0.lobby_out.send(vec![byte]).await.unwrap();
    }
    // The pacer spreads the history over several seconds.
    let within = Duration::from_secs(30);
    for byte in 0..history {
        assert_eq!(
            recv_lobby(&mut chan2.lobby_in, within).await,
            (SlotId(0), vec![byte]),
            "relay A accepts the whole history, in order",
        );
    }

    // Relay A dies. The host re-dials, reaches B over its fallback address, and
    // re-sends the history to a relay that has seen none of it.
    endpoint_a.close(noq::VarInt::from_u32(0), b"relay died");
    drop(chan2);
    let _ = task2.await;
    let id1 = identity_for(&tenant, session, SlotId(1));
    let link1 = endpoint.connect(addr_b, "localhost", &id1).await.unwrap();
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let task1 = tokio::spawn(driver1.run());
    for byte in 0..history {
        assert_eq!(
            recv_lobby(&mut chan1.lobby_in, within).await,
            (SlotId(0), vec![byte]),
            "relay B accepts the whole re-sent history, in order",
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(300), chan1.lobby_in.recv())
            .await
            .is_err(),
        "each lobby command reaches the peer's game once",
    );

    drop(chan0);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}
