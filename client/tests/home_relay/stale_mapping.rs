//! Re-dialing past a NAT mapping that went bad under the session's local port: a
//! public IP change can leave the mapping for a live flow translating to the old
//! address, so the client's datagrams still reach the relay but nothing the relay
//! sends back reaches the client, and the client's own re-dials keep that mapping
//! from ever expiring. A re-dial that fails moves the next one onto a fresh local
//! port, which the NAT maps anew.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rally_point_client::{ClientEndpoint, LinkDriver, Reconnect};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_transport::noq;
use tokio::net::UdpSocket;

use super::helpers::{
    KID, TENANT, client_endpoint, identity_for, make_tenant, started_session_relay,
    wait_connectivity,
};

/// A UDP forwarder in front of the relay that behaves like a NAT: each client source
/// address gets an upstream socket of its own, and what the relay sends to that socket
/// is passed back to the source. A source can be made stale, after which its datagrams
/// still reach the relay but the relay's replies to it are dropped.
struct StaleableNat {
    addr: SocketAddr,
    stale: Arc<Mutex<HashSet<SocketAddr>>>,
    /// Datagrams forwarded to the relay from a source after it went stale.
    stale_sends: Arc<AtomicUsize>,
}

impl StaleableNat {
    async fn start(relay: SocketAddr) -> Self {
        let front = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let addr = front.local_addr().unwrap();
        let stale = Arc::new(Mutex::new(HashSet::new()));
        let stale_sends = Arc::new(AtomicUsize::new(0));

        let (stale_in, sends) = (Arc::clone(&stale), Arc::clone(&stale_sends));
        tokio::spawn(async move {
            let mut upstreams: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
            let mut buf = vec![0u8; 65_536];
            loop {
                let Ok((len, source)) = front.recv_from(&mut buf).await else {
                    return;
                };
                let upstream = match upstreams.get(&source) {
                    Some(upstream) => Arc::clone(upstream),
                    None => {
                        let upstream =
                            Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
                        upstream.connect(relay).await.unwrap();
                        upstreams.insert(source, Arc::clone(&upstream));
                        let (reply_front, reply_upstream, stale) = (
                            Arc::clone(&front),
                            Arc::clone(&upstream),
                            Arc::clone(&stale_in),
                        );
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 65_536];
                            while let Ok(len) = reply_upstream.recv(&mut buf).await {
                                if !stale.lock().unwrap().contains(&source) {
                                    let _ = reply_front.send_to(&buf[..len], source).await;
                                }
                            }
                        });
                        upstream
                    }
                };
                if stale_in.lock().unwrap().contains(&source) {
                    sends.fetch_add(1, Ordering::Relaxed);
                }
                let _ = upstream.send(&buf[..len]).await;
            }
        });

        Self {
            addr,
            stale,
            stale_sends,
        }
    }

    fn make_stale(&self, source: SocketAddr) {
        self.stale.lock().unwrap().insert(source);
    }
}

#[tokio::test]
async fn a_re_dial_moves_to_a_fresh_port_when_the_sessions_mapping_went_stale() {
    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(110);
    let (relay_addr, ca) = started_session_relay(&tenant, session, &[SlotId(0), SlotId(1)]);
    let nat = StaleableNat::start(relay_addr).await;

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));

    // Slot 0 reaches the relay only through the NAT, on an endpoint of its own so its
    // local port is the session's alone.
    let endpoint0 = client_endpoint(&ca);
    let link0 = endpoint0
        .connect(nat.addr, "localhost", &id0)
        .await
        .unwrap();
    let conn0 = link0.connection().clone();
    let (driver0, mut chan0) = LinkDriver::new(link0);
    let reconnect0 = Reconnect {
        endpoint: ClientEndpoint::from_endpoint(endpoint0.endpoint().clone()),
        relay_addr: nat.addr,
        fallback_addrs: Vec::new(),
        server_name: "localhost".to_owned(),
        relay_id: 1,
        identity: id0,
        rehome: None,
        escalate_after: None,
        escalate_retry: None,
        fresh_port_redials: true,
    };
    let task0 = tokio::spawn(driver0.run_reconnecting(reconnect0));

    let endpoint1 = client_endpoint(&ca);
    let link1 = endpoint1
        .connect(relay_addr, "localhost", &id1)
        .await
        .unwrap();
    let (driver1, chan1) = LinkDriver::new(link1);
    let task1 = tokio::spawn(driver1.run());

    tokio::time::timeout(Duration::from_secs(5), chan0.session_start.recv())
        .await
        .expect("session start never fired")
        .expect("slot 0's session-start channel closed");

    // The mapping for the session's port goes stale, and the link drops.
    let session_local = endpoint0.endpoint().local_addr().unwrap();
    nat.make_stale(session_local);
    conn0.close(noq::VarInt::from_u32(0), b"simulated network drop");
    wait_connectivity(&mut chan0.connectivity, (SlotId(0), false)).await;

    // The first re-dial goes out through the stale mapping and times out; the next
    // one, from a fresh port, gets through.
    wait_connectivity(&mut chan0.connectivity, (SlotId(0), true)).await;
    assert!(
        nat.stale_sends.load(Ordering::Relaxed) > 0,
        "a re-dial was made through the stale mapping first",
    );
    let resumed_local = endpoint0.endpoint().local_addr().unwrap();
    assert_ne!(
        resumed_local.port(),
        session_local.port(),
        "the resumed link runs on a fresh port",
    );

    drop(chan0.outbound);
    drop(chan0.inbound);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}
