//! Failover to a replacement relay: a fixed re-home provider standing in for
//! the embedder's coordinator round-trip, a full two-relay failover proving
//! exactly-once turn delivery across the move, and the receive-window
//! regression for a client resuming its own slot's seq stream at a high
//! anchor on the fresh relay.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_transport::noq;
use rally_point_transport::rustls::pki_types::CertificateDer;

use super::helpers::{
    KID, TENANT, client_endpoint, identity_for, make_tenant, recv_turn, registry_for,
    start_relay_killable, start_relay_with_mesh, wait_connectivity,
};

/// A re-home provider that always hands back a fixed replacement relay's target,
/// building a fresh client endpoint that pins the replacement's cert on each call —
/// standing in for the embedder's coordinator round-trip + cert pinning. It also
/// asserts the driver passes the relay id it is homed on as the dead relay, and
/// hands back the replacement relay's own id — the driver-owns-the-id contract.
struct FixedTarget {
    ca: CertificateDer<'static>,
    addr: SocketAddr,
    /// The relay id the driver must name as dead (the home relay it is on).
    expected_dead: u64,
    /// The replacement relay's id, returned in the `NewTarget` outcome.
    relay_id: u64,
}

impl rally_point_client::RehomeProvider for FixedTarget {
    fn rehome(&self, dead_relay_id: u64) -> rally_point_client::RehomeFuture<'_> {
        assert_eq!(
            dead_relay_id, self.expected_dead,
            "the driver must name the relay it is homed on as the dead one",
        );
        let ca = self.ca.clone();
        let addr = self.addr;
        let relay_id = self.relay_id;
        Box::pin(async move {
            rally_point_client::RehomeOutcome::NewTarget {
                relay_id,
                endpoint: client_endpoint(&ca),
                relay_addr: addr,
                server_name: "localhost".to_owned(),
            }
        })
    }
}

#[tokio::test]
async fn a_group_re_homes_to_a_replacement_relay_when_the_home_dies() {
    use std::collections::HashSet;

    use rally_point_client::{LinkDriver, Reconnect};
    use rally_point_proto::control::BufferBounds;
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;

    // The full coordinator-mediated failover path against two real relays: both
    // slots home on relay A; A dies; each driver escalates to its re-home provider,
    // which hands relay B's target; both re-home onto B (which the coordinator would
    // have pushed a `resumed` descriptor to — here seeded as already-started); a turn
    // slot 0 sent before the death reaches slot 1 exactly once (the retention ring's
    // re-injection deduped against what slot 1 already had), and a fresh turn after
    // the re-home flows over B.
    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(80);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Relay A (the home). Seed its maker started with the two expected slots so it
    // records forwarded turns and fires session-start.
    let mesh_a = rally_point_relay::mesh::new_mesh_state();
    let _ = consensus::sync_maker(
        &mesh_a.decision_makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    let (addr_a, ca_a, endpoint_a) = start_relay_killable(registry_for(&[&tenant]), mesh_a);

    // Relay B (the replacement). Seed it as a resumed session (already started), as a
    // rehome descriptor from the coordinator would.
    let mesh_b = rally_point_relay::mesh::new_mesh_state();
    let _ = consensus::sync_maker(
        &mesh_b.decision_makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    consensus::mark_session_started(&mesh_b.decision_makers, &key);
    let (addr_b, ca_b, _endpoint_b) = start_relay_killable(registry_for(&[&tenant]), mesh_b);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));

    // Per-slot client endpoints trusting relay A, used for the initial connect and
    // then moved into each `Reconnect` for same-relay re-dials.
    let ep0 = client_endpoint(&ca_a);
    let ep1 = client_endpoint(&ca_a);

    let link0 = ep0.connect(addr_a, "localhost", &id0).await.unwrap();
    let (driver0, mut chan0) = LinkDriver::new(link0);
    let link1 = ep1.connect(addr_a, "localhost", &id1).await.unwrap();
    let (driver1, mut chan1) = LinkDriver::new(link1);

    // Both drivers re-home to relay B when A stays unreachable. A short escalation
    // window keeps the test fast (a cert/pin rejection would escalate at once; here
    // the dead relay just stops responding, so the timed window drives it).
    // Relay A is id 1 (the home the drivers start on); relay B is id 2 (the
    // replacement). The drivers seed their current relay id as A's and must name it
    // as the dead relay when they escalate.
    let reconnect0 = Reconnect {
        endpoint: ep0,
        relay_addr: addr_a,
        server_name: "localhost".to_owned(),
        relay_id: 1,
        identity: id0,
        rehome: Some(Arc::new(FixedTarget {
            ca: ca_b.clone(),
            addr: addr_b,
            expected_dead: 1,
            relay_id: 2,
        })),
        escalate_after: Some(Duration::from_millis(50)),
        escalate_retry: Some(Duration::from_millis(50)),
    };
    let reconnect1 = Reconnect {
        endpoint: ep1,
        relay_addr: addr_a,
        server_name: "localhost".to_owned(),
        relay_id: 1,
        identity: id1,
        rehome: Some(Arc::new(FixedTarget {
            ca: ca_b.clone(),
            addr: addr_b,
            expected_dead: 1,
            relay_id: 2,
        })),
        escalate_after: Some(Duration::from_millis(50)),
        escalate_retry: Some(Duration::from_millis(50)),
    };
    let task0 = tokio::spawn(driver0.run_reconnecting(reconnect0));
    let task1 = tokio::spawn(driver1.run_reconnecting(reconnect1));

    // Both connected to A: session-start fires.
    tokio::time::timeout(Duration::from_secs(5), chan0.session_start.recv())
        .await
        .expect("session start never fired on slot 0")
        .expect("slot 0's session-start channel closed");

    let turn = || Payload {
        commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
        ..Default::default()
    };

    // Slot 0 sends a turn over relay A; slot 1 receives it (seq 0).
    chan0.outbound.send(turn()).await.unwrap();
    assert_eq!(recv_turn(&mut chan1.inbound).await.seq, 0);

    // Relay A dies: closing its endpoint drops both client links and makes re-dials
    // to A fail, so each driver escalates to its re-home provider.
    endpoint_a.close(noq::VarInt::from_u32(0), b"relay A down");

    // Each driver surfaces its own disconnect, then re-homes onto relay B.
    wait_connectivity(&mut chan0.connectivity, (SlotId(0), false)).await;
    wait_connectivity(&mut chan1.connectivity, (SlotId(1), false)).await;
    wait_connectivity(&mut chan0.connectivity, (SlotId(0), true)).await;
    wait_connectivity(&mut chan1.connectivity, (SlotId(1), true)).await;

    // A fresh turn slot 0 sends after the re-home flows over relay B to slot 1 —
    // and it is the very next turn slot 1 sees, so the pre-death turn (which slot 0's
    // retention ring re-injected onto B) was deduped, delivered exactly once.
    chan0.outbound.send(turn()).await.unwrap();
    let after = recv_turn(&mut chan1.inbound).await;
    assert_eq!(
        after.seq, 1,
        "slot 1 sees the post-rehome turn next; the re-injected seq 0 was deduped, not re-delivered",
    );
    assert_eq!(&after.commands[..], &[0x0C, 1, 2, 3, 4, 5, 6, 7]);

    drop(chan0.outbound);
    drop(chan0.inbound);
    drop(chan1.outbound);
    drop(chan1.inbound);
    let _ = task0.await;
    let _ = task1.await;
}

#[tokio::test]
async fn a_re_homed_clients_high_seq_own_turn_is_accepted_by_the_fresh_relay() {
    use std::collections::HashSet;

    use rally_point_proto::control::BufferBounds;
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;

    // Regression for the re-home receive-window bug (the confirmed-disconnect-tier
    // failure). A client re-homing onto a fresh relay resumes its own slot's seq
    // stream mid-way — it kept counting across the move and re-injects only a recent
    // retention ring, never seq 0 onward. The fresh relay's dedup would base that
    // slot's receive window at 0, so once the resumed seq passed the window (4096) it
    // was rejected as out-of-window and the link dropped. Because every re-homed slot
    // crosses the window at the same absolute seq, that tore down the whole group at
    // once — so a peer death after the re-home never reached the survivor as a
    // relay-confirmed disconnect (the game stayed at "stall", never "confirmed").
    //
    // The driver now declares an own-slot resume anchor on the re-home dial and the
    // relay bases the window there, so the resumed high-seq stream is accepted and
    // the link survives — which is what lets the ordinary post-drop connectivity /
    // leave machinery (covered by the drop/reconnect tests above) confirm to the
    // survivor exactly as in a non-re-homed game.
    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(90);

    // Seed the relay as a resumed, already-started session over {0, 1}, standing in
    // for the replacement relay the coordinator pushed a `resumed` descriptor to.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let _ = consensus::sync_maker(
        &mesh.decision_makers,
        &key,
        BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    consensus::mark_session_started(&mesh.decision_makers, &key);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));

    // The seq the re-homing client resumes at — far past the from-zero window (4096).
    const ANCHOR: u64 = 5000;

    // The peer receives on a raw link whose receive window for the sender's slot is
    // anchored to the resume point — modeling a survivor already caught up on slot 0's
    // stream over the game (its own dedup never resets: the driver rebinds and keeps
    // it). The bug under test is the *relay's* fresh own-slot window, not this one.
    let mut peer = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    peer.anchor_receive_window(SlotId(0), ANCHOR);

    // Slot 0 dials as a re-home: it presents an own-slot resume anchor at the high
    // seq, exactly as the driver now does from its retention ring's front.
    let mut link0 = endpoint
        .reconnect_with_timeout(
            addr,
            "localhost",
            &id0,
            &[(SlotId(0), ANCHOR)],
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    // Slot 0 sends a turn at the anchored high seq — beyond a from-zero window. With
    // the anchor the relay accepts and forwards it; without it the relay would reject
    // it as out-of-window and close slot 0's link, and the peer would never see it. A
    // raw link runs no redundancy of its own, so re-send until it lands (or the outer
    // timeout fails the test), skipping the relay's ack-only maintenance packets.
    let turn = Payload {
        seq: ANCHOR,
        slot: 0,
        commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
        ..Default::default()
    };
    let got = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            link0.send(Some(turn.clone())).unwrap();
            if let Ok(Ok(received)) =
                tokio::time::timeout(Duration::from_millis(200), peer.recv()).await
                && let Some(payload) = received.fresh.into_iter().find(|p| p.seq == ANCHOR)
            {
                return payload;
            }
        }
    })
    .await
    .expect("the re-homed high-seq turn never crossed the relay (window not anchored)");
    assert_eq!(got.seq, ANCHOR);
    assert_eq!(
        got.slot, 0,
        "bound to the sender's authorized slot, like any turn"
    );
}
