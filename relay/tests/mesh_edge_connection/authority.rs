//! Session authority over the mesh: the handoff when the authority's players
//! leave, and the folded cross-relay delivery view a parked beacon exposes.

use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::{BufferBounds, RelayPeer, SessionDescriptor, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_relay::mesh::control;
use rally_point_relay::mesh::edge;
use rally_point_relay::routing::SessionKey;
use rally_point_transport::rustls;

use crate::helpers::*;
use tokio::sync::mpsc;

/// Buffer authority hands off to the next relay in the coordinator-assigned
/// order when the deciding relay's players all leave — driven end to end over
/// the production mesh presence path, with no descriptor re-push.
///
/// Relay A heads the order and serves the session's first client, so it
/// decides. When that client disconnects, A's slot roster empties: A demotes
/// itself locally, its mesh driver pushes the zero over the presence stream,
/// and B — next in the order, still serving a player — promotes itself. The
/// assertions poll rather than sleep because presence propagates on the mesh
/// flush cadence.
#[tokio::test]
async fn authority_hands_off_over_mesh_presence_when_players_leave() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Relay A (id 1) dials; relay B (id 2) accepts. Each control shares its
    // relay's decision-maker and presence registries, as the binary wires it —
    // the descriptor's order must land where the turn-path reports do.
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);
    let control_a = control::MeshControl::new(
        RelayId(1),
        relay_a.mesh.decision_makers.clone(),
        relay_a.mesh.presence.clone(),
    );
    let control_b = control::MeshControl::new(
        RelayId(2),
        relay_b.mesh.decision_makers.clone(),
        relay_b.mesh.presence.clone(),
    );

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        false,
    ));
    let (links_a_tx, mut links_a_rx) = mpsc::channel::<LinkHandle>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    tokio::spawn(edge::run_mesh_dial(
        edge::MeshDial {
            our_id: RelayId(1),
            peer_id: RelayId(2),
            peer_addrs: vec![relay_b.addr],
            server_name: "localhost".to_owned(),
            roots,
            cert_chain: dial_chain,
            key: dial_key,
        },
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
    ));

    let (peer_a, generation_a, cmds_a) = links_a_rx
        .recv()
        .await
        .ok_or("dial side did not produce a link")?;
    let _ = control_a.register_link(peer_a, generation_a, cmds_a);
    let (peer_b, generation_b, cmds_b) = links_b_rx
        .recv()
        .await
        .ok_or("accept side did not produce a link")?;
    let _ = control_b.register_link(peer_b, generation_b, cmds_b);

    // The coordinator ranked A first (the session's home relay).
    let descriptor_for = |peers: Vec<RelayPeer>| SessionDescriptor {
        finalized_drops: false,
        tenant: TenantId(TENANT.to_owned()),
        session,
        peers,
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![RelayId(1), RelayId(2)],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
        expected_slots: vec![],
        homed_slots: vec![],
        resumed: false,
        departed_slots: vec![],
        latency_estimate_ms: None,
        relay_regions: Vec::new(),
    };
    control_a.apply_descriptor(&descriptor_for(vec![RelayPeer {
        relay_id: RelayId(2),
        relay_addr: relay_b.addr,
        cert_der: relay_b.ca.to_vec(),
        relay_addrs: vec![],
    }]));
    control_b.apply_descriptor(&descriptor_for(vec![RelayPeer {
        relay_id: RelayId(1),
        relay_addr: relay_a.addr,
        cert_der: relay_a.ca.to_vec(),
        relay_addrs: vec![],
    }]));

    // A player on each relay. A's client is the one whose departure hands off.
    let mut client_a =
        connect_client(relay_a.addr, &relay_a.ca, &tenant, session, SlotId(0)).await?;
    let mut client_b =
        connect_client(relay_b.addr, &relay_b.ca, &tenant, session, SlotId(1)).await?;

    let a_is_authority = || {
        relay_a
            .mesh
            .decision_makers
            .lock()
            .get(&key)
            .is_some_and(|m| m.is_authority())
    };
    let b_is_authority = || {
        relay_b
            .mesh
            .decision_makers
            .lock()
            .get(&key)
            .is_some_and(|m| m.is_authority())
    };

    // Steady state: A (first in order, serving a player) decides, B defers.
    // Polled, not asserted immediately: right after Join, A's roster was still
    // empty, so B may hold a transiently different view until A's first
    // nonzero presence report lands.
    wait_for("A to hold authority and B to defer", || {
        a_is_authority() && !b_is_authority()
    })
    .await?;

    // Prove the session actually carries turns while A decides.
    client_a.send(Some(turn(0, 0))).unwrap();
    let received = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .map_err(|_| "client B did not receive the turn within 2s")?
        .map_err(|e| format!("client B link error: {e}"))?;
    assert_eq!(received.fresh.len(), 1);

    // A's only player leaves. No descriptor re-push follows — the handoff must
    // ride the relays' own presence exchange.
    drop(client_a);
    wait_for("authority to hand off from A to B", || {
        !a_is_authority() && b_is_authority()
    })
    .await?;

    drop(relay_a);
    Ok(())
}

/// End-to-end delivery tracking across the mesh: with cross-homed clients
/// exchanging turns and the destination's beacon advancing, the authority's
/// per-pair lag view converges near zero and the hop count reads 2; when the
/// destination's beacon stops while the origin keeps producing, that pair's
/// lag grows.
#[tokio::test]
async fn the_authority_folds_cross_relay_delivery_and_sees_a_parked_beacon_lag()
-> Result<(), AnyError> {
    use rally_point_relay::consensus;

    let tenant = make_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Relay A (id 1) is the authority (id-order fallback); relay B (id 2)
    // accepts A's dial. Each Join source shares its relay's REAL registries, so
    // the makers the descriptors create are the ones the link tasks feed.
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);
    let control_a = control::MeshControl::new(
        RelayId(1),
        Arc::clone(&relay_a.mesh.decision_makers),
        Arc::clone(&relay_a.mesh.presence),
    )
    .with_broadcast(Arc::clone(&relay_a.sessions), relay_a.mesh.links.clone());
    let control_b = control::MeshControl::new(
        RelayId(2),
        Arc::clone(&relay_b.mesh.decision_makers),
        Arc::clone(&relay_b.mesh.presence),
    )
    .with_broadcast(Arc::clone(&relay_b.sessions), relay_b.mesh.links.clone());

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        false,
    ));
    let (links_a_tx, mut links_a_rx) = mpsc::channel::<LinkHandle>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    tokio::spawn(edge::run_mesh_dial(
        edge::MeshDial {
            our_id: RelayId(1),
            peer_id: RelayId(2),
            peer_addrs: vec![relay_b.addr],
            server_name: "localhost".to_owned(),
            roots,
            cert_chain: dial_chain,
            key: dial_key,
        },
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
    ));
    let (peer_a, generation_a, cmds_a) = links_a_rx.recv().await.ok_or("no dial-side link")?;
    let _ = control_a.register_link(peer_a, generation_a, cmds_a);
    let (peer_b, generation_b, cmds_b) = links_b_rx.recv().await.ok_or("no accept-side link")?;
    let _ = control_b.register_link(peer_b, generation_b, cmds_b);

    // The coordinator's descriptors: each relay names the other as its peer,
    // with A ranked first (the authority).
    let delivery_descriptor = |peers: Vec<RelayPeer>| SessionDescriptor {
        finalized_drops: false,
        tenant: TenantId(TENANT.to_owned()),
        session,
        peers,
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![RelayId(1), RelayId(2)],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
        expected_slots: vec![],
        homed_slots: vec![],
        resumed: false,
        departed_slots: vec![],
        latency_estimate_ms: None,
        relay_regions: Vec::new(),
    };
    control_a.apply_descriptor(&delivery_descriptor(vec![RelayPeer {
        relay_id: RelayId(2),
        relay_addr: relay_b.addr,
        cert_der: relay_b.ca.to_vec(),
        relay_addrs: vec![],
    }]));
    control_b.apply_descriptor(&delivery_descriptor(vec![RelayPeer {
        relay_id: RelayId(1),
        relay_addr: relay_a.addr,
        cert_der: relay_a.ca.to_vec(),
        relay_addrs: vec![],
    }]));

    // Cross-homed clients: the origin (slot 0) on the authority, the
    // destination (slot 1) on relay B. The turns carry frames, as in-game turns
    // always do — the delivery fold deliberately keys on framed (in-game)
    // turns, like the consensus coordinate it sits beside.
    let framed_turn = |slot: u8, seq: u64| Payload {
        seq,
        slot: u32::from(slot),
        commands: vec![].into(),
        game_frame_count: Some(seq as u32 + 1),
        ..Default::default()
    };
    let mut client_a =
        connect_client(relay_a.addr, &relay_a.ca, &tenant, session, SlotId(0)).await?;
    let mut client_b =
        connect_client(relay_b.addr, &relay_b.ca, &tenant, session, SlotId(1)).await?;
    tokio::time::sleep(Duration::from_millis(50)).await; // let the mesh join settle

    // Slot 0 sends turns 0..=5; the destination receives them across the mesh.
    for seq in 0..=5u64 {
        client_a.send(Some(framed_turn(0, seq)))?;
    }
    let mut received = 0;
    while received < 6 {
        let got = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
            .await
            .map_err(|_| "client B did not receive the turns within 2s")?
            .map_err(|e| format!("client B link error: {e}"))?;
        received += got.fresh.len();
    }

    // The destination confirms final delivery up its ack-beacon stream, exactly
    // as the client driver does in production.
    let mut beacon_send = client_b.connection().open_uni().await?;
    let mut beacon_writer = rally_point_transport::beacon::BeaconWriter::new();
    beacon_writer
        .flush(&mut beacon_send, std::iter::once((SlotId(0), 5u64)))
        .await;

    // The authority's fold converges: relay B taps the beacon, ships the
    // cursors over the mesh control stream, relay A folds them — lag near zero
    // (newest origin seq 5, delivered 5), and the cross-homed pair reads 2
    // relay hops.
    let mut view = (None, None);
    for _ in 0..150 {
        view = consensus::session_e2e(&relay_a.mesh.decision_makers, &key);
        if matches!(view, (Some(lag), Some(2)) if lag <= 1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        matches!(view, (Some(lag), Some(2)) if lag <= 1),
        "the authority's e2e view converges (lag ~0, hops 2): {view:?}",
    );

    // The destination's beacon parks (it confirms nothing further) while the
    // origin keeps producing: the pair's lag grows past what any healthy
    // in-flight window explains.
    for seq in 6..=30u64 {
        client_a.send(Some(framed_turn(0, seq)))?;
    }
    let mut lag = 0;
    for _ in 0..150 {
        if let (Some(l), _) = consensus::session_e2e(&relay_a.mesh.decision_makers, &key) {
            lag = l;
            if lag >= 20 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        lag >= 20,
        "a parked destination beacon shows as growing pair lag: {lag}",
    );

    drop(relay_a);
    Ok(())
}
