//! Session authority over the mesh: one authority through session start, the
//! handoff when the authority's players leave, and the folded cross-relay
//! delivery view a parked beacon exposes.

use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::{RelayPeer, SessionDescriptor, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_relay::key::SessionKey;
use rally_point_relay::mesh::control;
use rally_point_transport::control::{ControlInbound, spawn_control_reader};
use rally_point_transport::{Link, noq};
use tokio::sync::mpsc;

use crate::helpers::*;

/// Two relays serving one session: A (id 1) heads the authority order and
/// homes slot 0, B (id 2) homes slot 1, and both slots are expected. Each
/// step a test orders differently (applying a descriptor, meshing the pair,
/// connecting a client) is its own call.
struct TwoRelays {
    tenant: Tenant,
    key: SessionKey,
    relay_a: Relay,
    relay_b: Relay,
    control_a: control::MeshControl,
    control_b: control::MeshControl,
}

impl TwoRelays {
    fn start() -> Self {
        let tenant = make_default_tenant();
        let relay_a = Relay::start(&tenant, 1);
        let relay_b = Relay::start(&tenant, 2);
        let control_a =
            control::MeshControl::new(RelayId(1), &relay_a.mesh, Arc::clone(&relay_a.sessions));
        let control_b =
            control::MeshControl::new(RelayId(2), &relay_b.mesh, Arc::clone(&relay_b.sessions));
        Self {
            tenant,
            key: SessionKey {
                tenant: TenantId(TENANT.to_owned()),
                session: SessionId(1),
            },
            relay_a,
            relay_b,
            control_a,
            control_b,
        }
    }

    /// Establishes the A-B mesh link and registers it on both sides, which
    /// Joins every session whose descriptor is already applied.
    async fn mesh(&mut self) -> Result<(), AnyError> {
        let mut links_b = accept_on(&mut self.relay_b, empty_fleet_peers(), false);
        let mut links_a = dial_a_to_b(&self.relay_a, &self.relay_b);
        let (peer_a, generation_a, cmds_a) = next_link(&mut links_a, "A's link to B").await?;
        let _ = self.control_a.register_link(peer_a, generation_a, cmds_a);
        let (peer_b, generation_b, cmds_b) = next_link(&mut links_b, "B's link to A").await?;
        let _ = self.control_b.register_link(peer_b, generation_b, cmds_b);
        Ok(())
    }

    fn descriptor(&self, peer: &Relay, peer_id: u64, homed: SlotId) -> SessionDescriptor {
        SessionDescriptor {
            peers: vec![RelayPeer {
                relay_id: RelayId(peer_id),
                relay_addr: peer.addr,
                cert_der: peer.ca.to_vec(),
                relay_addrs: vec![],
            }],
            authority_order: vec![RelayId(1), RelayId(2)],
            expected_slots: vec![SlotId(0), SlotId(1)],
            homed_slots: vec![homed],
            ..descriptor(TENANT, self.key.session)
        }
    }

    fn apply_a(&self) {
        self.control_a
            .apply_descriptor(&self.descriptor(&self.relay_b, 2, SlotId(0)));
    }

    fn apply_b(&self) {
        self.control_b
            .apply_descriptor(&self.descriptor(&self.relay_a, 1, SlotId(1)));
    }

    async fn connect(&self, relay: &Relay, slot: SlotId) -> Result<Link, AnyError> {
        connect_client(relay, &self.tenant, self.key.session, slot).await
    }

    fn is_authority(&self, relay: &Relay) -> bool {
        relay
            .mesh
            .session
            .decision_makers
            .lock()
            .get(&self.key)
            .is_some_and(|m| m.is_authority())
    }

    fn roster(&self, relay: &Relay) -> usize {
        relay
            .sessions
            .lock()
            .get(&self.key)
            .map_or(0, |slots| slots.len())
    }
}

/// Opens a client's control stream, returning its send half (which must stay
/// open for the relay to keep pushing) and the reader for the frames the relay
/// pushes down it.
async fn control_reader(
    client: &Link,
) -> Result<(noq::SendStream, mpsc::Receiver<ControlInbound>), AnyError> {
    let (send, _recv) = client.connection().open_bi().await?;
    Ok((send, spawn_control_reader(client.connection().clone())))
}

/// Drains `reader` for `window`, counting `SessionStart` frames.
async fn count_session_starts(
    reader: &mut mpsc::Receiver<ControlInbound>,
    window: Duration,
) -> usize {
    let deadline = tokio::time::Instant::now() + window;
    let mut starts = 0;
    while let Ok(Some(frame)) = tokio::time::timeout_at(deadline, reader.recv()).await {
        if matches!(frame, ControlInbound::SessionStart(_)) {
            starts += 1;
        }
    }
    starts
}

/// Long enough for a presence count to be sampled on the mesh flush cadence
/// (~150ms), cross the link, and be acted on. Only for negative claims, and
/// for letting a report go out that the test cannot observe directly.
const PRESENCE_SETTLE: Duration = Duration::from_millis(300);

/// The first-in-order relay's client connecting last must not leave the session
/// with two authorities at start. The mesh Join sends each relay's current
/// live-player count, which is zero for the relay whose client has not dialed
/// yet; the other relay must read that as "not yet", not "gone". Otherwise it
/// crowns itself, and when the last client connects both relays see full
/// coverage and each fires `SessionStart` with its own initial depth, opening
/// the game at different depths on each side.
#[tokio::test]
async fn one_relay_starts_the_session_when_the_first_in_order_client_connects_last()
-> Result<(), AnyError> {
    let mut pair = TwoRelays::start();
    pair.mesh().await?;
    pair.apply_a();
    pair.apply_b();
    wait_for_mesh_link(&pair.relay_a.mesh, &pair.key).await;
    wait_for_mesh_link(&pair.relay_b.mesh, &pair.key).await;

    // B's client connects first, and B then holds A's Join-time zero.
    let client_b = pair.connect(&pair.relay_b, SlotId(1)).await?;
    let (_lobby_b, mut control_rx_b) = control_reader(&client_b).await?;
    wait_for_slots(&pair.relay_b.sessions, &pair.key, 1).await;
    tokio::time::sleep(PRESENCE_SETTLE).await;
    assert!(
        pair.is_authority(&pair.relay_a) && !pair.is_authority(&pair.relay_b),
        "A's zero before any players must not hand B the authority",
    );

    // A's client connects last, completing coverage on both relays at once.
    let client_a = pair.connect(&pair.relay_a, SlotId(0)).await?;
    let (_lobby_a, mut control_rx_a) = control_reader(&client_a).await?;

    // Each client gets the one directive, whichever relay delivered it. A second
    // authority would add its own copy on both sides.
    let window = Duration::from_millis(600);
    assert_eq!(count_session_starts(&mut control_rx_a, window).await, 1);
    assert_eq!(count_session_starts(&mut control_rx_b, window).await, 1);
    assert!(pair.is_authority(&pair.relay_a) && !pair.is_authority(&pair.relay_b));

    Ok(())
}

/// A relay whose players came and went before its link Joined the session must
/// say so on the Join. It demoted itself when its roster emptied; a bare zero
/// would read to its peer as "not yet joined", leaving each relay deferring to
/// the other and the session with no authority.
#[tokio::test]
async fn a_join_after_players_came_and_went_hands_off_the_authority() -> Result<(), AnyError> {
    let mut pair = TwoRelays::start();
    pair.apply_a();
    pair.apply_b();

    let client_a = pair.connect(&pair.relay_a, SlotId(0)).await?;
    wait_for_slots(&pair.relay_a.sessions, &pair.key, 1).await;
    drop(client_a);
    wait_for("A's roster to empty", || pair.roster(&pair.relay_a) == 0).await?;
    let _client_b = pair.connect(&pair.relay_b, SlotId(1)).await?;
    wait_for_slots(&pair.relay_b.sessions, &pair.key, 1).await;

    pair.mesh().await?;
    wait_for("B to take the authority A gave up", || {
        pair.is_authority(&pair.relay_b) && !pair.is_authority(&pair.relay_a)
    })
    .await?;

    Ok(())
}

/// A peer drops presence reports for a session it has not joined yet, so the
/// Join rendezvous must restate presence history in full rather than assume
/// the peer heard what this link wrote earlier. Here A reports its player and
/// the player's departure while B is still unjoined; only the rendezvous can
/// tell B that A's players have gone.
#[tokio::test]
async fn the_rendezvous_restates_players_the_unjoined_peer_never_heard() -> Result<(), AnyError> {
    let mut pair = TwoRelays::start();
    pair.mesh().await?;
    pair.apply_a();
    wait_for_mesh_link(&pair.relay_a.mesh, &pair.key).await;

    let client_a = pair.connect(&pair.relay_a, SlotId(0)).await?;
    wait_for_slots(&pair.relay_a.sessions, &pair.key, 1).await;
    tokio::time::sleep(PRESENCE_SETTLE).await;
    drop(client_a);
    wait_for("A's roster to empty", || pair.roster(&pair.relay_a) == 0).await?;
    tokio::time::sleep(PRESENCE_SETTLE).await;

    pair.apply_b();
    let _client_b = pair.connect(&pair.relay_b, SlotId(1)).await?;
    wait_for("B to take the authority A gave up", || {
        pair.is_authority(&pair.relay_b) && !pair.is_authority(&pair.relay_a)
    })
    .await?;

    Ok(())
}

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
    let tenant = make_default_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Relay A (id 1) dials; relay B (id 2) accepts. Each control drives its
    // relay's own turn-path state, as the binary wires it — the descriptor's
    // order must land where the turn-path reports do.
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);
    let control_a =
        control::MeshControl::new(RelayId(1), &relay_a.mesh, Arc::clone(&relay_a.sessions));
    let control_b =
        control::MeshControl::new(RelayId(2), &relay_b.mesh, Arc::clone(&relay_b.sessions));

    let mut links_b = accept_on(&mut relay_b, empty_fleet_peers(), false);
    let mut links_a = dial_a_to_b(&relay_a, &relay_b);

    let (peer_a, generation_a, cmds_a) = next_link(&mut links_a, "A's link to B").await?;
    let _ = control_a.register_link(peer_a, generation_a, cmds_a);
    let (peer_b, generation_b, cmds_b) = next_link(&mut links_b, "B's link to A").await?;
    let _ = control_b.register_link(peer_b, generation_b, cmds_b);

    // The coordinator ranked A first (the session's home relay).
    let descriptor_for = |peers: Vec<RelayPeer>| SessionDescriptor {
        peers,
        authority_order: vec![RelayId(1), RelayId(2)],
        ..descriptor(TENANT, session)
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
    let mut client_a = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let mut client_b = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;

    let a_is_authority = || {
        relay_a
            .mesh
            .session
            .decision_makers
            .lock()
            .get(&key)
            .is_some_and(|m| m.is_authority())
    };
    let b_is_authority = || {
        relay_b
            .mesh
            .session
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
    let tenant = make_default_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Relay A (id 1) is the authority (id-order fallback); relay B (id 2)
    // accepts A's dial. Each Join source drives its relay's REAL state, so the
    // makers the descriptors create are the ones the link tasks feed.
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);
    let control_a =
        control::MeshControl::new(RelayId(1), &relay_a.mesh, Arc::clone(&relay_a.sessions));
    let control_b =
        control::MeshControl::new(RelayId(2), &relay_b.mesh, Arc::clone(&relay_b.sessions));

    let mut links_b = accept_on(&mut relay_b, empty_fleet_peers(), false);
    let mut links_a = dial_a_to_b(&relay_a, &relay_b);
    let (peer_a, generation_a, cmds_a) = next_link(&mut links_a, "A's link to B").await?;
    let _ = control_a.register_link(peer_a, generation_a, cmds_a);
    let (peer_b, generation_b, cmds_b) = next_link(&mut links_b, "B's link to A").await?;
    let _ = control_b.register_link(peer_b, generation_b, cmds_b);

    // The coordinator's descriptors: each relay names the other as its peer,
    // with A ranked first (the authority).
    let delivery_descriptor = |peers: Vec<RelayPeer>| SessionDescriptor {
        peers,
        authority_order: vec![RelayId(1), RelayId(2)],
        ..descriptor(TENANT, session)
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
    let mut client_a = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let mut client_b = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;
    wait_for_mesh_link(&relay_a.mesh, &key).await;
    wait_for_mesh_link(&relay_b.mesh, &key).await;

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
        view = relay_a.mesh.session.decision_makers.delivery_view(&key);
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
        if let (Some(l), _) = relay_a.mesh.session.decision_makers.delivery_view(&key) {
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
