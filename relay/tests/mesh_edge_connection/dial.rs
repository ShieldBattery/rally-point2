//! The production dial half: which side dials (the lower relay id), what a turn
//! crossing an established pair proves, what makes the dial redial, and the
//! resume-cursor exchange that recovers the turns a queue reset dropped.

use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_relay::coordinator::client::FleetMeshPeers;
use rally_point_relay::key::SessionKey;
use rally_point_relay::mesh;
use rally_point_relay::mesh::edge;
use rally_point_relay::routing::FORWARD_CAPACITY;

use crate::helpers::*;

/// One connection per pair: only the lower-id relay dials, so `run_mesh_dial` is
/// a no-op for every other pairing and nothing ever reaches the `links` channel.
/// The peer's dial arrives on the accept side instead.
#[tokio::test]
async fn a_relay_does_not_dial_a_peer_whose_id_is_not_higher() -> Result<(), AnyError> {
    let tenant = make_default_tenant();
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);

    for (case, our_id, peer_id) in [
        ("equal ids would have both sides dialing", 1, 1),
        ("a higher-id relay defers to its lower-id peer", 2, 1),
    ] {
        let (links_tx, mut links_rx) = tokio::sync::mpsc::channel::<LinkHandle>(8);
        edge::run_mesh_dial(
            dial_to(&relay_b, our_id, peer_id),
            std::sync::Arc::clone(&relay_a.sessions),
            relay_a.mesh.clone(),
            links_tx,
        )
        .await;

        // `run_mesh_dial` returned without dialing at all, so nothing can be
        // in flight to arrive later.
        assert!(links_rx.try_recv().is_err(), "{case}");
    }
    Ok(())
}

/// Two relays mesh via the production connection half (`run_mesh_dial` +
/// `run_mesh_accept`), each link is labeled with the peer it reaches — the
/// dialer's id from its own config, the acceptor's learned from the identity
/// hello — and a turn flows cross-relay once both sides Join.
///
/// The dialer's certificate is seeded into the acceptor's fleet-peer map, so
/// this runs with peer-identity enforcement ACTIVE: the happy path has to keep
/// working when the fleet map is non-empty and the presented certificate
/// actually matches it, not only when enforcement is off.
#[tokio::test]
async fn cross_relay_turn_through_production_mesh_connection_half() -> Result<(), AnyError> {
    let tenant = make_default_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // Relay A is the lower id (1), so it dials. Relay B is the higher id (2),
    // so it accepts A's dial.
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);

    // A's mesh-dial identity: a real certificate, separate from A's client-edge
    // serving cert, whose fingerprint B's fleet map records.
    let (dial_chain, dial_key, dial_ca) = self_signed();
    let fleet = FleetMeshPeers::new();
    fleet.store(vec![rally_point_proto::control::MeshPeerIdentity {
        relay_id: RelayId(1),
        cert_sha256: rally_point_transport::quic::cert_fingerprint(dial_ca.as_ref()),
    }]);

    let mut links_b = accept_on(&mut relay_b, fleet.reader(), false);
    let mut links_a = spawn_dial(
        &relay_a,
        edge::MeshDial {
            cert_chain: dial_chain,
            key: dial_key,
            ..dial_to(&relay_b, 1, 2)
        },
    );

    // A dialed B, so A's link is labeled with B's id; B read the dialer's
    // identity hello, so B's link is labeled with A's id.
    let (peer_a, _generation_a, cmds_a) = next_link(&mut links_a, "A's link to B").await?;
    let (peer_b, _generation_b, cmds_b) = next_link(&mut links_b, "B's link to A").await?;
    assert_eq!(peer_a, RelayId(2), "A's link reaches B");
    assert_eq!(
        peer_b,
        RelayId(1),
        "B learned the dialer's id from the hello",
    );

    // Send Join on both sides — the test drives the command senders directly,
    // standing in for the coordinator-fed `MeshControl` Join source.
    cmds_a.send(mesh::MeshCommand::Join(key.clone()))?;
    cmds_b.send(mesh::MeshCommand::Join(key.clone()))?;

    // Clients: slot 0 (sender) on relay A, slot 1 on relay B.
    let mut client_a = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let mut client_b = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;
    wait_for_mesh_link(&relay_a.mesh, &key).await;
    wait_for_mesh_link(&relay_b.mesh, &key).await;

    client_a.send(Some(turn(0, 0)))?;

    let received_b = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .map_err(|_| "client B did not receive the turn within 2s")?
        .map_err(|e| format!("client B link error: {e}"))?;
    assert_eq!(received_b.fresh.len(), 1, "B: exactly one payload");
    assert_eq!(received_b.fresh[0].slot, 0);
    assert_eq!(received_b.fresh[0].seq, 0);

    drop(relay_a);
    Ok(())
}

/// The dial is supervised: when an established link's connection fails, the dialer
/// redials and surfaces a fresh link, rather than the pair being stranded until
/// the process restarts.
///
/// The test drains relay B's accept channel directly (instead of handing it to
/// `run_mesh_accept`) so it can application-close the first connection — forcing
/// the dialer's link driver to exit `ConnectionFailed` — and then observe the
/// redial arrive as a second accepted connection and a second surfaced link.
#[tokio::test]
async fn dial_redials_after_the_link_connection_fails() -> Result<(), AnyError> {
    let tenant = make_default_tenant();

    // A (id 1) dials; B (id 2) accepts. B stays up throughout, so the redial can
    // reconnect to it.
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);
    let mut accepted = relay_b.mesh_accept_rx();
    let mut links_a = dial_a_to_b(&relay_a, &relay_b);

    // The first dial connects: B accepts a connection and A surfaces a link
    // labeled with B's id.
    let conn1 = tokio::time::timeout(Duration::from_secs(2), accepted.recv())
        .await
        .map_err(|_| "B did not accept A's first dial within 2s")?
        .ok_or("B's accept channel closed")?;
    let (peer1, _generation1, _cmds1) = next_link(&mut links_a, "A's first link").await?;
    assert_eq!(peer1, RelayId(2), "A's first link reaches B");

    // The link's connection fails: B application-closes it, so A's driver exits
    // `ConnectionFailed` and the supervisor redials.
    conn1.close(0u32.into(), b"drop to force a redial");

    // A redials: B accepts a second connection, and A surfaces a fresh link — the
    // proof the dial is supervised, not fire-once.
    let _conn2 = tokio::time::timeout(Duration::from_secs(2), accepted.recv())
        .await
        .map_err(|_| "A did not redial after the connection failed")?
        .ok_or("B's accept channel closed")?;
    let (peer2, _generation2, _cmds2) = next_link(&mut links_a, "A's redialed link").await?;
    assert_eq!(peer2, RelayId(2), "A's redialed link reaches B");

    drop(relay_a);
    Ok(())
}

/// A peer's control-stream reader ending while the connection stays otherwise
/// alive must be treated as a link failure, not a degradation limped through —
/// otherwise the pair permanently loses
/// `SlotDeparted`/`LeaveDirective`/oversize-turn/delivery-cursor traffic between
/// them. Mirrors [`dial_redials_after_the_link_connection_fails`] exactly, but
/// kills the link by finishing the peer's control stream (a clean EOF, no reset,
/// no whole-connection close) instead of closing the connection outright — the
/// established link must still exit `ConnectionFailed` and the dial supervisor
/// must still redial.
#[tokio::test]
async fn dial_redials_after_the_peer_control_stream_dies() -> Result<(), AnyError> {
    let tenant = make_default_tenant();

    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);
    let mut accepted = relay_b.mesh_accept_rx();
    let mut links_a = dial_a_to_b(&relay_a, &relay_b);

    // The first dial connects. B's real driver never runs here (its accept
    // channel is drained directly), so nothing has yet accepted A's (the
    // dialer's) mesh control stream from B's side of the wire.
    let conn1 = tokio::time::timeout(Duration::from_secs(2), accepted.recv())
        .await
        .map_err(|_| "B did not accept A's first dial within 2s")?
        .ok_or("B's accept channel closed")?;
    let (peer1, _generation1, _cmds1) = next_link(&mut links_a, "A's first link").await?;
    assert_eq!(peer1, RelayId(2), "A's first link reaches B");

    // The mesh control stream is one bidirectional stream the dialer (A) opens
    // and writes an establishing frame on right away — which is why B's
    // `accept_bi` below completes promptly even though B's real driver never
    // ran. Accept B's paired half of that same stream, then immediately finish
    // B's send direction: a clean EOF on the stream A's `peer_control_rx`
    // reads, with the connection itself left fully alive.
    let (mut b_control_send, _unused) = conn1.accept_bi().await?;
    b_control_send.finish()?;

    // A's driver must treat that as a link failure and redial, exactly like the
    // whole-connection-close case.
    let _conn2 = tokio::time::timeout(Duration::from_secs(2), accepted.recv())
        .await
        .map_err(|_| "A did not redial after its peer's control stream died")?
        .ok_or("B's accept channel closed")?;
    let (peer2, _generation2, _cmds2) = next_link(&mut links_a, "A's redialed link").await?;
    assert_eq!(peer2, RelayId(2), "A's redialed link reaches B");

    drop(relay_a);
    Ok(())
}

/// A congested link's shared forward queue filling resets the link rather than
/// silently dropping the fresh turn — a dropped turn never enters the link's
/// `AckManager`, so its own redundancy has nothing to re-carry and the peer
/// relay's clients would stall on a permanent per-(slot, seq) gap forever — and
/// the turn that tripped the reset is not gone for good: once the link redials
/// and both sides re-Join, the resume-cursor exchange each Join sends replays
/// it, and it reaches the peer's client.
///
/// Both relays run their real, production drivers (`run_mesh_accept` on B, the
/// supervised dial on A) so the redial and rejoin happen exactly as they would
/// in the field, including B's real `MeshCommand::Join` handling re-sending its
/// own resume cursors down the fresh link.
///
/// The fill is a burst of throwaway `fan_out_to_mesh` calls — none are recorded
/// into any replay ring, so their own fate is irrelevant. The flood loop has no
/// `.await` in it and `#[tokio::test]` defaults to the current-thread runtime,
/// so cooperative scheduling can't preempt A's driver task mid-loop to drain the
/// queue: every send lands before the driver gets a chance to empty it, making
/// the fill (and which call trips it) deterministic rather than a race. The one
/// turn this test tracks is forwarded through `mesh::forward_client_turn` right
/// after the fill: its own `fan_out_to_mesh` call is the one that finds the
/// queue full and fires the reset, so it is, by construction, the exact turn
/// that tripped it — and it was already recorded into A's replay ring under
/// `TurnOrigin::Local` before that fan-out ever ran. Isolating the tracked turn
/// from the filler this way keeps the replay this test waits on to a single
/// small datagram; a large unpaced replay burst risks real datagram loss under
/// load with nothing left afterward to trigger the redundancy that would
/// normally recover it.
#[tokio::test]
async fn a_full_queue_reset_recovers_via_the_redialed_links_resume_cursor_exchange()
-> Result<(), AnyError> {
    let tenant = make_default_tenant();
    let session = SessionId(9);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // A (id 1) dials; B (id 2) runs the real accept loop, so a redial is
    // accepted and driven exactly as it would be in production.
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);
    let mut links_b = accept_on(&mut relay_b, empty_fleet_peers(), false);
    let mut links_a = dial_a_to_b(&relay_a, &relay_b);

    let (peer_a1, _generation_a1, cmds_a1) = next_link(&mut links_a, "A's first link").await?;
    let (peer_b1, _generation_b1, cmds_b1) = next_link(&mut links_b, "B's first link").await?;
    assert_eq!(peer_a1, RelayId(2));
    assert_eq!(peer_b1, RelayId(1));

    // A's own decision-maker exists and is latched started, so the replay
    // ring actually records what's about to be flooded through it —
    // `deliver_turn_to_locals` only buffers into the ring once the session
    // has started (pre-start traffic has its own, separate replay log).
    seed_authority(&relay_a.mesh.session.decision_makers, &key)
        .bounds(1, 6)
        .apply();
    relay_a.mesh.session.decision_makers.mark_started(&key);

    cmds_a1.send(mesh::MeshCommand::Join(key.clone()))?;
    cmds_b1.send(mesh::MeshCommand::Join(key.clone()))?;

    let mut client_a = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let mut client_b = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;
    wait_for_mesh_link(&relay_a.mesh, &key).await;
    wait_for_mesh_link(&relay_b.mesh, &key).await;

    // A real turn, sent and delivered through the full production path, so
    // B's forward-gate cursor for slot 0 genuinely advances to "next needed
    // = 1" before anything is lost.
    client_a.send(Some(turn(0, 0)))?;
    let received = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .map_err(|_| "client B did not receive the baseline turn within 2s")?
        .map_err(|e| format!("client B link error: {e}"))?;
    assert_eq!(received.fresh.len(), 1);
    assert_eq!(received.fresh[0].seq, 0, "the baseline turn arrived live");

    let triggering_seq = 1u64;
    for _ in 0..FORWARD_CAPACITY {
        mesh::fan_out_to_mesh(&relay_a.mesh.links, &key, turn(0, 0));
    }
    mesh::forward_client_turn(
        &relay_a.sessions,
        &relay_a.mesh,
        &key,
        SlotId(0),
        turn(0, triggering_seq),
    );

    // A's driver resets on the full queue and redials; B's real accept loop
    // takes the fresh connection and surfaces a new link.
    let (peer_a2, _generation_a2, cmds_a2) = next_link(&mut links_a, "A's redialed link").await?;
    let (peer_b2, _generation_b2, cmds_b2) =
        next_link(&mut links_b, "B's link to the redial").await?;
    assert_eq!(peer_a2, RelayId(2));
    assert_eq!(peer_b2, RelayId(1));

    // Re-Join both sides on the fresh link -- standing in for the
    // coordinator re-pushing the session descriptor after a reconnect, the
    // same way every other test in this file drives Join by hand. Each
    // Join's resume-cursor reconcile fires from here: B tells A it still
    // needs slot 0 from seq 1, and A replays its ring at or past that --
    // just the one triggering turn, since nothing else was ever recorded.
    cmds_a2.send(mesh::MeshCommand::Join(key.clone()))?;
    cmds_b2.send(mesh::MeshCommand::Join(key.clone()))?;

    // Collect fresh datagrams at B until the triggering seq arrives (or the
    // deadline lapses) -- the strongest available proof that recovery
    // reached all the way through, not just the reset alone.
    let mut seen = std::collections::HashSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !seen.contains(&triggering_seq) && tokio::time::Instant::now() < deadline {
        let Ok(Ok(received)) = tokio::time::timeout(Duration::from_secs(2), client_b.recv()).await
        else {
            break;
        };
        for payload in received.fresh {
            assert_eq!(payload.slot, 0, "only slot 0 is in play on this link");
            seen.insert(payload.seq);
        }
    }
    assert!(
        seen.contains(&triggering_seq),
        "the turn that triggered the full-queue reset did not arrive after resume; got seqs {seen:?}",
    );

    drop(relay_a);
    Ok(())
}
