//! Which side dials (the lower relay id) and what makes it redial: a dead
//! connection, a dead peer control stream, or a forward queue that filled — plus
//! the resume-cursor exchange that recovers the turns a queue reset dropped.

use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_relay::mesh;
use rally_point_relay::mesh::edge;
use rally_point_relay::routing::SessionKey;
use rally_point_transport::rustls;

use crate::helpers::*;
use tokio::sync::mpsc;

/// `should_dial_mesh` returns false for equal ids, so neither relay dials —
/// `run_mesh_dial` is a no-op and the `links` channel receives nothing.
#[tokio::test]
async fn equal_relay_ids_do_not_dial() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 1);

    let (links_tx, mut links_rx) = mpsc::channel::<LinkHandle>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let dial = edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(1),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    edge::run_mesh_dial(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_tx,
    )
    .await;

    // No link established — the dial was a no-op.
    assert!(
        links_rx.try_recv().is_err(),
        "equal ids should not produce a link"
    );
    Ok(())
}

/// A higher-id relay does not dial a lower-id peer — `run_mesh_dial` is a
/// no-op. The lower-id peer's dial arrives on the accept side instead.
#[tokio::test]
async fn higher_id_relay_does_not_dial_lower_id_peer() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let relay_a = Relay::start(&tenant, 2); // higher id
    let relay_b = Relay::start(&tenant, 1); // lower id (would dial A)

    let (links_tx, mut links_rx) = mpsc::channel::<LinkHandle>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let dial = edge::MeshDial {
        our_id: RelayId(2),
        peer_id: RelayId(1),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    edge::run_mesh_dial(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_tx,
    )
    .await;

    assert!(
        links_rx.try_recv().is_err(),
        "higher-id relay should not dial a lower-id peer"
    );
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
    let tenant = make_tenant();

    // A (id 1) dials; B (id 2) accepts. B stays up throughout, so the redial can
    // reconnect to it.
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);

    let (links_a_tx, mut links_a_rx) = mpsc::channel::<LinkHandle>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let dial = edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    // A short redial delay so the test doesn't wait the production interval.
    tokio::spawn(edge::run_mesh_dial_with(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
        Duration::from_millis(50),
    ));

    // The first dial connects: B accepts a connection and A surfaces a link
    // labeled with B's id.
    let conn1 = tokio::time::timeout(Duration::from_secs(2), relay_b.mesh_accept_rx.recv())
        .await
        .map_err(|_| "B did not accept A's first dial within 2s")?
        .ok_or("B's accept channel closed")?;
    let (peer1, _generation1, _cmds1) =
        tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
            .await
            .map_err(|_| "A did not surface its first link within 2s")?
            .ok_or("A's links channel closed")?;
    assert_eq!(peer1, RelayId(2), "A's first link reaches B");

    // The link's connection fails: B application-closes it, so A's driver exits
    // `ConnectionFailed` and the supervisor redials.
    conn1.close(0u32.into(), b"drop to force a redial");

    // A redials: B accepts a second connection, and A surfaces a fresh link — the
    // proof the dial is supervised, not fire-once.
    let _conn2 = tokio::time::timeout(Duration::from_secs(2), relay_b.mesh_accept_rx.recv())
        .await
        .map_err(|_| "A did not redial after the connection failed")?
        .ok_or("B's accept channel closed")?;
    let (peer2, _generation2, _cmds2) =
        tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
            .await
            .map_err(|_| "A did not surface a link after redialing")?
            .ok_or("A's links channel closed")?;
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
    let tenant = make_tenant();

    // A (id 1) dials; B (id 2) accepts. B stays up throughout, so the redial can
    // reconnect to it.
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);

    let (links_a_tx, mut links_a_rx) = mpsc::channel::<LinkHandle>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let dial = edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    // A short redial delay so the test doesn't wait the production interval.
    tokio::spawn(edge::run_mesh_dial_with(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
        Duration::from_millis(50),
    ));

    // The first dial connects: B accepts a connection and A surfaces a link
    // labeled with B's id. B's real driver never runs here (its accept channel
    // is drained directly), so nothing has yet accepted A's (the dialer's) mesh
    // control stream from B's side of the wire.
    let conn1 = tokio::time::timeout(Duration::from_secs(2), relay_b.mesh_accept_rx.recv())
        .await
        .map_err(|_| "B did not accept A's first dial within 2s")?
        .ok_or("B's accept channel closed")?;
    let (peer1, _generation1, _cmds1) =
        tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
            .await
            .map_err(|_| "A did not surface its first link within 2s")?
            .ok_or("A's links channel closed")?;
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
    // whole-connection-close case: B accepts a second connection, and A surfaces
    // a fresh link.
    let _conn2 = tokio::time::timeout(Duration::from_secs(2), relay_b.mesh_accept_rx.recv())
        .await
        .map_err(|_| "A did not redial after its peer's control stream died")?
        .ok_or("B's accept channel closed")?;
    let (peer2, _generation2, _cmds2) =
        tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
            .await
            .map_err(|_| "A did not surface a link after redialing")?
            .ok_or("A's links channel closed")?;
    assert_eq!(peer2, RelayId(2), "A's redialed link reaches B");

    drop(relay_a);
    Ok(())
}

/// A congested link's shared forward queue filling must reset the link, not
/// silently drop the fresh turn — a dropped turn never enters the link's
/// `AckManager`, so its own redundancy has nothing to re-carry and the peer
/// relay's clients would stall on a permanent per-(slot, seq) gap forever. Mirrors
/// [`dial_redials_after_the_peer_control_stream_dies`], but forces the reset by
/// flooding `fan_out_to_mesh` past the shared queue's capacity instead of
/// severing the control stream — the established link must still exit
/// `ConnectionFailed` and the dial supervisor must still redial.
///
/// The flood loop below has no `.await` in it, and `#[tokio::test]` defaults to
/// the current-thread runtime: cooperative scheduling can't preempt A's driver
/// task mid-loop to drain the queue, so every send lands before the driver ever
/// gets a chance to empty it — the fill is deterministic, not a timing race.
#[tokio::test]
async fn dial_redials_after_the_forward_queue_fills() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let session = SessionId(9);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // A (id 1) dials; B (id 2) accepts. B stays up throughout, so the redial can
    // reconnect to it. B's real driver never runs here (its accept channel is
    // drained directly), so nothing on B's side ever drains what A sends it —
    // irrelevant to this test, since the queue that fills is A's own outbound
    // `MeshLinkTx::forward`, drained only by A's driver.
    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);

    let (links_a_tx, mut links_a_rx) = mpsc::channel::<LinkHandle>(8);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let dial = edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    // A short redial delay so the test doesn't wait the production interval.
    tokio::spawn(edge::run_mesh_dial_with(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
        Duration::from_millis(50),
    ));

    // The first dial connects: B accepts a connection and A surfaces a link
    // labeled with B's id.
    let _conn1 = tokio::time::timeout(Duration::from_secs(2), relay_b.mesh_accept_rx.recv())
        .await
        .map_err(|_| "B did not accept A's first dial within 2s")?
        .ok_or("B's accept channel closed")?;
    let (peer1, _generation1, cmds_a) =
        tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
            .await
            .map_err(|_| "A did not surface its first link within 2s")?
            .ok_or("A's links channel closed")?;
    assert_eq!(peer1, RelayId(2), "A's first link reaches B");

    // Join the session so `fan_out_to_mesh` finds a registered target, then let
    // A's driver actually process the command and register.
    cmds_a.send(mesh::MeshCommand::Join(key.clone()))?;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Mirrors the private `routing::FORWARD_CAPACITY` (not visible to an
    // external integration test, like `CONTROL_STREAM_LOST_CLOSE` elsewhere in
    // this suite).
    const FORWARD_CAPACITY: usize = 1024;

    // Flood past the shared forward queue's capacity in one synchronous burst —
    // see the doc comment above for why this reliably fills it rather than
    // racing A's driver's own drain.
    for _ in 0..(FORWARD_CAPACITY + 8) {
        mesh::fan_out_to_mesh(
            &relay_a.mesh.links,
            &key,
            Payload {
                ..Default::default()
            },
        );
    }

    // A's driver must treat the full queue as a link failure and redial, exactly
    // like a dropped connection: B accepts a second connection, and A surfaces a
    // fresh link.
    let _conn2 = tokio::time::timeout(Duration::from_secs(2), relay_b.mesh_accept_rx.recv())
        .await
        .map_err(|_| "A did not redial after its forward queue filled")?
        .ok_or("B's accept channel closed")?;
    let (peer2, _generation2, _cmds2) =
        tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
            .await
            .map_err(|_| "A did not surface a link after redialing")?
            .ok_or("A's links channel closed")?;
    assert_eq!(peer2, RelayId(2), "A's redialed link reaches B");

    drop(relay_a);
    Ok(())
}

/// A turn that never made it across the link before a full-queue reset is not
/// gone for good: once the link redials and both sides re-Join, the
/// resume-cursor exchange each Join now sends replays it, and it reaches the
/// peer's client. Upgrades [`dial_redials_after_the_forward_queue_fills`] to
/// prove recovery, not just the reset, and to prove it for the *exact* turn
/// that tripped the reset — the very case the reset alone left unrecovered.
///
/// Both relays run their real, production drivers (`run_mesh_accept` on B,
/// `run_mesh_dial_with` on A) so a redial and rejoin happen exactly as they
/// would in the field, including B's real `MeshCommand::Join` handling
/// re-sending its own resume cursors down the fresh link.
///
/// The fill is a burst of throwaway `fan_out_to_mesh` calls, exactly like the
/// mirrored test's own flood (see its doc for why a no-`.await` loop makes
/// the fill deterministic on this test's current-thread runtime) — none of
/// those are recorded into any replay ring, so their own fate is irrelevant.
/// The one turn this test actually tracks is forwarded through
/// `mesh::forward_client_turn` right after the fill: its own `fan_out_to_mesh` call
/// is the one that finds the queue full and fires the reset, so it is, by
/// construction, the exact turn that tripped it — and it was already
/// recorded into A's replay ring under [`TurnOrigin::Local`] before that
/// fan-out ever ran. Isolating the tracked turn from the filler this way
/// (rather than recording and replaying the whole flood) keeps the replay
/// this test waits on to a single small datagram — the flood volume needed
/// to reliably trip `Full` has no bearing on how much needs replaying to
/// prove recovery, and a large unpaced replay burst risks real datagram loss
/// under load with nothing left afterward to trigger the redundancy that
/// would normally recover it.
#[tokio::test]
async fn a_full_queue_reset_recovers_via_the_redialed_links_resume_cursor_exchange()
-> Result<(), AnyError> {
    use rally_point_proto::control::BufferBounds;
    use rally_point_relay::consensus;

    let tenant = make_tenant();
    let session = SessionId(9);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    // A (id 1) dials; B (id 2) runs the real accept loop, so a redial is
    // accepted and driven exactly as it would be in production.
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);

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
    let dial = edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    // A short redial delay so the test doesn't wait the production interval.
    tokio::spawn(edge::run_mesh_dial_with(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
        Duration::from_millis(50),
    ));

    let (peer_a1, _generation_a1, cmds_a1) =
        tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
            .await
            .map_err(|_| "A did not surface its first link within 2s")?
            .ok_or("A's links channel closed")?;
    let (peer_b1, _generation_b1, cmds_b1) =
        tokio::time::timeout(Duration::from_secs(2), links_b_rx.recv())
            .await
            .map_err(|_| "B did not surface its first link within 2s")?
            .ok_or("B's links channel closed")?;
    assert_eq!(peer_a1, RelayId(2));
    assert_eq!(peer_b1, RelayId(1));

    // A's own decision-maker exists and is latched started, so the replay
    // ring actually records what's about to be flooded through it —
    // `deliver_turn_to_locals` only buffers into the ring once the session
    // has started (pre-start traffic has its own, separate replay log).
    let _ = consensus::sync_maker(
        &relay_a.mesh.decision_makers,
        &key,
        BufferBounds::new(1, 6).unwrap(),
        consensus::Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    consensus::mark_session_started(&relay_a.mesh.decision_makers, &key);

    cmds_a1.send(mesh::MeshCommand::Join(key.clone()))?;
    cmds_b1.send(mesh::MeshCommand::Join(key.clone()))?;

    let mut client_a =
        connect_client(relay_a.addr, &relay_a.ca, &tenant, session, SlotId(0)).await?;
    let mut client_b =
        connect_client(relay_b.addr, &relay_b.ca, &tenant, session, SlotId(1)).await?;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // A real turn, sent and delivered through the full production path, so
    // B's forward-gate cursor for slot 0 genuinely advances to "next needed
    // = 1" before anything is lost.
    client_a.send(Some(turn(0, 0))).unwrap();
    let received = tokio::time::timeout(Duration::from_secs(2), client_b.recv())
        .await
        .map_err(|_| "client B did not receive the baseline turn within 2s")?
        .map_err(|e| format!("client B link error: {e}"))?;
    assert_eq!(received.fresh.len(), 1);
    assert_eq!(received.fresh[0].seq, 0, "the baseline turn arrived live");

    // Mirrors the private `routing::FORWARD_CAPACITY` (see the sibling flood
    // test's own comment on this).
    const FORWARD_CAPACITY: usize = 1024;
    let triggering_seq = 1u64;

    // Fill A's shared forward queue to exactly capacity with throwaway
    // garbage (never recorded into the replay ring -- these exist only to
    // occupy the queue, and whether any of them individually reach B before
    // the reset is irrelevant to this test). Then forward ONE real, ring-recorded
    // turn: its own `fan_out_to_mesh` call is what finds the queue full and
    // fires the reset, so it is, by construction, the exact turn that
    // triggered Full -- and `deliver_turn_to_locals` already recorded it into
    // A's ring before that fan-out ever ran, so its loss on this link is
    // exactly the case resume-from-cursor recovers. Both loops run with no
    // `.await` in between -- see the doc comment above for why that is what
    // makes the fill (and which call trips it) deterministic rather than a
    // race with A's driver's own drain.
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
    let (peer_a2, _generation_a2, cmds_a2) =
        tokio::time::timeout(Duration::from_secs(2), links_a_rx.recv())
            .await
            .map_err(|_| "A did not surface a link after redialing")?
            .ok_or("A's links channel closed")?;
    let (peer_b2, _generation_b2, cmds_b2) =
        tokio::time::timeout(Duration::from_secs(2), links_b_rx.recv())
            .await
            .map_err(|_| "B did not surface a link after A redialed")?
            .ok_or("B's links channel closed")?;
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
