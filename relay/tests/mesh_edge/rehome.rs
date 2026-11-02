//! Recovery from a failed home relay onto a replacement relay.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::{RelayPeer, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_relay::key::SessionKey;
use rally_point_relay::mesh;
use rally_point_transport::Link;
use rally_point_transport::control::{ControlInbound, spawn_control_reader};

use crate::helpers::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fresh_replacement_replays_survivor_history_after_a_resumed_descriptor()
-> Result<(), AnyError> {
    replay_survivor_history(false, 10_000).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fresh_replacement_recovers_when_it_joins_before_the_survivor() -> Result<(), AnyError> {
    replay_survivor_history(true, 10_000).await
}

// Recovery must stay live without a receiver draining concurrently on another worker.
// Keep this scheduling case alongside the queue-floor unit tests.
#[tokio::test]
async fn a_replacement_replay_remains_live_on_a_single_worker() -> Result<(), AnyError> {
    replay_survivor_history(false, 10_000).await
}

// A retained prefix inside the receive window must recover without relying on
// forward collapse to establish a cumulative receipt.
#[tokio::test]
async fn a_replacement_replays_a_nonzero_prefix_inside_the_receive_window() -> Result<(), AnyError>
{
    replay_survivor_history(false, 3_000).await
}

async fn replay_survivor_history(replacement_first: bool, next: u64) -> Result<(), AnyError> {
    let tenant = make_default_tenant();
    let session = SessionId(61);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let survivor = Relay::start(&tenant, 508);
    let replacement = Relay::start(&tenant, 510);
    seed_authority(&survivor.mesh.session.decision_makers, &key)
        .expecting([0, 1])
        .homed([0])
        .apply();
    survivor.mesh.session.decision_makers.mark_started(&key);
    let _survivor_client = connect_client(&survivor, &tenant, session, SlotId(0)).await?;

    // Feed the validated forwarding boundary before the replacement has any
    // mesh link. Enough turns age out both the client's 512-turn retention and
    // the relay ring's beginning, so recovery cannot depend on receiving seq 0.
    let missing = next - 3;
    for seq in 0..next {
        mesh::forward_client_turn(
            &survivor.sessions,
            &survivor.mesh,
            &key,
            SlotId(0),
            build_turn(0, seq, Some(seq as u32)),
        );
    }
    let retained = survivor
        .mesh
        .session
        .turn_ring
        .replay(&key, &HashMap::new(), SlotId(1));
    let retained_front = retained.first().unwrap().seq;
    assert!(retained_front > 0);
    if next == 3_000 {
        assert!(retained_front + 256 < 4096);
    } else {
        assert!(retained_front > 4096);
    }
    assert_eq!(retained.last().unwrap().seq, next - 1);

    let control = mesh::control::MeshControl::new(
        RelayId(510),
        &replacement.mesh,
        Arc::clone(&replacement.sessions),
    );
    let mut resumed = descriptor(TENANT, session);
    resumed.peers = vec![RelayPeer {
        relay_id: RelayId(0),
        relay_addr: survivor.addr,
        cert_der: survivor.ca.as_ref().to_vec(),
        relay_addrs: vec![],
    }];
    resumed.resumed = true;
    resumed.expected_slots = vec![SlotId(0), SlotId(1)];
    resumed.homed_slots = vec![SlotId(1)];
    control.apply_descriptor(&resumed);
    assert!(replacement.mesh.session.decision_makers.is_started(&key));
    assert!(!mesh::has_resumable_state(&replacement.mesh.seen, &key));

    // The reconnect handshake carries the exact peer cursor the returning
    // client needs, but the replacement's local replay ring is still empty.
    let endpoint = client_endpoint(&replacement.ca);
    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(1), client_key.public);
    let connection = endpoint.connect(replacement.addr, "localhost")?.await?;
    handshake(
        &connection,
        &token,
        &client_key,
        &[(SlotId(0), missing), (SlotId(1), next - 512)],
    )
    .await?;
    let mut client = Link::new(connection);
    client.anchor_receive_window(SlotId(0), missing);
    let mut incoming_control = spawn_control_reader(client.connection().clone());
    let mut beacon_send = client.connection().open_uni().await?;
    let mut beacon = rally_point_transport::beacon::BeaconWriter::new();

    let (survivor_link, replacement_link, _survivor_ep, _replacement_ep) = mesh_link_pair().await;
    let survivor_commands = spawn_mesh_link(
        survivor_link,
        Arc::clone(&survivor.sessions),
        survivor.mesh.clone(),
    );
    let replacement_commands = spawn_mesh_link(
        replacement_link,
        Arc::clone(&replacement.sessions),
        replacement.mesh.clone(),
    );
    if replacement_first {
        assert!(control.register_link(RelayId(0), 1, replacement_commands));
        wait_for_mesh_link(&replacement.mesh, &key).await;
        survivor_commands.send(mesh::MeshCommand::Join(key.clone()))?;
        wait_for_mesh_link(&survivor.mesh, &key).await;
    } else {
        survivor_commands.send(mesh::MeshCommand::Join(key.clone()))?;
        wait_for_mesh_link(&survivor.mesh, &key).await;
        assert!(control.register_link(RelayId(0), 1, replacement_commands));
        wait_for_mesh_link(&replacement.mesh, &key).await;
    }

    // No survivor produces another turn while waiting for the missing peer.
    // The only way these three turns can arrive is the mesh replay handshake.
    let mut received = HashSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while received.len() < 3 {
        let turns = tokio::time::timeout_at(deadline, async {
            tokio::select! {
                packet = client.recv() => packet.map(|packet| packet.fresh).map_err(|e| e.to_string()),
                frame = incoming_control.recv() => match frame {
                    Some(ControlInbound::OversizeTurn(turn)) => Ok(vec![turn]),
                    Some(_) => Ok(vec![]),
                    None => Err(format!("client control stream ended: {:?}", client.connection().close_reason())),
                },
            }
        }).await.expect("the replacement never recovered the survivor's missing tail")?;
        client.send(None)?;
        beacon
            .flush(
                &mut beacon_send,
                client
                    .delivered_through(SlotId(0))
                    .map(|cursor| (SlotId(0), cursor)),
            )
            .await;
        for turn in turns {
            if turn.slot == 0 && turn.seq >= missing {
                received.insert(turn.seq);
            }
        }
    }
    assert_eq!(received, HashSet::from([missing, missing + 1, missing + 2]));
    Ok(())
}

/// A relay can die after its client's turns reached one peer but before they
/// reached another. The client re-homes onto the peer that has them and
/// re-sends them, but that relay already holds them as mesh arrivals and drops
/// the copies. As the slot's new home it must still carry them on to the peer
/// the old home never reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_home_forwards_the_turns_it_held_only_as_mesh_arrivals() -> Result<(), AnyError> {
    let tenant = make_default_tenant();
    let session = SessionId(62);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let old_home = Relay::start(&tenant, 520);
    let new_home = Relay::start(&tenant, 521);
    let other = Relay::start(&tenant, 522);
    for relay in [&old_home, &new_home, &other] {
        seed_authority(&relay.mesh.session.decision_makers, &key)
            .expecting([0, 1, 2])
            .apply();
        relay.mesh.session.decision_makers.mark_started(&key);
    }
    let link = |relay: &Relay, end, peer| {
        spawn_mesh_link_to(
            end,
            Arc::clone(&relay.sessions),
            relay.mesh.clone(),
            mesh::IDLE_TIMEOUT,
            RelayId(peer),
        )
        .0
    };
    let links_of = |relay: &Relay| relay.mesh.links.lock().get(&key).map_or(0, Vec::len);

    // The old home reaches the new home, and its turns for slot 2 arrive there.
    let (old_end, new_end, _old_ep, _new_ep) = mesh_link_pair().await;
    let old_commands = link(&old_home, old_end, 521);
    let new_commands = link(&new_home, new_end, 520);
    old_commands.send(mesh::MeshCommand::Join(key.clone()))?;
    new_commands.send(mesh::MeshCommand::Join(key.clone()))?;
    wait_until("both ends of the first link joined", || {
        links_of(&old_home) == 1 && links_of(&new_home) == 1
    })
    .await;
    for seq in 0..3 {
        mesh::forward_client_turn(
            &old_home.sessions,
            &old_home.mesh,
            &key,
            SlotId(2),
            build_turn(2, seq, Some(seq as u32)),
        );
    }
    wait_until("the new home received the old home's turns", || {
        mesh::forwarded_count(&new_home.mesh.seen, &key, SlotId(2)) == Some(3)
    })
    .await;

    // The old home never reached the third relay. A mesh arrival is never
    // forwarded on, so linking the new home to it carries nothing yet.
    let (new_end, other_end, _new_ep2, _other_ep) = mesh_link_pair().await;
    let new_to_other = link(&new_home, new_end, 522);
    let other_commands = link(&other, other_end, 521);
    new_to_other.send(mesh::MeshCommand::Join(key.clone()))?;
    other_commands.send(mesh::MeshCommand::Join(key.clone()))?;
    wait_until("both ends of the second link joined", || {
        links_of(&new_home) == 2 && links_of(&other) == 1
    })
    .await;
    // A negative claim: on loopback the joined link would have carried a
    // forwarded turn well inside this window.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        mesh::forwarded_count(&other.mesh.seen, &key, SlotId(2)),
        None
    );

    // Slot 2 re-homes onto the new home, anchoring its own re-sent range at 0.
    let endpoint = client_endpoint(&new_home.ca);
    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(2), client_key.public);
    let connection = endpoint.connect(new_home.addr, "localhost")?.await?;
    handshake(&connection, &token, &client_key, &[(SlotId(2), 0)]).await?;
    let _client = Link::new(connection);

    wait_until("the new home never forwarded the turns it held", || {
        mesh::forwarded_count(&other.mesh.seen, &key, SlotId(2)) == Some(3)
    })
    .await;
    Ok(())
}
