//! Recovery from a failed home relay onto a replacement with no session history.

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
