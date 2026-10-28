//! A replacement authority must keep measuring live turns after recovering only a retained tail.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::{BufferBounds, RelayPeer, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_relay::consensus::{Authority, MakerSync};
use rally_point_relay::key::SessionKey;
use rally_point_relay::mesh;
use rally_point_transport::control::{ControlInbound, spawn_control_reader};
use rally_point_transport::{Link, RECEIVE_WINDOW};
use tokio::sync::{mpsc, watch};

use crate::helpers::*;

fn turn(slot: u8, seq: u64) -> Payload {
    Payload {
        slot: slot.into(),
        seq,
        game_frame_count: Some(seq as u32),
        ..Default::default()
    }
}

fn seed_rollback(relay: &Relay, key: &SessionKey, home: u8, authority: Authority) {
    let _ = relay.mesh.session.decision_makers.sync_maker(
        key,
        MakerSync {
            expected_slots: [SlotId(0), SlotId(1)].into(),
            homed_slots: [SlotId(home)].into(),
            rollback: true,
            ..MakerSync::new(BufferBounds::new(1, 6).unwrap(), authority)
        },
    );
    relay.mesh.session.decision_makers.mark_started(key);
}

#[derive(Clone, Copy, Default)]
struct Received {
    next_peer: u64,
    lead_through: u64,
}

fn observe_peer_turn(
    received: &mut Received,
    pending: &mut BTreeSet<u64>,
    peer: SlotId,
    payload: Payload,
) {
    assert_eq!(payload.slot, u32::from(peer.0));
    if payload.seq < received.next_peer {
        return;
    }
    assert!(payload.seq - received.next_peer < RECEIVE_WINDOW);
    pending.insert(payload.seq);
    while pending.remove(&received.next_peer) {
        received.next_peer += 1;
    }
}

async fn resumed_client(
    relay: &Relay,
    tenant: &Tenant,
    session: SessionId,
    own: SlotId,
    own_anchor: u64,
    next_peer: u64,
) -> Result<(mpsc::Sender<Payload>, watch::Receiver<Received>), AnyError> {
    let endpoint = client_endpoint(&relay.ca);
    let client_key = keypair();
    let token = mint_token(tenant, session, own, client_key.public);
    let connection = endpoint.connect(relay.addr, "localhost")?.await?;
    let peer = SlotId(1 - own.0);
    handshake(
        &connection,
        &token,
        &client_key,
        &[(own, own_anchor), (peer, next_peer)],
    )
    .await?;
    let mut link = Link::new(connection);
    link.anchor_receive_window(peer, next_peer);
    let mut control = spawn_control_reader(link.connection().clone());
    let (send, mut outgoing) = mpsc::channel(32);
    let initial = Received {
        next_peer,
        ..Default::default()
    };
    let (observed, received) = watch::channel(initial);
    tokio::spawn(async move {
        let _endpoint = endpoint;
        let mut state = initial;
        let mut pending = BTreeSet::new();
        let mut flush = tokio::time::interval(Duration::from_millis(20));
        loop {
            tokio::select! {
                payload = outgoing.recv() => {
                    let Some(payload) = payload else { break };
                    link.send(Some(payload)).expect("client sends a turn");
                }
                packet = link.recv() => {
                    let packet = packet.expect("client link stays open");
                    for payload in packet.fresh {
                        observe_peer_turn(&mut state, &mut pending, peer, payload);
                    }
                    link.send(None).expect("client acknowledges turns");
                    observed.send_replace(state);
                }
                frame = control.recv() => {
                    match frame.expect("client control stays open") {
                        ControlInbound::LeadReport(report) => {
                            state.lead_through = state.lead_through.max(report.through_step);
                        }
                        ControlInbound::OversizeTurn(payload) => {
                            observe_peer_turn(&mut state, &mut pending, peer, payload);
                        }
                        _ => {}
                    }
                    observed.send_replace(state);
                }
                _ = flush.tick(), if link.payloads_in_flight() > 0 => {
                    link.send(None).expect("client retransmits pending turns");
                }
            }
        }
    });
    Ok((send, received))
}

#[tokio::test]
async fn a_fresh_rehomed_authority_keeps_both_clients_lead_reports_advancing()
-> Result<(), AnyError> {
    const NEXT: u64 = 3_000;
    const LIVE: u64 = 48;
    let tenant = make_default_tenant();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(74),
    };
    let former = Relay::start(&tenant, 511);
    let survivor = Relay::start(&tenant, 512);
    let replacement = Relay::start(&tenant, 513);
    seed_rollback(&former, &key, 1, Authority::SelfRelay);
    seed_rollback(&survivor, &key, 0, Authority::Peer);
    survivor.mesh.session.disconnect_budgets.configure_session(
        &key,
        false,
        &[SlotId(0)],
        &[SlotId(0), SlotId(1)],
        &[RelayId(0)],
    );
    for relay in [&former, &survivor, &replacement] {
        tokio::spawn(mesh::run_session_clock_heartbeat(
            relay.mesh.clone(),
            mesh::SESSION_CLOCK_HEARTBEAT,
        ));
    }
    let (former_link, survivor_link, _former_endpoint, _survivor_endpoint) = mesh_link_pair().await;
    let (former_commands, former_driver) = spawn_mesh_link_timed(
        former_link,
        Arc::clone(&former.sessions),
        former.mesh.clone(),
        mesh::IDLE_TIMEOUT,
    );
    let (survivor_commands, survivor_driver) = spawn_mesh_link_timed(
        survivor_link,
        Arc::clone(&survivor.sessions),
        survivor.mesh.clone(),
        mesh::IDLE_TIMEOUT,
    );
    former_commands.send(mesh::MeshCommand::Join(key.clone()))?;
    survivor_commands.send(mesh::MeshCommand::Join(key.clone()))?;
    wait_for_mesh_link(&former.mesh, &key).await;
    wait_for_mesh_link(&survivor.mesh, &key).await;

    // Actual forwarding creates complete history at both original relays. Batches
    // wait for observable peer delivery so bootstrap cannot overflow mesh queues.
    for first in (0..NEXT).step_by(64) {
        let end = (first + 64).min(NEXT);
        for seq in first..end {
            mesh::forward_client_turn(
                &former.sessions,
                &former.mesh,
                &key,
                SlotId(1),
                turn(1, seq),
            );
            mesh::forward_client_turn(
                &survivor.sessions,
                &survivor.mesh,
                &key,
                SlotId(0),
                turn(0, seq),
            );
        }
        wait_until("both original relays receive the bootstrap turns", || {
            mesh::forwarded_count(&former.mesh.seen, &key, SlotId(0)) == Some(end)
                && mesh::forwarded_count(&survivor.mesh.seen, &key, SlotId(1)) == Some(end)
        })
        .await;
    }
    wait_until("the survivor adopts the complete session clock", || {
        survivor
            .mesh
            .session
            .decision_makers
            .session_clock_frame(&key)
            .is_some_and(|clock| clock.final_through >= NEXT - 1)
    })
    .await;
    let old_limit = survivor
        .mesh
        .session
        .decision_makers
        .session_clock_frame(&key)
        .unwrap()
        .final_through;
    former_driver.abort();
    survivor_driver.abort();
    let _ = former_driver.await;
    let _ = survivor_driver.await;

    let survivor_control = mesh::control::MeshControl::new(
        RelayId(512),
        &survivor.mesh,
        Arc::clone(&survivor.sessions),
    );
    let replacement_control = mesh::control::MeshControl::new(
        RelayId(513),
        &replacement.mesh,
        Arc::clone(&replacement.sessions),
    );
    for (control, home, peer_relay, authority_order) in [
        (
            &survivor_control,
            0,
            &replacement,
            vec![RelayId(0), RelayId(512)],
        ),
        (
            &replacement_control,
            1,
            &survivor,
            vec![RelayId(513), RelayId(0)],
        ),
    ] {
        let mut resumed = descriptor(TENANT, key.session);
        resumed.rollback = true;
        resumed.resumed = true;
        resumed.expected_slots = vec![SlotId(0), SlotId(1)];
        resumed.homed_slots = vec![SlotId(home)];
        resumed.authority_order = authority_order;
        resumed.peers = vec![RelayPeer {
            relay_id: RelayId(0),
            relay_addr: peer_relay.addr,
            cert_der: peer_relay.ca.as_ref().to_vec(),
            relay_addrs: vec![],
        }];
        control.apply_descriptor(&resumed);
    }
    let (survivor_link, replacement_link, _survivor_endpoint2, _replacement_endpoint) =
        mesh_link_pair().await;
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
    assert!(survivor_control.register_link(RelayId(0), 1, survivor_commands));
    assert!(replacement_control.register_link(RelayId(0), 1, replacement_commands));
    wait_for_mesh_link(&survivor.mesh, &key).await;
    wait_for_mesh_link(&replacement.mesh, &key).await;
    wait_until(
        "replacement receives the survivor's budget baseline",
        || replacement.mesh.session.disconnect_budgets.is_synced(&key),
    )
    .await;
    let (survivor_send, survivor_received) =
        resumed_client(&survivor, &tenant, key.session, SlotId(0), NEXT, NEXT).await?;
    let (replacement_send, replacement_received) = resumed_client(
        &replacement,
        &tenant,
        key.session,
        SlotId(1),
        NEXT - 512,
        NEXT,
    )
    .await?;
    wait_until(
        "the fresh replacement becomes authority and adopts the old clock",
        || {
            replacement.mesh.session.decision_makers.is_authority(&key)
                && !survivor.mesh.session.decision_makers.is_authority(&key)
                && replacement
                    .mesh
                    .session
                    .decision_makers
                    .session_clock_frame(&key)
                    .is_some_and(|clock| clock.final_through >= old_limit)
        },
    )
    .await;

    for seq in NEXT - 512..NEXT {
        replacement_send.send(turn(1, seq)).await?;
    }
    wait_until("the replacement recovers both retained tails", || {
        let turns = replacement
            .mesh
            .session
            .turn_ring
            .replay(&key, &HashMap::new(), SlotId(2));
        [0, 1].into_iter().all(|slot| {
            turns
                .iter()
                .any(|turn| turn.slot == slot && turn.seq == NEXT - 1)
        })
    })
    .await;
    assert!(
        mesh::resume_cursor_snapshot(&replacement.mesh.seen, &key).is_empty(),
        "retained history does not fabricate a complete session prefix"
    );

    for seq in NEXT..NEXT + LIVE {
        survivor_send.send(turn(0, seq)).await?;
        replacement_send.send(turn(1, seq)).await?;
    }
    wait_until(
        "both clients receive every live turn after the rehome",
        || {
            survivor_received.borrow().next_peer >= NEXT + LIVE
                && replacement_received.borrow().next_peer >= NEXT + LIVE
        },
    )
    .await;
    wait_until(
        "both clients receive lead reports beyond the adopted clock limit",
        || {
            survivor_received.borrow().lead_through > old_limit
                && replacement_received.borrow().lead_through > old_limit
        },
    )
    .await;
    Ok(())
}
