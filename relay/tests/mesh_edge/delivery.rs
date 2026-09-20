//! What crosses the mesh on the reliable control stream: a turn too large for
//! any datagram, and a leave the authority decided.

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_relay::consensus::{self, Authority, LEAVE_REASON_LEFT};
use rally_point_relay::mesh;
use rally_point_relay::routing::SessionKey;

use crate::helpers::*;

/// `C-S===S-C` for a turn too large for any datagram: relay A's mesh forward
/// path diverts it onto the mesh control stream (no datagram could carry it),
/// relay B's dispatch folds it back into its normal turn path, and relay B's
/// slot link diverts it again onto the receiving client's own control stream.
/// Without the mesh divert this turn silently never reached B's clients — a
/// permanent lockstep stall in any cross-relay game whose turn outgrew the
/// datagram budget.
#[tokio::test]
async fn cross_relay_oversize_turn_diverts_over_the_mesh_control_stream() -> Result<(), AnyError> {
    use rally_point_transport::control::{ControlInbound, spawn_control_reader};

    let tenant = make_default_tenant();
    let session = SessionId(1);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);
    let (_cmds_a, _cmds_b, _mesh_ep) = mesh_two_relays(&relay_a, &mut relay_b, &key).await;

    // The receiving client on relay B (slot 1), reading its control stream —
    // that's where B's slot link delivers a turn too large for the client path.
    let client_b = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;
    let mut ctrl_b = spawn_control_reader(client_b.connection().clone());

    // Both drivers have to have opened their sessions before A forwards, or the
    // turn has no mesh channel to divert onto.
    wait_for_mesh_link(&relay_a.mesh, &key).await;
    wait_for_mesh_link(&relay_b.mesh, &key).await;

    // Relay A forwards slot 0's turn, as its slot-link task would after
    // validating it — but this one is far past any datagram budget, so A's
    // mesh-link driver must divert it onto the mesh control stream.
    let oversize = Payload {
        seq: 0,
        slot: 0,
        commands: vec![0xAB; 5000].into(),
        game_frame_count: Some(12),
        ..Default::default()
    };
    mesh::forward_client_turn(
        &relay_a.sessions,
        &relay_a.mesh,
        &key,
        SlotId(0),
        oversize.clone(),
    );

    // Client B receives the turn on its control stream: two divert hops (mesh
    // control stream, then the client's own), one identical payload.
    let received = recv_meaningful(&mut ctrl_b).await;
    let ControlInbound::OversizeTurn(delivered) = received else {
        panic!("expected an oversize turn, got {received:?}");
    };
    assert_eq!(delivered.slot, 0);
    assert_eq!(delivered.seq, 0);
    assert_eq!(delivered.game_frame_count, Some(12));
    assert_eq!(
        delivered.commands, oversize.commands,
        "the command bytes cross both divert hops verbatim",
    );

    Ok(())
}

/// The synced player-leave, end to end across two relays: a client on the
/// authority relay announces its own clean departure, the authority decides the
/// leave, and the directive reaches the client homed on the *other* relay.
///
/// That last hop is the whole point. A survivor is only unstalled by the leave
/// it is pushed — it has nothing else to tell it the departed player's turns
/// will never come — so a directive that stops at the authority's own clients
/// leaves every cross-relay peer waiting on a slot that is already gone.
#[tokio::test]
async fn a_leave_decided_at_the_authority_reaches_the_peer_relays_client() -> Result<(), AnyError> {
    use rally_point_transport::control::{
        ControlInbound, send_control_leave_intent, spawn_control_reader,
    };

    let tenant = make_default_tenant();
    let session = SessionId(7);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };

    let relay_a = Relay::start(&tenant, 1);
    let mut relay_b = Relay::start(&tenant, 2);

    // A decides for this session and is home to slot 0; B defers and is home to
    // slot 1 — the coordinator-assigned split a two-region game runs with.
    seed_authority(&relay_a.mesh.decision_makers, &key)
        .expecting([0, 1])
        .homed([0])
        .apply();
    seed_authority(&relay_b.mesh.decision_makers, &key)
        .expecting([0, 1])
        .homed([1])
        .authority(Authority::Peer)
        .apply();

    let (_cmds_a, _cmds_b, _mesh_ep) = mesh_two_relays(&relay_a, &mut relay_b, &key).await;
    let mut leaver = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let survivor = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;
    let mut ctrl_survivor = spawn_control_reader(survivor.connection().clone());
    wait_for_mesh_link(&relay_a.mesh, &key).await;
    wait_for_mesh_link(&relay_b.mesh, &key).await;

    // A framed turn from the leaver gives the decision a frame to schedule the
    // departure against — without one the leave would be held, not decided.
    leaver.send(Some(build_turn(0, 0, Some(10))))?;
    wait_until("the authority never observed the leaver's turn", || {
        consensus::slot_frame(&relay_a.mesh.decision_makers, &key, SlotId(0)).is_some()
    })
    .await;

    // The leaver announces its own clean departure on the control stream it
    // opens, exactly as the client driver does.
    let (mut leave_send, _unused) = leaver.connection().open_bi().await?;
    send_control_leave_intent(&mut leave_send).await?;

    // The directive crosses the mesh and is pushed down the peer relay's
    // client's control stream, reason intact.
    let leave = loop {
        match recv_meaningful(&mut ctrl_survivor).await {
            ControlInbound::Leave(leave) => break leave,
            ControlInbound::SessionStart(_) | ControlInbound::OversizeTurn(_) => continue,
            other => panic!("expected the decided leave to cross the mesh, got {other:?}"),
        }
    };
    assert_eq!(leave.slot, 0, "the directive names the departed slot");
    assert_eq!(
        leave.reason, LEAVE_REASON_LEFT,
        "a cross-relay directive keeps the native quit reason",
    );

    Ok(())
}
