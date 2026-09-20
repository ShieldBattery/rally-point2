//! The session-start directive — when the relay fires it, what buffer depth it
//! carries, and how it reaches a slot that registers late — plus the
//! connectivity frames a register fans to the peers already there.

use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};

#[tokio::test]
async fn a_late_slot_receives_session_start_on_register() {
    use rally_point_relay::key::SessionKey;
    use rally_point_transport::control::{ControlInbound, spawn_control_reader};

    let tenant = make_default_tenant();
    let session = SessionId(89);

    // A one-slot expected set: slot 0 alone starts the session. A later slot then
    // registers after start and must be re-pushed the directive on register.
    let mesh = rally_point_relay::mesh::MeshState::default();
    let makers = mesh.session.decision_makers.clone();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    seed_authority(&makers, &key).expecting([0]).apply();

    let TestRelay { addr, ca, .. } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let endpoint = client_endpoint(&ca);

    // Slot 0 covers the expected set on its own: the session starts immediately
    // (past slot 0's own connectivity(true) frame).
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut reader0 = spawn_control_reader(slot0.connection().clone());
    assert!(
        matches!(
            recv_meaningful(&mut reader0).await,
            ControlInbound::SessionStart(_)
        ),
        "the sole expected slot starts the session on connect",
    );

    // A second slot registers well after the session has already started, and is
    // re-pushed the directive on register rather than left waiting.
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    assert!(
        matches!(
            recv_meaningful(&mut reader1).await,
            ControlInbound::SessionStart(_)
        ),
        "a slot that registers after start still receives the directive",
    );
}

/// The session-start directive fires exactly when the expected set is covered
/// — not before — and carries the computed initial buffer depth to every slot.
///
/// The depth is seeded to be hint-dominated and therefore deterministic: a
/// 400ms one-way latency hint is ceil(400000/41666) = 10 turns, and a
/// multi-relay session is never "fully observed" (its per-slot conditions never
/// cross the mesh pre-start), so the depth is max(observed, 10) + 1 hop cushion
/// = 11 — the localhost handshake RTT the slots contribute stays far below 10,
/// so it never lifts the max above the hint.
#[tokio::test]
async fn fires_session_start_with_the_computed_depth_once_every_expected_slot_connects() {
    use rally_point_relay::consensus;
    use rally_point_relay::key::SessionKey;
    use rally_point_transport::control::{ControlInbound, spawn_control_reader};

    let tenant = make_default_tenant();
    let session = SessionId(91);

    let mesh = rally_point_relay::mesh::MeshState::default();
    let makers = mesh.session.decision_makers.clone();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    seed_authority(&makers, &key).expecting([0, 1]).apply();
    consensus::set_session_shape(&makers, &key, Some(400), false);

    let TestRelay { addr, ca, .. } = start_relay_with_mesh(registry_for_one(&tenant), mesh);
    let endpoint = client_endpoint(&ca);

    // Slot 0 connects; it does not cover {0, 1}, so no session-start is sent
    // yet. The relay does fan slot 0 its own connectivity(true), which is fine
    // to see — what must NOT arrive is a session-start. A short window is
    // enough: the directive would ride the same register the connectivity
    // frame did.
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut reader0 = spawn_control_reader(slot0.connection().clone());
    loop {
        match tokio::time::timeout(Duration::from_millis(100), reader0.recv()).await {
            Ok(Some(ControlInbound::Connectivity(_))) => continue,
            Ok(Some(other)) => {
                panic!("no session-start until every expected slot connects, got {other:?}")
            }
            Ok(None) => panic!("slot 0's control stream closed early"),
            // Timed out with no session-start — the correct outcome.
            Err(_) => break,
        }
    }

    // Slot 1 completes the expected set: both slots receive the directive over
    // their reliable control streams, each stamped with the computed depth.
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    assert_eq!(
        recv_meaningful(&mut reader0).await.session_start_depth(),
        Some(Some(11)),
        "slot 0 starts once slot 1 completes the set, at the computed depth",
    );
    assert_eq!(
        recv_meaningful(&mut reader1).await.session_start_depth(),
        Some(Some(11)),
        "the slot that completed the set gets the same stamped depth",
    );
}

/// Test helper: the initial buffer depth a `SessionStart` control frame carried,
/// or `None` for any other frame kind. `Some(None)` is a depth-less directive.
trait SessionStartDepth {
    fn session_start_depth(&self) -> Option<Option<u32>>;
}

impl SessionStartDepth for rally_point_transport::control::ControlInbound {
    fn session_start_depth(&self) -> Option<Option<u32>> {
        match self {
            rally_point_transport::control::ControlInbound::SessionStart(depth) => Some(*depth),
            _ => None,
        }
    }
}

#[tokio::test]
async fn a_slots_connect_fans_a_connectivity_up_to_the_other_slots() {
    use rally_point_transport::control::{ControlInbound, spawn_control_reader};

    let tenant = make_default_tenant();
    let session = SessionId(90);

    let TestRelay { addr, ca, .. } = start_relay(registry_for_one(&tenant));
    let endpoint = client_endpoint(&ca);

    // Slot 0 connects first and opens its control reader.
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut reader0 = spawn_control_reader(slot0.connection().clone());

    // Slot 1 then connects: its registration broadcasts a `connected = true`
    // connectivity change to every slot in the session, so slot 0 hears that
    // slot 1 is connected over its reliable control stream. (Slot 0 also receives
    // its own `connected = true` frame; read past it to the one naming slot 1.)
    let _slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut saw_slot1_connected = false;
    for _ in 0..4 {
        match tokio::time::timeout(Duration::from_secs(5), reader0.recv()).await {
            Ok(Some(ControlInbound::Connectivity(change))) => {
                if change.slot == 1 {
                    assert!(change.connected, "slot 1's link is up");
                    saw_slot1_connected = true;
                    break;
                }
                // Slot 0's own `connected = true` frame — keep reading.
            }
            Ok(Some(other)) => panic!("unexpected control frame: {other:?}"),
            Ok(None) => panic!("slot 0's control stream closed early"),
            Err(_) => panic!("timed out waiting for slot 1's connectivity frame"),
        }
    }
    assert!(
        saw_slot1_connected,
        "slot 0 learns slot 1 connected via a fanned connectivity frame",
    );
}
