//! The session-start directive — when the relay fires it, what buffer depth it
//! carries, and how it reaches a slot that registers late — plus the
//! connectivity frames a register fans to the peers already there.

use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};

#[tokio::test]
async fn fires_session_start_when_every_expected_slot_connects() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::{ControlInbound, spawn_control_reader};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(88);

    // Seed the session's maker as the authority with two expected slots, before
    // any client connects — exactly as a coordinator descriptor would.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    // Slot 0 connects; it does not cover {0, 1}, so no session-start is sent yet.
    // The relay does fan slot 0 its own connectivity(true), which is fine to see —
    // what must NOT arrive is a session-start.
    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut reader0 = spawn_control_reader(slot0.connection().clone());
    loop {
        match tokio::time::timeout(Duration::from_millis(300), reader0.recv()).await {
            Ok(Some(ControlInbound::Connectivity(_))) => continue,
            Ok(Some(other)) => {
                panic!("no session-start until every expected slot connects, got {other:?}")
            }
            Ok(None) => panic!("slot 0's control stream closed early"),
            // Timed out with no session-start — the correct outcome.
            Err(_) => break,
        }
    }

    // Slot 1 connects, completing the expected set: every slot receives the
    // session-start directive over its reliable control stream (past any
    // connectivity frame slot 1's own register fanned).
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());
    assert!(
        matches!(
            recv_meaningful(&mut reader0).await,
            ControlInbound::SessionStart(_)
        ),
        "slot 0 receives the session-start directive once slot 1 completes the set",
    );
    assert!(
        matches!(
            recv_meaningful(&mut reader1).await,
            ControlInbound::SessionStart(_)
        ),
        "the slot that completed the set receives the directive too",
    );
}

#[tokio::test]
async fn a_late_slot_receives_session_start_on_register() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::{ControlInbound, spawn_control_reader};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(89);

    // A one-slot expected set: slot 0 alone starts the session. A later slot then
    // registers after start and must be re-pushed the directive on register.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
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

#[tokio::test]
async fn session_start_carries_the_computed_initial_buffer_depth() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;
    use rally_point_transport::control::spawn_control_reader;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(91);

    // Seed the maker as authority over two expected slots, then feed it the
    // session shape: a large one-way latency hint (400ms) and the multi-relay
    // flag, so the initial-depth computation is hint-dominated and deterministic.
    // 400ms is ceil(400000/41666) = 10 turns; a multi-relay session is never
    // "fully observed" (its per-slot conditions never cross the mesh pre-start),
    // so the depth is max(observed, 10) + 1 hop cushion = 11 — the localhost
    // handshake RTT the slots contribute stays far below 10, so it never lifts the
    // max above the hint.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let makers = mesh.decision_makers.clone();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let _ = consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    consensus::set_session_shape(&makers, &key, Some(400), false);

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    let slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut reader0 = spawn_control_reader(slot0.connection().clone());
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader1 = spawn_control_reader(slot1.connection().clone());

    assert_eq!(
        recv_meaningful(&mut reader0).await.session_start_depth(),
        Some(Some(11)),
        "slot 0's session-start carries the computed initial buffer depth",
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

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(90);

    let (addr, ca) = start_relay(registry_for(&[&tenant]));
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
