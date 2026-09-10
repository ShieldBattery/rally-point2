//! Region labels are held back from clients until the release delay elapses.

use std::sync::Arc;
use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;

/// End to end over real client connections: a coordinator descriptor's region
/// labels stay entirely inside the relay until the release delay has elapsed
/// since the relay latched the session started, then reach every connected
/// client -- and a client that dials in afterwards is pushed them on register
/// rather than left without.
///
/// The withholding is the property the whole path turns on: the labels place
/// every member geographically, so a client able to read them before real play
/// had elapsed could see its opponents' regions and abandon the match while the
/// game had barely begun. The relay is built with a shortened delay so the test
/// exercises both sides of the gate in a fraction of a second; the delay a
/// production relay uses is `REGION_LABEL_RELEASE_DELAY`.
#[tokio::test]
async fn region_labels_reach_clients_only_after_the_release_delay() {
    use rally_point_proto::control::{RegionId, RelayRegionLabel, SessionDescriptor};
    use rally_point_proto::ids::RelayId;
    use rally_point_relay::mesh::control::MeshControl;
    use rally_point_transport::control::{ControlInbound, spawn_control_reader};

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(410);

    let release_delay = Duration::from_millis(400);
    let mesh = rally_point_relay::mesh::new_mesh_state_with_region_release_delay(release_delay);
    // The same decision-maker registry the relay's turn path holds, so the
    // descriptor applied here lands on the very maker the release gate reads.
    let control = MeshControl::new(RelayId(1), mesh.decision_makers.clone(), Arc::default());
    let labels = vec![
        RelayRegionLabel {
            relay_id: RelayId(1),
            region: RegionId("us-east".to_owned()),
        },
        RelayRegionLabel {
            relay_id: RelayId(2),
            region: RegionId("eu-central".to_owned()),
        },
    ];
    // A two-slot expected set, so the session's start latch -- the instant the
    // release delay is measured from -- fires when both clients have connected,
    // exactly as it does in production.
    control.apply_descriptor(&SessionDescriptor {
        finalized_drops: false,
        tenant: TenantId(TENANT.to_owned()),
        session,
        peers: vec![],
        bounds: rally_point_proto::control::BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
        expected_slots: vec![SlotId(0), SlotId(1)],
        homed_slots: vec![],
        resumed: false,
        departed_slots: vec![],
        latency_estimate_ms: None,
        relay_regions: labels,
    });

    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);
    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    let mut reader0 = spawn_control_reader(slot0.connection().clone());
    let mut reader1 = spawn_control_reader(slot1.connection().clone());

    // A build command the relay validates and forwards -- delivering a turn is
    // what makes the relay evaluate its gate.
    let turn = |seq: u64, frame: u32| Payload {
        seq,
        slot: 0,
        commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
        game_frame_count: Some(frame),
        ..Default::default()
    };
    /// The next region-label map on `reader`, skipping every frame that
    /// legitimately precedes it for a slot registering after the session started:
    /// the re-pushed session-start and connectivity signals, and the replay of the
    /// turns the session has already recorded.
    async fn next_labels(
        reader: &mut tokio::sync::mpsc::Receiver<ControlInbound>,
    ) -> Vec<(u64, String)> {
        loop {
            match recv_meaningful(reader).await {
                ControlInbound::SessionStart(_) | ControlInbound::OversizeTurn(_) => continue,
                ControlInbound::RegionLabels(map) => {
                    return map
                        .labels
                        .into_iter()
                        .map(|label| (label.relay_id, label.region))
                        .collect();
                }
                other => panic!("expected region labels, got {other:?}"),
            }
        }
    }
    let expected = vec![
        (1u64, "us-east".to_owned()),
        (2u64, "eu-central".to_owned()),
    ];

    // Inside the delay, and claiming an enormous game frame: a client cannot buy
    // itself the labels by forging the only per-turn quantity it controls.
    // Nothing but the session-start and connectivity frames may reach either
    // client.
    slot0.send(Some(turn(0, u32::MAX))).unwrap();
    for reader in [&mut reader0, &mut reader1] {
        loop {
            match tokio::time::timeout(Duration::from_millis(150), reader.recv()).await {
                Ok(Some(ControlInbound::Connectivity(_) | ControlInbound::SessionStart(_))) => {
                    continue;
                }
                Ok(Some(other)) => {
                    panic!("no region labels before the release delay elapses, got {other:?}")
                }
                Ok(None) => panic!("a control stream closed early"),
                // Timed out with no labels — the correct outcome.
                Err(_) => break,
            }
        }
    }

    // Once the delay has genuinely elapsed, the next turn opens the gate and both
    // clients receive the descriptor's map over their reliable control streams.
    tokio::time::sleep(release_delay).await;
    slot0.send(Some(turn(1, 5))).unwrap();
    for reader in [&mut reader0, &mut reader1] {
        assert_eq!(next_labels(reader).await, expected);
    }

    // A client dialing in after the release is pushed the map on register, so it
    // is not left without what every other member already holds.
    let slot2 = connect_slot(&endpoint, addr, &tenant, session, SlotId(2)).await;
    let mut reader2 = spawn_control_reader(slot2.connection().clone());
    assert_eq!(next_labels(&mut reader2).await, expected);
}
