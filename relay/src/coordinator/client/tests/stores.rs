//! The stores a coordinator push replaces wholesale: the fleet mesh-peer map the
//! mesh acceptor pins against, and the region beacon targets the ping loop sweeps.

use super::*;

// --- Fleet mesh-peer map ---

#[test]
fn store_replaces_the_fleet_map_wholesale_and_the_reader_reflects_it() {
    let fleet = FleetMeshPeers::new();
    let reader = fleet.reader();
    assert!(reader.is_empty(), "a fresh map is empty");

    fleet.store(vec![
        MeshPeerIdentity {
            relay_id: RelayId(1),
            cert_sha256: [0x11; 32],
        },
        MeshPeerIdentity {
            relay_id: RelayId(2),
            cert_sha256: [0x22; 32],
        },
    ]);
    assert_eq!(reader.fingerprint(RelayId(1)), Some([0x11; 32]));
    assert_eq!(reader.fingerprint(RelayId(2)), Some([0x22; 32]));
    assert!(!reader.is_empty());

    // A later push is declarative current state: relay 1 drops out and relay
    // 2's cert rotates, replacing the map wholesale rather than merging.
    fleet.store(vec![MeshPeerIdentity {
        relay_id: RelayId(2),
        cert_sha256: [0xEE; 32],
    }]);
    assert_eq!(
        reader.fingerprint(RelayId(1)),
        None,
        "a wholesale replace drops the absent relay",
    );
    assert_eq!(
        reader.fingerprint(RelayId(2)),
        Some([0xEE; 32]),
        "the rotated cert is reflected",
    );
}

#[tokio::test]
async fn a_mesh_peers_push_updates_the_fleet_map_the_reader_exposes() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Stand-in coordinator: accept, complete the enroll handshake, push a
    // MeshPeers set, then hold the connection open so the relay does not
    // reconnect mid-assert.
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _hello = accept_enroll(&mut ws).await;
        let frame = serde_json::to_string(&CoordinatorToRelay::MeshPeers {
            peers: vec![
                MeshPeerIdentity {
                    relay_id: RelayId(2),
                    cert_sha256: [0x22; 32],
                },
                MeshPeerIdentity {
                    relay_id: RelayId(3),
                    cert_sha256: [0x33; 32],
                },
            ],
        })
        .unwrap();
        ws.send(Message::Text(frame.into())).await.unwrap();
        std::future::pending::<()>().await;
    });

    // The reader is taken before the writer moves into the subscriber, so it
    // observes exactly the map the received push stores.
    let fleet = FleetMeshPeers::new();
    let reader = fleet.reader();
    let control = MeshControl::new(
        RelayId(1),
        std::sync::Arc::default(),
        std::sync::Arc::default(),
    );
    let (drain_rx, drain_acked) = no_drain();
    tokio::spawn(run_descriptor_subscriber_with(
        enroll(addr, drain_hello()),
        ControlApplyTargets {
            control,
            applied: AppliedSessions::default(),
            fleet,
            verifying_keys: SharedRegistry::default(),
            region_targets: RegionPingTargets::default(),
            drain_acked,
        },
        OutboundQueues::new(
            mpsc::unbounded_channel().1,
            no_flight(),
            ControlConnStats::new(),
        ),
        heartbeat(Duration::from_secs(3600)),
        drain_rx,
        no_connected(),
        backoff(Duration::from_millis(20), Duration::from_secs(60)),
    ));

    // The pushed set lands in the shared map the reader observes.
    let landed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if reader.fingerprint(RelayId(2)) == Some([0x22; 32])
                && reader.fingerprint(RelayId(3)) == Some([0x33; 32])
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        landed.is_ok(),
        "the reader exposes the coordinator's pushed fleet map",
    );
    assert_eq!(
        reader.fingerprint(RelayId(9)),
        None,
        "a relay absent from the pushed set has no fingerprint",
    );
}

// --- Region ping targets ---

fn beacon(region: &str, host_port: &str) -> RegionBeaconTarget {
    RegionBeaconTarget {
        region: RegionId(region.to_owned()),
        beacon: host_port.to_owned(),
    }
}

#[test]
fn a_region_beacons_push_lands_in_the_store_and_an_unchanged_repush_signals_nothing() {
    let targets = RegionPingTargets::new();
    let mut watch = targets.subscribe();

    let set = vec![
        beacon("eu-central", "eu.example:20000"),
        beacon("us-east", "us.example:20000"),
    ];
    targets.store(set.clone());
    assert!(
        watch.has_changed().unwrap(),
        "the first push signals the ping loop",
    );
    assert_eq!(
        *watch.borrow_and_update(),
        set,
        "the pushed set lands in the store"
    );

    // A reconnect re-push of the identical set is declarative current state:
    // `send_if_modified` sees no change, so it wakes no sweep.
    targets.store(set.clone());
    assert!(
        !watch.has_changed().unwrap(),
        "an unchanged re-push does not re-signal the watch",
    );

    // A genuinely different set does signal again.
    targets.store(vec![beacon("eu-central", "eu.example:20000")]);
    assert!(
        watch.has_changed().unwrap(),
        "a changed set signals the ping loop",
    );
}
