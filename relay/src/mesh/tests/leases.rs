//! Per-peer physical-link provenance: which connection attempt is current,
//! what a superseded driver may still do, and how supersession wakes a wait.

use super::*;

#[tokio::test]
async fn newer_mesh_link_generation_invalidates_and_tombstones_the_old_one() {
    let mesh = MeshState::default();
    let peer = RelayId(9);
    let old = new_mesh_link_attempt();
    let replacement = new_mesh_link_attempt();

    let old_lease = claim_mesh_link(&mesh, peer, &old).expect("old link claims first");
    let replacement_lease =
        claim_mesh_link(&mesh, peer, &replacement).expect("replacement claims next");
    tokio::time::timeout(
        std::time::Duration::from_millis(50),
        old.superseded.notified(),
    )
    .await
    .expect("replacement wakes the old generation");

    let mut stale_dispatched = false;
    assert!(
        old_lease
            .with_current(|| {
                stale_dispatched = true;
            })
            .is_none()
    );
    assert!(!stale_dispatched);
    assert!(claim_mesh_link(&mesh, peer, &old).is_none());
    assert!(replacement_lease.is_current());
}

#[test]
fn mesh_link_claims_for_different_peers_do_not_share_the_dispatch_lock() {
    let mesh = MeshState::default();
    let first = new_mesh_link_attempt();
    assert!(claim_mesh_link(&mesh, RelayId(1), &first).is_some());
    let first_state = mesh.current_links.lock()[&RelayId(1)].clone();
    let _first_dispatch = first_state.lock();

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let other_mesh = mesh.clone();
    std::thread::spawn(move || {
        let other = new_mesh_link_attempt();
        done_tx
            .send(claim_mesh_link(&other_mesh, RelayId(2), &other).is_some())
            .unwrap();
    });
    assert_eq!(
        done_rx.recv_timeout(std::time::Duration::from_secs(1)),
        Ok(true),
        "peer 2 claim must not wait for peer 1's in-flight dispatch",
    );
}

/// A command queued behind a supersession loses provenance before it can
/// touch shared state, whichever mutation it wraps: the stale driver's
/// mesh-control dispatch reaches no local inbox and cannot regress the slot's
/// connection generation, and its queued Join registers no link.
#[test]
fn a_superseded_lease_runs_neither_a_queued_dispatch_nor_a_queued_join() {
    let sessions: routing::Sessions = Arc::default();
    let mesh = test_mesh_state();
    let makers = Arc::clone(&mesh.session.decision_makers);
    let key = control_key();
    test_maker(&makers, &key, crate::consensus::Authority::Peer);
    assert!(makers.activate_connection_epoch(&key, SlotId(0), 22));

    let peer = RelayId(9);
    let old = new_mesh_link_attempt();
    let replacement = new_mesh_link_attempt();
    let old_lease = claim_mesh_link(&mesh, peer, &old).expect("old link claims first");
    let _replacement_lease = claim_mesh_link(&mesh, peer, &replacement).expect("replacement wins");

    // The stale driver's ingress: a connectivity frame stamped with the
    // slot's older connection generation.
    let (mut guard, mut inbox) =
        routing::register(&sessions, &key, SlotId(5), 1).expect("local survivor registers");
    guard.disarm();
    let joined = joined_state(&mesh.links, &key);
    let stale_e1 = slot_connectivity_frame(key.session, SlotId(0), true, Some(11));
    assert!(
        old_lease
            .with_current(|| {
                dispatch_mesh_control(stale_e1, peer, &joined, &sessions, &mesh);
            })
            .is_none()
    );
    assert_eq!(inbox.try_recv_connectivity(), None);
    assert!(makers.connection_epoch_matches(&key, SlotId(0), Some(22)));

    // The stale driver's queued Join, into a registry of its own so the
    // emptiness assertion is about this registration alone.
    let links = new_mesh_links();
    let (forward_tx, _forward_rx) = mpsc::channel(1);
    let (control_tx, _control_rx) = mpsc::unbounded_channel();
    let shutdown = Arc::new(Notify::new());
    let mut mutation_ran = false;
    assert!(
        old_lease
            .with_current(|| {
                mutation_ran = true;
                let _registration =
                    register_mesh_link(&links, key.clone(), forward_tx, control_tx, shutdown);
            })
            .is_none(),
        "the queued command loses provenance before any shared mutation"
    );
    assert!(!mutation_ran);
    assert!(links.lock().is_empty());
}

/// `claim_verified_mesh_link` runs the datagram-floor check before it claims:
/// claiming supersedes the peer's current driver (advancing the generation and
/// waking it to exit), so an attempt that is going to be refused must be
/// refused first, or an authenticated but misconfigured connection kills a
/// healthy mesh link on its way to being rejected and leaves nothing serving
/// the peer.
#[tokio::test]
async fn an_under_floor_attempt_is_refused_before_it_can_claim_the_peer() {
    use rally_point_transport::test_util::{Edge, loopback, loopback_with_datagram_limit};

    let mesh = MeshState::default();
    let peer = RelayId(3);
    let healthy_attempt = new_mesh_link_attempt();
    let healthy = claim_mesh_link(&mesh, peer, &healthy_attempt).expect("the healthy link claims");

    // A peer advertising a datagram budget below the guaranteed floor.
    let (under_floor, _acceptor, _dial_ep, _accept_ep) =
        loopback_with_datagram_limit(Edge::Mesh, 800).await;
    match claim_verified_mesh_link(&mesh, peer, &new_mesh_link_attempt(), &under_floor) {
        MeshLinkAdmission::UnderFloor(_) => {}
        MeshLinkAdmission::Claimed(_) => panic!("an under-floor peer must not be admitted"),
        MeshLinkAdmission::Superseded => {
            panic!("the refusal must come from the floor check, not the claim")
        }
    }
    assert!(
        healthy.is_current(),
        "a refused under-floor attempt leaves the healthy lease current",
    );

    // A floor-clearing attempt still supersedes normally, so the gate refuses
    // only what it should.
    let (clearing, _acceptor, _dial_ep, _accept_ep) = loopback(Edge::Mesh).await;
    assert!(matches!(
        claim_verified_mesh_link(&mesh, peer, &new_mesh_link_attempt(), &clearing),
        MeshLinkAdmission::Claimed(_),
    ));
    assert!(
        !healthy.is_current(),
        "the newer verified claim supersedes the old link",
    );
}

#[tokio::test]
async fn supersession_cancels_an_inline_driver_wait_promptly() {
    let mesh = MeshState::default();
    let peer = RelayId(9);
    let old = new_mesh_link_attempt();
    let replacement = new_mesh_link_attempt();
    let old_lease = claim_mesh_link(&mesh, peer, &old).expect("old link claims first");

    let wait = await_while_current(&old_lease, std::future::pending::<()>());
    tokio::pin!(wait);
    assert!(claim_mesh_link(&mesh, peer, &replacement).is_some());
    let result = tokio::time::timeout(std::time::Duration::from_millis(100), &mut wait)
        .await
        .expect("supersession wakes the inline wait");
    assert!(matches!(result, LeaseAwait::Superseded));
}
