//! Per-peer physical-link provenance: which connection attempt is current,
//! what a superseded driver may still do, and how supersession wakes a wait.

use super::*;

#[tokio::test]
async fn newer_mesh_link_generation_invalidates_and_tombstones_the_old_one() {
    let mesh = new_mesh_state();
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
fn old_mesh_driver_cannot_dispatch_e1_after_e2_is_current() {
    let sessions: routing::Sessions = Arc::default();
    let links = new_mesh_links();
    let seen = new_seen_registries();
    let makers = Arc::new(crate::consensus::new_decision_makers());
    let lobby = crate::session::lobby::new_lobby_registry();
    let chat = crate::session::chat::new_chat_registry();
    let skins = crate::session::skin::new_skin_registry();
    let key = control_key();
    let _ = crate::consensus::sync_maker(
        &makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        crate::consensus::Authority::Peer,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    assert!(crate::consensus::activate_connection_epoch(
        &makers,
        &key,
        SlotId(0),
        22,
    ));
    let mesh = test_mesh_state(&links, &seen, &makers, &lobby, &chat, &skins);
    let peer = RelayId(9);
    let old = new_mesh_link_attempt();
    let current = new_mesh_link_attempt();
    let old_lease = claim_mesh_link(&mesh, peer, &old).expect("old link claims first");
    let _current_lease = claim_mesh_link(&mesh, peer, &current).expect("current link replaces old");

    let (mut guard, mut inbox) =
        routing::register(&sessions, &key, SlotId(5), 1).expect("local survivor registers");
    guard.disarm();
    let joined = joined_state(&links, &key);
    let stale_e1 = slot_connectivity_frame(key.session, SlotId(0), true, Some(11));
    assert!(
        old_lease
            .with_current(|| {
                dispatch_mesh_control(stale_e1, peer, &joined, &sessions, &mesh);
            })
            .is_none()
    );

    assert_eq!(inbox.try_recv_connectivity(), None);
    assert!(crate::consensus::connection_epoch_matches(
        &makers,
        &key,
        SlotId(0),
        Some(22),
    ));
}

#[test]
fn mesh_link_claims_for_different_peers_do_not_share_the_dispatch_lock() {
    let mesh = new_mesh_state();
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

#[test]
fn queued_join_on_a_superseded_lease_cannot_register_the_session() {
    let mesh = new_mesh_state();
    let peer = RelayId(9);
    let old = new_mesh_link_attempt();
    let replacement = new_mesh_link_attempt();
    let old_lease = claim_mesh_link(&mesh, peer, &old).expect("old link claims first");
    let _replacement_lease = claim_mesh_link(&mesh, peer, &replacement).expect("replacement wins");

    let key = control_key();
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

#[tokio::test]
async fn supersession_cancels_an_inline_driver_wait_promptly() {
    let mesh = new_mesh_state();
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
