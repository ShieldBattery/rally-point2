//! Per-link driver state over a real QUIC connection: the unacked-window cap,
//! the relay-pair RTT cache, the maintenance schedule, redundancy-aware flush
//! deferral, and the ack-cursor and oversize-turn folds.

use super::*;

#[test]
fn mesh_window_exhausted_trips_only_strictly_past_the_cap() {
    assert!(!mesh_window_exhausted(0));
    assert!(!mesh_window_exhausted(MESH_UNACKED_WINDOW_CAP));
    assert!(mesh_window_exhausted(MESH_UNACKED_WINDOW_CAP + 1));
}

#[test]
fn mesh_rtt_cache_samples_on_first_use() {
    let now = tokio::time::Instant::now();
    let samples = std::cell::Cell::new(0);
    let mut cache = MeshRttCache::default();

    let rtt = cache.get_or_refresh_with(now, || {
        samples.set(samples.get() + 1);
        12_000
    });

    assert_eq!(rtt, 12_000);
    assert_eq!(samples.get(), 1);
}

#[test]
fn mesh_rtt_cache_reuses_a_sample_within_the_window() {
    let start = tokio::time::Instant::now();
    let samples = std::cell::Cell::new(0);
    let mut cache = MeshRttCache::default();
    let sample = || {
        samples.set(samples.get() + 1);
        samples.get() * 10_000
    };

    assert_eq!(cache.get_or_refresh_with(start, sample), 10_000);
    assert_eq!(
        cache.get_or_refresh_with(
            start + MESH_RTT_CACHE_TTL - std::time::Duration::from_nanos(1),
            sample,
        ),
        10_000,
    );
    assert_eq!(samples.get(), 1, "the within-window closure is not run");
}

#[test]
fn mesh_rtt_cache_refreshes_at_the_window_boundary() {
    let start = tokio::time::Instant::now();
    let samples = std::cell::Cell::new(0);
    let mut cache = MeshRttCache::default();
    let sample = || {
        samples.set(samples.get() + 1);
        samples.get() * 10_000
    };

    assert_eq!(cache.get_or_refresh_with(start, sample), 10_000);
    assert_eq!(
        cache.get_or_refresh_with(start + MESH_RTT_CACHE_TTL, sample),
        20_000,
    );
    assert_eq!(samples.get(), 2);
}

#[test]
fn mesh_maintenance_timer_is_link_wide_and_idle_aware() {
    let start = tokio::time::Instant::now();
    let mut timer = MeshMaintenanceTimer::default();

    assert_eq!(timer.deadline(), None, "an idle link has no wakeup");

    timer.arm(start);
    let first_deadline = start + routing::FLUSH_INTERVAL;
    assert_eq!(timer.deadline(), Some(first_deadline));

    // Another session joining this active link must not move the shared
    // cadence; otherwise a stream of Joins could postpone maintenance for
    // sessions already on the link indefinitely.
    timer.arm(start + std::time::Duration::from_millis(75));
    assert_eq!(timer.deadline(), Some(first_deadline));

    let completed_at = start + std::time::Duration::from_secs(1);
    timer.complete_tick(completed_at);
    assert_eq!(
        timer.deadline(),
        Some(completed_at + routing::FLUSH_INTERVAL),
    );

    timer.disarm();
    assert_eq!(
        timer.deadline(),
        None,
        "the last Leave removes the periodic wakeup",
    );

    let rejoined_at = start + std::time::Duration::from_secs(2);
    timer.arm(rejoined_at);
    assert_eq!(
        timer.deadline(),
        Some(rejoined_at + routing::FLUSH_INTERVAL),
        "a later first Join starts a fresh cadence",
    );
}

#[test]
fn redundancy_defers_only_the_session_whose_send_carried_it() {
    let now = tokio::time::Instant::now();
    let original = now + std::time::Duration::from_millis(10);
    let mut redundant_session = original;
    let mut fresh_only_session = original;

    defer_flush_after_send(&mut redundant_session, true, now);
    defer_flush_after_send(&mut fresh_only_session, false, now);

    assert_eq!(
        redundant_session,
        now + routing::FLUSH_INTERVAL,
        "the normal stream is already providing recovery",
    );
    assert_eq!(
        fresh_only_session, original,
        "a fresh-only send still needs its pending maintenance flush",
    );
}

#[tokio::test]
async fn live_and_replay_sends_report_when_they_carry_redundancy() {
    let (mut link, _peer, _client_ep, _server_ep) = connected_mesh_link_pair().await;
    let live_key = control_key();
    link.open_session(mesh_session_key(&live_key));
    let mut control_send = link.connection().open_uni().await.unwrap();

    assert_eq!(
        send_turn_over_link(
            &mut link,
            &mut control_send,
            &live_key,
            turn_payload(0, 0),
            None,
            "test live forward",
        )
        .await,
        Some(false),
        "the first turn has no older unacked turn to re-carry",
    );
    assert_eq!(
        send_turn_over_link(
            &mut link,
            &mut control_send,
            &live_key,
            turn_payload(0, 1),
            None,
            "test live forward",
        )
        .await,
        Some(true),
        "the next live turn reports its redundant re-carry",
    );

    let replay_key = SessionKey {
        tenant: live_key.tenant.clone(),
        session: SessionId(2),
    };
    link.open_session(mesh_session_key(&replay_key));
    assert_eq!(
        send_resume_replay(
            &mut link,
            &mut control_send,
            &new_conditions_registry(),
            &replay_key,
            vec![turn_payload(0, 0), turn_payload(0, 1)],
        )
        .await,
        Some(true),
        "a replay batch propagates the redundancy carried by its later send",
    );
}

fn self_signed() -> (
    Vec<rally_point_transport::rustls::pki_types::CertificateDer<'static>>,
    rally_point_transport::rustls::pki_types::PrivateKeyDer<'static>,
    rally_point_transport::rustls::pki_types::CertificateDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key = rally_point_transport::rustls::pki_types::PrivateKeyDer::try_from(
        cert.signing_key.serialize_der(),
    )
    .unwrap();
    (vec![cert_der.clone()], key, cert_der)
}

/// A loopback mesh-link QUIC connection, wrapped as a [`MeshLink`]. Only one
/// side is needed for the ack-cursor tests below: `apply_ack_cursors` and
/// `reconcile_ack_cursors` operate purely on in-memory transport state
/// (`payloads_in_flight`, `delivered_through_all`, `retire_through`), so
/// what matters is a genuinely established connection to build a
/// `MeshLink` from, not a live peer on the other end.
async fn connected_mesh_link() -> (
    rally_point_transport::MeshLink,
    rally_point_transport::noq::Endpoint,
    rally_point_transport::noq::Endpoint,
) {
    use std::net::{Ipv4Addr, SocketAddr};

    use rally_point_transport::noq;
    use rally_point_transport::quic::{mesh_client_config, server_config};

    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let mut roots = rally_point_transport::rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let client_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();

    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server = noq::Endpoint::server(server_cfg, bind).unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = noq::Endpoint::client(bind).unwrap();
    client.set_default_client_config(client_cfg);

    let accept = {
        let server = server.clone();
        tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() })
    };
    let client_conn = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let _server_conn = accept.await.unwrap();

    (
        rally_point_transport::MeshLink::new(client_conn),
        client,
        server,
    )
}

/// A minimal `SessionState` for `reconcile_ack_cursors`'s `joined` map --
/// a real `MeshLinkRegistration` (needed so its `Drop` doesn't panic) but
/// otherwise inert: nothing in this test drains the registry it points at.
fn bare_session_state(key: SessionKey) -> SessionState {
    let links = new_mesh_links();
    let (fwd, _fwd_rx) = mpsc::channel(8);
    let (ctl, _ctl_rx) = mpsc::unbounded_channel();
    let registration = register_mesh_link(&links, key.clone(), fwd, ctl, Arc::new(Notify::new()));
    SessionState {
        key,
        flush_deadline: tokio::time::Instant::now(),
        _registration: registration,
    }
}

/// `apply_ack_cursors` force-retires exactly the named slots' unacked
/// windows through the peer-confirmed cursor, ignores a frame naming a
/// different session or the wrong kind, and tolerates a malformed slot id
/// rather than panicking -- the mesh-link counterpart of a client-edge
/// driver's beacon-reader-fed `retire_through` call.
#[tokio::test]
async fn apply_ack_cursors_retires_the_named_slots_unacked_window() {
    let (mut link, _client_ep, _server_ep) = connected_mesh_link().await;
    let key = control_key();
    let session = key.session;
    link.open_session(mesh_session_key(&key));
    let mut joined = HashMap::new();
    joined.insert(session, bare_session_state(key.clone()));

    for slot in [0u8, 1] {
        for seq in 0..3u64 {
            let payload = Payload {
                seq,
                slot: u32::from(slot),
                commands: vec![0xAA].into(),
                ..Default::default()
            };
            link.send(mesh_session_key(&key), Some(payload), None)
                .unwrap();
        }
    }
    assert_eq!(link.payloads_in_flight(mesh_session_key(&key)), 6);

    // A frame for a different (unjoined) session is a no-op.
    let other_session_frame = ack_cursors_frame(SessionId(2), vec![(SlotId(0), 2)]);
    apply_ack_cursors(&mut link, &other_session_frame, &joined);
    assert_eq!(link.payloads_in_flight(mesh_session_key(&key)), 6);

    // Retire only slot 0 through seq 1 (seq 2 stays in flight); slot 1 is
    // untouched.
    let frame = ack_cursors_frame(session, vec![(SlotId(0), 1)]);
    apply_ack_cursors(&mut link, &frame, &joined);
    assert_eq!(
        link.payloads_in_flight(mesh_session_key(&key)),
        4,
        "slot 0's seqs 0 and 1 retired; its seq 2 and all of slot 1 remain",
    );

    // A malformed slot id (out of u8 range) in the cursor list is
    // skipped, not a panic; the rest of the frame still applies.
    let mixed = MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::MeshAckCursors(
            rally_point_proto::messages::MeshAckCursors {
                cursors: vec![
                    rally_point_proto::messages::MeshAckCursor {
                        slot: 300,
                        delivered_through: 0,
                    },
                    rally_point_proto::messages::MeshAckCursor {
                        slot: 1,
                        delivered_through: 2,
                    },
                ],
            },
        )),
    };
    apply_ack_cursors(&mut link, &mixed, &joined);
    assert_eq!(
        link.payloads_in_flight(mesh_session_key(&key)),
        1,
        "slot 1 fully retired despite the malformed entry alongside it; \
         only slot 0's seq 2 remains",
    );
}

/// `fold_oversize_into_link` records a stream-delivered oversize turn in
/// the link's per-session receive dedup — advancing the delivered-through
/// cursor the ack-beacon pushes — and gates dispatch: a fresh turn (and
/// every non-oversize frame) proceeds, an already-delivered copy is
/// dropped before it burns a session-level dedup pass, and a frame for an
/// unjoined session passes through for the dispatch's own defensive drop.
#[tokio::test]
async fn fold_oversize_into_link_advances_the_dedup_and_gates_dispatch() {
    let (mut link, _client_ep, _server_ep) = connected_mesh_link().await;
    let key = control_key();
    let session = key.session;
    link.open_session(mesh_session_key(&key));
    let mut joined = HashMap::new();
    joined.insert(session, bare_session_state(key.clone()));

    let oversize = MeshControlFrame {
        session: session.0,
        kind: Some(mesh_control_frame::Kind::OversizeTurn(Payload {
            seq: 0,
            slot: 0,
            commands: vec![0xAB; 2000].into(),
            ..Default::default()
        })),
    };

    assert!(
        fold_oversize_into_link(&mut link, &oversize, &joined),
        "a fresh oversize turn proceeds to dispatch",
    );
    assert_eq!(
        link.delivered_through(mesh_session_key(&key), SlotId(0)),
        Some(0),
        "the stream-delivered seq advances the link's delivered prefix",
    );

    assert!(
        !fold_oversize_into_link(&mut link, &oversize, &joined),
        "a redundant copy is dropped before dispatch",
    );

    // Any other frame kind passes straight through.
    let other = ack_cursors_frame(session, vec![(SlotId(0), 0)]);
    assert!(fold_oversize_into_link(&mut link, &other, &joined));

    // A session this link hasn't joined has no transport state to fold
    // into; the frame still reaches the dispatch's own unjoined-session
    // drop.
    let unjoined = MeshControlFrame {
        session: 99,
        ..oversize.clone()
    };
    assert!(fold_oversize_into_link(&mut link, &unjoined, &joined));
}

/// `reconcile_ack_cursors` pushes a session's advanced cursors exactly
/// once each, stays quiet once the peer has heard the latest value, and
/// resumes pushing on the next genuine advance -- the push-on-advance
/// discipline the mesh-link ack-beacon needs to stay off the hot path on
/// a healthy, quiet link.
#[tokio::test]
async fn reconcile_ack_cursors_pushes_only_on_advance() {
    let key = control_key();
    let session = key.session;

    // `delivered_through_all` reads receive state, so this needs a real
    // sender-to-receiver round trip (mirroring the transport-level
    // tests), not just one side of a connection.
    let (mut sender, mut receiver, _e1, _e2) = connected_mesh_link_pair().await;
    receiver.open_session(mesh_session_key(&key));
    sender.open_session(mesh_session_key(&key));
    sender
        .send(mesh_session_key(&key), Some(turn_payload(0, 0)), None)
        .unwrap();
    receiver.recv().await.unwrap();

    let mut sent: HashMap<(SessionId, SlotId), u64> = HashMap::new();
    let mut joined = HashMap::new();
    joined.insert(session, bare_session_state(key.clone()));

    let frame = reconcile_ack_cursors(&receiver, &mut sent, joined.get(&session).unwrap())
        .expect("the fresh cursor is pushed");
    match frame.kind {
        Some(mesh_control_frame::Kind::MeshAckCursors(cursors)) => {
            assert_eq!(cursors.cursors.len(), 1);
            assert_eq!(cursors.cursors[0].slot, 0);
            assert_eq!(cursors.cursors[0].delivered_through, 0);
        }
        other => panic!("expected MeshAckCursors, got {other:?}"),
    }

    // Nothing advanced: a second reconcile with no new receipt sends
    // nothing.
    let frame = reconcile_ack_cursors(&receiver, &mut sent, joined.get(&session).unwrap());
    assert!(
        frame.is_none(),
        "no advance since the last push -- the beacon stays quiet",
    );

    // A genuine advance (seq 1) is pushed again.
    sender
        .send(mesh_session_key(&key), Some(turn_payload(0, 1)), None)
        .unwrap();
    receiver.recv().await.unwrap();
    let frame = reconcile_ack_cursors(&receiver, &mut sent, joined.get(&session).unwrap())
        .expect("the advance is pushed");
    match frame.kind {
        Some(mesh_control_frame::Kind::MeshAckCursors(cursors)) => {
            assert_eq!(cursors.cursors[0].delivered_through, 1);
        }
        other => panic!("expected MeshAckCursors, got {other:?}"),
    }
}

/// A second loopback mesh-link pair (both sides), for the one test above
/// that needs a real receive to observe `delivered_through_all` advance —
/// distinct from `connected_mesh_link`, which only needs one live side.
pub(crate) async fn connected_mesh_link_pair() -> (
    rally_point_transport::MeshLink,
    rally_point_transport::MeshLink,
    rally_point_transport::noq::Endpoint,
    rally_point_transport::noq::Endpoint,
) {
    use std::net::{Ipv4Addr, SocketAddr};

    use rally_point_transport::noq;
    use rally_point_transport::quic::{mesh_client_config, server_config};

    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let mut roots = rally_point_transport::rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let client_cfg = mesh_client_config(roots, dial_chain, dial_key).unwrap();

    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server = noq::Endpoint::server(server_cfg, bind).unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = noq::Endpoint::client(bind).unwrap();
    client.set_default_client_config(client_cfg);

    let accept = {
        let server = server.clone();
        tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() })
    };
    let client_conn = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let server_conn = accept.await.unwrap();

    (
        rally_point_transport::MeshLink::new(client_conn),
        rally_point_transport::MeshLink::new(server_conn),
        client,
        server,
    )
}

fn turn_payload(slot: u8, seq: u64) -> Payload {
    Payload {
        seq,
        slot: u32::from(slot),
        commands: vec![0xAA].into(),
        ..Default::default()
    }
}
