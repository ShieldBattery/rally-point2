//! `mesh::edge` unit tests: the accept-side handshake semaphore's own
//! mechanism and its wiring through `run_mesh_accept`, plus fleet-peer
//! identity verification against an empty (not-yet-pushed) fleet map.

use std::net::Ipv4Addr;

use rally_point_transport::quic::server_config;
use rally_point_transport::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::mpsc;

use crate::mesh;
use crate::routing::Sessions;

use super::accept::{MESH_ACCEPT_CONCURRENCY, MESH_ACCEPT_PERMITS};
use super::*;

fn self_signed() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    (vec![cert_der.clone()], key, cert_der)
}

/// A loopback QUIC connection negotiated on `MESH_ALPN`, mirroring the
/// integration tests' own helper -- only the accept side is returned
/// (what `run_mesh_accept` would receive off the client edge's ALPN
/// dispatch in production); the dial side is kept alive by the caller via
/// the returned endpoints but is never made to speak, so the accepted
/// connection just sits there as a stalled, unauthenticated mesh peer.
async fn silent_mesh_connection() -> (
    noq::Connection,
    noq::Connection,
    noq::Endpoint,
    noq::Endpoint,
) {
    use rally_point_transport::quic::mesh_client_config;

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
    // Returned, not just dropped here: noq's `Connection` triggers an
    // implicit close of that side when its last handle drops, which
    // would immediately end the "silent" connection this helper exists
    // to hold open.
    let client_conn = client
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let server_conn = accept.await.unwrap();

    (server_conn, client_conn, client, server)
}

/// `MESH_ACCEPT_PERMITS` is a process-wide `static`, so both halves of
/// this coverage run inside ONE test function rather than two -- cargo
/// test runs `#[tokio::test]` functions in parallel by default, and two
/// separate tests both reading/mutating the same static would interfere
/// with each other's `available_permits()` readings. Nothing else in
/// this binary touches this static.
///
/// Part one: the semaphore mechanism itself -- exactly
/// [`MESH_ACCEPT_CONCURRENCY`] permits are available, a request past that
/// queues (does not fail outright -- there is no `try_acquire` refusal
/// path here, unlike the client edge's admission bound), and releasing
/// one lets a queued acquire through.
///
/// Part two: `run_mesh_accept` actually threads a connection's handshake
/// window through the semaphore -- accepting a real (but silent, never
/// sending its hello) mesh connection holds exactly one permit for as
/// long as the connection is alive and unidentified, and releases it
/// once the connection ends. Proves the wiring, not just the mechanism
/// part one already covers.
#[tokio::test]
async fn mesh_accept_permits_cap_concurrency_queue_and_are_held_only_across_the_handshake() {
    // Part one: mechanism.
    let mut held = Vec::new();
    for _ in 0..MESH_ACCEPT_CONCURRENCY {
        held.push(MESH_ACCEPT_PERMITS.acquire().await.unwrap());
    }
    assert_eq!(MESH_ACCEPT_PERMITS.available_permits(), 0);

    // A request past the cap does not resolve while every permit is held.
    let waiter = tokio::spawn(async { MESH_ACCEPT_PERMITS.acquire().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !waiter.is_finished(),
        "a request past the cap must queue, not be refused or admitted early",
    );

    // Releasing one held permit lets the queued request through.
    held.pop();
    let unblocked = tokio::time::timeout(Duration::from_millis(500), waiter)
        .await
        .expect("the queued acquire completes once a permit frees up")
        .unwrap();
    drop(unblocked);
    drop(held);
    assert_eq!(
        MESH_ACCEPT_PERMITS.available_permits(),
        MESH_ACCEPT_CONCURRENCY,
        "every permit released back to the pool before part two begins",
    );

    // Part two: the real wiring.
    let (mesh_accept_tx, mesh_accept_rx) = mpsc::channel(1);
    let (links_tx, _links_rx) = mpsc::channel(1);
    let accept_task = tokio::spawn(run_mesh_accept(
        mesh_accept_rx,
        Sessions::default(),
        mesh::new_mesh_state(),
        links_tx,
        crate::coordinator::client::FleetMeshPeers::new().reader(),
        false,
    ));

    let (silent_conn, _client_conn, _client_ep, _server_ep) = silent_mesh_connection().await;
    mesh_accept_tx.send(silent_conn.clone()).await.unwrap();

    // Give the spawned per-connection task time to acquire its permit and
    // start (and block on) `recv_mesh_hello`.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        MESH_ACCEPT_PERMITS.available_permits(),
        MESH_ACCEPT_CONCURRENCY - 1,
        "one permit held for the one stalled, unidentified connection",
    );

    // End the connection outright (rather than waiting the full
    // `MESH_HELLO_TIMEOUT`) so `recv_mesh_hello` fails fast and the task
    // returns, releasing its permit.
    silent_conn.close(noq::VarInt::from_u32(0), b"test done");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        MESH_ACCEPT_PERMITS.available_permits(),
        MESH_ACCEPT_CONCURRENCY,
        "the permit is released once the stalled connection ends",
    );

    // Part three: back-pressure. With every handshake slot held, the
    // accept loop must stop draining the hand-off channel: at most one
    // connection waits at the loop itself (taken off the channel, parked
    // on its permit) and the channel's own bound queues the rest — never
    // one parked task per connection. Proven by filling both stations and
    // watching a third connection find the cap-1 channel still full.
    let mut held = Vec::new();
    for _ in 0..MESH_ACCEPT_CONCURRENCY {
        held.push(MESH_ACCEPT_PERMITS.acquire().await.unwrap());
    }
    let (parked_conn, _pc, _pe1, _pe2) = silent_mesh_connection().await;
    mesh_accept_tx.send(parked_conn.clone()).await.unwrap();
    let (queued_conn, _qc, _qe1, _qe2) = silent_mesh_connection().await;
    mesh_accept_tx.send(queued_conn.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (overflow_conn, _oc, _oe1, _oe2) = silent_mesh_connection().await;
    assert!(
        mesh_accept_tx.try_send(overflow_conn).is_err(),
        "with every handshake slot busy, one connection waits at the loop and \
         the channel holds the next — a third finds the queue full",
    );

    // Freeing the slots drains the waiting room into handshake tasks.
    drop(held);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        MESH_ACCEPT_PERMITS.available_permits(),
        MESH_ACCEPT_CONCURRENCY - 2,
        "both waiting connections were admitted once slots freed",
    );
    parked_conn.close(noq::VarInt::from_u32(0), b"test done");
    queued_conn.close(noq::VarInt::from_u32(0), b"test done");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        MESH_ACCEPT_PERMITS.available_permits(),
        MESH_ACCEPT_CONCURRENCY,
        "every permit released once the drained connections end",
    );

    drop(mesh_accept_tx);
    let _ = accept_task.await;
}

#[tokio::test]
async fn an_empty_fleet_map_is_enforced_only_when_peer_auth_is_required() {
    // The seam a coordinator-driven relay turns on: with the fleet map still
    // empty (no push has landed yet), `require_peer_auth` decides whether a
    // dialing peer is admitted. A coordinator-driven relay passes `true` here
    // (see `main::mesh_peer_auth_required`), so it fails closed from boot; a
    // dev/static `--mesh-peer` relay passes `false` and stays open.
    let (server_conn, _client_conn, _client_ep, _server_ep) = silent_mesh_connection().await;
    let empty = crate::coordinator::client::FleetMeshPeers::new().reader();
    assert!(empty.is_empty(), "no fleet-peer push has landed");

    // Peer auth off (dev/static, no coordinator): the empty map is unenforced,
    // so the dial is admitted even though nothing could be pinned against it.
    assert!(
        verify_mesh_peer_identity(&server_conn, RelayId(1), &empty, false).is_ok(),
        "an empty fleet map with peer auth off admits the dial",
    );

    // Peer auth required (a coordinator-driven relay, or `--require-mesh-peer-auth`):
    // the claimed id is absent from the empty set, so the dial is refused as an
    // unknown peer before the first push ever lands.
    assert_eq!(
        verify_mesh_peer_identity(&server_conn, RelayId(1), &empty, true),
        Err(MeshPeerAuthRefusal::UnknownPeer),
        "an empty fleet map with peer auth required refuses every dial",
    );
}
