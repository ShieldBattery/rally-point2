//! `mesh::edge` unit tests: the accept-side handshake semaphore's own
//! mechanism and its wiring through `run_mesh_accept`, plus fleet-peer
//! identity verification against an empty (not-yet-pushed) fleet map.

use rally_point_transport::test_util::{Edge, loopback};
use tokio::sync::mpsc;

use crate::mesh;
use crate::routing::Sessions;

use super::accept::{MESH_ACCEPT_CONCURRENCY, MESH_ACCEPT_PERMITS};
use super::*;

/// A loopback QUIC connection negotiated on `MESH_ALPN`: the accept side --
/// what `run_mesh_accept` receives off the client edge's ALPN dispatch in
/// production -- plus the dial side and both endpoints. The dialer is never
/// made to speak, so the accepted connection just sits there as a stalled,
/// unauthenticated mesh peer; every handle is returned rather than dropped
/// here because noq closes a connection once its last handle goes away, which
/// would end the "silent" connection immediately.
async fn silent_mesh_connection() -> (
    noq::Connection,
    noq::Connection,
    noq::Endpoint,
    noq::Endpoint,
) {
    let (dialer, acceptor, dial_endpoint, accept_endpoint) = loopback(Edge::Mesh).await;
    (acceptor, dialer, dial_endpoint, accept_endpoint)
}

/// Waits for the accept semaphore to report exactly `want` free permits,
/// failing with `why` if it never does. A bounded poll rather than a fixed
/// sleep: the common case returns almost immediately, and only a genuine
/// regression spends the whole bound.
async fn await_permits(want: usize, why: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let available = MESH_ACCEPT_PERMITS.available_permits();
        if available == want {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{why}: expected {want} free mesh-accept permits, saw {available}",
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
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
    // The one genuinely negative wait here: "still queued" has nothing to
    // poll towards, so it keeps a short window.
    let waiter = tokio::spawn(async { MESH_ACCEPT_PERMITS.acquire().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(20)).await;
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

    // The spawned per-connection task takes its permit and then blocks on
    // `recv_mesh_hello`.
    await_permits(
        MESH_ACCEPT_CONCURRENCY - 1,
        "one permit held for the one stalled, unidentified connection",
    )
    .await;

    // End the connection outright (rather than waiting the full
    // `MESH_HELLO_TIMEOUT`) so `recv_mesh_hello` fails fast and the task
    // returns, releasing its permit.
    silent_conn.close(noq::VarInt::from_u32(0), b"test done");
    await_permits(
        MESH_ACCEPT_CONCURRENCY,
        "the permit is released once the stalled connection ends",
    )
    .await;

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
    // The channel is one deep, so this send completes only once the loop has
    // taken the first connection off it — by the time it returns both
    // stations are occupied, with no wait to guess at.
    mesh_accept_tx.send(queued_conn.clone()).await.unwrap();

    let (overflow_conn, _oc, _oe1, _oe2) = silent_mesh_connection().await;
    assert!(
        mesh_accept_tx.try_send(overflow_conn).is_err(),
        "with every handshake slot busy, one connection waits at the loop and \
         the channel holds the next — a third finds the queue full",
    );

    // Freeing the slots drains the waiting room into handshake tasks.
    drop(held);
    await_permits(
        MESH_ACCEPT_CONCURRENCY - 2,
        "both waiting connections were admitted once slots freed",
    )
    .await;
    parked_conn.close(noq::VarInt::from_u32(0), b"test done");
    queued_conn.close(noq::VarInt::from_u32(0), b"test done");
    await_permits(
        MESH_ACCEPT_CONCURRENCY,
        "every permit released once the drained connections end",
    )
    .await;

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
