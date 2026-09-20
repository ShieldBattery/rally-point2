//! Shared fixtures for the driver's tests: a connected link both ends of a
//! driver can run over, the shortened timing they run on, a fake authorization
//! identity, and the helpers that drive a bare `session` or read one control
//! frame at a time.
//!
//! The topic modules below inherit all of it, plus the driver's own private
//! items, through their `use super::*;`.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::Ordering;

use rally_point_proto::beacon;
use rally_point_transport::control::{ControlInbound, send_control_turn, spawn_control_reader};
use rally_point_transport::noq;
use rally_point_transport::test_util::{Edge, loopback};

use super::backoff::*;
use super::reconnect::*;
use super::retention::*;
use super::send::*;
use super::state::*;
use super::*;

mod connectivity;
mod control_frames;
mod delivery;
mod leave_result;
mod reconnect;
mod recovery;
mod retention;
mod teardown;

/// The windows every driver test here runs on. Each is cut to the shortest span
/// that still comfortably outlasts a loopback round trip, so a test waits on the
/// driver reacting rather than on a window sized for a real network — and a test
/// that asserts a window actually elapsed asserts against these, not the
/// production defaults.
const TEST_TIMING: DriverTiming = DriverTiming {
    teardown_settle: Duration::from_millis(100),
    leave_intent_timeout: Duration::from_millis(200),
    flush_interval: Duration::from_millis(50),
};

/// [`LinkDriver::new`] on the shortened [`TEST_TIMING`] — what a test builds a
/// driver with unless it is specifically about the production windows.
fn test_driver(link: Link) -> (LinkDriver, TurnChannels) {
    let (driver, channels) = LinkDriver::new(link);
    (driver.with_timing(TEST_TIMING), channels)
}

/// [`test_driver`] with an explicit per-direction channel depth.
fn test_driver_with_capacity(link: Link, capacity: usize) -> (LinkDriver, TurnChannels) {
    let (driver, channels) = LinkDriver::with_capacity(link, capacity);
    (driver.with_timing(TEST_TIMING), channels)
}

/// Brings up a loopback QUIC connection and wraps each end in a [`Link`]. The
/// endpoints are returned so the caller keeps them alive for the test.
async fn connected_links() -> (Link, Link, noq::Endpoint, noq::Endpoint) {
    let (client_conn, server_conn, client, server) = loopback(Edge::Client).await;
    (
        Link::new(client_conn),
        Link::new(server_conn),
        client,
        server,
    )
}

fn turn(seq: u64, bytes: &[u8]) -> Payload {
    Payload {
        // The sending client assigns the origin seq; a raw link send honors
        // it verbatim, while the driver stamps its own counter (so the value
        // here is ignored on the driver-send path).
        seq,
        slot: 0,
        commands: bytes.to_vec().into(),
        ..Default::default()
    }
}

/// A token-shaped identity for driving `run_reconnecting` against fakes: the
/// signature is never presented to a verifier here, so a zeroed one is fine —
/// the driver itself only reads the claims (its own slot, the expiry).
fn fake_identity(slot: SlotId) -> crate::identity::Identity {
    use rally_point_proto::control::TenantId;
    use rally_point_proto::ids::SessionId;
    use rally_point_proto::token::{
        ClientPublicKey, ExpiresAt, KeyId, Signature, SignedToken, TokenClaims,
    };

    let pkcs8 =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let claims = TokenClaims::new(
        TenantId("test".to_owned()),
        SessionId(1),
        slot,
        ExpiresAt(u64::MAX),
        ClientPublicKey([0; 32]),
    );
    let token = SignedToken {
        kid: KeyId::new("test-key".to_owned()).unwrap(),
        claims,
        signature: Signature([0; 64]),
    };
    crate::identity::Identity::from_pkcs8(token, pkcs8.as_ref()).unwrap()
}

/// A provider whose ask never resolves — the embedder's app-server call
/// hanging — with a signal for when the driver actually asked.
struct HangingProvider {
    asked: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl HangingProvider {
    fn new() -> (Arc<Self>, tokio::sync::oneshot::Receiver<()>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        (
            Arc::new(Self {
                asked: std::sync::Mutex::new(Some(tx)),
            }),
            rx,
        )
    }
}

impl RehomeProvider for HangingProvider {
    fn rehome(&self, _dead_relay_id: u64) -> RehomeFuture<'_> {
        if let Some(tx) = self.asked.lock().unwrap().take() {
            let _ = tx.send(());
        }
        Box::pin(std::future::pending())
    }
}

/// Drives one session on `own_slot`, feeding it one small datagram turn per
/// entry in `turns` and then closing the outbound seam so the session returns.
/// The peer link is never driven, so nothing acks: every sent turn stays in the
/// returned link's unacked window — the in-flight shape a reconnect anchors on.
/// The peer link and endpoints are returned so the caller keeps the connection
/// alive for any post-session wire inspection.
async fn drive_unacked_session(
    own_slot: SlotId,
    turns: &[&[u8]],
) -> (Link, LoopState, Link, noq::Endpoint, noq::Endpoint) {
    let (link_a, link_b, ea, eb) = connected_links().await;
    let (driver_a, chan_a) = test_driver(link_a);
    // Buffer every turn (channel depth is ample) and then drop the sender, so
    // the session drains them all and returns Ok on the closed-seam `None`.
    for bytes in turns {
        chan_a.outbound.send(turn(0, bytes)).await.unwrap();
    }
    drop(chan_a.outbound);
    let (mut link, mut seam, mut state) = driver_a.into_parts();
    // `session_body`, not `session`: this helper's whole contract (see its
    // doc above) is inspecting the connection after the session ends, and
    // `session`'s own clean-exit close would race that inspection over
    // the unreliable datagram path -- exactly the hazard closing on a
    // clean exit is supposed to be safe to do in production, just not
    // compatible with a test that wants to keep reading afterward.
    LinkDriver::session_body(&mut link, &mut seam, &mut state, own_slot)
        .await
        .expect("session stops cleanly once the outbound seam closes");
    (link, state, link_b, ea, eb)
}

/// Runs one session over `link`/`seam`/`state` in its own task, handing all
/// three back when it ends — the shape a test needs to drive two consecutive
/// links (a reconnect) while watching the wire in between.
fn spawn_session(
    mut link: Link,
    mut seam: GameSeam,
    mut state: LoopState,
) -> tokio::task::JoinHandle<(Result<(), DriverError>, Link, GameSeam, LoopState)> {
    tokio::spawn(async move {
        let result = LinkDriver::session_body(&mut link, &mut seam, &mut state, SlotId(0)).await;
        (result, link, seam, state)
    })
}

/// Awaits the next control frame `control_rx` delivers, failing the test with
/// `context` if none arrives.
async fn next_control_frame(
    control_rx: &mut mpsc::Receiver<ControlInbound>,
    context: &str,
) -> ControlInbound {
    tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{context}"))
        .expect("control reader ended early")
}

/// Mirrors the driver's datagram-branch inbound ingest for a single slot:
/// buffer a turn only at or above the next-needed seq, then release the
/// contiguous prefix to the game. This is the exact bookkeeping the resume
/// cursor is read from.
fn ingest_turn(
    slot: SlotId,
    seq: u64,
    next_seq: &mut HashMap<SlotId, u64>,
    pending: &mut HashMap<SlotId, BTreeMap<u64, Payload>>,
    inbound: &mpsc::Sender<Payload>,
) {
    let slot_next = *next_seq.entry(slot).or_insert(0);
    if seq >= slot_next {
        pending
            .entry(slot)
            .or_default()
            .insert(seq, turn(seq, &[seq as u8]));
    }
    assert!(matches!(
        release_ready(next_seq, pending, inbound),
        Release::Delivered
    ));
}
