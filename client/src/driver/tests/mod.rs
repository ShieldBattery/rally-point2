//! Shared fixtures for the driver's tests: a connected link both ends of a
//! driver can run over, the shortened timing they run on, a fake authorization
//! identity, and the helpers that drive a bare `session` or read one control
//! frame at a time.
//!
//! The topic modules below inherit all of it, plus the driver's own private
//! items, through their `use super::*;`.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::Ordering;

use rally_point_proto::beacon;
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{LeaveDirective, Payload};
use rally_point_transport::control::{ControlInbound, send_control_turn, spawn_control_reader};
use rally_point_transport::noq;
use rally_point_transport::test_util::{Edge, loopback};
use tokio::sync::mpsc;

use super::backoff::*;
use super::reconnect::*;
use super::reorder::*;
use super::retention::*;
use super::state::*;
use super::*;

mod connectivity;
mod control_frames;
mod delivery;
mod leave_result;
mod reconnect;
mod recovery;
mod reorder;
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

/// A running driver with the peer's side of the wire fully wired up: the game's
/// channels, the peer's raw [`Link`], a control-frame reader watching what the
/// driver writes (the way a relay does), and the peer's own control stream to
/// write frames down.
///
/// The endpoints ride along, so a test never has to hold them by hand — several
/// of these tests keep the connection alive through nothing but an unused
/// binding, and getting that wrong produces a confusing unrelated failure.
struct DriverFixture {
    /// The game thread's end of the seam.
    chan: TurnChannels,
    /// The peer's end of the wire — the relay's side.
    peer: Link,
    /// The frames the driver has written up its control stream.
    control_rx: mpsc::Receiver<ControlInbound>,
    /// The peer's own control stream, the one a relay pushes frames down.
    peer_control: noq::SendStream,
    task: tokio::task::JoinHandle<Result<(), DriverError>>,
    /// The peer's unused recv half: by convention each side reads the stream the
    /// other opened, so this one only has to stay open.
    _peer_control_recv: noq::RecvStream,
    _endpoints: (noq::Endpoint, noq::Endpoint),
}

impl DriverFixture {
    /// A driver on the shortened [`TEST_TIMING`], running `run` on its own task.
    async fn new() -> Self {
        let (link_a, peer, ea, eb) = connected_links().await;
        let (driver, chan) = test_driver(link_a);
        Self::over(driver, chan, peer, ea, eb).await
    }

    /// [`new`](Self::new) with an explicit per-direction channel depth.
    async fn with_capacity(capacity: usize) -> Self {
        let (link_a, peer, ea, eb) = connected_links().await;
        let (driver, chan) = test_driver_with_capacity(link_a, capacity);
        Self::over(driver, chan, peer, ea, eb).await
    }

    /// [`new`](Self::new) over a driver the caller built — for a test that needs
    /// its own timing.
    async fn over(
        driver: LinkDriver,
        chan: TurnChannels,
        peer: Link,
        ea: noq::Endpoint,
        eb: noq::Endpoint,
    ) -> Self {
        let control_rx = spawn_control_reader(peer.connection().clone());
        let (peer_control, peer_control_recv) = peer.connection().open_bi().await.unwrap();
        let task = tokio::spawn(driver.run());
        Self {
            chan,
            peer,
            control_rx,
            peer_control,
            task,
            _peer_control_recv: peer_control_recv,
            _endpoints: (ea, eb),
        }
    }

    /// Awaits the next frame the driver wrote up its control stream, failing the
    /// test with `context` if none arrives.
    async fn next_control_frame(&mut self, context: &str) -> ControlInbound {
        next_control_frame(&mut self.control_rx, context).await
    }

    /// Commands a `delay_us` send-phase delay and waits for the driver to adopt
    /// it. The commanded slew rate is absurd on purpose: the client must clamp
    /// it rather than trust it, so the applied delay still only creeps upward.
    async fn command_phase_delay(&mut self, delay_us: u32) {
        use rally_point_proto::messages::PhaseDirective;
        use rally_point_transport::control::send_control_phase_directive;

        send_control_phase_directive(
            &mut self.peer_control,
            PhaseDirective {
                delay_us,
                slew_us_per_s: 1_000_000,
            },
        )
        .await
        .unwrap();
        let mut status_rx = self.chan.phase_status.clone();
        tokio::time::timeout(
            Duration::from_secs(5),
            status_rx.wait_for(|status| status.target_us == delay_us),
        )
        .await
        .expect("the directive reaches the driver before the timeout")
        .expect("the status watch stays open");
    }

    /// [`command_phase_delay`](Self::command_phase_delay) plus the wait that
    /// lets the slew build a delay a test can race a beat against. The applied
    /// delay climbs at the clamped ceiling of 10 ms per second, so this buys
    /// roughly 5 ms — several times the millisecond beats below, and nowhere
    /// near the target a client that stepped instead of slewing would have
    /// jumped straight to.
    async fn slewed_session(&mut self, delay_us: u32) {
        self.command_phase_delay(delay_us).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    /// The teardown epilogue: the game drops its whole side of the seam, and the
    /// driver drains and stops cleanly.
    async fn finish(self) {
        drop(self.chan);
        let joined = tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("the driver stops once the game seam closes")
            .unwrap();
        assert!(joined.is_ok(), "a seam drop is a clean stop: {joined:?}");
    }

    /// [`finish`](Self::finish) for a driver expected to have ended with a
    /// failure, handing the error back to be classified.
    async fn finish_err(self) -> DriverError {
        drop(self.chan);
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("the driver stops instead of hanging")
            .unwrap()
            .expect_err("the driver was expected to end with a failure")
    }
}

/// A driver's sessions across a simulated outage, the shape the reconnect loop
/// drives: one session per connection with the loop state carried across, and a
/// control-frame reader on whichever connection is current. Standing this up by
/// hand is four fiddly steps in a fixed order — split the driver, spawn a
/// session, kill the connection, rebind onto a fresh one — that a test about
/// what survives a reconnect should not have to restate.
struct ReconnectSessions {
    session: tokio::task::JoinHandle<(Result<(), DriverError>, Link, GameSeam, LoopState)>,
    /// The frames the driver has written up the current connection.
    control_rx: mpsc::Receiver<ControlInbound>,
    /// The peer end of the current connection, plus everything holding it open.
    peer: Link,
    _connection: (Option<Link>, noq::Endpoint, noq::Endpoint),
}

impl ReconnectSessions {
    /// Brings the first session up over a fresh loopback pair, on the shortened
    /// [`TEST_TIMING`].
    async fn start() -> (Self, TurnChannels) {
        let (link_a, peer, ea, eb) = connected_links().await;
        let (driver, chan) = test_driver(link_a);
        let control_rx = spawn_control_reader(peer.connection().clone());
        let (link, seam, state) = driver.into_parts();
        let sessions = Self {
            session: spawn_session(link, seam, state),
            control_rx,
            peer,
            _connection: (None, ea, eb),
        };
        (sessions, chan)
    }

    /// The outage and the re-dial: the relay's connection dies under the driver
    /// (ending the session with a failure, the game seam untouched), then the
    /// link is rebound in place onto a fresh connection — carrying the loop
    /// state, which is where anything a resumed session must re-assert lives.
    async fn reconnect(self) -> Self {
        self.peer.connection().close(0u32.into(), b"outage");
        let (result, mut link, seam, state) = self.session.await.unwrap();
        assert!(result.is_err(), "the closed connection ends the session");

        let (fresh, peer, ea, eb) = connected_links().await;
        link.rebind(fresh.connection().clone());
        let control_rx = spawn_control_reader(peer.connection().clone());
        Self {
            session: spawn_session(link, seam, state),
            control_rx,
            peer,
            _connection: (Some(fresh), ea, eb),
        }
    }

    /// Awaits the next frame the driver wrote up the current control stream.
    async fn next_control_frame(&mut self, context: &str) -> ControlInbound {
        next_control_frame(&mut self.control_rx, context).await
    }
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
    identity_expiring_at(slot, u64::MAX)
}

/// [`fake_identity`] whose token expires at `expires_at` (seconds since the
/// Unix epoch) rather than never — the input the reconnect loop's own expiry
/// check reads.
fn identity_expiring_at(slot: SlotId, expires_at: u64) -> crate::identity::Identity {
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
        ExpiresAt(expires_at),
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

/// The driver's half of the game seam with no connection behind it, plus the
/// game's half and the state a session would run on — what a test of the waits
/// that keep servicing the seam (`await_rehome`, `wait_backoff`) needs, with no
/// QUIC pair to stand up for a link the code under test never touches.
fn seam_only() -> (GameSeam, TurnChannels, LoopState) {
    let (seam, channels, result_expected) = GameSeam::with_capacity(TURN_CHANNEL_CAPACITY);
    (seam, channels, LoopState::new(result_expected, TEST_TIMING))
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
