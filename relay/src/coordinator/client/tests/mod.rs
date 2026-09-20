//! Shared fixtures for the coordinator-client tests: the session/descriptor
//! builders, the notice and flight-shipment samples, the stand-in coordinator's
//! enroll handshake driver, and the config constructors the subscriber tests all
//! spawn through.

use std::net::{Ipv4Addr, SocketAddr};

use bytes::Bytes;

use super::connect::{build_request, to_ws_scheme};
use super::heartbeat::{
    LoadStateAnswer, LoadStateAsk, fenced_load_state_snapshot, heartbeat_presence,
    heartbeat_region_rtts, session_load_snapshot, start_load_state_answer,
};
use super::reader::{apply_message, reconcile};
use super::writer::{FlightGrant, WriterRoutes, send_notice, write_control_frames};
use super::*;
use crate::mesh::MeshCommand;
use crate::observability::flight_recorder::FLIGHT_SHIP_QUEUE;
use futures_util::{SinkExt, StreamExt};
use rally_point_proto::control::{
    BufferBounds, CoordinatorToRelay, DepartureNotice, DescriptorKey, DesyncNotice, DivergedSlot,
    RegionBeaconTarget, RegionId, RegionRttReport, RelayPeer, RelayToCoordinator,
    SessionDescriptor, SessionPresence, TenantId,
};
use rally_point_proto::ids::SessionId;
use rally_point_proto::version::{
    CONTROL_CLOSE_DUPLICATE_RELAY_ID, CONTROL_CLOSE_ENROLL_UNAUTHORIZED,
    CONTROL_CLOSE_IDENTITY_UNPROVEN, CONTROL_CLOSE_PROTOCOL_MISMATCH, CONTROL_CLOSE_UNKNOWN_REGION,
};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;

mod descriptors;
mod drain;
mod enroll;
mod fence;
mod flight;
mod notices;
mod presence;
mod reconnect;
mod stores;

const TENANT: &str = "sb-test";

/// The Join source the tests drive, with no mesh link registered.
fn control() -> MeshControl {
    MeshControl::new(RelayId(1), Arc::default(), Arc::default())
}

/// [`control`] with a link to `peer` registered, paired with the receiver that
/// link's [`MeshCommand`]s arrive on.
fn control_with_link(peer: u64) -> (MeshControl, mpsc::UnboundedReceiver<MeshCommand>) {
    let control = control();
    let (tx, rx) = mpsc::unbounded_channel();
    let _ = control.register_link(RelayId(peer), 1, tx);
    (control, rx)
}

/// Decodes one frame a stand-in coordinator read into the message it carries.
fn decode(message: Message) -> RelayToCoordinator {
    let Message::Text(text) = message else {
        panic!("a text frame");
    };
    serde_json::from_str(&text).expect("the frame is a relay-to-coordinator message")
}

/// A session with a decision-maker and no bounds worth speaking of — enough for
/// the retained load state a fence or a heartbeat entry reads and re-reads.
fn fence_fixture() -> (Sessions, Arc<crate::consensus::DecisionMakers>) {
    let sessions: Sessions = Arc::default();
    let decision_makers = Arc::new(crate::consensus::new_decision_makers());
    let _ = crate::consensus::sync_maker(
        &decision_makers,
        &key(7),
        crate::consensus::MakerSync::new(
            BufferBounds { min: 1, max: 6 },
            crate::consensus::Authority::SelfRelay,
        ),
    );
    (sessions, decision_makers)
}

/// Everything one subscriber launch takes, with every seam a test is not
/// asserting on defaulted to disabled: a closed notice pipe, no flight
/// shipments, a drain that never fires, an empty roster beating an hour from
/// now, and a fast ordinary redial. A test names only the fields it drives:
///
/// ```ignore
/// SubscriberFixture { notices, ..Default::default() }.spawn(addr);
/// ```
struct SubscriberFixture {
    control: MeshControl,
    applied: AppliedSessions,
    fleet: FleetMeshPeers,
    drain_acked: watch::Sender<bool>,
    notices: UnboundedReceiver<RelayNotice>,
    flight: Receiver<FlightShipment>,
    stats: ControlConnStats,
    heartbeat: HeartbeatConfig,
    drain: watch::Receiver<bool>,
    connected: watch::Sender<bool>,
    backoff: ReconnectBackoff,
}

impl Default for SubscriberFixture {
    fn default() -> Self {
        Self {
            control: control(),
            applied: AppliedSessions::default(),
            fleet: FleetMeshPeers::default(),
            // A throwaway sender: an ack `send` on it is a harmless no-op.
            drain_acked: watch::channel(false).0,
            // Both pipes' send halves drop here, so the loop's notice and flight
            // arms disable themselves rather than spinning on a closed channel.
            notices: mpsc::unbounded_channel().1,
            flight: no_flight(),
            stats: ControlConnStats::new(),
            heartbeat: heartbeat(Duration::from_secs(3600)),
            drain: watch::channel(false).1,
            connected: no_connected(),
            backoff: backoff(Duration::from_millis(20), Duration::from_secs(60)),
        }
    }
}

impl SubscriberFixture {
    /// Spawns the subscriber against the stand-in coordinator listening at `addr`.
    fn spawn(self, addr: SocketAddr) {
        tokio::spawn(run_descriptor_subscriber_with(
            enroll(addr, drain_hello()),
            ControlApplyTargets {
                control: self.control,
                applied: self.applied,
                fleet: self.fleet,
                verifying_keys: SharedRegistry::default(),
                region_targets: RegionPingTargets::default(),
                drain_acked: self.drain_acked,
            },
            OutboundQueues::new(self.notices, self.flight, self.stats),
            self.heartbeat,
            self.drain,
            self.connected,
            self.backoff,
        ));
    }
}

fn key(session: u64) -> SessionKey {
    SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(session),
    }
}

fn descriptor(session: u64, peers: &[u64]) -> SessionDescriptor {
    SessionDescriptor {
        finalized_drops: false,
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(session),
        peers: peers
            .iter()
            .map(|&id| RelayPeer {
                relay_id: RelayId(id),
                relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900 + id as u16)),
                cert_der: vec![id as u8; 4],
                relay_addrs: vec![],
            })
            .collect(),
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
        expected_slots: vec![],
        homed_slots: vec![],
        resumed: false,
        departed_slots: vec![],
        latency_estimate_ms: None,
        relay_regions: Vec::new(),
    }
}

fn dropped_notice() -> DepartureNotice {
    DepartureNotice {
        finalized: false,
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(42),
        slot: rally_point_proto::ids::SlotId(2),
        kind: rally_point_proto::control::DepartureKind::Dropped,
        reason: 0x4000_0006,
        leave_seq: 3,
        external_id: None,
        external_ref: None,
        result: None,
        final_turn_count: None,
    }
}

fn desync_notice() -> DesyncNotice {
    DesyncNotice {
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(42),
        sync_ordinal: 91,
        game_frame: Some(3000),
        detected_at_ms: 1_700_000_000_000,
        no_majority: false,
        diverged: vec![DivergedSlot {
            slot: rally_point_proto::ids::SlotId(1),
            external_ref: Some("sb-user-1".to_owned()),
        }],
        external_id: Some("game-42".to_owned()),
    }
}

/// A throwaway `control_connected` sender for a test that doesn't assert
/// on the connection-state signal itself.
fn no_connected() -> watch::Sender<bool> {
    watch::channel(false).0
}

/// A closed flight receiver for tests that don't exercise the flight pipe: its
/// sender is dropped, so the loop's flight arm disables itself and never fires.
fn no_flight() -> Receiver<FlightShipment> {
    mpsc::channel(1).1
}

/// The enroll config for a subscriber pointed at the stand-in coordinator at
/// `addr`, presenting `relay_hello` and a signable throwaway identity key.
fn enroll(addr: std::net::SocketAddr, relay_hello: RelayHello) -> EnrollConfig {
    EnrollConfig {
        coordinator_url: format!("http://{addr}"),
        bootstrap_secret: None,
        relay_hello,
        identity_key: throwaway_identity_key(),
    }
}

/// A heartbeat config over an empty roster and RTT cache at the given interval —
/// the common case for tests not asserting on heartbeat content.
fn heartbeat(interval: Duration) -> HeartbeatConfig {
    HeartbeatConfig {
        sources: HeartbeatSources {
            sessions: Arc::default(),
            decision_makers: Arc::new(crate::consensus::new_decision_makers()),
            region_rtt_cache: RegionRttCache::default(),
            load_fence: crate::coordinator::load_fence::LoadStateFence::new(),
        },
        interval,
    }
}

/// The two redial delays as a backoff config.
fn backoff(ordinary: Duration, version_refused: Duration) -> ReconnectBackoff {
    ReconnectBackoff {
        ordinary,
        version_refused,
    }
}

/// A flight shipment for the connection-loop tests, paired with the ack receiver
/// its `sent` half resolves once the recording is stored. The stand-in coordinator
/// reads the `FlightUploadRequest` frame the loop sends for it.
fn flight_shipment() -> (FlightShipment, oneshot::Receiver<()>) {
    flight_shipment_with_payload(Bytes::from_static(b"compressed-bytes"))
}

/// A flight shipment carrying `payload` (the compressed recording bytes), paired
/// with the ack receiver its `sent` half resolves once stored.
fn flight_shipment_with_payload(payload: Bytes) -> (FlightShipment, oneshot::Receiver<()>) {
    let (sent, ack) = oneshot::channel();
    let shipment = FlightShipment {
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(7),
        desynced: false,
        payload,
        sent,
    };
    (shipment, ack)
}

/// The relay's enroll Hello for these drain tests.
fn drain_hello() -> RelayHello {
    RelayHello::new(
        RelayId(1),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 14900)),
        rally_point_proto::version::ProtocolVersion::CURRENT,
        vec![0xAB; 4],
    )
}

/// A private key for the `identity_key` these stand-in-coordinator tests
/// pass. `rcgen`'s default is an ECDSA P-256 key, which [`sign_enroll_proof`]
/// can sign, so [`accept_enroll`]'s challenge is answered with a valid
/// `IdentityProof`. The stand-in coordinators don't *verify* the signature —
/// they only assert the proof frame arrives in the right order — so any
/// signable key suffices.
fn throwaway_identity_key() -> PrivateKeyDer<'static> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap()
}

/// Drives the coordinator side of the enroll proof-of-possession handshake on
/// `ws`: reads the relay's Hello, sends an `IdentityChallenge`, and reads and
/// asserts the relay's `IdentityProof` answer — leaving `ws` positioned to
/// read the relay's first post-enroll application frame. Returns the Hello
/// frame for the caller's own assertions.
///
/// Every stand-in coordinator that reads past the Hello must run this first:
/// the relay completes the enroll handshake before it sends any application
/// frame (notice, drain, heartbeat), so a coordinator that skipped the
/// challenge would leave the relay blocked waiting for one.
async fn accept_enroll<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> Message
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let hello = ws.next().await.unwrap().unwrap();
    let challenge =
        serde_json::to_string(&CoordinatorToRelay::IdentityChallenge { nonce: [0u8; 32] })
            .expect("an identity-challenge frame serializes");
    ws.send(Message::Text(challenge.into())).await.unwrap();
    let proof = ws.next().await.unwrap().unwrap();
    let Message::Text(proof) = proof else {
        panic!("the relay answers the challenge with a text IdentityProof frame");
    };
    assert!(
        matches!(
            serde_json::from_str::<RelayToCoordinator>(&proof).unwrap(),
            RelayToCoordinator::IdentityProof { .. },
        ),
        "the relay's first post-Hello frame is the IdentityProof",
    );
    hello
}
