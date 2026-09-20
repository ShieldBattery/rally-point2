//! Shared control-connection test machinery for the coordinator's integration
//! suites: minting relay identities and answering the coordinator's enroll
//! proof-of-possession challenge, so the descriptor-transport and
//! enroll-identity tests drive a real challenged control connection the same way.
//!
//! Every accepted control connection is challenged — negotiation refuses any
//! relay advertising a version below the challenge threshold — so a fake relay
//! that opens a raw control socket must read the `IdentityChallenge` and answer
//! it with a signature made by the key backing the certificate its `Hello`
//! carried, or the coordinator refuses it before any descriptor flows.

// Each integration-test binary that pulls this module in uses only some of these
// helpers; the rest are legitimately unused there, which is the norm for a shared
// `tests/common` module.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rally_point_coordinator::api::{self, ControlAuth, CoordinatorState};
use rally_point_coordinator::ledger::RelayLedger;
use rally_point_coordinator::lifecycle::Lifecycle;
use rally_point_coordinator::regions::RegionsConfig;
use rally_point_coordinator::registry::{self, RelayRegistry};
use rally_point_coordinator::session::SessionSetup;
use rally_point_coordinator::tenant;
use rally_point_proto::control::{
    BufferBounds, CoordinatorToRelay, RegionBeaconTarget, RelayHello, RelayToCoordinator, TenantId,
    TenantVerifyingKey,
};
use rally_point_proto::ids::RelayId;
use rally_point_proto::token::KeyId;
use rally_point_proto::version::ProtocolVersion;
use rally_point_relay::coordinator;
use rustls_pki_types::PrivateKeyDer;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// The client WebSocket a test drives against the coordinator's control
/// endpoint.
pub type ControlSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A self-signed certificate (DER) plus its matching PKCS#8 private key — the
/// pair a relay needs to answer an enroll proof-of-possession challenge. Each
/// call mints a fresh, independent identity.
pub fn self_signed() -> (Vec<u8>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = cert.cert.der().to_vec();
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    (cert_der, key)
}

/// Relay id → (cert DER, PKCS#8 key DER), the per-id identity cache's contents.
type IdentityMap = HashMap<u64, (Vec<u8>, Vec<u8>)>;

/// A per-relay-id identity cache. The first lookup for an id mints a self-signed
/// cert+key and remembers its DER bytes; every later lookup for the same id
/// returns the same bytes. Determinism matters because a test both seeds the
/// registry from `relay_hello(id, ..)` and re-enrolls the same id over a live
/// control connection: the duplicate-id check refuses a re-enroll whose
/// certificate differs from the seeded one, so a given id's certificate must be
/// byte-stable across calls.
fn identity_cache() -> &'static Mutex<IdentityMap> {
    static CACHE: OnceLock<Mutex<IdentityMap>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(IdentityMap::new()))
}

fn relay_identity(id: u64) -> (Vec<u8>, Vec<u8>) {
    identity_cache()
        .lock()
        .unwrap()
        .entry(id)
        .or_insert_with(|| {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
            (cert.cert.der().to_vec(), cert.signing_key.serialize_der())
        })
        .clone()
}

/// The DER certificate relay `id` enrolls with — stable across calls, so a
/// seeded entry and a later live re-enroll for the same id present the same
/// certificate (the duplicate-id check compares fingerprints).
pub fn relay_cert(id: u64) -> Vec<u8> {
    relay_identity(id).0
}

/// The private key matching [`relay_cert`] for relay `id`, for signing that
/// relay's enroll proof-of-possession.
pub fn relay_key(id: u64) -> PrivateKeyDer<'static> {
    PrivateKeyDer::try_from(relay_identity(id).1).unwrap()
}

/// A relay `Hello` negotiating at `CURRENT` (so the enroll challenge runs)
/// carrying `cert_der`.
pub fn hello_at_current(id: u64, port: u16, cert_der: Vec<u8>) -> RelayHello {
    RelayHello::new(
        RelayId(id),
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ProtocolVersion::CURRENT,
        cert_der,
    )
}

/// Connects to `base_url`'s control endpoint and sends `hello` as the enroll
/// frame, returning the open socket.
pub async fn connect_and_send_hello(base_url: &str, hello: RelayHello) -> ControlSocket {
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
    let frame = serde_json::to_string(&RelayToCoordinator::Hello(hello)).unwrap();
    socket.send(Message::Text(frame.into())).await.unwrap();
    socket
}

/// Reads the coordinator's next frame, asserts it is an `IdentityChallenge`, and
/// returns the nonce.
pub async fn expect_identity_challenge(socket: &mut ControlSocket) -> [u8; 32] {
    let frame = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("the coordinator challenges promptly")
        .expect("a frame arrives")
        .unwrap();
    let Message::Text(text) = frame else {
        panic!("expected an identity challenge, got {frame:?}");
    };
    match serde_json::from_str(&text).unwrap() {
        CoordinatorToRelay::IdentityChallenge { nonce } => nonce,
        other => panic!("expected an identity_challenge frame, got: {other:?}"),
    }
}

/// Signs `nonce` with `key` (via the relay's own signing helper — the same code
/// path a real relay runs) and sends it as an `IdentityProof`.
pub async fn answer_challenge(
    socket: &mut ControlSocket,
    key: &PrivateKeyDer<'static>,
    nonce: &[u8; 32],
) {
    let signature =
        coordinator::client::sign_enroll_proof(key, nonce).expect("a supported key always signs");
    let frame = serde_json::to_string(&RelayToCoordinator::IdentityProof { signature }).unwrap();
    socket.send(Message::Text(frame.into())).await.unwrap();
}

/// Reads the coordinator's challenge and answers it with `key` — the whole
/// proof-of-possession round trip a fake relay completes before it enrolls.
pub async fn prove_identity(socket: &mut ControlSocket, key: &PrivateKeyDer<'static>) {
    let nonce = expect_identity_challenge(socket).await;
    answer_challenge(socket, key, &nonce).await;
}

/// Reads the coordinator's next frame, asserts it is the `TenantKeys` push, and
/// returns its entries. A freshly enrolled connection is led by this frame — the
/// tenant verifying keys the relay checks client tokens against — before any
/// session descriptor.
pub async fn expect_tenant_keys(socket: &mut ControlSocket) -> Vec<TenantVerifyingKey> {
    let frame = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("the coordinator pushes tenant keys promptly")
        .expect("a frame arrives")
        .unwrap();
    let Message::Text(text) = frame else {
        panic!("expected a tenant_keys frame, got {frame:?}");
    };
    match serde_json::from_str(&text).unwrap() {
        CoordinatorToRelay::TenantKeys { keys } => keys,
        other => panic!("expected a tenant_keys frame, got: {other:?}"),
    }
}

/// Reads the coordinator's next frame, asserts it is the `RegionBeacons` push, and
/// returns its targets. A freshly enrolled connection to a coordinator with regions
/// configured carries this frame — the region ping beacon targets — in its
/// connect-time lead, ahead of any session descriptor.
pub async fn expect_region_beacons(socket: &mut ControlSocket) -> Vec<RegionBeaconTarget> {
    let frame = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("the coordinator pushes region beacons promptly")
        .expect("a frame arrives")
        .unwrap();
    let Message::Text(text) = frame else {
        panic!("expected a region_beacons frame, got {frame:?}");
    };
    match serde_json::from_str(&text).unwrap() {
        CoordinatorToRelay::RegionBeacons { beacons } => beacons,
        other => panic!("expected a region_beacons frame, got: {other:?}"),
    }
}

/// Reads down-frames until the enrolled path's initial `descriptors` re-sync
/// arrives, returning that frame's text. A freshly enrolled connection is led by a
/// `tenant_keys` push (the relay must be able to verify a session's client tokens
/// before any descriptor for it lands) and, when the coordinator has regions
/// configured, a `region_beacons` push — so a test that only needs to confirm the
/// enrolled path proceeds reads past both here. Panics on a close (a refusal) or if
/// the stream ends before a descriptor arrives.
pub async fn read_to_descriptors(socket: &mut ControlSocket) -> String {
    loop {
        let frame = timeout(Duration::from_secs(5), socket.next())
            .await
            .expect("the coordinator answers promptly")
            .expect("a frame arrives before the stream ends")
            .unwrap();
        match frame {
            Message::Text(text) if text.contains("\"type\":\"descriptors\"") => {
                return text.to_string();
            }
            // Skip the tenant_keys and region_beacons leads (and any other
            // non-descriptor push).
            Message::Text(_) => continue,
            Message::Close(frame) => {
                panic!("expected the descriptor re-sync, got a close: {frame:?}")
            }
            other => panic!("expected a text frame, got {other:?}"),
        }
    }
}

// --- The served coordinator every suite drives ---

/// The tenant these suites enroll and create sessions under.
pub const TENANT: &str = "sb-test";

/// The key id the test tenant is enrolled with.
pub const TENANT_KEY_ID: &str = "test-key-1";

/// A generous liveness deadline for tests that don't exercise the timeout — long
/// enough that no enrolled relay is ever deregistered for going silent.
pub const LIVENESS: Duration = Duration::from_secs(30);

/// A coordinator serving on an ephemeral loopback port, plus the handles its
/// tests assert against. The setup and lifecycle are the very ones the served
/// router holds, so a test can drive the descriptor outbox or read per-session
/// state while a relay is connected.
pub struct ServedCoordinator {
    /// `http://127.0.0.1:<port>` — what a control connection dials.
    pub base_url: String,
    /// The served router's session-setup context: relay registry, tenant store,
    /// session membership, descriptor outbox.
    pub setup: SessionSetup,
    /// The served router's per-session lifecycle.
    pub lifecycle: Lifecycle,
}

impl ServedCoordinator {
    /// The relay registry the served coordinator enrolls into.
    pub fn registry(&self) -> &RelayRegistry {
        self.setup.registry()
    }

    /// The `ws://…/relay/control` URL a raw-socket test connects to.
    pub fn ws_url(&self) -> String {
        format!(
            "{}/relay/control",
            self.base_url.replace("http://", "ws://")
        )
    }
}

/// Builds and serves a coordinator for one test.
///
/// Every suite here needs the same thing — a real `axum::serve` on an ephemeral
/// loopback port over a real `CoordinatorState` — differing only in a handful of
/// knobs, so the stand-up lives here once and each test names the two or three
/// fields it actually configures. Defaults are the dev / loopback posture: open
/// control auth, production handshake deadline, a liveness deadline long enough
/// never to fire, no regions, no ledger, no tenant, no pre-enrolled relays, and
/// no connect-info (so `peer_ip` reads as unknown, as it does for every server
/// not built with `into_make_service_with_connect_info`).
pub struct CoordinatorBuilder {
    control_auth: ControlAuth,
    hello_timeout: Duration,
    liveness_timeout: Duration,
    regions: RegionsConfig,
    ledger: Option<Arc<RelayLedger>>,
    relays: Vec<RelayHello>,
    tenant: bool,
    connect_info: bool,
    pending_hellos: Option<usize>,
}

impl Default for CoordinatorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CoordinatorBuilder {
    pub fn new() -> Self {
        Self {
            control_auth: ControlAuth::Open,
            hello_timeout: api::HELLO_TIMEOUT,
            liveness_timeout: LIVENESS,
            regions: RegionsConfig::default(),
            ledger: None,
            relays: Vec::new(),
            tenant: false,
            connect_info: false,
            pending_hellos: None,
        }
    }

    /// Requires a bootstrap secret on the control upgrade instead of serving it
    /// open.
    pub fn with_control_auth(mut self, control_auth: ControlAuth) -> Self {
        self.control_auth = control_auth;
        self
    }

    /// Shortens the window a connection has to send its `Hello` (and to answer
    /// the identity challenge, which the same deadline bounds).
    pub fn with_hello_timeout(mut self, hello_timeout: Duration) -> Self {
        self.hello_timeout = hello_timeout;
        self
    }

    /// Shortens the deadline an enrolled relay may go silent for.
    pub fn with_liveness(mut self, liveness_timeout: Duration) -> Self {
        self.liveness_timeout = liveness_timeout;
        self
    }

    /// Configures the placement regions an enrolling relay's tag is validated
    /// against and whose beacons ride the connect-time lead.
    pub fn with_regions(mut self, regions: RegionsConfig) -> Self {
        self.regions = regions;
        self
    }

    /// Puts the coordinator in ledger mode: only an id this ledger minted, with
    /// its token or its bound certificate, may enroll. Pair with
    /// [`in_memory_ledger`], which the test also keeps a handle to so it can mint
    /// ids and record tasks the served handler then authorizes against.
    pub fn with_ledger(mut self, ledger: Arc<RelayLedger>) -> Self {
        self.ledger = Some(ledger);
        self
    }

    /// Seeds the registry with relays enrolled directly (no control connection),
    /// each on a loopback address at its given port with that id's stable
    /// certificate.
    pub fn with_relays(mut self, relays: &[(u64, u16)]) -> Self {
        self.relays.extend(
            relays
                .iter()
                .map(|&(id, port)| hello_at_current(id, port, relay_cert(id))),
        );
        self
    }

    /// Seeds the registry with one relay whose `Hello` the caller shaped (a
    /// region tag, say).
    pub fn with_relay_hello(mut self, hello: RelayHello) -> Self {
        self.relays.push(hello);
        self
    }

    /// Enrolls the test tenant, so sessions can be created and the connect-time
    /// tenant-key push carries a key.
    pub fn with_tenant(mut self) -> Self {
        self.tenant = true;
        self
    }

    /// Serves with `into_make_service_with_connect_info::<SocketAddr>()`, the way
    /// the binary does, so the control handler reads the connection's real
    /// transport peer address instead of `None`.
    pub fn with_connect_info(mut self) -> Self {
        self.connect_info = true;
        self
    }

    /// Shrinks the gate bounding how many connections may sit between the
    /// WebSocket upgrade and a verified `Hello` at once, so a test can saturate
    /// it with a couple of sockets instead of the production five hundred.
    pub fn with_pending_hello_limit(mut self, permits: usize) -> Self {
        self.pending_hellos = Some(permits);
        self
    }

    /// Binds an ephemeral loopback port and spawns the server on it.
    pub async fn serve(self) -> ServedCoordinator {
        let reg = registry::new_registry();
        for hello in self.relays {
            registry::enroll(&reg, hello);
        }
        let tenants = tenant::new_store();
        if self.tenant {
            tenant::enroll(
                &tenants,
                KeyId(TENANT_KEY_ID.to_owned()),
                TenantId(TENANT.to_owned()),
                BufferBounds::new(1, 6).unwrap(),
            )
            .unwrap();
        }
        let setup = SessionSetup::new(reg, tenants);
        let handle = setup.clone();
        let mut state = CoordinatorState {
            hello_timeout: self.hello_timeout,
            liveness_timeout: self.liveness_timeout,
            regions: self.regions,
            ledger: self.ledger,
            ..CoordinatorState::new(setup, self.control_auth)
        };
        if let Some(permits) = self.pending_hellos {
            state.pending_hellos = Arc::new(tokio::sync::Semaphore::new(permits));
        }
        let lifecycle = state.lifecycle.clone();

        let app = api::router(state);
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        if self.connect_info {
            tokio::spawn(async move {
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .unwrap();
            });
        } else {
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
        }
        ServedCoordinator {
            base_url: format!("http://{addr}"),
            setup: handle,
            lifecycle,
        }
    }
}

/// Polls the registry until `id` enrolls, up to a couple of seconds. Returns
/// whether it appeared — enrollment happens asynchronously once a relay's
/// control connection sends its Hello and proves its identity.
pub async fn wait_for_enrollment(reg: &RelayRegistry, id: RelayId) -> bool {
    for _ in 0..100 {
        if registry::peer(reg, id).is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// Polls the registry until `id` is gone, up to a couple of seconds. Returns
/// whether it disappeared — deregistration happens asynchronously once the
/// relay's control connection drops or its liveness deadline lapses.
pub async fn wait_for_deregistration(reg: &RelayRegistry, id: RelayId) -> bool {
    for _ in 0..100 {
        if registry::peer(reg, id).is_none() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// Reads the coordinator's next frame and asserts it is a close with
/// `expected_code`.
pub async fn expect_close(socket: &mut ControlSocket, expected_code: u16) {
    let frame = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("the coordinator answers promptly")
        .expect("a frame arrives")
        .unwrap();
    let Message::Close(Some(close)) = frame else {
        panic!("expected a close frame, got {frame:?}");
    };
    assert_eq!(
        u16::from(close.code),
        expected_code,
        "reason: {}",
        close.reason
    );
}

/// Asserts the coordinator ends the connection without ever serving it an
/// application frame — the refusals it signals by dropping the socket rather
/// than by a close code (no Hello inside the deadline, a first frame that is not
/// a Hello). Stronger than draining until the stream ends: a handler that pushed
/// anything at all before closing fails here.
pub async fn expect_closed_unserved(socket: &mut ControlSocket) {
    let ended = timeout(Duration::from_secs(2), async {
        while let Some(frame) = socket.next().await {
            match frame {
                Ok(Message::Close(_)) | Err(_) => return,
                Ok(Message::Ping(_) | Message::Pong(_)) => continue,
                Ok(other) => panic!("the connection was served a frame before closing: {other:?}"),
            }
        }
    })
    .await;
    assert!(
        ended.is_ok(),
        "the coordinator must end an unenrolled connection rather than hold it",
    );
}

/// A fresh, empty provisioned-relay ledger held entirely in memory — nothing on
/// disk to clean up between tests, and every test gets its own.
pub fn in_memory_ledger() -> Arc<RelayLedger> {
    Arc::new(RelayLedger::open(Path::new(":memory:")).expect("an in-memory ledger opens"))
}
