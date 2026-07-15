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
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rally_point_proto::control::{
    CoordinatorToRelay, RegionBeaconTarget, RelayHello, RelayToCoordinator, TenantVerifyingKey,
};
use rally_point_proto::ids::RelayId;
use rally_point_proto::version::ProtocolVersion;
use rally_point_relay::coordinator_client;
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
        coordinator_client::sign_enroll_proof(key, nonce).expect("a supported key always signs");
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
