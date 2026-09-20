//! Fixtures every relay integration-test binary shares.
//!
//! Not a test target of its own: `tests/common/` holds only this file, so Cargo
//! does not auto-discover it, and each suite pulls it in with
//! `#[path = "../common/mod.rs"] mod common;`. Anything here must therefore be
//! usable by all three suites; a fixture only one suite wants belongs in that
//! suite's `helpers.rs`.

#![allow(dead_code)]

use std::collections::HashSet;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::{BufferBounds, SessionDescriptor, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_proto::token::{
    CHALLENGE_LEN, CHANNEL_BINDING_EXPORTER_LABEL, CHANNEL_BINDING_LEN, ClientPublicKey,
    ConnectionChallenge, ExpiresAt, KeyId, PUBLIC_KEY_LEN, SIGNATURE_LEN, Signature, SignedToken,
    TokenClaims,
};
use rally_point_relay::auth::{HANDSHAKE_OK, Registry};
use rally_point_relay::consensus::{self, Authority};
use rally_point_relay::mesh::{self, MeshState};
use rally_point_relay::routing::{SessionKey, Sessions};
use rally_point_relay::server;
use rally_point_transport::control::ControlInbound;
use rally_point_transport::quic::{client_config, server_config};
use rally_point_transport::rustls::pki_types::CertificateDer;
use rally_point_transport::{Link, noq, rustls};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tokio::sync::mpsc;

pub const KID: &str = "staging-key-1";

pub const TENANT: &str = "sb-staging";

pub type AnyError = Box<dyn Error + Send + Sync>;

/// An Ed25519 keypair usable both to sign (tenant or client) and to publish its
/// public key.
pub struct Keypair {
    pair: Ed25519KeyPair,
    pub public: [u8; PUBLIC_KEY_LEN],
}

pub fn keypair() -> Keypair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public = pair.public_key().as_ref().try_into().unwrap();
    Keypair { pair, public }
}

impl Keypair {
    /// A keypair recovered from a PKCS#8 document — how a test reaches a key
    /// something else generated, such as the relay binary's own dev tenant key.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Self {
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8).unwrap();
        let public = pair.public_key().as_ref().try_into().unwrap();
        Self { pair, public }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.pair.sign(message).as_ref().try_into().unwrap()
    }
}

/// A tenant the relay trusts: a signing key, the `kid` that names it, and the
/// tenant id it's bound to.
pub struct Tenant {
    pub kid: String,
    pub name: String,
    pub key: Keypair,
}

pub fn make_tenant(kid: &str, name: &str) -> Tenant {
    Tenant {
        kid: kid.to_owned(),
        name: name.to_owned(),
        key: keypair(),
    }
}

/// Mints a token for `slot` in `session`, signed by `tenant`'s key and carrying
/// its `kid` and tenant id, embedding `client_pub` as the connection-binding key
/// and never expiring.
pub fn mint_token(
    tenant: &Tenant,
    session: SessionId,
    slot: SlotId,
    client_pub: [u8; PUBLIC_KEY_LEN],
) -> SignedToken {
    let claims = TokenClaims::new(
        TenantId(tenant.name.clone()),
        session,
        slot,
        ExpiresAt(u64::MAX),
        ClientPublicKey(client_pub),
    );
    let mut token = SignedToken::from_parts(
        KeyId(tenant.kid.clone()),
        claims,
        Signature([0; SIGNATURE_LEN]),
    );
    let mut message = Vec::new();
    token.signed_message(&mut message).unwrap();
    token.signature = Signature(tenant.key.sign(&message));
    token
}

/// A self-signed cert + key for the relay, plus the cert alone to seed a client's
/// trust roots. Re-exported from the transport crate's shared fixtures so every
/// suite still reaches it as `common::self_signed`.
pub use rally_point_transport::test_util::self_signed;

/// A client endpoint trusting `ca`. One endpoint can dial the relay for several
/// slots; the caller keeps it alive for as long as its connections are needed.
pub fn client_endpoint(ca: &CertificateDer<'static>) -> noq::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let endpoint = noq::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    endpoint.set_default_client_config(client_config(roots).unwrap());
    endpoint
}

/// A registry trusting each of `tenants`.
pub fn registry_for(tenants: &[&Tenant]) -> Registry {
    let mut registry = Registry::new();
    for tenant in tenants {
        registry.insert(
            KeyId(tenant.kid.clone()),
            TenantId(tenant.name.clone()),
            tenant.key.public,
        );
    }
    registry
}

/// Runs the client side of the handshake on `connection`: present `token`, answer
/// the relay's challenge with `signing_key`, present `resume_cursors`, and confirm
/// the acknowledgement.
///
/// `signing_key` is passed separately from the token's embedded public key so a
/// test can deliberately answer with the wrong key. `resume_cursors` is the
/// per-peer-slot delivery position a reconnecting client resumes from; a fresh dial
/// passes an empty slice.
pub async fn handshake(
    connection: &noq::Connection,
    token: &SignedToken,
    signing_key: &Keypair,
    resume_cursors: &[(SlotId, u64)],
) -> Result<(), AnyError> {
    let (mut send, mut recv) = connection.open_bi().await?;

    let encoded = token.encode()?;
    let len = u16::try_from(encoded.len())?;
    send.write_all(&len.to_le_bytes()).await?;
    send.write_all(&encoded).await?;

    let mut challenge = [0u8; CHALLENGE_LEN];
    recv.read_exact(&mut challenge).await?;
    let mut channel_binding = [0u8; CHANNEL_BINDING_LEN];
    connection
        .export_keying_material(&mut channel_binding, CHANNEL_BINDING_EXPORTER_LABEL, &[])
        .map_err(|_| "deriving channel binding failed")?;
    let response =
        signing_key.sign(&ConnectionChallenge(challenge).signed_message(&channel_binding));
    send.write_all(&response).await?;

    let cursor_frame = rally_point_proto::handshake::encode_resume_cursors(resume_cursors)?;
    send.write_all(&cursor_frame).await?;

    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await?;
    if ack[0] != HANDSHAKE_OK {
        return Err("relay did not acknowledge".into());
    }
    Ok(())
}

/// Reads control frames until one is a `SlotConnectivity` naming `(slot, connected)`,
/// skipping every other frame kind. Panics on timeout. A reconnect test uses this
/// to synchronize on the relay having observed a drop (the disconnect fan-out) before
/// it acts further.
pub async fn wait_for_connectivity(
    reader: &mut tokio::sync::mpsc::Receiver<rally_point_transport::control::ControlInbound>,
    slot: SlotId,
    connected: bool,
) {
    use rally_point_transport::control::ControlInbound;
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("a connectivity frame arrives before the timeout")
            .expect("the control stream stays open");
        if let ControlInbound::Connectivity(change) = frame
            && change.slot == u32::from(slot.0)
            && change.connected == connected
        {
            return;
        }
    }
}

pub fn turn(slot: u8, seq: u64) -> Payload {
    Payload {
        seq,
        slot: u32::from(slot),
        // Empty commands — a bare turn signal. validate_turn accepts this
        // (it yields an empty payload after stripping). A non-empty command
        // would need to be a valid SC:R opcode or validate_turn rejects it.
        commands: vec![].into(),
        ..Default::default()
    }
}

/// The one tenant a suite that needs only one trusts, named by the fixed key id.
pub fn make_default_tenant() -> Tenant {
    make_tenant(KID, TENANT)
}

/// A registry trusting `tenant` alone.
pub fn registry_for_one(tenant: &Tenant) -> Registry {
    registry_for(&[tenant])
}

/// [`handshake`] as a fresh dial: no resume cursors (an empty, zero-count
/// frame), so the relay replays nothing.
pub async fn handshake_fresh(
    connection: &noq::Connection,
    token: &SignedToken,
    signing_key: &Keypair,
) -> Result<(), AnyError> {
    handshake(connection, token, signing_key, &[]).await
}

/// A build-command turn: the gameplay payload most tests send when the point is
/// that a *validated* turn moves, not what is in it. `frame` is the game frame
/// the turn was authored at — `None` for a turn the session has no frame basis
/// from (a pre-start or lobby-era turn).
pub fn build_turn(slot: u8, seq: u64, frame: Option<u32>) -> Payload {
    Payload {
        seq,
        slot: u32::from(slot),
        game_frame_count: frame,
        commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
        ..Default::default()
    }
}

/// A coordinator session descriptor with everything unset: no peers, no
/// authority order, no slot sets, not resumed. Callers name the two or three
/// fields their test is about with struct-update syntax, so a new descriptor
/// field costs one line here instead of one per test.
pub fn descriptor(tenant: &str, session: SessionId) -> SessionDescriptor {
    SessionDescriptor {
        finalized_drops: false,
        tenant: TenantId(tenant.to_owned()),
        session,
        peers: vec![],
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

/// Seeds the session's decision-maker the way a coordinator descriptor would,
/// so a lone relay decides at all: without a maker, `decide_leave` and the
/// buffer authority are no-ops, and nothing a test drives through the relay is
/// ever decided.
///
/// Starts as this relay holding authority over bounds `0..=20` with every slot
/// set empty; `expecting` / `homed` / `bounds` / `authority` name the parts a
/// test actually depends on.
pub fn seed_authority<'a>(
    makers: &'a consensus::DecisionMakers,
    key: &'a SessionKey,
) -> SeedAuthority<'a> {
    SeedAuthority {
        makers,
        key,
        bounds: BufferBounds::new(0, 20).unwrap(),
        authority: Authority::SelfRelay,
        expected: HashSet::new(),
        homed: HashSet::new(),
    }
}

/// The seeding in progress — see [`seed_authority`].
pub struct SeedAuthority<'a> {
    makers: &'a consensus::DecisionMakers,
    key: &'a SessionKey,
    bounds: BufferBounds,
    authority: Authority,
    expected: HashSet<SlotId>,
    homed: HashSet<SlotId>,
}

impl SeedAuthority<'_> {
    /// The slots the session waits on before it may start.
    pub fn expecting(mut self, slots: impl IntoIterator<Item = u8>) -> Self {
        self.expected = slots.into_iter().map(SlotId).collect();
        self
    }

    /// The slots this relay is home for. A non-empty set refuses every other
    /// slot at the admission gate.
    pub fn homed(mut self, slots: impl IntoIterator<Item = u8>) -> Self {
        self.homed = slots.into_iter().map(SlotId).collect();
        self
    }

    /// The latency-buffer bounds every decision is clamped to.
    pub fn bounds(mut self, min: u32, max: u32) -> Self {
        self.bounds = BufferBounds::new(min, max).unwrap();
        self
    }

    /// Who decides for this session — [`Authority::Peer`] for the relay that
    /// must defer to the other side of a mesh pair.
    pub fn authority(mut self, authority: Authority) -> Self {
        self.authority = authority;
        self
    }

    /// Applies the sync, creating the maker.
    pub fn apply(self) {
        let _ = consensus::sync_maker(
            self.makers,
            self.key,
            consensus::MakerSync {
                expected_slots: self.expected,
                homed_slots: self.homed,
                ..consensus::MakerSync::new(self.bounds, self.authority)
            },
        );
    }
}

/// A relay serving its client edge on an ephemeral loopback port, with the
/// shared state a test drives it through.
pub struct Relay {
    pub addr: SocketAddr,
    pub ca: CertificateDer<'static>,
    pub sessions: Sessions,
    pub mesh: MeshState,
    mesh_rx: Option<mpsc::Receiver<noq::Connection>>,
}

impl Relay {
    /// Starts a relay trusting `tenant` alone. `relay_id` only names it in this
    /// test's logs — the ids the mesh negotiates come from each dial and accept
    /// configuration, never from here.
    pub fn start(tenant: &Tenant, relay_id: u64) -> Self {
        let (chain, key, ca) = self_signed();
        let cfg = server_config(chain, key).unwrap();
        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let endpoint = noq::Endpoint::server(cfg, bind).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let sessions: Sessions = Arc::default();
        let mesh = mesh::new_mesh_state();
        let (mesh_tx, mesh_rx) = mpsc::channel(8);

        tokio::spawn(server::serve(
            endpoint,
            Arc::new(registry_for_one(tenant)),
            Arc::clone(&sessions),
            mesh.clone(),
            Some(mesh_tx),
        ));

        tracing::info!(relay_id, %addr, "relay started");
        Self {
            addr,
            ca,
            sessions,
            mesh,
            mesh_rx: Some(mesh_rx),
        }
    }

    /// The channel this relay's ALPN dispatch hands mesh connections to, taken
    /// by whatever drives the mesh side of the test (the production accept
    /// drain, or the test itself). Available once.
    pub fn mesh_accept_rx(&mut self) -> mpsc::Receiver<noq::Connection> {
        self.mesh_rx
            .take()
            .expect("a relay's mesh-accept channel is taken once")
    }
}

/// Connects a client to `relay` for `slot`, runs the authorization handshake,
/// and returns the connection wrapped as a transport link ready to carry turns.
pub async fn connect_client(
    relay: &Relay,
    tenant: &Tenant,
    session: SessionId,
    slot: SlotId,
) -> Result<Link, AnyError> {
    let client_key = keypair();
    let token = mint_token(tenant, session, slot, client_key.public);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay.ca.clone()).unwrap();
    let endpoint = noq::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into())?;
    endpoint.set_default_client_config(client_config(roots)?);
    let connection = endpoint.connect(relay.addr, "localhost")?.await?;
    handshake_fresh(&connection, &token, &client_key).await?;
    Ok(Link::new(connection))
}

/// Reads the next control frame that carries real meaning, skipping the
/// informational `SlotConnectivity` frames the relay fans on every register and
/// disconnect. Panics on timeout or a closed stream. Asserting on the next
/// frame directly instead is the usual flake: a connectivity frame legitimately
/// precedes the leave, session-start or lobby frame a test is waiting for.
pub async fn recv_meaningful(reader: &mut mpsc::Receiver<ControlInbound>) -> ControlInbound {
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), reader.recv())
            .await
            .expect("a control frame arrives before the timeout")
            .expect("the control stream stays open");
        if !matches!(frame, ControlInbound::Connectivity(_)) {
            return frame;
        }
    }
}

/// Polls `condition` until it holds, panicking with `what` if it has not within
/// five seconds. How a test observes server-side state that no control frame
/// reports — a teardown finishing, a mesh link registering, a timer standing
/// down — without sleeping a fixed guess.
pub async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if condition() {
            return;
        }
        assert!(tokio::time::Instant::now() <= deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Waits until `mesh` holds a forward channel for `key` — the observable that a
/// mesh-link driver has processed its `Join`, and that cross-relay traffic will
/// actually leave this relay.
pub async fn wait_for_mesh_link(mesh: &MeshState, key: &SessionKey) {
    wait_until("the mesh link never registered the session", || {
        mesh.links.lock().contains_key(key)
    })
    .await;
}

/// Waits until at least `count` slots are registered on `sessions` for `key` —
/// the observable that every client a test connected is routable. A turn sent
/// before that simply has no peer to reach.
pub async fn wait_for_slots(sessions: &Sessions, key: &SessionKey, count: usize) {
    wait_until("the session's slots never all registered", || {
        sessions
            .lock()
            .get(key)
            .is_some_and(|slots| slots.len() >= count)
    })
    .await;
}
