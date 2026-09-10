//! Fixtures every relay integration-test binary shares.
//!
//! Not a test target of its own: `tests/common/` holds only this file, so Cargo
//! does not auto-discover it, and each suite pulls it in with
//! `#[path = "../common/mod.rs"] mod common;`. Anything here must therefore be
//! usable by all three suites; a fixture only one suite wants belongs in that
//! suite's `helpers.rs`.

#![allow(dead_code)]

use std::error::Error;
use std::net::Ipv4Addr;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_proto::token::{
    CHALLENGE_LEN, CHANNEL_BINDING_EXPORTER_LABEL, CHANNEL_BINDING_LEN, ClientPublicKey,
    ConnectionChallenge, ExpiresAt, KeyId, PUBLIC_KEY_LEN, SIGNATURE_LEN, Signature, SignedToken,
    TokenClaims,
};
use rally_point_relay::auth::{HANDSHAKE_OK, Registry};
use rally_point_transport::quic::client_config;
use rally_point_transport::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rally_point_transport::{noq, rustls};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

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
/// trust roots.
pub fn self_signed() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    (vec![cert_der.clone()], key, cert_der)
}

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
