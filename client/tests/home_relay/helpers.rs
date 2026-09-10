//! Shared fixtures for the `home_relay` suite: a trusted tenant + signed
//! tokens, a real relay bound on loopback (plain, mesh-seeded, or killable),
//! and the client-side endpoint/identity helpers every topic file dials
//! through. Also holds the two small receive helpers (`recv_turn`,
//! `wait_connectivity`) shared by the reconnect and rehome tests.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_client::{ClientEndpoint, Identity};
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_proto::token::{
    ClientPublicKey, ExpiresAt, KeyId, PUBLIC_KEY_LEN, SIGNATURE_LEN, Signature, SignedToken,
    TokenClaims,
};
use rally_point_relay::auth::Registry;
use rally_point_relay::server;
use rally_point_transport::quic::{client_config, server_config};
use rally_point_transport::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rally_point_transport::{noq, rustls};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

pub(super) const KID: &str = "staging-key-1";
pub(super) const TENANT: &str = "sb-staging";

/// A tenant the relay trusts: a signing key, the `kid` that names it, and the
/// tenant id it's bound to.
pub(super) struct Tenant {
    kid: String,
    name: String,
    key: Ed25519KeyPair,
    public: [u8; PUBLIC_KEY_LEN],
}

pub(super) fn make_tenant(kid: &str, name: &str) -> Tenant {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public = key.public_key().as_ref().try_into().unwrap();
    Tenant {
        kid: kid.to_owned(),
        name: name.to_owned(),
        key,
        public,
    }
}

/// Mints a token for `slot` in `session`, signed by `tenant`'s key and carrying
/// its `kid` and tenant id, embedding `client_pub` as the connection-binding key
/// and never expiring.
pub(super) fn mint_token(
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
    token.signature = Signature(tenant.key.sign(&message).as_ref().try_into().unwrap());
    token
}

/// A self-signed cert + key for the relay, plus the cert alone to seed a client's
/// trust roots.
pub(super) fn self_signed() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    (vec![cert_der.clone()], key, cert_der)
}

/// Binds a relay endpoint on `bind` serving `registry`, returning its actual
/// address and the CA a client trusts to reach it.
pub(super) fn start_relay_on(
    bind: SocketAddr,
    registry: Registry,
) -> (SocketAddr, CertificateDer<'static>) {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let endpoint = server::bind_endpoint(server_cfg, bind).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(server::serve(
        endpoint,
        Arc::new(registry),
        std::sync::Arc::default(),
        rally_point_relay::mesh::new_mesh_state(),
        None,
    ));
    (addr, ca)
}

/// Binds an ephemeral IPv4-loopback relay endpoint serving `registry`.
pub(super) fn start_relay(registry: Registry) -> (SocketAddr, CertificateDer<'static>) {
    start_relay_on((Ipv4Addr::LOCALHOST, 0).into(), registry)
}

/// Binds an ephemeral IPv4-loopback relay serving `registry` over a caller-supplied
/// mesh state, so a test can seed the session's decision-maker (marking it started
/// with an expected-slot set) before any client connects — which is what makes the
/// relay fire session-start and record forwarded turns in its per-session replay
/// ring, exactly as a coordinator descriptor would in production.
pub(super) fn start_relay_with_mesh(
    registry: Registry,
    mesh: rally_point_relay::mesh::MeshState,
) -> (SocketAddr, CertificateDer<'static>) {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let endpoint = noq::Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(server::serve(
        endpoint,
        Arc::new(registry),
        std::sync::Arc::default(),
        mesh,
        None,
    ));
    (addr, ca)
}

/// Binds an ephemeral IPv4-loopback relay over a caller-supplied mesh state,
/// returning its address, CA, *and* the endpoint — so a test can `close()` the
/// endpoint to simulate the relay dying (client links drop and re-dials fail),
/// which is what forces the driver to escalate to re-home.
pub(super) fn start_relay_killable(
    registry: Registry,
    mesh: rally_point_relay::mesh::MeshState,
) -> (SocketAddr, CertificateDer<'static>, noq::Endpoint) {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let endpoint = noq::Endpoint::server(server_cfg, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(server::serve(
        endpoint.clone(),
        Arc::new(registry),
        std::sync::Arc::default(),
        mesh,
        None,
    ));
    (addr, ca, endpoint)
}

/// A registry trusting each of `tenants`.
pub(super) fn registry_for(tenants: &[&Tenant]) -> Registry {
    let mut registry = Registry::new();
    for tenant in tenants {
        registry.insert(
            KeyId(tenant.kid.clone()),
            TenantId(tenant.name.clone()),
            tenant.public,
        );
    }
    registry
}

/// A client endpoint trusting `ca`, bound to loopback so the test is deterministic.
pub(super) fn client_endpoint(ca: &CertificateDer<'static>) -> ClientEndpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let endpoint = noq::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    endpoint.set_default_client_config(client_config(roots).unwrap());
    ClientEndpoint::from_endpoint(endpoint)
}

/// Generates a fresh client keypair, mints a matching token for `slot`, and bundles
/// them as an [`Identity`] — the credentials the app would hand the game DLL.
pub(super) fn identity_for(tenant: &Tenant, session: SessionId, slot: SlotId) -> Identity {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public: [u8; PUBLIC_KEY_LEN] = pair.public_key().as_ref().try_into().unwrap();
    let token = mint_token(tenant, session, slot, public);
    Identity::from_pkcs8(token, pkcs8.as_ref()).unwrap()
}

/// Awaits one forwarded turn on `inbound`, bounded so a stall fails rather than
/// hangs.
pub(super) async fn recv_turn(inbound: &mut tokio::sync::mpsc::Receiver<Payload>) -> Payload {
    tokio::time::timeout(Duration::from_secs(5), inbound.recv())
        .await
        .expect("a turn never arrived")
        .expect("the inbound channel closed")
}

/// Drains the connectivity channel until the wanted `(slot, connected)` shows,
/// ignoring the relay's own peer-connectivity frames that share the channel.
pub(super) async fn wait_connectivity(
    rx: &mut tokio::sync::mpsc::Receiver<(SlotId, bool)>,
    want: (SlotId, bool),
) {
    loop {
        let got = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("connectivity signal never arrived")
            .expect("connectivity channel closed");
        if got == want {
            return;
        }
    }
}
