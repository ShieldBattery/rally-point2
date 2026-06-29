//! Closes the `C–S–C` loop with real code on both ends: real clients (this
//! crate) authorize against a real relay (`rally-point-relay`) over loopback
//! QUIC, and a turn from one client is validated and fanned out to the other.
//!
//! Where `relay/tests/client_edge.rs` drove the client side of the handshake by
//! hand, these exercise the actual client transport — the same handshake codec on
//! both ends — so a drift in the wire framing would fail here.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_client::{ClientEndpoint, DialError, Identity};
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
use rally_point_transport::{quinn, rustls};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const KID: &str = "staging-key-1";
const TENANT: &str = "sb-staging";

/// A tenant the relay trusts: a signing key, the `kid` that names it, and the
/// tenant id it's bound to.
struct Tenant {
    kid: String,
    name: String,
    key: Ed25519KeyPair,
    public: [u8; PUBLIC_KEY_LEN],
}

fn make_tenant(kid: &str, name: &str) -> Tenant {
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
fn mint_token(
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

/// Binds a relay endpoint on `bind` serving `registry`, returning its actual
/// address and the CA a client trusts to reach it.
fn start_relay_on(bind: SocketAddr, registry: Registry) -> (SocketAddr, CertificateDer<'static>) {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let endpoint = quinn::Endpoint::server(server_cfg, bind).unwrap();
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
fn start_relay(registry: Registry) -> (SocketAddr, CertificateDer<'static>) {
    start_relay_on((Ipv4Addr::LOCALHOST, 0).into(), registry)
}

/// A registry trusting each of `tenants`.
fn registry_for(tenants: &[&Tenant]) -> Registry {
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
fn client_endpoint(ca: &CertificateDer<'static>) -> ClientEndpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let mut endpoint = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    endpoint.set_default_client_config(client_config(roots).unwrap());
    ClientEndpoint::from_endpoint(endpoint)
}

/// Generates a fresh client keypair, mints a matching token for `slot`, and bundles
/// them as an [`Identity`] — the credentials the app would hand the game DLL.
fn identity_for(tenant: &Tenant, session: SessionId, slot: SlotId) -> Identity {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public: [u8; PUBLIC_KEY_LEN] = pair.public_key().as_ref().try_into().unwrap();
    let token = mint_token(tenant, session, slot, public);
    Identity::from_pkcs8(token, pkcs8.as_ref()).unwrap()
}

#[tokio::test]
async fn two_clients_exchange_a_turn_through_the_relay() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(42);

    // Both clients must be authorized before the turn is sent, or fan-out has no
    // peer to reach — the relay does not buffer for not-yet-connected slots.
    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));
    let mut slot0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let mut slot1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();

    // A build, sent with a wire slot the relay must overwrite with the authorized 0.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 9,
            game_frame_count: None,
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
        }))
        .unwrap();

    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = slot1.recv().await.unwrap().fresh;
    }

    assert_eq!(delivered.len(), 1);
    let turn = &delivered[0];
    // Bound to the authorized slot, not the value on the wire.
    assert_eq!(turn.slot, 0);
    // The gameplay command passes through verbatim.
    assert_eq!(&turn.commands[..], &[0x0C, 1, 2, 3, 4, 5, 6, 7]);
}

#[tokio::test]
async fn connect_fails_when_the_signing_key_does_not_match_the_token() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);

    // Mint a token committing to one client key, but build the identity from a
    // different, unrelated key — so the challenge is answered with the wrong key.
    let rng = SystemRandom::new();
    let committed =
        Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap();
    let committed_pub: [u8; PUBLIC_KEY_LEN] = committed.public_key().as_ref().try_into().unwrap();
    let token = mint_token(&tenant, SessionId(1), SlotId(0), committed_pub);

    let other_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let identity = Identity::from_pkcs8(token, other_pkcs8.as_ref()).unwrap();

    // The relay rejects the challenge response and closes the connection, so the
    // client never reads an acknowledgement.
    assert!(
        endpoint
            .connect(addr, "localhost", &identity)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn connect_fails_against_an_untrusted_relay_certificate() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, _ca) = start_relay(registry_for(&[&tenant]));

    // A client that trusts a *different* CA than the one the relay presents must
    // fail the TLS handshake before any authorization happens.
    let (_chain, _key, unrelated_ca) = self_signed();
    let endpoint = client_endpoint(&unrelated_ca);
    let identity = identity_for(&tenant, SessionId(1), SlotId(0));

    assert!(
        endpoint
            .connect(addr, "localhost", &identity)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn connect_times_out_when_the_peer_stalls_during_authorization() {
    // A peer that completes TLS with a cert the client trusts and accepts the
    // connection, but never sends the connection-binding challenge — the exact
    // stall the dial must bound rather than wait on forever.
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let stalled = quinn::Endpoint::server(server_cfg, bind).unwrap();
    let addr = stalled.local_addr().unwrap();
    tokio::spawn(async move {
        // Accept the connection and the handshake stream, then keep both stream
        // halves open — never sending the challenge, never finishing the stream,
        // never closing the connection — so the client blocks on its challenge read.
        if let Some(incoming) = stalled.accept().await
            && let Ok(connection) = incoming.await
            && let Ok((_send, _recv)) = connection.accept_bi().await
        {
            std::future::pending::<()>().await;
        }
    });

    let tenant = make_tenant(KID, TENANT);
    let endpoint = client_endpoint(&ca);
    let identity = identity_for(&tenant, SessionId(1), SlotId(0));

    // Map the link away so the outcome is `Debug` for the assertion message.
    let outcome = endpoint
        .connect_with_timeout(addr, "localhost", &identity, Duration::from_millis(300))
        .await
        .map(|_link| ());
    assert!(
        matches!(outcome, Err(DialError::TimedOut { .. })),
        "expected a timeout, got {outcome:?}"
    );
}

#[tokio::test]
async fn bind_builds_a_usable_endpoint() {
    // The convenience constructor binds a real local socket even with no trusted
    // roots; trust only matters once it dials a relay.
    let endpoint = ClientEndpoint::bind(rustls::RootCertStore::empty()).unwrap();
    assert!(endpoint.endpoint().local_addr().is_ok());
}

#[tokio::test]
async fn bind_dials_an_ipv6_relay() {
    // The deployment is IPv6-primary, so the dual-stack default endpoint must reach
    // a relay listening on IPv6 — the case an IPv4-only endpoint would reject.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay_on((Ipv6Addr::LOCALHOST, 0).into(), registry_for(&[&tenant]));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let endpoint = ClientEndpoint::bind(roots).unwrap();
    let identity = identity_for(&tenant, SessionId(7), SlotId(0));

    let outcome = endpoint
        .connect(addr, "localhost", &identity)
        .await
        .map(|_link| ());
    assert!(
        outcome.is_ok(),
        "dual-stack bind failed to dial IPv6 relay: {outcome:?}"
    );
}
