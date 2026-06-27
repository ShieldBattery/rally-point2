//! End-to-end coverage of the relay's client-facing edge over loopback QUIC.
//!
//! Each test stands up a real relay endpoint and drives the client side of the
//! authorization handshake by hand — there is no client crate doing it yet, so
//! these tests are also the executable spec for the handshake's wire shape: a
//! `u16`-LE-prefixed token, a 32-byte challenge, a 64-byte response, then the
//! relay's one acknowledgement byte. Past that the connection carries turns as
//! transport [`Link`] datagrams exactly as the client will.

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_proto::token::{
    CHALLENGE_LEN, ClientPublicKey, ConnectionChallenge, ExpiresAt, KeyId, PUBLIC_KEY_LEN,
    SIGNATURE_LEN, Signature, SignedToken, TokenClaims,
};
use rally_point_relay::auth::{HANDSHAKE_OK, Registry};
use rally_point_relay::server;
use rally_point_transport::quic::{client_config, server_config};
use rally_point_transport::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rally_point_transport::{Link, quinn, rustls};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const KID: &str = "staging-key-1";
const TENANT: &str = "sb-staging";

type AnyError = Box<dyn Error + Send + Sync>;

/// An Ed25519 keypair usable both to sign (tenant or client) and to publish its
/// public key.
struct Keypair {
    pair: Ed25519KeyPair,
    public: [u8; PUBLIC_KEY_LEN],
}

fn keypair() -> Keypair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public = pair.public_key().as_ref().try_into().unwrap();
    Keypair { pair, public }
}

impl Keypair {
    fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.pair.sign(message).as_ref().try_into().unwrap()
    }
}

/// A tenant the relay trusts: a signing key, the `kid` that names it, and the
/// tenant id it's bound to.
struct Tenant {
    kid: String,
    name: String,
    key: Keypair,
}

fn make_tenant(kid: &str, name: &str) -> Tenant {
    Tenant {
        kid: kid.to_owned(),
        name: name.to_owned(),
        key: keypair(),
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
    token.signature = Signature(tenant.key.sign(&message));
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

/// Binds an ephemeral relay endpoint serving `registry`, returning its address
/// and the CA a client trusts to reach it.
fn start_relay(registry: Registry) -> (SocketAddr, CertificateDer<'static>) {
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let endpoint = quinn::Endpoint::server(server_cfg, bind).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(server::serve(endpoint, Arc::new(registry)));
    (addr, ca)
}

/// A client endpoint trusting `ca`. One endpoint can dial the relay for several
/// slots; the caller keeps it alive for as long as its connections are needed.
fn client_endpoint(ca: &CertificateDer<'static>) -> quinn::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let mut endpoint = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    endpoint.set_default_client_config(client_config(roots).unwrap());
    endpoint
}

/// A registry trusting each of `tenants`.
fn registry_for(tenants: &[&Tenant]) -> Registry {
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
/// the relay's challenge with `signing_key`, and confirm the acknowledgement.
///
/// `signing_key` is passed separately from the token's embedded public key so a
/// test can deliberately answer with the wrong key.
async fn handshake(
    connection: &quinn::Connection,
    token: &SignedToken,
    signing_key: &Keypair,
) -> Result<(), AnyError> {
    let (mut send, mut recv) = connection.open_bi().await?;

    let encoded = token.encode()?;
    let len = u16::try_from(encoded.len())?;
    send.write_all(&len.to_le_bytes()).await?;
    send.write_all(&encoded).await?;

    let mut challenge = [0u8; CHALLENGE_LEN];
    recv.read_exact(&mut challenge).await?;
    let response = signing_key.sign(&ConnectionChallenge(challenge).signed_message());
    send.write_all(&response).await?;

    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await?;
    if ack[0] != HANDSHAKE_OK {
        return Err("relay did not acknowledge".into());
    }
    Ok(())
}

/// Connects a client for `slot`, completes the handshake, and returns the
/// connection wrapped as a transport link ready to carry turns.
async fn connect_slot(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    tenant: &Tenant,
    session: SessionId,
    slot: SlotId,
) -> Link {
    let client_key = keypair();
    let token = mint_token(tenant, session, slot, client_key.public);
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
    handshake(&connection, &token, &client_key).await.unwrap();
    Link::new(connection)
}

#[tokio::test]
async fn fans_a_validated_turn_to_the_other_slot() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(42);

    // Both clients must be registered before the turn is sent, or fan-out has no
    // peer to reach — the relay does not buffer for not-yet-connected slots.
    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;

    // A keep-alive, a client-injected latency change (relay strips it), and a
    // build. The wire slot is a lie the relay must overwrite with the authorized 0.
    slot0
        .send(Some(Payload {
            seq: 0,
            slot: 9,
            commands: vec![0x05, 0x55, 0x02, 0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
        }))
        .unwrap();

    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = slot1.recv().await.unwrap();
    }

    assert_eq!(delivered.len(), 1);
    let turn = &delivered[0];
    // Bound to the authorized slot, not the value on the wire.
    assert_eq!(turn.slot, 0);
    // The latency control is stripped; gameplay commands pass through verbatim.
    assert_eq!(&turn.commands[..], &[0x05, 0x0C, 1, 2, 3, 4, 5, 6, 7]);
}

#[tokio::test]
async fn rejects_a_bad_connection_binding_proof() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);

    // A valid token, but the challenge is answered with a key that isn't the one
    // the token commits to.
    let client_key = keypair();
    let wrong_key = keypair();
    let token = mint_token(&tenant, SessionId(1), SlotId(0), client_key.public);
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    assert!(handshake(&connection, &token, &wrong_key).await.is_err());
}

#[tokio::test]
async fn rejects_a_token_from_an_unknown_tenant_key() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);

    // The token is signed by a tenant key the relay's registry has never seen.
    let impostor = make_tenant("impostor-key", "impostor");
    let client_key = keypair();
    let token = mint_token(&impostor, SessionId(1), SlotId(0), client_key.public);
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    assert!(handshake(&connection, &token, &client_key).await.is_err());
}

#[tokio::test]
async fn rejects_a_second_client_on_the_same_slot() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(5);

    // First client takes slot 0 and stays connected (keep the link alive).
    let _slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;

    // A second client presenting a valid token for the same slot completes the
    // crypto but is refused at registration, so it never sees the acknowledgement.
    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(0), client_key.public);
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    assert!(handshake(&connection, &token, &client_key).await.is_err());
}

#[tokio::test]
async fn isolates_identical_session_ids_across_tenants() {
    // Two tenants the relay trusts, each with its own signing key.
    let tenant_a = make_tenant("tenant-a-key", "tenant-a");
    let tenant_b = make_tenant("tenant-b-key", "tenant-b");
    let (addr, ca) = start_relay(registry_for(&[&tenant_a, &tenant_b]));
    let endpoint = client_endpoint(&ca);

    // The same numeric session id is live for both tenants at once. Session ids are
    // unique only within a tenant, so this must not be treated as one game.
    let session = SessionId(100);

    let mut a0 = connect_slot(&endpoint, addr, &tenant_a, session, SlotId(0)).await;
    let mut a1 = connect_slot(&endpoint, addr, &tenant_a, session, SlotId(1)).await;

    // Tenant B claims slot 1 in the same numeric session. Keyed on the session
    // number alone this would collide with tenant A's slot 1 and be refused; it
    // connects cleanly here, proving the groups are kept apart.
    let mut b1 = connect_slot(&endpoint, addr, &tenant_b, session, SlotId(1)).await;

    // Tenant A, slot 0, submits a build.
    a0.send(Some(Payload {
        seq: 0,
        slot: 0,
        commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
    }))
    .unwrap();

    // It reaches tenant A's other slot.
    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = a1.recv().await.unwrap();
    }
    assert_eq!(delivered[0].slot, 0);
    assert_eq!(&delivered[0].commands[..], &[0x0C, 1, 2, 3, 4, 5, 6, 7]);

    // It must never reach tenant B, despite the shared session number. The turn has
    // already fanned out by the time tenant A's peer holds it, so a short wait that
    // yields nothing is conclusive that no cross-tenant copy was queued.
    let leaked = tokio::time::timeout(Duration::from_millis(300), b1.recv()).await;
    assert!(leaked.is_err(), "tenant B received tenant A's turn");
}

#[tokio::test]
async fn refuses_connections_beyond_the_handshake_limit() {
    let tenant = make_tenant(KID, TENANT);

    // A relay that allows only one authorization handshake in flight at a time.
    let (chain, key, ca) = self_signed();
    let server_cfg = server_config(chain, key).unwrap();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let relay = quinn::Endpoint::server(server_cfg, bind).unwrap();
    let addr = relay.local_addr().unwrap();
    tokio::spawn(server::serve_with_max_pending(
        relay,
        Arc::new(registry_for(&[&tenant])),
        1,
    ));

    let endpoint = client_endpoint(&ca);

    // First client connects but never opens the auth stream, so the relay parks in
    // the handshake holding the only admission slot.
    let _stalled = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    // A second connection is refused while that slot is occupied.
    let refused = endpoint.connect(addr, "localhost").unwrap().await;
    assert!(
        refused.is_err(),
        "second connection should be refused at the handshake limit"
    );
}

#[tokio::test]
async fn frees_the_slot_when_a_client_disconnects() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(11);

    // A client authorizes for slot 0, then drops its connection.
    {
        let _slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    }

    // The slot must not stay occupied: a fresh client reclaims it. Allow a few
    // attempts for the relay to observe the departure and deregister the slot.
    let mut reclaimed = false;
    for _ in 0..20 {
        let client_key = keypair();
        let token = mint_token(&tenant, session, SlotId(0), client_key.public);
        let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        if handshake(&connection, &token, &client_key).await.is_ok() {
            reclaimed = true;
            break;
        }
    }
    assert!(
        reclaimed,
        "slot stayed occupied after the client disconnected"
    );
}

#[tokio::test]
async fn acks_a_one_way_sender_with_no_peer_traffic() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);

    // A lone slot: nothing is ever fanned back to it, so the relay has no forwarded
    // turn to carry acks on and must flush ack-only packets on its own cadence.
    let mut solo = connect_slot(&endpoint, addr, &tenant, SessionId(7), SlotId(0)).await;

    for _ in 0..3 {
        solo.send(Some(Payload {
            seq: 0,
            slot: 0,
            commands: vec![0x05].into(),
        }))
        .unwrap();
    }
    assert_eq!(solo.payloads_in_flight(), 3);

    // Draining the relay's ack-only packets must retire everything in flight, even
    // though no turn ever comes back the other way. Each recv yields the relay's
    // idle ack flush; the per-recv timeout sits above the flush delay, and the loop
    // is bounded so a missing flush fails rather than hangs.
    let mut retired = false;
    for _ in 0..15 {
        let _ = tokio::time::timeout(Duration::from_millis(400), solo.recv()).await;
        if solo.payloads_in_flight() == 0 {
            retired = true;
            break;
        }
    }
    assert!(
        retired,
        "relay never acked the one-way sender; {} payloads still in flight",
        solo.payloads_in_flight()
    );
}
