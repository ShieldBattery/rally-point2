//! Smoke test for the relay's process configuration: cert generation, tenant-key
//! generation, and registry construction — the real new logic in `config.rs`
//! that `main.rs` wires up.
//!
//! Tests what `main.rs` actually does (self-signed cert, generated dev tenant
//! keypair, registry from that key) by calling the same library functions the
//! binary calls, then connecting a client with a token minted from the generated
//! key and exchanging a turn through a relay built with that cert + registry.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_proto::token::{
    CHALLENGE_LEN, CHANNEL_BINDING_EXPORTER_LABEL, CHANNEL_BINDING_LEN, ClientPublicKey,
    ConnectionChallenge, ExpiresAt, KeyId, PUBLIC_KEY_LEN, SIGNATURE_LEN, Signature, SignedToken,
    TokenClaims,
};
use rally_point_relay::auth::HANDSHAKE_OK;
use rally_point_relay::config;
use rally_point_relay::server;
use rally_point_transport::quic::client_config;
use rally_point_transport::{Link, quinn, rustls};
use ring::signature::{Ed25519KeyPair, KeyPair};

const KID: &str = "smoke-key-1";
const TENANT: &str = "sb-smoke";

type AnyError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::test]
async fn a_client_connects_through_a_self_signed_relay_and_exchanges_a_turn() -> Result<(), AnyError>
{
    let cert = config::self_signed_cert().map_err(|e| e.to_string())?;
    let tenant_key = config::generate_dev_tenant_key(KID.to_owned(), TENANT.to_owned())
        .map_err(|e| e.to_string())?;
    let registry = config::registry_from_tenant_key(&tenant_key);
    let pkcs8 = tenant_key
        .generated_pkcs8
        .as_ref()
        .expect("dev key has a pkcs8");

    let server_config = config::server_config_from_self_signed(&cert).map_err(|e| e.to_string())?;
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let endpoint = quinn::Endpoint::server(server_config, bind)?;
    let addr = endpoint.local_addr()?;
    tokio::spawn(server::serve(
        endpoint,
        Arc::new(registry),
        Arc::default(),
        rally_point_relay::mesh::new_mesh_state(),
        None,
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.ca.clone()).unwrap();
    let client_cfg = client_config(roots).unwrap();
    let mut client_endpoint = quinn::Endpoint::client((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    client_endpoint.set_default_client_config(client_cfg);

    let tenant_pair = Ed25519KeyPair::from_pkcs8(pkcs8).unwrap();
    let session = SessionId(1);

    let (slot0_conn, slot0_token, slot0_key) =
        connect_client(&client_endpoint, addr, &tenant_pair, session, SlotId(0)).await?;
    let (slot1_conn, slot1_token, slot1_key) =
        connect_client(&client_endpoint, addr, &tenant_pair, session, SlotId(1)).await?;

    authorize(&slot0_conn, &slot0_token, &slot0_key).await?;
    authorize(&slot1_conn, &slot1_token, &slot1_key).await?;

    let mut sender = Link::new(slot0_conn);
    let mut receiver = Link::new(slot1_conn);

    sender
        .send(Some(Payload {
            seq: 0,
            slot: 0,
            game_frame_count: Some(42),
            commands: vec![0x05].into(),
            ..Default::default()
        }))
        .map_err(|e| e.to_string())?;

    let delivered = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .map_err(|_| -> AnyError { "timed out waiting for the turn".into() })?
        .map_err(|e| e.to_string())?;

    assert_eq!(delivered.fresh.len(), 1);
    assert_eq!(delivered.fresh[0].seq, 0);
    assert_eq!(delivered.fresh[0].game_frame_count, Some(42));
    Ok(())
}

async fn connect_client(
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    tenant_pair: &Ed25519KeyPair,
    session: SessionId,
    slot: SlotId,
) -> Result<(quinn::Connection, SignedToken, Ed25519KeyPair), AnyError> {
    let rng = ring::rand::SystemRandom::new();
    let client_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let client_key = Ed25519KeyPair::from_pkcs8(client_pkcs8.as_ref()).unwrap();
    let pubkey: [u8; PUBLIC_KEY_LEN] = client_key.public_key().as_ref().try_into().unwrap();

    let claims = TokenClaims::new(
        TenantId(TENANT.to_owned()),
        session,
        slot,
        ExpiresAt(u64::MAX),
        ClientPublicKey(pubkey),
    );
    let mut token =
        SignedToken::from_parts(KeyId(KID.to_owned()), claims, Signature([0; SIGNATURE_LEN]));
    let mut message = Vec::new();
    token.signed_message(&mut message)?;
    token.signature = Signature(tenant_pair.sign(&message).as_ref().try_into().unwrap());

    let connection = endpoint
        .connect(addr, "localhost")
        .map_err(|e| -> AnyError { format!("connect: {e}").into() })?
        .await
        .map_err(|e| -> AnyError { format!("connect await: {e}").into() })?;
    Ok((connection, token, client_key))
}

async fn authorize(
    connection: &quinn::Connection,
    token: &SignedToken,
    signing_key: &Ed25519KeyPair,
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
        .map_err(|_| -> AnyError { "deriving channel binding failed".into() })?;

    let response =
        signing_key.sign(&ConnectionChallenge(challenge).signed_message(&channel_binding));
    send.write_all(response.as_ref()).await?;

    // A fresh dial presents no resume cursors: an empty (zero-count) frame.
    let cursor_frame = rally_point_proto::handshake::encode_resume_cursors(&[])?;
    send.write_all(&cursor_frame).await?;

    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await?;
    if ack[0] != HANDSHAKE_OK {
        return Err("relay rejected the handshake".into());
    }
    Ok(())
}
