//! Smoke test for the relay's process configuration: cert generation, tenant-key
//! generation, and registry construction — the real new logic in `config.rs`
//! that `main.rs` wires up.
//!
//! Tests what `main.rs` actually does (self-signed cert, generated dev tenant
//! keypair, registry from that key) by calling the same library functions the
//! binary calls, then authorizing a client with a token minted from the
//! generated key against a relay built with that cert + registry. What the
//! relay does with a turn once a client is authorized is the client-edge
//! suite's subject; here the acknowledgement is the assertion.

#[path = "common/mod.rs"]
mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use common::{
    AnyError, KID, Keypair, TENANT, Tenant, client_endpoint, handshake_fresh, mint_token,
};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_relay::config;
use rally_point_relay::server;
use rally_point_transport::noq;

#[tokio::test]
async fn a_client_connects_through_a_self_signed_relay_and_is_authorized() -> Result<(), AnyError> {
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
    let endpoint = noq::Endpoint::server(server_config, bind)?;
    let addr = endpoint.local_addr()?;
    tokio::spawn(server::serve(
        endpoint,
        Arc::new(registry),
        Arc::default(),
        rally_point_relay::mesh::MeshState::default(),
        None,
    ));

    // The issuer side of the generated dev key: the relay registered its public
    // half, and a token minted with its private half must satisfy that registry.
    let issuer = Tenant {
        kid: KID.to_owned(),
        name: TENANT.to_owned(),
        key: Keypair::from_pkcs8(pkcs8),
    };

    let client_endpoint = client_endpoint(&cert.ca);
    let client_key = common::keypair();
    let token = mint_token(&issuer, SessionId(1), SlotId(0), client_key.public);
    let connection = client_endpoint.connect(addr, "localhost")?.await?;

    // The acknowledgement byte is the whole assertion: cert, key generation and
    // registry construction composed into a relay that admits this client.
    handshake_fresh(&connection, &token, &client_key).await?;
    Ok(())
}
