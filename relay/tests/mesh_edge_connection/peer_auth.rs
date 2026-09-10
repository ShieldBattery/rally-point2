//! What the mesh acceptor refuses: an incompatible hello, a missing or
//! unenrolled client certificate, a fingerprint that does not match the fleet
//! map — and what an empty fleet map admits instead.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::ids::RelayId;
use rally_point_relay::coordinator::client::FleetMeshPeers;
use rally_point_relay::mesh::edge;
use rally_point_transport::{noq, rustls};

use crate::helpers::*;
use tokio::sync::mpsc;

/// The accept side enforces protocol-version negotiation on the identity hello:
/// a dialer advertising a version this build cannot negotiate is refused — the
/// connection is application-closed with `MESH_CLOSE_PROTOCOL_MISMATCH` before
/// the link driver spawns, and nothing ever surfaces on the `links` channel.
#[tokio::test]
async fn acceptor_refuses_an_incompatible_mesh_hello() -> Result<(), AnyError> {
    use rally_point_proto::mesh::MeshHello;
    use rally_point_proto::version::{MESH_CLOSE_PROTOCOL_MISMATCH, ProtocolVersion};

    let tenant = make_tenant();
    let relay_b = Relay::start(&tenant, 2);

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        false,
    ));

    // A stand-in dialer speaking only v1 (below MIN_SUPPORTED): connect on the
    // mesh ALPN and announce the incompatible version in the hello.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let cfg = rally_point_transport::quic::mesh_client_config(roots, dial_chain, dial_key)
        .map_err(|e| format!("building mesh client config: {e}"))?;
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let ep = noq::Endpoint::client(bind)?;
    ep.set_default_client_config(cfg);
    let connection = ep.connect(relay_b.addr, "localhost")?.await?;

    let mut hello_stream = connection.open_uni().await?;
    // A version below the supported floor — one this build cannot negotiate.
    let incompatible = ProtocolVersion(ProtocolVersion::MIN_SUPPORTED.0 - 1);
    let hello = MeshHello::new(RelayId(1), incompatible);
    hello_stream.write_all(&hello.encode()).await?;

    // The acceptor refuses with the protocol-mismatch application close...
    let reason = connection.closed().await;
    match reason {
        noq::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                close.error_code,
                noq::VarInt::from_u32(MESH_CLOSE_PROTOCOL_MISMATCH),
                "the close carries the protocol-mismatch code",
            );
        }
        other => panic!("expected an application close refusing the version, got {other:?}"),
    }

    // ...and no link ever surfaces for the refused peer.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), links_b_rx.recv())
            .await
            .is_err(),
        "a refused peer must not surface on the links channel",
    );
    Ok(())
}

// --- Mesh-accept peer-identity enforcement ---

/// Connects to `addr` on the mesh ALPN using `cfg`, then sends the identity
/// hello claiming `relay_id` at the current protocol version — the shared setup
/// every peer-identity enforcement test below drives before checking how the
/// acceptor answers.
async fn dial_and_send_hello(
    addr: SocketAddr,
    cfg: noq::ClientConfig,
    relay_id: RelayId,
) -> Result<noq::Connection, AnyError> {
    use rally_point_proto::mesh::MeshHello;
    use rally_point_proto::version::ProtocolVersion;

    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let ep = noq::Endpoint::client(bind)?;
    ep.set_default_client_config(cfg);
    let connection = ep.connect(addr, "localhost")?.await?;
    let mut hello_stream = connection.open_uni().await?;
    let hello = MeshHello::new(relay_id, ProtocolVersion::CURRENT);
    hello_stream.write_all(&hello.encode()).await?;
    Ok(connection)
}

/// Asserts `connection` was application-closed with `expected_code`.
async fn expect_mesh_close(connection: &noq::Connection, expected_code: u32) {
    let reason = connection.closed().await;
    match reason {
        noq::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(
                close.error_code,
                noq::VarInt::from_u32(expected_code),
                "unexpected close code (reason: {:?})",
                close.reason,
            );
        }
        other => panic!("expected an application close, got {other:?}"),
    }
}

/// Builds a mesh-ALPN client config that presents **no** TLS client
/// certificate — what a peer relay predating this leg would still do, and the
/// exact shape [`MESH_CLOSE_NO_CLIENT_CERT`](rally_point_proto::version::MESH_CLOSE_NO_CLIENT_CERT)
/// exists to refuse once enforcement is active. `mesh_client_config` cannot
/// express this any more (it always presents a certificate), so this builds the
/// TLS config by hand, mirroring `quic.rs`'s own stale-ALPN tests.
fn mesh_client_config_without_a_certificate(roots: rustls::RootCertStore) -> noq::ClientConfig {
    let mut tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![rally_point_transport::quic::MESH_ALPN.to_vec()];
    let client =
        noq::crypto::rustls::QuicClientConfig::try_from(tls).expect("a valid TLS 1.3 config");
    noq::ClientConfig::new(Arc::new(client))
}

/// With no coordinator ever having pushed a fleet-peer set (the dev/loopback
/// `--mesh-peer` posture), peer-identity enforcement stays off: a dialer
/// presenting a real certificate and a valid hello establishes a link exactly
/// as before this leg, with no fingerprint check at all.
#[tokio::test]
async fn an_empty_fleet_map_admits_any_peer_certificate() -> Result<(), AnyError> {
    // A full production dial (not the bare hello-only helper the refusal tests
    // below use): the acceptor's `accept_bi` for the mesh control stream is
    // bounded by the hello timeout, so reaching an established link needs the
    // dialer to actually open and establish that stream too, exactly as
    // `run_mesh_dial` does.
    let tenant = make_tenant();
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        false,
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let (links_a_tx, _links_a_rx) = mpsc::channel::<LinkHandle>(8);
    let dial = edge::MeshDial {
        our_id: RelayId(1),
        peer_id: RelayId(2),
        peer_addrs: vec![relay_b.addr],
        server_name: "localhost".to_owned(),
        roots,
        cert_chain: dial_chain,
        key: dial_key,
    };
    tokio::spawn(edge::run_mesh_dial(
        dial,
        Arc::clone(&relay_a.sessions),
        relay_a.mesh.clone(),
        links_a_tx,
    ));

    let (peer_id, _generation, _cmds) =
        tokio::time::timeout(Duration::from_secs(2), links_b_rx.recv())
            .await
            .map_err(|_| "the link should establish with enforcement off")?
            .ok_or("accept side did not produce a link")?;
    assert_eq!(peer_id, RelayId(1));
    drop(relay_a);
    Ok(())
}

/// `--require-mesh-peer-auth` fails closed even before the coordinator's first
/// push: every dial is refused while the fleet map is still empty, with the
/// same code an unrecognized claimed id draws (an empty map trivially has no
/// entry for any id).
#[tokio::test]
async fn require_peer_auth_refuses_every_dial_while_the_fleet_map_is_empty() -> Result<(), AnyError>
{
    let tenant = make_tenant();
    let relay_b = Relay::start(&tenant, 2);

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        empty_fleet_peers(),
        true, // --require-mesh-peer-auth
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let cfg = rally_point_transport::quic::mesh_client_config(roots, dial_chain, dial_key)?;
    let connection = dial_and_send_hello(relay_b.addr, cfg, RelayId(1)).await?;

    expect_mesh_close(
        &connection,
        rally_point_proto::version::MESH_CLOSE_UNKNOWN_PEER,
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), links_b_rx.recv())
            .await
            .is_err(),
        "a refused peer must not surface on the links channel",
    );
    Ok(())
}

/// A peer that completes the TLS handshake without presenting a client
/// certificate is refused once enforcement is active (a non-empty fleet map) —
/// there is nothing to pin against it.
#[tokio::test]
async fn acceptor_refuses_a_peer_presenting_no_client_certificate() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let relay_b = Relay::start(&tenant, 2);

    // Enforcement is active: seed one (unrelated) fleet entry so the map is
    // non-empty. Which entry doesn't matter — this refusal fires before the
    // fleet map is even consulted for a specific id.
    let fleet = FleetMeshPeers::new();
    fleet.store(vec![rally_point_proto::control::MeshPeerIdentity {
        relay_id: RelayId(99),
        cert_sha256: [0xAA; 32],
    }]);

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        fleet.reader(),
        false,
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let cfg = mesh_client_config_without_a_certificate(roots);
    let connection = dial_and_send_hello(relay_b.addr, cfg, RelayId(1)).await?;

    expect_mesh_close(
        &connection,
        rally_point_proto::version::MESH_CLOSE_NO_CLIENT_CERT,
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), links_b_rx.recv())
            .await
            .is_err(),
        "a refused peer must not surface on the links channel",
    );
    Ok(())
}

/// A peer presenting a real certificate but claiming a relay id the fleet map
/// does not name is refused — the coordinator never enrolled that id.
#[tokio::test]
async fn acceptor_refuses_a_peer_claiming_an_unenrolled_relay_id() -> Result<(), AnyError> {
    let tenant = make_tenant();
    let relay_b = Relay::start(&tenant, 2);

    // The fleet only knows relay 9; the dialer below claims relay 42.
    let fleet = FleetMeshPeers::new();
    fleet.store(vec![rally_point_proto::control::MeshPeerIdentity {
        relay_id: RelayId(9),
        cert_sha256: [0xAA; 32],
    }]);

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        fleet.reader(),
        false,
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let cfg = rally_point_transport::quic::mesh_client_config(roots, dial_chain, dial_key)?;
    let connection = dial_and_send_hello(relay_b.addr, cfg, RelayId(42)).await?;

    expect_mesh_close(
        &connection,
        rally_point_proto::version::MESH_CLOSE_UNKNOWN_PEER,
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), links_b_rx.recv())
            .await
            .is_err(),
        "a refused peer must not surface on the links channel",
    );
    Ok(())
}

/// A peer whose claimed relay id is enrolled, but whose presented certificate's
/// fingerprint does not match what the coordinator recorded for that id, is
/// refused — the fleet-set pin caught an impostor (or a cert that rotated
/// without a fresh coordinator push).
#[tokio::test]
async fn acceptor_refuses_a_peer_whose_certificate_fingerprint_does_not_match()
-> Result<(), AnyError> {
    let tenant = make_tenant();
    let relay_b = Relay::start(&tenant, 2);

    // The fleet records relay 1 under a fingerprint that is NOT the dialer's
    // actual certificate below — a decoy cert's fingerprint.
    let (_decoy_chain, _decoy_key, decoy_ca) = self_signed();
    let fleet = FleetMeshPeers::new();
    fleet.store(vec![rally_point_proto::control::MeshPeerIdentity {
        relay_id: RelayId(1),
        cert_sha256: rally_point_transport::quic::cert_fingerprint(decoy_ca.as_ref()),
    }]);

    let (links_b_tx, mut links_b_rx) = mpsc::channel::<LinkHandle>(8);
    tokio::spawn(edge::run_mesh_accept(
        relay_b.mesh_accept_rx,
        Arc::clone(&relay_b.sessions),
        relay_b.mesh.clone(),
        links_b_tx,
        fleet.reader(),
        false,
    ));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let cfg = rally_point_transport::quic::mesh_client_config(roots, dial_chain, dial_key)?;
    let connection = dial_and_send_hello(relay_b.addr, cfg, RelayId(1)).await?;

    expect_mesh_close(
        &connection,
        rally_point_proto::version::MESH_CLOSE_CERT_MISMATCH,
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), links_b_rx.recv())
            .await
            .is_err(),
        "a refused peer must not surface on the links channel",
    );
    Ok(())
}
