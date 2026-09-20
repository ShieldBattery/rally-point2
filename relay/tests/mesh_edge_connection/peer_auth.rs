//! What the mesh acceptor refuses: an incompatible hello, a missing or
//! unenrolled client certificate, and a fingerprint that does not match the
//! fleet map.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::MeshPeerIdentity;
use rally_point_proto::ids::RelayId;
use rally_point_proto::version::{
    MESH_CLOSE_CERT_MISMATCH, MESH_CLOSE_NO_CLIENT_CERT, MESH_CLOSE_UNKNOWN_PEER,
};
use rally_point_relay::coordinator::client::FleetMeshPeers;
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

    let tenant = make_default_tenant();
    let mut relay_b = Relay::start(&tenant, 2);
    let mut links_b = accept_on(&mut relay_b, empty_fleet_peers(), false);

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

    expect_mesh_close(&connection, MESH_CLOSE_PROTOCOL_MISMATCH).await;
    expect_no_link(&mut links_b).await;
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
    match connection.closed().await {
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

/// Asserts a refused peer never surfaces on the acceptor's links channel. The
/// refusal has already been observed as a close by the time this runs, so a
/// short window is enough to catch a link that was spawned anyway.
async fn expect_no_link(links: &mut mpsc::Receiver<LinkHandle>) {
    assert!(
        tokio::time::timeout(Duration::from_millis(100), links.recv())
            .await
            .is_err(),
        "a refused peer must not surface on the links channel",
    );
}

/// Builds a mesh-ALPN client config that presents **no** TLS client
/// certificate — what a peer relay predating this leg would still do, and the
/// exact shape [`MESH_CLOSE_NO_CLIENT_CERT`] exists to refuse once enforcement
/// is active. `mesh_client_config` cannot express this any more (it always
/// presents a certificate), so this builds the TLS config by hand, mirroring
/// `quic.rs`'s own stale-ALPN tests.
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

/// `--require-mesh-peer-auth` fails closed even before the coordinator's first
/// push: every dial is refused while the fleet map is still empty, with the
/// same code an unrecognized claimed id draws (an empty map trivially has no
/// entry for any id).
#[tokio::test]
async fn require_peer_auth_refuses_every_dial_while_the_fleet_map_is_empty() -> Result<(), AnyError>
{
    let tenant = make_default_tenant();
    let mut relay_b = Relay::start(&tenant, 2);
    let mut links_b = accept_on(&mut relay_b, empty_fleet_peers(), true);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(relay_b.ca.clone()).unwrap();
    let (dial_chain, dial_key, _) = self_signed();
    let cfg = rally_point_transport::quic::mesh_client_config(roots, dial_chain, dial_key)?;
    let connection = dial_and_send_hello(relay_b.addr, cfg, RelayId(1)).await?;

    expect_mesh_close(&connection, MESH_CLOSE_UNKNOWN_PEER).await;
    expect_no_link(&mut links_b).await;
    Ok(())
}

/// Every way a peer can fail the fleet-map pin, each with its own close code —
/// the codes are the diagnosis, so collapsing them would hide exactly what the
/// design wants an operator to be able to read off a refused dial.
///
/// The rows are: a peer that completes the TLS handshake without presenting a
/// client certificate at all (there is nothing to pin against it, and this
/// fires before the map is even consulted for a specific id); a peer presenting
/// a real certificate but claiming a relay id the coordinator never enrolled;
/// and a peer whose claimed id *is* enrolled but whose certificate fingerprint
/// is not the one recorded for it — the pin catching an impostor, or a cert
/// that rotated without a fresh coordinator push.
///
/// One relay and one accept loop serve all three: the fleet map is re-stored
/// between rows, which also keeps the suite's hold on the process-wide accept
/// permits to a minimum.
#[tokio::test]
async fn the_acceptor_refuses_a_peer_that_fails_the_fleet_pin() -> Result<(), AnyError> {
    let tenant = make_default_tenant();
    let mut relay_b = Relay::start(&tenant, 2);
    let fleet = FleetMeshPeers::new();
    let mut links_b = accept_on(&mut relay_b, fleet.reader(), false);

    // A certificate the dialer below will never present: the fingerprint the
    // fleet map records for the mismatch row.
    let (_decoy_chain, _decoy_key, decoy_ca) = self_signed();
    let decoy_fingerprint = rally_point_transport::quic::cert_fingerprint(decoy_ca.as_ref());

    for (case, enrolled, presents_a_certificate, claimed_id, expected_close) in [
        (
            "a peer presenting no client certificate",
            // Enforcement is active (a non-empty map); which entry it holds
            // does not matter, this refusal fires first.
            vec![MeshPeerIdentity {
                relay_id: RelayId(99),
                cert_sha256: [0xAA; 32],
            }],
            false,
            RelayId(1),
            MESH_CLOSE_NO_CLIENT_CERT,
        ),
        (
            "a peer claiming an unenrolled relay id",
            vec![MeshPeerIdentity {
                relay_id: RelayId(9),
                cert_sha256: [0xAA; 32],
            }],
            true,
            RelayId(42),
            MESH_CLOSE_UNKNOWN_PEER,
        ),
        (
            "a peer whose certificate fingerprint does not match",
            vec![MeshPeerIdentity {
                relay_id: RelayId(1),
                cert_sha256: decoy_fingerprint,
            }],
            true,
            RelayId(1),
            MESH_CLOSE_CERT_MISMATCH,
        ),
    ] {
        fleet.store(enrolled);

        let mut roots = rustls::RootCertStore::empty();
        roots.add(relay_b.ca.clone()).unwrap();
        let cfg = if presents_a_certificate {
            let (dial_chain, dial_key, _) = self_signed();
            rally_point_transport::quic::mesh_client_config(roots, dial_chain, dial_key)?
        } else {
            mesh_client_config_without_a_certificate(roots)
        };

        let connection = dial_and_send_hello(relay_b.addr, cfg, claimed_id).await?;
        match tokio::time::timeout(Duration::from_secs(5), connection.closed()).await {
            Ok(noq::ConnectionError::ApplicationClosed(close)) => assert_eq!(
                close.error_code,
                noq::VarInt::from_u32(expected_close),
                "{case} must draw its own close code (reason: {:?})",
                close.reason,
            ),
            other => {
                panic!("expected {case} to be refused with an application close, got {other:?}")
            }
        }
        expect_no_link(&mut links_b).await;
    }
    Ok(())
}
