//! Shared QUIC setup for a netcode v2 link.
//!
//! Both endpoints of a link use the same crypto configuration: the client dials
//! its home relay, and the relay accepts both clients and mesh peers. Building
//! that config once here keeps the two roles in lockstep on protocol version,
//! ALPN, and crypto provider.
//!
//! The crypto provider is pinned to **ring**, not the default aws-lc-rs, because
//! the client links this crate into the 32-bit game DLL, and ring builds for
//! `i686-pc-windows-msvc` without a C/NASM toolchain. Selecting it explicitly
//! (rather than relying on a process-wide default provider) means a host that
//! happens to have aws-lc-rs linked elsewhere can't change which provider a link
//! uses.
//!
//! TLS here secures the channel and proves the relay's server identity; it does
//! **not** authenticate the *client*. Client authorization is a separate
//! app-level step — the signed token plus a connection-binding challenge — that
//! runs after the QUIC handshake, so these connections use no client
//! certificates.

use std::sync::Arc;

use quinn::crypto::rustls::{NoInitialCipherSuite, QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// ALPN protocol id negotiated on every netcode v2 QUIC connection. The trailing
/// number is bumped on any change an older peer can't interoperate with — the
/// datagram wire framing, the connection-binding handshake, or the connection's
/// stream shape — so a peer on the old protocol is rejected at the TLS handshake
/// rather than later, as a malformed datagram or a puzzling credential failure.
///
/// `4`: the payload `seq` is now the turn's origin identity — assigned by the
/// sending client and preserved end-to-end, never restamped per hop — and each
/// slot carries its own seq space. The ack-beacon frame correspondingly carries
/// a `(slot, cursor)` pair, not a bare cursor. A `3` peer restamps seq per link
/// and sends a bare beacon cursor, so its dedup, retirement, and ordering are
/// incompatible.
///
/// `3`: the connection now opens an ack-beacon unidirectional stream after the
/// authorization handshake, so each side can force-advance the peer's unacked
/// window. A `2` peer opens no such stream and never sends beacons, so its
/// `retire_through` never fires — incompatible.
///
/// `2`: the connection-binding challenge is signed together with a TLS channel
/// binding, not the nonce alone, so a `1` peer's proof no longer verifies and is
/// deliberately not accepted — the old proof was replayable.
pub const ALPN: &[u8] = b"rp2/4";

/// Failure to assemble a QUIC TLS configuration.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The underlying rustls configuration was rejected (e.g. the cert and key
    /// don't match, or no protocol version is available).
    #[error("rustls configuration error: {0}")]
    Rustls(#[from] rustls::Error),
    /// rustls produced a config QUIC can't use because it lacks a TLS 1.3
    /// initial cipher suite. Not reachable with the ring provider, which always
    /// supplies one.
    #[error("QUIC requires a TLS 1.3 cipher suite: {0}")]
    NoInitialCipherSuite(#[from] NoInitialCipherSuite),
}

/// The ring crypto provider, constructed fresh so we never depend on a
/// process-wide default having been installed.
fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Builds the relay-side QUIC server config from its certificate chain and
/// private key. The relay presents this chain; clients verify it against their
/// trusted roots (see [`client_config`]).
pub fn server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, TlsError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let server = QuicServerConfig::try_from(tls)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(server)))
}

/// Builds the client-side QUIC config, trusting the given root certificates to
/// authenticate the relay it dials.
pub fn client_config(roots: rustls::RootCertStore) -> Result<quinn::ClientConfig, TlsError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let client = QuicClientConfig::try_from(tls)?;
    Ok(quinn::ClientConfig::new(Arc::new(client)))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;

    /// A self-signed cert + key plus the cert on its own (to seed a client's
    /// trust roots), for loopback tests.
    fn self_signed() -> (
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        CertificateDer<'static>,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
        (vec![cert_der.clone()], key_der, cert_der)
    }

    /// Proves the pinned quinn + rustls + ring stack actually completes a
    /// handshake and carries a datagram over loopback — the foundation every
    /// link is built on.
    #[tokio::test]
    async fn loopback_connects_and_exchanges_a_datagram() {
        let (chain, key, ca) = self_signed();
        let server_cfg = server_config(chain, key).unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let client_cfg = client_config(roots).unwrap();

        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let server = quinn::Endpoint::server(server_cfg, bind).unwrap();
        let server_addr = server.local_addr().unwrap();

        let mut client = quinn::Endpoint::client(bind).unwrap();
        client.set_default_client_config(client_cfg);

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            conn.read_datagram().await.unwrap()
        });

        let conn = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        conn.send_datagram(prost::bytes::Bytes::from_static(b"hello"))
            .unwrap();

        let received = server_task.await.unwrap();
        assert_eq!(&received[..], b"hello");
    }

    /// A peer on an older protocol — here, advertising the previous ALPN — is
    /// rejected at the TLS handshake instead of connecting and then failing later.
    /// This is the rollout gate for an incompatible change like the channel-bound
    /// auth proof: old and new builds simply can't form a connection.
    ///
    /// The server task drives its end of the handshake to completion and the test
    /// asserts *both* ends fail, so the client can't pass by failing on a dropped
    /// server instead of on ALPN. The matching-ALPN success case is the positive
    /// control in [`loopback_connects_and_exchanges_a_datagram`].
    #[tokio::test]
    async fn rejects_a_peer_with_a_stale_alpn() {
        let (chain, key, ca) = self_signed();
        let server_cfg = server_config(chain, key).unwrap();

        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let server = quinn::Endpoint::server(server_cfg, bind).unwrap();
        let server_addr = server.local_addr().unwrap();

        // Keep the endpoint and the incoming connection alive and drive the
        // server-side handshake to its result, so any client failure is the ALPN
        // rejection, not a server that went away mid-handshake.
        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("a connection arrived");
            incoming.await
        });

        // A client identical to the real one except it advertises the prior ALPN.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(ring_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"rp2/1".to_vec()];
        let stale_cfg =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));

        let mut client = quinn::Endpoint::client(bind).unwrap();
        client.set_default_client_config(stale_cfg);

        let client_result = client.connect(server_addr, "localhost").unwrap().await;
        let server_result = server_task.await.unwrap();

        assert!(
            client_result.is_err(),
            "a stale-ALPN client must fail the handshake"
        );
        assert!(
            server_result.is_err(),
            "the server must reject a stale-ALPN handshake"
        );
    }
}
