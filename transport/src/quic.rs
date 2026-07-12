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
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

/// ALPN protocol id negotiated on every client ↔ relay QUIC connection. The
/// trailing number is bumped on any change an older peer can't interoperate
/// with — the datagram wire framing, the connection-binding handshake, or the
/// connection's stream shape — so a peer on the old protocol is rejected at the
/// TLS handshake rather than later, as a malformed datagram or a puzzling
/// credential failure.
///
/// `5`: each side opens a reliable **control stream** (one bidirectional
/// stream, after the auth handshake) carrying length-prefixed `ControlFrame`s —
/// the divert path for a turn too large to ever ride a datagram. A `4` peer
/// never accepts the stream and never opens its own, so an oversize turn
/// diverted to it would sit unread while lockstep stalls on the missing seq —
/// a silent mid-game hang, rejected at the handshake instead.
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
///
/// This is the client-edge ALPN. Mesh links use [`MESH_ALPN`] — a separate
/// `rp2-mesh/N` namespace, not this `rp2/N` line — so a relay server advertises
/// both and dispatches by which one negotiated, and the two can never collide
/// even as each bumps independently. The two connection kinds carry distinct
/// wire types (`Packet` vs `MeshPacket`), so the ALPN selects which one a
/// connection may exchange. A client dialing with this ALPN can never produce a
/// `MeshPacket` even by mistake: the type lives in a code path the client crate
/// never touches.
pub const ALPN: &[u8] = b"rp2/5";

/// ALPN protocol id negotiated on every relay ↔ relay mesh QUIC connection. A
/// relay-pair shares one connection across every game both relays jointly serve,
/// so it is distinct from the client-edge [`ALPN`]: the connection carries
/// `MeshPacket` datagrams (a `Packet` wrapped with the session it belongs to),
/// not client-edge `Packet` datagrams.
///
/// Versions on a **separate line** from the client-edge [`ALPN`] (`rp2-mesh/N`,
/// not `rp2/N`), because the server advertises both and dispatches by which one
/// negotiated — so the two strings must stay distinct forever, even as each
/// bumps independently. A shared `rp2/N` line would collide: a future
/// client-edge-only bump (a handshake change the mesh's own establishment
/// doesn't share, like the channel-binding change that took client to `rp2/2`)
/// would push client to the same number mesh already occupies, the server would
/// advertise two identical strings, and `protocol()` couldn't tell a client
/// from a peer relay. The separate namespace makes that impossible.
///
/// `1`: introduces `MeshPacket` — one connection per relay-pair carries every
/// jointly-served game's traffic, demultiplexed by a session id, so the mesh has
/// one congestion controller per backbone path rather than N competing ones. A
/// peer that doesn't know `MeshPacket` sends bare `Packet` datagrams that can't
/// be demuxed by session — incompatible.
///
/// `2`: the dialing relay sends a `MeshHello` (its relay id) on a fresh
/// unidirectional stream immediately after connecting, and the accepting relay
/// now *requires* it before serving the link (it labels the link with the peer's
/// id so session joins can target it). A `1` peer never sends that hello, so a
/// mixed pair would connect and then stall until the acceptor's hello timeout —
/// an asymmetric runtime failure. Bumping the version rejects the mismatch
/// cleanly at TLS negotiation instead.
///
/// `3`: both sides carry per-session presence (`MeshPresence` frames — live
/// home-client counts, driving buffer-authority handoff) on reliable
/// uni-streams: the dialer appends frames to its hello stream and keeps it
/// open; the acceptor opens a uni-stream of its own that carries presence
/// alone. A `2` peer closes its hello stream after the hello and never reads
/// the acceptor's stream, so a mixed pair would half-work — presence flowing
/// one way or not at all, leaving a session with a frozen buffer authority —
/// which is worse to debug than a clean connect-time refusal.
///
/// `4`: both sides carry a bidirectional mesh control stream — the dialer opens
/// it right after its hello and the acceptor `accept_bi`s it — on which they
/// propagate synced player-leaves across the mesh (`MeshControlFrame`s:
/// `SlotDeparted` and `LeaveDirective`). A `3` peer never opens or accepts that
/// stream, so a mixed pair would leave the acceptor's bounded `accept_bi` to time
/// out and drop the connection — an asymmetric runtime failure. Bumping the
/// version rejects the mismatch cleanly at TLS negotiation instead, exactly as
/// `2` and `3` did for their new streams. (Both relays of a deployment update
/// together, so no long-lived mixed pair is expected.)
///
/// `5`: the dialer now presents a TLS client certificate on the mesh connection
/// — the same self-signed certificate it serves with — and the acceptor pins it
/// against the coordinator-distributed fleet set (relay id → cert fingerprint)
/// before the link driver ever spawns. `MeshPacket` also gains the session's
/// tenant alongside the bare session id (an additive field an older decoder
/// would ignore, staying tenant-blind). A `4` peer presents no client
/// certificate at all, so against an enforcing acceptor a mixed pair would
/// complete the TLS handshake and then be refused post-handshake — bumping the
/// ALPN rejects the pair cleanly at TLS negotiation instead, and gives both
/// changes a single fleet-upgrade boundary.
pub const MESH_ALPN: &[u8] = b"rp2-mesh/5";

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

/// How often a QUIC mesh connection sends a keepalive PING frame when it has
/// no outgoing datagrams of its own. Prevents idle-timeout disconnects on a
/// mesh link that goes briefly silent — between turns in a quiet game, or
/// when no sessions are joined yet — without adding app-level traffic. QUIC's
/// keepalive is cheaper than an app-level datagram (no payload, no redundancy
/// processing) and rides the existing congestion controller.
///
/// Set clear of ordinary jitter (the mesh flush timer fires every 150ms
/// during active play, so a keepalive at 5s only fires during a genuine
/// silence). Short enough that a NAT mapping or firewall state doesn't expire
/// mid-game (consumer NAT timeouts are typically 30–60s; AWS security groups
/// allow established UDP flows indefinitely).
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// The maximum idle time before QUIC closes a connection. The default (30s) is
/// too long: a dead peer or a dropped NAT mapping would stall lockstep for 30s
/// before anyone notices. 10s detects a dead peer fast enough that a stall
/// surfaces promptly (and, on the client edge, that a departed player's leave is
/// decided within ~10s), while staying clear of brief silences (keepalive fires
/// at 5s, so a live connection never approaches this timeout).
///
/// Applied to every dial side ([`keepalive_transport_config`]): the mesh edge and
/// the client edge. QUIC negotiates the idle timeout as the minimum of both
/// endpoints' advertised values, so the dial side's value governs without touching
/// `server_config`, and one side's keepalive keeps both ends alive (its PINGs
/// elicit ACKs, resetting both idle timers), so the accept side needs no change.
const MAX_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Builds a `TransportConfig` with keepalive (to prevent idle disconnects during
/// silences) and a shorter-than-default idle timeout (to detect dead peers fast).
/// Applied to every dial side — mesh ([`mesh_client_config`]) *and* client edge
/// ([`client_config`]). On the client edge it is load-bearing: when a player
/// drops, lockstep stalls every survivor and their turn traffic stops, so without
/// keepalive their own connections would idle-time-out and the relay would wrongly
/// drop them too; the PINGs keep a stalled-but-alive client connected until the
/// relay pushes it the leave that unstalls it, and only the genuinely dead client
/// (no PINGs) times out — a clean drop detector. QUIC negotiates the idle timeout
/// as the minimum of both ends, so setting it on the dial side governs without
/// touching `server_config`, and one side's keepalive keeps both idle timers reset.
fn keepalive_transport_config() -> quinn::TransportConfig {
    let mut config = quinn::TransportConfig::default();
    config.keep_alive_interval(Some(KEEPALIVE_INTERVAL));
    config.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(MAX_IDLE_TIMEOUT).expect("10s fits in a VarInt"),
    ));
    config
}

/// The ring crypto provider, constructed fresh so we never depend on a
/// process-wide default having been installed.
fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The SHA-256 fingerprint of a DER-encoded TLS certificate — the compact form
/// the mesh-accept path pins a dialing peer's presented client certificate
/// against, and the coordinator records to remember which certificate a relay
/// enrolled with. A relay's identity *is* this fingerprint: there is no shared
/// certificate authority, so two independently self-signed relay certs have
/// nothing else in common to check.
///
/// The fingerprints the coordinator distributes in the fleet-peer set are
/// computed by its own equivalent of this digest (SHA-256 over the raw DER
/// bytes), and the accept-path pin compares the two byte-for-byte — any change
/// to this digest must land on both sides at once.
pub fn cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, cert_der).as_ref());
    out
}

/// Requests but does not require a TLS client certificate from a peer dialing
/// the relay's single listening endpoint ([`server_config`]), and accepts
/// whatever certificate is presented without validating it against any
/// certificate chain, trust anchor, or expiry.
///
/// The client edge and the mesh edge share one TLS listener, and their two
/// kinds of dialer need opposite defaults: a game client presents no
/// certificate at all (client authorization is a separate app-level step, see
/// the module docs) and must keep connecting exactly as before; a peer relay
/// dialing the mesh edge now presents its own self-signed leaf certificate as
/// its TLS client identity ([`mesh_client_config`]). `client_auth_mandatory`
/// returning `false` is what keeps the client edge unaffected — a connection
/// presenting no certificate is accepted here exactly as `with_no_client_auth`
/// always accepted it.
///
/// **This verifier makes no trust decision.** `verify_client_cert` accepts any
/// certificate unconditionally — there is no root store to check it against,
/// because relay certs are independently self-signed with no shared CA. The
/// actual trust decision is made one layer up, at the application level: the
/// mesh acceptor SHA-256s the presented leaf ([`cert_fingerprint`]) and pins it
/// against the fingerprint the coordinator recorded for the claimed relay id at
/// that relay's enroll, refusing the connection post-handshake on a mismatch. A
/// certificate this verifier "accepted" only proves the dialer holds the
/// matching private key — which certificate is trustworthy is a fact this
/// verifier does not have.
///
/// Signature verification still runs for real: `verify_tls12_signature` and
/// `verify_tls13_signature` delegate to the ring provider's default webpki-based
/// checks, which parse the certificate to extract its public key. So "no chain
/// validation" means no root/issuer/expiry check, not no check at all — a
/// certificate that isn't valid X.509, or a handshake signature that doesn't
/// actually match the presented certificate's public key, still fails here.
#[derive(Debug)]
struct RequestClientCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ClientCertVerifier for RequestClientCert {
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // No trust anchors to hint at: this verifier trusts no CA, so there is
        // nothing to name here. An empty list asks a client to present whatever
        // it has rather than steering it toward a specific issuer.
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // No chain validation — see the type doc. A malformed certificate still
        // fails the handshake below, where signature verification must parse it
        // to extract a public key.
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Builds the relay-side QUIC server config from its certificate chain and
/// private key. The relay presents this chain; clients verify it against their
/// trusted roots (see [`client_config`]). The server advertises both the
/// client-edge [`ALPN`] and the mesh [`MESH_ALPN`], so a single listening
/// endpoint accepts both connection kinds; the negotiated ALPN tells the accept
/// loop which wire type (`Packet` or `MeshPacket`) the connection will carry.
///
/// Requests (does not require) a TLS client certificate from every dialer —
/// see `RequestClientCert`, this module's client-cert verifier. A client-edge
/// dialer presents none and connects
/// unaffected; a mesh-edge dialer presents its own leaf cert, which the mesh
/// acceptor pins against the coordinator's fleet set at the application layer.
pub fn server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, TlsError> {
    let provider = ring_provider();
    let client_verifier = Arc::new(RequestClientCert {
        provider: Arc::clone(&provider),
    });
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, key)?;
    tls.alpn_protocols = vec![ALPN.to_vec(), MESH_ALPN.to_vec()];

    let server = QuicServerConfig::try_from(tls)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(server)))
}

/// Builds the client-edge QUIC config, trusting the given root certificates to
/// authenticate the relay it dials. Negotiates the client-edge [`ALPN`], so the
/// connection carries `Packet` datagrams — never `MeshPacket`.
pub fn client_config(roots: rustls::RootCertStore) -> Result<quinn::ClientConfig, TlsError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let client = QuicClientConfig::try_from(tls)?;
    let mut config = quinn::ClientConfig::new(Arc::new(client));
    // Keepalive + short idle timeout on the client edge: keeps a stalled-but-alive
    // client connected (so a drop doesn't idle-time-out the survivors) while a dead
    // client is detected fast. See `keepalive_transport_config`.
    config.transport_config(Arc::new(keepalive_transport_config()));
    Ok(config)
}

/// Builds the mesh-edge QUIC config a relay uses to dial a peer relay,
/// trusting the given root certificates to authenticate it and presenting
/// `cert_chain`/`key` as this relay's own TLS client identity — the same
/// certificate it serves with (see [`server_config`]'s `RequestClientCert`,
/// which the peer's acceptor applies to us in turn). Negotiates the mesh
/// [`MESH_ALPN`], so the connection carries `MeshPacket` datagrams — never
/// client-edge `Packet`. A mesh link is a relay ↔ relay connection distinct from
/// the client ↔ relay edge; the ALPN keeps the two wire types from crossing.
///
/// Presenting a client certificate is unconditional here — every mesh dial
/// announces itself — because the *enforcement* decision (whether an acceptor
/// actually checks it) lives entirely on the accept side, keyed off whether the
/// coordinator has pushed a fleet-peer set. An acceptor with no fleet set yet
/// (or one that predates this leg) simply never looks at the certificate this
/// presents, so dialing with one is always safe.
pub fn mesh_client_config(
    roots: rustls::RootCertStore,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ClientConfig, TlsError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)?;
    tls.alpn_protocols = vec![MESH_ALPN.to_vec()];

    let client = QuicClientConfig::try_from(tls)?;
    let mut config = quinn::ClientConfig::new(Arc::new(client));
    config.transport_config(Arc::new(keepalive_transport_config()));
    Ok(config)
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
    /// link is built on. `client_config` presents no TLS client certificate (a
    /// game client never does), so this also proves `RequestClientCert`'s
    /// `client_auth_mandatory: false` keeps a certificate-less dialer connecting
    /// exactly as `with_no_client_auth` always did.
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

    /// A mesh dial presents its own certificate as its TLS client identity, and
    /// the accepting side observes exactly that certificate via
    /// `Connection::peer_identity` — the raw material the mesh-accept path's
    /// fingerprint pin (built one layer up, in `relay::mesh_edge`) checks
    /// against the coordinator's fleet set. This only proves the TLS plumbing
    /// carries the certificate through; the pin comparison itself is relay-side.
    #[tokio::test]
    async fn mesh_dial_presents_its_client_certificate_to_the_acceptor() {
        let (server_chain, server_key, server_ca) = self_signed();
        let server_cfg = server_config(server_chain, server_key).unwrap();

        let (dial_chain, dial_key, _dial_ca) = self_signed();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(server_ca).unwrap();
        let client_cfg = mesh_client_config(roots, dial_chain.clone(), dial_key).unwrap();

        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let server = quinn::Endpoint::server(server_cfg, bind).unwrap();
        let server_addr = server.local_addr().unwrap();

        let mut client = quinn::Endpoint::client(bind).unwrap();
        client.set_default_client_config(client_cfg);

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            incoming.await.unwrap()
        });

        let _client_conn = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let server_conn = server_task.await.unwrap();

        let peer_certs = server_conn
            .peer_identity()
            .expect("the mesh dial presented a client certificate")
            .downcast::<Vec<CertificateDer<'static>>>()
            .expect("the rustls backend's peer identity is a cert chain");
        assert_eq!(
            peer_certs.first(),
            dial_chain.first(),
            "the acceptor observes exactly the leaf the dialer presented",
        );
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

    /// A relay still on the previous mesh ALPN (`rp2-mesh/1`, before the
    /// mandatory post-connect identity hello) is rejected at the handshake by a
    /// current relay, rather than connecting and then stalling until the
    /// acceptor's hello timeout. The mesh establishment protocol is versioned on
    /// its own `rp2-mesh/N` line, so a connection-shape change like requiring
    /// the hello is an incompatible bump old and new builds can't negotiate.
    ///
    /// Mirrors [`rejects_a_peer_with_a_stale_alpn`] for the mesh edge: the server
    /// advertises both current ALPNs, and a dialer offering only the stale
    /// `rp2-mesh/1` matches neither.
    #[tokio::test]
    async fn rejects_a_mesh_peer_with_a_stale_alpn() {
        let (chain, key, ca) = self_signed();
        let server_cfg = server_config(chain, key).unwrap();

        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let server = quinn::Endpoint::server(server_cfg, bind).unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("a connection arrived");
            incoming.await
        });

        // A mesh dialer identical to the real one except it advertises the prior
        // mesh ALPN — neither current ALPN the server offers.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(ring_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"rp2-mesh/1".to_vec()];
        let stale_cfg =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));

        let mut client = quinn::Endpoint::client(bind).unwrap();
        client.set_default_client_config(stale_cfg);

        let client_result = client.connect(server_addr, "localhost").unwrap().await;
        let server_result = server_task.await.unwrap();

        assert!(
            client_result.is_err(),
            "a stale mesh-ALPN dialer must fail the handshake"
        );
        assert!(
            server_result.is_err(),
            "the server must reject a stale mesh-ALPN handshake"
        );
    }
}
