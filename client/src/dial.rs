//! Dialing the home relay: open a QUIC connection, complete the authorization
//! handshake, and hand back a transport [`Link`] ready to carry turns.
//!
//! This is the client mirror of the relay's accept-and-authorize edge. A
//! [`ClientEndpoint`] owns the local UDP socket; [`connect`](ClientEndpoint::connect)
//! dials a relay, runs the four-step handshake over one client-opened
//! bidirectional stream, and — once the relay acknowledges the connection as
//! routable — wraps the connection as a [`Link`]. Turns then ride QUIC datagrams
//! through that link; the handshake stream has done its job and is closed.
//!
//! The handshake's wire shape is the shared codec in
//! [`rally_point_proto::handshake`], so the client and relay can never drift on
//! the framing. The one piece the client owns is signing the relay's challenge
//! with its private key, proving it holds the key the token commits to.
//!
//! The whole dial is bounded by a deadline, so a relay that accepts the
//! connection but then stalls in the handshake — rather than completing or
//! rejecting it — surfaces a timeout instead of hanging the game-launch path.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::close_codes;
use rally_point_proto::handshake::{self, HandshakeError};
use rally_point_proto::ids::SlotId;
use rally_point_proto::token::{
    CHALLENGE_LEN, CHANNEL_BINDING_EXPORTER_LABEL, CHANNEL_BINDING_LEN, ConnectionChallenge,
};
use rally_point_transport::{Link, noq, quic, rustls};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::time::{Instant, timeout_at};

use crate::identity::Identity;

/// Default upper bound on a full dial — the QUIC handshake plus the authorization
/// exchange. A conforming relay bounds its own side of the handshake on a shorter
/// timer and rejects cleanly, so this is the backstop for a relay that accepts the
/// connection but then stalls without ever sending the challenge or rejecting it,
/// which would otherwise leave the game-launch path waiting forever. Callers with
/// their own launch budget use [`ClientEndpoint::connect_with_timeout`].
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A QUIC client endpoint for dialing relays.
///
/// Holds the local UDP socket open for as long as its connections live, so a
/// caller keeps the endpoint alive for the duration of a session. One endpoint
/// can dial more than once (a relay's different address families, say, or a
/// re-dial after a drop).
pub struct ClientEndpoint {
    endpoint: noq::Endpoint,
}

/// Why a client endpoint could not be built.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// Assembling the QUIC/TLS client configuration failed.
    #[error("building the client TLS configuration failed: {0}")]
    Tls(#[from] quic::TlsError),
    /// Binding the local UDP socket failed.
    #[error("binding the client UDP socket failed: {0}")]
    Bind(#[from] std::io::Error),
    /// No async runtime was available to drive the QUIC endpoint. The endpoint
    /// must be built from within a tokio runtime — the game DLL provides one.
    #[error("no async runtime available to drive the QUIC endpoint")]
    NoRuntime,
}

/// Why dialing a relay or completing the authorization handshake failed.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    /// Starting the QUIC connection failed (a bad address, or the endpoint is
    /// shutting down) — the connection never began.
    #[error("starting the QUIC connection failed: {0}")]
    Connect(#[from] noq::ConnectError),
    /// The QUIC connection failed during the handshake — including the relay
    /// closing it because authorization was refused (an unknown or expired token,
    /// a bad challenge response, or the slot already taken).
    #[error("QUIC connection failed: {0}")]
    Connection(#[from] noq::ConnectionError),
    /// The relay's advertised datagram budget is under the guaranteed floor the
    /// transport's admission and replay invariants assume — an unsupported peer
    /// configuration, refused outright at establishment rather than partially
    /// supported (see
    /// [`verify_datagram_budget`](rally_point_transport::quic::verify_datagram_budget)).
    /// Not retryable against the same relay.
    #[error(transparent)]
    DatagramBudgetTooSmall(#[from] rally_point_transport::quic::DatagramBudgetTooSmall),
    /// Framing the authorization token for the wire failed.
    #[error("framing the authorization token failed: {0}")]
    Token(#[from] HandshakeError),
    /// Writing a handshake message to the relay failed.
    #[error("writing a handshake message failed: {0}")]
    Write(#[from] noq::WriteError),
    /// Reading a handshake message from the relay failed.
    #[error("reading a handshake message failed: {0}")]
    Read(#[from] noq::ReadExactError),
    /// The relay replied on the handshake stream with something other than its
    /// acknowledgement byte. A conforming relay never does this — it acknowledges
    /// or closes the connection — so this guards against a misbehaving peer.
    #[error("relay sent an unexpected handshake acknowledgement")]
    UnexpectedAck,
    /// The connection's TLS channel binding could not be derived, so the
    /// connection-binding proof can't be produced.
    #[error("deriving the connection's channel binding failed")]
    ChannelBinding,
    /// The dial did not finish within its deadline: either nothing answered the
    /// QUIC handshake at all (a filtered or black-holed path looks exactly like
    /// this), or the relay accepted the connection and then stalled instead of
    /// completing or rejecting the authorization. The connection has been closed.
    #[error("dial timed out after {timeout:?}")]
    TimedOut { timeout: Duration },
    /// The relay refused a re-dial because this slot's leave was already decided —
    /// a survivor's drop request was honored, or it left cleanly — so the game has
    /// moved on without it (the relay's slot-departed close). Terminal for a reconnecting
    /// client: retrying cannot bring the slot back. Only ever produced by
    /// [`reconnect_with_timeout`](ClientEndpoint::reconnect_with_timeout); a fresh
    /// dial surfaces the same close as a plain [`Connection`](DialError::Connection)
    /// error, unchanged.
    #[error("relay refused the re-dial: slot already departed")]
    SlotDeparted,
    /// The relay refused the connection under its evidence policy. Terminal for a re-dial.
    #[error("relay refused the connection")]
    EvidenceRejected,
}

impl ClientEndpoint {
    /// Binds an ephemeral local UDP port, trusting `roots` to authenticate the
    /// relays it dials.
    ///
    /// The socket is dual-stack so this default constructor reaches the
    /// IPv6-primary, dual-stack relay deployment: IPv6 relays directly and IPv4
    /// ones via their IPv4-mapped form (handled in [`connect`](Self::connect)).
    ///
    /// Must be called from within a tokio runtime, which drives the endpoint.
    pub fn bind(roots: rustls::RootCertStore) -> Result<Self, EndpointError> {
        Self::bind_on_port(roots, 0)
    }

    /// [`bind`](Self::bind) on a caller-chosen local UDP port instead of an
    /// ephemeral one — the same dual-stack socket, only the port differs. A known
    /// per-client port lets tooling that filters traffic by port (clumsy,
    /// WinDivert, tc) single out one client among several on a machine. Port `0`
    /// binds ephemerally, exactly like [`bind`](Self::bind). A caller whose needs
    /// go beyond the port — an IPv4-only host, a shared endpoint — still builds
    /// its own socket and uses [`from_endpoint`](Self::from_endpoint).
    ///
    /// When the host can't set up a dual-stack endpoint, this falls back to an
    /// IPv4-only one, which reaches only the relays' IPv4 addresses. Wine on macOS
    /// is one such host: it refuses the IPv4-level socket options noq sets on a
    /// dual-stack socket.
    ///
    /// Must be called from within a tokio runtime, which drives the endpoint.
    pub fn bind_on_port(roots: rustls::RootCertStore, port: u16) -> Result<Self, EndpointError> {
        let config = quic::client_config(roots)?;
        let runtime = noq::default_runtime().ok_or(EndpointError::NoRuntime)?;
        let endpoint = endpoint_with_fallback(port, runtime, endpoint_on)?;
        endpoint.set_default_client_config(config);
        Ok(Self { endpoint })
    }

    /// Wraps an endpoint the caller has already built and configured with a client
    /// config (a custom socket, or one shared across roles).
    pub fn from_endpoint(endpoint: noq::Endpoint) -> Self {
        Self { endpoint }
    }

    /// The underlying QUIC endpoint.
    pub fn endpoint(&self) -> &noq::Endpoint {
        &self.endpoint
    }

    /// Moves the endpoint onto a freshly bound ephemeral UDP port on the same local
    /// address, returning the new local address. Every handle cloned from the same
    /// [`noq::Endpoint`] moves with it.
    ///
    /// A new source port is a new flow to every NAT and stateful firewall on the
    /// path, so this gets a dial past a mapping that went bad under the old port —
    /// one a public IP change left translating to the old address, say, where
    /// datagrams still leave but replies never come back, and that the client's own
    /// re-dials keep alive. An IPv6 socket is rebound dual-stack, as
    /// [`bind`](Self::bind) builds it. On error the endpoint keeps its old socket.
    pub fn rebind_fresh_port(&self) -> std::io::Result<SocketAddr> {
        let mut local = self.endpoint.local_addr()?;
        local.set_port(0);
        self.endpoint.rebind(udp_socket(local)?.into())?;
        self.endpoint.local_addr()
    }

    /// Dials `relay_addr`, runs the authorization handshake as `identity`, and
    /// returns the connection as a transport [`Link`] once the relay has
    /// acknowledged it as routable.
    ///
    /// `server_name` is the relay's TLS server name, checked against the
    /// certificate it presents. The relay preserves each origin slot's payload
    /// sequence and forwards turns as they arrive. The driver above the link
    /// ([`LinkDriver`](crate::LinkDriver)) restores game order independently per
    /// slot, combining turns received through datagrams and the reliable control
    /// stream. A packet's sequence is only a per-link acknowledgement handle.
    ///
    /// The whole dial is bounded by `CONNECT_TIMEOUT` so a relay that accepts the
    /// connection but then stalls cannot hang the caller; use
    /// [`connect_with_timeout`](Self::connect_with_timeout) to set the bound.
    pub async fn connect(
        &self,
        relay_addr: SocketAddr,
        server_name: &str,
        identity: &Identity,
    ) -> Result<Link, DialError> {
        self.connect_with_timeout(relay_addr, server_name, identity, CONNECT_TIMEOUT)
            .await
    }

    /// [`connect`](Self::connect) with an explicit upper bound on the whole dial —
    /// the QUIC handshake plus the authorization exchange.
    ///
    /// On expiry the connection is closed and [`DialError::TimedOut`] is returned,
    /// so a relay that never answers, or accepts the connection and then goes
    /// silent, surfaces a bounded error instead of blocking the game-launch path
    /// indefinitely.
    pub async fn connect_with_timeout(
        &self,
        relay_addr: SocketAddr,
        server_name: &str,
        identity: &Identity,
        timeout: Duration,
    ) -> Result<Link, DialError> {
        // One deadline spans both phases, so a stall anywhere in the dial — the
        // QUIC handshake or the authorization exchange — is bounded by `timeout`.
        let deadline = Instant::now() + timeout;

        let target = mapped_target(self.endpoint.local_addr().ok(), relay_addr);
        let connecting = self.endpoint.connect(target, server_name)?;
        let connection = match timeout_at(deadline, connecting).await {
            Ok(result) => result?,
            // The half-open connection drops here, which closes it.
            Err(_elapsed) => return Err(DialError::TimedOut { timeout }),
        };

        rally_point_transport::quic::verify_datagram_budget(&connection)?;

        // A fresh dial presents no resume cursors: the relay replays nothing.
        match timeout_at(deadline, authorize(&connection, identity, &[])).await {
            Ok(result) => {
                if refused_with(&connection, close_codes::EVIDENCE_REJECTED) {
                    Err(DialError::EvidenceRejected)
                } else {
                    result
                }
            }
            Err(_elapsed) => {
                connection.close(
                    noq::VarInt::from_u32(close_codes::CLIENT_CONNECT_TIMEOUT),
                    b"authorization timed out",
                );
                Err(DialError::TimedOut { timeout })
            }
        }
    }

    /// Re-dials the same relay to resume a session whose link dropped, presenting
    /// per-slot resume `cursors` so the relay replays only the turns this client
    /// missed. Each cursor is `(slot, next_needed_seq)`: the relay replays every
    /// recorded turn for that slot at or past the seq, on the reliable control
    /// stream, before live turns resume.
    ///
    /// The dial is bounded by `timeout` like [`connect_with_timeout`](Self::connect_with_timeout),
    /// but classifies one refusal specially: if the relay closes the connection with
    /// its slot-departed code, this returns [`DialError::SlotDeparted`] so the
    /// reconnect loop can stop rather than retry a slot the game has already moved
    /// past. Every other failure (a timeout, a lost connection, a slot still held by
    /// a not-yet-reaped previous connection) surfaces unchanged, for the caller to
    /// retry.
    pub async fn reconnect_with_timeout(
        &self,
        relay_addr: SocketAddr,
        server_name: &str,
        identity: &Identity,
        cursors: &[(SlotId, u64)],
        timeout: Duration,
    ) -> Result<Link, DialError> {
        let deadline = Instant::now() + timeout;

        let target = mapped_target(self.endpoint.local_addr().ok(), relay_addr);
        let connecting = self.endpoint.connect(target, server_name)?;
        let connection = match timeout_at(deadline, connecting).await {
            Ok(result) => result?,
            Err(_elapsed) => return Err(DialError::TimedOut { timeout }),
        };

        rally_point_transport::quic::verify_datagram_budget(&connection)?;

        match timeout_at(deadline, authorize(&connection, identity, cursors)).await {
            Ok(Ok(link)) => Ok(link),
            Ok(Err(error)) => {
                // A read/write failure during the handshake may be the relay closing
                // the connection to refuse the re-dial. Prefer its application close
                // code, which names *why* — a departed slot is terminal — over the
                // transport-level error the failed I/O surfaced.
                if refused_with(&connection, close_codes::SLOT_DEPARTED) {
                    Err(DialError::SlotDeparted)
                } else if refused_with(&connection, close_codes::EVIDENCE_REJECTED) {
                    Err(DialError::EvidenceRejected)
                } else {
                    Err(error)
                }
            }
            Err(_elapsed) => {
                connection.close(
                    noq::VarInt::from_u32(close_codes::CLIENT_CONNECT_TIMEOUT),
                    b"authorization timed out",
                );
                Err(DialError::TimedOut { timeout })
            }
        }
    }
}

/// Why [`endpoint_on`] could not build an endpoint.
enum EndpointSetupError {
    /// Binding `local` failed, e.g. because the port is taken. Another address
    /// family on the same port is no substitute for the requested bind.
    Bind(std::io::Error),
    /// Creating the socket or setting it up for noq failed.
    Setup(std::io::Error),
}

/// Builds a dual-stack endpoint on `port` with `build`, or an IPv4-only one when
/// the dual-stack setup (not its bind) fails. If both attempts fail, the IPv4
/// error is returned and the earlier dual-stack error is logged.
fn endpoint_with_fallback(
    port: u16,
    runtime: Arc<dyn noq::Runtime>,
    build: impl Fn(SocketAddr, Arc<dyn noq::Runtime>) -> Result<noq::Endpoint, EndpointSetupError>,
) -> std::io::Result<noq::Endpoint> {
    match build((Ipv6Addr::UNSPECIFIED, port).into(), runtime.clone()) {
        Ok(endpoint) => Ok(endpoint),
        Err(EndpointSetupError::Bind(error)) => Err(error),
        Err(EndpointSetupError::Setup(dual_stack_error)) => {
            match build((Ipv4Addr::UNSPECIFIED, port).into(), runtime) {
                Ok(endpoint) => {
                    tracing::warn!(
                        error = %dual_stack_error,
                        "dual-stack client endpoint unavailable, using IPv4 only"
                    );
                    Ok(endpoint)
                }
                Err(ipv4_failure) => {
                    let (ipv4_stage, ipv4_error) = match ipv4_failure {
                        EndpointSetupError::Bind(error) => ("bind", error),
                        EndpointSetupError::Setup(error) => ("setup", error),
                    };
                    tracing::warn!(
                        error = %dual_stack_error,
                        ipv4_stage,
                        ipv4_error = %ipv4_error,
                        "dual-stack and IPv4-only client endpoint setup failed"
                    );
                    Err(ipv4_error)
                }
            }
        }
    }
}

/// Builds a noq endpoint on a UDP socket bound at `local` (see [`udp_socket`]).
fn endpoint_on(
    local: SocketAddr,
    runtime: Arc<dyn noq::Runtime>,
) -> Result<noq::Endpoint, EndpointSetupError> {
    let socket = unbound_udp_socket(local).map_err(EndpointSetupError::Setup)?;
    socket
        .bind(&local.into())
        .map_err(EndpointSetupError::Bind)?;
    noq::Endpoint::new(noq::EndpointConfig::default(), None, socket.into(), runtime)
        .map_err(EndpointSetupError::Setup)
}

/// Binds a UDP socket at `local`. An IPv6 socket is made dual-stack: std's
/// UdpSocket can't clear IPV6_V6ONLY (set by default on Windows), and a v6-only
/// socket can't reach IPv4 relays, so the socket is built by hand for noq.
fn udp_socket(local: SocketAddr) -> std::io::Result<Socket> {
    let socket = unbound_udp_socket(local)?;
    socket.bind(&local.into())?;
    Ok(socket)
}

fn unbound_udp_socket(local: SocketAddr) -> std::io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(local), Type::DGRAM, Some(Protocol::UDP))?;
    if local.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    Ok(socket)
}

/// Whether the relay supplied the specified application close code.
fn refused_with(connection: &noq::Connection, code: u32) -> bool {
    matches!(
        connection.close_reason(),
        Some(noq::ConnectionError::ApplicationClosed(ref close))
            if close.error_code == noq::VarInt::from_u32(code)
    )
}

/// Runs the client side of the authorization handshake on an established
/// connection: present the token, answer the relay's challenge, and confirm the
/// acknowledgement.
async fn authorize(
    connection: &noq::Connection,
    identity: &Identity,
    cursors: &[(SlotId, u64)],
) -> Result<Link, DialError> {
    let (mut send, mut recv) = connection.open_bi().await?;

    // Present the token: a length-prefixed frame the relay reads in two reads.
    let frame = handshake::encode_token_frame(&identity.token)?;
    send.write_all(&frame).await?;

    // Answer the relay's connection-binding challenge by signing it — bound to
    // this connection's TLS channel — with the private key the token's embedded
    // public key commits to. The channel binding ties the proof to this session,
    // so a relay that forwards our token can't replay our signature elsewhere.
    let mut challenge = [0u8; CHALLENGE_LEN];
    recv.read_exact(&mut challenge).await?;
    let mut channel_binding = [0u8; CHANNEL_BINDING_LEN];
    connection
        .export_keying_material(&mut channel_binding, CHANNEL_BINDING_EXPORTER_LABEL, &[])
        .map_err(|_| DialError::ChannelBinding)?;
    let response = identity
        .signing_key
        .sign(&ConnectionChallenge(challenge).signed_message(&channel_binding));
    send.write_all(response.as_ref()).await?;

    // Present the resume cursors: a first dial passes none, so this is an empty
    // (zero-count) frame that asks the relay to replay nothing. A mid-game reconnect
    // passes the seq this client next needs from each peer slot, so the relay replays
    // only the turns it missed. Either way the relay reads this frame, so every dial
    // sends it to keep the handshake byte-aligned.
    let cursor_frame = handshake::encode_resume_cursors(cursors)?;
    send.write_all(&cursor_frame).await?;

    let request = handshake::EvidenceRequest {
        periodic: None,
        challenge,
        channel_binding,
        tenant: identity.token.claims.tenant.clone(),
        session: identity.token.claims.session,
        slot: identity.token.claims.slot,
        client_pubkey: identity.token.claims.client_pubkey,
    };
    if quic::supports_evidence(connection) {
        let evidence = identity.collect_evidence(request.clone()).await;
        let frame = handshake::encode_evidence_frame(evidence.as_ref())?;
        send.write_all(&frame).await?;
    }

    // The relay acknowledges only once our slot is routable.
    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await?;
    if ack[0] != handshake::HANDSHAKE_OK {
        return Err(DialError::UnexpectedAck);
    }

    let link = Link::new(connection.clone());
    if quic::supports_periodic_evidence(connection) {
        let task = identity.start_periodic(connection.clone(), send, recv, request);
        Ok(link.with_connection_task(task))
    } else {
        let _ = send.finish();
        Ok(link)
    }
}

/// Rewrites an IPv4 relay address to its IPv4-mapped IPv6 form when dialing
/// through a dual-stack IPv6 endpoint, which can only reach an IPv4 peer via the
/// mapped address. Every other combination — an IPv4 endpoint, an IPv6 target, or
/// an unknown local family — is left untouched, so a caller's own IPv4 endpoint
/// still dials IPv4 peers directly.
fn mapped_target(local: Option<SocketAddr>, relay_addr: SocketAddr) -> SocketAddr {
    match (local, relay_addr) {
        (Some(SocketAddr::V6(_)), SocketAddr::V4(v4)) => {
            SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
        }
        _ => relay_addr,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[tokio::test]
    async fn bind_on_port_uses_the_requested_port() {
        // Find a port the OS considers free, then request it explicitly. The
        // window between releasing the probe and binding it again is a real (if
        // tiny) chance for something else on the machine to take the port; a
        // failure here is that race, not a regression in the explicit-port bind.
        let probe = std::net::UdpSocket::bind("[::]:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let endpoint = ClientEndpoint::bind_on_port(rustls::RootCertStore::empty(), port).unwrap();
        assert_eq!(endpoint.endpoint().local_addr().unwrap().port(), port);

        // While that endpoint lives, the port is taken: a second request for it
        // must surface as a bind error, not silently bind somewhere else.
        assert!(matches!(
            ClientEndpoint::bind_on_port(rustls::RootCertStore::empty(), port),
            Err(EndpointError::Bind(_))
        ));
    }

    #[tokio::test]
    async fn failed_dual_stack_setup_falls_back_to_ipv4() {
        let runtime = noq::default_runtime().unwrap();
        let endpoint = endpoint_with_fallback(0, runtime, |local, runtime| {
            if local.is_ipv6() {
                Err(EndpointSetupError::Setup(
                    std::io::ErrorKind::InvalidInput.into(),
                ))
            } else {
                endpoint_on(local, runtime)
            }
        })
        .unwrap();
        assert!(endpoint.local_addr().unwrap().is_ipv4());
    }

    #[tokio::test]
    async fn failed_dual_stack_bind_does_not_fall_back() {
        let runtime = noq::default_runtime().unwrap();
        let result = endpoint_with_fallback(0, runtime, |local, runtime| {
            if local.is_ipv6() {
                Err(EndpointSetupError::Bind(
                    std::io::ErrorKind::AddrInUse.into(),
                ))
            } else {
                endpoint_on(local, runtime)
            }
        });
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn failed_ipv4_fallback_reports_its_own_error() {
        let runtime = noq::default_runtime().unwrap();
        for ipv4_bind_fails in [true, false] {
            let result = endpoint_with_fallback(0, runtime.clone(), |local, _| {
                if local.is_ipv6() {
                    Err(EndpointSetupError::Setup(
                        std::io::Error::from_raw_os_error(10022),
                    ))
                } else if ipv4_bind_fails {
                    Err(EndpointSetupError::Bind(std::io::Error::from_raw_os_error(
                        10048,
                    )))
                } else {
                    Err(EndpointSetupError::Setup(
                        std::io::Error::from_raw_os_error(10045),
                    ))
                }
            });
            assert_eq!(
                result.unwrap_err().raw_os_error(),
                Some(if ipv4_bind_fails { 10048 } else { 10045 })
            );
        }
    }

    #[tokio::test]
    async fn rebind_fresh_port_moves_to_a_new_port_on_the_same_address() {
        for local in [
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        ] {
            let endpoint = noq::Endpoint::client(local).unwrap();
            let endpoint = ClientEndpoint::from_endpoint(endpoint);
            let before = endpoint.endpoint().local_addr().unwrap();

            let after = endpoint.rebind_fresh_port().unwrap();
            assert_eq!(after.ip(), before.ip(), "rebinding keeps the local address");
            assert_ne!(after.port(), before.port(), "rebinding takes a new port");
            assert_eq!(endpoint.endpoint().local_addr().unwrap(), after);
        }
    }

    #[test]
    fn maps_ipv4_targets_only_when_dialing_from_an_ipv6_endpoint() {
        let v6_local: SocketAddr = (Ipv6Addr::UNSPECIFIED, 1234).into();
        let v4_local: SocketAddr = (Ipv4Addr::UNSPECIFIED, 1234).into();
        let v4_relay: SocketAddr = (Ipv4Addr::new(203, 0, 113, 7), 14_900).into();
        let v6_relay: SocketAddr = (Ipv6Addr::LOCALHOST, 14_900).into();

        // Dual-stack endpoint + IPv4 relay → reached via the IPv4-mapped form.
        let expected = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(203, 0, 113, 7).to_ipv6_mapped()),
            14_900,
        );
        assert_eq!(mapped_target(Some(v6_local), v4_relay), expected);

        // An IPv4 endpoint dials an IPv4 relay directly; an IPv6 relay is never
        // rewritten; an unknown local family is left alone.
        assert_eq!(mapped_target(Some(v4_local), v4_relay), v4_relay);
        assert_eq!(mapped_target(Some(v6_local), v6_relay), v6_relay);
        assert_eq!(mapped_target(None, v4_relay), v4_relay);
    }
}
