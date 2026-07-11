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

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rally_point_proto::handshake::{self, HandshakeError};
use rally_point_proto::ids::SlotId;
use rally_point_proto::token::{
    CHALLENGE_LEN, CHANNEL_BINDING_EXPORTER_LABEL, CHANNEL_BINDING_LEN, ConnectionChallenge,
};
use rally_point_transport::{Link, quic, quinn, rustls};
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

/// QUIC application close code the client uses when it abandons a dial because the
/// authorization exchange did not finish within the deadline.
const CONNECT_TIMEOUT_CLOSE: u32 = 0x01;

/// QUIC application close code the relay uses to refuse a re-dial whose slot has
/// already departed — a survivor's drop request was honored, or it left cleanly —
/// so the game has moved on without it. Mirrors the relay's `SLOT_DEPARTED_CLOSE` (a wire
/// contract); a client that sees it on a reconnect must stop retrying, since no
/// later dial can bring the slot back. Distinct from the relay's slot-taken close
/// (a still-live double-connect) and from any transport-level failure, both of
/// which are worth retrying.
const SLOT_DEPARTED_CLOSE: u32 = 0x06;

/// A QUIC client endpoint for dialing relays.
///
/// Holds the local UDP socket open for as long as its connections live, so a
/// caller keeps the endpoint alive for the duration of a session. One endpoint
/// can dial more than once (a relay's different address families, say, or a
/// re-dial after a drop).
pub struct ClientEndpoint {
    endpoint: quinn::Endpoint,
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
    Connect(#[from] quinn::ConnectError),
    /// The QUIC connection failed during the handshake — including the relay
    /// closing it because authorization was refused (an unknown or expired token,
    /// a bad challenge response, or the slot already taken).
    #[error("QUIC connection failed: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// Framing the authorization token for the wire failed.
    #[error("framing the authorization token failed: {0}")]
    Token(#[from] HandshakeError),
    /// Writing a handshake message to the relay failed.
    #[error("writing a handshake message failed: {0}")]
    Write(#[from] quinn::WriteError),
    /// Reading a handshake message from the relay failed.
    #[error("reading a handshake message failed: {0}")]
    Read(#[from] quinn::ReadExactError),
    /// The relay replied on the handshake stream with something other than its
    /// acknowledgement byte. A conforming relay never does this — it acknowledges
    /// or closes the connection — so this guards against a misbehaving peer.
    #[error("relay sent an unexpected handshake acknowledgement")]
    UnexpectedAck,
    /// The connection's TLS channel binding could not be derived, so the
    /// connection-binding proof can't be produced.
    #[error("deriving the connection's channel binding failed")]
    ChannelBinding,
    /// The dial did not finish within its deadline: the relay accepted the
    /// connection but stalled during the handshake instead of completing or
    /// rejecting it. The connection has been closed.
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
}

impl ClientEndpoint {
    /// Binds an ephemeral local UDP port, trusting `roots` to authenticate the
    /// relays it dials.
    ///
    /// The socket is dual-stack so this default constructor reaches the
    /// IPv6-primary, dual-stack relay deployment: IPv6 relays directly and IPv4
    /// ones via their IPv4-mapped form (handled in [`connect`](Self::connect)). A
    /// caller that needs a specific socket — a fixed port, an IPv4-only host, a
    /// shared endpoint — builds its own and uses
    /// [`from_endpoint`](Self::from_endpoint).
    ///
    /// Must be called from within a tokio runtime, which drives the endpoint.
    pub fn bind(roots: rustls::RootCertStore) -> Result<Self, EndpointError> {
        let config = quic::client_config(roots)?;

        // std's UdpSocket can't clear IPV6_V6ONLY (set by default on Windows), and
        // a v6-only socket can't reach IPv4 relays — so build the dual-stack socket
        // by hand and hand it to quinn.
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(false)?;
        let bind: SocketAddr = (Ipv6Addr::UNSPECIFIED, 0).into();
        socket.bind(&bind.into())?;

        let runtime = quinn::default_runtime().ok_or(EndpointError::NoRuntime)?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket.into(),
            runtime,
        )?;
        endpoint.set_default_client_config(config);
        Ok(Self { endpoint })
    }

    /// Wraps an endpoint the caller has already built and configured with a client
    /// config (a custom socket, or one shared across roles).
    pub fn from_endpoint(endpoint: quinn::Endpoint) -> Self {
        Self { endpoint }
    }

    /// The underlying QUIC endpoint.
    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }

    /// Dials `relay_addr`, runs the authorization handshake as `identity`, and
    /// returns the connection as a transport [`Link`] once the relay has
    /// acknowledged it as routable.
    ///
    /// `server_name` is the relay's TLS server name, checked against the
    /// certificate it presents. The relay re-sequences each outbound link onto one
    /// gapless transport-seq stream that muxes every slot, so the turns can be put
    /// back in order from that single sequence — but the datagrams carrying them can
    /// still arrive out of order, so doing that ordering is the job of the driver
    /// above the link ([`LinkDriver`](crate::LinkDriver)), not of this dial.
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
    /// so a relay that accepts the connection and then goes silent surfaces a
    /// bounded error instead of blocking the game-launch path indefinitely.
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

        // A fresh dial presents no resume cursors: the relay replays nothing.
        match timeout_at(deadline, authorize(&connection, identity, &[])).await {
            Ok(result) => result.map(|()| Link::new(connection)),
            Err(_elapsed) => {
                connection.close(
                    quinn::VarInt::from_u32(CONNECT_TIMEOUT_CLOSE),
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

        match timeout_at(deadline, authorize(&connection, identity, cursors)).await {
            Ok(Ok(())) => Ok(Link::new(connection)),
            Ok(Err(error)) => {
                // A read/write failure during the handshake may be the relay closing
                // the connection to refuse the re-dial. Prefer its application close
                // code, which names *why* — a departed slot is terminal — over the
                // transport-level error the failed I/O surfaced.
                if refused_as_departed(&connection) {
                    Err(DialError::SlotDeparted)
                } else {
                    Err(error)
                }
            }
            Err(_elapsed) => {
                connection.close(
                    quinn::VarInt::from_u32(CONNECT_TIMEOUT_CLOSE),
                    b"authorization timed out",
                );
                Err(DialError::TimedOut { timeout })
            }
        }
    }
}

/// Whether the relay closed `connection` with its slot-departed application code —
/// the terminal "the game moved on without you" refusal, as opposed to a live
/// double-connect refusal or any transport-level failure.
fn refused_as_departed(connection: &quinn::Connection) -> bool {
    matches!(
        connection.close_reason(),
        Some(quinn::ConnectionError::ApplicationClosed(ref close))
            if close.error_code == quinn::VarInt::from_u32(SLOT_DEPARTED_CLOSE)
    )
}

/// Runs the client side of the authorization handshake on an established
/// connection: present the token, answer the relay's challenge, and confirm the
/// acknowledgement.
async fn authorize(
    connection: &quinn::Connection,
    identity: &Identity,
    cursors: &[(SlotId, u64)],
) -> Result<(), DialError> {
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

    // The relay acknowledges only once our slot is routable.
    let mut ack = [0u8; 1];
    recv.read_exact(&mut ack).await?;
    if ack[0] != handshake::HANDSHAKE_OK {
        return Err(DialError::UnexpectedAck);
    }

    // Turns ride datagrams from here; the handshake stream has nothing more to say.
    let _ = send.finish();
    Ok(())
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
