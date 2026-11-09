//! A noq runtime wrapper whose sockets leave every outgoing datagram's source
//! address to the OS.
//!
//! Once a client connection's handshake is confirmed, noq adopts the local IP
//! that incoming packets arrive on and pins every later send to it, which
//! noq-udp encodes as an `IP_PKTINFO`/`IPV6_PKTINFO` control message. Some
//! Windows network stacks (third-party filter drivers, presumably) reject every
//! send carrying that message with WSAEINVAL, so a connection whose handshake
//! got through goes silent right after it. The client endpoint owns a single
//! socket and never needs a pinned source, so the wrapper drops it and the OS
//! routes each datagram as it does any unconnected UDP send.
//!
//! The wrapping lives in the runtime because a noq endpoint keeps the runtime it
//! was built with and sets up every rebound socket through it, so every clone of
//! the endpoint and every rebind keeps the policy.

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use rally_point_transport::noq::udp::{RecvMeta, Transmit};
use rally_point_transport::noq::{AsyncTimer, AsyncUdpSocket, Runtime, UdpSender};

/// Wraps `runtime` so that no datagram sent through a socket it sets up names a
/// source address.
pub(crate) fn unpinned_source_runtime(runtime: Arc<dyn Runtime>) -> Arc<dyn Runtime> {
    Arc::new(UnpinnedSourceRuntime(runtime))
}

#[derive(Debug)]
struct UnpinnedSourceRuntime(Arc<dyn Runtime>);

impl Runtime for UnpinnedSourceRuntime {
    fn new_timer(&self, at: Instant) -> Pin<Box<dyn AsyncTimer>> {
        self.0.new_timer(at)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.0.spawn(future)
    }

    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Box<dyn AsyncUdpSocket>> {
        Ok(Box::new(UnpinnedSourceSocket(
            self.0.wrap_udp_socket(socket)?,
        )))
    }

    fn now(&self) -> Instant {
        self.0.now()
    }
}

#[derive(Debug)]
struct UnpinnedSourceSocket(Box<dyn AsyncUdpSocket>);

impl AsyncUdpSocket for UnpinnedSourceSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(UnpinnedSourceSender(self.0.create_sender()))
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        self.0.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.0.may_fragment()
    }
}

#[derive(Debug)]
struct UnpinnedSourceSender(Pin<Box<dyn UdpSender>>);

impl UdpSender for UnpinnedSourceSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let transmit = Transmit {
            src_ip: None,
            ..transmit.clone()
        };
        self.get_mut().0.as_mut().poll_send(&transmit, cx)
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        self.0.max_transmit_segments()
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
    use std::time::Duration;

    use socket2::{Domain, Protocol, Socket, Type};

    use super::*;

    /// A source address no host owns (TEST-NET-1). Pinned as a datagram's source,
    /// the OS either rejects the send or drops the datagram; it never delivers it.
    const UNOWNED_SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

    #[tokio::test]
    async fn sends_ignore_a_pinned_source_address() {
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Dual-stack and unbound to an address, as the client endpoint's socket is.
        let dual_stack = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        dual_stack.set_only_v6(false).unwrap();
        dual_stack
            .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())
            .unwrap();
        let runtime =
            unpinned_source_runtime(rally_point_transport::noq::default_runtime().unwrap());
        let socket = runtime.wrap_udp_socket(dual_stack.into()).unwrap();
        let local_port = socket.local_addr().unwrap().port();
        let mut sender = socket.create_sender();

        let transmit = Transmit {
            destination: SocketAddr::new(
                IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
                listener.local_addr().unwrap().port(),
            ),
            ecn: None,
            contents: b"ping",
            segment_size: None,
            src_ip: Some(UNOWNED_SOURCE.into()),
        };
        poll_fn(|cx| sender.as_mut().poll_send(&transmit, cx))
            .await
            .unwrap();

        let mut buf = [0u8; 8];
        let (len, from) = listener.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..len], b"ping");
        assert_eq!(from.port(), local_port);
    }
}
