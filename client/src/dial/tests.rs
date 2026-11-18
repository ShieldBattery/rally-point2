//! Endpoint construction (explicit ports, the IPv4 fallback, rebinding), the
//! unpinned source address across a rebind, and IPv4-mapped dial targets.

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

/// Counts the sends that pass through its sockets, and those that name a
/// source address.
#[derive(Debug, Default)]
struct SendCounts {
    sent: std::sync::atomic::AtomicUsize,
    pinned: std::sync::atomic::AtomicUsize,
}

/// The tokio runtime, with each socket's sends counted into `counts`.
#[derive(Debug)]
struct CountingRuntime {
    counts: Arc<SendCounts>,
}

#[derive(Debug)]
struct CountingSocket {
    inner: Box<dyn noq::AsyncUdpSocket>,
    counts: Arc<SendCounts>,
}

#[derive(Debug)]
struct CountingSender {
    inner: std::pin::Pin<Box<dyn noq::UdpSender>>,
    counts: Arc<SendCounts>,
}

impl noq::Runtime for CountingRuntime {
    fn new_timer(&self, at: std::time::Instant) -> std::pin::Pin<Box<dyn noq::AsyncTimer>> {
        noq::TokioRuntime.new_timer(at)
    }

    fn spawn(&self, future: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>) {
        noq::TokioRuntime.spawn(future)
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<Box<dyn noq::AsyncUdpSocket>> {
        Ok(Box::new(CountingSocket {
            inner: noq::TokioRuntime.wrap_udp_socket(socket)?,
            counts: self.counts.clone(),
        }))
    }
}

impl noq::AsyncUdpSocket for CountingSocket {
    fn create_sender(&self) -> std::pin::Pin<Box<dyn noq::UdpSender>> {
        Box::pin(CountingSender {
            inner: self.inner.create_sender(),
            counts: self.counts.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [noq::udp::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl noq::UdpSender for CountingSender {
    fn poll_send(
        self: std::pin::Pin<&mut Self>,
        transmit: &noq::udp::Transmit<'_>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::sync::atomic::Ordering::Relaxed;
        let this = self.get_mut();
        let result = this.inner.as_mut().poll_send(transmit, cx);
        if result.is_ready() {
            this.counts.sent.fetch_add(1, Relaxed);
            if transmit.src_ip.is_some() {
                this.counts.pinned.fetch_add(1, Relaxed);
            }
        }
        result
    }
}

/// Runs one request/response exchange over a fresh stream, so packets flow
/// both ways on whatever socket the client endpoint holds.
async fn echo_round_trip(connection: &noq::Connection) {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(64).await.unwrap(), b"ping");
}

#[tokio::test]
async fn sends_stay_unpinned_after_a_rebind_through_an_endpoint_clone() {
    use rally_point_transport::quic::{client_config, server_config};
    use rally_point_transport::test_util::self_signed;
    use std::sync::atomic::Ordering::Relaxed;

    let (chain, key, ca) = self_signed();
    let server = noq::Endpoint::server(
        server_config(chain, key).unwrap(),
        (Ipv4Addr::LOCALHOST, 0).into(),
    )
    .unwrap();
    let server_addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            let request = recv.read_to_end(64).await.unwrap();
            send.write_all(&request).await.unwrap();
            send.finish().unwrap();
        }
    });

    let counts = Arc::new(SendCounts::default());
    let runtime = Arc::new(CountingRuntime {
        counts: counts.clone(),
    });
    let endpoint = ClientEndpoint::from_endpoint(unpinned_endpoint(0, runtime).unwrap());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let connection = endpoint
        .endpoint()
        .connect_with(
            client_config(roots).unwrap(),
            mapped_target(endpoint.endpoint().local_addr().ok(), server_addr),
            "localhost",
        )
        .unwrap()
        .await
        .unwrap();
    for _ in 0..3 {
        echo_round_trip(&connection).await;
    }

    // The reconnect path holds the endpoint through a handle made from a
    // clone of the underlying noq endpoint, and rebinds through that.
    let alias = ClientEndpoint::from_endpoint(endpoint.endpoint().clone());
    alias.rebind_fresh_port().unwrap();
    let sent_before_rebind = counts.sent.load(Relaxed);
    for _ in 0..3 {
        echo_round_trip(&connection).await;
    }

    assert!(
        counts.sent.load(Relaxed) > sent_before_rebind,
        "the rebound socket carried the later exchanges",
    );
    assert_eq!(
        counts.pinned.load(Relaxed),
        0,
        "no send named a source address"
    );
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
