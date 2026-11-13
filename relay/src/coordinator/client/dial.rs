//! Race resolved addresses through TCP and the WebSocket handshake.
use super::{ControlError, liveness::ControlTiming};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{net::SocketAddr, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite::handshake::client::Request};

/// Resolve the original host and race its addresses through the full upgrade.
pub(super) async fn connect(
    request: Request,
    timing: ControlTiming,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, SocketAddr), ControlError> {
    let uri = request.uri();
    let host = uri
        .host()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing coordinator host")
        })?
        .to_owned();
    let port = uri
        .port_u16()
        .unwrap_or(if uri.scheme_str() == Some("wss") {
            443
        } else {
            80
        });
    let resolved = timeout(
        timing.dns,
        tokio::net::lookup_host((host.trim_start_matches('[').trim_end_matches(']'), port)),
    )
    .await
    .map_err(|_| ControlError::Timeout("DNS"))
    .and_then(|result| result.map_err(ControlError::from));
    let addresses: Vec<SocketAddr> = resolved?.collect();
    if addresses.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "coordinator DNS returned no addresses",
        )
        .into());
    }
    connect_resolved(request, addresses, timing).await
}

/// Bound the combined TCP, TLS, and WebSocket upgrade race.
async fn connect_resolved(
    request: Request,
    addresses: Vec<SocketAddr>,
    timing: ControlTiming,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, SocketAddr), ControlError> {
    timeout(
        timing.dial,
        race(request, interleave(addresses), timing.stagger),
    )
    .await
    .map_err(|_| ControlError::Timeout("dial and handshake"))?
}

/// Stagger address attempts while preserving the request host for TLS and HTTP.
async fn race(
    request: Request,
    addresses: Vec<SocketAddr>,
    stagger: Duration,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, SocketAddr), ControlError> {
    let mut attempts = FuturesUnordered::new();
    for (index, address) in addresses.into_iter().enumerate() {
        let request = request.clone();
        attempts.push(async move {
            tokio::time::sleep(stagger.saturating_mul(index as u32)).await;
            let stream = TcpStream::connect(address).await?;
            let (socket, _) =
                tokio_tungstenite::client_async_tls_with_config(request, stream, None, None)
                    .await?;
            tracing::debug!(%address, "coordinator control connection dialed");
            Ok::<_, ControlError>((socket, address))
        });
    }
    let mut last_error = None;
    while let Some(result) = attempts.next().await {
        match result {
            Ok(socket) => return Ok(socket),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "coordinator DNS returned no addresses",
        )
        .into()
    }))
}

/// Alternate address families without disturbing their order within each family.
fn interleave(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first) = addresses.first() else {
        return addresses;
    };
    let first_v6 = first.is_ipv6();
    let (first, second): (Vec<_>, Vec<_>) =
        addresses.into_iter().partition(|a| a.is_ipv6() == first_v6);
    let mut first = first.into_iter();
    let mut second = second.into_iter();
    let mut result = Vec::new();
    loop {
        let a = first.next();
        let b = second.next();
        if a.is_none() && b.is_none() {
            break;
        }
        result.extend(a);
        result.extend(b);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    #[test]
    fn address_families_are_interleaved() {
        let input: Vec<SocketAddr> = ["[::1]:1", "[::2]:1", "127.0.0.1:1", "127.0.0.2:1"]
            .into_iter()
            .map(|a| a.parse().unwrap())
            .collect();
        let output = interleave(input.clone());
        assert_eq!(output, vec![input[0], input[2], input[1], input[3]]);
    }

    #[tokio::test]
    async fn ipv6_literal_resolves_and_dials() {
        let Ok(listener) = TcpListener::bind("[::1]:0").await else {
            return; // IPv6 loopback is not available on every host.
        };
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio_tungstenite::accept_async(socket).await.unwrap()
        });
        let request = format!("ws://{address}/relay/control")
            .into_client_request()
            .unwrap();
        let (_, selected) = connect(request, ControlTiming::default()).await.unwrap();
        assert_eq!(selected, address);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn stalled_upgrade_does_not_block_another_address() {
        let stalled = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let working = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addresses = vec![stalled.local_addr().unwrap(), working.local_addr().unwrap()];
        let server = tokio::spawn(async move {
            let (_socket, _) = stalled.accept().await.unwrap();
            let (socket, _) = working.accept().await.unwrap();
            let _ws = tokio_tungstenite::accept_async(socket).await.unwrap();
        });
        let request = "ws://localhost/relay/control"
            .into_client_request()
            .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            race(request, addresses, Duration::from_millis(25)),
        )
        .await;
        assert!(result.unwrap().is_ok());
        server.await.unwrap();
    }
}
