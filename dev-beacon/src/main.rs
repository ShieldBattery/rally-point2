//! A loopback stand-in for a region's ping endpoints, so latency-based region
//! ranking is exercisable without real infrastructure.
//!
//! A game client measures its latency to a region by pinging that region's
//! endpoints: a **UDP beacon** (the primary — send bytes, get the same bytes
//! back, time the round trip) and a **TCP fallback** (measure connect time when
//! the beacon path is blocked). `dev-beacon` simulates both on loopback so a full
//! sweep — client auto-ranking, the settings display, the matchmaker's latency
//! inputs — can be driven end-to-end with fake regions on one machine.
//!
//! Each `--listen <ip:port>=<delay_ms>` argument starts one listener at `ip:port`
//! with two halves:
//!
//! - A **UDP echo** that returns every datagram it receives to its sender
//!   verbatim, after waiting `delay_ms` — the same send-bytes-get-bytes-back shape
//!   as a GameLift ping beacon. Giving different listeners different delays makes
//!   fake regions have genuinely different measured RTTs on loopback. The sleep is
//!   per-datagram and spawned off the receive loop, so one slow echo never holds
//!   up the next datagram.
//! - A **TCP listener** on the same address that accepts a connection and
//!   immediately closes it, so the fallback path has a real endpoint to connect
//!   to. The configured delay **does not** apply to it: a TCP handshake completes
//!   in the kernel before `accept()` ever returns, so connect-time cannot be
//!   artificially delayed from user space — fallback *ranking* is therefore not
//!   exercisable on loopback, only that the fallback has something live to reach.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use color_eyre::eyre::{Context, Result, eyre};
use tokio::net::{TcpListener, UdpSocket};

/// The largest datagram the echo buffers. A ping beacon's datagrams are tiny
/// (tens of bytes), so this is generous headroom; anything larger is truncated to
/// this on echo, which no real ping ever hits.
const MAX_DATAGRAM: usize = 2048;

/// Loopback stand-in for per-region ping endpoints.
#[derive(Debug, Parser)]
#[command(name = "dev-beacon", version, about)]
struct Cli {
    /// A listener to run, as `<ip:port>=<delay_ms>` (e.g. `127.0.0.1:20000=10`).
    /// Repeatable — one per fake region — so a single process serves a whole dev
    /// region set. `delay_ms` is the artificial UDP echo delay; it does not affect
    /// the TCP listener.
    #[arg(long = "listen", value_name = "IP:PORT=DELAY_MS", value_parser = parse_listener)]
    listeners: Vec<Listener>,
}

/// One configured listener: where it binds and how long its UDP echo waits.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listener {
    /// The address both the UDP echo and the TCP listener bind.
    addr: SocketAddr,
    /// The artificial delay applied to each UDP echo (never the TCP accept).
    delay: Duration,
}

/// Parses a `<ip:port>=<delay_ms>` listener spec.
fn parse_listener(spec: &str) -> Result<Listener, String> {
    let (addr, delay) = spec
        .split_once('=')
        .ok_or_else(|| format!("expected <ip:port>=<delay_ms>, got {spec:?}"))?;
    let addr: SocketAddr = addr
        .parse()
        .map_err(|e| format!("invalid address {addr:?}: {e}"))?;
    let delay_ms: u64 = delay
        .parse()
        .map_err(|e| format!("invalid delay {delay:?}: {e}"))?;
    Ok(Listener {
        addr,
        delay: Duration::from_millis(delay_ms),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    init_tracing();

    let cli = Cli::parse();
    if cli.listeners.is_empty() {
        return Err(eyre!(
            "no --listen given; specify at least one <ip:port>=<delay_ms>"
        ));
    }

    // One UDP echo + one TCP listener per configured address. The process runs
    // until a task fails (a bind conflict) or it is signalled; there is no clean
    // shutdown — it is a dev tool that is killed when the dev stack stops.
    let mut tasks = tokio::task::JoinSet::new();
    for Listener { addr, delay } in cli.listeners {
        tracing::info!(%addr, delay_ms = delay.as_millis(), "dev-beacon listener starting");
        tasks.spawn(run_udp_echo(addr, delay));
        tasks.spawn(run_tcp_accept(addr));
    }

    while let Some(joined) = tasks.join_next().await {
        joined.context("a dev-beacon listener task panicked")??;
    }
    Ok(())
}

/// Binds `addr` for UDP and echoes every datagram back to its sender after
/// `delay`.
async fn run_udp_echo(addr: SocketAddr, delay: Duration) -> Result<()> {
    let socket = UdpSocket::bind(addr)
        .await
        .with_context(|| format!("binding UDP echo on {addr}"))?;
    udp_echo_loop(Arc::new(socket), delay).await
}

/// The UDP echo loop over an already-bound socket: receive a datagram, then spawn
/// a task that waits `delay` and sends the bytes back verbatim. The spawn is what
/// keeps a slow echo from blocking the next receive, so the delay shapes each
/// datagram's round trip independently rather than serializing them.
async fn udp_echo_loop(socket: Arc<UdpSocket>, delay: Duration) -> Result<()> {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (len, peer) = socket
            .recv_from(&mut buf)
            .await
            .context("receiving on the UDP echo socket")?;
        let datagram = buf[..len].to_vec();
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            if let Err(error) = socket.send_to(&datagram, peer).await {
                tracing::debug!(%peer, %error, "dropping a UDP echo that failed to send");
            }
        });
    }
}

/// Binds `addr` for TCP and closes each accepted connection immediately, so the
/// region's fallback target has something live to connect to. The configured
/// delay is deliberately not applied: the handshake completes in the kernel
/// before `accept()` returns, so connect-time cannot be delayed from here.
async fn run_tcp_accept(addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding TCP fallback on {addr}"))?;
    loop {
        let (stream, _peer) = listener
            .accept()
            .await
            .context("accepting on the TCP fallback listener")?;
        // Dropping the stream closes the connection at once — the accept-and-close
        // shape a connect-time probe measures.
        drop(stream);
    }
}

fn init_tracing() {
    use std::io::IsTerminal;

    use tracing_subscriber::{EnvFilter, fmt};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // Color only when stdout is a real terminal: container logs (docker, CloudWatch)
    // otherwise fill with raw ANSI escape sequences.
    fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stdout().is_terminal())
        .init();
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use super::*;

    #[test]
    fn parses_a_listener_spec() {
        assert_eq!(
            parse_listener("127.0.0.1:20000=150").unwrap(),
            Listener {
                addr: "127.0.0.1:20000".parse().unwrap(),
                delay: Duration::from_millis(150),
            },
        );
        assert!(parse_listener("127.0.0.1:20000").is_err(), "missing delay");
        assert!(parse_listener("not-an-addr=10").is_err(), "bad address");
        assert!(parse_listener("127.0.0.1:20000=abc").is_err(), "bad delay");
    }

    #[tokio::test]
    async fn udp_echo_returns_the_datagram_after_at_least_the_delay() {
        let server = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let delay = Duration::from_millis(120);
        tokio::spawn(udp_echo_loop(Arc::clone(&server), delay));

        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        client.connect(server_addr).await.unwrap();

        let payload = b"ping-abcdef";
        let start = Instant::now();
        client.send(payload).await.unwrap();
        let mut buf = [0u8; 64];
        let len = client.recv(&mut buf).await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(&buf[..len], payload, "the datagram is echoed verbatim");
        // Lower bound only — a loaded CI box may add arbitrary slack on top, but
        // the echo can never come back sooner than the configured delay.
        assert!(
            elapsed >= delay,
            "the echo waits at least the configured delay (elapsed {elapsed:?})",
        );
    }
}
