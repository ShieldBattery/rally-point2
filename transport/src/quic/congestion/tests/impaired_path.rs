//! The heaviest turn stream over a slow, lossy path, through real QUIC connections: the controller
//! must deliver it at the path's own delay rather than queue it behind its window.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::time::sleep_until;

use crate::quic::{client_config, server_config};
use crate::test_util::self_signed;

/// Each direction's delay through the proxy: a 400 ms round trip.
const ONE_WAY: Duration = Duration::from_millis(200);

/// The share of server-to-client packets the proxy drops, in thousandths.
const DOWNLINK_LOSS_PER_MILLE: u64 = 100;

/// The turns a twelve-slot session's client receives each step: one from each of its eleven peers.
const TURNS_PER_STEP: usize = 11;

/// A step of the game's turn clock.
const STEP: Duration = Duration::from_millis(42);

/// The bytes of each turn datagram: a turn with its re-carried redundancy at the policy's budget.
const TURN_BYTES: usize = 450;

/// How long the stream runs, and how much of its start is left out of the measurement: long enough
/// for loss to drive an unfloored window to its minimum and for turns queued behind it to show.
const RUN: Duration = Duration::from_secs(6);
const WARM_UP: Duration = Duration::from_secs(2);

/// A UDP proxy between a client and `server`, delaying every packet by [`ONE_WAY`] and dropping
/// [`DOWNLINK_LOSS_PER_MILLE`] of the server's, from a fixed seed so every run loses the same
/// packets. Returns the address the client dials.
async fn impaired_proxy(server: SocketAddr) -> SocketAddr {
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let client_facing = Arc::new(UdpSocket::bind(bind).await.unwrap());
    let server_facing = Arc::new(UdpSocket::bind(bind).await.unwrap());
    server_facing.connect(server).await.unwrap();
    let address = client_facing.local_addr().unwrap();
    let client: Arc<Mutex<Option<SocketAddr>>> = Arc::default();

    {
        let (client_facing, server_facing, client) = (
            Arc::clone(&client_facing),
            Arc::clone(&server_facing),
            Arc::clone(&client),
        );
        tokio::spawn(async move {
            let mut buf = vec![0; 65_536];
            while let Ok((len, from)) = client_facing.recv_from(&mut buf).await {
                *client.lock().unwrap() = Some(from);
                let packet = buf[..len].to_vec();
                let server_facing = Arc::clone(&server_facing);
                let due = tokio::time::Instant::now() + ONE_WAY;
                tokio::spawn(async move {
                    sleep_until(due).await;
                    let _ = server_facing.send(&packet).await;
                });
            }
        });
    }
    tokio::spawn(async move {
        let mut buf = vec![0; 65_536];
        let mut random: u64 = 0x9e37_79b9_7f4a_7c15;
        while let Ok(len) = server_facing.recv(&mut buf).await {
            // xorshift64
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            if random % 1000 < DOWNLINK_LOSS_PER_MILLE {
                continue;
            }
            let Some(to) = *client.lock().unwrap() else {
                continue;
            };
            let packet = buf[..len].to_vec();
            let client_facing = Arc::clone(&client_facing);
            let due = tokio::time::Instant::now() + ONE_WAY;
            tokio::spawn(async move {
                sleep_until(due).await;
                let _ = client_facing.send_to(&packet, to).await;
            });
        }
    });
    address
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_heaviest_turn_stream_crosses_a_slow_lossy_path_at_the_paths_own_delay() {
    let (chain, key, ca) = self_signed();
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let server = noq::Endpoint::server(server_config(chain, key).unwrap(), bind).unwrap();
    let proxy = impaired_proxy(server.local_addr().unwrap()).await;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let client = noq::Endpoint::client(bind).unwrap();
    client.set_default_client_config(client_config(roots).unwrap());

    let accept = {
        let server = server.clone();
        tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() })
    };
    let receiver = client.connect(proxy, "localhost").unwrap().await.unwrap();
    let sender = accept.await.unwrap();

    // Each turn carries when it was sent, against a clock both ends of this process share.
    let epoch = Instant::now();
    let send = tokio::spawn(async move {
        let mut ticks = tokio::time::interval(STEP);
        while epoch.elapsed() < RUN {
            ticks.tick().await;
            for _ in 0..TURNS_PER_STEP {
                let mut turn = vec![0; TURN_BYTES];
                let sent_us = epoch.elapsed().as_micros() as u64;
                turn[..8].copy_from_slice(&sent_us.to_le_bytes());
                sender.send_datagram(turn.into()).unwrap();
            }
        }
        sender
    });

    let mut delays = Vec::new();
    let deadline = RUN + ONE_WAY * 10;
    while epoch.elapsed() < deadline {
        let Ok(Ok(turn)) =
            tokio::time::timeout(Duration::from_millis(500), receiver.read_datagram()).await
        else {
            continue;
        };
        let sent = Duration::from_micros(u64::from_le_bytes(turn[..8].try_into().unwrap()));
        if sent >= WARM_UP {
            delays.push(epoch.elapsed() - sent);
        }
        if sent >= RUN - STEP * 2 {
            break;
        }
    }
    let _sender = send.await.unwrap();

    let expected_turns = (RUN - WARM_UP).as_millis() / STEP.as_millis() * TURNS_PER_STEP as u128;
    assert!(
        delays.len() as u128 > expected_turns * 8 / 10,
        "only {} of about {expected_turns} measured turns arrived",
        delays.len(),
    );
    delays.sort_unstable();
    let p95 = delays[delays.len() * 95 / 100];
    assert!(
        p95 < ONE_WAY * 2,
        "95th percentile delivery took {p95:?} over a path delaying {ONE_WAY:?}",
    );
}
