//! Tests for the region ping loop: the nonce-matched echo measurement, the
//! median it reports, and the sweep that skips the relay's own region and
//! drops a region it could not measure.

use super::*;

/// Binds a loopback UDP socket that echoes back the first `limit` datagrams it
/// receives verbatim and drops the rest, so a test can force some attempts to
/// time out. Returns the bound `host:port` string `measure_region` resolves.
async fn spawn_echo(limit: usize) -> String {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let mut seen = 0usize;
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            seen += 1;
            if seen <= limit {
                let _ = socket.send_to(&buf[..len], peer).await;
            }
        }
    });
    addr.to_string()
}

/// Binds a loopback UDP socket that replies to every datagram with bytes that
/// can never byte-equal an 8-byte nonce (a shorter datagram), so every reply is
/// ignored as a mismatch and every attempt times out. Returns the `host:port`.
async fn spawn_wrong_length_responder() -> String {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 64];
        while let Ok((_len, peer)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&[0u8; 4], peer).await;
        }
    });
    addr.to_string()
}

#[test]
fn median_takes_the_middle_of_the_sorted_samples() {
    assert_eq!(median(&mut []), None);
    assert_eq!(median(&mut [42]), Some(42));
    assert_eq!(median(&mut [30, 10, 20]), Some(20));
    // Even count: the upper-middle element.
    assert_eq!(median(&mut [10, 20, 30, 40]), Some(30));
}

#[tokio::test]
async fn measure_region_returns_a_median_against_a_live_beacon() {
    let beacon = spawn_echo(usize::MAX).await;
    let rtt = measure_region(
        &beacon,
        5,
        Duration::from_millis(5),
        Duration::from_millis(500),
        SANITY_CAP,
    )
    .await
    .expect("a responsive beacon yields a median");
    assert!(
        rtt < 500,
        "a loopback round-trip is far under the timeout (got {rtt}ms)",
    );
}

#[tokio::test]
async fn a_reply_that_is_not_the_nonce_is_ignored() {
    let beacon = spawn_wrong_length_responder().await;
    let rtt = measure_region(
        &beacon,
        3,
        Duration::from_millis(5),
        Duration::from_millis(100),
        SANITY_CAP,
    )
    .await;
    assert_eq!(
        rtt, None,
        "a reply that doesn't byte-equal the nonce never counts as a sample",
    );
}

#[tokio::test]
async fn timed_out_attempts_are_excluded_from_the_median() {
    // The beacon answers only the first two attempts; the remaining three time
    // out. The median reflects the two live loopback replies, not the timed-out
    // attempts — were those counted, the median would sit near the timeout.
    let beacon = spawn_echo(2).await;
    let rtt = measure_region(
        &beacon,
        5,
        Duration::from_millis(5),
        Duration::from_millis(200),
        SANITY_CAP,
    )
    .await
    .expect("two successful attempts yield a median");
    assert!(
        rtt < 100,
        "the median reflects the two live replies, not the timed-out attempts (got {rtt}ms)",
    );
}

#[tokio::test]
async fn a_sweep_skips_the_relays_own_region() {
    // Pre-seed the own region's entry: if the sweep skips it, the entry is left
    // untouched; if it wrongly pinged it, the unreachable beacon would fail and
    // the entry would be dropped. The other region is measured normally.
    let other = spawn_echo(usize::MAX).await;
    let cache = RegionRttCache::new();
    cache.record(RegionId("self".to_owned()), 999);
    let targets = vec![
        RegionBeaconTarget {
            region: RegionId("self".to_owned()),
            // Never contacted, because the own region is skipped.
            beacon: "203.0.113.1:9".to_owned(),
        },
        RegionBeaconTarget {
            region: RegionId("other".to_owned()),
            beacon: other,
        },
    ];
    sweep_once(
        &targets,
        &cache,
        Some(&RegionId("self".to_owned())),
        3,
        Duration::from_millis(5),
        Duration::from_millis(300),
        SANITY_CAP,
    )
    .await;
    let snapshot = cache.snapshot();
    assert_eq!(
        snapshot.get(&RegionId("self".to_owned())),
        Some(&999),
        "the own region is skipped, its cache entry untouched",
    );
    assert!(
        snapshot.contains_key(&RegionId("other".to_owned())),
        "other regions are measured",
    );
}

#[tokio::test]
async fn a_sweep_with_no_successful_attempt_drops_the_region() {
    // A last-known value is dropped (absence), never left stale or zeroed, when
    // a sweep's every attempt fails to match a nonce.
    let beacon = spawn_wrong_length_responder().await;
    let cache = RegionRttCache::new();
    cache.record(RegionId("gone".to_owned()), 55);
    let targets = vec![RegionBeaconTarget {
        region: RegionId("gone".to_owned()),
        beacon,
    }];
    sweep_once(
        &targets,
        &cache,
        None,
        2,
        Duration::from_millis(5),
        Duration::from_millis(80),
        SANITY_CAP,
    )
    .await;
    assert!(
        !cache.snapshot().contains_key(&RegionId("gone".to_owned())),
        "a region with no successful sample is removed, not left at its old value",
    );
}
