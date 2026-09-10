//! Region handling end to end: a Hello's region tag is validated at enroll (an
//! untagged Hello always passes; an unrecognized tag — including any tag at all
//! when nothing is configured — is refused), every configured region's ping
//! beacon is pushed ahead of the first descriptor, and a heartbeat's reported
//! backbone round-trip is folded into the pair table the `/regions` endpoint
//! serves.

use std::time::Duration;

use rally_point_coordinator::regions::RegionsConfig;
use rally_point_coordinator::registry;
use rally_point_proto::control::{
    RegionBeaconTarget, RegionId, RegionRttReport, RelayToCoordinator,
};
use rally_point_proto::ids::RelayId;
use tokio::time::timeout;

use crate::common;
use crate::common::{
    connect_and_send_hello, expect_region_beacons, expect_tenant_keys, prove_identity,
    read_to_descriptors, relay_key,
};
use crate::helpers::*;

#[tokio::test]
async fn a_region_less_hello_enrolls_even_with_a_region_config() {
    // An untagged relay always enrolls — regions are for tagged relays; a
    // region-less hello is the dev/loopback and region-blind-fallback path.
    let (base_url, setup) = serve_coordinator_with_regions(two_region_config()).await;
    let mut socket = connect_and_send_hello(&base_url, relay_hello(9, 14909)).await;
    // Region validation passes (untagged), so the coordinator challenges before
    // enrolling; answer it, then the enrolled path proceeds — the tenant-key lead
    // followed by the descriptor re-sync, not a close.
    prove_identity(&mut socket, &relay_key(9)).await;
    let _ = read_to_descriptors(&mut socket).await;
    assert!(
        wait_for_enrollment(setup.registry(), RelayId(9)).await,
        "an untagged relay enrolls",
    );
}

#[tokio::test]
async fn a_valid_region_enrolls_and_lands_in_the_registry_entry() {
    let (base_url, setup) = serve_coordinator_with_regions(two_region_config()).await;
    let hello = relay_hello(9, 14909).with_region(RegionId("region-a".to_owned()));
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    // A configured region passes validation, so the coordinator challenges before
    // enrolling; answer it, then drain the initial descriptor re-sync.
    prove_identity(&mut socket, &relay_key(9)).await;
    let _ = timeout(Duration::from_secs(5), {
        use futures_util::StreamExt;
        socket.next()
    })
    .await;
    assert!(
        wait_for_enrollment(setup.registry(), RelayId(9)).await,
        "a relay in a configured region enrolls",
    );
    let entry = registry::entry(setup.registry(), RelayId(9)).expect("relay 9 enrolled");
    assert_eq!(
        entry.region,
        Some(RegionId("region-a".to_owned())),
        "the registry entry carries the enrolled region",
    );
}

#[tokio::test]
async fn an_unknown_region_is_refused_and_never_enrolled() {
    // A typo'd region tag is refused rather than silently serving nobody.
    let (base_url, setup) = serve_coordinator_with_regions(two_region_config()).await;
    let hello = relay_hello(9, 14909).with_region(RegionId("region-z".to_owned()));
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    expect_unknown_region_close(&mut socket, "region-z").await;
    assert!(
        registry::peer(setup.registry(), RelayId(9)).is_none(),
        "a relay tagged with an unknown region is never enrolled",
    );
}

#[tokio::test]
async fn any_region_is_refused_when_no_regions_are_configured() {
    // With no region config at all, a region tag is unrecognizable, so a tagged
    // relay is refused — the empty-config case of the unknown-region rule.
    let (base_url, setup) = serve_coordinator_with_regions(RegionsConfig::default()).await;
    let hello = relay_hello(9, 14909).with_region(RegionId("region-a".to_owned()));
    let mut socket = connect_and_send_hello(&base_url, hello).await;
    expect_unknown_region_close(&mut socket, "region-a").await;
    assert!(
        registry::peer(setup.registry(), RelayId(9)).is_none(),
        "with no region config a tagged relay is never enrolled",
    );
}

// --- Region ping-beacon distribution ---

#[tokio::test]
async fn the_region_beacon_set_is_pushed_before_the_first_descriptor() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // A coordinator with two configured regions and the test tenant enrolled. A
    // relay enrolls over a raw control socket so the test can read the exact
    // post-enroll frame order.
    let (base_url, _setup) = serve_coordinator_with_regions(two_region_config()).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(9, 14909))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    prove_identity(&mut socket, &relay_key(9)).await;

    // The tenant-key lead comes first; the region-beacon set follows it, still
    // ahead of any descriptor. Every configured region's beacon is pushed — the
    // relay filters its own later — in file order.
    let _ = expect_tenant_keys(&mut socket).await;
    let beacons = expect_region_beacons(&mut socket).await;
    assert_eq!(
        beacons,
        vec![
            RegionBeaconTarget {
                region: RegionId("region-a".to_owned()),
                beacon: "a:20000".to_owned(),
            },
            RegionBeaconTarget {
                region: RegionId("region-b".to_owned()),
                beacon: "b:20000".to_owned(),
            },
        ],
        "the beacon set names every configured region, in file order",
    );

    // The descriptor re-sync follows the beacon lead on the same connection.
    let descriptors = read_to_descriptors(&mut socket).await;
    assert!(descriptors.contains("\"type\":\"descriptors\""));
}

#[tokio::test]
async fn no_region_beacons_are_pushed_without_a_region_config() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    // A coordinator with no region config: the region-blind posture has no beacons
    // to measure, so the connect-time lead is the tenant keys followed directly by
    // the descriptor re-sync, with no region-beacons frame between them.
    let (base_url, _setup) = serve_coordinator_with_regions(RegionsConfig::default()).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    let hello = serde_json::to_string(&RelayToCoordinator::Hello(relay_hello(9, 14909))).unwrap();
    socket.send(Message::Text(hello.into())).await.unwrap();
    prove_identity(&mut socket, &relay_key(9)).await;

    // After the tenant-key lead, the very next frame is the descriptor re-sync — a
    // region-beacons frame interposed here would fail this assertion.
    let _ = expect_tenant_keys(&mut socket).await;
    let next = timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("the coordinator answers promptly")
        .expect("a frame arrives before the stream ends")
        .unwrap();
    let Message::Text(text) = next else {
        panic!("expected the descriptor re-sync, got {next:?}");
    };
    assert!(
        text.contains("\"type\":\"descriptors\""),
        "with no region config the descriptor re-sync directly follows the tenant keys, \
         with no region-beacons frame between: {text}",
    );
}

// --- Backbone RTT ingest + serve (end to end) ---

#[tokio::test]
async fn a_heartbeats_region_rtts_are_served_on_the_regions_endpoint() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // A coordinator with two configured regions. A relay enrolls in region-a and
    // heartbeats a measured round-trip to region-b; the coordinator folds it into the
    // pair table and serves it on GET /regions.
    let (base_url, _setup) = serve_coordinator_with_regions(two_region_config()).await;
    let ws_url = format!("{}/relay/control", base_url.replace("http://", "ws://"));
    let (mut socket, _resp) = tokio_tungstenite::connect_async(ws_url).await.unwrap();

    let hello = relay_hello(9, 14909).with_region(RegionId("region-a".to_owned()));
    let frame = serde_json::to_string(&RelayToCoordinator::Hello(hello)).unwrap();
    socket.send(Message::Text(frame.into())).await.unwrap();
    common::prove_identity(&mut socket, &relay_key(9)).await;
    // Drain the connect-time lead (tenant keys, region beacons, descriptor re-sync) so
    // the socket is not backpressured before the heartbeat is sent.
    let _ = read_to_descriptors(&mut socket).await;

    // Report a round-trip to region-b (the relay's own region-a is skipped by the pair
    // definition). The heartbeat is declarative, so one beat carries the whole set.
    let heartbeat = RelayToCoordinator::Heartbeat {
        roster_complete: true,
        sessions: vec![],
        region_rtts: vec![RegionRttReport {
            region: RegionId("region-b".to_owned()),
            rtt_ms: 87,
        }],
    };
    let beat = serde_json::to_string(&heartbeat).unwrap();
    socket.send(Message::Text(beat.into())).await.unwrap();

    // The ingest is asynchronous; poll GET /regions until the pair appears.
    let mut served = None;
    for _ in 0..100 {
        let json = get_regions_json(&base_url).await;
        if let Some(rtts) = json.get("backbone_rtts").and_then(|v| v.as_array())
            && !rtts.is_empty()
        {
            served = Some(json);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let json = served.expect("the reported pair is served on GET /regions");
    let rtts = json["backbone_rtts"].as_array().unwrap();
    assert_eq!(rtts.len(), 1);
    assert_eq!(rtts[0]["a"].as_str().unwrap(), "region-a");
    assert_eq!(rtts[0]["b"].as_str().unwrap(), "region-b");
    assert_eq!(rtts[0]["rtt_ms"].as_u64().unwrap(), 87);
    assert!(
        rtts[0].get("measured_at").is_some(),
        "each served pair carries its recorded age",
    );
}
