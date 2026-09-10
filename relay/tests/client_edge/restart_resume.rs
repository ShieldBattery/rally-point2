//! Resume cursors on a reconnecting handshake: where the relay anchors the
//! replay, what it seeds from retained receipts, and the anchors it refuses.

use std::time::Duration;

use crate::helpers::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::Payload;
use rally_point_transport::{Link, noq};

/// The bottom-of-stream resume shape: a client loses its very first turn (seq
/// 0) while a later one (seq 1) reaches the relay, then reconnects. Its
/// resume anchor — the oldest unacked seq — is 0, and the anchor must still
/// be presented and honored: the fresh receive window's acked hole at seq 1
/// is closed from the relay's own forward-gate receipts, not by any re-send
/// (the client will never re-send an acked seq). Without the seed, the
/// window's contiguous prefix — and the ack-beacon cursor it drives — wedges
/// at 0 forever, no matter how far the live stream advances. This also pins
/// the pre-start case: nothing here starts the session, so the bounded
/// replay ring records nothing, and only the forward gate can seed.
#[tokio::test]
async fn a_cursor_zero_resume_seeds_the_acked_hole_from_the_forward_gate() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(322);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;

    // Slot 1's first connection delivers seq 1 and never seq 0 (lost on the
    // way to the relay). Waiting for the fan-out to slot 0 proves the relay
    // recorded seq 1 in its forward gate before the connection drops.
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    slot1
        .send(Some(Payload {
            seq: 1,
            slot: 0,
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = slot0.recv().await.unwrap().fresh;
    }
    assert_eq!(delivered[0].slot, 1);
    assert_eq!(delivered[0].seq, 1);
    slot1.connection().close(0u32.into(), b"dropped");

    // The reconnect presents the own-slot cursor at 0 — an anchor of 0 is a
    // real, meaningful cursor, not an omittable default.
    let slot1b = connect_slot_resuming(
        &endpoint,
        addr,
        &tenant,
        session,
        SlotId(1),
        &[(SlotId(1), 0)],
    )
    .await;
    let mut beacons =
        rally_point_transport::beacon::spawn_beacon_reader(slot1b.connection().clone());
    let mut slot1b = slot1b;

    // Replay the lost seq 0, then continue live past the acked hole at 1.
    for seq in [0u64, 2] {
        slot1b
            .send(Some(Payload {
                seq,
                slot: 0,
                commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
                ..Default::default()
            }))
            .unwrap();
    }

    // The relay's ack-beacon cursor for the slot must fold through the seeded
    // seq 1 and reach 2. A wedged window reports 0 forever — the beacon only
    // pushes on advance, so this times out instead of passing.
    let reached = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match beacons.recv().await {
                Some((SlotId(1), cursor)) if cursor >= 2 => break cursor,
                Some(_) => continue,
                None => panic!("the beacon stream ended before the cursor advanced"),
            }
        }
    })
    .await
    .expect("the resumed window's prefix must fold through the seeded receipt");
    assert_eq!(reached, 2);
}

/// The RELAY-SIDE integration of the lost-oversize-turn resume: oversize seq
/// 0 was written to the old connection's control stream but never reached the
/// relay, while datagram seq 1 was received. The reconnect anchors at 0 — the
/// oldest seq its restage will re-send — and the relay must both seed the
/// received seq 1 from its forward-gate receipts and accept the
/// control-stream retry of seq 0 as FRESH. An anchor at 1 (what the datagram
/// window alone would name — the oversize turn never entered it) has the
/// relay's dedup swallow the retry as a duplicate before fan-out,
/// permanently stranding every peer on seq 0.
///
/// This test supplies the anchor value and the retry directly, exercising
/// the relay half in full: the real handshake, receipt seeding, control
/// ingress, dedup, and fan-out. The client half — that a production
/// reconnect computes exactly this anchor, the min across both re-send
/// paths — is pinned by the driver's own
/// `same_relay_cursor_anchors_below_a_restaged_oversize_turn` unit test.
#[tokio::test]
async fn a_resume_anchored_below_a_lost_oversize_turn_forwards_its_control_retry() {
    use rally_point_transport::control::{ControlInbound, send_control_turn, spawn_control_reader};

    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(323);

    let mut slot0 = connect_slot(&endpoint, addr, &tenant, session, SlotId(0)).await;
    let mut ctrl0 = spawn_control_reader(slot0.connection().clone());

    // Datagram seq 1 reaches the relay; oversize seq 0 never does.
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    slot1
        .send(Some(Payload {
            seq: 1,
            slot: 0,
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    let mut delivered = Vec::new();
    while delivered.is_empty() {
        delivered = slot0.recv().await.unwrap().fresh;
    }
    assert_eq!(delivered[0].seq, 1);
    slot1.connection().close(0u32.into(), b"dropped");

    // The anchor a production reconnect computes for this shape: an emptied
    // datagram window (its client retires seq 1 on ack — not observed here;
    // the awaited fan-out above proves receipt, which is what the seeding
    // depends on) and an oldest retained oversize turn at 0 name cursor 0.
    let slot1b = connect_slot_resuming(
        &endpoint,
        addr,
        &tenant,
        session,
        SlotId(1),
        &[(SlotId(1), 0)],
    )
    .await;

    // The resume restages the oversize turn onto the fresh control stream.
    let (mut ctrl1_send, _unused_recv) = slot1b.connection().open_bi().await.unwrap();
    send_control_turn(
        &mut ctrl1_send,
        Payload {
            seq: 0,
            slot: 0,
            commands: vec![0x05u8; 2000].into(),
            game_frame_count: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // The retry is accepted as fresh and fanned to the peer's control stream
    // (oversize turns ride the reliable path end to end).
    let forwarded = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ctrl0
                .recv()
                .await
                .expect("slot 0's control stream stays open")
            {
                ControlInbound::OversizeTurn(payload) => break payload,
                _ => continue,
            }
        }
    })
    .await
    .expect("the restaged oversize turn must be forwarded, not deduped away");
    assert_eq!(forwarded.seq, 0);
    assert_eq!(forwarded.slot, 1, "bound to the authorized slot");
    assert_eq!(forwarded.commands.len(), 2000);
}

/// A never-started session's last-slot disconnect closes the session at once
/// but keeps the undecided drop hold — the token that admits a quick
/// reconnect. The receipts that reconnect's resume seeds from must survive
/// exactly as long as the token: here seq 1 was received and acked while seq
/// 0 was lost, the reconnect anchors at 0, and the relay must still close the
/// acked hole at 1 from receipts that outlived the emptied-session teardown.
#[tokio::test]
async fn a_held_reconnect_after_a_never_started_close_seeds_from_retained_receipts() {
    use rally_point_relay::consensus::{self, Authority};
    use rally_point_relay::routing::SessionKey;

    let tenant = make_tenant(KID, TENANT);
    let session = SessionId(324);

    // Descriptor-backed but never started: the maker exists, and the expected
    // set is never covered by slot 1 alone, so no session-start ever fires.
    let mesh = rally_point_relay::mesh::new_mesh_state();
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let _ = consensus::sync_maker(
        &mesh.decision_makers,
        &key,
        rally_point_proto::control::BufferBounds::new(0, 20).unwrap(),
        Authority::SelfRelay,
        std::collections::HashSet::new(),
        [SlotId(0), SlotId(1)].into_iter().collect(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    let (addr, ca) = start_relay_with_mesh(registry_for(&[&tenant]), mesh);
    let endpoint = client_endpoint(&ca);

    // Seq 1 reaches the relay (seq 0 is lost). Waiting for the ack — the
    // unacked window emptying — proves the relay received and recorded it.
    let mut slot1 = connect_slot(&endpoint, addr, &tenant, session, SlotId(1)).await;
    slot1
        .send(Some(Payload {
            seq: 1,
            slot: 0,
            commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
            ..Default::default()
        }))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while slot1.payloads_in_flight() > 0 {
            let _ = slot1.recv().await;
        }
    })
    .await
    .expect("the relay acks the received turn");
    slot1.connection().close(0u32.into(), b"dropped");

    // Give the relay time to process the disconnect: the departure marks the
    // drop hold and the never-started emptying runs its close — the teardown
    // that must retain the receipts. (Reconnecting faster would still work,
    // but by replacing the live seat rather than exercising the retention.)
    tokio::time::sleep(Duration::from_millis(300)).await;

    let slot1b = connect_slot_resuming(
        &endpoint,
        addr,
        &tenant,
        session,
        SlotId(1),
        &[(SlotId(1), 0)],
    )
    .await;
    let mut beacons =
        rally_point_transport::beacon::spawn_beacon_reader(slot1b.connection().clone());
    let mut slot1b = slot1b;

    // Replay the lost seq 0, then continue live past the acked hole at 1.
    for seq in [0u64, 2] {
        slot1b
            .send(Some(Payload {
                seq,
                slot: 0,
                commands: vec![0x0C, 1, 2, 3, 4, 5, 6, 7].into(),
                ..Default::default()
            }))
            .unwrap();
    }

    // The beacon cursor folds through the retained receipt at 1 and reaches
    // 2. If the teardown had destroyed the receipts, the prefix would wedge
    // at 0 forever and this times out.
    let reached = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match beacons.recv().await {
                Some((SlotId(1), cursor)) if cursor >= 2 => break cursor,
                Some(_) => continue,
                None => panic!("the beacon stream ended before the cursor advanced"),
            }
        }
    })
    .await
    .expect("the resumed window must fold through receipts retained past the close");
    assert_eq!(reached, 2);
}

/// A client presenting an absurd own-slot resume-cursor anchor (near the u64
/// ceiling) is refused outright rather than let that value become the dedup
/// window's base -- the real gate the transport-level saturating arithmetic
/// is only a backstop for. Task-isolated: only the presenting connection is
/// closed, never the relay itself.
#[tokio::test]
async fn an_absurd_resume_anchor_is_refused_not_applied() {
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(321);

    let client_key = keypair();
    let token = mint_token(&tenant, session, SlotId(0), client_key.public);
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    // The relay applies the anchor (and closes the connection over it) only
    // after the handshake ack -- but the close can race the ack's own
    // delivery, so this accepts either observable outcome: the handshake's
    // own read failing with the connection closed, or a successful handshake
    // followed by the closed connection on the first subsequent recv. Either
    // way, the load-bearing proof is the close code and reason below.
    let handshake_outcome =
        handshake(&connection, &token, &client_key, &[(SlotId(0), u64::MAX)]).await;

    if handshake_outcome.is_ok() {
        let mut link = Link::new(connection.clone());
        let _ = tokio::time::timeout(Duration::from_secs(2), link.recv()).await;
    }
    // `close_reason` reflects the local endpoint's own processed state, which
    // can lag slightly behind the read/write error already observed above;
    // poll briefly rather than risk a one-shot race.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let close = loop {
        if let Some(reason) = connection.close_reason() {
            break Some(reason);
        }
        if tokio::time::Instant::now() >= deadline {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    match close {
        Some(noq::ConnectionError::ApplicationClosed(close)) => {
            assert_eq!(
                close.error_code,
                noq::VarInt::from_u32(0x09),
                "closed with the dedicated resume-anchor-invalid code",
            );
        }
        other => panic!("expected the connection closed over the absurd anchor, got {other:?}"),
    }
}
