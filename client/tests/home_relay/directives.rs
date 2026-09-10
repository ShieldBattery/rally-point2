//! The control-stream broadcasts alongside the turn path: lobby setup
//! commands, in-game chat (including its size cap and rate cap), and cosmetic
//! skin blobs. Each is relay-stamped with the authenticated author's slot and,
//! for lobby and skins, replayed to a client that joins after the fact.

use std::time::Duration;

use rally_point_proto::ids::{SessionId, SlotId};

use super::helpers::{
    KID, TENANT, client_endpoint, identity_for, make_tenant, registry_for, start_relay,
};

#[tokio::test]
async fn two_clients_exchange_lobby_commands_through_the_relay() {
    use rally_point_client::LinkDriver;

    // The full pre-game path through the real client transport: each client
    // authors lobby commands on its `lobby_out` seam, the driver sends them up
    // its control stream, the relay stamps the authoring slot and fans them down
    // the other member's control stream, and that driver surfaces them on
    // `lobby_in` tagged with the author's slot. The relay never parses the bytes.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(50);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver0, mut chan0) = LinkDriver::new(link0);
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let task0 = tokio::spawn(driver0.run());
    let task1 = tokio::spawn(driver1.run());

    // Host (slot 0) authors a lobby command; slot 1 receives it stamped slot 0.
    chan0.lobby_out.send(vec![0x0C, 1, 2, 3]).await.unwrap();
    let (author, bytes) = tokio::time::timeout(Duration::from_secs(5), chan1.lobby_in.recv())
        .await
        .expect("slot 1 never received the host's lobby command")
        .expect("driver 1 closed early");
    assert_eq!(author, SlotId(0));
    assert_eq!(bytes, vec![0x0C, 1, 2, 3]);

    // Slot 1 replies with its own; the host receives it stamped slot 1 — the
    // relay binds the author to the authenticated slot, never the wire value.
    chan1.lobby_out.send(vec![0x09, 0xAB]).await.unwrap();
    let (author, bytes) = tokio::time::timeout(Duration::from_secs(5), chan0.lobby_in.recv())
        .await
        .expect("the host never received slot 1's lobby command")
        .expect("driver 0 closed early");
    assert_eq!(author, SlotId(1));
    assert_eq!(bytes, vec![0x09, 0xAB]);

    drop(chan0.outbound);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}

#[tokio::test]
async fn a_lobby_command_is_replayed_to_a_late_joining_client() {
    use rally_point_client::LinkDriver;

    // A member dialing in after the host already sent its setup commands still
    // receives the whole sequence, in order — the relay's per-session replay log
    // catches it up before it tails live commands.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(51);

    // Only the host connects and authors its setup commands — before the peer
    // exists, so a plain fan-out would lose them.
    let id0 = identity_for(&tenant, session, SlotId(0));
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let (driver0, chan0) = LinkDriver::new(link0);
    let task0 = tokio::spawn(driver0.run());
    for command in [vec![0x01u8], vec![0x02], vec![0x03]] {
        chan0.lobby_out.send(command).await.unwrap();
    }
    // Let the driver send them up and the relay append them to its log.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The peer dials late and replays the whole sequence, in order, stamped with
    // the host's slot.
    let id1 = identity_for(&tenant, session, SlotId(1));
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let task1 = tokio::spawn(driver1.run());

    let mut got = Vec::new();
    while got.len() < 3 {
        let (author, bytes) = tokio::time::timeout(Duration::from_secs(5), chan1.lobby_in.recv())
            .await
            .expect("the late-joining peer's replay stalled")
            .expect("driver 1 closed early");
        assert_eq!(author, SlotId(0));
        got.push(bytes);
    }
    assert_eq!(got, vec![vec![0x01], vec![0x02], vec![0x03]]);

    drop(chan0.outbound);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}

#[tokio::test]
async fn a_game_chat_message_reaches_other_members_with_the_relay_stamped_slot() {
    use rally_point_client::{ChatOut, LinkDriver};

    // The full production path for in-game chat: a member authors a message on
    // its `chat_out` seam, the driver sends it up its control stream, the relay
    // stamps the authoring slot and fans it down every other member's control
    // stream, and each driver surfaces it on `chat_in` tagged with the author's
    // slot. Three members (A sends, B and C receive) proves the fan-out, and the
    // relay-stamp proof mirrors the lobby test: the driver always sends `slot: 0`
    // regardless of which client it's wrapping, so the different authoritative
    // slots each peer sees can only come from the relay's own stamp.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(60);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));
    let id2 = identity_for(&tenant, session, SlotId(2));
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let link2 = endpoint.connect(addr, "localhost", &id2).await.unwrap();
    let (driver0, mut chan0) = LinkDriver::new(link0);
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let (driver2, mut chan2) = LinkDriver::new(link2);
    let task0 = tokio::spawn(driver0.run());
    let task1 = tokio::spawn(driver1.run());
    let task2 = tokio::spawn(driver2.run());

    // Slot 0 sends an all-chat message; slots 1 and 2 both receive it, tagged
    // with the author's slot, and its scope fields pass through verbatim.
    chan0
        .chat_out
        .send(ChatOut {
            target_kind: 0,
            target_slot: 0,
            text: "gl hf".to_owned(),
        })
        .await
        .unwrap();
    for chan in [&mut chan1, &mut chan2] {
        let (author, msg) = tokio::time::timeout(Duration::from_secs(5), chan.chat_in.recv())
            .await
            .expect("member never received the chat message")
            .expect("driver closed early");
        assert_eq!(author, SlotId(0));
        assert_eq!(msg.target_kind, 0);
        assert_eq!(msg.target_slot, 0);
        assert_eq!(msg.text, "gl hf");
    }

    // Slot 1 replies with a targeted message; slot 0 receives it stamped slot 1
    // with the target fields preserved — the relay never interprets them.
    chan1
        .chat_out
        .send(ChatOut {
            target_kind: 3,
            target_slot: 2,
            text: "psst".to_owned(),
        })
        .await
        .unwrap();
    let (author, msg) = tokio::time::timeout(Duration::from_secs(5), chan0.chat_in.recv())
        .await
        .expect("slot 0 never received slot 1's message")
        .expect("driver 0 closed early");
    assert_eq!(author, SlotId(1));
    assert_eq!(msg.target_kind, 3);
    assert_eq!(msg.target_slot, 2);
    assert_eq!(msg.text, "psst");

    drop(chan0.outbound);
    drop(chan1.outbound);
    drop(chan2.outbound);
    let _ = task0.await;
    let _ = task1.await;
    let _ = task2.await;
}

#[tokio::test]
async fn an_oversize_game_chat_message_is_dropped_but_the_session_keeps_working() {
    use rally_point_client::{ChatOut, LinkDriver};

    // The relay's size cap drops an over-cap chat message without closing the
    // connection — the client driver enforces no cap of its own, so this proves
    // the relay is the one refusing it, and that a well-formed message right
    // after still gets through.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(61);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver0, chan0) = LinkDriver::new(link0);
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let task0 = tokio::spawn(driver0.run());
    let task1 = tokio::spawn(driver1.run());

    // 257 bytes: one past the relay's 256-byte cap.
    let oversize = "x".repeat(257);
    chan0
        .chat_out
        .send(ChatOut {
            target_kind: 0,
            target_slot: 0,
            text: oversize,
        })
        .await
        .unwrap();

    // A well-formed message right behind it still arrives — proving the
    // connection survived the drop rather than being closed.
    chan0
        .chat_out
        .send(ChatOut {
            target_kind: 0,
            target_slot: 0,
            text: "still here".to_owned(),
        })
        .await
        .unwrap();

    let (author, msg) = tokio::time::timeout(Duration::from_secs(5), chan1.chat_in.recv())
        .await
        .expect("the well-formed message following the oversize one never arrived")
        .expect("driver 1 closed early");
    assert_eq!(author, SlotId(0));
    assert_eq!(msg.text, "still here");

    // Confirm the oversize message was truly dropped, not just delayed: nothing
    // else is waiting.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), chan1.chat_in.recv())
            .await
            .is_err(),
        "the oversize message must never have been delivered"
    );

    drop(chan0.outbound);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}

#[tokio::test]
async fn a_burst_of_game_chat_past_the_rate_cap_is_dropped_then_recovers() {
    use rally_point_client::{ChatOut, LinkDriver};

    // The relay's per-slot rate cap allows a burst of 8, then drops further
    // messages until the token bucket refills (one token per 500ms) — proving
    // both the drop and the later recovery, with the session staying up
    // throughout.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(62);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver0, chan0) = LinkDriver::new(link0);
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let task0 = tokio::spawn(driver0.run());
    let task1 = tokio::spawn(driver1.run());

    let send = |text: &str| {
        let text = text.to_owned();
        let sender = chan0.chat_out.clone();
        async move {
            sender
                .send(ChatOut {
                    target_kind: 0,
                    target_slot: 0,
                    text,
                })
                .await
                .unwrap();
        }
    };

    // A burst of 9: the cap's burst size (8) plus one over.
    for i in 0..9u32 {
        send(&format!("msg{i}")).await;
    }

    // Exactly 8 arrive — the 9th was dropped by the relay's rate cap.
    let mut got = Vec::new();
    for _ in 0..8 {
        let (author, msg) = tokio::time::timeout(Duration::from_secs(5), chan1.chat_in.recv())
            .await
            .expect("expected message never arrived")
            .expect("driver 1 closed early");
        assert_eq!(author, SlotId(0));
        got.push(msg.text);
    }
    assert_eq!(
        got,
        (0..8).map(|i| format!("msg{i}")).collect::<Vec<_>>(),
        "only the first 8 of the burst were admitted"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), chan1.chat_in.recv())
            .await
            .is_err(),
        "the 9th message must have been dropped by the rate cap"
    );

    // After the refill interval (500ms/token) passes, the slot has budget again.
    tokio::time::sleep(Duration::from_millis(600)).await;
    send("recovered").await;
    let (author, msg) = tokio::time::timeout(Duration::from_secs(5), chan1.chat_in.recv())
        .await
        .expect("the post-refill message never arrived")
        .expect("driver 1 closed early");
    assert_eq!(author, SlotId(0));
    assert_eq!(msg.text, "recovered");

    drop(chan0.outbound);
    drop(chan1.outbound);
    let _ = task0.await;
    let _ = task1.await;
}

#[tokio::test]
async fn player_skins_reach_other_members_with_the_relay_stamped_slot() {
    use rally_point_client::LinkDriver;

    // The full production path for a cosmetic-skin broadcast: a member hands its
    // blob to its `skin_out` seam, the driver sends it up its control stream, the
    // relay stamps the authoring slot and fans it down every other member's
    // control stream, and each driver surfaces it on `skin_in` tagged with the
    // author's slot. Three members (A sends, B and C receive) proves the fan-out,
    // and the relay-stamp proof mirrors the chat/lobby tests: the driver always
    // sends `slot: 0` regardless of which client it wraps, so the different
    // authoritative slots each peer sees can only come from the relay's own stamp.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(63);

    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));
    let id2 = identity_for(&tenant, session, SlotId(2));
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let link2 = endpoint.connect(addr, "localhost", &id2).await.unwrap();
    let (driver0, chan0) = LinkDriver::new(link0);
    let (driver1, mut chan1) = LinkDriver::new(link1);
    let (driver2, mut chan2) = LinkDriver::new(link2);
    let task0 = tokio::spawn(driver0.run());
    let task1 = tokio::spawn(driver1.run());
    let task2 = tokio::spawn(driver2.run());

    // Slot 0 broadcasts its blob; slots 1 and 2 both receive it, tagged with the
    // author's slot, and the opaque bytes pass through verbatim.
    chan0
        .skin_out
        .send(vec![0xDE, 0xAD, 0xBE, 0xEF])
        .await
        .unwrap();
    for chan in [&mut chan1, &mut chan2] {
        let (author, bytes) = tokio::time::timeout(Duration::from_secs(5), chan.skin_in.recv())
            .await
            .expect("member never received the skin blob")
            .expect("driver closed early");
        assert_eq!(author, SlotId(0));
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    drop(chan0.outbound);
    drop(chan1.outbound);
    drop(chan2.outbound);
    let _ = task0.await;
    let _ = task1.await;
    let _ = task2.await;
}

#[tokio::test]
async fn a_player_skin_is_replayed_to_a_late_joining_client() {
    use rally_point_client::LinkDriver;

    // The load-bearing difference from chat: a member dialing in after other
    // members already broadcast their blobs still receives each one — the relay's
    // per-session latest-blob-per-slot map replays it on register. Two members
    // broadcast before the third joins; the third replays both, stamped with each
    // author's slot.
    let tenant = make_tenant(KID, TENANT);
    let (addr, ca) = start_relay(registry_for(&[&tenant]));
    let endpoint = client_endpoint(&ca);
    let session = SessionId(64);

    // Slots 0 and 1 connect and broadcast their blobs before the peer exists, so
    // a plain fan-out would lose them.
    let id0 = identity_for(&tenant, session, SlotId(0));
    let id1 = identity_for(&tenant, session, SlotId(1));
    let link0 = endpoint.connect(addr, "localhost", &id0).await.unwrap();
    let link1 = endpoint.connect(addr, "localhost", &id1).await.unwrap();
    let (driver0, chan0) = LinkDriver::new(link0);
    let (driver1, chan1) = LinkDriver::new(link1);
    let task0 = tokio::spawn(driver0.run());
    let task1 = tokio::spawn(driver1.run());
    chan0.skin_out.send(vec![0x00, 0xA0]).await.unwrap();
    chan1.skin_out.send(vec![0x01, 0xB1]).await.unwrap();
    // Let the drivers send them up and the relay store them in its map.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The peer dials late and replays both stored blobs, each stamped with its
    // author's slot (the replay is unordered — a map, not a sequence — so collect
    // and compare as a set).
    let id2 = identity_for(&tenant, session, SlotId(2));
    let link2 = endpoint.connect(addr, "localhost", &id2).await.unwrap();
    let (driver2, mut chan2) = LinkDriver::new(link2);
    let task2 = tokio::spawn(driver2.run());

    let mut got = Vec::new();
    while got.len() < 2 {
        let (author, bytes) = tokio::time::timeout(Duration::from_secs(5), chan2.skin_in.recv())
            .await
            .expect("the late-joining peer's replay stalled")
            .expect("driver 2 closed early");
        got.push((author, bytes));
    }
    got.sort_by_key(|(author, _)| author.0);
    assert_eq!(
        got,
        vec![(SlotId(0), vec![0x00, 0xA0]), (SlotId(1), vec![0x01, 0xB1]),],
    );

    drop(chan0.outbound);
    drop(chan1.outbound);
    drop(chan2.outbound);
    let _ = task0.await;
    let _ = task1.await;
    let _ = task2.await;
}
