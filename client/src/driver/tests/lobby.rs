//! Lobby commands across reconnects: each authored command's origin seq, the
//! retention ceiling and the write pacing, the re-send of every retained command
//! on a fresh control stream, and the receiving side dropping a command the game
//! already has.

use rally_point_proto::messages::LobbyCommand;
use rally_point_transport::control::send_control_lobby;

use super::super::lobby::*;
use super::*;

/// The `(seq, payload)` of a lobby frame the driver wrote, failing the test on
/// any other frame.
fn authored(frame: ControlInbound) -> (Option<u64>, Vec<u8>) {
    match frame {
        ControlInbound::Lobby(command) => (command.seq, command.payload.to_vec()),
        other => panic!("expected a lobby command, got {other:?}"),
    }
}

#[test]
fn authored_commands_keep_the_whole_history_up_to_the_relays_log_ceiling() {
    // A relay that has seen none of an author's commands accepts only a
    // history starting at seq 0, so nothing is ever dropped from the front;
    // past the ceiling no relay could accept another, so the newest is refused.
    let mut outbox = LobbyOutbox::new(tokio::time::Instant::now());
    for _ in 0..rally_point_proto::lobby::LOG_MAX_COMMANDS {
        assert!(outbox.author(vec![0xB0]));
    }
    assert!(!outbox.author(vec![0xB1]), "past the log ceiling");
    let seqs: Vec<_> = outbox.retained().map(|command| command.seq).collect();
    assert_eq!(seqs.len(), rally_point_proto::lobby::LOG_MAX_COMMANDS);
    assert!(
        seqs.iter()
            .enumerate()
            .all(|(index, seq)| *seq == Some(index as u64)),
        "seqs climb from 0 with no gap",
    );

    let mut outbox = LobbyOutbox::new(tokio::time::Instant::now());
    assert!(outbox.author(vec![0; rally_point_proto::lobby::LOG_MAX_BYTES]));
    assert!(!outbox.author(vec![0]), "past the log's byte ceiling");
}

#[test]
fn the_pacer_bursts_half_the_relays_cap_then_refills_at_half_its_rate() {
    let start = tokio::time::Instant::now();
    let mut pacer = LobbyPacer::new(start);
    for _ in 0..PACE_BURST {
        assert!(pacer.try_take(start));
    }
    assert!(!pacer.try_take(start), "the burst is spent");
    assert_eq!(pacer.next_token_at(), start + PACE_REFILL);
    assert!(!pacer.try_take(start + PACE_REFILL - Duration::from_millis(1)));
    assert!(pacer.try_take(start + PACE_REFILL));
    assert!(!pacer.try_take(start + PACE_REFILL));
}

#[test]
fn receipts_drop_an_authors_repeat_but_never_an_unsequenced_command() {
    let mut receipts = LobbyReceipts::default();
    assert!(receipts.admit(SlotId(1), Some(0)));
    assert!(receipts.admit(SlotId(1), Some(1)));
    assert!(
        !receipts.admit(SlotId(1), Some(0)),
        "a replayed seq is dropped"
    );
    assert!(
        !receipts.admit(SlotId(1), Some(1)),
        "a repeated seq is dropped"
    );
    assert!(
        receipts.admit(SlotId(2), Some(0)),
        "each author has its own seq space",
    );
    assert!(receipts.admit(SlotId(1), Some(3)));
    assert!(
        receipts.admit(SlotId(1), Some(2)),
        "a command an author had to re-send can arrive after a later one",
    );
    assert!(!receipts.admit(SlotId(1), Some(2)));
    assert!(receipts.admit(SlotId(1), None));
    assert!(
        receipts.admit(SlotId(1), None),
        "a command with no seq has no identity to drop it by",
    );
}

#[tokio::test]
async fn every_retained_command_is_re_sent_in_order_on_the_reconnects_stream() {
    // The writes land on the first connection, which then dies: nothing tells
    // the driver whether the relay processed them, so the fresh stream carries
    // all of them again, under the seqs they first went out with, ahead of
    // anything authored afterwards.
    let (mut sessions, chan) = ReconnectSessions::start().await;

    chan.lobby_out.send(vec![0x01]).await.unwrap();
    chan.lobby_out.send(vec![0x02]).await.unwrap();
    for (seq, byte) in [(0, 0x01), (1, 0x02)] {
        let frame = sessions
            .next_control_frame("an authored lobby command never arrived")
            .await;
        assert_eq!(authored(frame), (Some(seq), vec![byte]));
    }

    let mut sessions = sessions.reconnect().await;
    // Authored as the new session comes up, possibly before its re-send has
    // run: it still follows the retained commands on the wire.
    chan.lobby_out.send(vec![0x03]).await.unwrap();
    for (seq, byte) in [(0, 0x01), (1, 0x02), (2, 0x03)] {
        let frame = sessions
            .next_control_frame("a retained lobby command was never re-sent")
            .await;
        assert_eq!(authored(frame), (Some(seq), vec![byte]));
    }

    drop(chan);
    let _ = sessions.session.await;
}

#[tokio::test]
async fn a_lobby_command_the_game_already_has_is_not_handed_over_again() {
    // The relay replays its whole log each time this client's stream
    // registers. A command this client already handed its game is dropped;
    // one without a seq (an older author) is always handed over.
    let mut fixture = DriverFixture::new().await;

    let command = |seq, byte| LobbyCommand {
        slot: 1,
        payload: vec![byte].into(),
        seq,
    };
    for frame in [
        command(Some(0), 0x01),
        command(Some(1), 0x02),
        command(Some(0), 0x01),
        command(Some(1), 0x02),
        command(Some(2), 0x03),
        command(None, 0x0F),
        command(None, 0x0F),
    ] {
        send_control_lobby(&mut fixture.peer_control, frame)
            .await
            .unwrap();
    }

    for byte in [0x01, 0x02, 0x03, 0x0F, 0x0F] {
        let (author, bytes) =
            tokio::time::timeout(Duration::from_secs(5), fixture.chan.lobby_in.recv())
                .await
                .expect("a new lobby command never reached the game")
                .expect("the lobby channel stays open");
        assert_eq!((author, bytes), (SlotId(1), vec![byte]));
    }
    // Every frame above was written before this check, on one ordered stream,
    // and the last two reached the game, so the repeats had already been read
    // and dropped by then.
    assert!(
        fixture.chan.lobby_in.try_recv().is_err(),
        "a repeated command must not reach the game",
    );

    fixture.finish().await;
}
