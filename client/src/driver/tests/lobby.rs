//! Lobby commands across reconnects: each authored command's origin seq, the
//! re-send of every retained command on a fresh control stream, and the
//! receiving side dropping a command the game already has.

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
fn authored_commands_take_climbing_seqs_and_the_oldest_leaves_past_the_cap() {
    let mut retention = LobbyRetention::default();
    let first = retention.author(vec![0xA0]);
    let second = retention.author(vec![0xA1]);
    assert_eq!((first.seq, second.seq), (Some(0), Some(1)));

    for _ in 0..LOBBY_RETENTION_CAP {
        retention.author(vec![0xB0]);
    }
    let seqs: Vec<_> = retention.retained().map(|command| command.seq).collect();
    assert_eq!(seqs.len(), LOBBY_RETENTION_CAP);
    // The two oldest left; the rest keep their seqs, so a relay still dedupes
    // whatever it already accepted among them.
    assert_eq!(seqs.first(), Some(&Some(2)));
    assert_eq!(seqs.last(), Some(&Some(LOBBY_RETENTION_CAP as u64 + 1)));
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
