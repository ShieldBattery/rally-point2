//! The game's rollback statistics going up the control stream: the newest
//! snapshot written as the game publishes it, the final one ahead of the leave
//! intent, and the newest re-sent on a reconnect's fresh stream.

use rally_point_proto::messages::RollbackStats;

use super::*;

/// A snapshot told apart from the others by the turn it runs through.
fn stats(through_turn: u32) -> RollbackStats {
    RollbackStats {
        version: 1,
        through_turn,
        ticks: through_turn * 2,
        rollback_histogram: vec![5, 3, 1],
        pipe_histogram: vec![0, 9],
        schedule_corrected_us: -12_000,
        ..Default::default()
    }
}

/// The turn a frame's snapshot runs through, failing the test on any other
/// frame.
fn through_turn(frame: ControlInbound) -> u32 {
    match frame {
        ControlInbound::RollbackStats(stats) => stats.through_turn,
        other => panic!("expected a rollback-stats frame, got {other:?}"),
    }
}

#[tokio::test]
async fn a_published_snapshot_is_written_up_the_control_stream_whole() {
    let mut fixture = DriverFixture::new().await;

    fixture.chan.rollback_stats.send_replace(Some(stats(720)));
    let frame = fixture
        .next_control_frame("the published snapshot never arrived")
        .await;
    let ControlInbound::RollbackStats(received) = frame else {
        panic!("expected a rollback-stats frame, got {frame:?}");
    };
    assert_eq!(received, stats(720), "every field survives the trip");

    fixture.finish().await;
}

#[tokio::test]
async fn the_final_snapshot_goes_out_ahead_of_the_leave_intent() {
    // The game publishes its final snapshot and signals its departure at once.
    // The relay stops reading at the intent, so whichever the driver services
    // first, the snapshot must be on the stream before it.
    let mut fixture = DriverFixture::new().await;

    fixture.chan.rollback_stats.send_replace(Some(stats(1_000)));
    fixture.chan.leave_intent.send(()).await.unwrap();

    let first = fixture
        .next_control_frame("the final snapshot never arrived")
        .await;
    assert_eq!(through_turn(first), 1_000);
    let second = fixture
        .next_control_frame("the leave intent never arrived")
        .await;
    assert!(
        matches!(second, ControlInbound::LeaveIntent),
        "expected the leave intent after the snapshot, got {second:?}",
    );

    fixture.finish().await;
}

#[tokio::test]
async fn the_newest_snapshot_is_re_sent_on_the_reconnects_control_stream() {
    // A write carries no acknowledgement, so the relay serving the next
    // connection is handed the newest snapshot again, and only the newest.
    let (mut sessions, chan) = ReconnectSessions::start().await;

    chan.rollback_stats.send_replace(Some(stats(720)));
    let frame = sessions
        .next_control_frame("the published snapshot never arrived")
        .await;
    assert_eq!(through_turn(frame), 720);

    let mut sessions = sessions.reconnect().await;
    let frame = sessions
        .next_control_frame("the snapshot was never re-sent")
        .await;
    assert_eq!(through_turn(frame), 720);

    // A snapshot published on the new connection follows as usual, and nothing
    // else was written in between.
    chan.rollback_stats.send_replace(Some(stats(1_440)));
    let frame = sessions
        .next_control_frame("the next snapshot never arrived")
        .await;
    assert_eq!(through_turn(frame), 1_440);

    drop(chan);
    let _ = sessions.session.await;
}
