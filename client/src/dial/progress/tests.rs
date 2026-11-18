//! The authorization progress record: what it reports as outstanding and the
//! timeline of finished steps a failed dial logs.

use super::*;

fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

#[test]
fn a_fresh_record_has_the_stream_outstanding_and_nothing_finished() {
    let dial_started = Instant::now();
    let progress = AuthorizeProgress::new_at(dial_started, dial_started + ms(812));

    assert_eq!(progress.quic_handshake, ms(812));
    assert_eq!(progress.outstanding, AuthorizeStep::OpenStream);
    assert_eq!(progress.completed().to_string(), "none");
}

#[test]
fn each_finished_step_is_timed_from_the_end_of_the_quic_handshake() {
    let dial_started = Instant::now();
    let handshake_done = dial_started + ms(300);
    let mut progress = AuthorizeProgress::new_at(dial_started, handshake_done);

    progress.advance_at(AuthorizeStep::SendToken, handshake_done);
    progress.advance_at(AuthorizeStep::AwaitChallenge, handshake_done + ms(1));
    progress.advance_at(
        AuthorizeStep::SendChallengeResponse,
        handshake_done + ms(41),
    );
    progress.advance_at(AuthorizeStep::SendResumeCursors, handshake_done + ms(42));
    progress.advance_at(AuthorizeStep::CollectEvidence, handshake_done + ms(42));
    progress.record_evidence(true);
    progress.advance_at(AuthorizeStep::SendEvidence, handshake_done + ms(1042));
    progress.advance_at(AuthorizeStep::AwaitAck, handshake_done + ms(1043));

    assert_eq!(progress.quic_handshake, ms(300));
    assert_eq!(progress.outstanding, AuthorizeStep::AwaitAck);
    assert_eq!(
        progress.outstanding.outstanding(),
        "waiting for the acknowledgement"
    );
    assert_eq!(
        progress.completed().to_string(),
        "stream opened +0ms, token sent +1ms, challenge received +41ms, \
         challenge response sent +42ms, resume cursors sent +42ms, \
         evidence collected +1042ms, evidence sent +1043ms",
    );
}

#[test]
fn steps_skipped_on_a_connection_without_evidence_stay_out_of_the_timeline() {
    let dial_started = Instant::now();
    let mut progress = AuthorizeProgress::new_at(dial_started, dial_started);

    progress.advance_at(AuthorizeStep::SendToken, dial_started);
    progress.advance_at(AuthorizeStep::AwaitChallenge, dial_started);
    progress.advance_at(AuthorizeStep::SendChallengeResponse, dial_started + ms(5));
    progress.advance_at(AuthorizeStep::SendResumeCursors, dial_started + ms(5));
    progress.advance_at(AuthorizeStep::AwaitAck, dial_started + ms(6));

    assert_eq!(
        progress.completed().to_string(),
        "stream opened +0ms, token sent +0ms, challenge received +5ms, \
         challenge response sent +5ms, resume cursors sent +6ms",
    );
}

#[test]
fn a_stall_before_the_challenge_reports_the_wait_for_it() {
    let dial_started = Instant::now();
    let mut progress = AuthorizeProgress::new_at(dial_started, dial_started + ms(90));

    progress.advance_at(AuthorizeStep::SendToken, dial_started + ms(90));
    progress.advance_at(AuthorizeStep::AwaitChallenge, dial_started + ms(91));

    assert_eq!(
        progress.outstanding.outstanding(),
        "waiting for the challenge"
    );
    assert_eq!(
        progress.completed().to_string(),
        "stream opened +0ms, token sent +1ms",
    );
}

#[test]
fn collection_that_supplied_nothing_reads_as_an_empty_frame() {
    let dial_started = Instant::now();
    let handshake_done = dial_started + ms(20);
    let mut progress = AuthorizeProgress::new_at(dial_started, handshake_done);
    for step in [
        AuthorizeStep::SendToken,
        AuthorizeStep::AwaitChallenge,
        AuthorizeStep::SendChallengeResponse,
        AuthorizeStep::SendResumeCursors,
        AuthorizeStep::CollectEvidence,
    ] {
        progress.advance_at(step, handshake_done + ms(5));
    }
    // The provider ran out of time, so the frame that follows carries nothing.
    progress.record_evidence(false);
    progress.advance_at(AuthorizeStep::SendEvidence, handshake_done + ms(1005));
    progress.advance_at(AuthorizeStep::AwaitAck, handshake_done + ms(1006));

    assert_eq!(
        progress.completed().to_string(),
        "stream opened +5ms, token sent +5ms, challenge received +5ms, \
         challenge response sent +5ms, resume cursors sent +5ms, \
         no evidence collected +1005ms, empty evidence frame sent +1006ms",
    );
}
