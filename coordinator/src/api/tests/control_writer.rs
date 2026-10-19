//! The writer half: what it sends as a descriptor delta and the per-send stall
//! bound that tears down a relay which stops reading.

use std::pin::Pin;
use std::task::{Context, Poll};

use super::*;

/// A session descriptor for `session` meshing the given peer relays — a compact
/// fixture for the descriptor-diff unit tests.
fn diff_descriptor(session: u64, peers: &[u64]) -> SessionDescriptor {
    SessionDescriptor {
        lobby_policy: None,
        lobby_settled: false,
        rollback: false,
        finalized_drops: false,
        tenant: tenant_id(),
        session: SessionId(session),
        peers: peers
            .iter()
            .map(|&id| rally_point_proto::control::RelayPeer {
                relay_id: RelayId(id),
                relay_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 14900 + id as u16)),
                cert_der: vec![id as u8; 4],
                relay_addrs: vec![],
            })
            .collect(),
        bounds: BufferBounds::new(1, 6).unwrap(),
        authority_order: vec![],
        external_id: None,
        slot_refs: vec![],
        observer_slots: vec![],
        expected_slots: vec![],
        homed_slots: vec![],
        resumed: false,
        departed_slots: vec![],
        latency_estimate_ms: None,
        relay_regions: Vec::new(),
    }
}

#[test]
fn diff_reports_adds_removals_and_in_place_mutations() {
    // Baseline: sessions 1 and 2.
    let set = vec![diff_descriptor(1, &[2]), diff_descriptor(2, &[2])];
    let baseline = index_descriptors(&set);

    // The steady-state arm relies on the identity case: a coalesced wake that
    // nets to no change diffs to nothing, so the writer sends no frame.
    let (upserts, removals) = diff_descriptors(&baseline, &set);
    assert!(upserts.is_empty(), "an unchanged set produces no upserts");
    assert!(removals.is_empty(), "an unchanged set produces no removals");

    // Session 1 mutated in place (its peers change), session 2 removed, session
    // 3 added.
    let current = vec![diff_descriptor(1, &[9]), diff_descriptor(3, &[2])];
    let (upserts, removals) = diff_descriptors(&baseline, &current);

    let mut upsert_sessions: Vec<u64> = upserts.iter().map(|d| d.session.0).collect();
    upsert_sessions.sort_unstable();
    assert_eq!(
        upsert_sessions,
        vec![1, 3],
        "the mutated session and the added one are both upserts",
    );
    // The mutated session's upsert carries the new value, not the stale one.
    let one = upserts.iter().find(|d| d.session == SessionId(1)).unwrap();
    assert_eq!(one.peers[0].relay_id, RelayId(9));
    assert_eq!(
        removals,
        vec![DescriptorKey {
            tenant: tenant_id(),
            session: SessionId(2),
        }],
    );
}

/// A sink whose send never completes: `poll_ready` is always `Pending`, so the
/// frame is never even accepted. Stands in for a relay that stopped reading
/// while its socket stays open — the case the per-send stall bound exists for,
/// and one a real socket cannot be made to reproduce on demand.
struct StalledSink;

impl futures_util::Sink<Message> for StalledSink {
    type Error = axum::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Pending
    }

    fn start_send(self: Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
        unreachable!("poll_ready never admits a frame");
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Pending
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Pending
    }
}

#[tokio::test(start_paused = true)]
async fn a_send_that_never_completes_ends_the_connection_at_the_stall_bound() {
    // A relay that keeps heartbeating but stops reading refreshes the reader's
    // deadline forever, so only the writer's own fixed bound can end it. Under
    // a paused clock the deadline is exact rather than a margin to race.
    let bound = Duration::from_secs(30);
    let started = tokio::time::Instant::now();
    let keep_running = writer_send(
        &mut StalledSink,
        Message::Text("frame".into()),
        RelayId(1),
        bound,
        "test",
    )
    .await;

    assert!(
        !keep_running,
        "a send stalled past the bound ends the connection rather than waiting on it",
    );
    assert_eq!(
        started.elapsed(),
        bound,
        "the send is abandoned exactly at its own bound",
    );
}

/// A sink that accepts every frame at once and keeps it, so a test can read
/// back exactly what the writer sent.
#[derive(Default)]
struct RecordingSink(Vec<Message>);

impl futures_util::Sink<Message> for RecordingSink {
    type Error = axum::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        self.0.push(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

/// Runs relay 1's writer to its end with its reader already gone (the drain and
/// grant channels closed), optionally retiring the relay first, and returns
/// every frame it sent. The drain arm is polled ahead of the descriptor arm, so
/// a retirement here is seen first by an arm other than the descriptor one —
/// the same position a multi-thread runtime can put the reap or load-state arm
/// in when the retirement lands between two arms' polls.
async fn frames_sent_once_the_reader_is_gone(retire: bool) -> Vec<Message> {
    let state = state_with_relay_and_tenant();
    let (drain_tx, drain) = tokio::sync::mpsc::unbounded_channel();
    let (grants_tx, grants) = tokio::sync::mpsc::unbounded_channel();
    let mut sources = WriterSources::new(&state.setup, RelayId(1), &state.regions, drain, grants);
    drop((drain_tx, grants_tx));
    if retire {
        state.setup.forget_relay(RelayId(1));
    }
    let mut sink = RecordingSink::default();
    run_writer(
        &mut sink,
        &mut sources,
        RelayId(1),
        Duration::from_secs(5),
        rally_point_proto::version::ProtocolVersion::CURRENT,
    )
    .await;
    sink.0
}

#[tokio::test]
async fn a_retirement_seen_through_another_arm_still_closes_as_retired() {
    let frames = frames_sent_once_the_reader_is_gone(true).await;
    let Some(Message::Close(Some(close))) = frames.last() else {
        panic!("a retired relay's writer must end on a close, sent {frames:?}");
    };
    assert_eq!(
        close.code,
        rally_point_proto::version::CONTROL_CLOSE_RETIRED
    );
}

#[tokio::test]
async fn an_ending_without_a_retirement_sends_no_retired_close() {
    // A replaced subscription or a departed reader leaves the descriptor channel
    // open; the relay may well reconnect, so it must not be told it is retired.
    let frames = frames_sent_once_the_reader_is_gone(false).await;
    assert!(
        !frames
            .iter()
            .any(|frame| matches!(frame, Message::Close(_))),
        "an un-retired relay's connection ends without a close, sent {frames:?}",
    );
}
