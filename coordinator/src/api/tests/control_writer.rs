//! The writer half: what it sends as a descriptor delta, the per-send stall
//! bound that tears down a relay which stops reading, and the drain mark's
//! generation fence.

use std::pin::Pin;
use std::task::{Context, Poll};

use super::*;

/// A session descriptor for `session` meshing the given peer relays — a compact
/// fixture for the descriptor-diff unit tests.
fn diff_descriptor(session: u64, peers: &[u64]) -> SessionDescriptor {
    SessionDescriptor {
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

#[test]
fn a_drain_mark_from_a_superseded_connection_cannot_mark_its_live_successor() {
    // A relay's stale connection can flush a `Draining` after the relay already
    // reconnected. The successor's enroll cleared the draining flag, and the
    // stale mark must not set it again: that would exclude a live, idle relay
    // from every new assignment until it re-enrolled once more. The live
    // connection runs its own drain exchange when its own `Draining` arrives.
    let reg = registry::new_registry();
    let hello = (RelaySpec {
        id: 1,
        region: None,
    })
    .hello();
    let stale_generation = registry::enroll(&reg, hello.clone());
    let current_generation = registry::enroll(&reg, hello);
    let setup = session::SessionSetup::new(reg, crate::tenant::new_store());

    let draining = || {
        registry::enrolled_relays(setup.registry())
            .into_iter()
            .find(|relay| relay.relay_id == RelayId(1))
            .expect("relay 1 is enrolled")
            .draining
    };

    assert!(
        !apply_drain_mark(&setup, RelayId(1), stale_generation),
        "a Draining from the superseded connection draws no ack",
    );
    assert!(
        !draining(),
        "the live successor stays eligible for new assignments",
    );

    // The current connection's own Draining does apply.
    assert!(apply_drain_mark(&setup, RelayId(1), current_generation));
    assert!(
        draining(),
        "the relay its own connection drained is excluded from new assignments",
    );
}
