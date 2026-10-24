//! Fair, bounded recovery work on a relay-pair link. Live turns keep their immediate path.

use std::collections::{HashMap, HashSet, VecDeque};
use std::ops::ControlFlow;

use rally_point_proto::messages::Payload;
use rally_point_transport::RECEIVE_WINDOW;

use crate::key::SessionKey;
use crate::session::turn_ring::{max_bytes, max_turns};

use super::conditions::snapshot_conditions;
use super::forward::send_turn_over_link;
use super::link_arms::LinkDriver;
use super::link_run::defer_flush_after_send;
use super::links::{LeaseAwait, MESH_STREAM_WRITE_TIMEOUT, MeshLinkExit, await_while_current};
use super::mesh_session_key;

const REPLAY_DISPATCH_LIMIT: usize = 16;
const REPLAY_IN_FLIGHT_LIMIT: usize = 256;

struct ReplayJob {
    pending: VecDeque<Payload>,
    // Keep emitted identities until the job drains: repeated asks cannot rewind a
    // partially sent snapshot. Its sent turns already belong to transport recovery.
    scheduled: HashSet<(u32, u64)>,
    command_bytes: usize,
    last_progress: tokio::time::Instant,
}

impl Default for ReplayJob {
    fn default() -> Self {
        Self {
            pending: VecDeque::new(),
            scheduled: HashSet::new(),
            command_bytes: 0,
            last_progress: tokio::time::Instant::now(),
        }
    }
}

/// Newest recorded turns usually close the small gap blocking a resumed client.
/// A ring is bounded across all slots, so one slot can still span more than a
/// receive window. Keep that snapshot's order: its newest turn would otherwise
/// move the peer's window past older retained turns before they were delivered.
fn prioritize_tail(payloads: &mut [Payload]) {
    let mut ranges = HashMap::<u32, (u64, u64)>::new();
    for payload in payloads.iter() {
        let (first, last) = ranges
            .entry(payload.slot)
            .or_insert((payload.seq, payload.seq));
        *first = (*first).min(payload.seq);
        *last = (*last).max(payload.seq);
        if *last - *first >= RECEIVE_WINDOW {
            return;
        }
    }
    payloads.reverse();
}

/// One snapshot per joined session, rotated after every payload. Repeated requests
/// add only previously unscheduled identities, including any widened requested range.
/// Each active job charges all distinct turns it has scheduled (emitted ones included)
/// against a full ring's count and command-byte limits. Exceeding either resets the
/// link instead of silently dropping recovery history or accumulating unbounded work.
#[derive(Default)]
pub(super) struct ReplayQueue {
    jobs: HashMap<SessionKey, ReplayJob>,
    order: VecDeque<SessionKey>,
}

impl ReplayQueue {
    pub(super) fn enqueue(
        &mut self,
        key: SessionKey,
        mut payloads: Vec<Payload>,
        prefer_recent: bool,
    ) -> Result<(), ()> {
        if payloads.is_empty() {
            return Ok(());
        }
        if prefer_recent {
            prioritize_tail(&mut payloads);
        }
        if !self.jobs.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        let job = self.jobs.entry(key).or_default();
        for payload in payloads {
            let identity = (payload.slot, payload.seq);
            if job.scheduled.contains(&identity) {
                continue;
            }
            let bytes = crate::session::payload_command_bytes(&payload);
            if job.scheduled.len() >= max_turns(0)
                || bytes > max_bytes(0).saturating_sub(job.command_bytes)
            {
                return Err(());
            }
            job.command_bytes += bytes;
            job.scheduled.insert(identity);
            job.pending.push_back(payload);
        }
        Ok(())
    }

    fn stalled(&self, now: tokio::time::Instant) -> bool {
        self.jobs
            .values()
            .any(|job| now.duration_since(job.last_progress) >= MESH_STREAM_WRITE_TIMEOUT)
    }

    fn has_ready(&self, eligible: impl Fn(&SessionKey) -> bool) -> bool {
        self.order.iter().any(eligible)
    }

    fn next(&mut self, eligible: impl Fn(&SessionKey) -> bool) -> Option<(SessionKey, Payload)> {
        for _ in 0..self.order.len() {
            let key = self.order.pop_front()?;
            if !eligible(&key) {
                self.order.push_back(key);
                continue;
            }
            let job = self.jobs.get_mut(&key).expect("queued replay job exists");
            job.last_progress = tokio::time::Instant::now();
            let payload = job.pending.pop_front().expect("queued replay job has work");
            if job.pending.is_empty() {
                self.jobs.remove(&key);
            } else {
                self.order.push_back(key.clone());
            }
            return Some((key, payload));
        }
        None
    }

    pub(super) fn remove(&mut self, key: &SessionKey) {
        self.jobs.remove(key);
        self.order.retain(|queued| queued != key);
    }
}

impl LinkDriver {
    pub(super) fn replay_ready(&self) -> bool {
        self.replays.has_ready(|key| {
            self.joined
                .get(&key.session)
                .is_some_and(|state| state.key == *key)
                && self.link.payloads_in_flight(mesh_session_key(key)) < REPLAY_IN_FLIGHT_LIMIT
        }) && self.lease.is_current()
    }

    /// Return to the receive/control loop after bounded work. The watermark limits
    /// redundancy selection cost while ACKs are in flight; it pauses recovery only,
    /// leaving live sends and the existing hard window cap unchanged.
    pub(super) async fn dispatch_replays(&mut self) -> ControlFlow<MeshLinkExit> {
        if self.replays.order.is_empty() {
            return ControlFlow::Continue(());
        }
        // Maintenance wakes this loop even while every replay is window-blocked.
        // Repeated asks cannot postpone the deadline: only emitted work advances it.
        if self.replays.stalled(tokio::time::Instant::now()) {
            tracing::warn!("mesh replay made no progress before its deadline; resetting link");
            return ControlFlow::Break(MeshLinkExit::ConnectionFailed);
        }
        for _ in 0..REPLAY_DISPATCH_LIMIT {
            if !self.lease.is_current() {
                return ControlFlow::Break(MeshLinkExit::Superseded);
            }
            let Some((key, payload)) = self.replays.next(|key| {
                self.joined
                    .get(&key.session)
                    .is_some_and(|state| state.key == *key)
                    && self.link.payloads_in_flight(mesh_session_key(key)) < REPLAY_IN_FLIGHT_LIMIT
            }) else {
                break;
            };
            let outgoing = snapshot_conditions(&self.conditions, &key);
            let carried = match await_while_current(
                &self.lease,
                send_turn_over_link(
                    &mut self.link,
                    &mut self.control_send,
                    &key,
                    payload,
                    outgoing,
                    "resume replay",
                ),
            )
            .await
            {
                LeaseAwait::Superseded => return ControlFlow::Break(MeshLinkExit::Superseded),
                LeaseAwait::Completed(None) => {
                    return ControlFlow::Break(MeshLinkExit::ConnectionFailed);
                }
                LeaseAwait::Completed(Some(carried)) => carried,
            };
            if let Some(state) = self.joined.get_mut(&key.session) {
                defer_flush_after_send(
                    &mut state.flush_deadline,
                    carried,
                    tokio::time::Instant::now(),
                );
            }
        }
        ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rally_point_proto::control::TenantId;
    use rally_point_proto::ids::SessionId;

    fn key(id: u64) -> SessionKey {
        SessionKey {
            tenant: TenantId("test".to_owned()),
            session: SessionId(id),
        }
    }

    fn turn(seq: u64) -> Payload {
        Payload {
            seq,
            ..Default::default()
        }
    }

    #[test]
    fn tail_priority_checks_sequence_span_per_slot() {
        let mut turns = vec![turn(10), turn(10 + RECEIVE_WINDOW - 1)];
        prioritize_tail(&mut turns);
        assert_eq!(turns[0].seq, 10 + RECEIVE_WINDOW - 1);

        // Count alone cannot detect a sparse range wider than the window.
        let mut turns = vec![turn(10), turn(10 + RECEIVE_WINDOW)];
        prioritize_tail(&mut turns);
        assert_eq!(turns[0].seq, 10);

        // Slots have independent sequence spaces; their absolute positions
        // need not be near one another, and bounds near u64::MAX cannot wrap.
        let mut turns = vec![
            turn(0),
            Payload {
                slot: 1,
                ..turn(u64::MAX)
            },
        ];
        prioritize_tail(&mut turns);
        assert_eq!(turns[0].slot, 1);
    }

    #[test]
    fn repeated_and_widened_requests_preserve_progress() {
        let mut queue = ReplayQueue::default();
        let k = key(1);
        queue
            .enqueue(k.clone(), vec![turn(10), turn(11)], true)
            .unwrap();
        assert_eq!(queue.next(|_| true).unwrap().1.seq, 11);
        queue
            .enqueue(k.clone(), vec![turn(9), turn(10), turn(11), turn(12)], true)
            .unwrap();
        queue
            .enqueue(k, vec![turn(9), turn(10), turn(11), turn(12)], true)
            .unwrap();
        assert_eq!(queue.next(|_| true).unwrap().1.seq, 10);
        assert_eq!(queue.next(|_| true).unwrap().1.seq, 12);
        assert_eq!(queue.next(|_| true).unwrap().1.seq, 9);
        assert!(queue.next(|_| true).is_none());
    }

    #[test]
    fn sessions_rotate_and_a_blocked_session_does_not_block_others() {
        let mut queue = ReplayQueue::default();
        queue
            .enqueue(key(1), vec![turn(0), turn(1), turn(2)], true)
            .unwrap();
        queue.enqueue(key(2), vec![turn(0), turn(1)], true).unwrap();
        assert_eq!(queue.next(|_| true).unwrap().0, key(1));
        assert_eq!(queue.next(|_| true).unwrap().0, key(2));
        assert_eq!(queue.next(|_| true).unwrap().0, key(1));
        assert_eq!(queue.next(|k| *k != key(1)).unwrap().0, key(2));
        assert!(!queue.has_ready(|k| *k != key(1)));
        assert!(queue.next(|k| *k != key(1)).is_none());
        assert_eq!(queue.next(|_| true).unwrap().1.seq, 0);
    }

    #[test]
    fn removal_matches_the_full_session_key_and_releases_progress() {
        let mut queue = ReplayQueue::default();
        let a = key(1);
        let b = SessionKey {
            tenant: TenantId("other".to_owned()),
            ..key(1)
        };
        queue
            .enqueue(a.clone(), vec![turn(0), turn(1)], true)
            .unwrap();
        queue.enqueue(b.clone(), vec![turn(0)], true).unwrap();
        queue.next(|k| *k == a).unwrap();
        queue.remove(&a);
        assert_eq!(queue.next(|_| true).unwrap().0, b);
        queue.enqueue(a.clone(), vec![turn(0)], true).unwrap();
        assert_eq!(queue.next(|_| true).unwrap().1.seq, 0);
    }

    #[test]
    fn count_bound_includes_already_emitted_identities() {
        let mut queue = ReplayQueue::default();
        let k = key(1);
        let count = max_turns(0) as u64;
        queue
            .enqueue(k.clone(), (0..count).map(turn).collect(), true)
            .unwrap();
        queue.next(|_| true).unwrap();
        queue.enqueue(k.clone(), vec![turn(0)], true).unwrap();
        assert!(queue.enqueue(k, vec![turn(count)], true).is_err());
    }

    #[test]
    fn byte_bound_includes_emitted_payloads_and_duplicates_cost_nothing() {
        let mut queue = ReplayQueue::default();
        let k = key(1);
        let payload = Payload {
            commands: vec![0; max_bytes(0)].into(),
            ..turn(1)
        };
        queue
            .enqueue(k.clone(), vec![turn(0), payload.clone()], true)
            .unwrap();
        queue.next(|_| true).unwrap();
        queue.enqueue(k.clone(), vec![payload], true).unwrap();
        assert!(
            queue
                .enqueue(
                    k,
                    vec![Payload {
                        commands: vec![0].into(),
                        ..turn(2)
                    }],
                    true
                )
                .is_err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_requests_cannot_keep_a_stalled_replay_alive() {
        let mut queue = ReplayQueue::default();
        let k = key(1);
        queue
            .enqueue(k.clone(), vec![turn(0), turn(1)], true)
            .unwrap();
        tokio::time::advance(MESH_STREAM_WRITE_TIMEOUT / 2).await;
        queue
            .enqueue(k.clone(), vec![turn(0), turn(1), turn(2)], true)
            .unwrap();
        assert!(!queue.stalled(tokio::time::Instant::now()));
        tokio::time::advance(MESH_STREAM_WRITE_TIMEOUT / 2).await;
        assert!(queue.stalled(tokio::time::Instant::now()));
        queue.next(|_| true).unwrap();
        assert!(!queue.stalled(tokio::time::Instant::now()));
        queue.remove(&k);
        tokio::time::advance(MESH_STREAM_WRITE_TIMEOUT).await;
        assert!(!queue.stalled(tokio::time::Instant::now()));
    }
}
