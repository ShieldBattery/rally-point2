use super::*;
use crate::test_support::session_key;

fn seconds(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[test]
fn accumulates_episodes_without_refilling_and_preserves_tenant_and_slot_isolation() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let other = session_key(2);
    let slot = SlotId(2);
    let now = Instant::now();
    assert!(budgets.start_outage(&key, slot, 9, now));
    assert!(budgets.start_outage(&key, slot, 9, now + seconds(10)));
    assert!(budgets.end_outage(&key, slot, 9, now + seconds(70)));
    assert!(!budgets.start_outage(&key, slot, 9, now + seconds(71)));
    assert!(budgets.start_outage(&key, slot, 3, now + seconds(100)));
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(200)),
        seconds(10)
    );
    assert_eq!(
        budgets.remaining(&key, SlotId(3), now + seconds(200)),
        seconds(180)
    );
    assert_eq!(
        budgets.remaining(&other, slot, now + seconds(200)),
        seconds(180)
    );
    assert!(budgets.exhausted(&key, slot, now + seconds(210)));
    assert!(budgets.exhausted(&key, slot, now + seconds(500)));
}

#[test]
fn reconnect_at_deadline_succeeds_and_settles_the_outage() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let slot = SlotId(1);
    let now = Instant::now();
    assert!(budgets.start_outage(&key, slot, 7, now));
    assert_eq!(
        budgets.try_reconnect(&key, slot, Some(7), now + seconds(180), || Ok::<_, ()>(42)),
        Ok(42),
    );
    assert!(budgets.snapshot(&key, now + seconds(180))[0].complete);
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(180)),
        Duration::ZERO
    );
}

#[test]
fn failed_admission_leaves_outage_running_and_success_settles_it() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let slot = SlotId(0);
    let now = Instant::now();
    assert!(budgets.start_outage(&key, slot, 8, now));
    assert_eq!(
        budgets.try_reconnect(&key, slot, Some(8), now + seconds(5), || Err::<(), _>("no")),
        Err(ReconnectError::Admission("no"))
    );
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(10)),
        seconds(170)
    );
    assert_eq!(
        budgets.try_reconnect(&key, slot, Some(8), now + seconds(10), || Ok::<_, ()>(42)),
        Ok(42)
    );
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(100)),
        seconds(170)
    );
    assert_eq!(
        budgets.try_reconnect(&key, slot, Some(8), now + seconds(11), || Ok::<_, ()>(())),
        Err(ReconnectError::StaleEpisode)
    );
}

#[test]
fn stale_generation_cannot_close_or_reconnect_a_new_outage() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let slot = SlotId(0);
    let now = Instant::now();
    assert!(budgets.start_outage(&key, slot, 55, now));
    assert!(!budgets.start_outage(&key, slot, 3, now));
    assert!(!budgets.end_outage(&key, slot, 3, now));
    assert_eq!(
        budgets.try_reconnect(&key, slot, Some(3), now, || Ok::<_, ()>(())),
        Err(ReconnectError::StaleEpisode)
    );
    assert!(budgets.end_outage(&key, slot, 55, now + seconds(5)));
    assert!(budgets.start_outage(&key, slot, 3, now + seconds(6)));
    assert!(!budgets.end_outage(&key, slot, 55, now + seconds(7)));
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(8)),
        seconds(173)
    );
}

#[test]
fn snapshots_merge_by_episode_and_completion_never_restarts() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let slot = SlotId(0);
    let now = Instant::now();
    let running = EpisodeSnapshot {
        slot,
        connection_epoch: 1,
        elapsed: seconds(20),
        complete: false,
    };
    budgets.merge(&key, &[running], now);
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(10)),
        seconds(150)
    );
    budgets.merge(&key, &[running], now + seconds(10));
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(15)),
        seconds(145)
    );
    budgets.merge(
        &key,
        &[EpisodeSnapshot {
            elapsed: seconds(40),
            complete: true,
            ..running
        }],
        now + seconds(15),
    );
    budgets.merge(&key, &[running], now + seconds(200));
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(210)),
        seconds(140)
    );
    assert!(budgets.snapshot(&key, now + seconds(210))[0].complete);
    budgets.merge(
        &key,
        &[EpisodeSnapshot {
            connection_epoch: 2,
            elapsed: seconds(50),
            complete: true,
            ..running
        }],
        now + seconds(210),
    );
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(210)),
        seconds(90)
    );
}

#[test]
fn conflicting_running_records_fail_closed_and_retire_is_session_scoped() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let other = session_key(2);
    let slot = SlotId(1);
    let now = Instant::now();
    let first = EpisodeSnapshot {
        slot,
        connection_epoch: 1,
        elapsed: seconds(10),
        complete: false,
    };
    let second = EpisodeSnapshot {
        connection_epoch: 2,
        ..first
    };
    budgets.merge(&key, &[first, second], now);
    budgets.merge(&other, &[first], now);
    assert_eq!(
        budgets.try_reconnect(&key, slot, Some(1), now, || Ok::<_, ()>(())),
        Err(ReconnectError::StaleEpisode)
    );
    budgets.retire(&key);
    assert!(budgets.snapshot(&key, now).is_empty());
    assert_eq!(budgets.snapshot(&other, now), vec![first]);
}

#[test]
fn racing_reconnects_can_complete_an_episode_only_once() {
    use std::sync::{Arc, Barrier};

    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let slot = SlotId(1);
    let now = Instant::now();
    assert!(budgets.start_outage(&key, slot, 2, now));
    let barrier = Arc::new(Barrier::new(3));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let registry = budgets.clone();
            let key = key.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                registry.try_reconnect(&key, slot, Some(2), now + seconds(5), || Ok::<_, ()>(()))
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(ReconnectError::StaleEpisode))
            .count(),
        1
    );
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(30)),
        seconds(175)
    );
}

#[test]
fn completion_does_not_charge_time_spent_in_transit() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let now = Instant::now();
    let slot = SlotId(2);
    let episode = EpisodeSnapshot {
        slot,
        connection_epoch: 7,
        elapsed: seconds(10),
        complete: false,
    };
    budgets.merge(&key, &[episode], now);
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(12)),
        seconds(158)
    );
    // The sender completed at 20 seconds, arriving two seconds later.
    budgets.merge(
        &key,
        &[EpisodeSnapshot {
            elapsed: seconds(20),
            complete: true,
            ..episode
        }],
        now + seconds(12),
    );
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(30)),
        seconds(160)
    );
    // A late projected running copy cannot inflate a completed episode.
    budgets.merge(
        &key,
        &[EpisodeSnapshot {
            elapsed: seconds(25),
            ..episode
        }],
        now + seconds(31),
    );
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(31)),
        seconds(160)
    );
    // A later completed measurement may still advance the reported floor.
    budgets.merge(
        &key,
        &[EpisodeSnapshot {
            elapsed: seconds(21),
            complete: true,
            ..episode
        }],
        now + seconds(32),
    );
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(32)),
        seconds(159)
    );
}

#[test]
fn configuration_requires_matching_snapshots_from_every_peer() {
    let budgets = DisconnectBudgets::default();
    let resumed = session_key(1);
    let fresh = session_key(2);
    let alone = session_key(3);
    let now = Instant::now();
    let slot = SlotId(3);
    let peers = [RelayId(11), RelayId(12)];
    budgets.configure_session(&resumed, true, &[slot], &[slot], &peers);
    let challenge = budgets.bootstrap_id(&resumed);
    assert_ne!(challenge, 0);
    assert!(budgets.merge_peer_snapshot(&resumed, peers[0], &[], now, 0));
    assert!(!budgets.is_synced(&resumed));
    assert!(budgets.merge_peer_snapshot(&resumed, peers[0], &[], now, challenge));
    assert!(!budgets.is_synced(&resumed));
    assert!(!budgets.merge_peer_snapshot(&resumed, RelayId(99), &[], now, challenge));
    assert!(budgets.merge_peer_snapshot(&resumed, peers[1], &[], now, challenge));
    assert!(budgets.is_synced(&resumed));
    assert_eq!(
        budgets.status(&resumed, now),
        vec![SlotBudgetStatus {
            slot,
            remaining: seconds(180),
            running: false
        }]
    );
    budgets.configure_session(&fresh, false, &[], &[], &[]);
    budgets.configure_session(&alone, true, &[], &[], &[]);
    assert!(budgets.is_synced(&fresh));
    assert!(!budgets.is_synced(&alone));
    assert_eq!(budgets.keys().len(), 3);
    budgets.retire(&resumed);
    assert!(!budgets.is_synced(&resumed));
    assert_eq!(budgets.keys().len(), 2);
}

#[test]
fn running_helpers_reflect_outages_and_ignore_other_sessions() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let other = session_key(2);
    let now = Instant::now();
    budgets.configure_session(
        &key,
        false,
        &[SlotId(0), SlotId(2)],
        &[SlotId(0), SlotId(2)],
        &[],
    );
    assert!(budgets.start_outage(&key, SlotId(2), 9, now));
    assert!(budgets.start_outage(&other, SlotId(1), 8, now));
    assert_eq!(budgets.running_epoch(&key, SlotId(2)), Some(9));
    assert_eq!(
        budgets.status(&key, now + seconds(2)),
        vec![
            SlotBudgetStatus {
                slot: SlotId(0),
                remaining: seconds(180),
                running: false
            },
            SlotBudgetStatus {
                slot: SlotId(2),
                remaining: seconds(178),
                running: true
            },
        ]
    );
    assert!(budgets.end_outage(&key, SlotId(2), 9, now + seconds(3)));
    assert_eq!(budgets.running_epoch(&key, SlotId(2)), None);
    assert!(!budgets.status(&key, now + seconds(3))[1].running);
}

#[test]
fn descriptor_change_requires_a_fresh_challenge_and_replies() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let now = Instant::now();
    let a = RelayId(1);
    let b = RelayId(2);
    budgets.configure_session(&key, true, &[], &[], &[a]);
    let old = budgets.bootstrap_id(&key);
    budgets.configure_session(&key, true, &[], &[], &[a, b]);
    let new = budgets.bootstrap_id(&key);
    assert_ne!(old, new);
    assert!(budgets.merge_peer_snapshot(&key, a, &[], now, old));
    assert!(budgets.merge_peer_snapshot(&key, b, &[], now, new));
    assert!(!budgets.is_synced(&key));
    assert!(budgets.merge_peer_snapshot(&key, a, &[], now, new));
    assert!(budgets.is_synced(&key));
}

#[test]
fn remote_running_projection_is_not_rebroadcast_and_completion_wins() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let now = Instant::now();
    let slot = SlotId(0);
    assert!(budgets.start_remote_outage(&key, slot, 7, now));
    assert_eq!(
        budgets.snapshot(&key, now + seconds(20))[0].elapsed,
        Duration::ZERO
    );
    let running = EpisodeSnapshot {
        slot,
        connection_epoch: 7,
        elapsed: seconds(10),
        complete: false,
    };
    budgets.merge(&key, &[running], now + seconds(20));
    assert_eq!(
        budgets.snapshot(&key, now + seconds(22))[0].elapsed,
        seconds(10)
    );
    budgets.merge(
        &key,
        &[EpisodeSnapshot {
            elapsed: seconds(12),
            complete: true,
            ..running
        }],
        now + seconds(25),
    );
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(50)),
        seconds(168)
    );
}

#[test]
fn completed_episodes_are_charged_at_least_one_whole_second_and_bounded() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let now = Instant::now();
    let slot = SlotId(0);
    for epoch in 0..180 {
        assert!(budgets.start_outage(&key, slot, epoch, now));
        assert!(budgets.end_outage(&key, slot, epoch, now + Duration::from_millis(1)));
    }
    assert_eq!(budgets.remaining(&key, slot, now), Duration::ZERO);
    for epoch in 180..1_000 {
        assert!(budgets.start_outage(&key, slot, epoch, now));
        assert_eq!(budgets.running_epoch(&key, slot), None);
        assert_eq!(
            budgets.try_reconnect(&key, slot, None, now, || Ok::<_, ()>(())),
            Ok(())
        );
        assert_eq!(budgets.remaining(&key, slot, now), Duration::ZERO);
    }
    assert_eq!(budgets.snapshot(&key, now).len(), 180);
}

#[test]
fn invalid_peer_snapshot_cannot_establish_baseline() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let now = Instant::now();
    let peer = RelayId(1);
    budgets.configure_session(&key, true, &[], &[SlotId(0)], &[peer]);
    let id = budgets.bootstrap_id(&key);
    let invalid = EpisodeSnapshot {
        slot: SlotId(2),
        connection_epoch: 1,
        elapsed: seconds(1),
        complete: true,
    };
    assert!(!budgets.merge_peer_snapshot(&key, peer, &[invalid], now, id));
    assert!(!budgets.is_synced(&key));
    assert!(budgets.snapshot(&key, now).is_empty());
}

#[test]
fn an_existing_relay_must_resync_before_serving_new_homes() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let now = Instant::now();
    let peer = RelayId(9);
    budgets.configure_session(&key, false, &[SlotId(0)], &[SlotId(0), SlotId(1)], &[peer]);
    assert!(budgets.is_synced(&key));
    budgets.configure_session(
        &key,
        true,
        &[SlotId(0), SlotId(1)],
        &[SlotId(0), SlotId(1)],
        &[peer],
    );
    assert!(!budgets.is_synced(&key));
    let challenge = budgets.bootstrap_id(&key);
    assert!(budgets.merge_peer_snapshot(&key, peer, &[], now, challenge));
    assert!(budgets.is_synced(&key));
}

#[test]
fn pending_baseline_is_rechecked_inside_reconnect_guard() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let slot = SlotId(0);
    let now = Instant::now();
    budgets.configure_session(&key, true, &[slot], &[slot], &[RelayId(4)]);
    assert_eq!(
        budgets.try_reconnect(&key, slot, None, now, || -> Result<(), ()> {
            panic!("admission must not run while the baseline is unknown")
        }),
        Err(ReconnectError::Unsynced),
    );
}

#[test]
fn checkpoints_require_each_current_peer_and_ignore_stale_acknowledgements() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let a = RelayId(1);
    let b = RelayId(2);
    let outsider = RelayId(3);
    budgets.configure_session(&key, false, &[], &[], &[a, b]);
    let first = budgets.begin_checkpoint(&key).unwrap();
    let second = budgets.begin_checkpoint(&key).unwrap();
    assert_ne!(first, second);
    budgets.acknowledge_checkpoint(&key, a, first);
    budgets.acknowledge_checkpoint(&key, a, first);
    budgets.acknowledge_checkpoint(&key, outsider, first);
    budgets.acknowledge_checkpoint(&key, b, second);
    assert!(!budgets.is_checkpoint_complete(&key, first));
    assert!(!budgets.is_checkpoint_complete(&key, second));
    assert!(budgets.is_synced(&key));
    budgets.acknowledge_checkpoint(&key, b, first);
    assert!(budgets.is_checkpoint_complete(&key, first));
    budgets.finish_checkpoint(&key, first);
    budgets.acknowledge_checkpoint(&key, a, first);
    assert!(!budgets.is_checkpoint_complete(&key, first));
    budgets.acknowledge_checkpoint(&key, a, second);
    assert!(budgets.is_checkpoint_complete(&key, second));
}

#[test]
fn checkpoint_tracks_peer_changes_and_empty_sets() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let a = RelayId(1);
    let b = RelayId(2);
    budgets.configure_session(&key, false, &[], &[], &[a, b]);
    let id = budgets.begin_checkpoint(&key).unwrap();
    budgets.acknowledge_checkpoint(&key, a, id);
    budgets.configure_session(&key, false, &[], &[], &[a]);
    assert!(budgets.is_checkpoint_complete(&key, id));
    budgets.configure_session(&key, false, &[], &[], &[a, b]);
    assert!(!budgets.is_checkpoint_complete(&key, id));
    budgets.acknowledge_checkpoint(&key, b, id);
    assert!(budgets.is_checkpoint_complete(&key, id));
    budgets.configure_session(&key, false, &[], &[], &[]);
    let local = budgets.begin_checkpoint(&key).unwrap();
    assert!(budgets.is_checkpoint_complete(&key, local));
    budgets.retire(&key);
    assert!(!budgets.is_checkpoint_complete(&key, local));
}

#[test]
fn unsynced_sessions_cannot_begin_or_complete_a_checkpoint() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let peer = RelayId(1);
    budgets.configure_session(&key, false, &[SlotId(0)], &[SlotId(0), SlotId(1)], &[peer]);
    let id = budgets.begin_checkpoint(&key).unwrap();
    budgets.acknowledge_checkpoint(&key, peer, id);
    assert!(budgets.is_checkpoint_complete(&key, id));
    budgets.configure_session(
        &key,
        true,
        &[SlotId(0), SlotId(1)],
        &[SlotId(0), SlotId(1)],
        &[peer],
    );
    assert!(!budgets.is_checkpoint_complete(&key, id));
    assert!(budgets.begin_checkpoint(&key).is_none());
}

#[test]
fn prior_home_does_not_ack_a_completion_until_assignment_changes() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let now = Instant::now();
    let slot = SlotId(0);
    let peer = RelayId(1);
    budgets.configure_session(&key, false, &[slot], &[slot], &[peer]);
    assert!(budgets.start_outage(&key, slot, 7, now));
    let completion = EpisodeSnapshot {
        slot,
        connection_epoch: 7,
        elapsed: seconds(5),
        complete: true,
    };
    assert!(!budgets.merge_peer_snapshot(&key, peer, &[completion], now + seconds(10), 0));
    budgets.configure_session(&key, true, &[], &[slot], &[peer]);
    assert!(budgets.merge_peer_snapshot(&key, peer, &[completion], now + seconds(10), 0));
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(20)),
        seconds(175)
    );
}

#[test]
fn sequential_rehomes_checkpoint_the_inherited_elapsed_without_refunds() {
    let first = DisconnectBudgets::default();
    let second = DisconnectBudgets::default();
    let third = DisconnectBudgets::default();
    let observer = DisconnectBudgets::default();
    let key = session_key(1);
    let slot = SlotId(0);
    let now = Instant::now();
    first.configure_session(&key, false, &[slot], &[slot], &[]);
    assert!(first.start_outage(&key, slot, 7, now));
    let first_checkpoint = first.snapshot(&key, now + seconds(10));
    assert_eq!(first_checkpoint[0].elapsed, seconds(10));
    second.configure_session(&key, false, &[slot], &[slot], &[]);
    second.merge(&key, &first_checkpoint, now + seconds(10));
    observer.configure_session(&key, false, &[], &[slot], &[]);
    observer.merge(&key, &first_checkpoint, now + seconds(10));
    assert_eq!(
        observer.snapshot(&key, now + seconds(40))[0].elapsed,
        seconds(10)
    );
    let second_checkpoint = second.snapshot(&key, now + seconds(40));
    assert_eq!(second_checkpoint[0].elapsed, seconds(40));
    third.configure_session(&key, false, &[slot], &[slot], &[]);
    third.merge(&key, &second_checkpoint, now + seconds(40));
    let third_checkpoint = third.snapshot(&key, now + seconds(70));
    assert_eq!(third_checkpoint[0].elapsed, seconds(70));
    // A delayed lower completion cannot roll back a measurement a home shared.
    third.merge(
        &key,
        &[EpisodeSnapshot {
            complete: true,
            elapsed: seconds(10),
            ..third_checkpoint[0]
        }],
        now + seconds(70),
    );
    assert_eq!(third.remaining(&key, slot, now + seconds(80)), seconds(110));
}

#[test]
fn checkpoint_advertisement_preserves_rounded_millisecond_floor() {
    let budgets = DisconnectBudgets::default();
    let key = session_key(1);
    let slot = SlotId(0);
    let now = Instant::now();
    budgets.configure_session(&key, false, &[slot], &[slot], &[]);
    assert!(budgets.start_remote_outage(&key, slot, 1, now));
    let sent = budgets.snapshot(&key, now + Duration::from_micros(1));
    assert_eq!(sent[0].elapsed, Duration::from_millis(1));
    budgets.merge(
        &key,
        &[EpisodeSnapshot {
            elapsed: Duration::ZERO,
            complete: true,
            ..sent[0]
        }],
        now + Duration::from_micros(1),
    );
    assert_eq!(
        budgets.remaining(&key, slot, now + seconds(2)),
        seconds(179)
    );
}

#[test]
fn recovery_reply_preserves_replica_elapsed_since_checkpoint() {
    let home = DisconnectBudgets::default();
    let survivor = DisconnectBudgets::default();
    let replacement = DisconnectBudgets::default();
    let key = session_key(1);
    let now = Instant::now();
    let slot = SlotId(0);
    home.configure_session(&key, false, &[slot], &[slot], &[]);
    survivor.configure_session(&key, false, &[], &[slot], &[]);
    assert!(home.start_outage(&key, slot, 7, now));
    let checkpoint = home.snapshot(&key, now + seconds(10));
    survivor.merge(&key, &checkpoint, now + seconds(10));
    // Periodic snapshots keep the last home-authored floor.
    assert_eq!(
        survivor.snapshot(&key, now + seconds(30))[0].elapsed,
        seconds(10)
    );
    // A recovery reply includes the survivor's time since the checkpoint.
    let recovery = survivor.snapshot_for_recovery(&key, now + seconds(30));
    assert_eq!(recovery[0].elapsed, seconds(30));
    assert_eq!(
        survivor.snapshot(&key, now + seconds(31))[0].elapsed,
        seconds(30)
    );
    replacement.configure_session(&key, false, &[slot], &[slot], &[]);
    replacement.merge(&key, &recovery, now + seconds(30));
    replacement.merge(
        &key,
        &[EpisodeSnapshot {
            elapsed: seconds(10),
            complete: true,
            ..recovery[0]
        }],
        now + seconds(31),
    );
    assert_eq!(
        replacement.remaining(&key, slot, now + seconds(32)),
        seconds(150)
    );
}
