use std::collections::HashSet;
use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rally_point_proto::control::{BufferBounds, TenantId};
use rally_point_proto::ids::{GameFrameCount, RelayId, SessionId, SlotId};
use rally_point_proto::messages::{LinkConditions, Payload, SlotConditions};
use rally_point_relay::consensus::{Authority, ControlLaw, DecisionMaker};
use rally_point_relay::delivery::DeliveryHome;
use rally_point_relay::mesh::{MeshSeen, Seen, mark_seen, new_seen_registries};
use rally_point_relay::routing::SessionKey;
use rally_point_relay::turn_ring::{TurnOrigin, TurnRing};
use rally_point_relay::validation::validate_turn;

fn payload(seq: u64, commands: Vec<u8>) -> Payload {
    Payload {
        seq,
        // Deliberately wrong: validation must bind the authorized slot while
        // retaining the command allocation on the clean fast path.
        slot: u32::MAX,
        commands: commands.into(),
        game_frame_count: Some(seq as u32),
        buffer_directive: None,
    }
}

fn session_key() -> SessionKey {
    SessionKey {
        tenant: TenantId("benchmark-tenant-with-a-nontrivial-key".to_owned()),
        session: SessionId(7),
    }
}

fn validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("validation");

    for command_bytes in [1_usize, 32, 256, 1_024] {
        group.throughput(Throughput::Bytes(command_bytes as u64));
        group.bench_function(format!("clean/{command_bytes}_bytes"), |b| {
            let input = payload(42, vec![0x05; command_bytes]);
            b.iter_batched(
                || input.clone(),
                |input| black_box(validate_turn(SlotId(3), input).expect("valid command stream")),
                BatchSize::SmallInput,
            );
        });
    }

    // KeepAlive + client-forbidden Latency + Build: this measures the cold
    // sanitize path separately so optimizing the honest path cannot hide a
    // regression in attacker-facing validation.
    let stripped = vec![0x05, 0x55, 0x02, 0x0c, 1, 2, 3, 4, 5, 6, 7];
    group.throughput(Throughput::Bytes(stripped.len() as u64));
    group.bench_function("strip_one_control", |b| {
        let input = payload(42, stripped.clone());
        b.iter_batched(
            || input.clone(),
            |input| black_box(validate_turn(SlotId(3), input).expect("valid command stream")),
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn mesh_dedup(c: &mut Criterion) {
    const TURNS: u64 = 4_096;
    let mut group = c.benchmark_group("mesh_dedup");
    group.throughput(Throughput::Elements(TURNS));

    group.bench_function("direct_in_order", |b| {
        b.iter_batched(
            MeshSeen::new,
            |mut seen| {
                for seq in 0..TURNS {
                    assert_eq!(seen.mark_forwarded(SlotId(3), seq), Seen::New);
                }
                black_box(seen)
            },
            BatchSize::SmallInput,
        );
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("registry_warm_session", |b| {
        let registries = new_seen_registries();
        let key = session_key();
        assert_eq!(mark_seen(&registries, &key, SlotId(3), 0), Seen::New);
        let mut next_seq = 1_u64;
        b.iter(|| {
            let result = mark_seen(&registries, &key, SlotId(3), next_seq);
            next_seq += 1;
            black_box(result)
        });
    });

    group.finish();
}

fn conditions(slots: std::ops::Range<u8>, sent_packets: u64) -> LinkConditions {
    LinkConditions {
        slots: slots
            .map(|slot| SlotConditions {
                slot: u32::from(slot),
                rtt_us: 25_000 + u32::from(slot) * 7_000,
                lost_packets: u64::from(slot) * 3,
                sent_packets,
            })
            .collect(),
    }
}

fn delivery_home(slot: u8, players: u8) -> DeliveryHome {
    if slot < players / 2 {
        DeliveryHome::Local
    } else {
        DeliveryHome::Peer(RelayId(2))
    }
}

/// Builds a steady-state, evenly split two-relay session. Every ordered
/// origin/destination pair has a healthy delivery cursor, so an authority's
/// decision pass pays the same O(P^2) delivery-fold cost as production while a
/// peer still takes its real early return after updating conditions.
fn decision_maker(players: u8, authority: Authority) -> DecisionMaker {
    let mut maker = DecisionMaker::new(
        session_key(),
        BufferBounds::new(1, 12).expect("valid benchmark bounds"),
        ControlLaw::default(),
        authority,
        HashSet::new(),
    );

    let expected = (0..players).map(SlotId).collect();
    maker.set_expected_slots(expected);
    maker.set_session_shape(Some(70), false);
    maker.mark_started();

    let frontier = 50_000_u64;
    for slot in 0..players {
        maker.observe_turn_frame(
            SlotId(slot),
            frontier,
            GameFrameCount(30_000 + u32::from(slot)),
        );
        maker.delivery_mut().observe_origin(
            SlotId(slot),
            frontier + u64::from(slot),
            delivery_home(slot, players),
        );
    }
    for dest in 0..players {
        for origin in 0..players {
            if origin == dest {
                continue;
            }
            let newest = frontier + u64::from(origin);
            let healthy_lag = 4 + u64::from((origin + dest) % 4);
            maker.delivery_mut().observe_delivery(
                SlotId(dest),
                SlotId(origin),
                newest.saturating_sub(healthy_lag),
                delivery_home(dest, players),
            );
        }
    }

    let local_end = players / 2;
    let local_baseline = conditions(0..local_end, 10_000);
    let remote_baseline = conditions(local_end..players, 10_000);
    let local_current = conditions(0..local_end, 10_024);
    let remote_current = conditions(local_end..players, 10_024);
    let _ = maker.ingest_local(&local_baseline);
    let _ = maker.ingest_remote(&remote_baseline, 35_000);
    let _ = maker.ingest_local(&local_current);
    let _ = maker.ingest_remote(&remote_current, 35_000);
    maker
}

fn consensus(c: &mut Criterion) {
    let mut target_group = c.benchmark_group("consensus/target");
    for slots in [2_u8, 4, 8, 12] {
        let maker = decision_maker(slots, Authority::SelfRelay);
        target_group.throughput(Throughput::Elements(u64::from(slots)));
        target_group.bench_with_input(BenchmarkId::from_parameter(slots), &slots, |b, _| {
            b.iter(|| black_box(maker.target()))
        });
    }
    target_group.finish();

    // Preserve the allocation comparison that motivated the single-condition
    // API separately from the authority-cost topology below.
    let mut allocation_group = c.benchmark_group("consensus/ingest_one_local_condition");
    allocation_group.throughput(Throughput::Elements(1));
    let sample = SlotConditions {
        slot: 3,
        rtt_us: 65_000,
        lost_packets: 2,
        sent_packets: 10_000,
    };
    allocation_group.bench_function("single_slot", |b| {
        let mut maker = decision_maker(8, Authority::Peer);
        b.iter(|| black_box(maker.ingest_local_condition(black_box(&sample))));
    });
    allocation_group.bench_function("one_element_batch", |b| {
        let mut maker = decision_maker(8, Authority::Peer);
        b.iter(|| {
            let batch = LinkConditions {
                slots: vec![black_box(sample)],
            };
            black_box(maker.ingest_local(black_box(&batch)))
        });
    });
    allocation_group.finish();

    let authorities = [
        ("self_relay", Authority::SelfRelay),
        ("peer", Authority::Peer),
    ];

    let mut local_group = c.benchmark_group("consensus/ingest_local_condition");
    local_group.throughput(Throughput::Elements(1));
    for players in [2_u8, 4, 8] {
        for (label, authority) in authorities {
            local_group.bench_function(BenchmarkId::new(format!("P{players}"), label), |b| {
                let mut maker = decision_maker(players, authority);
                let mut sample = conditions(0..1, 10_024).slots.remove(0);
                b.iter(|| {
                    // Local condition reports are fresh samples rather than
                    // per-turn repeats, so advance the healthy sent counter.
                    sample.sent_packets += 24;
                    black_box(maker.ingest_local_condition(black_box(&sample)))
                });
            });
        }
    }
    local_group.finish();

    let mut remote_group = c.benchmark_group("consensus/ingest_remote_conditions");
    for players in [2_u8, 4, 8] {
        let remote_slots = players / 2;
        remote_group.throughput(Throughput::Elements(u64::from(remote_slots)));
        for (label, authority) in authorities {
            remote_group.bench_function(BenchmarkId::new(format!("P{players}"), label), |b| {
                let mut maker = decision_maker(players, authority);
                let sidecar = conditions(remote_slots..players, 10_024);
                b.iter(|| {
                    // Mesh packets carry the latest complete snapshot on
                    // every turn; most snapshots repeat between client
                    // condition updates, which is the production hot case.
                    black_box(maker.ingest_remote(black_box(&sidecar), 35_000))
                });
            });
        }
    }
    remote_group.finish();
}

fn healthy_sync_command_streams() -> Vec<Vec<u8>> {
    (0_u8..16)
        .map(|ring| {
            let kind = if ring.is_multiple_of(2) { 1 } else { 2 };
            let mut commands = vec![0x05; 8];
            commands.extend_from_slice(&[0x37, (ring << 4) | kind, 1, 2, 0, 0, 0]);
            commands.extend_from_slice(&[0x05; 8]);
            commands
        })
        .collect()
}

fn consensus_sync(c: &mut Criterion) {
    let authorities = [
        ("self_relay", Authority::SelfRelay),
        ("peer", Authority::Peer),
    ];
    let commands = healthy_sync_command_streams();
    let mut group = c.benchmark_group("consensus/observe_sync_healthy_round");

    for players in [2_u8, 4, 8] {
        group.throughput(Throughput::Elements(u64::from(players)));
        for (label, authority) in authorities {
            group.bench_function(BenchmarkId::new(format!("P{players}"), label), |b| {
                let mut maker = decision_maker(players, authority);
                // Establish every comparator member before measuring the
                // steady stream. On a peer this remains the intended no-op.
                for slot in 0..players {
                    let result =
                        maker.observe_sync(SlotId(slot), Some(30_000), black_box(&commands[0]));
                    debug_assert!(result.is_none());
                }

                let mut ordinal = 1_u64;
                b.iter(|| {
                    let stream = &commands[(ordinal % 16) as usize];
                    let frame = 30_000_u32.wrapping_add(ordinal as u32);
                    for slot in 0..players {
                        let result =
                            maker.observe_sync(SlotId(slot), Some(frame), black_box(stream));
                        debug_assert!(result.is_none());
                        black_box(result);
                    }
                    ordinal += 1;
                });
            });
        }
    }
    group.finish();
}

fn turn_ring(c: &mut Criterion) {
    c.bench_function("turn_ring/record_warm_session", |b| {
        let ring = TurnRing::new();
        let key = session_key();
        let turn = payload(0, vec![0x05; 64]);
        ring.record(&key, &turn, TurnOrigin::Local, 8);
        b.iter(|| {
            ring.record(&key, &turn, TurnOrigin::Local, 8);
            black_box(&ring)
        });
    });
}

criterion_group!(
    benches,
    validation,
    mesh_dedup,
    turn_ring,
    consensus,
    consensus_sync
);
criterion_main!(benches);
