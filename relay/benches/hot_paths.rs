use std::collections::HashSet;
use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rally_point_proto::control::{BufferBounds, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::messages::{LinkConditions, Payload, SlotConditions};
use rally_point_relay::consensus::{Authority, ControlLaw, DecisionMaker};
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

fn decision_maker(slots: u8) -> DecisionMaker {
    let mut maker = DecisionMaker::new(
        session_key(),
        BufferBounds::new(1, 12).expect("valid benchmark bounds"),
        ControlLaw::default(),
        Authority::Peer,
        HashSet::new(),
    );
    let conditions = LinkConditions {
        slots: (0..slots)
            .map(|slot| SlotConditions {
                slot: u32::from(slot),
                rtt_us: 25_000 + u32::from(slot) * 7_000,
                lost_packets: u64::from(slot),
                sent_packets: 10_000,
            })
            .collect(),
    };
    let _ = maker.ingest_local(&conditions);
    // A second cumulative sample establishes a loss delta, exercising every
    // target input rather than only the RTT half.
    let _ = maker.ingest_local(&conditions);
    maker
}

fn consensus(c: &mut Criterion) {
    let mut target_group = c.benchmark_group("consensus/target");
    for slots in [2_u8, 8, 12] {
        let maker = decision_maker(slots);
        target_group.throughput(Throughput::Elements(u64::from(slots)));
        target_group.bench_with_input(BenchmarkId::from_parameter(slots), &slots, |b, _| {
            b.iter(|| black_box(maker.target()))
        });
    }
    target_group.finish();

    let mut ingest_group = c.benchmark_group("consensus/ingest_one_local_condition");
    ingest_group.throughput(Throughput::Elements(1));
    let sample = SlotConditions {
        slot: 3,
        rtt_us: 65_000,
        lost_packets: 2,
        sent_packets: 10_000,
    };
    ingest_group.bench_function("single_slot", |b| {
        let mut maker = decision_maker(8);
        b.iter(|| black_box(maker.ingest_local_condition(black_box(&sample))));
    });
    ingest_group.bench_function("one_element_batch", |b| {
        let mut maker = decision_maker(8);
        b.iter(|| {
            let batch = LinkConditions {
                slots: vec![black_box(sample)],
            };
            black_box(maker.ingest_local(black_box(&batch)))
        });
    });
    ingest_group.finish();
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

criterion_group!(benches, validation, mesh_dedup, turn_ring, consensus);
criterion_main!(benches);
