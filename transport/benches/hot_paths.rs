use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{Packet, Payload};
use rally_point_transport::AckManager;

fn payload(slot: u8, seq: u64, command_bytes: usize) -> Payload {
    Payload {
        seq,
        slot: u32::from(slot),
        commands: vec![0x05; command_bytes].into(),
        game_frame_count: Some(seq as u32),
        buffer_directive: None,
    }
}

fn seeded_manager(slots: u8, payloads_per_slot: u64, command_bytes: usize) -> AckManager {
    let mut manager = AckManager::new();
    for slot in 0..slots {
        for seq in 0..payloads_per_slot {
            manager.reinject_unacked(payload(slot, seq, command_bytes));
        }
    }
    manager
}

fn build_outgoing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ack_manager/build_outgoing");

    for depth in [1_u64, 8, 32, 256] {
        group.throughput(Throughput::Elements(depth + 1));
        group.bench_with_input(BenchmarkId::new("all_fit", depth), &depth, |b, &depth| {
            b.iter_batched(
                || seeded_manager(1, depth, 32),
                |mut manager| {
                    let packet = manager
                        .build_outgoing(Some(payload(0, depth, 32)), 64 * 1024)
                        .expect("benchmark cannot exhaust the packet sequence space");
                    black_box(packet)
                },
                BatchSize::SmallInput,
            );
        });
    }

    for depth in [8_u64, 32, 128] {
        group.throughput(Throughput::Elements(depth + 1));
        group.bench_with_input(
            BenchmarkId::new("constrained_1200b", depth),
            &depth,
            |b, &depth| {
                b.iter_batched(
                    || seeded_manager(1, depth, 128),
                    |mut manager| {
                        let packet = manager
                            .build_outgoing(Some(payload(0, depth, 128)), 1_200)
                            .expect("benchmark cannot exhaust the packet sequence space");
                        black_box(packet)
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn retire_payloads(c: &mut Criterion) {
    let mut group = c.benchmark_group("ack_manager/retire_payloads_through");

    for per_slot in [8_u64, 64, 256] {
        group.throughput(Throughput::Elements(per_slot));
        group.bench_with_input(
            BenchmarkId::new("one_of_eight_slots", per_slot),
            &per_slot,
            |b, &per_slot| {
                b.iter_batched(
                    || seeded_manager(8, per_slot, 32),
                    |mut manager| {
                        black_box(
                            manager.retire_payloads_through(SlotId(4), per_slot.saturating_sub(1)),
                        )
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn ack_history(c: &mut Criterion) {
    let mut dense = AckManager::new();
    for seq in 0..33 {
        dense
            .handle_incoming(&Packet {
                seq,
                ack: None,
                ack_bits: 0,
                payloads: Vec::new(),
            })
            .expect("synthetic receive history is valid");
    }

    c.bench_function("ack_manager/build_ack_history/dense_33", |b| {
        b.iter(|| {
            let packet = dense
                .build_outgoing(None, 1_200)
                .expect("benchmark cannot exhaust the packet sequence space");
            black_box((packet.ack, packet.ack_bits))
        });
    });
}

criterion_group!(benches, build_outgoing, retire_payloads, ack_history);
criterion_main!(benches);
