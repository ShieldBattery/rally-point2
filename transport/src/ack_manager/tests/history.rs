//! The peer-packet history: that the rolling `ack` / `ack_bits` pair matches
//! the ring-buffer model it replaced, and that upstream loss is only counted
//! once a seq can no longer arrive.

use super::*;

#[derive(Clone, Default)]
struct ModelReceivedPacket;

fn model_ack_state(history: &SequenceBuffer<ModelReceivedPacket>) -> (Option<u32>, u32) {
    let Some(most_recent) = history.sequence().checked_sub(1) else {
        return (None, 0);
    };
    let mut bits = 0u32;
    for behind in 1u64..=32 {
        if most_recent < behind {
            break;
        }
        if history.exists(most_recent - behind) {
            bits |= 1u32 << (behind - 1);
        }
    }
    (Some(most_recent as u32), bits)
}

fn rolling_ack_state(history: &ReceivedPacketHistory) -> (Option<u32>, u32) {
    (history.most_recent, history.ack_bits)
}

#[test]
fn rolling_ack_history_matches_sequence_buffer_for_exhaustive_short_traces() {
    // Reset plus values chosen around the 32-bit history boundary and the
    // u32 sequence ceiling. Exhausting every trace through length five
    // covers in-order delivery, duplicates, arbitrary reordering, exact and
    // beyond-window late arrivals, large forward jumps, and reset at every
    // position.
    const ACTIONS: [Option<u32>; 10] = [
        None,
        Some(0),
        Some(1),
        Some(2),
        Some(31),
        Some(32),
        Some(33),
        Some(u32::MAX - 32),
        Some(u32::MAX - 1),
        Some(u32::MAX),
    ];

    for len in 0..=5u32 {
        for case in 0..ACTIONS.len().pow(len) {
            let mut rolling = ReceivedPacketHistory::default();
            let mut model = SequenceBuffer::with_capacity(33);
            let mut encoded = case;

            for step in 0..len {
                let action = ACTIONS[encoded % ACTIONS.len()];
                encoded /= ACTIONS.len();
                match action {
                    Some(seq) => {
                        rolling.record(seq);
                        let _ = model.insert(u64::from(seq), ModelReceivedPacket);
                    }
                    None => {
                        rolling = ReceivedPacketHistory::default();
                        model = SequenceBuffer::with_capacity(33);
                    }
                }

                assert_eq!(
                    rolling_ack_state(&rolling),
                    model_ack_state(&model),
                    "history diverged for len={len}, case={case}, step={step}, action={action:?}",
                );
            }
        }
    }
}

#[test]
fn rolling_ack_history_matches_sequence_buffer_for_deterministic_randomized_traces() {
    let mut rolling = ReceivedPacketHistory::default();
    let mut model = SequenceBuffer::with_capacity(33);
    let mut most_recent = None::<u32>;
    let mut random = 0xD1B5_4A32_D192_ED03u64;
    let boundaries = [
        0,
        1,
        31,
        32,
        33,
        u32::MAX - 33,
        u32::MAX - 32,
        u32::MAX - 1,
        u32::MAX,
    ];

    for step in 0..100_000u32 {
        // A fixed xorshift stream keeps the test deterministic while
        // exercising far more interleavings than the short exhaustive set.
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;

        if random.is_multiple_of(97) {
            rolling = ReceivedPacketHistory::default();
            model = SequenceBuffer::with_capacity(33);
            most_recent = None;
        } else {
            let current = most_recent.unwrap_or(0);
            let seq = match random % 7 {
                0 => random as u32,
                1 => current,
                2 => current.saturating_sub((random as u32) % 40),
                3 => current.saturating_add((random as u32) % 4_096),
                4 => boundaries[(random as usize) % boundaries.len()],
                5 => (random as u32) % 64,
                _ => current.saturating_sub(32 + (random as u32) % 4_096),
            };
            rolling.record(seq);
            let _ = model.insert(u64::from(seq), ModelReceivedPacket);
            most_recent = Some(most_recent.map_or(seq, |recent| recent.max(seq)));
        }

        assert_eq!(
            rolling_ack_state(&rolling),
            model_ack_state(&model),
            "history diverged at deterministic randomized step {step}",
        );
    }
}

#[test]
fn upstream_loss_counts_only_seqs_that_can_no_longer_arrive() {
    let mut history = ReceivedPacketHistory::default();
    for seq in 0..40 {
        history.record(seq);
    }
    assert_eq!(history.lost, 0, "a gapless run loses nothing");

    // A gap inside the window is not yet loss: the packet may still arrive
    // reordered, and does.
    let mut history = ReceivedPacketHistory::default();
    for seq in [0u32, 1, 3] {
        history.record(seq);
    }
    assert_eq!(history.lost, 0, "2 is still reachable");
    history.record(2);
    for seq in 4..80 {
        history.record(seq);
    }
    assert_eq!(history.lost, 0, "the late packet landed before it aged out");

    // The same gap, never filled, is counted once it leaves the window.
    let mut history = ReceivedPacketHistory::default();
    for seq in [0u32, 1, 3] {
        history.record(seq);
    }
    for seq in 4..80 {
        history.record(seq);
    }
    assert_eq!(history.lost, 1, "seq 2 aged out unset");

    // A jump far past the window: everything skipped is unreachable, and
    // the seqs the shifted window still covers are not counted yet.
    let mut history = ReceivedPacketHistory::default();
    history.record(0);
    history.record(1000);
    assert_eq!(
        history.lost, 967,
        "1..999 skipped, less the 32 the new window still covers",
    );
}
