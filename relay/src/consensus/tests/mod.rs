//! Shared fixtures for the consensus tests plus the topic modules that use
//! them.
//!
//! Every helper here is visible to the child modules through their
//! `use super::*;`, which also re-exports the private items of `consensus`
//! itself, so a topic file reaches the internals under test without naming
//! them again.

use super::*;
use std::sync::Arc;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::SessionId;
use rally_point_proto::messages::SlotConditions;

mod authority;
mod control_law;
mod desync_majority;
mod desync_ordinals;
mod directive;
mod epochs;
mod finalize;
mod homing;
mod initial_depth;
mod leave_clamp;
mod leave_promotion;
mod leave_schedule;
mod load_state;
mod loss;
mod loss_memory;
mod notices_departure;
mod notices_result;
mod notices_session;
mod observe_leave;
mod outages;
mod region_labels;
mod seed_departed;
mod session_start;
mod shrink;
mod silence;
mod target;

fn key() -> SessionKey {
    SessionKey {
        tenant: TenantId::new("sb-test").unwrap(),
        session: SessionId(1),
    }
}

fn bounds(min: u32, max: u32) -> BufferBounds {
    BufferBounds { min, max }
}

fn law() -> ControlLaw {
    ControlLaw::default()
}

fn conditions(slot: u8, rtt_us: u32, lost: u64, sent: u64) -> LinkConditions {
    LinkConditions {
        slots: vec![SlotConditions {
            slot: slot as u32,
            rtt_us,
            lost_packets: lost,
            sent_packets: sent,
            connection_epoch: None,
        }],
    }
}

fn epoch_conditions(slot: u8, epoch: u64, rtt_us: u32, lost: u64, sent: u64) -> LinkConditions {
    let mut conditions = conditions(slot, rtt_us, lost, sent);
    conditions.slots[0].connection_epoch = Some(epoch);
    conditions
}

fn multi_conditions(slots: &[(u8, u32, u64, u64)]) -> LinkConditions {
    LinkConditions {
        slots: slots
            .iter()
            .map(|&(s, rtt, lost, sent)| SlotConditions {
                slot: s as u32,
                rtt_us: rtt,
                lost_packets: lost,
                sent_packets: sent,
                connection_epoch: None,
            })
            .collect(),
    }
}

/// The slot's loss estimate as the control law sees it (the windowed rate
/// under the maker's own attack horizon).
fn slot_loss_rate(maker: &DecisionMaker, slot: u8) -> Option<f64> {
    maker.slots[&SlotId(slot)].windowed_loss_rate(maker.law.loss_attack_samples)
}

/// Drives one raw counter sample into an established slot's state at a
/// synthetic instant, so tests can fabricate receive gaps without
/// sleeping. Bypasses ingest deliberately: epoch activation and RTT
/// admission are not what the gap tests exercise.
fn sample_at(
    maker: &mut DecisionMaker,
    slot: u8,
    lost: u64,
    sent: u64,
    at: Instant,
) -> CounterUpdate {
    let interval = maker.law.loss_snapshot_interval();
    let span = maker.law.blackout_run_bucket_span();
    maker
        .slots
        .get_mut(&SlotId(slot))
        .unwrap()
        .update_counters(lost, sent, interval, span, at)
}

/// One slot-link packet's worth of input: frames observed off the packet's
/// validated turns, then the sampled conditions ingested.
fn ingest_at(maker: &mut DecisionMaker, c: &LinkConditions, frame: u32) -> Option<Decision> {
    for slot in &c.slots {
        maker.observe_frame(SlotId(slot.slot as u8), GameFrameCount(frame));
    }
    maker.ingest_local(c)
}

/// One mesh datagram's worth of input: frames observed off the forwarded
/// turns, then the peer's conditions sidecar ingested with its mesh hop.
fn ingest_remote_at(
    maker: &mut DecisionMaker,
    c: &LinkConditions,
    mesh_rtt_us: u32,
    frame: u32,
) -> Option<Decision> {
    for slot in &c.slots {
        maker.observe_frame(SlotId(slot.slot as u8), GameFrameCount(frame));
    }
    maker.ingest_remote(c, mesh_rtt_us)
}

/// The allocation-and-sort implementation that `target_inputs` used
/// before its single-pass fold. Kept in tests as an equivalence oracle.
fn reference_target_inputs(maker: &DecisionMaker) -> Option<TargetInputs> {
    let mut eff_rtts: Vec<u32> = maker
        .slots
        .values()
        .map(SlotState::eff_rtt)
        .filter(|&rtt| rtt > 0)
        .collect();
    if eff_rtts.is_empty() {
        return None;
    }

    eff_rtts.sort_unstable_by(|a, b| b.cmp(a));
    let path_us = if eff_rtts.len() >= 2 {
        ((u64::from(eff_rtts[0]) + u64::from(eff_rtts[1])) / 2) as u32
    } else {
        eff_rtts[0]
    };
    let worst_loss_risk = maker
        .slots
        .values()
        .filter_map(|state| {
            state
                .windowed_loss_rate(maker.law.loss_attack_samples)
                .map(|rate| rate * f64::from(state.eff_rtt()))
        })
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap_or(0.0);
    let burst_turns = maker
        .slots
        .values()
        .map(SlotState::burst_turns)
        .max()
        .unwrap_or(0);
    let turn_us = f64::from(maker.law.turn_duration_us);
    let path_turns = (f64::from(path_us) / turn_us).ceil() as u32;
    let loss_turns = (worst_loss_risk / turn_us).ceil() as u32;
    let margined_path_turns =
        (f64::from(path_us.saturating_add(maker.law.shrink_headroom_us)) / turn_us).ceil() as u32;
    let loss_delay_turns = loss_turns.max(burst_turns);

    Some(TargetInputs {
        target: path_turns.saturating_add(loss_delay_turns),
        shrink_target: margined_path_turns.saturating_add(loss_delay_turns),
        path_us,
        worst_loss_risk,
        burst_turns,
    })
}

fn assert_target_inputs_match_reference(maker: &DecisionMaker) {
    let compact = |inputs: TargetInputs| {
        (
            inputs.target,
            inputs.shrink_target,
            inputs.path_us,
            inputs.worst_loss_risk.to_bits(),
        )
    };
    assert_eq!(
        maker.target_inputs().map(compact),
        reference_target_inputs(maker).map(compact),
    );
}

fn push_rtt_and_check_reference(
    window: &mut RttWindow,
    reference: &mut VecDeque<u32>,
    sample: u32,
) {
    window.push(sample);
    if sample != 0 {
        if reference.len() == RTT_WINDOW_SIZE {
            reference.pop_front();
        }
        reference.push_back(sample);
    }
    assert_eq!(
        window.max(),
        reference.iter().copied().max().unwrap_or(0),
        "cached max diverged after pushing {sample}",
    );
}

// -- Target formula --

fn region_labels(labels: &[(u64, &str)]) -> Vec<RegionLabel> {
    labels
        .iter()
        .map(|(relay_id, region)| RegionLabel {
            relay_id: *relay_id,
            region: (*region).to_owned(),
        })
        .collect()
}

/// Builds a maker holding the given relay → region labels on a session that
/// has NOT started — the state a descriptor push alone leaves behind.
fn maker_with_labels(labels: &[(u64, &str)]) -> DecisionMaker {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 20),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    assert_eq!(
        maker.set_region_labels(region_labels(labels)),
        None,
        "recording labels never releases them on its own",
    );
    maker
}

/// A registry whose maker runs the finalized-drop handshake, is the
/// authority, and strictly homes the given slots, with framed history so
/// a decide has a basis.
fn finalized_drop_registry(k: &SessionKey, homed: &[u8]) -> DecisionMakers {
    let registry = new_decision_makers();
    let _ = sync_maker(
        &registry,
        k,
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        HashSet::new(),
        homed.iter().map(|&s| SlotId(s)).collect(),
        HashSet::new(),
        None,
        true,
    );
    observe_frame(&registry, k, SlotId(0), GameFrameCount(40));
    observe_frame(&registry, k, SlotId(1), GameFrameCount(50));
    registry
}

/// Test-only helper for [`sync_maker_promotion_skips_a_held_departure`]:
/// observes a frame and records an undecided departure for slot 1, mirroring
/// what a real disconnect does before a promotion races it.
fn consensus_observe_and_hold(registry: &DecisionMakers, key: &SessionKey) {
    let mut makers = registry.lock();
    let maker = makers.get_mut(key).unwrap();
    maker.observe_frame(SlotId(0), GameFrameCount(40));
    maker.record_departure(
        SlotId(1),
        DepartureStamps {
            last_frame: Some(GameFrameCount(50)),
            ..Default::default()
        },
        DROPPED,
    );
}

/// Unwraps the next queued notice as a departure, panicking on anything else.
/// The leave-path tests only ever expect departures on the shared notice
/// channel, so this keeps their assertions reading against `DepartureNotice`.
fn recv_departure(rx: &mut tokio::sync::mpsc::UnboundedReceiver<RelayNotice>) -> DepartureNotice {
    match rx.try_recv().expect("a queued notice") {
        RelayNotice::Departure(notice) => notice,
        RelayNotice::Desync(_) => panic!("expected a departure notice, got a desync"),
        RelayNotice::Result(_) => panic!("expected a departure notice, got a result"),
        RelayNotice::SlotConnected(_) => {
            panic!("expected a departure notice, got a slot-connected")
        }
        RelayNotice::SessionStarted(_) => {
            panic!("expected a departure notice, got a session-started")
        }
        RelayNotice::SlotStarted(_) => {
            panic!("expected a departure notice, got a slot-started")
        }
        RelayNotice::SessionClosed { .. } => {
            panic!("expected a departure notice, got a session-closed")
        }
    }
}

/// Unwraps the next queued notice as a result, panicking on anything else.
fn recv_result(rx: &mut tokio::sync::mpsc::UnboundedReceiver<RelayNotice>) -> ResultNotice {
    match rx.try_recv().expect("a queued notice") {
        RelayNotice::Result(notice) => notice,
        other => panic!("expected a result notice, got {other:?}"),
    }
}

const DROPPED: u32 = 0x4000_0006;

/// Feeds a run of framed turns for `slot`, one frame per turn (frame = 100 +
/// seq), through the seq-aware production path that populates frame history.
fn feed_turns(maker: &mut DecisionMaker, slot: u8, seqs: std::ops::RangeInclusive<u64>) {
    for seq in seqs {
        maker.observe_turn_frame(SlotId(slot), seq, GameFrameCount(100 + seq as u32));
    }
}

// -- Backwards-stamp tripwire: a client whose executable-turn index
//    restarted underneath its stamps (a turn stamped before its game loop
//    began) is reported once, never corrected, and out-of-order arrival
//    never trips it. --

/// then decide the (clamped) leave.
fn home_decide_leave(maker: &mut DecisionMaker, slot: u8) -> LeaveDirective {
    let last = maker.slot_frame(SlotId(slot));
    let ceiling = maker.reachable_frame(SlotId(slot));
    maker.record_departure(
        SlotId(slot),
        DepartureStamps {
            last_frame: last,
            reachable_frame: ceiling,
            ..Default::default()
        },
        DROPPED,
    );
    maker
        .decide_leave(SlotId(slot), DROPPED)
        .expect("a leave is scheduled")
}

/// The two `hash16` bytes stand in for a sim state hash; distinct arrays
/// are distinct sims.
const SYNC_A: SyncValue = [1, 2];
const SYNC_B: SyncValue = [9, 8];
const SYNC_C: SyncValue = [4, 4];

/// Builds a 7-byte `0x37` sync command: opcode, `(ring << 4) | kind`, the
/// 2-byte `hash16`, then fixed zero filler for `[4..7]` (the per-sender
/// fog/vision bytes the comparator never reads — see `SyncValue`; a value
/// here is irrelevant to the code under test except in the dedicated
/// `sync_command_with_fog` regression test below).
fn sync_command(ring: u8, kind: u8, value: SyncValue) -> Vec<u8> {
    sync_command_with_fog(ring, kind, value, [0, 0, 0])
}

/// [`sync_command`], but with explicit `[4..7]` filler — for the
/// regression test proving those bytes are never compared.
fn sync_command_with_fog(ring: u8, kind: u8, value: SyncValue, fog: [u8; 3]) -> Vec<u8> {
    let mut command = vec![SYNC_COMMAND, ((ring & 0x0F) << 4) | (kind & 0x0F)];
    command.extend_from_slice(&value);
    command.extend_from_slice(&fog);
    command
}

/// Feeds one slot's sync command at a chosen ring nibble, kind, and frame.
/// Returns the divergence if this feed confirmed one.
fn feed_ring_kind(
    maker: &mut DecisionMaker,
    slot: u8,
    ring: u8,
    kind: u8,
    value: SyncValue,
    frame: u32,
) -> Option<SyncDivergence> {
    maker.observe_sync(SlotId(slot), Some(frame), &sync_command(ring, kind, value))
}

/// [`feed_ring_kind`] with the kind SC:R's native check ties to `ring`'s
/// parity (even → 1, odd → 2) — what an honest client always sends.
fn feed_ring(
    maker: &mut DecisionMaker,
    slot: u8,
    ring: u8,
    value: SyncValue,
    frame: u32,
) -> Option<SyncDivergence> {
    let kind = expected_kind_for_ordinal(u64::from(ring));
    feed_ring_kind(maker, slot, ring, kind, value, frame)
}

/// Feeds one slot's sync command with the ring nibble its true ordinal
/// expects (`ordinal % 16`) and the kind that ordinal's parity implies.
/// The frame is a distinct-per-ordinal marker. Feeding a slot's ordinals
/// out of order (or interleaved with another slot's) exercises the same
/// nibble-corrected placement a real reordered or racing-ahead slot would.
fn feed(
    maker: &mut DecisionMaker,
    slot: u8,
    ordinal: u8,
    value: SyncValue,
) -> Option<SyncDivergence> {
    feed_ring(maker, slot, ordinal % 16, value, 1000 + u32::from(ordinal))
}

/// Advances `slot`'s ordinal from 0 up to (but not including) `through`,
/// reporting `value` at every step. Used to push the tracker's frontier
/// past the evaluation margin without needing every compared slot to
/// individually advance — the margin only cares about the single furthest
/// member's progress, so racing one slot ahead is enough to make earlier
/// ordinals eligible for evaluation. Returns the last divergence observed,
/// if any (there is at most one, since the comparator fires exactly one
/// notice per event).
fn advance(
    maker: &mut DecisionMaker,
    slot: u8,
    value: SyncValue,
    through: u8,
) -> Option<SyncDivergence> {
    let mut divergence = None;
    for ordinal in 0..through {
        if let Some(d) = feed(maker, slot, ordinal, value) {
            divergence = Some(d);
        }
    }
    divergence
}

/// A representative buffer policy, well under [`SYNC_ABSURD_BUFFER_MAX`],
/// so these tests exercise the comparator exactly as it runs with
/// detection live.
fn authority_maker() -> DecisionMaker {
    DecisionMaker::new(
        key(),
        bounds(0, 6),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    )
}

/// The evaluation margin [`authority_maker`]'s bounds (`max = 6`) implies
/// — computed via the real formula ([`sync_eval_margin`]) so these tests
/// can't silently drift from it.
fn authority_margin() -> u64 {
    sync_eval_margin(6)
}

/// One session's retained load state, picked out of the whole-registry
/// snapshot every heartbeat is built from. Default for a session with no
/// maker, which the snapshot never names.
fn load_state_of(registry: &DecisionMakers, key: &SessionKey) -> RetainedLoadState {
    retained_load_states(registry)
        .into_iter()
        .find(|(k, _)| k == key)
        .map(|(_, load)| load)
        .unwrap_or_default()
}

/// Builds an authority maker with the given bounds, expected slots, and
/// session shape, ready to drive to the coverage latch.
fn initial_depth_maker(
    min: u32,
    max: u32,
    expected: &[u8],
    latency_hint_ms: Option<u32>,
    single_relay: bool,
) -> DecisionMaker {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(min, max),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    maker.set_expected_slots(expected.iter().map(|&s| SlotId(s)).collect());
    maker.set_session_shape(latency_hint_ms, single_relay);
    maker
}

/// Reports each of `present` as registered, returning whether the last one
/// fired the coverage latch (and, with it, the initial-depth computation).
fn drive_to_coverage(maker: &mut DecisionMaker, present: &[u8]) -> bool {
    let mut fired = false;
    for &s in present {
        fired = maker.note_slot_present(SlotId(s));
    }
    fired
}

/// The silence window these tests measure against.
const SILENCE_WINDOW: Duration = Duration::from_secs(10);

/// Gives `slot` a live link, the way a registering client does: the
/// connection generation activates, and the first conditions sample creates
/// the slot's state. Activating before that sample leaves the slot's
/// link-age grace unset, which is what a slot present since the session
/// began actually looks like.
fn connect_slot(maker: &mut DecisionMaker, slot: u8, at: Instant) {
    assert!(maker.activate_connection_epoch(SlotId(slot), 1, at));
    maker.ingest_local(&epoch_conditions(slot, 1, 50_000, 0, 10));
}

/// A started session whose descriptor expects `expected` and homes `homed`
/// here, where every slot in `connected` has a live link and every slot in
/// `started` has reported its game loop running. Returned with the instant
/// the session latched its start, which is where every slot's clock begins
/// and what the tests measure from.
fn silence_maker_with(
    expected: &[u8],
    connected: &[u8],
    homed: &[u8],
    started: &[u8],
) -> (DecisionMaker, Instant) {
    let mut maker = DecisionMaker::new(
        key(),
        bounds(0, 6),
        law(),
        Authority::SelfRelay,
        HashSet::new(),
    );
    maker.mark_started();
    let start = maker
        .started_at
        .expect("a started session latched its start instant");
    maker.set_expected_slots(expected.iter().copied().map(SlotId).collect());
    maker.set_homed_slots(homed.iter().copied().map(SlotId).collect());
    for &slot in connected {
        connect_slot(&mut maker, slot, start);
    }
    for &slot in started {
        maker.note_slot_started(SlotId(slot));
    }
    (maker, start)
}

/// The two-slot session most of these tests run on: slots 0 and 1 expected
/// by the descriptor and both connected here.
fn silence_maker(homed: &[u8], started: &[u8]) -> (DecisionMaker, Instant) {
    silence_maker_with(&[0, 1], &[0, 1], homed, started)
}

/// The stall this watch exists to end. Slot 1's turns stopped reaching the
/// session a second in; slot 0 kept forwarding for another 200ms — the turns
/// of slot 1's it had already buffered — and then starved behind the missing
/// ones. Slot 1 stopped first, so slot 1 is the slot everyone is waiting on.
fn stalled_session(homed: &[u8], started: &[u8]) -> (DecisionMaker, Instant) {
    let (mut maker, start) = silence_maker(homed, started);
    maker.note_forward_advance(SlotId(1), start + Duration::from_secs(1));
    maker.note_forward_advance(SlotId(0), start + Duration::from_millis(1200));
    (maker, start)
}

/// Records `slot`'s drop with a frame to schedule against — the departure a
/// leave can actually be decided from.
fn drop_slot(maker: &mut DecisionMaker, slot: u8) {
    assert!(maker.record_departure_for_epoch(
        SlotId(slot),
        DepartureStamps {
            last_frame: Some(GameFrameCount(112)),
            ..Default::default()
        },
        DROPPED,
        Some(1),
    ));
}
