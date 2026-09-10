//! The send-phase control loop across the seams a real session crosses:
//! client-edge arrivals in, a correction fanned to the slot it names, and
//! the connect-time re-push that reads it back.

use super::*;

/// Drives the send-phase control loop end to end across the module seams a
/// real session crosses: client-edge arrivals fold into the session's
/// controller, the correction it issues is fanned to exactly the slot it
/// names, the connect-time re-push reads the same value back, and nothing
/// at all happens before the session starts.
#[test]
fn phase_corrections_fan_to_the_corrected_slot_and_survive_for_repush() {
    use rally_point_proto::control::BufferBounds;
    use std::time::{Duration, Instant};

    let sessions: Sessions = Arc::default();
    let makers = Arc::new(consensus::new_decision_makers());
    let k = key();
    let _ = consensus::sync_maker(
        &makers,
        &k,
        BufferBounds::new(1, 6).unwrap(),
        crate::consensus::Authority::SelfRelay,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        None,
        false,
    );
    let (_reg0, mut inbox0) = register(&sessions, &k, SlotId(0), 1).unwrap();
    let (_reg1, mut inbox1) = register(&sessions, &k, SlotId(1), 1).unwrap();

    let turn_us: u64 = 41_667;
    let base = Instant::now();
    let feed = |makers: &consensus::DecisionMakers, slot: u8, seq: u64, offset_us: u64| {
        let at = base + Duration::from_micros(seq * turn_us + offset_us);
        makers
            .lock()
            .get_mut(&k)
            .unwrap()
            .ingest_arrival_phase(SlotId(slot), seq, at)
    };

    // Before the session starts nothing is recorded, however long the flow.
    for seq in 0..400u64 {
        assert!(feed(&makers, 0, seq, 0).is_empty());
        assert!(feed(&makers, 1, seq, 15_000).is_empty());
    }
    consensus::mark_session_started(&makers, &k);

    // Steady post-start flow: slot 0 at the cycle's base phase, slot 1
    // fifteen milliseconds later. The controller evaluates on its own
    // schedule and eventually asks slot 0 (the early one) to delay onto
    // slot 1's phase; slot 1, already the latest, is left alone.
    let mut corrections = Vec::new();
    for seq in 400..900u64 {
        corrections = feed(&makers, 0, seq, 0);
        assert!(corrections.is_empty() || corrections[0].0 == SlotId(0));
        if !corrections.is_empty() {
            break;
        }
        corrections = feed(&makers, 1, seq, 15_000);
        assert!(corrections.is_empty(), "the latest slot is never corrected");
    }
    let &[(corrected, delay_us)] = corrections.as_slice() else {
        panic!("expected exactly one correction, got {corrections:?}");
    };
    assert_eq!(corrected, SlotId(0));
    assert!(
        (6_000..=8_000).contains(&delay_us),
        "slot 0 takes a capped first step toward slot 1's phase, got {delay_us}"
    );

    // Fan-out reaches exactly the corrected slot, carrying the delay.
    fan_out_phase_directives(&sessions, &k, &corrections);
    let directive = inbox0
        .try_recv_phase_directive()
        .expect("the corrected slot receives its directive");
    assert_eq!(directive.delay_us, delay_us);
    assert!(directive.slew_us_per_s > 0);
    assert_eq!(
        inbox1.try_recv_phase_directive(),
        None,
        "an uncorrected slot receives nothing",
    );

    // The commanded value survives on the maker for the connect-time
    // re-push a reconnecting slot gets.
    assert_eq!(
        consensus::commanded_phase_delay(&makers, &k, SlotId(0)),
        Some(delay_us),
    );
    assert_eq!(
        consensus::commanded_phase_delay(&makers, &k, SlotId(1)),
        None
    );
    deliver_phase_directive_to_slot(
        &sessions,
        &k,
        SlotId(0),
        PhaseDirective {
            delay_us,
            slew_us_per_s: crate::consensus::phase::SLEW_US_PER_S,
        },
    );
    assert_eq!(
        inbox0.try_recv_phase_directive().map(|d| d.delay_us),
        Some(delay_us),
    );
}
