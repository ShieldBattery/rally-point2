//! Where the authority starts the clock: at the latest instant any player's last turn of the
//! lockstep start reached that player's own relay, which for a player homed elsewhere is its
//! arrival at the authority less the mesh hop.

use super::*;

/// The relay hop between the two relays of these sessions, one way.
const HOP: Duration = Duration::from_millis(147);

/// The mesh round trip of [`HOP`] in microseconds, as a relay samples it.
fn round_trip_us(hop: Duration) -> u32 {
    u32::try_from(us(hop * 2)).unwrap()
}

/// An authority homing slot 0 that has sampled slot 1's relay at `mesh_rtts_us`, in order.
fn authority_homing_slot_0(mesh_rtts_us: &[u32]) -> DecisionMaker {
    let mut authority = rollback(maker(), &[0, 1]);
    authority.set_homed_slots([SlotId(0)].into());
    for (sent, &mesh_rtt_us) in (1..).zip(mesh_rtts_us) {
        let _ = authority.ingest_remote(&conditions(1, 50_000, 0, sent), mesh_rtt_us);
    }
    authority
}

/// The other relay of the session, homing slot 1.
fn relay_homing_slot_1() -> DecisionMaker {
    let mut relay = rollback(peer_maker(), &[0, 1]);
    relay.set_homed_slots([SlotId(1)].into());
    relay
}

#[test]
fn a_remote_players_turn_starts_the_clock_when_it_reached_that_players_relay() {
    let start = Instant::now();
    let mut authority = authority_homing_slot_0(&[round_trip_us(HOP)]);
    let mark = authority.clock_mark();
    // Slot 0's last turn of the lockstep start arrives here first; slot 1's reached its own relay
    // 30 ms later and arrives here a hop after that.
    assert_eq!(
        authority.note_forwarded_turns(SlotId(0), LOCKSTEP_START_STEPS, start),
        None
    );
    let completed = start + 30 * MS + HOP;
    let update = authority
        .note_forwarded_turns(SlotId(1), LOCKSTEP_START_STEPS, completed)
        .expect("anchored");

    assert_eq!(authority.clock.due_at(ANCHOR), Some(start + 30 * MS));
    let frame = update.frame.expect("the anchor goes to every other relay");
    assert_eq!(frame.since_anchor_us, u64::try_from(us(HOP)).unwrap());
    assert_eq!(
        authority.clock_events(mark, false)[0],
        Some(FlightEvent::SessionClockAnchored {
            anchor_step: ANCHOR,
            adopted: false,
            start_backdate_us: Some(147_000),
            deciding_slot: Some(1),
        }),
    );
}

#[test]
fn a_session_on_one_relay_starts_when_its_last_turn_arrives() {
    let start = Instant::now();
    let completed = start + 177 * MS;
    // Both players homed here: one of them measured on another relay before it moved here, and a
    // sidecar from that relay still carrying it, changes nothing.
    let mut rehomed = authority_homing_slot_0(&[round_trip_us(HOP)]);
    rehomed.set_homed_slots([SlotId(0), SlotId(1)].into());
    // Both players sending conditions straight to this relay.
    let mut local = rollback(maker(), &[0, 1]);
    let _ = local.ingest_local(&conditions(0, 5_000, 0, 1));
    let _ = local.ingest_local(&conditions(1, 5_000, 0, 1));
    // No conditions from anyone yet.
    let unmeasured = rollback(maker(), &[0, 1]);

    for mut authority in [rehomed, local, unmeasured] {
        let _ = authority.note_forwarded_turns(SlotId(0), LOCKSTEP_START_STEPS, start);
        let _ = authority
            .note_forwarded_turns(SlotId(1), LOCKSTEP_START_STEPS, completed)
            .expect("anchored");
        assert_eq!(authority.clock.due_at(ANCHOR), Some(completed));
    }
}

#[test]
fn the_least_round_trip_sets_the_hop() {
    let start = Instant::now();
    // A queue on the backbone made most samples slower than the route.
    let mut authority = authority_homing_slot_0(&[400_000, round_trip_us(HOP), 350_000]);
    let _ = authority.note_forwarded_turns(SlotId(0), LOCKSTEP_START_STEPS, start);
    let _ = authority
        .note_forwarded_turns(SlotId(1), LOCKSTEP_START_STEPS, start + 177 * MS)
        .expect("anchored");
    assert_eq!(authority.clock.due_at(ANCHOR), Some(start + 30 * MS));
}

#[test]
fn no_players_start_lands_before_its_turn_reached_its_own_relay() {
    let start = Instant::now();
    let reached_home = start + 30 * MS;
    // The mesh round trip the authority sampled least, and the legs the two trips actually took:
    // routes slower one way than the other, and trips slowed by a queue the round trip the other
    // relay sampled as the copy arrived also includes.
    let cases = [
        // (least round trip, turn's leg to the authority, copy's leg back, round trip at the copy)
        (HOP * 2, HOP, HOP, HOP * 2),
        (HOP * 2, 100 * MS, 194 * MS, HOP * 2),
        (HOP * 2, 194 * MS, 100 * MS, HOP * 2),
        (HOP * 2, 250 * MS, 44 * MS, HOP * 2),
        (HOP * 2, 160 * MS, 160 * MS, 320 * MS),
        (HOP * 2, 200 * MS, 120 * MS, 320 * MS),
    ];
    for (least, there, back, at_copy) in cases {
        let mut authority = authority_homing_slot_0(&[round_trip_us(least / 2)]);
        let _ = authority.note_forwarded_turns(SlotId(0), LOCKSTEP_START_STEPS, start);
        let completed = reached_home + there;
        let frame = authority
            .note_forwarded_turns(SlotId(1), LOCKSTEP_START_STEPS, completed)
            .and_then(|update| update.frame)
            .expect("anchored");
        let mut relay = relay_homing_slot_1();
        let _ = relay.merge_session_clock(&frame, completed + back, round_trip_us(at_copy / 2));

        let case = (least, there, back, at_copy);
        assert!(
            authority.clock.due_at(ANCHOR).unwrap() >= start,
            "{case:?}: slot 0 is measured on the authority"
        );
        assert!(
            relay.clock.due_at(ANCHOR).unwrap() >= reached_home,
            "{case:?}: slot 1 is measured on its own relay"
        );
    }
}

/// Plays a session whose players' game loops run together, slot 0 homed on the authority and
/// slot 1 on the other relay, each turn of slot 1 reaching its relay 30 ms after slot 0's reached
/// the authority.
fn play_across_relays(mesh_rtts_us: &[u32]) -> AcrossRelays {
    let start = Instant::now();
    let slot_1_late = 30 * MS;
    let mut authority = authority_homing_slot_0(mesh_rtts_us);
    let mut relay = relay_homing_slot_1();

    let _ = authority.note_forwarded_turns(SlotId(0), LOCKSTEP_START_STEPS, start);
    let completed = start + slot_1_late + HOP;
    let frame = authority
        .note_forwarded_turns(SlotId(1), LOCKSTEP_START_STEPS, completed)
        .and_then(|update| update.frame)
        .expect("anchored");
    let _ = relay.merge_session_clock(&frame, completed + HOP, round_trip_us(HOP));

    for seq in LOCKSTEP_START_STEPS..LOCKSTEP_START_STEPS + 60 {
        let sent = start + steps(seq - ANCHOR);
        let _ = authority.note_lead_arrival(SlotId(0), seq, sent);
        let _ = authority.note_forwarded_turns(SlotId(0), seq + 1, sent);
        let _ = relay.note_lead_arrival(SlotId(1), seq, sent + slot_1_late);
        let at_authority = sent + slot_1_late + HOP;
        let _ = authority.note_forwarded_turns(SlotId(1), seq + 1, at_authority);
        let heartbeat = authority.session_clock_frame(at_authority).unwrap();
        let _ = relay.merge_session_clock(&heartbeat, at_authority + HOP, round_trip_us(HOP));
    }
    AcrossRelays {
        slot_0: authority.lead_report(SlotId(0)).unwrap(),
        slot_1: relay.lead_report(SlotId(1)).unwrap(),
        deadlines: (ANCHOR..=authority.clock.final_through().unwrap())
            .map(|seq| (seq, authority.clock.due_at(seq), relay.clock.due_at(seq)))
            .collect(),
    }
}

/// What [`play_across_relays`] ends with.
struct AcrossRelays {
    /// Slot 0's report, as the authority measured it.
    slot_0: LeadReport,
    /// Slot 1's report, as its own relay measured it.
    slot_1: LeadReport,
    /// Each step from the anchor through the authority's limit, with its deadline on the authority
    /// and on the other relay.
    deadlines: Vec<(u64, Option<Instant>, Option<Instant>)>,
}

#[test]
fn a_remote_player_measures_on_time_from_its_first_turns_and_copies_share_the_start() {
    let AcrossRelays {
        slot_0,
        slot_1,
        deadlines,
    } = play_across_relays(&[round_trip_us(HOP)]);
    assert_eq!((slot_1.median_us, slot_1.p90_us), (0, 0));
    assert_eq!((slot_0.median_us, slot_0.p90_us), (-30_000, -30_000));
    assert_eq!(slot_1.samples, u32::try_from(LEAD_WINDOW_TURNS).unwrap());
    for (seq, authority, relay) in deadlines {
        assert!(authority.is_some(), "seq {seq}");
        assert_eq!(authority, relay, "seq {seq}");
    }

    // Before the authority has heard the other relay's round trip it starts the clock as the turn
    // arrives, and both players read a hop early or more.
    let AcrossRelays { slot_0, slot_1, .. } = play_across_relays(&[]);
    assert_eq!(slot_1.median_us, -147_000);
    assert_eq!(slot_0.median_us, -177_000);
}

#[test]
fn a_hop_longer_than_the_slack_leaves_the_clock_running() {
    let start = Instant::now();
    let hop = Duration::from_millis(600);
    let mut authority = authority_homing_slot_0(&[round_trip_us(hop)]);
    let _ = authority.note_forwarded_turns(SlotId(0), LOCKSTEP_START_STEPS, start);
    let completed = start + 100 * MS + hop;
    let _ = authority
        .note_forwarded_turns(SlotId(1), LOCKSTEP_START_STEPS, completed)
        .expect("anchored");
    assert_eq!(
        authority.clock.due_at(ANCHOR),
        Some(completed - steps(STALL_SLACK_STEPS - 2)),
    );

    // Slot 1's next turn arrives a step later and the clock hasn't reached its limit.
    let _ = authority.note_forwarded_turns(SlotId(0), LOCKSTEP_START_STEPS + 1, start + STEP);
    let _ = authority.note_forwarded_turns(SlotId(1), LOCKSTEP_START_STEPS + 1, completed + STEP);
    assert_eq!(authority.clock.pause(), Duration::ZERO);
}

#[test]
fn an_observers_turns_have_no_say_in_the_start() {
    let start = Instant::now();
    let mut authority = rollback(
        DecisionMaker::new(
            key(),
            bounds(0, 20),
            law(),
            Authority::SelfRelay,
            [SlotId(2)].into(),
        ),
        &[0, 1, 2],
    );
    authority.set_homed_slots([SlotId(0)].into());
    let _ = authority.ingest_remote(&conditions(1, 50_000, 0, 1), round_trip_us(HOP));
    // The observer, homed elsewhere and never measured, completes its lockstep start last.
    let _ = authority.note_forwarded_turns(SlotId(0), LOCKSTEP_START_STEPS, start);
    let completed = start + 30 * MS + HOP;
    let _ = authority
        .note_forwarded_turns(SlotId(1), LOCKSTEP_START_STEPS, completed)
        .expect("anchored");
    let _ = authority.note_forwarded_turns(SlotId(2), LOCKSTEP_START_STEPS, completed + STEP);
    assert_eq!(authority.clock.due_at(ANCHOR), Some(start + 30 * MS));
}

#[test]
fn a_promoted_authority_anchoring_itself_moves_its_start_back_by_the_shortest_hop() {
    let start = Instant::now();
    // Both players are homed on other relays, one 100 ms away and one 60 ms.
    let mut promoted = rollback(peer_maker(), &[0, 1]);
    promoted.set_homed_slots([SlotId(2)].into());
    let _ = promoted.ingest_remote(&conditions(0, 50_000, 0, 1), 200_000);
    let _ = promoted.ingest_remote(&conditions(1, 50_000, 0, 1), 120_000);
    play_on_schedule(&mut promoted, &[0, 1], 100, start);
    let _ = promoted.set_authority(Authority::SelfRelay, &HashSet::new());
    let first = on_time(start, 100);
    assert_eq!(forward(&mut promoted, &[0, 1], 101, first), None);

    // When each player's newest confirmable turn reached its own relay isn't kept, so either may
    // have been there just a hop ago: the start moves back by the shorter one.
    let quiet = first + CLOCK_ANCHOR_QUIET;
    let mark = promoted.clock_mark();
    let _ = forward(&mut promoted, &[0, 1], 103, quiet).expect("anchored");
    assert_eq!(promoted.clock.due_at(102), Some(quiet - 60 * MS));
    assert_eq!(
        promoted.clock_events(mark, false)[0],
        Some(FlightEvent::SessionClockAnchored {
            anchor_step: ANCHOR,
            adopted: false,
            start_backdate_us: Some(60_000),
            deciding_slot: Some(1),
        }),
    );

    // A promoted authority homing one of the players anchors as that player's turn arrives.
    let mut homing = rollback(peer_maker(), &[0, 1]);
    homing.set_homed_slots([SlotId(0)].into());
    let _ = homing.ingest_remote(&conditions(1, 50_000, 0, 1), 120_000);
    play_on_schedule(&mut homing, &[0, 1], 100, start);
    let _ = homing.set_authority(Authority::SelfRelay, &HashSet::new());
    assert_eq!(forward(&mut homing, &[0, 1], 101, first), None);
    let _ = forward(&mut homing, &[0, 1], 103, quiet).expect("anchored");
    assert_eq!(homing.clock.due_at(102), Some(quiet));
}
