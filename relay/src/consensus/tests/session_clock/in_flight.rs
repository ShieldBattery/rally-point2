//! Turns measured against their deadlines as they stood when the turns arrived: stopped time that
//! came after a turn's arrival doesn't count against it, and stopped time before it does. A turn
//! already on its way when the clock stopped reads the lead it was sent with, while a player the
//! clock stood waiting for reads every moment of the wait, on the authority or a mesh hop from it.

use super::*;

#[test]
fn a_turn_in_flight_across_a_stop_reads_the_lead_it_arrived_with() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], 100, start);
    let limit = 99 + STALL_SLACK_STEPS;
    let stopped_at = on_time(start, limit);
    // Slot 0 runs 100 ms ahead of the clock, so its turns for the two steps past the limit reach
    // this relay before the clock gets there. Nothing of it has been measured yet.
    for seq in [limit + 1, limit + 2] {
        let arrived = on_time(start, seq) - 100 * MS;
        assert!(arrived < stopped_at);
        assert_eq!(m.note_lead_arrival(SlotId(0), seq, arrived), None);
    }

    // Then slot 1 goes silent, and the clock stands at its limit for twenty seconds.
    let resumed = stopped_at + Duration::from_secs(20);
    let update = forward(&mut m, &[0, 1], 101, resumed).expect("stopped");
    assert_eq!(update.reports.len(), 1);
    let (slot, report) = update.reports[0];
    assert_eq!(slot, SlotId(0));
    assert_eq!(report.pause_us, 20_000_000);
    assert_eq!((report.through_step, report.samples), (limit + 1, 1));
    assert_eq!(
        (report.median_us, report.p90_us),
        (-100_000, -100_000),
        "the stop came after the turn arrived, so it reads its lead, not twenty seconds early",
    );
    let _ = forward(&mut m, &[0, 1], 102, resumed + STEP);
    let report = m.lead_report(SlotId(0)).unwrap();
    assert_eq!(
        (report.through_step, report.samples, report.median_us),
        (limit + 2, 2, -100_000)
    );
}

#[test]
fn a_late_turn_the_clock_stood_waiting_for_reads_the_whole_wait() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], 100, start);
    let limit = 99 + STALL_SLACK_STEPS;
    let stopped_at = on_time(start, limit);
    // Slot 0 keeps to the schedule; slot 1, homed here, stalls, and the clock stands at its limit
    // waiting for it until its turns come in a burst half a second later.
    let _ = m.note_forwarded_turns(SlotId(0), 101, on_time(start, 100));
    let burst = stopped_at + 500 * MS;
    let update = m
        .note_forwarded_turns(SlotId(1), 101, burst)
        .expect("stopped");
    assert!(update.frame.is_some());
    let first = m
        .note_lead_arrival(SlotId(1), 100, burst)
        .expect("a slot's first measured turn reports");
    assert_eq!(
        first.p90_us,
        i32::try_from(us(steps(5) + 500 * MS)).unwrap(),
        "the slack it ran into and every moment the clock stood waiting for it",
    );
    for seq in 101..=limit {
        let _ = m.note_lead_arrival(SlotId(1), seq, burst);
    }
    // Lateness in ms: 710, 668, 626, 584, 542, 500.
    let report = m.lead_report(SlotId(1)).unwrap();
    assert_eq!(report.samples, 6);
    assert_eq!((report.median_us, report.p90_us), (626_000, 710_000));
}

/// How far ahead of the clock the slots that follow it send their turns.
const FOLLOWER_LEAD_STEPS: u64 = 3;

/// The seq a slot following the clock sends as the clock reaches the deadline of `step`.
fn followers_seq(step: u64) -> u64 {
    step + FOLLOWER_LEAD_STEPS
}

#[test]
fn a_slot_stopping_the_clock_every_step_reads_late_and_its_stops_dont_read_others_early() {
    let start = Instant::now();
    let mut m = rollback(maker(), &[0, 1]);
    play_on_schedule(&mut m, &[0, 1], LOCKSTEP_START_STEPS, start);
    // Slot 0's turns come two steps apart, from twenty steps behind: the clock reaches its limit
    // before every one of them and stands still a step each time, running at half speed. Slot 1
    // follows the clock exactly, sending each turn three steps of the clock ahead of its deadline.
    // Both are homed here.
    let first = LOCKSTEP_START_STEPS + 1;
    let last = LOCKSTEP_START_STEPS + 300;
    let mut reports: Vec<(SlotId, LeadReport)> = Vec::new();
    let mut stops = 0;
    let mut next = LOCKSTEP_START_STEPS;
    for count in first..=last {
        let at = on_time(start, count - 1) + steps(20) + steps(count - first);
        // Every turn slot 1 sent before slot 0's turn arrives: one each time the clock reaches a
        // deadline, none while it stands at its limit.
        while let Some(sent) = m
            .clock
            .due_at(next - FOLLOWER_LEAD_STEPS)
            .or((next <= followers_seq(ANCHOR)).then_some(start))
            .filter(|&sent| sent <= at)
        {
            if let Some(update) = m.note_forwarded_turns(SlotId(1), next + 1, sent) {
                reports.extend(update.reports);
            }
            reports.extend(
                m.note_lead_arrival(SlotId(1), next, sent)
                    .map(|report| (SlotId(1), report)),
            );
            next += 1;
        }
        if let Some(update) = m.note_forwarded_turns(SlotId(0), count, at) {
            stops += usize::from(update.frame.is_some());
            reports.extend(update.reports);
        }
        reports.extend(
            m.note_lead_arrival(SlotId(0), count - 1, at)
                .map(|report| (SlotId(0), report)),
        );
    }

    assert_eq!(stops, usize::try_from(last - first + 1).unwrap());
    let steady = |slot: u8| -> Vec<LeadReport> {
        reports
            .iter()
            .filter(|&&(s, report)| s == SlotId(slot) && report.through_step > ANCHOR + 60)
            .map(|&(_, report)| report)
            .collect()
    };
    // Slot 0 reads as late as the slack lets the clock run ahead of its turns, plus the step the
    // clock stood still at each of those deadlines and the one it stood waiting for the turn
    // itself, in every report: a full window each time, so its pacing always has a reading.
    let gating = steady(0);
    assert!(gating.len() > 200, "{} reports", gating.len());
    let late = i32::try_from(us(steps(STALL_SLACK_STEPS - 1) + steps(STALL_SLACK_STEPS))).unwrap();
    for report in gating {
        assert_eq!(usize::try_from(report.samples).unwrap(), LEAD_WINDOW_TURNS);
        assert_eq!((report.median_us, report.p90_us), (late, late));
    }
    // Slot 1's turns read the three steps of the clock it sent them ahead by. The stops slot 0
    // makes between a turn's arrival and its deadline move that deadline, but came after the turn
    // arrived.
    let following = steady(1);
    assert!(following.len() > 200, "{} reports", following.len());
    let ahead = -i32::try_from(us(steps(FOLLOWER_LEAD_STEPS))).unwrap();
    for report in following {
        assert_eq!(usize::try_from(report.samples).unwrap(), LEAD_WINDOW_TURNS);
        assert_eq!((report.median_us, report.p90_us), (ahead, ahead));
    }
}

/// How long after `from` the instant `to` is, in microseconds, negative when it is before.
fn signed_us(from: Instant, to: Instant) -> i64 {
    match to.checked_duration_since(from) {
        Some(after) => us(after),
        None => -us(from - to),
    }
}

/// One way across the mesh between the authority and the other relay.
const HOP: Duration = Duration::from_millis(40);

/// How often the authority sends its copy of the clock, stopped or not.
const HEARTBEAT: Duration = Duration::from_millis(250);

/// What happens next in a [`Mesh`].
enum Event {
    /// A turn of a slot homed on the other relay reaches it.
    AtHome { slot: u8, seq: u64 },
    /// A turn reaches the authority.
    AtAuthority { slot: u8, seq: u64 },
    /// A copy of the authority's clock reaches the other relay.
    Copy(SessionClockFrame),
    /// The authority sends its copy on its heartbeat.
    Heartbeat,
}

/// A session over two relays a [`HOP`] apart: the authority, homing slot 1, and the relay homing
/// every other slot, which measures them against the copies of the clock it gets.
struct Mesh {
    authority: DecisionMaker,
    home: DecisionMaker,
    /// By when each happens, in the order they were scheduled.
    events: BTreeMap<(Instant, u64), Event>,
    scheduled: u64,
    /// When the session ends: no heartbeat is sent past it.
    end: Instant,
    /// Slot 2 follows the clock: its next seq, and whether that turn is on its way.
    follower: Option<(u64, bool)>,
    /// Every report the other relay made.
    reports: Vec<(SlotId, LeadReport)>,
}

impl Mesh {
    /// The session of `slots`, its lockstep start completing on the authority at `start` and its
    /// slots homed on the other relay sending every turn of it then.
    fn new(slots: &[u8], start: Instant, end: Instant) -> Self {
        let mut authority = rollback(maker(), slots);
        authority.set_homed_slots([SlotId(1)].into());
        let mut home = rollback(peer_maker(), slots);
        home.set_homed_slots(
            slots
                .iter()
                .filter(|&&slot| slot != 1)
                .map(|&slot| SlotId(slot))
                .collect(),
        );
        let anchor = forward(&mut authority, slots, LOCKSTEP_START_STEPS, start)
            .and_then(|update| update.frame)
            .expect("anchored");
        let mut mesh = Self {
            authority,
            home,
            events: BTreeMap::new(),
            scheduled: 0,
            end,
            follower: None,
            reports: Vec::new(),
        };
        mesh.schedule(start + HOP, Event::Copy(anchor));
        mesh.schedule(start + HEARTBEAT, Event::Heartbeat);
        mesh
    }

    fn schedule(&mut self, at: Instant, event: Event) {
        self.events.insert((at, self.scheduled), event);
        self.scheduled += 1;
    }

    /// `slot`'s turn `seq` reaches its relay at `at`.
    fn turn(&mut self, slot: u8, seq: u64, at: Instant) {
        let event = if slot == 1 {
            Event::AtAuthority { slot, seq }
        } else {
            Event::AtHome { slot, seq }
        };
        self.schedule(at, event);
    }

    /// Has slot 2 follow the clock from seq `next`, sending each turn as the clock reaches the
    /// deadline [`FOLLOWER_LEAD_STEPS`] before its step.
    fn follow_the_clock(&mut self, next: u64) {
        self.follower = Some((next, false));
    }

    /// Plays every event in order.
    fn run(&mut self) {
        while let Some(((at, _), event)) = self.events.pop_first() {
            match event {
                Event::AtHome { slot, seq } => {
                    self.reports.extend(
                        self.home
                            .note_lead_arrival(SlotId(slot), seq, at)
                            .map(|report| (SlotId(slot), report)),
                    );
                    self.schedule(at + HOP, Event::AtAuthority { slot, seq });
                    if slot == 2 && self.follower == Some((seq, true)) {
                        self.follower = Some((seq + 1, false));
                    }
                }
                Event::AtAuthority { slot, seq } => {
                    if let Some(frame) = self
                        .authority
                        .note_forwarded_turns(SlotId(slot), seq + 1, at)
                        .and_then(|update| update.frame)
                    {
                        self.schedule(at + HOP, Event::Copy(frame));
                    }
                }
                Event::Copy(frame) => {
                    let rtt_us = u32::try_from(us(HOP * 2)).unwrap();
                    self.reports
                        .extend(self.home.merge_session_clock(&frame, at, rtt_us));
                }
                Event::Heartbeat => {
                    let frame = self.authority.session_clock_frame(at).unwrap();
                    self.schedule(at + HOP, Event::Copy(frame));
                    if at + HEARTBEAT <= self.end {
                        self.schedule(at + HEARTBEAT, Event::Heartbeat);
                    }
                }
            }
            // The follower sends its next turn as the clock reaches the deadline it leads, which
            // is known once the authority holds that deadline final.
            if let Some((next, false)) = self.follower
                && let Some(due) = self.authority.clock.due_at(next - FOLLOWER_LEAD_STEPS)
            {
                self.follower = Some((next, true));
                self.turn(2, next, due.max(at));
            }
        }
    }

    /// `slot`'s reports through steps in `steps`.
    fn reports_through(&self, slot: u8, steps: std::ops::RangeInclusive<u64>) -> Vec<LeadReport> {
        self.reports
            .iter()
            .filter(|&&(s, report)| s == SlotId(slot) && steps.contains(&report.through_step))
            .map(|&(_, report)| report)
            .collect()
    }
}

#[test]
fn a_turn_in_flight_across_a_stop_reads_its_lead_a_hop_from_the_authority() {
    let start = Instant::now();
    let limit = 99 + STALL_SLACK_STEPS;
    let stopped_at = on_time(start, limit);
    let resumed = stopped_at + Duration::from_secs(20);
    let mut mesh = Mesh::new(&[0, 1], start, resumed + Duration::from_secs(2));
    // Slot 1, on the authority, keeps to the schedule through seq 99, then goes silent for twenty
    // seconds. Slot 0, a hop away, runs 200 ms ahead of the clock, and its last three turns 150 ms
    // ahead, all of them reaching its relay before the clock reaches its limit.
    for seq in LOCKSTEP_START_STEPS..=99 {
        mesh.turn(1, seq, on_time(start, seq));
    }
    for seq in 100..=115 {
        mesh.turn(1, seq, resumed + steps(seq - 100));
    }
    for seq in LOCKSTEP_START_STEPS..=limit {
        mesh.turn(0, seq, on_time(start, seq) - 200 * MS);
    }
    for seq in limit + 1..=limit + 3 {
        let arrived = on_time(start, seq) - 150 * MS;
        assert!(arrived < stopped_at);
        mesh.turn(0, seq, arrived);
    }
    mesh.run();

    assert_eq!(mesh.home.clock.pause(), Duration::from_secs(20));
    let report = mesh.home.lead_report(SlotId(0)).unwrap();
    assert_eq!((report.through_step, report.samples), (limit + 3, 24));
    // The three turns that left last are the window's latest, the stop that came after they
    // arrived moving none of them twenty seconds early.
    assert_eq!((report.median_us, report.p90_us), (-200_000, -150_000));
}

#[test]
fn a_slot_a_hop_away_stopping_the_clock_every_step_reads_late_and_reads_others_on_time() {
    let start = Instant::now();
    let behind = steps(20);
    // Slot 0, a hop from the authority, sends its turns two steps apart from twenty steps behind,
    // through seq `last`, then stalls for a second and sends the next ten at once.
    let first = LOCKSTEP_START_STEPS;
    let last = LOCKSTEP_START_STEPS + 200;
    let arrives = |seq: u64| on_time(start, seq) + behind + steps(seq - first);
    let burst = arrives(last) + Duration::from_secs(1);
    let mut mesh = Mesh::new(&[0, 1, 2], start, burst + Duration::from_secs(2));
    for seq in first..=last {
        mesh.turn(0, seq, arrives(seq));
    }
    for seq in last + 1..=last + 10 {
        mesh.turn(0, seq, burst);
    }
    // Slot 1, on the authority, keeps far ahead of the clock. Slot 2, homed with slot 0, follows
    // the clock three steps ahead.
    for seq in first..=last + 40 {
        mesh.turn(1, seq, on_time(start, seq));
    }
    for seq in first..=followers_seq(ANCHOR) {
        mesh.turn(2, seq, start);
    }
    mesh.follow_the_clock(followers_seq(ANCHOR) + 1);
    mesh.run();

    // Slot 0 reads as late as it would on the authority, less the hop its turns take to get there,
    // in a full window every time.
    let gating = mesh.reports_through(0, ANCHOR + 60..=last);
    assert!(gating.len() > 100, "{} reports", gating.len());
    let late = i32::try_from(us(
        steps(STALL_SLACK_STEPS - 1) + steps(STALL_SLACK_STEPS) - HOP
    ))
    .unwrap();
    for report in gating {
        assert_eq!(usize::try_from(report.samples).unwrap(), LEAD_WINDOW_TURNS);
        assert_eq!((report.median_us, report.p90_us), (late, late));
    }
    // The burst. The clock stood at the limit seq `last` left it at until the burst reached the
    // authority, a hop after reaching slot 0's relay. Its turns up to that limit read every moment
    // of the wait until they arrived, as they always did.
    let limit = last + STALL_SLACK_STEPS;
    let clock = &mesh.home.clock;
    let final_lateness = |seq: u64| signed_us(clock.due_at(seq).expect("final"), burst);
    for seq in last + 1..=limit {
        let lateness = clock.lateness_us(seq, burst).unwrap();
        assert_eq!(lateness, final_lateness(seq), "seq {seq}");
        assert!(
            lateness >= us(Duration::from_secs(1) - HOP - STEP),
            "seq {seq}: {lateness}"
        );
    }
    // Those past it arrived while the clock still stood there, and read as early as their steps
    // are past it: a hop later than against their final deadlines, which take in the hop the stop
    // went on for after they arrived. That is the most the hop can move a reading, and only ever
    // later.
    for seq in limit + 1..=last + 10 {
        let lateness = clock.lateness_us(seq, burst).unwrap();
        assert_eq!(lateness, -us(steps(seq - limit)), "seq {seq}");
        assert_eq!(final_lateness(seq), lateness - us(HOP), "seq {seq}");
    }

    // Slot 2 reads the three steps of the clock it sends its turns ahead by: each stop is placed on
    // the other relay where it fell on the authority, so one that came after a turn arrived moves
    // nothing that turn reads.
    let following = mesh.reports_through(2, ANCHOR + 60..=last);
    assert!(following.len() > 100, "{} reports", following.len());
    let ahead = -i32::try_from(us(steps(FOLLOWER_LEAD_STEPS))).unwrap();
    for report in following {
        assert_eq!(usize::try_from(report.samples).unwrap(), LEAD_WINDOW_TURNS);
        assert_eq!((report.median_us, report.p90_us), (ahead, ahead));
    }
}
