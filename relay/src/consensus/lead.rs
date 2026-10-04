//! How late each of this relay's home slots' turns have been arriving against the session clock,
//! and the `LeadReport`s made from it.
//!
//! Every turn a home slot sends is measured once, at its first arrival on this relay's client edge
//! — including turns that arrive together in a catch-up burst, because a turn that arrived in a
//! burst arrived late. A slot's window is its last [`LEAD_WINDOW_TURNS`] turns, and it gets a
//! report every [`LEAD_REPORT_EVERY`] turns. The turn path never allocates: each slot's window is a
//! fixed ring, and a report is computed on the stack.
//!
//! Each slot also keeps what the flight recorder's sample rows read: the interval's turn and
//! report counts and its worst lateness, taken (and reset) by each sample, and a cumulative
//! histogram of every turn's lateness. All fixed-size, so the turn path stays allocation-free.
//!
//! When the clock stops, every window starts over. A turn measured around a stop can have been
//! measured against the clock from before it (on the authority, a turn that arrived just before the
//! one that moved the clock; on another relay, any turn that arrived before the authority's frame
//! did), and it would read as late by the whole stop. The report sent with the stop carries no
//! lateness at all, only the stop.

use super::*;

use crate::observability::events::{
    LEAD_LATENESS_BUCKET_BOUNDS_MS, LEAD_LATENESS_BUCKETS, LeadReportRecord, SlotLeadSample,
};

/// How many of a slot's newest turns a report covers: one second.
pub(in crate::consensus) const LEAD_WINDOW_TURNS: usize = 24;

/// How many turns go between a slot's reports: half a second.
pub(in crate::consensus) const LEAD_REPORT_EVERY: u64 = 12;

/// How far below a slot's newest seq a turn can still be told apart from a repeat: about five
/// seconds of turns. Turns arrive out of order, so a turn first arriving after a newer one is a
/// late arrival like any other and is measured; one this far behind can't be told from a copy of
/// a turn already measured (a resume replay on a new link), and is skipped.
const LEAD_SEEN_SEQS: u64 = u128::BITS as u64;

/// The bucket of [`LEAD_LATENESS_BUCKET_BOUNDS_MS`] a turn `lateness_us` late falls in: the first
/// whose bound it does not exceed, or the one past the last bound.
fn lateness_bucket(lateness_us: i32) -> usize {
    LEAD_LATENESS_BUCKET_BOUNDS_MS
        .iter()
        .take_while(|&&bound_ms| i64::from(lateness_us) > i64::from(bound_ms) * 1_000)
        .count()
}

/// What one slot's measurements added up to since the flight recorder last sampled them.
#[derive(Debug, Default)]
struct LeadInterval {
    /// Turns measured.
    turns: u32,
    /// Reports made, each one due and each one a clock stop forced.
    reports: u32,
    /// The highest p90 among the reports that carried any lateness.
    max_p90_us: Option<i32>,
    /// The latest any single turn arrived.
    max_lateness_us: Option<i32>,
}

/// One home slot's measurements.
#[derive(Debug)]
struct SlotLead {
    /// The newest seq measured.
    newest: u64,
    /// Which of the [`LEAD_SEEN_SEQS`] seqs up to `newest` were measured: bit `i` is seq
    /// `newest - i`. A seq whose bit is set is a copy of a turn already measured.
    seen: u128,
    /// The lateness of the newest turns, in microseconds, as a ring.
    window: [i32; LEAD_WINDOW_TURNS],
    len: usize,
    next: usize,
    /// The seq at or past which the next report is due.
    report_at: u64,
    /// The turns and reports since the flight recorder last sampled this slot.
    interval: LeadInterval,
    /// The newest report made.
    last_report: Option<LeadReportRecord>,
    /// Every turn measured, by lateness, in the buckets of [`LEAD_LATENESS_BUCKET_BOUNDS_MS`].
    histogram: [u64; LEAD_LATENESS_BUCKETS],
}

impl SlotLead {
    fn new(seq: u64) -> Self {
        Self {
            newest: seq,
            seen: 1,
            window: [0; LEAD_WINDOW_TURNS],
            len: 0,
            next: 0,
            report_at: seq,
            interval: LeadInterval::default(),
            last_report: None,
            histogram: [0; LEAD_LATENESS_BUCKETS],
        }
    }

    /// Marks `seq` measured, returning `false` when it already was or is too far behind the newest
    /// seq to tell.
    fn mark(&mut self, seq: u64) -> bool {
        if seq > self.newest {
            let ahead = seq - self.newest;
            self.seen = if ahead >= LEAD_SEEN_SEQS {
                0
            } else {
                self.seen << ahead
            };
            self.seen |= 1;
            self.newest = seq;
            return true;
        }
        let behind = self.newest - seq;
        if behind >= LEAD_SEEN_SEQS || self.seen & (1 << behind) != 0 {
            return false;
        }
        self.seen |= 1 << behind;
        true
    }

    fn push(&mut self, lateness_us: i32) {
        self.window[self.next] = lateness_us;
        self.next = (self.next + 1) % LEAD_WINDOW_TURNS;
        self.len = (self.len + 1).min(LEAD_WINDOW_TURNS);
        self.interval.turns = self.interval.turns.saturating_add(1);
        self.interval.max_lateness_us = self.interval.max_lateness_us.max(Some(lateness_us));
        self.histogram[lateness_bucket(lateness_us)] += 1;
    }

    /// Makes the slot's report (see [`report`](Self::report)) to send it, counting it toward the
    /// flight recorder's figures.
    fn make_report(&mut self, pause: Duration) -> LeadReport {
        let report = self.report(pause);
        self.interval.reports = self.interval.reports.saturating_add(1);
        if report.samples > 0 {
            self.interval.max_p90_us = self.interval.max_p90_us.max(Some(report.p90_us));
        }
        self.last_report = Some(LeadReportRecord::from(&report));
        report
    }

    /// The slot's figures for the flight recorder, starting the next interval.
    fn take_sample(&mut self) -> SlotLeadSample {
        let interval = std::mem::take(&mut self.interval);
        SlotLeadSample {
            turns: interval.turns,
            reports: interval.reports,
            last_report: self.last_report,
            max_p90_us: interval.max_p90_us,
            max_lateness_us: interval.max_lateness_us,
            lateness_histogram: self.histogram.to_vec(),
        }
    }

    fn restart(&mut self) {
        self.len = 0;
        self.next = 0;
    }

    /// The slot's report: its window's figures, or none (`samples` of 0) when the window has just
    /// started over, with the clock's stopped time either way.
    fn report(&self, pause: Duration) -> LeadReport {
        let mut sorted = self.window;
        let sorted = &mut sorted[..self.len];
        sorted.sort_unstable();
        let (median_us, p90_us) = match self.len {
            0 => (0, 0),
            len => (sorted[len / 2], sorted[(len * 9).div_ceil(10) - 1]),
        };
        LeadReport {
            through_step: self.newest,
            median_us,
            p90_us,
            samples: self.len as u32,
            pause_us: u64::try_from(pause.as_micros()).unwrap_or(u64::MAX),
        }
    }
}

/// The measurements of every home slot this relay has measured.
#[derive(Debug, Default)]
pub(in crate::consensus) struct LeadTracker {
    slots: HashMap<SlotId, SlotLead>,
}

impl LeadTracker {
    /// Measures `slot`'s turn with seq `seq`, `lateness_us` late, and returns the slot's report
    /// when one is due. `pause` is the clock's stopped time, which every report carries.
    pub(in crate::consensus) fn note(
        &mut self,
        slot: SlotId,
        seq: u64,
        lateness_us: i64,
        pause: Duration,
    ) -> Option<LeadReport> {
        let lead = match self.slots.entry(slot) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                let lead = entry.into_mut();
                if !lead.mark(seq) {
                    return None;
                }
                lead
            }
            std::collections::hash_map::Entry::Vacant(entry) => entry.insert(SlotLead::new(seq)),
        };
        lead.push(lateness_us.clamp(i32::MIN.into(), i32::MAX.into()) as i32);
        // Due by the newest seq, so a late turn filling a gap below it is measured without
        // bringing a report forward.
        if lead.newest < lead.report_at {
            return None;
        }
        lead.report_at = lead.newest + LEAD_REPORT_EVERY;
        Some(lead.make_report(pause))
    }

    /// `slot`'s current report, if it has been measured at all.
    pub(in crate::consensus) fn report(&self, slot: SlotId, pause: Duration) -> Option<LeadReport> {
        Some(self.slots.get(&slot)?.report(pause))
    }

    /// Starts every measured slot's window over because the clock stopped for longer, returning
    /// each slot's report carrying the new stopped time and no lateness.
    pub(in crate::consensus) fn restart(&mut self, pause: Duration) -> Vec<(SlotId, LeadReport)> {
        self.slots
            .iter_mut()
            .map(|(&slot, lead)| {
                lead.restart();
                (slot, lead.make_report(pause))
            })
            .collect()
    }

    /// Every measured slot's figures for the flight recorder's sample row, by slot id, each slot
    /// starting its next interval.
    pub(in crate::consensus) fn take_samples(&mut self) -> Vec<(u8, SlotLeadSample)> {
        let mut samples: Vec<_> = self
            .slots
            .iter_mut()
            .map(|(slot, lead)| (slot.0, lead.take_sample()))
            .collect();
        samples.sort_unstable_by_key(|&(slot, _)| slot);
        samples
    }
}
