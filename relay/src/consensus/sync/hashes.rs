//! The comparator for rollback sessions, where clients strip native sync commands (they would hash
//! predicted state) and put a hash of a confirmed step's state on their turns instead. Step `n`
//! is the state once every slot's first `n` turns (`seq` 0 to `n - 1`) have run, so it is
//! confirmable once this relay has forwarded `n` turns of every required slot.
//!
//! A step is compared as soon as every required slot has reported it, or once its deadline has
//! passed: [`STATE_HASH_DEADLINE`] after the step became confirmable, meaning this relay had
//! forwarded every required slot's turn for it, so every honest client could have computed the
//! hash. The deadline is the relay's own observation; no client-sent count or stamp moves it.
//! Whenever the verdict can name who is at fault it does: the minority when the rest agree, and a
//! slot that kept sending turns without its report. A slot whose turns stopped soon after the
//! step is not blamed for a missing report, since its link went quiet and the leave machinery
//! settles it. When nobody can be singled out (a 1v1 that disagrees, an even split, nobody
//! reporting) the verdict names no one.

use super::*;
use crate::rate_limit::RateLimitedCounter;

/// Clients report every this many steps, from this step on. A step is the state once every
/// slot's first `step` turns have run.
pub(in crate::consensus) const STATE_HASH_INTERVAL: u64 = 8;

/// How long after a step became confirmable its reports are awaited before the slots still
/// missing are judged.
pub(in crate::consensus) const STATE_HASH_DEADLINE: Duration = Duration::from_secs(5);

/// How many of a slot's turns past a step this relay must have forwarded before a missing report
/// for the step counts against the slot: four seconds of turns. An honest client sends at most its
/// pipe (the latency buffer, up to [`rally_point_proto::control::GAME_SYNC_SAFE_BUFFER_MAX`], plus
/// up to a second of input delay) and its prediction limit past the newest step it has every turn
/// of, well under this, so one that got this far had the step's turns in hand long enough to
/// report it. Still short of what a slot sends before [`STATE_HASH_DEADLINE`].
pub(in crate::consensus) const STATE_HASH_LIVE_TURNS: u64 = 96;

/// The most report steps held in flight before the oldest is dropped unjudged. The deadline
/// resolves every step long before this in a live session; the bound only matters for one whose
/// turns stopped, where steps can go on being reported without ever becoming confirmable.
pub(in crate::consensus) const STATE_HASH_WINDOW: usize = 64;

/// One step's reports, and when it became confirmable.
#[derive(Debug, Default)]
struct PendingStep {
    reports: Vec<(SlotId, u64)>,
    confirmable_at: Option<Instant>,
}

/// The state hash comparator of one rollback session. Every relay serving the session keeps it,
/// so a promoted authority carries on where the old one stopped; only the authority judges.
#[derive(Debug, Default)]
pub(in crate::consensus) struct StateHashTracker {
    pending: BTreeMap<u64, PendingStep>,
    /// Each slot's count of turns this relay has forwarded without a gap.
    forwarded: HashMap<SlotId, u64>,
    /// The newest step that is confirmable: this relay has forwarded that many turns of every
    /// required slot.
    confirmable_until: u64,
    /// Every step before this one has been judged or dropped.
    retired_below: u64,
    /// Slots a verdict named; they take no further part.
    excluded: HashSet<SlotId>,
    /// Set once a verdict named nobody: with no majority to trust, nothing later is comparable.
    pub(in crate::consensus) dormant: bool,
    invalid_warns: RateLimitedCounter,
    conflict_warns: RateLimitedCounter,
    evict_warns: RateLimitedCounter,
}

impl StateHashTracker {
    /// Records `slot`'s report of `hash` for `step`. A report for a step that isn't on the report
    /// interval, was already judged, or is implausibly far past what is confirmable is dropped, and
    /// a second report of a step keeps the first.
    pub(in crate::consensus) fn record(
        &mut self,
        key: &SessionKey,
        slot: SlotId,
        step: u64,
        hash: u64,
    ) {
        if self.dormant || self.excluded.contains(&slot) {
            return;
        }
        let horizon = self
            .confirmable_until
            .saturating_add(STATE_HASH_WINDOW as u64 * STATE_HASH_INTERVAL);
        // A later step can be judged before an earlier one whose reports aren't all in, so a step
        // below `retired_below` still counts as open while it is pending.
        let judged = step < self.retired_below && !self.pending.contains_key(&step);
        let on_interval = step >= STATE_HASH_INTERVAL && step.is_multiple_of(STATE_HASH_INTERVAL);
        if !on_interval || judged || step > horizon {
            if self.invalid_warns.observe() {
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    step,
                    retired_below = self.retired_below,
                    horizon,
                    count = self.invalid_warns.count(),
                    "state hash report for a step that isn't on the report interval, was \
                     already judged, or can't be confirmed yet; ignoring it",
                );
            }
            return;
        }
        let pending = self.pending.entry(step).or_default();
        match pending.reports.iter().find(|x| x.0 == slot) {
            Some(&(_, existing)) if existing != hash => {
                if self.conflict_warns.observe() {
                    tracing::warn!(
                        tenant = key.tenant.as_ref(),
                        session = key.session.0,
                        slot = slot.0,
                        step,
                        count = self.conflict_warns.count(),
                        "slot reported two different state hashes for one step; keeping the first",
                    );
                }
            }
            Some(_) => {}
            None => pending.reports.push((slot, hash)),
        }
        self.evict_over_window(key);
    }

    /// Notes that this relay has forwarded `count` of `slot`'s turns without a gap, as of `now`,
    /// and starts the deadline of every report step that has become confirmable. `required` yields
    /// the slots whose turns a step needs. Runs for every forwarded turn, so it allocates nothing
    /// unless a step became confirmable.
    pub(in crate::consensus) fn note_forwarded(
        &mut self,
        key: &SessionKey,
        slot: SlotId,
        count: u64,
        now: Instant,
        required: impl Iterator<Item = SlotId>,
    ) {
        let entry = self.forwarded.entry(slot).or_default();
        *entry = (*entry).max(count);
        let until = required
            .filter(|slot| !self.excluded.contains(slot))
            .map(|slot| self.forwarded.get(&slot).copied().unwrap_or(0))
            .min()
            .unwrap_or(0);
        if until <= self.confirmable_until {
            return;
        }
        let first = (self.confirmable_until + 1)
            .next_multiple_of(STATE_HASH_INTERVAL)
            .max(STATE_HASH_INTERVAL)
            .max(self.retired_below);
        let mut step = first;
        while step <= until {
            self.pending
                .entry(step)
                .or_default()
                .confirmable_at
                .get_or_insert(now);
            step += STATE_HASH_INTERVAL;
        }
        self.confirmable_until = until;
        self.evict_over_window(key);
    }

    /// Judges every step whose reports are all in, or whose deadline has passed by `now`, oldest
    /// first, and returns the verdicts that named anyone. `required` yields the slots whose
    /// reports a step needs.
    pub(in crate::consensus) fn judge_ready(
        &mut self,
        now: Instant,
        required: impl Iterator<Item = SlotId>,
    ) -> Vec<SyncDivergence> {
        let required: HashSet<SlotId> = required.collect();
        let required = &required;
        let mut verdicts = Vec::new();
        while !self.dormant {
            // A step is judged only once it is confirmable here too, so every reported hash is
            // of a step whose turns this relay has seen.
            let ready = self.pending.iter().find(|(_, pending)| {
                let Some(confirmable_at) = pending.confirmable_at else {
                    return false;
                };
                let complete = required
                    .iter()
                    .filter(|slot| !self.excluded.contains(slot))
                    .all(|slot| pending.reports.iter().any(|x| x.0 == *slot));
                complete || now.saturating_duration_since(confirmable_at) >= STATE_HASH_DEADLINE
            });
            let Some(step) = ready.map(|(&step, _)| step) else {
                break;
            };
            let pending = self.pending.remove(&step).unwrap_or_default();
            self.retired_below = self.retired_below.max(step + 1);
            if let Some(verdict) = self.judge(step, &pending.reports, required) {
                verdicts.push(verdict);
            }
        }
        verdicts
    }

    /// Judges one step's reports.
    fn judge(
        &mut self,
        step: u64,
        reports: &[(SlotId, u64)],
        required: &HashSet<SlotId>,
    ) -> Option<SyncDivergence> {
        let reports: Vec<(SlotId, u64)> = reports
            .iter()
            .copied()
            .filter(|(slot, _)| required.contains(slot) && !self.excluded.contains(slot))
            .collect();
        // A slot that sent no report is at fault only if it kept sending turns well past the step.
        let mut missing: Vec<SlotId> = required
            .iter()
            .copied()
            .filter(|slot| !self.excluded.contains(slot))
            .filter(|slot| !reports.iter().any(|x| x.0 == *slot))
            .filter(|slot| {
                self.forwarded.get(slot).copied().unwrap_or(0)
                    >= step.saturating_add(STATE_HASH_LIVE_TURNS)
            })
            .collect();
        missing.sort_unstable();
        let agreed = reports.windows(2).all(|pair| pair[0].1 == pair[1].1);
        if agreed && missing.is_empty() {
            return None;
        }
        let mut groups: HashMap<u64, Vec<SlotId>> = HashMap::new();
        for &(slot, hash) in &reports {
            groups.entry(hash).or_default().push(slot);
        }
        let majority = groups
            .values()
            .find(|slots| slots.len() * 2 > reports.len())
            .cloned();
        let Some(majority) = majority else {
            // Nobody to trust: a 1v1 that disagrees, an even split, or nobody reporting at all.
            self.dormant = true;
            return Some(SyncDivergence {
                sync_ordinal: step,
                game_frame: None,
                no_majority: true,
                diverged: Vec::new(),
                missing,
            });
        };
        let mut diverged: Vec<SlotId> = reports
            .iter()
            .map(|x| x.0)
            .filter(|slot| !majority.contains(slot))
            .collect();
        diverged.sort_unstable();
        for slot in diverged.iter().chain(&missing) {
            self.excluded.insert(*slot);
        }
        if required
            .iter()
            .filter(|x| !self.excluded.contains(x))
            .count()
            < 2
        {
            self.dormant = true;
        }
        Some(SyncDivergence {
            sync_ordinal: step,
            game_frame: None,
            no_majority: false,
            diverged,
            missing,
        })
    }

    /// Drops the oldest steps while more than [`STATE_HASH_WINDOW`] are in flight.
    fn evict_over_window(&mut self, key: &SessionKey) {
        while self.pending.len() > STATE_HASH_WINDOW {
            let Some((step, _)) = self.pending.pop_first() else {
                return;
            };
            self.retired_below = self.retired_below.max(step + 1);
            if self.evict_warns.observe() {
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    step,
                    count = self.evict_warns.count(),
                    "state hash step dropped unjudged; its turns never all arrived",
                );
            }
        }
    }
}
