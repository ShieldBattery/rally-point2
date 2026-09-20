//! The comparator fold: placing each slot's sync report at its true ordinal,
//! evaluating an ordinal once the frontier clears the margin, and naming the
//! diverged minority.

use super::*;

impl SyncTracker {
    /// Records one sync report whose transport-ordered origin stream assigned
    /// it `ordinal`. `kind` must be [`SYNC_KIND_UNITS`] or
    /// [`SYNC_KIND_HEADER`]; anything else is malformed and skipped before it
    /// can affect membership or pending comparisons.
    pub(in crate::consensus) fn record(
        &mut self,
        key: &SessionKey,
        slot: SlotId,
        ordinal: u64,
        report: SyncReport,
        skipped: Option<SyncGap>,
        margin: u64,
    ) -> Option<SyncDivergence> {
        let SyncReport { kind, value, .. } = report;
        if self.excluded.contains(&slot) {
            return None;
        }
        if kind != SYNC_KIND_UNITS && kind != SYNC_KIND_HEADER {
            if self.malformed_kind_warns.observe() {
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    slot = slot.0,
                    kind,
                    count = self.malformed_kind_warns.count(),
                    "sync command's hash-kind nibble is neither 1 nor 2; \
                     skipping this report as malformed",
                );
            }
            return None;
        }
        // A freshly reset comparator can begin after a long-running session.
        // Anchor it at the first canonical ordinal rather than retiring every
        // nonexistent ordinal from zero. `initialized` stays set after later
        // departures, so an empty compare set never rewinds established progress.
        if !self.initialized {
            self.initialized = true;
            self.base_ordinal = ordinal;
        }
        let next_expected = ordinal.saturating_add(1);
        let member = self.members.entry(slot).or_insert(Member {
            next_expected,
            since: ordinal,
        });
        member.next_expected = member.next_expected.max(next_expected);
        let since = member.since;
        if ordinal < self.base_ordinal {
            // The ordered source can retain a report whose comparison interval
            // already retired before this relay became authority. Keep the
            // member's forward progress, but never resurrect that interval.
            return None;
        }
        if let Some(skipped) = skipped {
            self.record_skipped(slot, since, skipped);
        }
        match self.pending.entry(ordinal).or_default().entry(slot) {
            std::collections::hash_map::Entry::Occupied(existing) => match existing.get() {
                SyncObservation::Report(existing) if existing.value != value => {
                    if self.duplicate_warns.observe() {
                        tracing::warn!(
                            tenant = key.tenant.as_ref(),
                            session = key.session.0,
                            slot = slot.0,
                            ordinal,
                            count = self.duplicate_warns.count(),
                            "conflicting sync value for a slot already reported \
                             at this ordinal; keeping the first",
                        );
                    }
                }
                SyncObservation::Skipped => {
                    // Validated per-origin monotone ordering makes a report after
                    // a recorded omission unreachable; retain this guard defensively.
                    if self.duplicate_warns.observe() {
                        tracing::warn!(
                            tenant = key.tenant.as_ref(),
                            session = key.session.0,
                            slot = slot.0,
                            ordinal,
                            count = self.duplicate_warns.count(),
                            "checksum report arrived after this origin asserted the generation was omitted; \
                             keeping the omission",
                        );
                    }
                }
                SyncObservation::Report(_) => {}
            },
            std::collections::hash_map::Entry::Vacant(vacant) => {
                vacant.insert(SyncObservation::Report(report));
            }
        }
        if let Some(divergence) = self.evaluate_ready(key, margin) {
            return Some(divergence);
        }
        self.evict_over_window(key);
        None
    }

    fn record_skipped(&mut self, slot: SlotId, since: u64, skipped: SyncGap) {
        for ordinal in skipped.first.max(self.base_ordinal)..skipped.end {
            if ordinal < since {
                continue;
            }
            self.pending
                .entry(ordinal)
                .or_default()
                .entry(slot)
                .or_insert(SyncObservation::Skipped);
        }
    }
    /// Evaluates every ordinal now ready: the frontier (the furthest any
    /// member has reached) has moved at least `margin` past it (see
    /// [`sync_eval_margin`]), and every member required for it (its `since` at
    /// or before it) has reported it. Returns the first [`SyncDivergence`]
    /// fired, if any — the caller's next `record` call resumes draining from
    /// where this left off.
    pub(in crate::consensus) fn evaluate_ready(
        &mut self,
        key: &SessionKey,
        margin: u64,
    ) -> Option<SyncDivergence> {
        loop {
            let Some(frontier) = self.members.values().map(|m| m.next_expected).max() else {
                return None; // no members yet
            };
            let base = self.base_ordinal;
            if frontier.saturating_sub(base) < margin {
                return None; // not enough lead yet to trust completeness
            }

            // Which members are required (their `since` at or before `base`)
            // and whether every one of them has reported `base`, computed in
            // one pass with no allocation — both are cheap membership checks
            // against `self.pending`, never stored past this iteration.
            let reports_at_base = self.pending.get(&base);
            let mut any_required = false;
            let mut complete = true;
            for (slot, member) in &self.members {
                if member.since <= base {
                    any_required = true;
                    if !reports_at_base.is_some_and(|reports| reports.contains_key(slot)) {
                        complete = false;
                    }
                }
            }
            if !any_required {
                // No member was active this far back -- vacuously nothing to
                // compare (only reachable right after a promotion anchors the
                // frontier ahead of ordinal 0, or once every once-required
                // member has since departed). Just retire and move on.
                self.pending.remove(&base);
                self.base_ordinal = self.base_ordinal.saturating_add(1);
                continue;
            }
            if !complete {
                // Should be rare given the margin; a genuinely stalled member
                // is bounded by window eviction instead of blocking here.
                return None;
            }

            let observations = self.pending.remove(&base).expect("just matched complete");
            self.base_ordinal = self.base_ordinal.saturating_add(1);
            if let Some(divergence) = self.evaluate(base, &observations, key) {
                return Some(divergence);
            }
        }
    }

    /// Marks the comparator permanently dormant because the session's
    /// negotiated buffer bounds reach the absurd-bounds backstop
    /// ([`SYNC_ABSURD_BUFFER_MAX`]) — not a live constraint under any real
    /// policy, just a defensive ceiling: logs once, then behaves exactly like
    /// any other dormant comparator (a cheap no-op).
    pub(in crate::consensus) fn disable_for_absurd_bounds(
        &mut self,
        key: &SessionKey,
        max_buffer: u32,
    ) {
        if !self.dormant {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                max_buffer,
                absurd_at = SYNC_ABSURD_BUFFER_MAX,
                "session's buffer bounds reach the desync comparator's absurd-bounds \
                 backstop; disabling desync detection for this session",
            );
        }
        self.dormant = true;
    }

    /// Compares the reports at a complete `ordinal`. `None` when every
    /// *comparable* report agrees (the ordinal retires silently, whether or
    /// not there were zero or more kind-mismatched reports excluded);
    /// otherwise the [`SyncDivergence`] to fire, after pruning the diverged
    /// minority from the compare set.
    ///
    /// A report whose `kind` disagrees with `ordinal`'s expected parity (see
    /// [`expected_kind_for_ordinal`]) is excluded from the comparison
    /// entirely — a rate-limited warn, not a vote either way: kind is a
    /// deterministic function of the true ring index, so a mismatch here
    /// means this report's placement (not necessarily its sim) drifted, and
    /// grouping a wrong-kind hash alongside the right-kind ones would compare
    /// two different quantities (the native check alternates between a
    /// per-unit hash and a game-header/rng hash — see [`SyncValue`]) as if
    /// they were the same checksum.
    pub(in crate::consensus) fn evaluate(
        &mut self,
        ordinal: u64,
        observations: &HashMap<SlotId, SyncObservation>,
        key: &SessionKey,
    ) -> Option<SyncDivergence> {
        let expected_kind = expected_kind_for_ordinal(ordinal);

        // Common case first: every comparable report agrees on the same
        // value (the honest, no-desync turn). A single zero-allocation pass
        // confirms this without ever building the value groups below —
        // those only matter once there's an actual disagreement to resolve,
        // which is the rare path. Also counts `comparable` and fires the
        // kind/parity warn, both needed again below only on that rare path.
        let mut comparable = 0usize;
        let mut agreed_value: Option<SyncValue> = None;
        let mut diverges = false;
        for (slot, observation) in observations {
            let SyncObservation::Report(report) = observation else {
                continue;
            };
            if report.kind != expected_kind {
                if self.kind_parity_warns.observe() {
                    tracing::warn!(
                        tenant = key.tenant.as_ref(),
                        session = key.session.0,
                        slot = slot.0,
                        ordinal,
                        kind = report.kind,
                        expected_kind,
                        count = self.kind_parity_warns.count(),
                        "sync kind disagrees with this ordinal's expected parity; \
                         excluding this report from the desync comparison as a \
                         likely alignment drift, not a desync",
                    );
                }
                continue;
            }
            comparable += 1;
            match agreed_value {
                None => agreed_value = Some(report.value),
                Some(value) if value == report.value => {}
                Some(_) => diverges = true,
            }
        }
        if !diverges {
            return None; // every comparable report agreed (or fewer than 2 were comparable)
        }

        // A genuine mismatch: fall back to grouping by value to find the
        // majority and the minority to prune. Rare enough that the
        // allocation here doesn't matter. `comparable` and the kind/parity
        // warn were already handled in the pass above, so this only groups.
        let mut groups: HashMap<SyncValue, Vec<SlotId>> = HashMap::new();
        for (slot, observation) in observations {
            if let SyncObservation::Report(report) = observation
                && report.kind == expected_kind
            {
                groups.entry(report.value).or_default().push(*slot);
            }
        }

        // The frame the mismatch was confirmed at. In lockstep every report at
        // one ordinal shares a frame, so picking the newest present is only a
        // defensive tie-break, not a meaningful choice among disagreeing values.
        let game_frame = observations
            .values()
            .filter_map(|observation| match observation {
                SyncObservation::Report(report) => report.game_frame,
                SyncObservation::Skipped => None,
            })
            .max();

        let majority = groups
            .iter()
            .find(|(_, slots)| slots.len() * 2 > comparable)
            .map(|(_, slots)| slots.clone());

        match majority {
            Some(majority_slots) => {
                let majority: HashSet<SlotId> = majority_slots.into_iter().collect();
                // Drawn from `groups` (comparable reports only) — a
                // kind-excluded slot never appears here; it was never really
                // "in" the comparison to have diverged from it.
                let mut diverged: Vec<SlotId> = groups
                    .values()
                    .flatten()
                    .copied()
                    .filter(|slot| !majority.contains(slot))
                    .collect();
                diverged.sort_unstable();
                // Drop the minority from the compare set *and* from every future
                // pending ordinal, so the survivors are compared only against each
                // other from here on.
                for slot in &diverged {
                    self.exclude_member(*slot);
                }
                // With fewer than two comparable slots left there is nothing to
                // compare, so stop for the session.
                if self.members.len() < 2 {
                    self.dormant = true;
                }
                Some(SyncDivergence {
                    sync_ordinal: ordinal,
                    game_frame,
                    no_majority: false,
                    diverged,
                })
            }
            None => {
                // A 1v1 or even split: undecidable, and no survivor set to keep
                // watching. Report it and go dormant for the session.
                self.dormant = true;
                Some(SyncDivergence {
                    sync_ordinal: ordinal,
                    game_frame,
                    no_majority: true,
                    diverged: Vec::new(),
                })
            }
        }
    }

    /// Evicts the oldest in-flight ordinal(s) while over [`SYNC_WINDOW`]. A slot
    /// that stalled leaves its ordinals forever-incomplete; the eviction bounds
    /// memory and is the missing-sync signal too — the evicted ordinal's report
    /// set names who *did* report, so the rest are the stalled slots.
    pub(in crate::consensus) fn evict_over_window(&mut self, key: &SessionKey) {
        while self.pending.len() > SYNC_WINDOW {
            let ordinal = *self
                .pending
                .keys()
                .next()
                .expect("over-window is non-empty");
            let reports = self.pending.remove(&ordinal).expect("just matched");
            let mut missing: Vec<u8> = self
                .members
                .keys()
                .filter(|member| !reports.contains_key(member))
                .map(|slot| slot.0)
                .collect();
            missing.sort_unstable();
            if self.evict_warns.observe() {
                tracing::warn!(
                    tenant = key.tenant.as_ref(),
                    session = key.session.0,
                    ordinal,
                    ?missing,
                    count = self.evict_warns.count(),
                    "evicting an incomplete sync ordinal over the window cap; \
                     a slot's sync stream is lagging or stopped",
                );
            }
            if ordinal >= self.base_ordinal {
                self.base_ordinal = ordinal.saturating_add(1);
            }
        }
    }

    /// Excludes a confirmed divergent minority for this tracker instance. A
    /// queued turn may still arrive after the verdict, but it must not recreate
    /// the member and make survivors compare against a known-bad simulation.
    pub(in crate::consensus) fn exclude_member(&mut self, slot: SlotId) {
        self.excluded.insert(slot);
        self.remove_member(slot);
    }

    /// Removes `slot` from the compare set and drops its reports from every
    /// pending ordinal. Departures and observer changes use this non-sticky
    /// removal because a later descriptor can legitimately reinstate a slot.
    /// Idempotent — a slot not in the set is a no-op.
    pub(in crate::consensus) fn remove_member(&mut self, slot: SlotId) {
        self.members.remove(&slot);
        for reports in self.pending.values_mut() {
            reports.remove(&slot);
        }
    }
}
