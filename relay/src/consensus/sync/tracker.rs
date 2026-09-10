//! The comparator fold: placing each slot's sync report at its true ordinal,
//! evaluating an ordinal once the frontier clears the margin, and naming the
//! diverged minority.

use super::*;

impl SyncTracker {
    /// Records one slot's `0x37`, nibble-correcting its placement, and
    /// evaluates any now-ready ordinals, returning a [`SyncDivergence`] if one
    /// fired. `ring` is the command's ring nibble (the high nibble of `[1]`,
    /// already shifted to 0..15); `kind` is the low nibble (the hash kind).
    ///
    /// `kind` must be [`SYNC_KIND_UNITS`] or [`SYNC_KIND_HEADER`] — anything
    /// else is a malformed sync command (defensive; validated bytes shouldn't
    /// produce this) and the report is skipped entirely: no member
    /// bookkeeping, no calibration, nothing recorded, just a rate-limited warn.
    ///
    /// Placement: the ordinal congruent to `ring` (mod 16) nearest this slot's
    /// expected ordinal — its own [`Member::next_expected`] if already a
    /// member (steady state), else [`Self::join_expected`]'s frame-anchored
    /// (or frontier, or ring-face-value) estimate for a first-ever report. See
    /// the module docs for why the two cases differ and the bound on how far
    /// each correction can reach. `margin` is this session's current
    /// evaluation margin ([`sync_eval_margin`]) — threaded through to
    /// [`Self::evaluate_ready`] rather than stored, so a mid-session bounds
    /// change is picked up immediately without the tracker needing to be told.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::consensus) fn record(
        &mut self,
        key: &SessionKey,
        slot: SlotId,
        ring: u8,
        kind: u8,
        value: SyncValue,
        game_frame: Option<u32>,
        margin: u64,
    ) -> Option<SyncDivergence> {
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

        let ring = u64::from(ring);
        let existing_next_expected = self.members.get(&slot).map(|m| m.next_expected);
        let is_new_member = existing_next_expected.is_none();
        let expected = match existing_next_expected {
            Some(expected) => expected,
            None => match self.join_expected(ring, game_frame) {
                Some(expected) => expected,
                // Deep join with no corroborated rate and the frontier more than a
                // ring cycle ahead: defer (see `defer_join`).
                None => return self.defer_join(key, slot),
            },
        };

        // Nearest ordinal ≡ ring (mod 16) to `expected`. `diff` lands in
        // [-8, 8]; the ends (exactly ±8) are the ambiguous case the module
        // docs' bound note calls out — deterministic here, but not
        // necessarily correct, which is why each case's own bound (transport
        // reordering for steady state, frame skew for a join) is what keeps
        // real gaps well inside this range rather than at its edge.
        let expected_mod = (expected % SYNC_RING_MODULUS) as i64;
        let mut diff = ring as i64 - expected_mod;
        if diff > 8 {
            diff -= 16;
        } else if diff < -8 {
            diff += 16;
        }
        let placed = i128::from(expected) + i128::from(diff);

        // A *joining* slot placed above the frontier means the nibble jumped a
        // ring cycle upward off the frontier anchor — the tell-tale of a deep
        // join we can't resolve without a corroborated rate. Defer it (drop and
        // retry) rather than misplace it a full cycle and risk framing an honest
        // slot. Steady-state members are exempt: they legitimately *are* the
        // frontier. (No frontier yet — the very first observation — is never
        // above itself.)
        if is_new_member
            && let Some(frontier) = self.members.values().map(|m| m.next_expected).max()
            && placed > i128::from(frontier)
        {
            return self.defer_join(key, slot);
        }

        if diff != 0 && self.corrections.observe() {
            tracing::debug!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                expected,
                ring,
                placed,
                count = self.corrections.count(),
                "sync ordinal placement corrected from the ring nibble; \
                 the turn arrived out of order, the slot is running ahead, \
                 or it just joined the compare set",
            );
        }

        // Advance this member's bookkeeping regardless of whether the
        // placement itself lands in already-retired territory below — a
        // dropped comparison must not also leave the member's own progress
        // stale (it has still, after all, reported this many sync commands).
        let next_expected_candidate = u64::try_from(placed + 1).unwrap_or(0);
        let since_candidate = u64::try_from(placed).unwrap_or(0);
        let member = self.members.entry(slot).or_insert_with(|| Member {
            next_expected: 0,
            since: since_candidate,
        });
        member.next_expected = member.next_expected.max(next_expected_candidate);
        if is_new_member {
            member.since = since_candidate;
        }

        if placed < i128::from(self.base_ordinal) {
            // Already-retired territory (possible right after a correction or
            // an eviction): the comparison is lost, which is acceptable —
            // don't let it perturb anything beyond the bookkeeping above.
            return None;
        }
        let ordinal = placed as u64; // non-negative: checked above

        match self.pending.entry(ordinal).or_default().entry(slot) {
            std::collections::hash_map::Entry::Occupied(existing) => {
                if existing.get().value != value && self.duplicate_warns.observe() {
                    // An honest client never emits two different checksums for
                    // the same turn; keep the first and just flag it.
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
                // Same value: a harmless duplicate (the belt-and-suspenders
                // case — the caller is expected to already dedup turns, but
                // nibble correction can independently re-place a redundant
                // report at an ordinal it already holds). Either way, nothing
                // to insert.
            }
            std::collections::hash_map::Entry::Vacant(vacant) => {
                vacant.insert(SyncReport {
                    value,
                    kind,
                    game_frame,
                });
            }
        }

        // Fold this ordinal into the corroborated calibration: once ≥3 distinct
        // slots have reported it with frames, its median frame anchors the
        // frame-rate estimate used to place late joins (see `join_expected`).
        self.update_corroboration(ordinal);

        if let Some(divergence) = self.evaluate_ready(key, margin) {
            return Some(divergence);
        }
        self.evict_over_window(key);
        None
    }

    /// The join-placement anchor for a slot's first-ever report: the ordinal
    /// [`Self::record`]'s nibble correction will refine — or `None` to **defer**
    /// the placement entirely when no anchor can be trusted.
    ///
    /// Three cases, in order:
    /// - **No members yet** (the tracker's very first observation): the ring's
    ///   own face value.
    /// - **A corroborated rate is available**: project frame-anchored from the
    ///   corroborated latest `(ordinal, frame)` point — a point ≥3 distinct slots
    ///   agreed on (see [`Self::frame_rate`]), so a lone slot cannot swing it —
    ///   clamped to `[0, frontier]`. This keeps deep honest joins (>7 ordinals
    ///   from the frontier) landing on the true ordinal, exactly as before, but
    ///   now from a reference an attacker can't poison.
    /// - **No corroborated rate yet**: anchor on the frontier and let
    ///   [`Self::record`]'s nibble correction resolve the placement — but only
    ///   within a single ring cycle (`frontier < SYNC_RING_MODULUS`). Beyond one
    ///   cycle the nibble could land a deep joiner a full cycle off a slot's true
    ///   ordinal with no way to tell, so return `None` to **defer**. Within a
    ///   cycle, `record` additionally defers any placement that lands *above* the
    ///   frontier (the tell-tale of a deep joiner whose nibble jumped a cycle
    ///   upward) — so a slot is only ever placed at or below the frontier, within
    ///   the nibble's reliable ±7 range of its true ordinal.
    ///
    /// A joining slot's own single-slot frame is deliberately **never** trusted
    /// as a rate/anchor source; that was the calibration-poisoning lever.
    pub(in crate::consensus) fn join_expected(
        &self,
        ring: u64,
        game_frame: Option<u32>,
    ) -> Option<u64> {
        let Some(frontier) = self.members.values().map(|m| m.next_expected).max() else {
            return Some(ring); // no members at all: the very first observation
        };
        if let Some(frame) = game_frame
            && let Some(rate) = self.frame_rate()
            && let Some((ref_ordinal, ref_frame)) = self.corroborated_latest
        {
            let predicted = ref_ordinal as f64 + (f64::from(frame) - f64::from(ref_frame)) / rate;
            return Some(predicted.clamp(0.0, frontier as f64).round() as u64);
        }
        // No trustworthy rate: safe to anchor on the frontier only within a
        // single ring cycle; deeper than that, defer (the caller drops the report
        // and retries on the slot's next one).
        (frontier < SYNC_RING_MODULUS).then_some(frontier)
    }

    /// The frames-per-ordinal rate this session is advancing at, from the spread
    /// between [`Self::corroborated_first`] and [`Self::corroborated_latest`] —
    /// both **corroborated** points (≥3 distinct slots agreeing), so the slope an
    /// attacker sees is one it cannot move with its single slot. `None` until two
    /// distinct-ordinal corroborated points exist, or if the computed rate isn't a
    /// sane forward rate (frames must advance, not stall or run backward, between
    /// distinct ordinals).
    pub(in crate::consensus) fn frame_rate(&self) -> Option<f64> {
        let (o1, f1) = self.corroborated_first?;
        let (o2, f2) = self.corroborated_latest?;
        if o2 <= o1 {
            return None;
        }
        let rate = (f64::from(f2) - f64::from(f1)) / (o2 - o1) as f64;
        (rate.is_finite() && rate > 0.0).then_some(rate)
    }

    /// Drops a joining slot's report because it can't be safely placed yet (no
    /// corroborated rate and the frontier is more than a ring cycle ahead, or the
    /// placement would land above the frontier). No member is created and no
    /// calibration is fed, so the slot stays in the join path and retries on its
    /// next report — the natural re-placement, no separate comparison-lost flag.
    /// Missing a possible desync for this slot is an acceptable false negative;
    /// framing an honest slot by misplacing it a full ring cycle is not.
    pub(in crate::consensus) fn defer_join(
        &mut self,
        key: &SessionKey,
        slot: SlotId,
    ) -> Option<SyncDivergence> {
        if self.defer_warns.observe() {
            tracing::warn!(
                tenant = key.tenant.as_ref(),
                session = key.session.0,
                slot = slot.0,
                count = self.defer_warns.count(),
                "deferring a joining slot's sync placement: no corroborated rate \
                 yet and the join is more than a ring cycle from the frontier — \
                 dropping this report, will retry on the slot's next one",
            );
        }
        None
    }

    /// Folds the pending reports at `ordinal` into the corroborated calibration:
    /// once at least [`SYNC_CORROBORATION_MIN`] **distinct** slots have reported
    /// it with a frame, records `(ordinal, median_frame)` as a corroborated point
    /// — extending the corroborated ordinal range at either end. The **median**
    /// is what a single attacker cannot move (≤1 outlier among ≥3 values), so the
    /// resulting rate/anchor is tolerance-free and poisoning-resistant.
    pub(in crate::consensus) fn update_corroboration(&mut self, ordinal: u64) {
        let Some(reports) = self.pending.get(&ordinal) else {
            return;
        };
        // Reused across calls (cleared, not reallocated) since this runs on
        // every accepted sync report and the common case never needs the sort
        // below at all.
        self.frame_scratch.clear();
        self.frame_scratch
            .extend(reports.values().filter_map(|r| r.game_frame));
        if self.frame_scratch.len() < SYNC_CORROBORATION_MIN {
            return;
        }
        self.frame_scratch.sort_unstable();
        let median = self.frame_scratch[self.frame_scratch.len() / 2];
        if self.corroborated_first.is_none_or(|(o, _)| ordinal < o) {
            self.corroborated_first = Some((ordinal, median));
        }
        if self.corroborated_latest.is_none_or(|(o, _)| ordinal > o) {
            self.corroborated_latest = Some((ordinal, median));
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
            if frontier < base + margin {
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
                self.base_ordinal += 1;
                continue;
            }
            if !complete {
                // Should be rare given the margin; a genuinely stalled member
                // is bounded by window eviction instead of blocking here.
                return None;
            }

            let reports = self.pending.remove(&base).expect("just matched complete");
            self.base_ordinal += 1;
            if let Some(divergence) = self.evaluate(base, &reports, key) {
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
        reports: &HashMap<SlotId, SyncReport>,
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
        for (slot, report) in reports {
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
        for (slot, report) in reports {
            if report.kind == expected_kind {
                groups.entry(report.value).or_default().push(*slot);
            }
        }

        // The frame the mismatch was confirmed at. In lockstep every report at
        // one ordinal shares a frame, so picking the newest present is only a
        // defensive tie-break, not a meaningful choice among disagreeing values.
        let game_frame = reports.values().filter_map(|r| r.game_frame).max();

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
                    self.remove_member(*slot);
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
                self.base_ordinal = ordinal + 1;
            }
        }
    }

    /// Removes `slot` from the compare set and drops its reports from every
    /// pending ordinal, so it is neither required nor compared from here on.
    /// Idempotent — a slot not in the set is a no-op.
    pub(in crate::consensus) fn remove_member(&mut self, slot: SlotId) {
        self.members.remove(&slot);
        for reports in self.pending.values_mut() {
            reports.remove(&slot);
        }
    }
}
