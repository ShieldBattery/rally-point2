//! Sequence-ordered checksum observation, independent of gameplay forwarding.

use super::*;

impl DecisionMaker {
    /// Observes one validated turn after the session's forwarding dedup gate.
    /// Gameplay forwarding never waits for this observer: only the compact
    /// checksum metadata is held until every preceding origin sequence arrives.
    /// Peer relays keep the same ordered cursor so promotion retains continuity.
    pub fn observe_sync(
        &mut self,
        slot: SlotId,
        seq: u64,
        game_frame: Option<u32>,
        commands: &[u8],
    ) -> Option<SyncDivergence> {
        self.observe_sync_with_generation(slot, seq, game_frame, commands, None)
    }

    /// `sync_generation` is client-authored metadata bound to the first parsed
    /// native sync command in this turn; it never supplies another slot's
    /// history or a checksum value.
    pub fn observe_sync_with_generation(
        &mut self,
        slot: SlotId,
        seq: u64,
        game_frame: Option<u32>,
        commands: &[u8],
        sync_generation: Option<u64>,
    ) -> Option<SyncDivergence> {
        if self.observers.contains(&slot) {
            return None;
        }
        if self.sync_turns.unavailable(slot) {
            return None;
        }
        let turn = SyncTurn {
            frame: game_frame,
            ordinal: None,
            command: self.parse_sync(slot, commands),
            generation: sync_generation,
            skipped: None,
        };
        let mut ready = match self.sync_turns.push(slot, seq, turn) {
            Ok(None) => self.sync_turns.pop_ready(slot),
            result => result,
        };
        loop {
            match ready {
                Ok(Some(turn)) => {
                    if let Some(divergence) = self.compare_sync_turn(slot, turn) {
                        // Preserve the queued tail for the next observation so
                        // another minority's verdict is not lost during draining.
                        return Some(divergence);
                    }
                }
                Ok(None) => return None,
                Err(failure) => {
                    // An origin with uncertain history supplies no valid votes.
                    // Its failure cannot erase other origins' epochs or prevent
                    // their complete intervals from being compared.
                    self.sync.remove_member(slot);
                    tracing::warn!(
                        tenant = self.key.tenant.as_ref(),
                        session = self.key.session.0,
                        slot = slot.0,
                        reason = failure.reason,
                        seq = failure.seq,
                        missing_next = failure.next,
                        previous_ordinal = failure.previous_ordinal,
                        ring = failure.ring,
                        "checksum ordering unavailable for this slot; other slots remain comparable",
                    );
                    return None;
                }
            }
            ready = self.sync_turns.pop_ready(slot);
        }
    }

    /// Coverage counts describe this relay's current observation, not whether
    /// any player's simulation is honest. Missing expected players count even
    /// before their first turn arrives. Observers and departed players do not.
    pub fn sync_coverage(&self) -> crate::observability::flight_recorder::SyncCoverage {
        let mut players = self.expected_slots.clone();
        players.extend(self.sync_turns.slots());
        players
            .retain(|slot| !self.observers.contains(slot) && !self.departures.contains_key(slot));
        let mut coverage = crate::observability::flight_recorder::SyncCoverage {
            expected_players: players.len() as u32,
            authority: self.authority == Authority::SelfRelay,
            dormant: self.sync.dormant,
            ..Default::default()
        };
        for slot in players {
            if self.sync_turns.unavailable(slot) {
                coverage.unavailable_slots += 1;
            } else if self.sync_turns.ordered(slot) {
                coverage.ordered_slots += 1;
                if coverage.authority && !coverage.dormant && self.sync.members.contains_key(&slot)
                {
                    coverage.comparable_slots += 1;
                }
            } else {
                coverage.waiting_slots += 1;
            }
        }
        coverage
    }

    fn compare_sync_turn(&mut self, slot: SlotId, turn: SyncTurn) -> Option<SyncDivergence> {
        if self.authority != Authority::SelfRelay || self.departures.contains_key(&slot) {
            return None;
        }
        if self.bounds.max >= SYNC_ABSURD_BUFFER_MAX {
            self.sync
                .disable_for_absurd_bounds(&self.key, self.bounds.max);
        }
        if self.sync.dormant {
            return None;
        }
        let command = turn.command?;
        self.sync.record(
            &self.key,
            slot,
            turn.ordinal?,
            SyncReport {
                kind: command.kind,
                value: command.value,
                game_frame: turn.frame,
            },
            turn.skipped,
            sync_eval_margin(self.bounds.max),
        )
    }

    /// Parser/comparison fixtures generate consecutive transport sequences while
    /// selecting the native sync ring and game-frame fields independently.
    #[cfg(test)]
    pub(in crate::consensus) fn observe_ordered_sync(
        &mut self,
        slot: SlotId,
        frame: Option<u32>,
        commands: &[u8],
    ) -> Option<SyncDivergence> {
        let seq = self.sync_turns.next_for_test(slot);
        self.observe_sync(slot, seq, frame, commands)
    }

    fn parse_sync(&mut self, slot: SlotId, commands: &[u8]) -> Option<SyncCommand> {
        // Only the first sync command in a turn contributes checksum metadata.
        // Extra commands cannot advance the native ring cursor or create votes.
        // Parse with the shared length table and stop on an unknown or truncated
        // command so malformed bytes cannot be mistaken for another checksum.
        let mut offset = 0;
        let mut sync_seen = false;
        let mut extra_syncs = 0u32;
        let mut parsed = None;
        while offset < commands.len() {
            let Some(len) = command_length(&commands[offset..]) else {
                break; // an opcode the table doesn't know: stop, don't guess
            };
            if len == 0 || offset + len > commands.len() {
                break; // a length that overruns the buffer: stop
            }
            if commands[offset] == SYNC_COMMAND && len == SYNC_COMMAND_LEN {
                if sync_seen {
                    // A second (or later) sync command in the same turn: ignore
                    // it, and remember that this turn was anomalous.
                    extra_syncs += 1;
                } else {
                    sync_seen = true;
                    let command = &commands[offset..offset + SYNC_COMMAND_LEN];
                    let ring = command[1] >> 4;
                    let kind = command[1] & 0x0F;
                    let mut value = SyncValue::default();
                    value.copy_from_slice(&command[2..2 + SYNC_HASH16_LEN]);
                    // `[4..7]` (fog/vision, per-sender and pairwise-only in the
                    // native check) is deliberately never read — see `SyncValue`.
                    parsed = Some(SyncCommand { ring, kind, value });
                }
            }
            offset += len;
        }
        if extra_syncs > 0 && self.sync.multi_sync_warns.observe() {
            tracing::warn!(
                tenant = self.key.tenant.as_ref(),
                session = self.key.session.0,
                slot = slot.0,
                extra_syncs,
                count = self.sync.multi_sync_warns.count(),
                "turn carried more than one sync command; an honest client emits exactly \
                 one per turn — fed only the first to the comparator and ignored the rest",
            );
        }
        parsed
    }
}
