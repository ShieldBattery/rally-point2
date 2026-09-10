//! The decision-maker's hook into the desync comparator: feeding one
//! forwarded turn's commands in and surfacing a confirmed divergence.

use super::*;

impl DecisionMaker {
    /// Feeds one turn's commands into the desync comparator, returning a
    /// [`SyncDivergence`] if this turn's sync command confirmed one. A cheap no-op
    /// unless this relay is the session authority and the comparator is still live
    /// (not dormant, and `slot` is a compared, non-observer, non-departed slot).
    ///
    /// **Caller contract: exactly once per distinct `(slot, seq)` turn.** The
    /// comparator's per-slot ordinal counting is not idempotent the way
    /// [`observe_frame`](Self::observe_frame)'s monotone max is — a turn handed
    /// to this method twice (for example during reconnect/resume overlap) would be counted twice and
    /// silently misalign that slot's ordinals. The one call site
    /// (`deliver_turn_to_locals` in `mesh.rs`) is placed immediately after that
    /// function's own duplicate check for exactly this reason — don't add
    /// another call site upstream of it.
    ///
    /// It re-walks the command bytes itself looking for `0x37` sync commands. The
    /// bytes were bounds-checked at the ingress client edge — mesh hops trust that
    /// and do not re-validate — but this walk stays independent and defensive (it
    /// parses with the shared length table and stops on any anomaly rather than
    /// trusting a length): the authority reaches its own desync verdict from the
    /// bytes, it does not rely on a peer's parse, and the data is still nominally
    /// attacker-adjacent.
    ///
    /// `game_frame` is the turn's `game_frame_count` (carried into the notice as
    /// the interval the mismatch was confirmed at); `commands` is the raw command
    /// stream.
    pub fn observe_sync(
        &mut self,
        slot: SlotId,
        game_frame: Option<u32>,
        commands: &[u8],
    ) -> Option<SyncDivergence> {
        if self.authority != Authority::SelfRelay {
            return None;
        }
        // The session's negotiated buffer bounds may have grown to the
        // defensive absurd-bounds backstop (see `SYNC_ABSURD_BUFFER_MAX`) —
        // checked on every call since bounds can change mid-session
        // (`sync`/`apply_descriptor`); cheap, and `disable_for_absurd_bounds`
        // only logs once. Ordinary policy never approaches this.
        if self.bounds.max >= SYNC_ABSURD_BUFFER_MAX {
            self.sync
                .disable_for_absurd_bounds(&self.key, self.bounds.max);
        }
        // No-op fast paths: a dormant comparator has reached a terminal
        // verdict (or was just disabled above), and observers/departed slots
        // are never compared.
        if self.sync.dormant
            || self.observers.contains(&slot)
            || self.departures.contains_key(&slot)
        {
            return None;
        }
        let margin = sync_eval_margin(self.bounds.max);

        // Walk the command stream for this turn's sync command. A real client
        // emits **exactly one** `0x37` per outgoing turn, and the comparator's
        // ordinal counting depends on that (each turn advances a slot's ordinal
        // by one). A turn carrying more than one is not something an honest
        // client produces — packing several into one turn is precisely the
        // lever a malicious client would use to inflate its own frontier and
        // seed the join-placement calibration in a single turn (and to evade
        // its own detection by racing ordinals past the eviction window). So
        // only the first `0x37` is fed to the comparator; any extras are
        // ignored (they neither advance the slot's ordinal nor feed
        // calibration) and counted for a rate-limited anomaly warn. The walk
        // still parses with the shared length table and stops cleanly on any
        // malformed length without panicking.
        let mut offset = 0;
        let mut sync_seen = false;
        let mut extra_syncs = 0u32;
        let mut divergence = None;
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
                    divergence = self
                        .sync
                        .record(&self.key, slot, ring, kind, value, game_frame, margin);
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
        divergence
    }
}
