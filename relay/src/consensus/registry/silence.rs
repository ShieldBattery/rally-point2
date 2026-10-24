//! The silence watch's registry half — the per-tick verdict sweep — and the
//! retained load state read alongside it.

use super::*;

impl DecisionMakers {
    /// Every session this relay holds a decision-maker for, paired with the load
    /// progress facts that maker has retained — the heartbeat builder's session universe.
    /// Opaque observations are attached separately after the heartbeat byte budget
    /// selects a rotating subset; requested single-session snapshots retain them all.
    ///
    /// A maker lives from the descriptor apply that created it until the session
    /// retires, which outlasts every local link: a session whose slots have all
    /// disconnected still has its retained state restated on every beat while the
    /// game runs on elsewhere, which is the only way the coordinator hears facts this
    /// relay learned before its last slot left. A session run without a maker (no
    /// descriptor) is absent here and carries no retained state at all, which is
    /// exactly what "this relay knows of no arrivals" means on the wire.
    pub fn retained_load_states(&self) -> Vec<(SessionKey, RetainedLoadState)> {
        self.lock()
            .iter()
            .map(|(key, maker)| (key.clone(), maker.heartbeat_load_state()))
            .collect()
    }

    /// The load state one session's decision-maker has retained, or the empty state
    /// for a session this relay holds no maker for.
    ///
    /// Empty is a real answer, not a missing one: a relay with no maker for the session
    /// has learned nothing about who arrived there, which is exactly what empty sets
    /// say. The distinction that matters to the coordinator is between this relay
    /// answering and this relay not answering at all, never between an empty answer and
    /// an absent maker.
    pub fn retained_load_state(&self, key: &SessionKey) -> RetainedLoadState {
        self.lock()
            .get(key)
            .map(|maker| maker.load_state())
            .unwrap_or_default()
    }

    /// Records that `slot`'s gap-free forwarded prefix advanced for `key`'s
    /// session to `forwarded` turns, stamping the slot's stop clock (see
    /// [`DecisionMaker::note_forward_advance`]) and, in a rollback session, starting the report
    /// deadlines of the steps that became confirmable and moving the authority's session clock
    /// on (see [`DecisionMaker::note_forwarded_turns`]). Returns what moving the clock calls for: a
    /// frame for the caller to send the other relays, and reports to push down this relay's home
    /// slots. The clock's anchoring or stop is recorded in the flight recording. Called from the
    /// forward gate's fan-out choke point, once per turn that genuinely extends the prefix.
    #[must_use]
    pub fn note_forward_advance(
        &self,
        key: &SessionKey,
        slot: SlotId,
        forwarded: u64,
    ) -> Option<ClockUpdate> {
        let now = Instant::now();
        let (update, events) = {
            let mut makers = self.lock();
            let maker = makers.get_mut(key)?;
            maker.note_forward_advance(slot, now);
            let mark = maker.clock_mark();
            let update = maker.note_forwarded_turns(slot, forwarded, now)?;
            (update, maker.clock_events(mark, false))
        };
        self.record_clock_events(key, events);
        Some(update)
    }

    /// Every session whose decision-maker names a slot that has gone silent,
    /// marking nothing.
    ///
    /// The verdict itself is [`DecisionMaker::silent_slot`]: complete knowledge of
    /// the session or no verdict at all, and only ever the slot that stopped
    /// strictly earliest. Naming a slot is not yet evicting it. A slot whose
    /// turns stopped because its whole link went dead is the transport's to
    /// close, as an ordinary disconnect its client may come back from; only a
    /// link that still carries frames while its turns have stopped is a
    /// simulation that will not restart. Telling the two apart takes the link
    /// itself, which this layer does not hold, so the caller judges that,
    /// re-checks the verdict with [`still_silent`](Self::still_silent), and has
    /// the link's own task record the eviction with
    /// [`mark_silence_evicted`](Self::mark_silence_evicted).
    pub fn silent_slots(&self, now: Instant, window: Duration) -> Vec<(SessionKey, SilentSlot)> {
        self.lock()
            .iter_mut()
            .filter_map(|(key, maker)| Some((key.clone(), maker.silent_slot(now, window)?)))
            .collect()
    }

    /// `key`'s session's verdict, rendered again, if it still names `slot`.
    ///
    /// An earlier [`silent_slots`](Self::silent_slots) is not trusted across
    /// the link reads in between: the slot may have forwarded a turn,
    /// disconnected, or reconnected since.
    pub fn still_silent(
        &self,
        key: &SessionKey,
        slot: SlotId,
        now: Instant,
        window: Duration,
    ) -> Option<SilentSlot> {
        self.lock()
            .get_mut(key)?
            .silent_slot(now, window)
            .filter(|found| found.slot == slot)
    }

    /// Records that `slot` was evicted for silence, so it is out of every later
    /// comparison and its re-dials are refused.
    ///
    /// Called by the slot's own link task as the silence close ends its link,
    /// before the task gives up the slot's roster seat: no re-dial can be
    /// admitted ahead of the mark, and a link that was already ending for any
    /// other reason never gets one.
    pub fn mark_silence_evicted(&self, key: &SessionKey, slot: SlotId) {
        if let Some(maker) = self.lock().get_mut(key) {
            maker.mark_evicted(slot, EvictionCause::Silent);
        }
    }
}
