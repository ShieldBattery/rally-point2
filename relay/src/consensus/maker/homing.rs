//! Who the session is made of and where they are served: the observer, expected
//! and homed slot sets a coordinator descriptor supplies, this relay's own id,
//! the admission questions the homed set answers, and the relay -> region label
//! map plus the gate that withholds it.

use super::*;

impl DecisionMaker {
    /// Replaces the session's observer slots (from the coordinator descriptor)
    /// on a re-push, dropping any newly-observer slot from the desync compare
    /// set — an observer must never be a required reporter. The first descriptor
    /// seeds the observer set at maker creation instead (see
    /// [`DecisionMaker::new`]); this re-applies it when a later descriptor
    /// carries a changed set, so the observer set follows the descriptor rather
    /// than accumulating.
    pub fn set_observers(&mut self, observers: HashSet<SlotId>) {
        for slot in &observers {
            self.sync.remove_member(*slot);
        }
        self.observers = observers;
    }

    /// Replaces the session's expected-slot set from the coordinator descriptor —
    /// the slots that must connect before the session may start. Descriptor-driven
    /// like [`set_observers`](Self::set_observers): the first descriptor seeds it,
    /// a later one carrying a changed set replaces it. Never clears the `started`
    /// latch: a session that already started stays started even if a re-push
    /// reshaped the expected set.
    pub fn set_expected_slots(&mut self, expected: HashSet<SlotId>) {
        self.expected_slots = expected;
    }

    /// Replaces the session's homed-slot set from the coordinator descriptor —
    /// the slots the coordinator assigned to THIS relay. Descriptor-driven like
    /// [`set_expected_slots`](Self::set_expected_slots): the first descriptor
    /// seeds it, a later one (e.g. a rehome) replaces it wholesale, so a slot
    /// moved off this relay stops being admissible here and one moved onto it
    /// starts being admissible, with no accumulation across descriptors.
    pub fn set_homed_slots(&mut self, homed: HashSet<SlotId>) {
        self.homed_slots = homed;
    }

    /// Records this relay's own id, stamped onto every `BufferDirective` this
    /// maker queues from here on (see `queue_directive`).
    /// Idempotent — the caller's own id never changes for a running relay
    /// process, so calling this again on every descriptor push is harmless.
    pub fn set_own_relay_id(&mut self, id: RelayId) {
        self.own_relay_id = Some(id);
    }

    /// Whether `slot` is admissible on this relay: the homed set is empty
    /// (unenforced — see the field's doc) or contains `slot`. Read by
    /// [`slot_homed`] at client admission.
    pub(in crate::consensus) fn admits_slot(&self, slot: SlotId) -> bool {
        self.homed_slots.is_empty() || self.homed_slots.contains(&slot)
    }

    /// Whether the descriptor strictly homes `slot` here — see the free
    /// [`slot_strictly_homed`] for why this, unlike `admits_slot`, never
    /// fails open on an empty set.
    pub(in crate::consensus) fn strictly_homes(&self, slot: SlotId) -> bool {
        self.homed_slots.contains(&slot)
    }

    /// Replaces the session's relay → region labels from the coordinator
    /// descriptor, returning the map to (re)send when the release gate is already
    /// open and the new map differs from what clients were last told — a re-home
    /// names a different relay, and a client still holding the old map would
    /// label a member by a relay that no longer serves it.
    ///
    /// Returns `None` while the gate is shut, so a descriptor push can never be
    /// the thing that leaks a label early: the labels are recorded and go nowhere
    /// until [`maybe_release_region_labels`](Self::maybe_release_region_labels)
    /// opens the gate. Descriptor-driven like
    /// [`set_expected_slots`](Self::set_expected_slots) — a later push replaces
    /// the map wholesale rather than accumulating.
    #[must_use]
    pub fn set_region_labels(&mut self, labels: Vec<RegionLabel>) -> Option<Vec<RegionLabel>> {
        if self.region_labels == labels {
            return None;
        }
        self.region_labels = labels;
        self.released_region_labels()
    }

    /// Opens the region-label release gate once `delay` has elapsed since this
    /// relay latched the session started, returning the map to fan out on the one
    /// call that opens it.
    ///
    /// `Some` comes back on that single transition only, and only when there is
    /// actually a map to send; every later call returns `None`, so a caller on the
    /// turn path fans the labels out exactly once. A session that never starts, or
    /// that ends inside the delay, never opens its gate and never sends labels —
    /// the intended outcome, not a failure.
    ///
    /// Reads nothing but this relay's own clock and its own start latch. In
    /// particular it does **not** read the turns being delivered: a turn's
    /// `game_frame_count` is a client-asserted claim, and a relay delivers turns
    /// that originated at other relays, so keying on one would let a single client
    /// open the gate across every relay serving the session. `delay` is a caller
    /// parameter rather than a direct read of [`REGION_LABEL_RELEASE_DELAY`] so a
    /// relay can be built with a shortened one for testing without a second
    /// gate-evaluating path existing at all.
    #[must_use]
    pub fn maybe_release_region_labels(&mut self, delay: Duration) -> Option<Vec<RegionLabel>> {
        if self.region_labels_released {
            return None;
        }
        if self.started_at?.elapsed() < delay {
            return None;
        }
        self.region_labels_released = true;
        self.released_region_labels()
    }

    /// The session's relay → region labels when the release gate is open and
    /// there are labels to send, else `None`. Read for the direct push a slot
    /// gets when it connects after the gate has already opened, so a late or
    /// reconnecting client is not left without them.
    pub fn released_region_labels(&self) -> Option<Vec<RegionLabel>> {
        (self.region_labels_released && !self.region_labels.is_empty())
            .then(|| self.region_labels.clone())
    }
}
