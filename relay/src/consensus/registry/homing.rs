//! Where a session's slots and relays sit: this relay's own id, and the
//! relay -> region label map — recording what a coordinator descriptor
//! carries, opening the release gate once a session has been running long
//! enough, and reading back what clients may be told.

use super::*;

impl DecisionMakers {
    /// Records `id` as the session's own relay id on its maker, if one exists
    /// (see [`DecisionMaker::set_own_relay_id`]). A no-op when the session has no
    /// maker yet — nothing to stamp until one is created.
    pub fn set_own_relay_id(&self, key: &SessionKey, id: RelayId) {
        if let Some(maker) = self.lock().get_mut(key) {
            maker.set_own_relay_id(id);
        }
    }

    /// Records `key`'s relay → region labels from a coordinator descriptor, returning
    /// the map to (re)send to this relay's local slots when the release gate is
    /// already open and the map changed (see
    /// [`DecisionMaker::set_region_labels`]). `None` when no maker exists — a session
    /// with no maker has no gate, and therefore nothing that may be released.
    #[must_use]
    pub fn set_region_labels(
        &self,
        key: &SessionKey,
        labels: Vec<RegionLabel>,
    ) -> Option<Vec<RegionLabel>> {
        self.lock().get_mut(key)?.set_region_labels(labels)
    }

    /// Evaluates `key`'s region-label release gate against this relay's clock,
    /// returning the map to fan out on the single call that opens it (see
    /// [`DecisionMaker::maybe_release_region_labels`]). `None` on every other call,
    /// and when no maker exists. The delay comes from the registry, so every session
    /// on a relay is gated by the same one.
    #[must_use]
    pub fn maybe_release_region_labels(&self, key: &SessionKey) -> Option<Vec<RegionLabel>> {
        let delay = self.region_release_delay();
        self.lock().get_mut(key)?.maybe_release_region_labels(delay)
    }

    /// `key`'s relay → region labels when its release gate is already open, for the
    /// direct push a slot gets on connecting after the gate opened. `None` when the
    /// gate is shut, when there are no labels, or when no maker exists.
    pub fn released_region_labels(&self, key: &SessionKey) -> Option<Vec<RegionLabel>> {
        self.lock().get(key)?.released_region_labels()
    }
}
