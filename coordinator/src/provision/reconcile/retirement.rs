//! Max-age retirement: replacing relays that have run longer than the
//! configured lifetime, so a deploy or a host-maintenance window never has to
//! wait out a relay that steady traffic keeps busy.
//!
//! Placement homes a region's slots on its lowest-id available relay — its
//! oldest — so without this a region that never goes quiet keeps that relay
//! indefinitely, while the younger relays a surge brought up are the ones that
//! idle out. Retirement is make-before-break: an aged relay stops counting
//! toward its region's target (so scale-up launches its replacement) but keeps
//! taking sessions until a younger relay has enrolled in the region. Only then is
//! it marked draining, and its task is stopped once its last session ends. Its
//! running games are never cut short.
//!
//! Everything is re-derived each tick from the ledger's launch times. Nothing is
//! remembered, so a coordinator restart, or a reconnect that lands the relay on a
//! fresh registry entry without the mark, is corrected on the next tick.

use super::*;

/// splitmix64's finalizer: a cheap, well-distributed hash of a relay id, so the
/// per-relay age jitter is spread evenly even though ids are sequential.
fn mix(id: u64) -> u64 {
    let mut z = id.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The age, in seconds, at which `relay_id` retires: `max_age` jittered by up to
/// ±1/12 of itself (±1h at 12h). Relays launched together in one surge then retire
/// spread out instead of all at once. Deterministic per id, so the limit holds
/// still across ticks and restarts.
pub(super) fn age_limit_secs(max_age: Duration, relay_id: RelayId) -> u64 {
    let max_age = max_age.as_secs();
    let spread = max_age / 6;
    if spread == 0 {
        return max_age;
    }
    max_age - spread / 2 + mix(relay_id.0) % spread
}

impl<P: Provisioner> ProvisionLoop<P> {
    /// The enrolled relays past their age limit at `now`, draining or not. Empty
    /// when no maximum age is configured, or when the ledger read fails. In that
    /// case the read is logged and retirement simply waits for a later tick.
    pub(super) fn aged_relays(&self, enrolled: &[EnrolledRelay], now: u64) -> HashSet<RelayId> {
        let Some(max_age) = self.config.max_relay_age else {
            return HashSet::new();
        };
        let launched = match self.ledger.launch_times() {
            Ok(launched) => launched,
            Err(error) => {
                tracing::warn!(%error, "reading relay launch times failed; skipping age retirement this tick");
                return HashSet::new();
            }
        };
        enrolled
            .iter()
            .filter(|r| {
                launched.get(&r.relay_id).is_some_and(|&at| {
                    now.saturating_sub(at) >= age_limit_secs(max_age, r.relay_id)
                })
            })
            .map(|r| r.relay_id)
            .collect()
    }

    /// Retires `region`'s aged relays. An aged relay is marked draining once the
    /// region has a younger relay enrolled and not draining to take its new
    /// sessions. Marking it before then would leave the region with nowhere to
    /// place a game until the replacement came up. An aged relay that is draining
    /// with no sessions left has its id retired and then its task stopped.
    ///
    /// Each relay this marks has its `draining` flag set in `enrolled`, so the rest
    /// of the tick sees it as already on its way out.
    ///
    /// The mark is taken, the session count read, and an idle relay's id
    /// tombstoned (see `tombstone_locked`), all under the assignment lock.
    /// Placement and re-home both refuse a draining relay, so a marked relay gains
    /// no session while its enrollment lasts, and the tombstone keeps a reconnect
    /// from installing a placeable one before its task is stopped. Unlike a
    /// scale-down, a relay found busy is left marked rather than spared: it keeps
    /// serving the games it has and takes no more.
    ///
    /// The replacement is re-checked against the live registry under that same
    /// lock before each new mark, not trusted from the snapshot. The snapshot is
    /// taken at the start of the tick, and stopping a retired relay awaits in
    /// between, so a replacement may have disconnected or begun its own drain (a
    /// mark also taken under the assignment lock) since. Trusting the snapshot
    /// would then drain the region's last placeable relay.
    pub(super) async fn retire_aged(
        &mut self,
        region: &RegionId,
        enrolled: &mut [EnrolledRelay],
        aged: &HashSet<RelayId>,
    ) {
        let replacements: Vec<RelayId> = enrolled
            .iter()
            .filter(|r| {
                !r.draining && r.region.as_ref() == Some(region) && !aged.contains(&r.relay_id)
            })
            .map(|r| r.relay_id)
            .collect();
        for relay in enrolled.iter_mut() {
            if relay.region.as_ref() != Some(region) || !aged.contains(&relay.relay_id) {
                continue;
            }
            if !relay.draining && replacements.is_empty() {
                // Make-before-break: keep it placeable until a replacement is up.
                continue;
            }
            let idle = {
                let _assignment = self.setup.lock_assignment();
                let registry = self.setup.registry();
                if !relay.draining
                    && !replacements
                        .iter()
                        .any(|&id| registry::is_available(registry, id))
                {
                    // The snapshot's replacements have all disconnected or begun
                    // draining since: keep this relay placeable.
                    continue;
                }
                // Idempotent for a relay already draining. False means the relay
                // reconnected or left since the snapshot; the next tick re-reads it.
                if !registry::mark_draining(registry, relay.relay_id, relay.generation) {
                    continue;
                }
                // A failed tombstone leaves the relay marked but running; the next
                // tick retries the stop.
                self.setup.session_count_for_relay(relay.relay_id) == 0
                    && self.tombstone_locked(relay.relay_id)
            };
            if !relay.draining {
                relay.draining = true;
                tracing::info!(
                    region = region.as_ref(),
                    relay_id = relay.relay_id.0,
                    "relay is past its maximum age; taking no new sessions",
                );
            }
            if idle {
                tracing::info!(
                    region = region.as_ref(),
                    relay_id = relay.relay_id.0,
                    "stopping a retired relay now that its sessions have ended",
                );
                self.stop_retired(relay.relay_id).await;
                crate::metrics::relay_reaped(Some(region), "max_age");
            }
        }
    }
}
