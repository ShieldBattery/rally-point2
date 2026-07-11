//! Active-player presence: which slots are connected to a relay *right now*,
//! aggregated from the rosters relays piggyback on their heartbeats — so a
//! tenant's app server can ask "is user U in a live game" and block an in-game
//! player from re-queueing.
//!
//! The store is a flat map keyed by `(tenant, session, slot)`, each entry stamped
//! with the relay that reported it, the reporting connection's **generation**
//! (the registry's fencing token), and when it was last seen. Slots — never
//! users: the relay is PII-free, so user resolution happens only at query time,
//! coordinator-side, against the session refs the tenant itself supplied at
//! session creation.
//!
//! # Declarative replace, fenced by generation
//!
//! Every heartbeat carries the relay's whole current roster, so applying one is
//! a per-relay **replace**: drop everything this relay previously reported (at
//! this or an older generation) and insert the fresh set. Lost or reordered
//! beats self-heal on the next one. The generation fence closes the same race
//! the registry's enroll/deregister fencing closes: a stale connection's late
//! beat, or its teardown, must not disturb what the relay's *newer* connection
//! has since reported. Callers additionally drop a stale connection's beat
//! outright ([`crate::registry::generation_is_current`]); the in-store fences
//! are the second line of defense.
//!
//! # Freshness: prompt clear on drop, TTL for silence
//!
//! A relay's control connection dropping clears its entries immediately — the
//! prompt "these players may queue again" signal for the common case (the relay
//! exited, its games are over or failing over). The TTL covers the remaining
//! case: a connection that is up but silent (or a coordinator-side stall), where
//! entries go stale without a drop event. Expiry is lazy — queries filter on
//! `last_seen`; there is no sweeper, because the per-relay replace and the
//! on-drop clear already bound the map by the fleet's live slots.
//!
//! Like the registry, this is in-memory state: a coordinator restart forgets it
//! and the next round of heartbeats (one interval, ~10s) repopulates it. The
//! query endpoint is deliberately **fail-open** across that window (see
//! [`crate::api`]'s presence endpoint).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rally_point_proto::control::{SessionPresence, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};

/// How long a presence entry stays fresh after the beat that reported it. 3.5×
/// the relay's 10s heartbeat interval: two consecutive lost beats still leave an
/// in-game player "present", so ordinary jitter never flaps a user to
/// "queueable" mid-game — and it sits at (not under) the control connection's
/// 30s liveness deadline, so a dead connection's wholesale on-drop clear always
/// fires before any of its entries would expire one by one.
pub const PRESENCE_TTL: Duration = Duration::from_secs(35);

/// One reported slot's provenance: which relay said so, over which connection
/// generation, and when. The generation is what lets a teardown (or a stale
/// beat) touch only the state its own connection reported.
struct PresenceEntry {
    relay: RelayId,
    generation: u64,
    last_seen: Instant,
}

/// The store's key: one slot of one session, tenant-scoped like every session
/// id in the system.
type SlotKey = (TenantId, SessionId, SlotId);

/// The coordinator's active-player presence store: `(tenant, session, slot)` →
/// the entry describing who last reported it connected. A plain (non-async)
/// mutex, same idiom as the relay registry: every critical section is a short,
/// await-free map edit or scan, never held across I/O.
#[derive(Clone, Default)]
pub struct PresenceStore {
    entries: Arc<Mutex<HashMap<SlotKey, PresenceEntry>>>,
}

/// Creates an empty presence store (a coordinator no relay has beaten at yet).
pub fn new_store() -> PresenceStore {
    PresenceStore::default()
}

/// Applies one relay's heartbeat roster as of `now`: removes every entry this
/// relay reported at this or an older generation, then inserts the fresh set
/// stamped `(relay, generation, now)`.
///
/// Generation-fenced at both steps: entries a *newer* connection reported (a
/// reconnect this beat raced) are neither removed by the replace nor overwritten
/// by the insert, so a stale beat that slipped past the caller's
/// [`generation_is_current`](crate::registry::generation_is_current) gate still
/// cannot clobber the live connection's truth.
pub fn apply_heartbeat(
    store: &PresenceStore,
    relay: RelayId,
    generation: u64,
    sessions: &[SessionPresence],
    now: Instant,
) {
    let mut entries = store.entries.lock();
    entries.retain(|_, e| !(e.relay == relay && e.generation <= generation));
    for session in sessions {
        for &slot in &session.slots {
            let key = (session.tenant.clone(), session.session, slot);
            match entries.get(&key) {
                // A newer connection's entry wins over this beat.
                Some(existing) if existing.generation > generation => {}
                _ => {
                    entries.insert(
                        key,
                        PresenceEntry {
                            relay,
                            generation,
                            last_seen: now,
                        },
                    );
                }
            }
        }
    }
}

/// Clears every entry the connection `(relay, generation)` reported — the prompt
/// "queueable again" signal a control-connection drop fires.
///
/// Exact-generation fenced: a stale connection's teardown racing a reconnect
/// removes only its *own* entries, never the fresh presence the reconnected
/// connection has already reported under a newer generation — the same race the
/// registry's [`remove_if_current`](crate::registry::remove_if_current) fencing
/// closes for enrollment itself.
pub fn clear_connection(store: &PresenceStore, relay: RelayId, generation: u64) {
    store
        .entries
        .lock()
        .retain(|_, e| !(e.relay == relay && e.generation == generation));
}

/// The tenant's presence entries still fresh at `now` (within [`PRESENCE_TTL`]
/// of their reporting beat), as `(session, slot)` pairs. Expiry happens here,
/// lazily — a stale entry is simply not returned; nothing sweeps it, because the
/// per-relay replace and the on-drop clear already bound the map.
pub fn fresh_slots(
    store: &PresenceStore,
    tenant: &TenantId,
    now: Instant,
) -> Vec<(SessionId, SlotId)> {
    store
        .entries
        .lock()
        .iter()
        .filter(|((t, _, _), entry)| {
            t == tenant && now.duration_since(entry.last_seen) < PRESENCE_TTL
        })
        .map(|((_, session, slot), _)| (*session, *slot))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> TenantId {
        TenantId("sb-test".to_owned())
    }

    fn roster(session: u64, slots: &[u8]) -> Vec<SessionPresence> {
        vec![SessionPresence {
            tenant: tenant(),
            session: SessionId(session),
            slots: slots.iter().map(|&s| SlotId(s)).collect(),
        }]
    }

    fn fresh_now(store: &PresenceStore, now: Instant) -> Vec<(SessionId, SlotId)> {
        let mut slots = fresh_slots(store, &tenant(), now);
        slots.sort_by_key(|(s, slot)| (s.0, slot.0));
        slots
    }

    #[test]
    fn a_beat_replaces_the_relays_prior_roster() {
        // Declarative replace: a slot absent from the next beat disappears; the
        // beat's own slots are the whole truth.
        let store = new_store();
        let now = Instant::now();
        apply_heartbeat(&store, RelayId(1), 5, &roster(1, &[0, 2]), now);
        assert_eq!(
            fresh_now(&store, now),
            vec![(SessionId(1), SlotId(0)), (SessionId(1), SlotId(2))],
        );

        // Slot 2's client disconnected: the next beat no longer names it.
        apply_heartbeat(&store, RelayId(1), 5, &roster(1, &[0]), now);
        assert_eq!(fresh_now(&store, now), vec![(SessionId(1), SlotId(0))]);

        // An empty beat (the relay went idle) clears everything it reported.
        apply_heartbeat(&store, RelayId(1), 5, &[], now);
        assert!(fresh_now(&store, now).is_empty());
    }

    #[test]
    fn a_stale_generations_beat_cannot_clobber_a_newer_connections_entries() {
        // The reconnect race, at the store level: the relay's new connection
        // (generation 8) reported the slot; a late beat from its old connection
        // (generation 5) must neither remove nor overwrite that entry.
        let store = new_store();
        let now = Instant::now();
        apply_heartbeat(&store, RelayId(1), 8, &roster(1, &[0]), now);

        // The stale beat names a different roster entirely.
        apply_heartbeat(&store, RelayId(1), 5, &roster(2, &[3]), now);

        // The newer connection's entry survives; the stale beat's own inserts
        // land (vacant keys), but its replace could not touch generation 8.
        let slots = fresh_now(&store, now);
        assert!(
            slots.contains(&(SessionId(1), SlotId(0))),
            "the newer connection's entry survives a stale beat",
        );
    }

    #[test]
    fn clear_connection_is_fenced_by_exact_generation() {
        // A stale connection's teardown racing a reconnect: the reconnect
        // (generation 8) has already reported fresh presence; the old
        // connection's drop-clear (generation 5) must remove only its own
        // entries — the same race the registry's enroll fencing closes.
        let store = new_store();
        let now = Instant::now();
        apply_heartbeat(&store, RelayId(1), 8, &roster(1, &[0]), now);

        clear_connection(&store, RelayId(1), 5);
        assert_eq!(
            fresh_now(&store, now),
            vec![(SessionId(1), SlotId(0))],
            "a stale connection's clear leaves the reconnect's presence intact",
        );

        // The current connection's own drop clears its entries promptly.
        clear_connection(&store, RelayId(1), 8);
        assert!(fresh_now(&store, now).is_empty());
    }

    #[test]
    fn expiry_is_lazy_at_query_time() {
        // An entry past the TTL is filtered by the query, not swept: querying
        // "now" sees it, querying past the TTL does not — and the entry's later
        // refresh (a beat finally getting through) revives it.
        let store = new_store();
        let reported = Instant::now();
        apply_heartbeat(&store, RelayId(1), 5, &roster(1, &[0]), reported);

        assert_eq!(fresh_now(&store, reported), vec![(SessionId(1), SlotId(0))]);
        let past_ttl = reported + PRESENCE_TTL + Duration::from_secs(1);
        assert!(
            fresh_slots(&store, &tenant(), past_ttl).is_empty(),
            "an entry past the TTL is not returned",
        );

        // A fresh beat re-stamps it: present again.
        apply_heartbeat(&store, RelayId(1), 5, &roster(1, &[0]), past_ttl);
        assert_eq!(fresh_now(&store, past_ttl), vec![(SessionId(1), SlotId(0))],);
    }
}
