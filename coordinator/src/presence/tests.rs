use super::*;
use crate::test_support::tid;

fn roster(session: u64, slots: &[u8]) -> Vec<SessionPresence> {
    roster_for(tid(), session, slots)
}

fn roster_for(tenant: TenantId, session: u64, slots: &[u8]) -> Vec<SessionPresence> {
    vec![SessionPresence {
        tenant,
        session: SessionId(session),
        slots: slots.iter().map(|&s| SlotId(s)).collect(),
        ever_connected: vec![],
        started: vec![],
        started_at_ms: None,
    }]
}

fn fresh_now(store: &PresenceStore, now: Instant) -> Vec<(SessionId, SlotId)> {
    fresh_for(store, &tid(), now)
}

fn fresh_for(store: &PresenceStore, tenant: &TenantId, now: Instant) -> Vec<(SessionId, SlotId)> {
    let mut slots = fresh_slots(store, tenant, now);
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
fn an_entry_naming_no_slots_reports_no_presence() {
    // A relay keeps naming a session after its last local slot leaves, so it
    // can go on restating the load state it retained for it. Presence is a
    // live view, so such an entry must contribute nothing — exactly as
    // leaving the session out of the roster does.
    let store = new_store();
    let now = Instant::now();
    apply_heartbeat(&store, RelayId(1), 5, &roster(1, &[0]), now);
    assert_eq!(fresh_now(&store, now), vec![(SessionId(1), SlotId(0))]);

    apply_heartbeat(&store, RelayId(1), 5, &roster(1, &[]), now);
    assert!(fresh_now(&store, now).is_empty());
}

#[test]
fn a_query_sees_only_its_own_tenants_presence() {
    // Presence is a tenant-scoped answer about a tenant's own players: another
    // tenant's roster sitting in the same store must never surface in this
    // tenant's query, whatever session and slot ids the two happen to share.
    let store = new_store();
    let now = Instant::now();
    let other = TenantId("sb-other".to_owned());
    apply_heartbeat(&store, RelayId(1), 5, &roster(1, &[0]), now);
    apply_heartbeat(
        &store,
        RelayId(2),
        5,
        &roster_for(other.clone(), 1, &[0, 3]),
        now,
    );

    assert_eq!(
        fresh_now(&store, now),
        vec![(SessionId(1), SlotId(0))],
        "the other tenant's slot 3 is not this tenant's presence",
    );
    assert_eq!(
        fresh_for(&store, &other, now),
        vec![(SessionId(1), SlotId(0)), (SessionId(1), SlotId(3))],
        "and the other tenant still sees its own roster in full",
    );
}

#[test]
fn a_stale_generations_beat_cannot_clobber_a_newer_connections_entries() {
    // The reconnect race, at the store level: the relay's new connection
    // (generation 8) reported the slot, and a late beat from its old connection
    // (generation 5) names that very slot. Neither the replace nor the insert
    // may touch the entry — and the entry must keep generation 8's provenance,
    // not be rewritten under generation 5.
    let store = new_store();
    let now = Instant::now();
    apply_heartbeat(&store, RelayId(1), 8, &roster(1, &[0]), now);
    apply_heartbeat(&store, RelayId(1), 5, &roster(1, &[0]), now);

    assert_eq!(
        fresh_now(&store, now),
        vec![(SessionId(1), SlotId(0))],
        "the newer connection's entry survives a stale beat",
    );

    // Provenance is what proves it was never overwritten: the stale
    // connection's own teardown, fenced on its exact generation, must not
    // touch an entry stamped generation 8...
    clear_connection(&store, RelayId(1), 5);
    assert_eq!(
        fresh_now(&store, now),
        vec![(SessionId(1), SlotId(0))],
        "the entry did not take on the stale beat's generation",
    );
    // ...while the generation that actually owns it clears it.
    clear_connection(&store, RelayId(1), 8);
    assert!(fresh_now(&store, now).is_empty());
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
        fresh_slots(&store, &tid(), past_ttl).is_empty(),
        "an entry past the TTL is not returned",
    );

    // A fresh beat re-stamps it: present again.
    apply_heartbeat(&store, RelayId(1), 5, &roster(1, &[0]), past_ttl);
    assert_eq!(fresh_now(&store, past_ttl), vec![(SessionId(1), SlotId(0))],);
}
