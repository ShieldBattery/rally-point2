//! Coordinator-mediated failover: move a session's homed group off a relay its
//! clients can no longer reach, and keep the resumed descriptors that carry the
//! move up to date. Everything that mutates a live session's serving set after
//! creation lives here, so the ordering rules that make the move safe against a
//! concurrent close sit in one place.

use rally_point_proto::control::{DepartedSlot, RegionId, RelayEndpoint, TenantId};
use rally_point_proto::ids::{RelayId, SessionId};

use crate::registry::{self, cert_fingerprint};

use super::RehomeOutcome;
use super::descriptor::build_descriptor;
use super::placement::relay_finalize_capable;
use super::setup::SessionSetup;

/// The replacement relay a prior [`rehome`] already recorded for
/// `(tenant, session, dead_relay)`, if one exists and its target is still live.
///
/// This is the idempotent fast path the re-home handler consults *before*
/// charging a rate-limit token: a straggler re-asking about a relay this session
/// already re-homed off must get the recorded answer without spending a token a
/// real survivor may need for the same session's bucket. Returns `None` when no
/// rehome was recorded (the caller then falls through to the rate-limited
/// [`rehome`] path) or when the recorded target has since left the registry.
///
/// A fully-closed session never matches: its recorded rehomes are cleared by
/// [`forget_rehomes`](SessionSetup::forget_rehomes) at close, at the same moment its membership is retired. This
/// is the lock-free sibling of the identical lookup inside [`rehome`], which runs
/// there under the rehomes lock so the read-and-mutate stays atomic; a shared
/// helper cannot be reused there without re-entering that lock.
/// The session's recorded build-class cohort — whether its relays advertise
/// the finalized-drop capability — or `None` for a session this coordinator
/// lifetime doesn't know. Enrollment consults this to evict a session from a
/// relay that re-enrolled on the other side of the boundary, in either
/// direction: build classes must never mix in one session.
pub(crate) fn session_capable_cohort(
    setup: &SessionSetup,
    tenant: &TenantId,
    session: SessionId,
) -> Option<bool> {
    setup
        .session_refs
        .lock()
        .get(&(tenant.clone(), session))
        .map(|refs| refs.capable_cohort)
}

pub fn recorded_rehome(
    setup: &SessionSetup,
    tenant: &TenantId,
    session: SessionId,
    dead_relay: RelayId,
) -> Option<RelayEndpoint> {
    let existing = *setup
        .rehomes
        .lock()
        .get(&(tenant.clone(), session, dead_relay))?;
    let entry = registry::entry(&setup.registry, existing)?;
    Some(RelayEndpoint::from(&entry))
}

/// Coordinator-mediated failover: the client believes `dead_relay` has died and
/// asks where its session should move. Returns [`RehomeOutcome::Stay`] when the
/// relay is in fact still enrolled (a false alarm the coordinator authoritatively
/// overrules from the registry), [`RehomeOutcome::Unavailable`] when the session
/// is unknown or no live relay can take it over, and otherwise moves the whole
/// homed group to a replacement relay and returns its [`RelayEndpoint`].
///
/// The replacement `R_new` is chosen as a live relay **already serving** the
/// session if one exists (earliest in the authority order, which the serving set
/// records home-first), else the lowest-id available relay in the **dead relay's
/// recorded region**, else the lowest-id available relay overall. The dead relay
/// is replaced **in place** in the serving set — which is also the descriptors'
/// authority order — so `R_new` inherits its rank, and every serving relay's
/// descriptor is rebuilt as a `resumed` (rehome) descriptor seeding
/// `departed_slots`. The push to `R_new` is recorded first, so it is staged for
/// its control connection before this returns.
///
/// Idempotent per `(tenant, session, dead_relay)`: a concurrent or repeated call
/// naming the same dead relay returns the same `R_new` without re-mutating the
/// session's relay set, as long as that target is still live.
pub fn rehome(
    setup: &SessionSetup,
    tenant: &TenantId,
    session: SessionId,
    dead_relay: RelayId,
    departed_slots: Vec<DepartedSlot>,
) -> RehomeOutcome {
    rehome_inner(
        setup,
        &(tenant.clone(), session),
        dead_relay,
        true,
        move || departed_slots,
        || {},
        |_| {},
    )
}

/// [`rehome`] with a synchronous assignment-commit hook. The hook runs after the
/// authoritative serving set and slot homes are updated but before resumed
/// descriptors are published, while the outer assignment lock is still held.
/// This lets lifecycle bookkeeping install the same assignment boundary before a
/// replacement can report `SessionClosed`; close handling takes that lock too, so
/// no terminal notice can observe one side of the mutation and commit on the
/// other.
pub fn rehome_with_assignment_commit(
    setup: &SessionSetup,
    tenant: &TenantId,
    session: SessionId,
    dead_relay: RelayId,
    read_departed: impl FnOnce() -> Vec<DepartedSlot>,
    assignment_committed: impl FnOnce(RelayId),
) -> RehomeOutcome {
    rehome_inner(
        setup,
        &(tenant.clone(), session),
        dead_relay,
        true,
        read_departed,
        || {},
        assignment_committed,
    )
}

/// Whether `relay`'s currently-presented cert (`current_der`) still matches the
/// cert `session`'s clients pinned to it, per the fingerprint recorded in
/// [`SessionRefs::relay_certs`]. A session with no recorded cert for `relay` (a
/// gap no caller in this module is expected to leave) reads as matching, so an
/// incomplete record cannot itself force a spurious move off a healthy relay.
fn cert_matches_pin(
    setup: &SessionSetup,
    key: &(TenantId, SessionId),
    relay: RelayId,
    current_der: &[u8],
) -> bool {
    let refs = setup.session_refs.lock();
    match refs.get(key).and_then(|refs| refs.relay_certs.get(&relay)) {
        Some(&recorded) => recorded == cert_fingerprint(current_der),
        None => true,
    }
}

/// [`rehome`]'s body, with a test seam `before_mutation` invoked after the
/// replacement relay is chosen but before the `session_relays` mutation — the exact
/// window in which a concurrent full close can land. Production passes a no-op; a
/// test passes a close to prove the mutation section re-validates and bails.
///
/// # Locking
///
/// Holds the outermost `assignment_lock` across its whole (await-free) body — so
/// the replacement pick (a registry read) and the descriptor re-staging are atomic
/// against a relay's drain mark, exactly as [`create_session`](crate::session::create_session)'s pick→commit is —
/// then the `rehomes` lock across the middle section, and the `session_relays` lock
/// *nested* inside that for the mutation. A terminal `SessionClosed` takes the same
/// assignment lock before lifecycle state, so it cannot cross the commit hook.
/// Direct lifecycle reapers take the same assignment lock through retirement,
/// then retire `session_relays` and `rehomes` as separate, non-nested
/// acquisitions after releasing lifecycle state. They therefore cannot cross
/// this body or invert its nested fine-lock order.
/// [`rehome`] that never answers Stay: the named relay is being **evicted**
/// (it re-enrolled without a capability its finalized-drops sessions
/// require), so "it is alive and its cert still matches" — the ordinary
/// false-alarm verdict — is exactly the case that must still move. The
/// caller marks the relay draining first, which keeps the replacement pick
/// from choosing the evictee itself.
pub fn rehome_evicting(
    setup: &SessionSetup,
    tenant: &TenantId,
    session: SessionId,
    evicted_relay: RelayId,
    departed_slots: Vec<DepartedSlot>,
) -> RehomeOutcome {
    rehome_inner(
        setup,
        &(tenant.clone(), session),
        evicted_relay,
        false,
        move || departed_slots,
        || {},
        |_| {},
    )
}

pub(super) fn rehome_inner(
    setup: &SessionSetup,
    session_key: &(TenantId, SessionId),
    dead_relay: RelayId,
    allow_stay: bool,
    read_departed: impl FnOnce() -> Vec<DepartedSlot>,
    before_mutation: impl FnOnce(),
    assignment_committed: impl FnOnce(RelayId),
) -> RehomeOutcome {
    let (tenant, session) = (&session_key.0, session_key.1);
    // The outermost assignment lock: this re-home's pick→re-stage span linearizes
    // against a relay's drain mark the same way `create_session` does.
    let _assign = setup.lock_assignment();

    let key = session_key.clone();
    let serving = setup.serving_relays(tenant, session);
    // Unknown session (never created here, or a coordinator restart wiped its
    // membership): there is nothing to re-home.
    if serving.is_empty() {
        return RehomeOutcome::Unavailable;
    }

    let mut rehomes = setup.rehomes.lock();

    // Idempotent / already-re-homed: a prior rehome for this dead relay already
    // chose a target. Return it verbatim as long as that target is still live,
    // without re-mutating. This lookup runs *before* the registry-liveness Stay
    // check below on purpose: a dead relay can restart and re-enroll under a fresh
    // cert, but a straggler client still pinned to its OLD cert (which this session
    // already re-homed off) can never accept that new cert, so telling it to Stay
    // would wedge it dialing a cert it can never pass. The recorded replacement is
    // the honest answer for it. (The handler runs the same lookup lock-free first —
    // see [`recorded_rehome`] — to answer a recorded re-ask without a rate-limit
    // token; this copy stays here so the read-and-mutate below is atomic.)
    if let Some(&existing) = rehomes.get(&(tenant.clone(), session, dead_relay))
        && let Some(entry) = registry::entry(&setup.registry, existing)
    {
        return RehomeOutcome::NewTarget(RelayEndpoint::from(&entry));
    }

    // The named relay is still enrolled, still serving this session, and the cert
    // its clients pinned still matches what it currently presents: a genuine false
    // alarm, so the coordinator authoritatively overrules the client's belief and
    // tells it to stay. The serving-set guard is what distinguishes this from the
    // already-re-homed straggler above: a relay that is enrolled but no longer in
    // the serving set was moved off in a prior re-home (handled by the idempotency
    // lookup), not a false alarm — falling into Stay there would pin the straggler
    // to a relay this session no longer uses.
    //
    // Enrolled-under-this-id is not, by itself, enough: a relay that restarted in
    // place re-enrolls under the same id with a fresh self-signed cert, and every
    // client still holding the old pin can never accept it — answering Stay would
    // wedge them dialing a cert they can never pass. The cert comparison catches
    // that case and falls through to a replacement pick instead. The relay's
    // enroll *generation* is deliberately not the signal: it also bumps on a
    // benign control-WS reconnect that keeps the same cert, where Stay remains the
    // right answer, so generation alone cannot tell the two apart.
    if allow_stay
        && serving.contains(&dead_relay)
        && let Some(entry) = registry::entry(&setup.registry, dead_relay)
        && cert_matches_pin(setup, &key, dead_relay, &entry.cert_der)
    {
        return RehomeOutcome::Stay;
    }

    // The named dead relay must actually be serving this session. It is not both
    // enrolled and serving (the stay-guard above ruled that out) and — checked here
    // — it has no recorded rehome yet (the idempotency block above returned if it
    // did), so if it is also not a member of the serving set, the client named a
    // relay unrelated to its session. The in-place `retain`/reassign over the serving set below would
    // then be a silent no-op, yet the function would still pick an `r_new`, re-push
    // `resumed` descriptors to the untouched (healthy) serving set, and record a
    // bogus idempotency entry. Refuse before any of that: the coordinator cannot
    // re-home a session off a relay that does not serve it. `Unavailable` (not
    // `Stay`) is the honest answer — the relay is genuinely gone, so "keep dialing
    // it" would be wrong; the client keeps its same-relay backoff and re-asks, and a
    // correctly-named later request (its real home relay) re-homes normally.
    if !serving.contains(&dead_relay) {
        return RehomeOutcome::Unavailable;
    }

    // The dead relay's recorded region, so the replacement can prefer a live relay
    // in the same region — keeping a re-homed slot near where it was placed. `None`
    // for an untagged dead relay (or a session with no recorded region), which
    // simply skips straight to the region-blind fallback.
    let dead_region: Option<RegionId> = setup
        .session_refs
        .lock()
        .get(&key)
        .and_then(|refs| refs.relay_regions.get(&dead_relay).cloned())
        .flatten();

    // Pick the replacement: prefer a live *available* relay already serving the
    // session (earliest in the authority order), else the lowest-id available relay
    // in the dead relay's region, else the lowest-id available relay overall. A
    // draining relay is never chosen — it asked to stop taking new work, and
    // re-homing a whole group onto it would be exactly that.
    //
    // The dead relay's own id is a legal candidate here: reaching this point means
    // it either is not enrolled at all (genuinely gone, so `is_available` below
    // already excludes it) or is enrolled under a cert that no longer matches the
    // pin (the stay-check above ruled out a match) — the restart-in-place case,
    // where the relay is live, enrolled, available, and its own fresh cert is
    // exactly the valid target every serving client needs to move onto.
    // The session's capability cohort (see `place_by_region`): a replacement
    // from the other side of the finalized-drop boundary would mix the
    // classes this session's placement deliberately kept apart. A
    // finalized-drops session picks only capable replacements; a session
    // created without the feature picks only incapable ones — and if its
    // cohort has fully drained from the fleet, the rehome is Unavailable (the
    // session ends) rather than silently mixed.
    let cohort_capable = setup
        .session_refs
        .lock()
        .get(&key)
        .is_some_and(|refs| refs.capable_cohort);
    // The cohort filter applies to BOTH branches: an already-serving member
    // can be capability-mismatched too — a serving relay that re-enrolled
    // across the finalized-drop boundary is being evicted concurrently, and
    // picking it here would land the whole homed group on the wrong side of
    // the boundary the placement kept apart.
    let cohort_matches = |id: RelayId| {
        registry::entry(&setup.registry, id)
            .is_some_and(|e| relay_finalize_capable(&e) == cohort_capable)
    };
    let r_new = serving
        .iter()
        .copied()
        .find(|&id| registry::is_available(&setup.registry, id) && cohort_matches(id))
        .or_else(|| {
            let mut entries = registry::available_entries(&setup.registry);
            entries.retain(|e| relay_finalize_capable(e) == cohort_capable);
            entries.sort_by_key(|e| e.relay_id);
            dead_region
                .as_ref()
                .and_then(|region| entries.iter().find(|e| e.region.as_ref() == Some(region)))
                .or_else(|| entries.first())
                .map(|e| e.relay_id)
        });
    let Some(r_new) = r_new else {
        return RehomeOutcome::Unavailable;
    };
    let Some(new_entry) = registry::entry(&setup.registry, r_new) else {
        return RehomeOutcome::Unavailable;
    };

    // Test seam: a full close landing between the serving-set snapshot above and
    // the mutation below (in production this is a no-op).
    before_mutation();

    // Move every slot homed on the dead relay onto R_new: replace the dead relay
    // in place in the serving set (which is also the authority order), so the
    // rebuilt descriptors rank R_new where the dead relay stood. If R_new was
    // already serving under a *different* id, drop the dead entry rather than
    // list it twice. A same-id replacement (the relay restarted in place) needs
    // neither move: its id already occupies its slot in the set, so membership
    // is left exactly as it is — only its recorded cert and descriptor, updated
    // below, actually change.
    //
    // Re-validate under the `session_relays` lock we are about to mutate: our
    // `serving` snapshot was taken before this lock, so a full close could have
    // cleared the membership (or a racing rehome moved the dead relay off) in the
    // meantime. If the entry is gone, or no longer names the dead relay, bail with
    // `Unavailable` here — before recording any rehome or pushing any descriptor —
    // so a close that lands mid-rehome can never leave a post-close recorded rehome
    // (which `recorded_rehome` would then serve token-free) or a re-staged
    // descriptor that resurrects the dead session on a live relay.
    {
        let mut relays = setup.session_relays.lock();
        let Some(members) = relays.get_mut(&key) else {
            return RehomeOutcome::Unavailable;
        };
        if !members.contains(&dead_relay) {
            return RehomeOutcome::Unavailable;
        }
        if dead_relay == r_new {
            // Same id, membership unchanged.
        } else if members.contains(&r_new) {
            members.retain(|&id| id != dead_relay);
        } else {
            for id in members.iter_mut() {
                if *id == dead_relay {
                    *id = r_new;
                }
            }
        }
    }

    // The dead relay's descriptor outbox entry for this session is stale — for a
    // different-id replacement it is no longer a member at all; for a same-id
    // restart its old descriptor predates the cert change and slot moves this
    // re-home is about to apply. Drop it now so that a relay reconnecting with
    // stale outbox state is not re-synced the pre-rehome descriptor before the
    // rebuild below re-records the current one. Safe even if the relay is
    // disconnected — the outbox is latest-wins current state.
    setup.descriptors.remove(dead_relay, tenant, session);

    // Move every slot's home-relay assignment from the dead relay onto R_new (a
    // same-id replacement reassigns each entry to its own unchanged id, a
    // harmless no-op), so the rebuilt descriptors below bind those slots to
    // their new home instead of a relay that no longer serves them — otherwise
    // R_new's descriptor would omit them from `homed_slots` and the client's own
    // reconnect to R_new would be refused as misrouted. Record R_new's cert here
    // too, replacing whatever this session had on file for the dead relay's id,
    // so the next Stay-check for R_new's id compares against the cert it
    // presents now rather than the one this re-home just moved off. A separate
    // lock acquisition from the `session_relays` mutation above, following
    // `take_session_membership`'s established precedent (see its doc): only
    // `session_relays` needs to be atomic with a racing close's re-validation,
    // and that already passed by this point, so a close landing exactly here
    // would simply retire this whole `session_refs` entry afterward regardless
    // of what this leaves in `homes`/`relay_certs`. Must still run before the
    // descriptor-rebuild loop below, which is what this position guarantees.
    if let Some(refs) = setup.session_refs.lock().get_mut(&key) {
        for home_relay in refs.homes.values_mut() {
            if *home_relay == dead_relay {
                *home_relay = r_new;
            }
        }
        refs.relay_certs.remove(&dead_relay);
        refs.relay_certs
            .insert(r_new, cert_fingerprint(&new_entry.cert_der));
        // Record R_new's region the same way, so a later re-home off R_new
        // prefers *its* region, and the dead relay's stale entry does not linger.
        refs.relay_regions.remove(&dead_relay);
        refs.relay_regions.insert(r_new, new_entry.region.clone());
    }

    // Install any coupled lifecycle view before publishing the resumed
    // descriptors. The assignment lock held across this function also gates
    // terminal-close handling, so a replacement close can only run after this
    // callback has completed.
    assignment_committed(r_new);

    // Read the departed accounting only now, at descriptor-build time under the
    // assignment lock, never as a caller-side snapshot: a departure notice can
    // land at any moment before this point, and one recorded after an early
    // snapshot but before publication would be omitted from every resumed
    // descriptor -- the fresh relay would then wait on a slot that permanently
    // left, since only surviving mesh peers could re-announce it (and after a
    // single-relay death there are none). A departure recorded after this read
    // reaches the fresh relay through those mesh peers' leave reconciliation,
    // which can only be missing in the case this read now covers.
    let departed_slots = read_departed();

    // Rebuild every serving relay's descriptor as a resumed (rehome) descriptor,
    // seeding the departed slots, and push each. Record R_new's first so it is
    // staged for its control connection before this returns, shrinking the
    // descriptor/dial race the client's backoff otherwise absorbs.
    let mut serving_now = setup.serving_relays(tenant, session);
    serving_now.sort_by_key(|&id| if id == r_new { 0 } else { 1 });
    for relay_id in serving_now {
        if let Some(descriptor) = build_descriptor(
            setup,
            tenant,
            session,
            relay_id,
            true,
            departed_slots.clone(),
        ) {
            setup.descriptors.record(relay_id, descriptor);
        }
    }

    // Re-point this session's earlier rehome records that answered with the
    // relay this rehome just moved off: after R1 → R2 and now R2 → R3, a
    // straggler still asking about R1 must be sent to R3, not to a
    // live-but-no-longer-serving R2 — the recorded-rehome fast path
    // validates only registry liveness, so a stale alias would misroute it
    // permanently (an evicted or restarted R2 is live in the registry while
    // serving nothing of this session).
    for ((alias_tenant, alias_session, _), target) in rehomes.iter_mut() {
        if alias_tenant == tenant && *alias_session == session && *target == dead_relay {
            *target = r_new;
        }
    }
    rehomes.insert((tenant.clone(), session, dead_relay), r_new);
    tracing::info!(
        tenant = tenant.as_ref(),
        session = session.0,
        dead_relay = dead_relay.0,
        new_relay = r_new.0,
        "session re-homed onto a replacement relay",
    );
    RehomeOutcome::NewTarget(RelayEndpoint::from(&new_entry))
}

/// Re-stages every serving relay's **resumed** descriptor for `session` with
/// the current departed accounting — a no-op unless the session's staged
/// descriptors are already resumed ones (it has been rehomed).
///
/// Called on every departure notice. A rehome reads the departed accounting
/// once, at descriptor-build time; a departure recorded after that read lives
/// only in the lifecycle's accounting and the reporting relay's own mesh
/// state, and if that relay drains or dies before mesh-reconciling with the
/// rehomed relay, no surviving peer can ever replay it — the fresh relay then
/// waits forever on a slot that permanently left. Re-staging folds the late
/// departure into the descriptors themselves, which every serving relay's
/// idempotent descriptor replay then seeds and fans.
///
/// `read_departed` is invoked under the assignment lock, exactly like the
/// rehome's own departed read, so the rebuild linearizes against a concurrent
/// rehome or terminal close: whichever runs second sees the other's committed
/// state. A never-rehomed session needs none of this — its relays all learn
/// departures over the mesh as they happen, and its original descriptors
/// carry no departure seeds by design.
pub(crate) fn refresh_resumed_descriptors(
    setup: &SessionSetup,
    tenant: &rally_point_proto::control::TenantId,
    session: SessionId,
    read_departed: impl FnOnce() -> Vec<DepartedSlot>,
) {
    let _assign = setup.lock_assignment();
    let serving = setup.serving_relays(tenant, session);
    let resumed = serving.iter().any(|&relay_id| {
        setup
            .descriptors
            .current_for(relay_id)
            .iter()
            .any(|d| d.tenant == *tenant && d.session == session && d.resumed)
    });
    if !resumed {
        return;
    }
    let departed_slots = read_departed();
    for relay_id in serving {
        if let Some(descriptor) = build_descriptor(
            setup,
            tenant,
            session,
            relay_id,
            true,
            departed_slots.clone(),
        ) {
            setup.descriptors.record(relay_id, descriptor);
        }
    }
}
