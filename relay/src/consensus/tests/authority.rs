//! Descriptor re-push reconciliation and what promotion and demotion keep.

use super::*;

/// `sync_maker` creates on the first push and reconciles bounds and
/// authority on a re-push -- the descriptor is declarative, so who decides
/// follows the current relay set instead of staying frozen at creation.
#[test]
fn sync_maker_reconciles_bounds_and_authority_on_a_repush() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 5),
        Authority::SelfRelay,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    {
        let makers = registry.lock();
        let maker = makers.get(&k).unwrap();
        assert_eq!(maker.bounds, bounds(0, 5));
        assert_eq!(maker.authority, Authority::SelfRelay);
    }

    // A lower-id relay joined the session: this relay is no longer the
    // authority, and the coordinator widened the bounds.
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 99),
        Authority::Peer,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    let makers = registry.lock();
    let maker = makers.get(&k).unwrap();
    assert_eq!(maker.bounds, bounds(0, 99), "bounds follow the descriptor");
    assert_eq!(
        maker.authority,
        Authority::Peer,
        "authority follows the current relay set",
    );
}

/// At the registry-level free function: a descriptor re-push that promotes
/// this relay must thread the caller's real held-slot set through to the
/// maker, not silently drop it. A slot's drop hold is the token a
/// reconnecting client's return still redeems; passing the maker an empty
/// set regardless of what the caller (here, an "apply_descriptor"
/// stand-in) actually knows from the drop-hold registry would let the
/// promotion decide (and broadcast) a leave for that slot anyway.
#[test]
fn sync_maker_promotion_skips_a_held_departure() {
    let registry = new_decision_makers();
    let k = key();
    // First push: this relay starts as a peer (not yet authority).
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::Peer,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    consensus_observe_and_hold(&registry, &k);

    // A re-push promotes this relay while slot 1's drop is held -- the
    // caller (standing in for `MeshControl::apply_descriptor`, which reads
    // the real drop-hold registry) passes the held set in.
    let held_slots = HashSet::from([SlotId(1)]);
    let leaves = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        held_slots,
        None,
        false,
    );
    assert!(
        leaves.is_empty(),
        "a descriptor-driven promotion must not decide a held departure",
    );
    let makers = registry.lock();
    assert!(
        makers.get(&k).unwrap().has_departure(SlotId(1)),
        "the departure record survives, undecided, for a later manual request",
    );
}

/// A relay demoted by a re-push stops broadcasting: only the authority
/// stamps, so its pending directive is dropped -- while its condition
/// history survives (it describes the links, not the descriptor).
#[test]
fn losing_authority_drops_the_pending_directive_but_keeps_history() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::SelfRelay,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    {
        let mut makers = registry.lock();
        let maker = makers.get_mut(&k).unwrap();
        ingest_at(maker, &conditions(0, 150_000, 0, 100), 1).expect("a raise fires");
    }
    assert!(active_directive(&registry, &k).is_some());

    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 20),
        Authority::Peer,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    assert_eq!(
        active_directive(&registry, &k),
        None,
        "a demoted relay stops stamping",
    );
    let makers = registry.lock();
    assert!(
        makers.get(&k).unwrap().target().is_some(),
        "condition history survives the demotion",
    );
}

/// `deregister_maker` removes a session's decision-maker.
#[test]
fn deregister_maker_removes_session() {
    let registry = new_decision_makers();
    let k = key();
    let _ = sync_maker(
        &registry,
        &k,
        bounds(0, 5),
        Authority::SelfRelay,
        HashSet::new(),
        std::collections::HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        None,
        false,
    );
    assert!(registry.lock().contains_key(&k));
    deregister_maker(&registry, &k);
    assert!(!registry.lock().contains_key(&k));
}

// -- Departure notifier --
