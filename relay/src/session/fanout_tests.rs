//! One shared set of test bodies for the three per-session fan-out registries.
//!
//! [`chat`](crate::session::chat), [`lobby`](crate::session::lobby) and
//! [`skin`](crate::session::skin) are the same registry with three replay
//! policies: a map of per-member push channels keyed by session, a
//! register/deregister/end-session lifecycle, an `admit` gate the client edge
//! runs before anything is fanned out, and a `deliver` that skips the stamped
//! author. Only the replay policy differs — none, an ordered log, a
//! latest-blob-per-slot map — so the guarantees that do not touch replay are
//! written once here, generic over [`FanOutChannel`], and each module
//! instantiates them beside the tests for its own policy.

use tokio::sync::mpsc;

use rally_point_proto::ids::SlotId;

use crate::routing::SessionKey;
use crate::test_support::session_key;

/// One session-scoped fan-out registry, as the shared bodies below drive it.
/// Implemented by a unit struct inside each module's own test module, so the
/// module's private constants and functions stay private.
pub(crate) trait FanOutChannel {
    /// The registry the module's `new_*_registry` builds.
    type Registry;
    /// The message the registry fans out to a session's local members.
    type Message;

    /// The burst size `admit` gives each authoring slot.
    const RATE_BURST: u32;

    fn new_registry() -> Self::Registry;
    fn register_member(
        registry: &Self::Registry,
        key: &SessionKey,
        slot: SlotId,
    ) -> mpsc::Receiver<Self::Message>;
    fn deregister_member(registry: &Self::Registry, key: &SessionKey, slot: SlotId);
    fn end_session(registry: &Self::Registry, key: &SessionKey);
    /// The client-edge admission gate. `len` is the payload length a size cap
    /// measures; a channel with no size cap ignores it.
    fn admit(registry: &Self::Registry, key: &SessionKey, slot: SlotId, len: usize) -> bool;
    /// The fan-out itself. A channel whose `deliver` returns nothing reports
    /// `true`, since it refuses nothing.
    fn deliver(registry: &Self::Registry, key: &SessionKey, message: Self::Message) -> bool;
    /// A message stamped as authored by `slot`, carrying `body`.
    fn message(slot: u32, body: &str) -> Self::Message;
    /// `(author, body)` — what a member's receiver yields.
    fn parts(message: &Self::Message) -> (u32, String);
}

/// Everything currently queued on a member's receiver, in delivery order —
/// the member's slot-link task would write these to its control stream in
/// exactly this order.
pub(crate) fn drain<C: FanOutChannel>(rx: &mut mpsc::Receiver<C::Message>) -> Vec<(u32, String)> {
    let mut got = Vec::new();
    while let Ok(message) = rx.try_recv() {
        got.push(C::parts(&message));
    }
    got
}

/// One expected `(author, body)` line, as [`drain`] yields it.
fn line(author: u32, body: &str) -> (u32, String) {
    (author, body.to_owned())
}

/// The author is never echoed its own message — its own game applied it
/// locally — while every other local member receives it. A mesh-received
/// message carries a remote author no local member matches, so it reaches
/// every one of them.
pub(crate) fn the_author_is_skipped_and_every_other_member_is_reached<C: FanOutChannel>() {
    let registry = C::new_registry();
    let k = session_key(1);
    let mut host = C::register_member(&registry, &k, SlotId(0));
    let mut peer = C::register_member(&registry, &k, SlotId(1));

    C::deliver(&registry, &k, C::message(0, "from the host"));
    assert_eq!(
        drain::<C>(&mut host),
        vec![],
        "the author is not echoed its own",
    );
    assert_eq!(drain::<C>(&mut peer), vec![line(0, "from the host")]);

    // Authored by a remote slot and arriving off the mesh: neither local
    // member is its author, so both of them receive it.
    C::deliver(&registry, &k, C::message(7, "from relay B"));
    assert_eq!(drain::<C>(&mut host), vec![line(7, "from relay B")]);
    assert_eq!(drain::<C>(&mut peer), vec![line(7, "from relay B")]);
}

/// A deregistered member stops receiving — its slot-link task has ended, so
/// nothing may keep filling a queue nobody drains — while the members that
/// remain are undisturbed. Ending the session then drops the state wholesale,
/// so a fresh join starts from empty.
pub(crate) fn a_deregistered_member_stops_receiving_and_end_session_clears_the_state<
    C: FanOutChannel,
>() {
    let registry = C::new_registry();
    let k = session_key(1);
    let mut leaving = C::register_member(&registry, &k, SlotId(0));
    let mut staying = C::register_member(&registry, &k, SlotId(1));

    C::deliver(&registry, &k, C::message(7, "first"));
    C::deregister_member(&registry, &k, SlotId(0));
    C::deliver(&registry, &k, C::message(7, "second"));

    assert_eq!(
        drain::<C>(&mut leaving),
        vec![line(7, "first")],
        "the removed member received nothing fanned out after its deregistration",
    );
    assert_eq!(
        drain::<C>(&mut staying),
        vec![line(7, "first"), line(7, "second")],
        "the remaining member is undisturbed",
    );

    C::end_session(&registry, &k);
    let mut after = C::register_member(&registry, &k, SlotId(1));
    assert_eq!(
        drain::<C>(&mut after),
        vec![],
        "a join after end_session has nothing to catch up on",
    );
}

/// The rate cap's burst-then-reject half: an authoring slot may spend its
/// whole burst back-to-back, and the next message inside the window is
/// refused. Recovery after a refill is the token bucket's own test
/// (`crate::rate_limit`), driven off synthetic instants rather than a real
/// wait on the production interval.
pub(crate) fn a_burst_past_the_rate_cap_is_rejected<C: FanOutChannel>() {
    let registry = C::new_registry();
    let k = session_key(1);
    for _ in 0..C::RATE_BURST {
        assert!(C::admit(&registry, &k, SlotId(0), 4));
    }
    assert!(!C::admit(&registry, &k, SlotId(0), 4));
}

/// The cap is keyed per authoring slot, so one flooding member can never
/// spend another member's budget.
pub(crate) fn the_rate_cap_is_independent_per_slot<C: FanOutChannel>() {
    let registry = C::new_registry();
    let k = session_key(1);
    for _ in 0..C::RATE_BURST {
        assert!(C::admit(&registry, &k, SlotId(0), 4));
    }
    assert!(
        !C::admit(&registry, &k, SlotId(0), 4),
        "slot 0 exhausted its burst",
    );
    assert!(
        C::admit(&registry, &k, SlotId(1), 4),
        "a different slot has its own, untouched budget",
    );
}

/// The size cap's exact boundary: a payload sized at the cap is admitted, one
/// byte past it is refused.
pub(crate) fn the_size_cap_admits_exactly_its_boundary<C: FanOutChannel>(cap: usize) {
    let registry = C::new_registry();
    let k = session_key(1);
    assert!(C::admit(&registry, &k, SlotId(0), cap));
    assert!(!C::admit(&registry, &k, SlotId(0), cap + 1));
}

/// The exactly-once boundary for a channel that replays: a message already
/// retained when a member joins reaches it through the replay and is not also
/// fanned to it live. Nothing else asserts the *absence* of that duplicate.
pub(crate) fn a_retained_message_is_replayed_to_a_joiner_and_not_also_fanned_live<
    C: FanOutChannel,
>() {
    let registry = C::new_registry();
    let k = session_key(1);
    let _host = C::register_member(&registry, &k, SlotId(0));
    C::deliver(&registry, &k, C::message(0, "before the join"));

    let mut peer = C::register_member(&registry, &k, SlotId(1));
    assert_eq!(
        drain::<C>(&mut peer),
        vec![line(0, "before the join")],
        "exactly one copy -- from the replay, never a second live delivery",
    );
}
