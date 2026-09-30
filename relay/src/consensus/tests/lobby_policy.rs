//! Descriptor policy verdicts for pre-game lobby commands.

use super::*;
use rally_point_proto::control::{AllowedLobbyCommand, LobbyPolicy};

fn policy(slot: u8, payload: &[u8]) -> LobbyPolicy {
    LobbyPolicy {
        allowed: vec![AllowedLobbyCommand {
            slot: SlotId(slot),
            payload: payload.to_vec(),
        }],
    }
}

#[test]
fn lobby_policy_waits_for_a_maker_and_allows_exact_records() {
    let registry = new_decision_makers();
    let k = key();

    assert_eq!(
        registry.admit_lobby_command(&k, SlotId(0), b"anything"),
        LobbyCommandVerdict::AwaitingDescriptor,
        "the caller decides whether a missing descriptor can be deferred",
    );

    let _ = registry.sync_maker(
        &k,
        MakerSync {
            lobby_policy: Some(policy(0, b"allowed")),
            ..MakerSync::new(bounds(1, 6), Authority::SelfRelay)
        },
    );
    assert_eq!(
        registry.admit_lobby_command(&k, SlotId(0), b"allowed"),
        LobbyCommandVerdict::Allowed
    );
    assert_eq!(
        registry.admit_lobby_command(&k, SlotId(1), b"allowed"),
        LobbyCommandVerdict::Violation
    );
    assert_eq!(
        registry.lock().get(&k).unwrap().eviction(SlotId(1)),
        Some(EvictionCause::LobbyViolation)
    );
}

#[test]
fn started_slot_drops_a_mismatch_without_eviction_or_report() {
    let (registry, mut notices) = notifying_registry();
    let k = key();
    let _ = registry.sync_maker(
        &k,
        MakerSync {
            lobby_policy: Some(policy(0, b"allowed")),
            ..MakerSync::new(bounds(1, 6), Authority::SelfRelay)
        },
    );
    registry.note_slot_started(&k, SlotId(0));
    let _ = notices.try_recv(); // the start report is unrelated to this verdict
    assert_eq!(
        registry.admit_lobby_command(&k, SlotId(0), b"wrong"),
        LobbyCommandVerdict::DroppedAfterStart
    );
    assert_eq!(registry.lock().get(&k).unwrap().eviction(SlotId(0)), None);
    assert!(notices.try_recv().is_err());
}

#[test]
fn re_push_cannot_replace_the_latched_lobby_policy() {
    let registry = new_decision_makers();
    let k = key();
    let _ = registry.sync_maker(
        &k,
        MakerSync {
            lobby_policy: Some(policy(0, b"first")),
            ..MakerSync::new(bounds(1, 6), Authority::SelfRelay)
        },
    );
    let _ = registry.sync_maker(
        &k,
        MakerSync {
            lobby_policy: Some(policy(0, b"replacement")),
            ..MakerSync::new(bounds(1, 6), Authority::SelfRelay)
        },
    );
    assert_eq!(
        registry.admit_lobby_command(&k, SlotId(0), b"first"),
        LobbyCommandVerdict::Allowed
    );
}
