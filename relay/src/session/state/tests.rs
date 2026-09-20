//! What each teardown phase sweeps — and, as importantly, what it leaves.

use super::*;

use rally_point_proto::messages::{GameChat, LobbyCommand, PlayerSkin};

use crate::mesh::{SeenRegistries, has_resumable_state, mark_seen, new_seen_registries};
use crate::session::turn_ring::TurnOrigin;
use crate::session::{chat, lobby, presence, skin};
use crate::test_support::{seed_local_maker, session_key};

/// A session with something in every store a teardown phase could sweep: two
/// lobby/chat/skin members with a command each logged, a forwarded turn in the
/// ring and its receipt in the seen gate, an undecided drop hold with the
/// abandon timer armed, a journaled turn, a provisional mark, and a live gate
/// entry.
struct Seeded {
    state: SessionState,
    seen: SeenRegistries,
    key: crate::key::SessionKey,
    lobby_rx: tokio::sync::mpsc::Receiver<LobbyCommand>,
    chat_rx: tokio::sync::mpsc::Receiver<GameChat>,
    skin_rx: tokio::sync::mpsc::Receiver<PlayerSkin>,
}

impl Seeded {
    fn new() -> Seeded {
        let state = SessionState::default();
        let seen = new_seen_registries();
        let key = session_key(1);

        // Slot 1 is the member the assertions watch; slot 0 authors, so slot 1
        // is never skipped as the author of its own command.
        let lobby_rx = lobby::register_member(&state.lobby, &key, SlotId(1));
        let chat_rx = chat::register_member(&state.chat, &key, SlotId(1));
        let skin_rx = skin::register_member(&state.skins, &key, SlotId(1));
        lobby::deliver(
            &state.lobby,
            &key,
            LobbyCommand {
                slot: 0,
                ..Default::default()
            },
        );
        skin::deliver(
            &state.skins,
            &key,
            PlayerSkin {
                slot: 0,
                ..Default::default()
            },
        );

        state.turn_ring.record(
            &key,
            &rally_point_proto::messages::Payload {
                seq: 0,
                slot: 0,
                ..Default::default()
            },
            TurnOrigin::Local,
            2,
        );
        mark_seen(&seen, &key, SlotId(0), 0);

        state.drop_holds.hold(key.clone(), SlotId(0));
        state
            .drop_holds
            .arm_abandon(key.clone(), |_| {})
            .expect("the abandon timer arms");

        state.provisional_turns.arm();
        assert!(
            state.provisional_turns.reserve(&key),
            "the journal reserves the session under its ceiling",
        );
        assert!(matches!(
            state.provisional_turns.hold(
                &key,
                crate::session::provisional_turns::PennedIngress::Turn(
                    SlotId(0),
                    rally_point_proto::messages::Payload {
                        seq: 1,
                        slot: 0,
                        ..Default::default()
                    },
                ),
            ),
            crate::session::provisional_turns::HoldOutcome::Held
        ));
        assert!(
            state
                .provisional
                .mark_if_undescribed(&state.decision_makers, &key),
            "a session with no maker takes the provisional mark",
        );
        state.gates.with_ingress(&key, || {}).expect("a live gate");

        Seeded {
            state,
            seen,
            key,
            lobby_rx,
            chat_rx,
            skin_rx,
        }
    }

    /// Whether a member registering now replays anything — the observable
    /// difference between "the session's side channels are still here" and
    /// "they were swept".
    fn side_channels_retained(&self) -> bool {
        let lobby_replay = lobby::register_member(&self.state.lobby, &self.key, SlotId(2));
        let skin_replay = skin::register_member(&self.state.skins, &self.key, SlotId(2));
        !lobby_replay.is_empty() && !skin_replay.is_empty()
    }
}

#[tokio::test]
async fn remove_slot_drops_only_the_slots_side_channel_membership() {
    let seeded = Seeded::new();

    seeded.state.remove_slot(&seeded.key, SlotId(1));

    // The member is gone from all three channels: nothing delivered after the
    // removal reaches it.
    lobby::deliver(
        &seeded.state.lobby,
        &seeded.key,
        LobbyCommand {
            slot: 0,
            ..Default::default()
        },
    );
    chat::deliver(
        &seeded.state.chat,
        &seeded.key,
        GameChat {
            slot: 0,
            ..Default::default()
        },
    );
    skin::deliver(
        &seeded.state.skins,
        &seeded.key,
        PlayerSkin {
            slot: 0,
            ..Default::default()
        },
    );
    // The one queued item each is the pre-removal seed; nothing was added.
    assert_eq!(seeded.lobby_rx.len(), 1);
    assert_eq!(seeded.chat_rx.len(), 0);
    assert_eq!(seeded.skin_rx.len(), 1);

    // The session's own state is untouched — a remaining or reconnecting
    // member still replays it, and nothing else is swept by one slot leaving.
    assert!(seeded.side_channels_retained());
    assert_eq!(seeded.state.turn_ring.len(&seeded.key), 1);
    assert!(has_resumable_state(&seeded.seen, &seeded.key));
    assert!(seeded.state.drop_holds.is_pending(&seeded.key, SlotId(0)));
    assert!(seeded.state.drop_holds.abandon_armed(&seeded.key));
    assert!(seeded.state.provisional.is_marked(&seeded.key));
    assert_eq!(seeded.state.provisional_turns.held(&seeded.key), 1);
    assert!(!seeded.state.gates.is_retired(&seeded.key));
}

#[tokio::test]
async fn close_emptied_sweeps_the_side_channels_but_keeps_the_reconnect_token() {
    let seeded = Seeded::new();
    // The journal must be empty for the gate to be discardable; a journal with
    // anything in it is the one thing that holds the emptied close back.
    seeded.state.provisional_turns.discard(&seeded.key);

    seeded.state.close_emptied(&seeded.key, &seeded.seen);

    assert!(
        !seeded.side_channels_retained(),
        "the last local member is gone, so the lobby log and skin map go with it",
    );
    assert_eq!(seeded.state.turn_ring.len(&seeded.key), 0);
    assert!(!has_resumable_state(&seeded.seen, &seeded.key));
    assert!(!seeded.state.provisional.is_marked(&seeded.key));
    assert_eq!(
        seeded.state.gates.tracked(),
        0,
        "a session no descriptor ever named has no retirement coming, so its \
         gate is dropped here",
    );

    // The undecided hold is the reconnect-admission token and the unlock clock
    // for a drop nobody has decided, so it outlives the close.
    assert!(seeded.state.drop_holds.is_pending(&seeded.key, SlotId(0)));
}

#[tokio::test]
async fn retire_sweeps_everything_the_descriptor_owned() {
    let seeded = Seeded::new();
    seed_local_maker(&seeded.state.decision_makers, &seeded.key, &[0, 1]);
    presence::record_own(&seeded.state.presence, &seeded.key, 2);

    seeded.state.retire(&seeded.key, &seeded.seen);

    assert!(seeded.state.gates.is_retired(&seeded.key));
    assert!(!crate::consensus::maker_exists(
        &seeded.state.decision_makers,
        &seeded.key
    ));
    assert_eq!(presence::verdict(&seeded.state.presence, &seeded.key), None);
    assert_eq!(seeded.state.provisional_turns.held(&seeded.key), 0);
    assert_eq!(seeded.state.turn_ring.len(&seeded.key), 0);
    assert!(!has_resumable_state(&seeded.seen, &seeded.key));
    // Terminal for the drop bookkeeping: no admission path remains for a held
    // slot's reconnect, so the hold and the timer go where the emptied close
    // would have kept them.
    assert!(!seeded.state.drop_holds.is_pending(&seeded.key, SlotId(0)));
    assert!(!seeded.state.drop_holds.abandon_armed(&seeded.key));

    // The side channels go too: the emptied close that would otherwise drop
    // them is refused by the gate this retirement just closed, so a session
    // retired with members still connected has no other sweep coming.
    assert!(
        !seeded.side_channels_retained(),
        "retirement is terminal, so the lobby log, chat state and skin map \
         must not outlive the session",
    );
}
