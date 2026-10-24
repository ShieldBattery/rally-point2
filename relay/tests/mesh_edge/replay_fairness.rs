//! Large mesh recovery must leave the shared link available to other sessions.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::mesh::MeshPresence;
use rally_point_proto::messages::{
    MeshAckCursor, MeshAckCursors, MeshControlFrame, MeshResumeCursors, Payload,
    mesh_control_frame::Kind,
};
use rally_point_relay::key::SessionKey;
use rally_point_relay::mesh;
use rally_point_relay::routing::Sessions;
use rally_point_relay::session::turn_ring::TurnOrigin;
use rally_point_transport::{MeshLink, MeshSessionKey};
use tokio::sync::mpsc;

use crate::helpers::*;

const FIRST: u64 = 10_000;
const REPLAY_WINDOW: usize = 256;

fn key(session: u64) -> SessionKey {
    SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(session),
    }
}

fn transport_key(key: &SessionKey) -> MeshSessionKey {
    MeshSessionKey::new(key.session, key.tenant.as_ref())
}

fn replay_request(key: &SessionKey, prefer_recent: bool) -> MeshControlFrame {
    MeshControlFrame {
        session: key.session.0,
        kind: Some(Kind::MeshResumeCursors(MeshResumeCursors {
            cursors: vec![],
            resuming: true,
            prefer_recent,
        })),
    }
}

/// Returns newly delivered turns from either production mesh delivery path.
async fn next_turns(
    peer: &mut MeshLink,
    control: &mut mpsc::Receiver<MeshControlFrame>,
) -> Result<(SessionId, Vec<Payload>), AnyError> {
    loop {
        tokio::select! {
            packet = peer.recv() => {
                let packet = packet?;
                return Ok((packet.session, packet.delivery.fresh));
            }
            frame = control.recv() => {
                let frame = frame.ok_or("the mesh control stream ended during replay")?;
                if let Some(Kind::OversizeTurn(turn)) = frame.kind {
                    let session = SessionId(frame.session);
                    if peer.deliver_external(
                        MeshSessionKey::new(session, TENANT), SlotId(turn.slot as u8), turn.seq,
                    )? {
                        return Ok((session, vec![turn]));
                    }
                }
            }
        }
    }
}

fn record_history(
    seen: &mut HashSet<(u32, u64)>,
    turns: Vec<Payload>,
    slots: u32,
    turns_per_slot: u64,
) {
    for turn in turns {
        assert!(turn.slot < slots);
        assert!((FIRST..FIRST + turns_per_slot).contains(&turn.seq));
        assert!(
            seen.insert((turn.slot, turn.seq)),
            "each recovered turn is delivered once"
        );
    }
}

async fn acknowledge(
    peer: &mut MeshLink,
    inbound_control: &mpsc::Sender<MeshControlFrame>,
    key: &SessionKey,
    last_cursors: &mut HashMap<u32, u64>,
    slots: u32,
) -> Result<(), AnyError> {
    peer.send(transport_key(key), None, None)?;
    let mut cursors = Vec::new();
    for slot in 0..slots {
        if let Some(cursor) = peer.delivered_through(transport_key(key), SlotId(slot as u8))
            && last_cursors
                .get(&slot)
                .is_none_or(|previous| cursor > *previous)
        {
            cursors.push(MeshAckCursor {
                slot,
                delivered_through: cursor,
            });
            last_cursors.insert(slot, cursor);
        }
    }
    if !cursors.is_empty() {
        inbound_control
            .send(MeshControlFrame {
                session: key.session.0,
                kind: Some(Kind::MeshAckCursors(MeshAckCursors { cursors })),
            })
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_large_replay_yields_to_other_sessions_and_resumes_after_receipts() -> Result<(), AnyError>
{
    check_replay_progress(1, 8_640, true, false).await
}

#[tokio::test]
async fn each_slots_recent_tail_arrives_before_receipts_and_full_history_follows()
-> Result<(), AnyError> {
    check_replay_progress(7, 1_080, true, true).await
}

#[tokio::test]
async fn a_legacy_peer_gets_recording_order_and_full_recovery() -> Result<(), AnyError> {
    check_replay_progress(7, 1_080, false, false).await
}

async fn check_replay_progress(
    slots: u32,
    turns_per_slot: u64,
    prefer_recent: bool,
    newest_first: bool,
) -> Result<(), AnyError> {
    let count = slots as usize * turns_per_slot as usize;
    // Oversize turns use the ordered control stream, so this marker proves the
    // replay has not finished when another session's reply passes it.
    let sent_last = if newest_first {
        (0, FIRST)
    } else {
        (slots - 1, FIRST + turns_per_slot - 1)
    };
    let history = key(71);
    let live = key(72);
    let barrier = key(73);
    let sessions: Sessions = Arc::default();
    let state = mesh::MeshState::default();

    // Record each tick across the local slots, as their turns arrive in a game.
    // These cases use an eight-slot session's ring bound; one deliberately has a
    // single origin spanning more than a receive window.
    for seq in FIRST..FIRST + turns_per_slot {
        for slot in 0..slots {
            let commands = if (slot, seq) == sent_last {
                vec![0xAB; 5000]
            } else {
                vec![]
            };
            state.session.turn_ring.record(
                &history,
                &Payload {
                    seq,
                    slot,
                    commands: commands.into(),
                    ..Default::default()
                },
                TurnOrigin::Local,
                8,
            );
        }
    }
    assert_eq!(
        state
            .session
            .turn_ring
            .replay_local(&history, &HashMap::new(), true)
            .len(),
        count,
    );
    state.session.turn_ring.record(
        &live,
        &Payload {
            seq: 0,
            slot: 0,
            commands: vec![0xCD; 5000].into(),
            ..Default::default()
        },
        TurnOrigin::Local,
        1,
    );

    let (local, mut peer, _local_endpoint, _peer_endpoint) = mesh_link_pair().await;
    let local_connection = local.connection().clone();
    let peer_connection = peer.connection().clone();
    for session in [&history, &live, &barrier] {
        peer.open_session(transport_key(session));
    }
    for slot in 0..slots {
        peer.anchor_receive_window(transport_key(&history), SlotId(slot as u8), FIRST);
    }
    let presence_send = local_connection.open_uni().await?;
    let (_presence_tx, presence_rx) = mpsc::channel::<MeshPresence>(8);
    let (mut control_send, _unused_control_recv) = local_connection.open_bi().await?;
    rally_point_transport::mesh_control_stream::establish_mesh_control(&mut control_send).await?;
    let mut outbound_control =
        rally_point_transport::mesh_control_stream::spawn_mesh_control_reader_accepting(
            peer_connection.clone(),
        );
    // Direct input channels make the two asks ready together, matching the
    // decoded frames the production readers hand to the same driver loop.
    let (inbound_control, control_rx) = mpsc::channel(8);
    let (commands, commands_rx) = mpsc::unbounded_channel();
    let attempt = mesh::new_mesh_link_attempt();
    let lease = mesh::claim_mesh_link(&state, RelayId(9), &attempt).unwrap();
    let driver = tokio::spawn(mesh::run_mesh_link(
        local,
        mesh::MeshLinkIo {
            presence: rally_point_relay::session::presence::PresenceIo {
                peer_id: RelayId(9),
                tx: presence_send,
                rx: presence_rx,
            },
            control: mesh::MeshControlIo {
                tx: control_send,
                rx: control_rx,
            },
            lease,
        },
        commands_rx,
        sessions,
        state.clone(),
        mesh::IDLE_TIMEOUT,
    ));

    commands.send(mesh::MeshCommand::Join(history.clone()))?;
    commands.send(mesh::MeshCommand::Join(live.clone()))?;
    let mut outbound_presence =
        tokio::time::timeout(Duration::from_secs(5), peer_connection.accept_uni()).await??;
    assert_eq!(
        next_mesh_presence(&mut outbound_presence).await.session,
        history.session
    );
    assert_eq!(
        next_mesh_presence(&mut outbound_presence).await.session,
        live.session
    );
    inbound_control
        .send(replay_request(&history, prefer_recent))
        .await?;
    inbound_control
        .send(replay_request(&live, prefer_recent))
        .await?;

    let mut seen = HashSet::new();
    let mut sent_last_before_other_reply = false;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (session, turns) = next_turns(&mut peer, &mut outbound_control).await?;
            if session == history.session {
                sent_last_before_other_reply |=
                    turns.iter().any(|turn| (turn.slot, turn.seq) == sent_last);
                record_history(&mut seen, turns, slots, turns_per_slot);
            } else if session == live.session && !turns.is_empty() {
                assert_eq!(turns.len(), 1);
                assert_eq!(turns[0].seq, 0);
                break;
            }
        }
        Ok::<_, AnyError>(())
    })
    .await??;
    assert!(seen.len() < count);

    // Recovery stops at the operational unacknowledged-turn budget. QUIC still
    // acknowledges its own packets, but this peer sends neither payload ACKs nor
    // delivered-through cursors until the separate session has made progress.
    tokio::time::timeout(Duration::from_secs(5), async {
        while seen.len() < REPLAY_WINDOW {
            let (session, turns) = next_turns(&mut peer, &mut outbound_control).await?;
            if session == history.session {
                record_history(&mut seen, turns, slots, turns_per_slot);
                assert!(
                    seen.len() <= REPLAY_WINDOW,
                    "replay exceeded its receipt budget"
                );
            }
        }
        Ok::<_, AnyError>(())
    })
    .await??;
    if newest_first {
        for slot in 0..slots {
            for seq in FIRST + turns_per_slot - 3..FIRST + turns_per_slot {
                assert!(
                    seen.contains(&(slot, seq)),
                    "slot {slot}'s recent turn {seq} did not arrive within the first replay window"
                );
            }
        }
    } else {
        for slot in 0..slots {
            for seq in FIRST..FIRST + 3 {
                assert!(
                    seen.contains(&(slot, seq)),
                    "slot {slot}'s oldest turn {seq} did not arrive within the first replay window"
                );
            }
        }
    }
    assert!(
        !sent_last_before_other_reply,
        "the entire history replay ran before the other session's control reply"
    );
    // A negative claim needs a bounded observation window. Redundant repeats
    // may arrive, but no additional fresh identity may cross the paused window.
    let paused_until = tokio::time::Instant::now() + Duration::from_millis(100);
    while let Ok(event) =
        tokio::time::timeout_at(paused_until, next_turns(&mut peer, &mut outbound_control)).await
    {
        let (session, turns) = event?;
        if session == history.session {
            assert!(turns.is_empty(), "replay advanced without a receipt");
        }
    }

    // No acknowledgements for the long replay have been sent. A live turn and
    // membership changes for another session must still traverse the pair.
    mesh::fan_out_to_mesh(
        &state.links,
        &live,
        Payload {
            seq: 1,
            slot: 0,
            ..Default::default()
        },
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (session, turns) = next_turns(&mut peer, &mut outbound_control).await?;
            if session == history.session {
                assert!(turns.iter().all(|turn| (turn.slot, turn.seq) != sent_last));
                record_history(&mut seen, turns, slots, turns_per_slot);
            } else if session == live.session && turns.iter().any(|turn| turn.seq == 1) {
                break;
            }
        }
        Ok::<_, AnyError>(())
    })
    .await??;
    commands.send(mesh::MeshCommand::Leave(live.clone()))?;
    commands.send(mesh::MeshCommand::Join(barrier.clone()))?;
    assert_eq!(
        next_mesh_presence(&mut outbound_presence).await.session,
        barrier.session
    );
    assert!(
        state
            .links
            .lock()
            .get(&live)
            .is_none_or(|links| links.is_empty())
    );

    // Release receipts and drive both packet ACKs and cumulative mesh cursors,
    // as a production peer does. Every retained identity must eventually arrive.
    let mut last_cursors = HashMap::new();
    acknowledge(
        &mut peer,
        &inbound_control,
        &history,
        &mut last_cursors,
        slots,
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        while seen.len() < count {
            let (session, turns) = next_turns(&mut peer, &mut outbound_control).await?;
            if session == history.session {
                record_history(&mut seen, turns, slots, turns_per_slot);
            }
            acknowledge(
                &mut peer,
                &inbound_control,
                &history,
                &mut last_cursors,
                slots,
            )
            .await?;
        }
        Ok::<_, AnyError>(())
    })
    .await??;
    for slot in 0..slots {
        assert_eq!(
            peer.delivered_through(transport_key(&history), SlotId(slot as u8)),
            Some(FIRST + turns_per_slot - 1)
        );
    }
    drop(commands);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), driver).await??,
        mesh::MeshLinkExit::CommandChannelClosed
    );
    Ok(())
}
