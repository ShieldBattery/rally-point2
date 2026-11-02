//! Slot presence over the mesh: asymmetric joins converging on one roster, and
//! the single current-state reply a first peer presence forces.

use std::sync::Arc;
use std::time::Duration;

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::mesh::MeshPresence;
use rally_point_relay::key::SessionKey;
use rally_point_relay::mesh;
use rally_point_relay::routing::Sessions;

use crate::helpers::*;
use tokio::sync::mpsc;

/// A relay can apply a session descriptor (and therefore Join its side of the
/// shared mesh link) before its peer applies the same descriptor. Slot-presence
/// announcements sent during that gap used to be dropped by the unjoined peer,
/// leaving the eventual authority permanently short of the expected roster.
/// The first post-Join presence report is now a rendezvous barrier: it proves the
/// peer has installed its Join and triggers one current-roster replay.
#[tokio::test]
async fn asymmetric_mesh_joins_converge_slot_presence_and_start_the_session() -> Result<(), AnyError>
{
    use rally_point_relay::consensus::Authority;
    use rally_point_transport::control::ControlInbound;

    let tenant = make_default_tenant();
    let session = SessionId(41);
    let key = SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session,
    };
    let relay_a = Relay::start(&tenant, 1);
    let relay_b = Relay::start(&tenant, 2);

    // Relay B is the authority. That choice is load-bearing for the regression:
    // A joins first, so B must recover A's early slot announcement after B's own
    // later Join rather than starting from the announcement B sends to A.
    seed_authority(&relay_a.mesh.session.decision_makers, &key)
        .expecting([0, 1])
        .homed([0])
        .authority(Authority::Peer)
        .apply();
    seed_authority(&relay_b.mesh.session.decision_makers, &key)
        .expecting([0, 1])
        .homed([1])
        .apply();

    // Both clients connect before either side joins the mesh session. Their live
    // SlotPresent frames therefore have no registered mesh channel to use; Join
    // reconciliation is the only way those already-live slots cross the link.
    let client_a = connect_client(&relay_a, &tenant, session, SlotId(0)).await?;
    let client_b = connect_client(&relay_b, &tenant, session, SlotId(1)).await?;
    let (_send_a, mut control_a) = open_lobby_streams(client_a.connection()).await;
    let (_send_b, mut control_b) = open_lobby_streams(client_b.connection()).await;
    wait_for_slots(&relay_a.sessions, &key, 1).await;
    wait_for_slots(&relay_b.sessions, &key, 1).await;
    assert!(!relay_b.mesh.session.decision_makers.is_started(&key));

    let (mesh_a, mesh_b, _mesh_ep_a, _mesh_ep_b) = mesh_link_pair().await;
    let commands_a = spawn_mesh_link(mesh_a, Arc::clone(&relay_a.sessions), relay_a.mesh.clone());
    let commands_b = spawn_mesh_link(mesh_b, Arc::clone(&relay_b.sessions), relay_b.mesh.clone());

    // A's replay happens while B is still unjoined and is intentionally
    // discarded. Prove that this one-sided state alone cannot start B.
    commands_a.send(mesh::MeshCommand::Join(key.clone()))?;
    wait_for_mesh_link(&relay_a.mesh, &key).await;
    // A's replay is on the wire by now; give B long enough to have acted on it
    // if it were going to. A negative claim needs some window, but a short one:
    // B is one loopback hop away.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!relay_b.mesh.session.decision_makers.is_started(&key));

    // B now joins and sends its initial aggregate. A's one-shot rendezvous
    // response replays slot 0 after B is known joined, completing B's expected
    // roster. The authority starts both local and peer clients exactly once.
    commands_b.send(mesh::MeshCommand::Join(key.clone()))?;
    assert!(matches!(
        recv_meaningful(&mut control_b).await,
        ControlInbound::SessionStart(_)
    ));
    assert!(matches!(
        recv_meaningful(&mut control_a).await,
        ControlInbound::SessionStart(_)
    ));
    assert!(relay_b.mesh.session.decision_makers.is_started(&key));

    Ok(())
}

/// The first report received after both sides have joined is a rendezvous, not
/// an ordinary push-on-change exchange. It must force this relay's current
/// aggregate back to a peer that may have dropped the original pre-Join frame,
/// even when that value is unchanged in `presence_sent`. The forced reply is
/// one-shot so the peer's corresponding reply cannot start an echo loop.
#[tokio::test]
async fn first_peer_presence_forces_exactly_one_current_reply() -> Result<(), AnyError> {
    let sessions: Sessions = Arc::default();
    let mesh_state = mesh::MeshState::default();
    let (local_link, peer_link, _local_endpoint, _peer_endpoint) = mesh_link_pair().await;
    let local_connection = local_link.connection().clone();
    let peer_connection = peer_link.connection().clone();

    // Feed peer reports directly so their ordering relative to command barriers
    // is deterministic, while retaining a real QUIC stream for outbound frames.
    let presence_send = local_connection.open_uni().await?;
    let (peer_presence_tx, peer_presence_rx) = mpsc::channel::<MeshPresence>(8);
    let (mut control_send, _unused_control_recv) = local_connection.open_bi().await?;
    rally_point_transport::mesh_control_stream::establish_mesh_control(&mut control_send).await?;
    let (peer_control_tx, peer_control_rx) =
        mpsc::channel::<rally_point_proto::messages::MeshControlFrame>(8);
    let attempt = mesh::new_mesh_link_attempt();
    let lease = mesh::claim_mesh_link(&mesh_state, RelayId(9), &attempt)
        .expect("the test driver claims its peer lease");
    let (commands_tx, commands_rx) = mpsc::unbounded_channel();
    let driver = tokio::spawn(mesh::run_mesh_link(
        local_link,
        mesh::MeshLinkIo {
            presence: rally_point_relay::session::presence::PresenceIo {
                peer_id: RelayId(9),
                tx: presence_send,
                rx: peer_presence_rx,
            },
            control: mesh::MeshControlIo {
                tx: control_send,
                rx: peer_control_rx,
            },
            lease,
        },
        commands_rx,
        Arc::clone(&sessions),
        mesh_state,
        mesh::IDLE_TIMEOUT,
    ));

    let key = |session| SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(session),
    };
    let rendezvous = key(42);
    commands_tx.send(mesh::MeshCommand::Join(rendezvous.clone()))?;
    let mut outbound_presence =
        tokio::time::timeout(Duration::from_secs(2), peer_connection.accept_uni())
            .await
            .map_err(|_| "the driver did not open its presence stream within 2s")??;
    assert_eq!(
        next_mesh_presence(&mut outbound_presence).await,
        MeshPresence {
            session: rendezvous.session,
            live_players: 0,
        },
        "Join sends the initial local aggregate",
    );

    // A same-session duplicate is documented as a no-op. The following fresh
    // Join is a stream-order barrier: if the duplicate wrote anything, that
    // unexpected session-42 frame would appear before session 43 here.
    commands_tx.send(mesh::MeshCommand::Join(rendezvous.clone()))?;
    let duplicate_barrier = key(43);
    commands_tx.send(mesh::MeshCommand::Join(duplicate_barrier.clone()))?;
    assert_eq!(
        next_mesh_presence(&mut outbound_presence).await.session,
        duplicate_barrier.session,
        "a duplicate Join emits no aggregate presence frame",
    );

    peer_presence_tx
        .send(MeshPresence {
            session: rendezvous.session,
            live_players: 7,
        })
        .await?;
    assert_eq!(
        next_mesh_presence(&mut outbound_presence).await,
        MeshPresence {
            session: rendezvous.session,
            live_players: 0,
        },
        "the first peer report forces the unchanged current aggregate",
    );

    // Enqueue the second report before its command barrier. The driver's biased
    // select handles ready presence before commands; if it echoed this report,
    // session 42 would therefore precede the barrier's session-44 frame.
    peer_presence_tx
        .send(MeshPresence {
            session: rendezvous.session,
            live_players: 8,
        })
        .await?;
    let repeat_barrier = key(44);
    commands_tx.send(mesh::MeshCommand::Join(repeat_barrier.clone()))?;
    assert_eq!(
        next_mesh_presence(&mut outbound_presence).await.session,
        repeat_barrier.session,
        "later peer reports do not trigger aggregate-presence echoes",
    );

    drop(commands_tx);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), driver).await??,
        mesh::MeshLinkExit::CommandChannelClosed,
    );
    drop(peer_presence_tx);
    drop(peer_control_tx);
    Ok(())
}

/// A Join's resume ask can reach a peer that has not joined the session yet,
/// which drops it unanswered; the accept side of a redial usually reads the
/// dialer's ask before its own Join lands. The peer's first presence report
/// proves it has joined, so every Join asks again then, once. That includes a
/// Join with no forward-gate history: its clients can still be waiting on
/// turns the peer's clients sent while the two were not joined, which no live
/// path carries.
///
/// The peer here is hand-driven: it never answers the first ask, exactly what
/// an unjoined peer's drop amounts to, and its presence reports are fed
/// straight into the driver so their order against the asks is deterministic.
#[tokio::test]
async fn first_peer_presence_repeats_every_joins_resume_ask() -> Result<(), AnyError> {
    use rally_point_proto::messages::mesh_control_frame::Kind;
    use rally_point_proto::messages::{MeshControlFrame, MeshResumeCursors};

    /// The next resume ask the driver wrote, skipping the other Join-time
    /// reconcile frames.
    async fn next_resume_ask(
        frames: &mut mpsc::Receiver<MeshControlFrame>,
    ) -> (u64, MeshResumeCursors) {
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(2), frames.recv())
                .await
                .expect("a mesh control frame arrived within 2s")
                .expect("the driver's control stream stayed open");
            if let Some(Kind::MeshResumeCursors(resume)) = frame.kind {
                return (frame.session, resume);
            }
        }
    }
    fn cursors(resume: &MeshResumeCursors) -> Vec<(u32, u64)> {
        resume
            .cursors
            .iter()
            .map(|c| (c.origin_slot, c.next_seq))
            .collect()
    }

    let key = |session| SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(session),
    };
    let resumed = key(50);
    let fresh = key(51);

    let sessions: Sessions = Arc::default();
    let mesh_state = mesh::MeshState::default();
    let seen = mesh_state.seen.clone();
    let descriptor_control =
        mesh::control::MeshControl::new(RelayId(8), &mesh_state, Arc::clone(&sessions));
    // History from before the link died: slot 1's seq 0 already reached this
    // relay's locals, so a Join of `resumed` asks for slot 1 from seq 1.
    mesh::mark_seen(&seen, &resumed, SlotId(1), 0);

    let (local_link, peer_link, _local_endpoint, _peer_endpoint) = mesh_link_pair().await;
    let local_connection = local_link.connection().clone();
    let peer_connection = peer_link.connection().clone();
    let presence_send = local_connection.open_uni().await?;
    let (peer_presence_tx, peer_presence_rx) = mpsc::channel::<MeshPresence>(8);
    let (mut control_send, _unused_control_recv) = local_connection.open_bi().await?;
    rally_point_transport::mesh_control_stream::establish_mesh_control(&mut control_send).await?;
    let mut outbound_control =
        rally_point_transport::mesh_control_stream::spawn_mesh_control_reader_accepting(
            peer_connection.clone(),
        );
    let (peer_control_tx, peer_control_rx) = mpsc::channel::<MeshControlFrame>(8);
    let attempt = mesh::new_mesh_link_attempt();
    let lease = mesh::claim_mesh_link(&mesh_state, RelayId(9), &attempt)
        .expect("the test driver claims its peer lease");
    let (commands_tx, commands_rx) = mpsc::unbounded_channel();
    let driver = tokio::spawn(mesh::run_mesh_link(
        local_link,
        mesh::MeshLinkIo {
            presence: rally_point_relay::session::presence::PresenceIo {
                peer_id: RelayId(9),
                tx: presence_send,
                rx: peer_presence_rx,
            },
            control: mesh::MeshControlIo {
                tx: control_send,
                rx: peer_control_rx,
            },
            lease,
        },
        commands_rx,
        Arc::clone(&sessions),
        mesh_state,
        mesh::IDLE_TIMEOUT,
    ));

    commands_tx.send(mesh::MeshCommand::Join(resumed.clone()))?;
    let (session, ask) = next_resume_ask(&mut outbound_control).await;
    assert_eq!(session, resumed.session.0);
    assert!(ask.resuming, "a Join with forward-gate history is resuming");
    assert_eq!(cursors(&ask), vec![(1, 1)]);

    commands_tx.send(mesh::MeshCommand::Join(fresh.clone()))?;
    let (session, ask) = next_resume_ask(&mut outbound_control).await;
    assert_eq!(session, fresh.session.0);
    assert!(
        ask.resuming,
        "a Join with no history still asks for everything retained",
    );
    assert!(ask.cursors.is_empty());
    // A local turn after the Join gives `fresh` history of its own, which the
    // repeated ask carries.
    mesh::mark_seen(&seen, &fresh, SlotId(0), 0);

    // Neither ask is answered. Both Joins ask again on the peer's first
    // presence, in report order.
    for session in [fresh.session, resumed.session] {
        peer_presence_tx
            .send(MeshPresence {
                session,
                live_players: 1,
            })
            .await?;
    }
    let (session, ask) = next_resume_ask(&mut outbound_control).await;
    assert_eq!(
        session, fresh.session.0,
        "a Join without history asks again on the peer's first presence",
    );
    assert!(ask.resuming);
    assert_eq!(cursors(&ask), vec![(0, 1)]);
    let (session, ask) = next_resume_ask(&mut outbound_control).await;
    assert_eq!(session, resumed.session.0);
    assert!(ask.resuming);
    assert_eq!(cursors(&ask), vec![(1, 1)]);

    // A later report is not a first presence. The driver handles ready presence
    // before commands, so a second re-ask would precede the barrier Join's ask.
    peer_presence_tx
        .send(MeshPresence {
            session: resumed.session,
            live_players: 2,
        })
        .await?;
    let barrier = key(52);
    commands_tx.send(mesh::MeshCommand::Join(barrier.clone()))?;
    let (session, _) = next_resume_ask(&mut outbound_control).await;
    assert_eq!(
        session, barrier.session.0,
        "the resume ask is repeated once, not on every presence report",
    );

    // Descriptor recovery must not depend on the replacement having forwarded
    // any turns. Exercise both installation before Join and an upgrade while
    // the peer has not yet announced its own Join.
    for (id, descriptor_before_join) in [(53, true), (54, false)] {
        let replacement = key(id);
        let mut assigned = descriptor(TENANT, replacement.session);
        assigned.resumed = descriptor_before_join;
        descriptor_control.apply_descriptor(&assigned);
        commands_tx.send(mesh::MeshCommand::Join(replacement.clone()))?;
        let (session, ask) = next_resume_ask(&mut outbound_control).await;
        assert_eq!(session, id);
        assert!(ask.resuming);
        assert!(ask.cursors.is_empty());
        assert!(!mesh::has_resumable_state(&seen, &replacement));
        if !descriptor_before_join {
            assigned.resumed = true;
            descriptor_control.apply_descriptor(&assigned);
        }
        peer_presence_tx
            .send(MeshPresence {
                session: replacement.session,
                live_players: 1,
            })
            .await?;
        let (session, ask) = next_resume_ask(&mut outbound_control).await;
        assert_eq!(session, id);
        assert!(
            ask.resuming,
            "a replacement retries history after the peer joins"
        );
        assert!(ask.cursors.is_empty());
    }

    drop(commands_tx);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), driver).await??,
        mesh::MeshLinkExit::CommandChannelClosed,
    );
    drop(peer_presence_tx);
    drop(peer_control_tx);
    Ok(())
}

/// The leave state and session start a Join replays are re-sent on the peer's
/// first presence too. A peer that has not joined the session yet drops every
/// control frame for it, and on a redial the accept side usually reads the
/// dialer's Join-time frames before its own Join lands. A synced leave or the
/// session start lost with the old link would then never reach that peer: its
/// survivors stall waiting for the leave, or its clients never start.
#[tokio::test]
async fn first_peer_presence_re_sends_leave_state_and_the_session_start() -> Result<(), AnyError> {
    use rally_point_proto::ids::GameFrameCount;
    use rally_point_proto::messages::MeshControlFrame;
    use rally_point_proto::messages::mesh_control_frame::Kind;

    /// Every frame the driver wrote up to and including `session`'s resume ask.
    async fn frames_through_ask(
        frames: &mut mpsc::Receiver<MeshControlFrame>,
        session: u64,
    ) -> Vec<MeshControlFrame> {
        let mut seen = Vec::new();
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(2), frames.recv())
                .await
                .expect("a mesh control frame arrived within 2s")
                .expect("the driver's control stream stayed open");
            let ask =
                frame.session == session && matches!(frame.kind, Some(Kind::MeshResumeCursors(_)));
            seen.push(frame);
            if ask {
                return seen;
            }
        }
    }

    let key = |session| SessionKey {
        tenant: TenantId(TENANT.to_owned()),
        session: SessionId(session),
    };
    let game = key(60);
    let barrier = key(61);

    let sessions: Sessions = Arc::default();
    let mesh_state = mesh::MeshState::default();
    let makers = mesh_state.session.decision_makers.clone();
    // This relay is the authority, already decided slot 1's leave, and
    // already started the session: the state a link redialing mid-game carries.
    seed_authority(&makers, &game).apply();
    makers.observe_frame(&game, SlotId(1), GameFrameCount(40));
    let leave = makers
        .decide_leave(
            &game,
            SlotId(1),
            rally_point_relay::consensus::LEAVE_REASON_DROPPED,
        )
        .expect("the authority decides slot 1's leave");
    makers.mark_started(&game);

    let (local_link, peer_link, _local_endpoint, _peer_endpoint) = mesh_link_pair().await;
    let local_connection = local_link.connection().clone();
    let peer_connection = peer_link.connection().clone();
    let presence_send = local_connection.open_uni().await?;
    let (peer_presence_tx, peer_presence_rx) = mpsc::channel::<MeshPresence>(8);
    let (mut control_send, _unused_control_recv) = local_connection.open_bi().await?;
    rally_point_transport::mesh_control_stream::establish_mesh_control(&mut control_send).await?;
    let mut outbound_control =
        rally_point_transport::mesh_control_stream::spawn_mesh_control_reader_accepting(
            peer_connection.clone(),
        );
    let (_peer_control_tx, peer_control_rx) = mpsc::channel::<MeshControlFrame>(8);
    let attempt = mesh::new_mesh_link_attempt();
    let lease = mesh::claim_mesh_link(&mesh_state, RelayId(9), &attempt)
        .expect("the test driver claims its peer lease");
    let (commands_tx, commands_rx) = mpsc::unbounded_channel();
    let driver = tokio::spawn(mesh::run_mesh_link(
        local_link,
        mesh::MeshLinkIo {
            presence: rally_point_relay::session::presence::PresenceIo {
                peer_id: RelayId(9),
                tx: presence_send,
                rx: peer_presence_rx,
            },
            control: mesh::MeshControlIo {
                tx: control_send,
                rx: peer_control_rx,
            },
            lease,
        },
        commands_rx,
        Arc::clone(&sessions),
        mesh_state,
        mesh::IDLE_TIMEOUT,
    ));

    let carries_the_state = |frames: &[MeshControlFrame]| {
        let leave_sent = frames.iter().any(|frame| {
            frame.session == game.session.0
                && matches!(frame.kind, Some(Kind::LeaveDirective(sent)) if sent == leave)
        });
        let start_sent = frames.iter().any(|frame| {
            frame.session == game.session.0 && matches!(frame.kind, Some(Kind::SessionStart(_)))
        });
        (leave_sent, start_sent)
    };

    // The Join replays both — to a peer that, not having joined, drops them.
    commands_tx.send(mesh::MeshCommand::Join(game.clone()))?;
    let join_time = frames_through_ask(&mut outbound_control, game.session.0).await;
    assert_eq!(carries_the_state(&join_time), (true, true));

    // The peer's first presence proves its Join. The driver handles ready
    // presence before commands, so everything it re-sends for `game` precedes
    // the barrier Join's ask.
    peer_presence_tx
        .send(MeshPresence {
            session: game.session,
            live_players: 1,
        })
        .await?;
    commands_tx.send(mesh::MeshCommand::Join(barrier.clone()))?;
    let after_presence = frames_through_ask(&mut outbound_control, barrier.session.0).await;
    assert_eq!(
        carries_the_state(&after_presence),
        (true, true),
        "the leave and the session start reach the peer once it has joined",
    );

    driver.abort();
    Ok(())
}
