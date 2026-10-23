use super::*;
use crate::consensus::{Authority, EvidenceConfig, MakerSync};
use rally_point_proto::control::{EvidenceKey, EvidenceVerdict};
use rally_point_proto::token::ClientPublicKey;

fn install(context: &Context, periodic: bool, revision: u64) {
    let _ = context.mesh.session.decision_makers.sync_maker(
        &context.key,
        MakerSync {
            evidence: EvidenceConfig {
                periodic,
                keys: vec![EvidenceKey {
                    key_id: 7,
                    public_key: ClientPublicKey([7; 32]),
                }],
                assignments: [(context.slot, revision)].into_iter().collect(),
                ..Default::default()
            },
            expected_slots: [context.slot].into_iter().collect(),
            homed_slots: [context.slot].into_iter().collect(),
            ..MakerSync::new(crate::test_support::wide_bounds(), Authority::SelfRelay)
        },
    );
}
fn admit(context: &Context, id: [u8; 32], epoch: u64) {
    let _ = context
        .mesh
        .session
        .decision_makers
        .activate_connection_epoch(&context.key, context.slot, epoch);
    assert!(context.mesh.session.decision_makers.note_slot_connected(
        &context.key,
        context.slot,
        false,
        Some(EvidenceObservation {
            sample_id: 0,
            connection_id: id,
            assignment_revision: context.revision,
            sequence: crate::consensus::next_evidence_sequence().unwrap(),
            verdict: EvidenceVerdict::Valid,
            key_id: Some(7),
            body: vec![1],
        })
    ));
}
fn fixture() -> Context {
    let context = Context {
        key: crate::test_support::session_key(42),
        slot: SlotId(0),
        epoch: 1,
        revision: 1,
        connection_id: [1; 32],
        sessions: Default::default(),
        mesh: Default::default(),
    };
    context.mesh.session.decision_makers.require_descriptors();
    install(&context, true, 1);
    let (mut guard, _) = super::super::registry::register(
        &context.sessions,
        &context.key,
        context.slot,
        context.epoch,
    )
    .unwrap();
    guard.disarm();
    admit(&context, context.connection_id, context.epoch);
    context
}
fn checked() -> crate::auth::CheckedEvidence {
    crate::auth::CheckedEvidence {
        connection_id: [1; 32],
        assignment_revision: 1,
        verdict: EvidenceVerdict::Valid,
        key_id: Some(7),
        body: vec![2],
    }
}

#[test]
fn periodic_samples_preserve_admission_and_coalesce_without_lifecycle_notices() {
    let context = fixture();
    let makers = &context.mesh.session.decision_makers;
    let before = makers.retained_load_state(&context.key).evidence;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(tx);
    assert!(!context.record(0, checked()));
    assert!(context.record(1, checked()));
    assert!(!context.record(1, checked()));
    assert!(context.record(
        2,
        crate::auth::CheckedEvidence {
            verdict: EvidenceVerdict::Invalid,
            ..checked()
        }
    ));
    let state = makers.retained_load_state(&context.key);
    assert_eq!(state.evidence, before);
    assert_eq!(state.periodic_evidence.len(), 1);
    assert_eq!(state.periodic_evidence[0].observation.sample_id, 2);
    assert!(state.periodic_evidence[0].observation.body.is_empty());
    assert!(state.periodic_evidence[0].observation.sequence > before[0].observation.sequence);
    assert!(rx.try_recv().is_err());
    assert_eq!(makers.periodic_evidence_candidates().len(), 1);
}

#[test]
fn old_registration_cannot_win_after_same_relay_reconnect() {
    let context = fixture();
    assert!(context.record(1, checked()));
    super::super::registry::deregister(&context.sessions, &context.key, context.slot);
    let (mut guard, _) =
        super::super::registry::register(&context.sessions, &context.key, context.slot, 2).unwrap();
    guard.disarm();
    admit(&context, [2; 32], 2);
    let before = context
        .mesh
        .session
        .decision_makers
        .retained_load_state(&context.key);
    assert!(before.periodic_evidence.is_empty());
    assert!(!context.record(99, checked()));
    assert!(context.current().is_none());
    assert_eq!(
        context
            .mesh
            .session
            .decision_makers
            .retained_load_state(&context.key),
        before
    );
}

#[test]
fn assignment_retirement_and_policy_changes_discard_late_results() {
    for change in 0..3 {
        let context = fixture();
        assert!(context.record(1, checked()));
        match change {
            0 => install(&context, true, 2),
            1 => install(&context, false, 1),
            _ => {
                context.mesh.session.gates.retire(&context.key);
            }
        }
        assert!(!context.record(2, checked()));
        assert!(context.current().is_none());
        if change != 2 {
            assert!(
                context
                    .mesh
                    .session
                    .decision_makers
                    .periodic_evidence_candidates()
                    .is_empty()
            );
        }
    }
}

#[test]
fn requests_wait_for_session_and_slot_start_and_jitter_is_bounded() {
    let context = fixture();
    assert!(!context.current().unwrap().1);
    context
        .mesh
        .session
        .decision_makers
        .mark_started(&context.key);
    assert!(!context.current().unwrap().1);
    context
        .mesh
        .session
        .decision_makers
        .note_slot_started(&context.key, context.slot);
    assert!(context.current().unwrap().1);
    for _ in 0..100 {
        assert!(
            (Duration::from_secs(30)..=Duration::from_secs(60)).contains(&jitter(true).unwrap())
        );
        assert!(
            (Duration::from_secs(60)..=Duration::from_secs(90)).contains(&jitter(false).unwrap())
        );
    }
}

#[tokio::test(start_paused = true)]
async fn bounded_exchange_accepts_empty_and_rejects_bad_ids_lengths_and_stalls() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for mode in 0..5 {
        let (mut relay, mut client) = tokio::io::duplex(4096);
        let challenge = PeriodicEvidenceContext {
            challenge_id: 1,
            nonce: [3; 32],
            assignment_revision: 2,
            check: EvidenceCheck::FullImage,
        };
        let (mut read, mut write) = tokio::io::split(&mut relay);
        let server = async {
            tokio::time::timeout(
                EXCHANGE_TIMEOUT,
                exchange(&mut write, &mut read, &challenge),
            )
            .await
        };
        let client_task = async {
            let mut bytes = [0; handshake::PERIODIC_CHALLENGE_LEN];
            client.read_exact(&mut bytes).await.unwrap();
            assert_eq!(
                handshake::decode_periodic_challenge(&bytes).unwrap(),
                challenge
            );
            match mode {
                0 => client
                    .write_all(&handshake::encode_periodic_response(1, None).unwrap())
                    .await
                    .unwrap(),
                1 => client
                    .write_all(&handshake::encode_periodic_response(2, None).unwrap())
                    .await
                    .unwrap(),
                2 => {
                    let mut header = [255; handshake::PERIODIC_RESPONSE_HEADER_LEN];
                    header[..8].copy_from_slice(&1u64.to_le_bytes());
                    client.write_all(&header).await.unwrap();
                }
                3 => {
                    client.shutdown().await.unwrap();
                }
                _ => {
                    tokio::time::sleep(EXCHANGE_TIMEOUT + Duration::from_secs(1)).await;
                }
            }
        };
        let (result, ()) = tokio::join!(server, client_task);
        match mode {
            0 => assert_eq!(result.unwrap(), Some(None)),
            4 => assert!(result.is_err()),
            _ => assert!(result.unwrap().is_none()),
        }
    }
}

#[tokio::test]
async fn dropping_task_guard_cancels_pending_work() {
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let guard = Task(tokio::spawn(async move {
        let _sender = tx;
        std::future::pending::<()>().await;
    }));
    drop(guard);
    assert!(rx.await.is_err());
}

#[test]
fn relay_wide_budget_sheds_instead_of_queueing() {
    let permits: Vec<_> = (0..32).map(|_| EXCHANGES.try_acquire().unwrap()).collect();
    assert!(EXCHANGES.try_acquire().is_err());
    drop(permits);
    assert!(EXCHANGES.try_acquire().is_ok());
}

#[test]
fn periodic_sample_cannot_enter_admission_path() {
    let context = fixture();
    let makers = &context.mesh.session.decision_makers;
    let before = makers.retained_load_state(&context.key);
    let mut observation = before.evidence[0].observation.clone();
    observation.sample_id = 1;
    assert!(!makers.note_slot_connected(&context.key, context.slot, false, Some(observation)));
    assert_eq!(makers.retained_load_state(&context.key), before);
}

fn request(context: &Context) -> EvidenceRequest {
    EvidenceRequest {
        periodic: None,
        challenge: context.connection_id,
        channel_binding: [8; 32],
        tenant: context.key.tenant.clone(),
        session: context.key.session,
        slot: context.slot,
        client_pubkey: ClientPublicKey([9; 32]),
    }
}

#[tokio::test(start_paused = true)]
async fn worker_waits_for_game_start_and_keeps_empty_responses_off_gameplay_lifecycle() {
    let context = fixture();
    let request = request(&context);
    let makers = context.mesh.session.decision_makers.clone();
    let key = context.key.clone();
    let sessions = context.sessions.clone();
    let (relay, client) = tokio::io::duplex(8192);
    let (read, write) = tokio::io::split(relay);
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let task = Task(tokio::spawn(run_with(context, write, read, request)));
    let mut frame = [0; handshake::PERIODIC_CHALLENGE_LEN];
    assert!(
        tokio::time::timeout(Duration::from_secs(120), client_read.read_exact(&mut frame))
            .await
            .is_err()
    );
    makers.mark_started(&key);
    makers.note_slot_started(&key, SlotId(0));
    tokio::time::timeout(Duration::from_secs(62), client_read.read_exact(&mut frame))
        .await
        .unwrap()
        .unwrap();
    let first = handshake::decode_periodic_challenge(&frame).unwrap();
    assert_eq!(first.challenge_id, 1);
    client_write
        .write_all(&handshake::encode_periodic_response(first.challenge_id, None).unwrap())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(92), client_read.read_exact(&mut frame))
        .await
        .unwrap()
        .unwrap();
    let second = handshake::decode_periodic_challenge(&frame).unwrap();
    assert_eq!(second.challenge_id, 2);
    assert_ne!(first.nonce, second.nonce);
    let state = makers.retained_load_state(&key);
    assert_eq!(state.evidence[0].observation.sample_id, 0);
    assert_eq!(
        state.periodic_evidence[0].observation.verdict,
        EvidenceVerdict::Missing
    );
    assert_eq!(
        super::super::live_session_slot_epochs(&sessions, &key),
        vec![(SlotId(0), 1)]
    );
    drop(task);
}

#[tokio::test(start_paused = true)]
async fn stalled_worker_stops_only_evidence_and_policy_off_sends_nothing() {
    for policy in [false, true] {
        let context = fixture();
        install(&context, policy, 1);
        let request = request(&context);
        let makers = context.mesh.session.decision_makers.clone();
        let key = context.key.clone();
        let sessions = context.sessions.clone();
        makers.mark_started(&key);
        makers.note_slot_started(&key, SlotId(0));
        let (relay, mut client) = tokio::io::duplex(8192);
        let (read, write) = tokio::io::split(relay);
        let task = tokio::spawn(run_with(context, write, read, request));
        if policy {
            let mut frame = [0; handshake::PERIODIC_CHALLENGE_LEN];
            tokio::time::timeout(Duration::from_secs(62), client.read_exact(&mut frame))
                .await
                .unwrap()
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(4), task)
            .await
            .unwrap()
            .unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        assert_eq!(
            super::super::live_session_slot_epochs(&sessions, &key),
            vec![(SlotId(0), 1)]
        );
        let state = makers.retained_load_state(&key);
        assert_eq!(state.periodic_evidence.len(), usize::from(policy));
    }
}
