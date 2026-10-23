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
    assert!(!record(&context, 0, checked()));
    assert!(record(&context, 1, checked()));
    assert!(!record(&context, 1, checked()));
    assert!(record(
        &context,
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
    assert!(record(&context, 1, checked()));
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
    assert!(!record(&context, 99, checked()));
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
        assert!(record(&context, 1, checked()));
        match change {
            0 => install(&context, true, 2),
            1 => install(&context, false, 1),
            _ => {
                context.mesh.session.gates.retire(&context.key);
            }
        }
        assert!(!record(&context, 2, checked()));
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
            (Duration::from_secs(35)..=Duration::from_secs(65)).contains(&jitter(true).unwrap())
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
    tokio::time::timeout(Duration::from_secs(67), client_read.read_exact(&mut frame))
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
            tokio::time::timeout(Duration::from_secs(67), client.read_exact(&mut frame))
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

fn record(context: &Context, sample: u64, checked: crate::auth::CheckedEvidence) -> bool {
    let makers = &context.mesh.session.decision_makers;
    if !makers.begin_periodic_evidence(
        &context.key,
        context.slot,
        context.epoch,
        EvidenceObservation {
            sample_id: sample,
            sequence: 0,
            connection_id: context.connection_id,
            assignment_revision: context.revision,
            verdict: EvidenceVerdict::Missing,
            key_id: None,
            body: Vec::new(),
        },
    ) {
        return false;
    }
    context.record(sample, checked)
}

#[test]
fn forwarded_turn_starts_sampling_without_a_client_started_claim() {
    let context = fixture();
    let makers = &context.mesh.session.decision_makers;
    makers.note_unframed_home_turn(&context.key, context.slot);
    assert!(!context.current().unwrap().1);
    makers.mark_started(&context.key);
    assert!(context.current().unwrap().1);
}

#[test]
fn optional_missing_admission_is_ineligible_but_required_missing_is_eligible() {
    for required in [false, true] {
        let context = fixture();
        let makers = &context.mesh.session.decision_makers;
        // Required policy is latched when the descriptor is first installed.
        let mut config = makers.evidence_config(&context.key).unwrap();
        if required {
            config.required_slots.insert(context.slot);
        }
        let other_key = crate::test_support::session_key(if required { 45 } else { 44 });
        let _ = makers.sync_maker(
            &other_key,
            MakerSync {
                evidence: config,
                expected_slots: [context.slot].into_iter().collect(),
                homed_slots: [context.slot].into_iter().collect(),
                ..MakerSync::new(crate::test_support::wide_bounds(), Authority::SelfRelay)
            },
        );
        assert!(makers.activate_connection_epoch(&other_key, context.slot, context.epoch));
        let observation = EvidenceObservation {
            sample_id: 0,
            sequence: crate::consensus::next_evidence_sequence().unwrap(),
            connection_id: context.connection_id,
            assignment_revision: 1,
            verdict: EvidenceVerdict::Missing,
            key_id: None,
            body: Vec::new(),
        };
        assert!(makers.note_slot_connected(&other_key, context.slot, false, Some(observation)));
        assert_eq!(
            makers
                .periodic_evidence_config(
                    &other_key,
                    context.slot,
                    context.epoch,
                    &context.connection_id,
                    1
                )
                .is_some(),
            required
        );
    }
}

fn begin(context: &Context, sample: u64) -> bool {
    context
        .mesh
        .session
        .decision_makers
        .begin_periodic_evidence(
            &context.key,
            context.slot,
            context.epoch,
            EvidenceObservation {
                sample_id: sample,
                sequence: 0,
                connection_id: context.connection_id,
                assignment_revision: context.revision,
                verdict: EvidenceVerdict::Valid,
                key_id: Some(99),
                body: vec![99],
            },
        )
}

#[test]
fn unanswered_challenge_survives_two_replacements_before_task_drop() {
    let mut context = fixture();
    let makers = context.mesh.session.decision_makers.clone();
    let admission = makers.retained_load_state(&context.key).evidence[0]
        .observation
        .clone();
    assert!(begin(&context, 1));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    makers.set_notice_notifier(tx);
    // Neither task destruction nor a control heartbeat runs before replacement.
    admit(&context, [2; 32], 2);
    admit(&context, [3; 32], 3);
    let state = makers.retained_load_state(&context.key);
    assert!(state.periodic_evidence.is_empty());
    let history = &state.evidence_history[0].history;
    assert_eq!(history.admission, admission);
    assert_eq!(history.sample.verdict, EvidenceVerdict::Missing);
    assert!(history.sample.body.is_empty());
    assert_eq!(history.sample.key_id, None);
    assert!(history.sample.sequence < state.evidence[0].observation.sequence);
    for _ in 0..2 {
        let crate::consensus::RelayNotice::SlotConnected(notice) = rx.try_recv().unwrap() else {
            panic!("wrong notice");
        };
        assert_eq!(notice.predecessor.as_deref(), Some(history));
    }
    // Old callback completion and old task destruction cannot mutate the history.
    assert!(!context.record(1, checked()));
    makers.abandon_periodic_evidence(&context.key, context.slot, 1, 1);
    assert_eq!(makers.retained_load_state(&context.key), state);
    context.epoch = 3;
    context.connection_id = [3; 32];
    assert!(begin(&context, 1));
    makers.abandon_periodic_evidence(&context.key, context.slot, 3, 1);
    assert_eq!(
        makers.retained_load_state(&context.key).evidence_history,
        state.evidence_history
    );
}

#[test]
fn completed_failure_and_later_valid_result_cannot_replace_first_failure() {
    let context = fixture();
    let makers = &context.mesh.session.decision_makers;
    assert!(record(
        &context,
        1,
        crate::auth::CheckedEvidence {
            verdict: EvidenceVerdict::Invalid,
            ..checked()
        }
    ));
    let failed = makers.retained_load_state(&context.key).evidence_history;
    assert!(record(&context, 2, checked()));
    assert_eq!(
        makers.retained_load_state(&context.key).evidence_history,
        failed
    );
    admit(&context, [2; 32], 2);
    assert_eq!(
        makers.retained_load_state(&context.key).evidence_history,
        failed
    );
}

#[tokio::test(start_paused = true)]
async fn abort_after_challenge_bytes_retains_missing_without_a_heartbeat() {
    let context = fixture();
    let req = request(&context);
    let makers = context.mesh.session.decision_makers.clone();
    let key = context.key.clone();
    makers.mark_started(&key);
    makers.note_unframed_home_turn(&key, context.slot);
    let (relay, mut client) = tokio::io::duplex(8192);
    let (read, write) = tokio::io::split(relay);
    let task = tokio::spawn(run_with(context, write, read, req));
    let mut frame = [0; handshake::PERIODIC_CHALLENGE_LEN];
    tokio::time::timeout(Duration::from_secs(67), client.read_exact(&mut frame))
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let history = makers.retained_load_state(&key).evidence_history;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].history.sample.verdict, EvidenceVerdict::Missing);
    assert_eq!(history[0].history.sample.sample_id, 1);
}

#[test]
fn cancelled_obligation_cannot_complete_after_policy_reenabled() {
    let context = fixture();
    assert!(begin(&context, 1));
    install(&context, false, 1);
    install(&context, true, 1);
    assert!(!context.record(1, checked()));
}
