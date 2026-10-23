use super::*;

#[test]
fn requested_shutdown_cause_wins_over_sampler_and_task_cleanup() {
    for (close, expected) in [
        (
            close_slots as fn(&Sessions, &SessionKey, &[SlotId]),
            EvidenceInterruption::Revoked,
        ),
        (close_slots_for_silence, EvidenceInterruption::SilentSlot),
        (close_slots_for_desync, EvidenceInterruption::DesyncEvicted),
        (
            close_slots_for_lobby_violation,
            EvidenceInterruption::LobbyViolation,
        ),
    ] {
        for complete_first in [false, true] {
            let context = fixture();
            assert!(begin(&context, 1));
            close(&context.sessions, &context.key, &[context.slot]);
            assert!(context.current().is_none());
            if complete_first {
                assert!(!context.record(1, checked(), Some(EvidenceInterruption::StreamClosed)));
            }
            drop(Obligation {
                context: &context,
                sample: 1,
            });
            let state = context
                .mesh
                .session
                .decision_makers
                .retained_load_state(&context.key);
            if expected == EvidenceInterruption::Revoked {
                assert!(state.periodic_evidence.is_empty());
                assert!(state.evidence_history.is_empty());
            } else {
                assert_eq!(
                    state.periodic_evidence[0].observation.interruption,
                    Some(expected)
                );
                assert_eq!(state.evidence_history[0].history.failures, 1);
            }
        }
    }
}

#[test]
fn provisional_reap_cancels_pending_evidence_before_task_cleanup() {
    let context = fixture();
    assert!(begin(&context, 1));
    super::super::lifecycle::reap_provisional(&context.sessions, &context.key);
    assert!(!context.record(1, checked(), Some(EvidenceInterruption::StreamClosed)));
    drop(Obligation {
        context: &context,
        sample: 1,
    });
    let state = context
        .mesh
        .session
        .decision_makers
        .retained_load_state(&context.key);
    assert!(state.periodic_evidence.is_empty());
    assert!(state.evidence_history.is_empty());
}

#[test]
fn forward_queue_count_and_byte_bounds_label_pending_evidence() {
    for bytes in [0, super::super::MAX_OVERSIZE_TURN_COMMANDS_LEN] {
        let (context, _inbox) = fixture_with_inbox();
        assert!(begin(&context, 1));
        for _ in 0..=super::super::FORWARD_CAPACITY {
            super::super::fan_out(
                &context.sessions,
                &context.key,
                SlotId(1),
                Payload {
                    commands: vec![0; bytes].into(),
                    ..Default::default()
                },
            );
        }
        assert!(!context.record(1, checked(), Some(EvidenceInterruption::StreamClosed)));
        drop(Obligation {
            context: &context,
            sample: 1,
        });
        let state = context
            .mesh
            .session
            .decision_makers
            .retained_load_state(&context.key);
        assert_eq!(state.evidence_history[0].history.failures, 1);
        assert_eq!(
            state.evidence_history[0].history.sample.interruption,
            Some(EvidenceInterruption::LaggingSlot)
        );
    }
}

#[test]
fn normal_departure_preserves_prior_failure_count_and_delivery() {
    let context = fixture();
    let makers = &context.mesh.session.decision_makers;
    assert!(begin(&context, 1));
    makers.interrupt_periodic_evidence(
        &context.key,
        context.slot,
        context.epoch,
        EvidenceInterruption::Timeout,
    );
    let before = makers.retained_load_state(&context.key).evidence_history;
    assert!(begin(&context, 2));
    makers.interrupt_periodic_evidence(
        &context.key,
        context.slot,
        context.epoch,
        EvidenceInterruption::SlotDeparted,
    );
    drop(Obligation {
        context: &context,
        sample: 2,
    });
    let state = makers.retained_load_state(&context.key);
    assert_eq!(state.evidence_history, before);
    assert_eq!(
        state.periodic_evidence[0].observation.interruption,
        Some(EvidenceInterruption::SlotDeparted)
    );
    let reports = makers.evidence_reports(std::time::Instant::now(), 16);
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].history, before[0].history);
}

#[test]
fn link_teardown_uses_stamped_cause_and_clean_leave_never_retains_failure() {
    for mode in 0..4 {
        let context = fixture();
        assert!(begin(&context, 1));
        match mode {
            1 => close_slots(&context.sessions, &context.key, &[context.slot]),
            2 => close_slots_for_silence(&context.sessions, &context.key, &[context.slot]),
            _ => {}
        }
        super::super::slot_link::end_slot_link(
            &context.sessions,
            &context.mesh,
            &context.key,
            context.slot,
            context.epoch,
            mode == 3,
        );
        drop(Obligation {
            context: &context,
            sample: 1,
        });
        let reports = context
            .mesh
            .session
            .decision_makers
            .evidence_reports(std::time::Instant::now(), 16);
        if mode == 1 || mode == 3 {
            assert!(reports.is_empty());
        } else {
            assert_eq!(reports.len(), 1);
            assert_eq!(reports[0].history.failures, 1);
            assert_eq!(
                reports[0].history.sample.interruption,
                Some(if mode == 0 {
                    EvidenceInterruption::ConnectionClosed
                } else {
                    EvidenceInterruption::SilentSlot
                })
            );
        }
    }
}

#[tokio::test]
async fn reset_evidence_stream_does_not_claim_the_gameplay_connection_closed() {
    use rally_point_transport::noq::VarInt;
    use rally_point_transport::test_util::{Edge, loopback};
    let (client, relay, _client_endpoint, _relay_endpoint) = loopback(Edge::Client).await;
    let (mut send, mut recv) = relay.open_bi().await.unwrap();
    let challenge = PeriodicEvidenceContext {
        challenge_id: 1,
        nonce: [1; 32],
        assignment_revision: 1,
        check: EvidenceCheck::FullImage,
    };
    let server = exchange(&mut send, &mut recv, &challenge);
    let reset = async {
        let (mut response, mut requests) = client.accept_bi().await.unwrap();
        let mut bytes = [0; handshake::PERIODIC_CHALLENGE_LEN];
        requests.read_exact(&mut bytes).await.unwrap();
        response.reset(VarInt::from_u32(0)).unwrap();
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(server, reset)
    })
    .await
    .unwrap();
    assert_eq!(result, Err(EvidenceInterruption::StreamClosed));
    assert!(relay.close_reason().is_none());
    assert!(client.close_reason().is_none());
    relay.send_datagram(b"still live".to_vec().into()).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), client.read_datagram())
            .await
            .unwrap()
            .unwrap()
            .as_ref(),
        b"still live"
    );
}

#[test]
fn administrative_and_departure_signals_cannot_become_client_failures() {
    for departed in [false, true] {
        for close in [
            close_slots_for_silence,
            close_slots_for_desync,
            close_slots_for_lobby_violation,
        ] {
            let context = fixture();
            assert!(begin(&context, 1));
            if departed {
                // Normal-leave ingress stamps this cause before settling the
                // pending obligation. Exercise a competing signal in that gap.
                context.sessions.lock()[&context.key][&context.slot]
                    .close_reason
                    .store(SlotCloseReason::SlotDeparted as u8, Ordering::Release);
            } else {
                close_slots(&context.sessions, &context.key, &[context.slot]);
            }
            close(&context.sessions, &context.key, &[context.slot]);
            assert!(!context.record(1, checked(), Some(EvidenceInterruption::StreamClosed)));
            drop(Obligation {
                context: &context,
                sample: 1,
            });
            let state = context
                .mesh
                .session
                .decision_makers
                .retained_load_state(&context.key);
            assert!(state.evidence_history.is_empty());
            if departed {
                assert_eq!(
                    state.periodic_evidence[0].observation.interruption,
                    Some(EvidenceInterruption::SlotDeparted)
                );
            } else {
                assert!(state.periodic_evidence.is_empty());
            }
            assert!(
                context
                    .mesh
                    .session
                    .decision_makers
                    .evidence_reports(std::time::Instant::now(), 16)
                    .is_empty()
            );
        }
    }
}

#[test]
fn administrative_signal_can_cancel_a_technical_close_before_settlement() {
    let context = fixture();
    assert!(begin(&context, 1));
    close_slots_for_silence(&context.sessions, &context.key, &[context.slot]);
    close_slots(&context.sessions, &context.key, &[context.slot]);
    drop(Obligation {
        context: &context,
        sample: 1,
    });
    let state = context
        .mesh
        .session
        .decision_makers
        .retained_load_state(&context.key);
    assert!(state.evidence_history.is_empty());
    assert!(state.periodic_evidence.is_empty());
}
