//! Future receipt semantics must neither lose reports nor reconnect the control link.
use super::periodic_reporting::reporting_fixture;
use super::*;
use rally_point_proto::control::{EvidenceInterruption, EvidenceObservation};
use rally_point_proto::ids::SlotId;

#[tokio::test]
async fn future_receipt_disposition_retains_report_and_keeps_control_link_usable() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let (sources, admission, _) = reporting_fixture();
    let makers = sources.decision_makers.clone();
    let mesh = crate::mesh::MeshState::new(crate::session::SessionState {
        decision_makers: makers.clone(),
        ..Default::default()
    });
    let control = MeshControl::new(RelayId(1), &mesh, sources.sessions.clone());
    assert!(makers.begin_periodic_evidence(
        &key(7),
        SlotId(0),
        1,
        EvidenceObservation {
            sample_id: 2,
            ..admission
        }
    ));
    makers.abandon_periodic_evidence(&key(7), SlotId(0), 1, 2, EvidenceInterruption::Timeout);
    control.end_session(&key(7));
    SubscriberFixture {
        control,
        heartbeat: HeartbeatConfig {
            sources,
            interval: Duration::from_secs(3600),
        },
        ..Default::default()
    }
    .spawn(listener.local_addr().unwrap());
    tokio::time::timeout(Duration::from_secs(5), async {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        accept_enroll(&mut ws).await;
        let RelayToCoordinator::EvidenceReport(report) = decode(ws.next().await.unwrap().unwrap())
        else {
            panic!("completed failure must reach the coordinator");
        };
        let receipt = report.receipt();
        let mut future =
            serde_json::to_value(CoordinatorToRelay::EvidenceReceipt(receipt.clone())).unwrap();
        future["disposition"] = "deferred_until_persistence".into();
        for (frame, ack_id, retained) in [
            (future, 1, true),
            (
                serde_json::to_value(CoordinatorToRelay::EvidenceReceipt(receipt.clone())).unwrap(),
                2,
                false,
            ),
        ] {
            ws.send(Message::Text(frame.to_string().into()))
                .await
                .unwrap();
            ws.send(Message::Text(
                serde_json::to_string(&CoordinatorToRelay::Descriptors {
                    ack_id: Some(ack_id),
                    staged_at_unix_ms: None,
                    descriptors: vec![],
                })
                .unwrap()
                .into(),
            ))
            .await
            .unwrap();
            assert_eq!(
                decode(ws.next().await.unwrap().unwrap()),
                RelayToCoordinator::DescriptorsApplied { ack_id }
            );
            // Ordered descriptor acknowledgement proves the preceding receipt was applied.
            assert_eq!(
                makers.evidence_report_pending(&receipt, std::time::Instant::now()),
                retained
            );
        }
    })
    .await
    .unwrap();
}
