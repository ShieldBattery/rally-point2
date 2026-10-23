//! Samples must not wait in, consume capacity from, or block lifecycle delivery.

use rally_point_proto::control::{
    EvidenceObservation, EvidenceVerdict, ResultNotice, SlotEvidenceNotice,
};
use tokio::sync::{Notify, Semaphore};

use super::*;

#[tokio::test]
async fn a_blocked_periodic_webhook_does_not_block_same_session_result_delivery() {
    let gate = Arc::new(Notify::new());
    let (url, mut rx) = WebhookReceiver {
        gate: Some(gate.clone()),
        ..Default::default()
    }
    .spawn()
    .await;
    let setup = setup_without_session(url);
    let lifecycle = Lifecycle::new(setup.clone());
    let tenant = TenantId(TEST_TENANT.to_owned());
    let session = SessionId(75);
    handle_slot_evidence(
        &setup,
        SlotEvidenceNotice {
            tenant: tenant.clone(),
            session,
            slot: SlotId(0),
            external_id: Some("game-1".to_owned()),
            external_ref: None,
            observed_at_ms: 123,
            evidence: EvidenceObservation {
                sample_id: 1,
                connection_id: [1; 32],
                sequence: 2,
                assignment_revision: 3,
                verdict: EvidenceVerdict::Valid,
                key_id: Some(4),
                body: vec![5],
            },
        },
    );
    let sample = signed_webhook(&setup, &mut rx).await;
    assert_eq!(sample.event(), "slotEvidence");
    report(
        &lifecycle,
        SessionNotice::Result(ResultNotice {
            tenant,
            session,
            slot: SlotId(0),
            external_id: Some("game-1".to_owned()),
            external_ref: None,
            payload: vec![1, 2],
            arrival_ms: 456,
            session_frame: None,
            slot_frame: None,
        }),
    );
    let result = signed_webhook(&setup, &mut rx).await;
    assert_eq!(result.event(), "result");
    assert_eq!(sample.body["session"], result.body["session"]);
    // Only now can the periodic attempt finish; it cannot have released a
    // session-ordered queue to permit the result observed above.
    gate.notify_one();
}

#[tokio::test]
async fn saturated_periodic_delivery_sheds_without_a_pending_queue_and_never_retries() {
    let permits = Arc::new(Semaphore::new(4));
    let release = Arc::new(Notify::new());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let app = Router::new().route(
        "/hook",
        post({
            let release = release.clone();
            move || {
                let release = release.clone();
                let tx = tx.clone();
                async move {
                    let released = release.notified();
                    tokio::pin!(released);
                    released.as_mut().enable();
                    tx.send(()).unwrap();
                    released.await;
                    StatusCode::TOO_MANY_REQUESTS
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let setup = setup_without_session(url.clone());
    let tenant = TenantId(TEST_TENANT.to_owned());
    let payload = serde_json::json!({"event":"slotEvidence"});
    let submit = || {
        super::super::periodic::try_dispatch_with(
            &permits,
            setup.tenants().clone(),
            tenant.clone(),
            NotifyConfig { url: url.clone() },
            &payload,
        )
    };
    // These calls are synchronous: capacity is reserved before the tasks can run.
    for _ in 0..4 {
        assert!(submit());
    }
    for _ in 0..100 {
        assert!(!submit());
    }
    assert_eq!(permits.available_permits(), 0);
    for _ in 0..4 {
        timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert!(rx.try_recv().is_err());
    release.notify_waiters();
    timeout(Duration::from_secs(2), async {
        while permits.available_permits() != 4 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Dropped submissions cannot start when permits return, and a 429 cannot
    // schedule the two-second retry used by lifecycle delivery.
    assert!(
        timeout(Duration::from_millis(2200), rx.recv())
            .await
            .is_err()
    );
    assert_eq!(permits.available_permits(), 4);
    tasks.shutdown().await;
}
