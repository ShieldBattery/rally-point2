//! Samples must not wait in, consume capacity from, or block lifecycle delivery.

use rally_point_proto::control::{
    EvidenceObservation, EvidenceVerdict, ResultNotice, SlotEvidenceNotice,
};
use tokio::sync::Notify;

use super::super::periodic::{DispatchGate, try_dispatch_with};

use super::*;

#[tokio::test]
async fn a_blocked_periodic_webhook_does_not_block_same_session_result_delivery() {
    let _delivery = crate::test_support::PERIODIC_WEBHOOK_TEST_LOCK.lock().await;
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
            admission: None,
            historical_admission: None,
            tenant: tenant.clone(),
            session,
            slot: SlotId(0),
            external_id: Some("game-1".to_owned()),
            external_ref: None,
            observed_at_ms: 123,
            evidence: EvidenceObservation {
                interruption: None,

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
    let permits = Arc::new(DispatchGate::default());
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
    let second = TenantId("periodic-saturation-second".to_owned());
    tenant::enroll(
        setup.tenants(),
        KeyId("periodic-saturation-key".to_owned()),
        second.clone(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let payload = serde_json::json!({"event":"slotEvidence"});
    let submit = |tenant: &TenantId| {
        super::super::periodic::try_dispatch_with(
            &permits,
            setup.tenants().clone(),
            tenant.clone(),
            NotifyConfig { url: url.clone() },
            &payload,
        )
    };
    // These calls are synchronous: capacity is reserved before the tasks can run.
    for tenant in [&tenant, &second] {
        for _ in 0..2 {
            assert!(submit(tenant));
        }
    }
    for _ in 0..100 {
        assert!(!submit(&tenant));
        assert!(!submit(&TenantId("another-tenant".to_owned())));
    }
    assert_eq!(permits.counts(), (4, 2));
    for _ in 0..4 {
        timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert!(rx.try_recv().is_err());
    release.notify_waiters();
    timeout(Duration::from_secs(2), async {
        while permits.counts() != (0, 0) {
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
    assert_eq!(permits.counts(), (0, 0));
    tasks.shutdown().await;
}

#[tokio::test]
async fn a_stalled_tenant_cannot_consume_another_tenants_periodic_budget() {
    let permits = Arc::new(DispatchGate::default());
    let release = Arc::new(Notify::new());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let app = Router::new()
        .route(
            "/slow",
            post({
                let release = release.clone();
                let tx = tx.clone();
                move || {
                    let release = release.clone();
                    let tx = tx.clone();
                    async move {
                        let released = release.notified();
                        tokio::pin!(released);
                        released.as_mut().enable();
                        tx.send("slow").unwrap();
                        released.await;
                        StatusCode::OK
                    }
                }
            }),
        )
        .route(
            "/fast",
            post(move || {
                let tx = tx.clone();
                async move {
                    tx.send("fast").unwrap();
                    StatusCode::OK
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let setup = setup_without_session(format!("{base_url}/slow"));
    let slow = TenantId(TEST_TENANT.to_owned());
    let fast = TenantId("periodic-isolation-fast".to_owned());
    tenant::enroll(
        setup.tenants(),
        KeyId("periodic-isolation-key".to_owned()),
        fast.clone(),
        BufferBounds::new(1, 6).unwrap(),
    )
    .unwrap();
    let payload = serde_json::json!({"event":"slotEvidence"});
    let submit = |tenant: &TenantId, path: &str| {
        try_dispatch_with(
            &permits,
            setup.tenants().clone(),
            tenant.clone(),
            NotifyConfig {
                url: format!("{base_url}/{path}"),
            },
            &payload,
        )
    };
    assert!(submit(&slow, "slow"));
    assert!(submit(&slow, "slow"));
    for _ in 0..100 {
        assert!(!submit(&slow, "slow"));
    }
    for _ in 0..2 {
        assert_eq!(
            timeout(Duration::from_secs(2), rx.recv()).await.unwrap(),
            Some("slow")
        );
    }
    assert_eq!(permits.counts(), (2, 1));
    assert!(submit(&fast, "fast"));
    assert_eq!(
        timeout(Duration::from_secs(2), rx.recv()).await.unwrap(),
        Some("fast")
    );
    timeout(Duration::from_secs(2), async {
        while permits.counts() != (2, 1) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Both slow requests remain in flight until after the fast one completed.
    release.notify_waiters();
    timeout(Duration::from_secs(2), async {
        while permits.counts() != (0, 0) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tasks.shutdown().await;
}

#[test]
fn serialization_failure_releases_reservations_without_retaining_tenant_entries() {
    struct Unserializable;
    impl serde::Serialize for Unserializable {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("test failure"))
        }
    }
    let permits = Arc::new(DispatchGate::default());
    let tenants = tenant::TenantStore::new();
    for i in 0..1000 {
        assert!(!try_dispatch_with(
            &permits,
            tenants.clone(),
            TenantId(format!("serialize-{i}")),
            NotifyConfig {
                url: "http://localhost/hook".to_owned()
            },
            &Unserializable,
        ));
        assert_eq!(permits.counts(), (0, 0));
    }
}
