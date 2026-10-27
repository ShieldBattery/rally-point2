use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use rally_point_proto::control::TenantId;
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::token::{ClientPublicKey, Signature};

use super::*;

fn request() -> EvidenceRequest {
    EvidenceRequest {
        periodic: None,
        challenge: [1; 32],
        channel_binding: [2; 32],
        tenant: TenantId("test".into()),
        session: SessionId(3),
        slot: SlotId(4),
        client_pubkey: ClientPublicKey([5; 32]),
    }
}

fn evidence(body: Vec<u8>) -> Evidence {
    Evidence {
        key_id: 7,
        body,
        signature: Signature([0; 64]),
    }
}

#[tokio::test]
async fn successful_provider_receives_the_connection_context() {
    let provider = Provider::new(|request| Some(evidence(request.challenge.to_vec())));
    assert_eq!(
        provider.collect(request()).await,
        Some(evidence(vec![1; 32]))
    );
}

#[tokio::test]
async fn missing_panicking_and_oversized_providers_supply_none() {
    for provider in [
        Provider::new(|_| None),
        Provider::new(|_| panic!("test callback")),
        Provider::new(|_| Some(evidence(vec![0; MAX_EVIDENCE_BODY_LEN + 1]))),
    ] {
        assert!(provider.collect(request()).await.is_none());
        // A callback that outlives the provider timeout keeps its permit until it returns, and
        // a panicking one can: unwinding prints a backtrace first, which takes a while on a busy
        // machine. Waiting for the permit checks that it comes back at all.
        let permit = tokio::time::timeout(Duration::from_secs(30), provider.available.acquire())
            .await
            .expect("the callback's permit is released once it returns")
            .unwrap();
        drop(permit);
        assert_eq!(provider.available.available_permits(), 1);
    }
}

#[tokio::test]
async fn concurrent_dials_wait_and_receive_their_own_evidence() {
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let started = Mutex::new(Some(started_tx));
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let release = Mutex::new(release_rx);
    let calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = calls.clone();
    let provider = Arc::new(Provider::new(move |request| {
        if callback_calls.fetch_add(1, Ordering::Relaxed) == 0 {
            let _ = started.lock().unwrap().take().unwrap().send(());
            let _ = release.lock().unwrap().recv_timeout(Duration::from_secs(5));
        }
        Some(evidence(request.challenge.to_vec()))
    }));
    let first_provider = provider.clone();
    let first = tokio::spawn(async move { first_provider.collect(request()).await });
    started_rx.await.unwrap();

    let mut second_request = request();
    second_request.challenge = [2; 32];
    let mut second = std::pin::pin!(provider.collect(second_request));
    let queued =
        std::future::poll_fn(|cx| std::task::Poll::Ready(second.as_mut().poll(cx).is_pending()))
            .await;
    let count_while_blocked = calls.load(Ordering::Relaxed);
    release_tx.send(()).unwrap();
    assert!(queued, "a concurrent dial must wait for the callback");
    assert_eq!(count_while_blocked, 1);
    let (first, second) = tokio::join!(first, second);
    assert_eq!(first.unwrap(), Some(evidence(vec![1; 32])));
    assert_eq!(second, Some(evidence(vec![2; 32])));
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn timeout_or_cancellation_does_not_allow_another_blocking_callback() {
    for cancel in [false, true] {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let started = Mutex::new(Some(started_tx));
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release = Mutex::new(release_rx);
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = calls.clone();
        let provider = Arc::new(Provider::new(move |_| {
            if callback_calls.fetch_add(1, Ordering::Relaxed) == 0 {
                let _ = started.lock().unwrap().take().unwrap().send(());
                // A failed assertion cannot leave a blocking task holding the runtime forever.
                let _ = release.lock().unwrap().recv_timeout(Duration::from_secs(5));
            }
            Some(evidence(vec![]))
        }));
        let task_provider = provider.clone();
        let task = tokio::spawn(async move { task_provider.collect(request()).await });
        started_rx.await.unwrap();
        let empty = if cancel {
            task.abort();
            task.await.unwrap_err().is_cancelled()
        } else {
            task.await.unwrap().is_none()
        };
        let second = provider.collect(request()).await;
        let count = calls.load(Ordering::Relaxed);
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while provider.available.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(empty);
        assert!(second.is_none());
        assert_eq!(count, 1);
        assert!(provider.collect(request()).await.is_some());
    }
}

#[test]
fn queued_callback_is_cancelled_before_it_can_start() {
    for cancel in [false, true] {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let (occupied, started) = tokio::sync::oneshot::channel();
            let (release, wait) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                occupied.send(()).unwrap();
                let _ = wait.recv_timeout(Duration::from_secs(5));
            });
            started.await.unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let callback_calls = calls.clone();
            let provider = Arc::new(Provider::new(move |_| {
                callback_calls.fetch_add(1, Ordering::Relaxed);
                None
            }));
            let task_provider = provider.clone();
            let task = tokio::spawn(async move { task_provider.collect(request()).await });
            while provider.available.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
            if cancel {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                assert!(task.await.unwrap().is_none());
            }
            release.send(()).unwrap();
            blocker.await.unwrap();
            tokio::task::spawn_blocking(|| ()).await.unwrap();
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            assert_eq!(provider.available.available_permits(), 1);
        });
    }
}
