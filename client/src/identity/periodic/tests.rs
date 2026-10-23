use super::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::handshake::{
    Evidence, EvidenceCheck, PERIODIC_RESPONSE_HEADER_LEN, PeriodicEvidenceContext,
};
use rally_point_proto::ids::{SessionId, SlotId};
use rally_point_proto::token::{ClientPublicKey, Signature};
use rally_point_transport::{
    Link,
    test_util::{Edge, loopback},
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn request() -> EvidenceRequest {
    EvidenceRequest {
        periodic: None,
        challenge: [1; 32],
        channel_binding: [2; 32],
        tenant: TenantId("t".into()),
        session: SessionId(3),
        slot: SlotId(4),
        client_pubkey: ClientPublicKey([5; 32]),
    }
}
fn challenge(id: u64) -> [u8; PERIODIC_CHALLENGE_LEN] {
    handshake::encode_periodic_challenge(&PeriodicEvidenceContext {
        challenge_id: id,
        nonce: [8; 32],
        assignment_revision: 2,
        check: EvidenceCheck::FullImage,
    })
    .unwrap()
}
fn provider(calls: Arc<AtomicUsize>) -> Arc<Provider> {
    Arc::new(Provider::new(move |request| {
        calls.fetch_add(1, Ordering::Relaxed);
        Some(Evidence {
            key_id: 7,
            body: request.signed_message(7, b"body"),
            signature: Signature([0; 64]),
        })
    }))
}
struct Fixture {
    link: Option<Link>,
    peer: noq::Connection,
    send: noq::SendStream,
    recv: noq::RecvStream,
    _client: noq::Endpoint,
    _server: noq::Endpoint,
}
impl Fixture {
    async fn new(provider: Option<Arc<Provider>>, budget: Arc<Budget>) -> Self {
        let (connection, peer, client, server) = loopback(Edge::Client).await;
        let (mut send, recv) = connection.open_bi().await.unwrap();
        send.write_all(&[0]).await.unwrap();
        let (peer_send, mut peer_recv) = peer.accept_bi().await.unwrap();
        peer_recv.read_exact(&mut [0]).await.unwrap();
        let task = start(connection.clone(), send, recv, request(), provider, budget);
        Self {
            link: Some(Link::new(connection).with_connection_task(task)),
            peer,
            send: peer_send,
            recv: peer_recv,
            _client: client,
            _server: server,
        }
    }
    async fn response(&mut self) -> (u64, Option<Evidence>) {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut header = [0; PERIODIC_RESPONSE_HEADER_LEN];
            self.recv.read_exact(&mut header).await.unwrap();
            let (_, len) = handshake::decode_periodic_response_header(&header).unwrap();
            let mut bytes = vec![0; len];
            self.recv.read_exact(&mut bytes).await.unwrap();
            handshake::decode_periodic_response(&header, &bytes).unwrap()
        })
        .await
        .unwrap()
    }
    async fn stream_ended(&mut self) {
        assert!(
            tokio::time::timeout(Duration::from_secs(5), self.recv.read_exact(&mut [0]))
                .await
                .unwrap()
                .is_err()
        );
        assert!(
            self.peer.close_reason().is_none(),
            "evidence failure must not close gameplay"
        );
    }
}
fn ready_budget() -> Arc<Budget> {
    Arc::new(Budget(Mutex::new(Instant::now())))
}

#[test]
fn identity_budget_has_initial_delay_and_shared_cooldown() {
    let budget = Arc::new(Budget::new());
    let another_connection = budget.clone();
    assert!(!budget.reserve(Instant::now()));
    let ready_at = *budget.0.lock().unwrap();
    assert!(budget.reserve(ready_at));
    assert!(!another_connection.reserve(ready_at));
    assert!(another_connection.reserve(ready_at + MIN_INTERVAL));
}

#[tokio::test]
async fn response_uses_periodic_context_and_does_not_park_datagrams() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut fixture = Fixture::new(Some(provider(calls.clone())), ready_budget()).await;
    fixture.send.write_all(&challenge(7)).await.unwrap();
    let (id, evidence) = fixture.response().await;
    assert_eq!(id, 7);
    let mut expected = request();
    expected.periodic = Some(handshake::decode_periodic_challenge(&challenge(7)).unwrap());
    assert_eq!(evidence.unwrap().body, expected.signed_message(7, b"body"));
    fixture
        .link
        .as_ref()
        .unwrap()
        .connection()
        .send_datagram(vec![42].into())
        .unwrap();
    assert_eq!(fixture.peer.read_datagram().await.unwrap().as_ref(), &[42]);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn excessive_duplicate_and_decreasing_challenges_end_only_the_stream() {
    for second_id in [8, 7, 6] {
        let calls = Arc::new(AtomicUsize::new(0));
        let budget = ready_budget();
        let mut fixture = Fixture::new(Some(provider(calls.clone())), budget.clone()).await;
        fixture.send.write_all(&challenge(7)).await.unwrap();
        fixture.response().await;
        if second_id != 8 {
            *budget.0.lock().unwrap() = Instant::now();
        }
        fixture.send.write_all(&challenge(second_id)).await.unwrap();
        fixture.stream_ended().await;
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn initial_rapid_malformed_and_partial_challenges_do_no_work() {
    for case in 0..4 {
        let calls = Arc::new(AtomicUsize::new(0));
        let budget = if case == 0 {
            Arc::new(Budget::new())
        } else {
            ready_budget()
        };
        let mut fixture = Fixture::new(Some(provider(calls.clone())), budget).await;
        let mut bytes = challenge(7);
        if case == 1 {
            bytes[48] = 255;
        }
        if case == 2 {
            bytes[..8].fill(0);
        }
        let bytes = if case == 3 { &bytes[..1] } else { &bytes[..] };
        fixture.send.write_all(bytes).await.unwrap();
        fixture.stream_ended().await;
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn missing_provider_answers_without_work() {
    let mut fixture = Fixture::new(None, ready_budget()).await;
    fixture.send.write_all(&challenge(7)).await.unwrap();
    assert_eq!(fixture.response().await, (7, None));
}

#[tokio::test]
async fn dropping_link_stops_idle_worker_even_with_another_connection_handle() {
    let mut fixture = Fixture::new(None, ready_budget()).await;
    let connection = fixture.link.as_ref().unwrap().connection().clone();
    fixture.link.take();
    fixture.stream_ended().await;
    assert!(connection.close_reason().is_none());
}

#[tokio::test]
async fn blocked_old_connection_cannot_accumulate_callbacks_after_timeout_or_drop() {
    let calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = calls.clone();
    let (started, running) = tokio::sync::oneshot::channel();
    let started = Mutex::new(Some(started));
    let (release, wait) = std::sync::mpsc::channel();
    let wait = Mutex::new(wait);
    let provider = Arc::new(Provider::new(move |_| {
        callback_calls.fetch_add(1, Ordering::Relaxed);
        if let Some(started) = started.lock().unwrap().take() {
            let _ = started.send(());
            let _ = wait.lock().unwrap().recv_timeout(Duration::from_secs(8));
        }
        None
    }));
    let budget = ready_budget();
    let mut old = Fixture::new(Some(provider.clone()), budget.clone()).await;
    old.send.write_all(&challenge(7)).await.unwrap();
    running.await.unwrap();
    old.link
        .as_ref()
        .unwrap()
        .connection()
        .send_datagram(vec![42].into())
        .unwrap();
    assert_eq!(old.peer.read_datagram().await.unwrap().as_ref(), &[42]);
    assert_eq!(old.response().await, (7, None));
    old.link.take();
    *budget.0.lock().unwrap() = Instant::now();
    let mut fresh = Fixture::new(Some(provider), budget).await;
    fresh.send.write_all(&challenge(1)).await.unwrap();
    assert_eq!(fresh.response().await, (1, None));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    release.send(()).unwrap();
}

#[tokio::test]
async fn dropping_or_aborting_driver_releases_evidence_worker() {
    for run in [false, true] {
        let mut fixture = Fixture::new(None, ready_budget()).await;
        let connection = fixture.link.as_ref().unwrap().connection().clone();
        let (driver, _channels) = crate::LinkDriver::new(fixture.link.take().unwrap());
        if run {
            let task = tokio::spawn(driver.run());
            tokio::task::yield_now().await;
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            drop(driver);
        }
        fixture.stream_ended().await;
        connection.close(0u32.into(), b"test done");
    }
}
