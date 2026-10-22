use super::*;
use std::sync::Arc;
use std::time::Duration;

use crate::consensus::{Authority, DecisionMakers, MakerSync};
use rally_point_proto::control::{BufferBounds, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};

fn config(revision: u64) -> EvidenceConfig {
    EvidenceConfig {
        required_slots: [SlotId(0)].into_iter().collect(),
        assignments: [(SlotId(0), revision)].into_iter().collect(),
        ..Default::default()
    }
}

fn install(registry: &DecisionMakers, key: &SessionKey, evidence: EvidenceConfig) {
    let _ = registry.sync_maker(
        key,
        MakerSync {
            evidence,
            ..MakerSync::new(BufferBounds::new(1, 6).unwrap(), Authority::SelfRelay)
        },
    );
}

#[tokio::test]
async fn descriptor_wait_wakes_only_after_configuration_is_installed() {
    let state = SessionState::default();
    let registry = &state.decision_makers;
    let key = SessionKey {
        tenant: TenantId("tenant".into()),
        session: SessionId(1),
    };
    registry.require_descriptors();
    let wait = state.wait_evidence_config(&key);
    tokio::pin!(wait);
    assert!(
        tokio::time::timeout(Duration::ZERO, &mut wait)
            .await
            .is_err()
    );
    install(registry, &key, config(1));
    assert_eq!(wait.await, Some(config(1)));
    install(
        registry,
        &key,
        EvidenceConfig {
            assignments: [(SlotId(0), 2)].into_iter().collect(),
            ..Default::default()
        },
    );
    assert_eq!(
        registry.evidence_config(&key),
        Some(config(2)),
        "repush refreshes assignment without dropping required policy"
    );
}

#[tokio::test]
async fn cached_descriptor_is_ready_on_every_poll_without_a_timer() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    let state = SessionState::default();
    let registry = &state.decision_makers;
    let key = crate::test_support::session_key(2);
    registry.require_descriptors();
    install(registry, &key, config(1));
    for _attempt in 0..2 {
        let wait = state.wait_evidence_config(&key);
        tokio::pin!(wait);
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            wait.as_mut().poll(&mut context),
            Poll::Ready(Some(config(1)))
        );
    }
}

#[tokio::test]
async fn retirement_resolves_an_existing_wait_and_a_later_dial_immediately() {
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};

    struct WakeCount(AtomicUsize);
    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let state = SessionState::default();
    let key = crate::test_support::session_key(3);
    let count = Arc::new(WakeCount(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    let mut context = Context::from_waker(&waker);
    let wait = state.wait_evidence_config(&key);
    tokio::pin!(wait);
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Pending);
    state.retire(&key, &crate::mesh::new_seen_registries());
    assert!(
        count.0.load(Ordering::Relaxed) > 0,
        "retirement wakes the parked dial"
    );
    assert_eq!(wait.as_mut().poll(&mut context), Poll::Ready(None));
    let later = state.wait_evidence_config(&key);
    tokio::pin!(later);
    assert_eq!(later.as_mut().poll(&mut context), Poll::Ready(None));
}

#[tokio::test]
async fn a_descriptor_wait_timeout_leaves_no_session_gate() {
    let state = SessionState::default();
    let registry = &state.decision_makers;
    let key = crate::test_support::session_key(4);
    assert!(
        tokio::time::timeout(Duration::ZERO, state.wait_evidence_config(&key),)
            .await
            .is_err()
    );
    assert_eq!(state.gates.tracked(), 0);
    assert!(!registry.maker_exists(&key));
}
