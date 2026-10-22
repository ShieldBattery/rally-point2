use super::*;

fn descriptor(session: u64) -> SessionDescriptor {
    crate::test_support::descriptor(TenantId("tenant".to_owned()), session)
}

#[test]
fn acknowledgements_are_generation_fenced_and_cannot_claim_unsent_frames() {
    let delivery = DescriptorDelivery::default();
    let relay = RelayId(1);
    let descriptor = descriptor(1);
    assert!(delivery.begin(relay, 10));
    assert_eq!(
        delivery.sent(relay, 10, std::slice::from_ref(&descriptor)),
        Some(1)
    );
    assert!(!delivery.acknowledge(relay, 9, 1));
    assert!(!delivery.acknowledge(relay, 10, 0));
    assert!(!delivery.acknowledge(relay, 10, 2));
    assert!(!delivery.is_ready(relay, 10, &descriptor));
    assert!(delivery.acknowledge(relay, 10, 1));
    assert!(delivery.is_ready(relay, 10, &descriptor));
    assert!(delivery.acknowledge(relay, 10, 1));
}

#[test]
fn unchanged_session_keeps_proof_while_other_sessions_change() {
    let delivery = DescriptorDelivery::default();
    let relay = RelayId(1);
    let first = descriptor(1);
    let mut second = descriptor(2);
    delivery.begin(relay, 1);
    delivery.sent(relay, 1, &[first.clone(), second.clone()]);
    delivery.acknowledge(relay, 1, 1);
    second.resumed = true;
    assert_eq!(
        delivery.sent(relay, 1, &[first.clone(), second.clone()]),
        Some(2)
    );
    assert!(delivery.is_ready(relay, 1, &first));
    assert!(!delivery.is_ready(relay, 1, &second));
    delivery.acknowledge(relay, 1, 2);
    assert!(delivery.is_ready(relay, 1, &second));
}

#[test]
fn late_ack_does_not_license_a_changed_or_reverted_descriptor() {
    let delivery = DescriptorDelivery::default();
    let relay = RelayId(1);
    let original = descriptor(1);
    let mut changed = original.clone();
    changed.resumed = true;
    delivery.begin(relay, 1);
    delivery.sent(relay, 1, std::slice::from_ref(&original));
    delivery.sent(relay, 1, std::slice::from_ref(&changed));
    delivery.sent(relay, 1, std::slice::from_ref(&original));
    delivery.acknowledge(relay, 1, 2);
    assert!(!delivery.is_ready(relay, 1, &original));
    assert!(!delivery.is_ready(relay, 1, &changed));
    delivery.acknowledge(relay, 1, 3);
    assert!(delivery.is_ready(relay, 1, &original));
}

#[test]
fn disconnect_and_reconnect_reset_proof_without_reopening_old_generations() {
    let delivery = DescriptorDelivery::default();
    let relay = RelayId(1);
    let descriptor = descriptor(1);
    delivery.begin(relay, 1);
    delivery.sent(relay, 1, std::slice::from_ref(&descriptor));
    delivery.acknowledge(relay, 1, 1);
    delivery.end(relay, 1);
    assert!(!delivery.is_ready(relay, 1, &descriptor));
    assert!(!delivery.begin(relay, 1));
    assert!(!delivery.begin(relay, 0));
    assert_eq!(
        delivery.sent(relay, 1, std::slice::from_ref(&descriptor)),
        None
    );
    assert!(!delivery.acknowledge(relay, 1, 1));
    assert!(delivery.begin(relay, 2));
    delivery.end(relay, 1);
    assert_eq!(
        delivery.sent(relay, 2, std::slice::from_ref(&descriptor)),
        Some(1)
    );
    assert!(!delivery.is_ready(relay, 2, &descriptor));
    assert!(!delivery.acknowledge(relay, 1, 1));
    delivery.acknowledge(relay, 2, 1);
    assert!(delivery.is_ready(relay, 2, &descriptor));
}

#[test]
fn snapshots_do_not_accumulate_history_and_sequence_exhaustion_refuses() {
    let delivery = DescriptorDelivery::default();
    let relay = RelayId(1);
    delivery.begin(relay, 1);
    for session in 1..100 {
        delivery.sent(relay, 1, &[descriptor(session)]);
        assert_eq!(delivery.inner.lock()[&relay].sent.len(), 1);
    }
    let last = descriptor(99);
    delivery.inner.lock().get_mut(&relay).unwrap().issued = u64::MAX;
    assert_eq!(delivery.sent(relay, 1, &[descriptor(100)]), None);
    assert_eq!(
        delivery.inner.lock()[&relay].sent[&key(&last)].descriptor,
        last
    );
    delivery.end(relay, 1);
    assert!(delivery.inner.lock()[&relay].sent.is_empty());
    delivery.forget(relay);
    assert!(delivery.inner.lock().is_empty());
}

#[tokio::test]
async fn outbox_changes_wake_waiters_and_retirement_discards_proof() {
    let outbox = crate::descriptors::RelayDescriptors::new();
    let relay = RelayId(1);
    let descriptor = descriptor(1);
    let delivery = outbox.delivery();
    delivery.begin(relay, 1);
    let changed = delivery.changed();
    tokio::pin!(changed);
    changed.as_mut().enable();
    outbox.record(relay, descriptor.clone());
    assert!(futures_util::poll!(changed.as_mut()).is_ready());
    delivery.sent(relay, 1, std::slice::from_ref(&descriptor));
    delivery.acknowledge(relay, 1, 1);
    assert!(delivery.is_ready(relay, 1, &descriptor));
    outbox.remove(relay, &descriptor.tenant, descriptor.session);
    assert!(delivery.inner.lock()[&relay].sent.is_empty());
    outbox.record(relay, descriptor.clone());
    assert!(!delivery.is_ready(relay, 1, &descriptor));
    delivery.sent(relay, 1, std::slice::from_ref(&descriptor));
    delivery.acknowledge(relay, 1, 1);
    assert!(!delivery.is_ready(relay, 1, &descriptor));
    delivery.acknowledge(relay, 1, 2);
    assert!(delivery.is_ready(relay, 1, &descriptor));
    outbox.forget(relay);
    assert!(delivery.inner.lock().is_empty());
}

#[tokio::test]
async fn clone_notifications_cover_enrollment_acknowledgement_and_disconnect() {
    let delivery = DescriptorDelivery::default();
    let other = delivery.clone();
    let relay = RelayId(1);
    let changed = delivery.changed();
    tokio::pin!(changed);
    changed.as_mut().enable();
    other.begin(relay, 1);
    assert!(futures_util::poll!(changed.as_mut()).is_ready());
    other.sent(relay, 1, &[descriptor(1)]);
    let changed = delivery.changed();
    tokio::pin!(changed);
    changed.as_mut().enable();
    other.acknowledge(relay, 1, 1);
    assert!(futures_util::poll!(changed.as_mut()).is_ready());
    let changed = delivery.changed();
    tokio::pin!(changed);
    changed.as_mut().enable();
    other.end(relay, 1);
    assert!(futures_util::poll!(changed.as_mut()).is_ready());
}

#[test]
fn forgotten_relay_is_not_recreated_when_its_writer_drops() {
    let delivery = DescriptorDelivery::default();
    let relay = RelayId(1);
    delivery.begin(relay, 5);
    delivery.sent(relay, 5, &[descriptor(1)]);
    delivery.forget(relay);
    delivery.end(relay, 5);
    assert_eq!(delivery.sent(relay, 5, &[descriptor(1)]), None);
    assert!(!delivery.acknowledge(relay, 5, 1));
    assert!(delivery.inner.lock().is_empty());
}
