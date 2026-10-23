use super::*;
use rally_point_proto::control::{EvidenceHistory, EvidenceObservation, EvidenceVerdict, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};

fn report(sequence: u64) -> EvidenceReport {
    let admission = EvidenceObservation {
        interruption: None,
        sample_id: 0,
        connection_id: [3; 32],
        sequence: 1,
        assignment_revision: 2,
        verdict: EvidenceVerdict::Valid,
        key_id: Some(1),
        body: vec![7; 32],
    };
    EvidenceReport {
        tenant: TenantId("test".into()),
        session: SessionId(sequence),
        slot: SlotId(0),
        history: EvidenceHistory {
            failures: 1,
            latest: None,
            sample: EvidenceObservation {
                interruption: None,
                sequence,
                sample_id: 1,
                verdict: EvidenceVerdict::Missing,
                body: Vec::new(),
                ..admission.clone()
            },
            admission,
            observed_at_ms: 50,
        },
    }
}

#[test]
fn receipt_requires_every_identity_field() {
    let outbox = EvidenceOutbox::default();
    let now = Instant::now();
    let report = report(2);
    outbox.insert(report.clone(), now);
    let exact = report.receipt();
    for field in 0..8 {
        let mut wrong = exact.clone();
        match field {
            0 => wrong.tenant = TenantId("other".into()),
            1 => wrong.session.0 += 1,
            2 => wrong.slot = SlotId(1),
            3 => wrong.assignment_revision += 1,
            4 => wrong.connection_id = [4; 32],
            5 => wrong.sample_id += 1,
            6 => wrong.sequence += 1,
            _ => wrong.failures += 1,
        }
        outbox.acknowledge(&wrong);
        assert_eq!(outbox.inner.lock().entries.len(), 1);
    }
    outbox.acknowledge(&exact);
    outbox.acknowledge(&exact);
    assert!(outbox.reports(now + RETRY, 16).is_empty());
    assert_eq!(outbox.inner.lock().bytes, 0);
}

#[test]
fn retries_are_paced_and_fair_without_connection_local_state() {
    let outbox = EvidenceOutbox::default();
    let now = Instant::now();
    for sequence in 2..22 {
        outbox.insert(report(sequence), now);
    }
    let first = outbox.reports(now, 16);
    assert_eq!(first.len(), 16);
    let next_connection = outbox.reports(now, 16);
    assert_eq!(next_connection.len(), 4);
    assert_eq!(next_connection[0].history.sample.sequence, 18);
    assert!(outbox.reports(now + RETRY / 2, 16).is_empty());
    let mut retried = outbox.reports(now + RETRY, 16);
    retried.extend(outbox.reports(now + RETRY, 16));
    let mut sequences: Vec<_> = retried.iter().map(|r| r.history.sample.sequence).collect();
    sequences.sort_unstable();
    assert_eq!(sequences, (2..22).collect::<Vec<_>>());
}

#[test]
fn count_limit_preserves_older_reports_and_expiry_frees_space() {
    let outbox = EvidenceOutbox::default();
    let now = Instant::now();
    for sequence in 2..(MAX_REPORTS as u64 + 3) {
        outbox.insert(report(sequence), now);
    }
    assert_eq!(outbox.inner.lock().entries.len(), MAX_REPORTS);
    assert_eq!(outbox.inner.lock().lost_capacity, 1);
    assert_eq!(outbox.reports(now, 1)[0].history.sample.sequence, 2);
    assert!(outbox.reports(now + RETENTION, 16).is_empty());
    assert_eq!(outbox.inner.lock().lost_expired, MAX_REPORTS as u64);
    assert_eq!(outbox.inner.lock().bytes, 0);
    outbox.insert(report(5000), now + RETENTION);
    assert_eq!(outbox.reports(now + RETENTION, 16).len(), 1);
}

#[test]
fn byte_limit_can_fill_before_count_limit_and_does_not_evict_oldest() {
    let outbox = EvidenceOutbox::default();
    let now = Instant::now();
    for sequence in 2..502 {
        let mut report = report(sequence);
        report.tenant = TenantId("tenant".repeat(4096));
        report.history.admission.body =
            vec![7; rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN];
        outbox.insert(report, now);
    }
    let inner = outbox.inner.lock();
    assert!(inner.entries.len() < 500);
    assert!(inner.bytes <= MAX_BYTES);
    assert!(inner.lost_capacity > 0);
    assert_eq!(
        inner
            .entries
            .front()
            .unwrap()
            .report
            .history
            .sample
            .sequence,
        2
    );
}

fn advance(mut report: EvidenceReport, sequence: u64) -> EvidenceReport {
    report.history.failures = report.history.failures.saturating_add(1);
    report.history.latest = Some(Box::new(rally_point_proto::control::EvidenceFailure {
        admission: report.history.admission.clone(),
        sample: EvidenceObservation {
            sequence,
            sample_id: sequence,
            ..report.history.sample.clone()
        },
        observed_at_ms: sequence,
    }));
    report
}

#[test]
fn updates_coalesce_preserve_retry_floor_and_require_exact_latest_receipt() {
    let outbox = EvidenceOutbox::default();
    let now = Instant::now();
    let first = report(2);
    outbox.insert(first.clone(), now);
    assert_eq!(outbox.reports(now, 16), vec![first.clone()]);
    let second = advance(first.clone(), 3);
    outbox.insert(second.clone(), now + RETRY / 2);
    assert_eq!(outbox.inner.lock().entries.len(), 1);
    assert!(outbox.reports(now + RETRY / 2, 16).is_empty());
    outbox.acknowledge(&first.receipt());
    assert!(outbox.contains(&second.receipt(), now + RETRY / 2));
    assert_eq!(outbox.reports(now + RETRY, 16), vec![second.clone()]);
    outbox.acknowledge(&second.receipt());
    assert_eq!(outbox.inner.lock().bytes, 0);
}

#[test]
fn a_new_failure_refreshes_expiry_and_recreates_an_expired_summary() {
    let outbox = EvidenceOutbox::default();
    let now = Instant::now();
    let first = report(2);
    outbox.insert(first.clone(), now);
    let second = advance(first, 3);
    outbox.insert(second.clone(), now + RETENTION / 2);
    assert_eq!(outbox.reports(now + RETENTION, 16), vec![second.clone()]);
    assert!(outbox.reports(now + RETENTION * 2, 16).is_empty());
    let third = advance(second, 4);
    outbox.insert(third.clone(), now + RETENTION * 2);
    assert_eq!(outbox.reports(now + RETENTION * 2, 16), vec![third]);
}

#[test]
fn byte_limited_update_preserves_deliverable_old_summary() {
    let outbox = EvidenceOutbox::default();
    let now = Instant::now();
    let first = report(2);
    outbox.insert(first.clone(), now);
    let previous_bytes = outbox.inner.lock().bytes;
    let mut oversized = advance(first.clone(), 3);
    oversized.tenant = first.tenant.clone();
    oversized.history.latest.as_mut().unwrap().admission.body =
        vec![1; rally_point_proto::handshake::MAX_EVIDENCE_BODY_LEN];
    // Reserve the remaining capacity as other entries without allocating it.
    outbox.inner.lock().bytes = MAX_BYTES;
    outbox.insert(oversized, now);
    assert!(outbox.contains(&first.receipt(), now));
    assert_eq!(outbox.inner.lock().lost_capacity, 1);
    outbox.inner.lock().bytes = previous_bytes;
    outbox.acknowledge(&first.receipt());
    assert_eq!(outbox.inner.lock().bytes, 0);
}

#[test]
fn saturated_count_still_advances_latest_and_fences_old_receipts() {
    let outbox = EvidenceOutbox::default();
    let now = Instant::now();
    let mut first = report(2);
    first.history.failures = u32::MAX;
    outbox.insert(first.clone(), now);
    let next = advance(first.clone(), 3);
    outbox.insert(next.clone(), now);
    outbox.acknowledge(&first.receipt());
    assert_eq!(outbox.reports(now, 16), vec![next]);
}
