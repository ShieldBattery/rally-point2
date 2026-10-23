use super::*;
use rally_point_proto::control::{EvidenceHistory, EvidenceObservation, EvidenceVerdict, TenantId};
use rally_point_proto::ids::{SessionId, SlotId};

fn report(sequence: u64) -> EvidenceReport {
    let admission = EvidenceObservation {
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
        session: SessionId(1),
        slot: SlotId(0),
        history: EvidenceHistory {
            sample: EvidenceObservation {
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
    for field in 0..7 {
        let mut wrong = exact.clone();
        match field {
            0 => wrong.tenant = TenantId("other".into()),
            1 => wrong.session = SessionId(2),
            2 => wrong.slot = SlotId(1),
            3 => wrong.assignment_revision += 1,
            4 => wrong.connection_id = [4; 32],
            5 => wrong.sample_id += 1,
            _ => wrong.sequence += 1,
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
