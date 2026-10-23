use super::*;

fn assignment(slot: u8, revision: u64, expires_at: u64) -> RetiredAssignment {
    RetiredAssignment {
        slot: SlotId(slot),
        relay: RelayId(1),
        boot_id: 7,
        revision,
        expires_at,
    }
}

#[test]
fn retirement_expires_and_evicts_oldest_per_slot_then_per_session() {
    let mut refs = SessionRefs {
        retired_evidence_assignments: (1..=6).map(|v| assignment(0, v, 1000)).collect(),
        ..Default::default()
    };
    refs.prune_retired_evidence_assignments(500);
    assert_eq!(
        refs.retired_evidence_assignments
            .iter()
            .map(|e| e.revision)
            .collect::<Vec<_>>(),
        vec![3, 4, 5, 6]
    );
    refs.retired_evidence_assignments
        .extend((1..=16).flat_map(|slot| (1..=4).map(move |v| assignment(slot, v, 1000))));
    refs.prune_retired_evidence_assignments(500);
    assert_eq!(refs.retired_evidence_assignments.len(), 64);
    assert!(
        refs.retired_evidence_assignments
            .iter()
            .all(|e| e.slot != SlotId(0))
    );
    refs.prune_retired_evidence_assignments(1000);
    assert!(refs.retired_evidence_assignments.is_empty());
}

#[test]
fn restore_clock_correction_bounds_remaining_grace() {
    let mut refs = SessionRefs {
        retired_evidence_assignments: vec![assignment(0, 1, u64::MAX), assignment(1, 1, 10)],
        ..Default::default()
    };
    refs.prune_retired_evidence_assignments(100);
    assert_eq!(
        refs.retired_evidence_assignments,
        vec![assignment(0, 1, 700)]
    );
}

#[test]
fn closed_assignment_receipts_are_bounded_and_expire() {
    let tenant = TenantId("test".into());
    let refs = SessionRefs {
        periodic_evidence: true,
        homes: [(SlotId(0), RelayId(1))].into_iter().collect(),
        evidence_home_boots: [(SlotId(0), 7)].into_iter().collect(),
        evidence_assignments: [(SlotId(0), 1)].into_iter().collect(),
        ..Default::default()
    };
    let mut closed = ClosedEvidenceAssignments::default();
    for session in 0..4097 {
        closed.retain_session(&tenant, SessionId(session), &refs);
    }
    assert_eq!(closed.entries.len(), 4096);
    assert_eq!(closed.assignments, 4096);
    assert_eq!(closed.entries.front().unwrap().session, SessionId(1));
    closed.expire(std::time::Instant::now() + std::time::Duration::from_secs(601));
    assert!(closed.entries.is_empty());
    assert_eq!(closed.assignments, 0);
}
