//! A coordinator lifetime is a `SessionSetup` + `Lifecycle` pair over one ledger;
//! each test runs a session through one, flushes, and restores a fresh pair from
//! the same ledger — what a restarted process does at startup.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use rally_point_proto::control::{DepartureKind, SessionRequest, TenantId};
use rally_point_proto::ids::{RelayId, SessionId, SlotId};
use rally_point_proto::token::ExpiresAt;

use super::*;
use crate::ledger::RelayLedger;
use crate::lifecycle::Lifecycle;
use crate::registry::{self, BootLineage, RelayRegistry};
use crate::session::{self, SessionSetup};
use crate::test_support::{fleet, request, tenant_store, tid, two_players};

fn ledger() -> Arc<RelayLedger> {
    Arc::new(RelayLedger::open(Path::new(":memory:")).expect("an in-memory ledger opens"))
}

/// One coordinator lifetime: its setup, lifecycle, and store.
struct Lifetime {
    setup: SessionSetup,
    lifecycle: Lifecycle,
    store: SessionStore,
}

impl Lifetime {
    /// The first lifetime: relays 1 and 2 enrolled, nothing stored yet.
    fn first(ledger: &Arc<RelayLedger>) -> Self {
        let (setup, _) = fleet(&[(1, 9001, None, false), (2, 9002, None, false)]);
        Self::over(ledger, setup).0
    }

    /// A restarted lifetime: an empty registry (no relay has reconnected yet) and
    /// whatever the ledger holds restored into it.
    fn restarted(ledger: &Arc<RelayLedger>) -> (Self, RestoreSummary) {
        Self::over(
            ledger,
            SessionSetup::new(RelayRegistry::new(), tenant_store()),
        )
    }

    fn over(ledger: &Arc<RelayLedger>, setup: SessionSetup) -> (Self, RestoreSummary) {
        let lifecycle = Lifecycle::new(setup.clone());
        let (store, summary) =
            SessionStore::restore(ledger.clone(), setup.clone(), lifecycle.clone()).unwrap();
        (
            Self {
                setup,
                lifecycle,
                store,
            },
            summary,
        )
    }

    /// Creates a session the way the create handler does: commit, then register.
    fn create(&self, request: SessionRequest) -> SessionId {
        let created = session::create_session(&self.setup, request, ExpiresAt(u64::MAX)).unwrap();
        let session = created.response.session;
        self.register(session);
        session
    }

    fn register(&self, session: SessionId) {
        self.lifecycle.register_session(
            tid(),
            session,
            self.setup.serving_relays(&tid(), session),
            [SlotId(0), SlotId(1)].into_iter().collect(),
            HashSet::new(),
        );
    }

    /// Every relay's descriptor set, for comparing two lifetimes' outboxes.
    fn outbox(&self) -> Vec<(RelayId, Vec<rally_point_proto::control::SessionDescriptor>)> {
        let mut sets = self.setup.descriptors().export_all();
        sets.sort_by_key(|(relay, _)| relay.0);
        sets
    }
}

fn stored_rows(ledger: &RelayLedger) -> usize {
    ledger.session_records().unwrap().len()
}

#[tokio::test]
async fn a_restart_restores_membership_descriptors_and_liveness() {
    let ledger = ledger();
    let first = Lifetime::first(&ledger);
    let session = first.create(request(two_players()));
    first.store.flush().unwrap();

    let (restarted, summary) = Lifetime::restarted(&ledger);
    assert_eq!(summary.restored, 1);
    assert_eq!(
        restarted.setup.serving_relays(&tid(), session),
        first.setup.serving_relays(&tid(), session),
    );
    assert_eq!(
        restarted.outbox(),
        first.outbox(),
        "every relay is re-synced to exactly the set it held",
    );
    assert_eq!(
        session::session_refs(&restarted.setup, &tid(), session),
        session::session_refs(&first.setup, &tid(), session),
    );
    assert!(restarted.lifecycle.is_alive(&tid(), session));
}

#[tokio::test]
async fn a_restart_keeps_accounting_departures_and_load_state() {
    let ledger = ledger();
    let first = Lifetime::first(&ledger);
    let session = first.create(request(two_players()));
    first.lifecycle.on_slot_connected(tid(), session, SlotId(0));
    first.lifecycle.on_slot_connected(tid(), session, SlotId(1));
    first.lifecycle.on_slot_started(tid(), session, SlotId(0));
    first.lifecycle.on_session_started(tid(), session, 1_234);
    first.lifecycle.on_departure(
        tid(),
        session,
        SlotId(1),
        DepartureKind::Left,
        Some(42),
        false,
    );
    first.store.flush().unwrap();

    let (restarted, _) = Lifetime::restarted(&ledger);
    assert_eq!(
        restarted.lifecycle.load_state(&tid(), session),
        first.lifecycle.load_state(&tid(), session),
        "the load record a tenant pulls reads the same across the restart",
    );
    assert_eq!(
        restarted.lifecycle.departed_slots(&tid(), session),
        first.lifecycle.departed_slots(&tid(), session),
        "a re-home after the restart still seeds the decided departure",
    );
    assert_eq!(
        restarted.lifecycle.export_facts().get(&(tid(), session)),
        first.lifecycle.export_facts().get(&(tid(), session)),
    );
}

#[tokio::test]
async fn a_create_retried_across_a_restart_replays_its_response() {
    let ledger = ledger();
    let first = Lifetime::first(&ledger);
    let retried = SessionRequest {
        external_id: Some("game-7".to_owned()),
        ..request(two_players())
    };
    let original = session::create_session(&first.setup, retried.clone(), ExpiresAt(u64::MAX))
        .unwrap()
        .response;
    first.register(original.session);
    first.store.flush().unwrap();

    let (restarted, _) = Lifetime::restarted(&ledger);
    let replay = session::create_session(&restarted.setup, retried, ExpiresAt(u64::MAX)).unwrap();
    assert!(
        replay.replayed,
        "the retry is a replay, not a second session"
    );
    assert_eq!(replay.response, original);
}

#[tokio::test]
async fn a_closed_session_is_deleted_and_not_restored() {
    let ledger = ledger();
    let first = Lifetime::first(&ledger);
    let session = first.create(request(two_players()));
    first.store.flush().unwrap();
    assert_eq!(stored_rows(&ledger), 1);

    first.setup.retire_session(&tid(), session);
    first.store.flush().unwrap();
    assert_eq!(stored_rows(&ledger), 0);

    let (restarted, summary) = Lifetime::restarted(&ledger);
    assert_eq!(summary.restored, 0);
    assert!(!restarted.lifecycle.is_alive(&tid(), session));
    assert!(restarted.outbox().is_empty());
}

#[tokio::test]
async fn a_session_is_persisted_only_once_its_lifecycle_registers() {
    // Between a create's commit and its lifecycle registration, the setup half
    // exists alone; persisting it would restore a session with no accounting.
    let ledger = ledger();
    let first = Lifetime::first(&ledger);
    let created =
        session::create_session(&first.setup, request(two_players()), ExpiresAt(u64::MAX)).unwrap();
    first.store.flush().unwrap();
    assert_eq!(stored_rows(&ledger), 0);

    first.register(created.response.session);
    first.store.flush().unwrap();
    assert_eq!(stored_rows(&ledger), 1);
}

#[tokio::test]
async fn an_unchanged_flush_writes_nothing() {
    let ledger = ledger();
    let first = Lifetime::first(&ledger);
    first.create(request(two_players()));
    first.store.flush().unwrap();
    let before = ledger.session_records().unwrap();

    // Replace the stored record behind the store's back: an unchanged capture
    // must not rewrite it, which is what keeps an idle tick write-free.
    let marker = StoredSession {
        record: "marker".to_owned(),
        ..before[0].clone()
    };
    ledger
        .write_session_state(&SessionStateWrite {
            upserts: vec![marker.clone()],
            ..SessionStateWrite::default()
        })
        .unwrap();
    first.store.flush().unwrap();
    assert_eq!(ledger.session_records().unwrap(), vec![marker]);
}

#[tokio::test]
async fn relay_boot_ids_survive_a_restart() {
    let ledger = ledger();
    let first = Lifetime::first(&ledger);
    registry::note_boot_id(first.setup.registry(), RelayId(1), Some(7));
    registry::note_boot_id(first.setup.registry(), RelayId(2), Some(9));
    first.store.flush().unwrap();

    // Without the restored memory, a first enroll after the restart would read as
    // continuous whatever its boot id — hiding a relay that restarted meanwhile.
    let (restarted, _) = Lifetime::restarted(&ledger);
    let registry = restarted.setup.registry();
    assert_eq!(
        registry::note_boot_id(registry, RelayId(1), Some(7)),
        BootLineage::Continuous,
    );
    assert_eq!(
        registry::note_boot_id(registry, RelayId(2), Some(10)),
        BootLineage::Broken,
    );
}

#[tokio::test]
async fn an_unreadable_record_refuses_the_restore_and_stays_stored() {
    // Restoring around it would re-sync that game's relays to a set without it,
    // ending the game — so the restore refuses and the record is kept intact.
    let ledger = ledger();
    let first = Lifetime::first(&ledger);
    let readable = first.create(request(two_players()));
    first.store.flush().unwrap();
    ledger
        .write_session_state(&SessionStateWrite {
            upserts: vec![StoredSession {
                tenant: TenantId("sb-test".to_owned()),
                session: SessionId(5),
                record: "{not json".to_owned(),
            }],
            ..SessionStateWrite::default()
        })
        .unwrap();

    let setup = SessionSetup::new(RelayRegistry::new(), tenant_store());
    let lifecycle = Lifecycle::new(setup.clone());
    let refused = SessionStore::restore(ledger.clone(), setup.clone(), lifecycle.clone());
    assert!(matches!(
        refused,
        Err(RestoreError::Unreadable {
            session: SessionId(5),
            ..
        })
    ));
    assert!(
        !lifecycle.is_alive(&tid(), readable),
        "a refused restore restores nothing, not a partial set",
    );
    assert_eq!(stored_rows(&ledger), 2, "both records are left in place");
}

#[tokio::test]
async fn a_flush_reads_facts_and_boot_ids_inside_one_assignment_hold() {
    // Enrollment records a relay's new boot id and clears the completeness claim
    // of the sessions it serves inside one hold of the assignment lock. A capture
    // that let go of the lock between reading the claim and the boot id could pair
    // the old claim with the new boot id; restored, that boot id matches on the
    // relay's next enroll and the stale claim is never cleared. So the lock must
    // still be held at the exact point between the two reads.
    let ledger = ledger();
    let first = Lifetime::first(&ledger);
    first.create(request(two_players()));

    let held = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (setup, seen) = (first.setup.clone(), held.clone());
    *first.store.capture_seam.lock() = Some(Box::new(move || {
        seen.store(
            setup.assignment_is_locked(),
            std::sync::atomic::Ordering::SeqCst,
        );
    }));
    first.store.flush().unwrap();
    assert!(held.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test]
async fn drain_webhooks_returns_at_once_with_nothing_queued() {
    let (setup, _) = fleet(&[(1, 9001, None, false)]);
    let lifecycle = Lifecycle::new(setup);
    let left = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        lifecycle.drain_webhooks(std::time::Duration::from_secs(30)),
    )
    .await
    .expect("an empty drain does not wait out its deadline");
    assert_eq!(left, 0);
}
