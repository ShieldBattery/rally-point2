//! Reconcile-sweep query tests (launching count, expired-launching,
//! bound-unretired, referenced task ARNs, per-id task lookup), the
//! per-direction RTT store, and schema-migration tests (fresh file, v1 -> v3,
//! v2 -> v3) that a provisioned relay's row survives the upgrade.

use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

/// A region id for the launching-count tests.
fn region(name: &str) -> RegionId {
    RegionId(name.to_owned())
}

#[test]
fn count_launching_counts_only_unretired_unbound_unexpired_in_region() {
    let ledger = ledger();
    let east = region("us-east");
    let west = region("us-west");

    // Two launching ids in us-east, one in us-west, one untagged.
    let a = ledger.mint_at(1_000, Some(&east), DAY).unwrap();
    let _b = ledger.mint_at(1_000, Some(&east), DAY).unwrap();
    let _c = ledger.mint_at(1_000, Some(&west), DAY).unwrap();
    let _d = ledger.mint_at(1_000, None, DAY).unwrap();

    assert_eq!(ledger.count_launching(Some(&east), 1_100).unwrap(), 2);
    assert_eq!(ledger.count_launching(Some(&west), 1_100).unwrap(), 1);
    assert_eq!(ledger.count_launching(None, 1_100).unwrap(), 1);

    // Binding `a` (a first enroll) drops it from the launching count.
    ledger
        .authorize_enroll_at(1_050, a.relay_id, fingerprint(0x01), Some(&a.token), None)
        .unwrap();
    assert_eq!(
        ledger.count_launching(Some(&east), 1_100).unwrap(),
        1,
        "a bound id no longer counts as launching",
    );

    // Retiring one of the remaining launching ids drops it too.
    ledger.retire(_b.relay_id).unwrap();
    assert_eq!(
        ledger.count_launching(Some(&east), 1_100).unwrap(),
        0,
        "a retired id no longer counts as launching",
    );
}

#[test]
fn count_launching_excludes_an_expired_token() {
    let ledger = ledger();
    let east = region("us-east");
    // A 10-second token minted at t=1000 expires at 1010.
    ledger
        .mint_at(1_000, Some(&east), Duration::from_secs(10))
        .unwrap();
    // Still counted while unexpired…
    assert_eq!(ledger.count_launching(Some(&east), 1_005).unwrap(), 1);
    // …and excluded once its token has expired (the launch-deadline sweep's
    // concern instead).
    assert_eq!(ledger.count_launching(Some(&east), 2_000).unwrap(), 0);
}

#[test]
fn expired_launching_returns_only_past_deadline_unbound_ids_with_tasks() {
    let ledger = ledger();
    // Two short tokens (expire at 1010) and one long token (a day).
    let a = ledger
        .mint_at(1_000, None, Duration::from_secs(10))
        .unwrap();
    let b = ledger
        .mint_at(1_000, None, Duration::from_secs(10))
        .unwrap();
    let _c = ledger.mint_at(1_000, None, DAY).unwrap();
    ledger.record_task(a.relay_id, "task/a", &[], &[]).unwrap();

    // At t=2000 both short tokens have expired; the long one has not.
    let mut expired = ledger.expired_launching(2_000).unwrap();
    expired.sort_by_key(|t| t.relay_id.0);
    assert_eq!(expired.len(), 2);
    assert_eq!(expired[0].relay_id, a.relay_id);
    assert_eq!(expired[0].task_arn.as_deref(), Some("task/a"));
    assert_eq!(expired[1].relay_id, b.relay_id);
    assert_eq!(expired[1].task_arn, None, "b never had a task recorded");

    // A bound id, even past the token expiry, is never "launching".
    ledger
        .authorize_enroll_at(1_005, a.relay_id, fingerprint(0x01), Some(&a.token), None)
        .unwrap();
    let after_bind = ledger.expired_launching(2_000).unwrap();
    assert_eq!(
        after_bind
            .iter()
            .filter(|t| t.relay_id == a.relay_id)
            .count(),
        0,
        "binding `a` removes it from the expired-launching set",
    );
}

#[test]
fn bound_unretired_lists_bound_ids_and_omits_retired_and_launching() {
    let ledger = ledger();
    let a = ledger.mint_at(1_000, None, DAY).unwrap();
    let b = ledger.mint_at(1_000, None, DAY).unwrap();
    let _launching = ledger.mint_at(1_000, None, DAY).unwrap();

    // Bind both a and b; record a task for a; retire b.
    ledger
        .authorize_enroll_at(1_010, a.relay_id, fingerprint(0xA1), Some(&a.token), None)
        .unwrap();
    ledger.record_task(a.relay_id, "task/a", &[], &[]).unwrap();
    ledger
        .authorize_enroll_at(1_010, b.relay_id, fingerprint(0xB1), Some(&b.token), None)
        .unwrap();
    ledger.retire(b.relay_id).unwrap();

    let bound = ledger.bound_unretired().unwrap();
    assert_eq!(bound.len(), 1, "only the bound, unretired id is listed");
    assert_eq!(bound[0].relay_id, a.relay_id);
    assert_eq!(bound[0].task_arn.as_deref(), Some("task/a"));
}

#[test]
fn referenced_task_arns_lists_unretired_recorded_tasks_only() {
    let ledger = ledger();
    let a = ledger.mint_at(1_000, None, DAY).unwrap();
    let b = ledger.mint_at(1_000, None, DAY).unwrap();
    let _no_task = ledger.mint_at(1_000, None, DAY).unwrap();
    ledger.record_task(a.relay_id, "task/a", &[], &[]).unwrap();
    ledger.record_task(b.relay_id, "task/b", &[], &[]).unwrap();
    ledger.retire(b.relay_id).unwrap();

    let mut arns = ledger.referenced_task_arns().unwrap();
    arns.sort();
    assert_eq!(
        arns,
        vec!["task/a".to_owned()],
        "a retired id's task is no longer referenced; an id with no task contributes none",
    );
}

#[test]
fn task_arn_returns_the_recorded_task_or_none() {
    let ledger = ledger();
    let a = ledger.mint_at(1_000, None, DAY).unwrap();
    assert_eq!(ledger.task_arn(a.relay_id).unwrap(), None);
    ledger.record_task(a.relay_id, "task/a", &[], &[]).unwrap();
    assert_eq!(
        ledger.task_arn(a.relay_id).unwrap(),
        Some("task/a".to_owned())
    );
    assert_eq!(
        ledger.task_arn(RelayId(9999)).unwrap(),
        None,
        "an unknown id has no recorded task",
    );
}

#[test]
fn record_direction_rtt_round_trips() {
    let ledger = ledger();
    ledger
        .record_direction_rtt(
            &region("eu-west"),
            &region("us-east"),
            &region("us-east"),
            87,
            1_752_555_555,
        )
        .unwrap();

    let rows = ledger.direction_rtts().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].a, region("eu-west"));
    assert_eq!(rows[0].b, region("us-east"));
    assert_eq!(rows[0].origin, region("us-east"));
    assert_eq!(rows[0].rtt_ms, 87);
    assert_eq!(rows[0].measured_at, 1_752_555_555);
}

#[test]
fn record_direction_rtt_upserts_on_pair_and_origin() {
    // The two ends of a link are two rows (one per origin); re-reporting one
    // direction upserts that row rather than inserting a duplicate. The change-only
    // write-through relies on one row per (pair, origin).
    let ledger = ledger();
    ledger
        .record_direction_rtt(&region("a"), &region("b"), &region("a"), 50, 10)
        .unwrap();
    ledger
        .record_direction_rtt(&region("a"), &region("b"), &region("b"), 60, 11)
        .unwrap();
    assert_eq!(
        ledger.direction_rtts().unwrap().len(),
        2,
        "each direction of the pair is its own row",
    );

    // Re-report the a-origin direction: it upserts, leaving two rows.
    ledger
        .record_direction_rtt(&region("a"), &region("b"), &region("a"), 75, 20)
        .unwrap();
    let rows = ledger.direction_rtts().unwrap();
    assert_eq!(rows.len(), 2, "the re-report upserts, not inserts");
    let from_a = rows
        .iter()
        .find(|r| r.origin == region("a"))
        .expect("the a-origin row is present");
    assert_eq!(
        from_a.rtt_ms, 75,
        "the later report for that direction wins"
    );
    assert_eq!(from_a.measured_at, 20);
    let from_b = rows
        .iter()
        .find(|r| r.origin == region("b"))
        .expect("the b-origin row is untouched");
    assert_eq!(from_b.rtt_ms, 60, "the other direction is left alone");
}

#[test]
fn a_fresh_ledger_stamps_the_current_schema_version() {
    let ledger = ledger();
    let version: i64 = ledger
        .conn
        .lock()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        version, 3,
        "a fresh file is created at the latest schema version"
    );
    // The current backbone-RTT table exists and is usable on a fresh file.
    ledger
        .record_direction_rtt(&region("a"), &region("b"), &region("a"), 1, 1)
        .unwrap();
    assert_eq!(ledger.direction_rtts().unwrap().len(), 1);
}

#[test]
fn a_v1_file_upgrades_to_v3_and_keeps_its_provisioned_relays() {
    // A database created at schema v1 (before any backbone-RTT table existed) is
    // opened by this build: the version chain runs straight through to v3, adding
    // the per-direction table while every v1 provisioned-relay row survives.
    let path = temp_db_path();

    // Stand up a v1-only file: the v1 schema plus one provisioned-relay row.
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute(
            "INSERT INTO provisioned_relays (token_hash, token_expires_at, launched_at)
             VALUES (?1, ?2, ?3)",
            params![[0u8; 32].as_slice(), 9_999_i64, 1_000_i64],
        )
        .unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1, "the hand-built file is at v1");
    }

    // Open through the ledger: it migrates the file straight through to v3.
    let ledger = RelayLedger::open(&path).unwrap();
    let version: i64 = ledger
        .conn
        .lock()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 3, "a v1 file migrates straight through to v3");

    // The v1 provisioned-relay row survived the upgrade.
    let relays: i64 = ledger
        .conn
        .lock()
        .query_row("SELECT COUNT(*) FROM provisioned_relays", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        relays, 1,
        "the v1 provisioned-relay row survives the migration"
    );

    // The per-direction backbone-RTT table exists and is usable.
    ledger
        .record_direction_rtt(&region("a"), &region("b"), &region("a"), 42, 7)
        .unwrap();
    assert_eq!(ledger.direction_rtts().unwrap().len(), 1);

    // Drop the connection before removing the file: Windows refuses to delete a
    // file an open handle still holds.
    drop(ledger);
    cleanup_db(&path);
}

#[test]
fn a_v2_file_upgrades_to_v3_dropping_the_pair_table_and_keeping_provisioned_relays() {
    // A database created at schema v2 (the single-value-per-pair table) is opened by
    // this build: the v3 migration drops `region_pair_rtts` and adds the
    // per-direction table, while every provisioned-relay row survives.
    let path = temp_db_path();

    // Stand up a v2 file: v1 + v2 schema, a provisioned-relay row, and a v2 pair row
    // (which carries no origin and so cannot be honestly migrated).
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(SCHEMA_V2).unwrap();
        conn.execute(
            "INSERT INTO provisioned_relays (token_hash, token_expires_at, launched_at)
             VALUES (?1, ?2, ?3)",
            params![[0u8; 32].as_slice(), 9_999_i64, 1_000_i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO region_pair_rtts (region_a, region_b, rtt_ms, measured_at)
             VALUES ('a', 'b', 50, 10)",
            [],
        )
        .unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 2, "the hand-built file is at v2");
    }

    // Open through the ledger: it migrates the file forward to v3.
    let ledger = RelayLedger::open(&path).unwrap();
    let version: i64 = ledger
        .conn
        .lock()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 3, "the file is migrated to v3");

    // The v2 single-value pair table is gone.
    let old_tables: i64 = ledger
        .conn
        .lock()
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'region_pair_rtts'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(old_tables, 0, "the v2 region_pair_rtts table is dropped");

    // The provisioned-relay row survived the migration.
    let relays: i64 = ledger
        .conn
        .lock()
        .query_row("SELECT COUNT(*) FROM provisioned_relays", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        relays, 1,
        "the provisioned-relay rows survive the v3 migration",
    );

    // The per-direction table exists and is usable.
    ledger
        .record_direction_rtt(&region("a"), &region("b"), &region("a"), 42, 7)
        .unwrap();
    assert_eq!(ledger.direction_rtts().unwrap().len(), 1);

    drop(ledger);
    cleanup_db(&path);
}

/// A unique temp-file path for the migration test, which needs a real file that
/// survives a close and reopen (an in-memory database cannot, since each open is a
/// fresh database).
fn temp_db_path() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "rp2-ledger-migration-{}-{nanos}.sqlite",
        std::process::id()
    ));
    path
}

/// Best-effort removal of a temp database and its WAL sidecars.
fn cleanup_db(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
}
