//! Schema versioning and migration, plus the small storage-adjacent helpers
//! every ledger method leans on: row parsing, the fail-closed clock read, the
//! token digest/compare, and the SQLite `INTEGER` <-> `u64` reinterpretation.
//! Grouped here because none of it is enrollment *policy* — `mod.rs` decides
//! what an enroll means; this file is just how a row gets in and out of SQLite.

use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use rally_point_proto::control::RegionId;
use rally_point_proto::ids::RelayId;
use rusqlite::Connection;

use super::{LedgerError, ProvisionedTask, RelayLedger};

/// How long a blocked writer waits for the database lock before erroring, rather
/// than failing instantly on transient contention.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The number of random bytes behind each minted enroll token, before encoding —
/// 256 bits, so a token is unguessable and its SHA-256 has no meaningful
/// collision risk.
pub(super) const TOKEN_BYTES: usize = 32;

/// The v1 schema, applied to a fresh database (one whose `user_version` is still 0)
/// and stamping it `user_version = 1`. Each later schema version is a separate
/// migration [`RelayLedger::open`] applies in order, keyed off the version it reads:
/// a fresh file runs every step up to the latest, while an existing file runs only
/// the steps past its recorded version, so its rows survive the upgrade.
/// `AUTOINCREMENT` on the primary key guarantees a retired id is never handed out
/// again, so a tombstone can never be shadowed by a freshly minted relay reusing the
/// number.
pub(super) const SCHEMA_V1: &str = "\
CREATE TABLE IF NOT EXISTS provisioned_relays (
  relay_id          INTEGER PRIMARY KEY AUTOINCREMENT,
  region            TEXT,
  token_hash        BLOB NOT NULL,
  token_expires_at  INTEGER NOT NULL,
  token_consumed_at INTEGER,
  cert_fingerprint  BLOB,
  task_arn          TEXT,
  -- JSON array of canonical IP strings the relay may enroll from; an empty or
  -- absent set gates nothing. A dual-stack task advertises a public IPv4 and an
  -- IPv6 and may open its control connection from either family, so the gate
  -- accepts any address in the set.
  expected_ips      TEXT,
  addrs             TEXT,
  launched_at       INTEGER NOT NULL,
  enrolled_at       INTEGER,
  retired_at        INTEGER
);
PRAGMA user_version = 1;";

/// The v2 migration: a backbone-RTT table keyed by canonical region pair, one value
/// per pair. Superseded by [`SCHEMA_V3`], which drops this table for a per-direction
/// one — but the step stays immutable so an existing v2 file migrates deterministically
/// and a fresh file's version chain is unbroken. Stamps `user_version = 2`.
pub(super) const SCHEMA_V2: &str = "\
CREATE TABLE IF NOT EXISTS region_pair_rtts (
  region_a    TEXT NOT NULL,
  region_b    TEXT NOT NULL,
  rtt_ms      INTEGER NOT NULL,
  measured_at INTEGER NOT NULL,
  PRIMARY KEY (region_a, region_b)
);
PRAGMA user_version = 2;";

/// The v3 migration: replaces the single-value-per-pair backbone-RTT table with a
/// per-direction one. `region_direction_rtts` holds one row per canonical region pair
/// (`region_a <= region_b`) per `origin` region that measured it, so the two ends of a
/// link — which measure genuinely different, persistently asymmetric paths — persist
/// side by side instead of overwriting each other. Upserted on the (pair, origin) key,
/// stamped with the Unix second recorded. It drops `region_pair_rtts` and stamps
/// `user_version = 3`.
///
/// The v2 rows are dropped, not migrated: a v2 row carries no origin, so which
/// direction it measured is unknowable and there is no honest way to place it in a
/// directional slot. The loss is momentary — every live relay re-reports its measured
/// medians on its next heartbeat (~10s), refilling the table within a beat — so
/// dropping is cheaper and truer than inventing an origin for a value.
///
/// On a fresh file the version chain runs v1 → v2 → v3 in order, so v2 creates
/// `region_pair_rtts` and v3 immediately drops it. That momentary create-then-drop is
/// intentional: each migration step stays immutable and self-contained, which is worth
/// far more than sparing a fresh file one redundant statement.
const SCHEMA_V3: &str = "\
CREATE TABLE IF NOT EXISTS region_direction_rtts (
  region_a    TEXT NOT NULL,
  region_b    TEXT NOT NULL,
  origin      TEXT NOT NULL,
  rtt_ms      INTEGER NOT NULL,
  measured_at INTEGER NOT NULL,
  PRIMARY KEY (region_a, region_b, origin)
);
DROP TABLE IF EXISTS region_pair_rtts;
PRAGMA user_version = 3;";

impl RelayLedger {
    /// Opens (creating if absent) the ledger database at `path`, migrating it forward
    /// to the current schema and leaving an already-current one untouched. Each schema
    /// step past the file's recorded `user_version` is applied in order, so a fresh
    /// file gets every table while an existing one gets only the additions and keeps
    /// its rows. Runs in WAL journal mode with a bounded busy timeout, so a reader
    /// never blocks the single writer and transient lock contention waits rather than
    /// erroring.
    pub fn open(path: &Path) -> Result<Self, LedgerError> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        // Apply each schema step whose version this file has not reached yet, in
        // order. Every step stamps its own `user_version`, so a fresh file (version 0)
        // runs all three and ends at 3, while an existing file runs only the steps past
        // its recorded version — preserving its provisioned-relay rows across the
        // upgrade.
        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version < 1 {
            conn.execute_batch(SCHEMA_V1)?;
        }
        if version < 2 {
            conn.execute_batch(SCHEMA_V2)?;
        }
        if version < 3 {
            conn.execute_batch(SCHEMA_V3)?;
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

/// Maps a `(relay_id, task_arn)` row to a [`ProvisionedTask`], shared by the
/// sweeps' queries so the id-reinterpretation and column order live in one place.
pub(super) fn row_to_provisioned_task(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ProvisionedTask> {
    Ok(ProvisionedTask {
        relay_id: RelayId(as_u64(row.get(0)?)),
        task_arn: row.get(1)?,
        region: row.get::<_, Option<String>>(2)?.map(RegionId),
    })
}

/// The columns [`RelayLedger::authorize_enroll_at`] reads for its decision.
pub(super) struct LedgerRow {
    pub(super) retired_at: Option<i64>,
    pub(super) cert_fingerprint: Option<Vec<u8>>,
    pub(super) token_hash: Vec<u8>,
    pub(super) token_expires_at: i64,
    pub(super) expected_ips: Option<String>,
    pub(super) launched_at: i64,
}

/// Parses the stored expected-peer-IP set — a JSON array of canonical IP strings,
/// or an absent column — into the addresses a relay may enroll from. Both an
/// absent column and an empty array yield an empty set, which gates nothing.
pub(super) fn parse_expected_ips(stored: Option<&str>) -> Result<Vec<IpAddr>, LedgerError> {
    let Some(json) = stored else {
        return Ok(Vec::new());
    };
    let strings: Vec<String> = serde_json::from_str(json)?;
    let ips = strings
        .iter()
        .map(|s| s.parse::<IpAddr>())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ips)
}

/// The current Unix time in seconds, **failing closed**: a pre-epoch or errored
/// system clock yields `u64::MAX`, so any expiry comparison against it reads as
/// "expired" and refuses rather than admitting a token whose age cannot be
/// trusted.
pub(super) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

/// The SHA-256 digest of `bytes` — the form the ledger stores a token in and
/// compares a presented token against, so the token plaintext never lands on
/// disk.
pub(super) fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
    out
}

/// Constant-time equality over two byte slices, so a token or fingerprint
/// comparison leaks no timing signal that would let it be probed a byte at a
/// time. A length mismatch short-circuits (already a non-match); equal-length
/// inputs are compared with no data-dependent branch.
pub(super) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Reinterprets a `u64` as SQLite's signed `INTEGER`. Relay ids and Unix-second
/// timestamps stay well inside `i64`'s positive range, and the round trip is
/// bit-exact, so a value written this way reads back identical via [`as_u64`].
pub(super) fn as_i64(value: u64) -> i64 {
    value as i64
}

/// The inverse of [`as_i64`]: reinterprets a stored SQLite `INTEGER` as the
/// `u64` it was written from.
pub(super) fn as_u64(value: i64) -> u64 {
    value as u64
}
