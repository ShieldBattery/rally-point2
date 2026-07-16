//! The provisioned-relay enrollment ledger: a small local SQLite store of the
//! relay identities this coordinator has minted, the one-time tokens that
//! authorize their first enroll, and the certificate fingerprint each id is
//! bound to.
//!
//! A relay id passes through three states and never leaves the last:
//!
//! - **launching** — [`mint`](RelayLedger::mint) records a fresh id with a
//!   one-time token (only the token's SHA-256 is stored; the token itself is
//!   handed to the launched relay and never written down) and no bound
//!   certificate.
//! - **live** — the relay's first enroll presents the token; the token is
//!   consumed and the id is bound to the certificate the enroll `Hello` carried,
//!   in one atomic step ([`authorize_enroll`](RelayLedger::authorize_enroll)).
//!   Every later reconnect must re-present that same certificate; a re-presented
//!   token is ignored, and no other certificate is ever accepted for the id.
//! - **retired** — [`retire`](RelayLedger::retire) sets a tombstone that refuses
//!   the id forever.
//!
//! This closes the takeover an offline-but-claimable id would otherwise leave: a
//! bootstrap-secret holder cannot enroll under a minted id it holds no token for,
//! cannot rebind a live id to a different certificate, and cannot revive a
//! retired one. A coordinator that runs no ledger keeps the dev / loopback
//! posture — the id claim in a `Hello` is accepted as presented.
//!
//! # Concurrency
//!
//! One coordinator process owns the file; a single [`rusqlite::Connection`]
//! behind a [`parking_lot::Mutex`] serializes every access. Each method is a
//! short, synchronous SQLite call — the mutex is never held across an `.await` —
//! so async call sites take the microsecond block directly rather than hopping
//! to a blocking pool. The consume-and-bind step is additionally guarded by an
//! atomic `UPDATE ... WHERE token_consumed_at IS NULL`, so two enrolls racing on
//! one token bind at most one certificate even though the mutex already
//! serializes them — the guard is what makes the property hold independent of the
//! lock.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use parking_lot::Mutex;
use rally_point_proto::control::RegionId;
use rally_point_proto::ids::RelayId;
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{Connection, OptionalExtension, params};

use crate::pair_rtts::DirectionRttRow;

/// How long a blocked writer waits for the database lock before erroring, rather
/// than failing instantly on transient contention.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The number of random bytes behind each minted enroll token, before encoding —
/// 256 bits, so a token is unguessable and its SHA-256 has no meaningful
/// collision risk.
const TOKEN_BYTES: usize = 32;

/// The v1 schema, applied to a fresh database (one whose `user_version` is still 0)
/// and stamping it `user_version = 1`. Each later schema version is a separate
/// migration [`RelayLedger::open`] applies in order, keyed off the version it reads:
/// a fresh file runs every step up to the latest, while an existing file runs only
/// the steps past its recorded version, so its rows survive the upgrade.
/// `AUTOINCREMENT` on the primary key guarantees a retired id is never handed out
/// again, so a tombstone can never be shadowed by a freshly minted relay reusing the
/// number.
const SCHEMA_V1: &str = "\
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
const SCHEMA_V2: &str = "\
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

/// A failure operating the ledger's storage — distinct from an
/// [`EnrollRefusal`], which is a *decision* the ledger reached, not a fault.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// The underlying SQLite call failed.
    #[error("relay ledger database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The secure RNG could not produce a token's random bytes.
    #[error("generating a relay enroll token failed")]
    Rng,
    /// The system clock is unusable (pre-epoch or errored), so a token expiry
    /// computed from it could never be enforced. Minting refuses rather than
    /// recording an expiry it cannot trust.
    #[error("system clock is unusable; refusing to mint an enroll token")]
    Clock,
    /// Serializing or deserializing the JSON advertise-address set failed.
    #[error("relay ledger advertise-address JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// A stored advertise address did not parse back to a `SocketAddr` — a
    /// corrupted row, since the ledger only ever writes canonical addresses.
    #[error("a stored relay advertise address failed to parse: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
}

/// A freshly minted relay identity: the coordinator-assigned id and the one-time
/// token whose plaintext lives only here, in this return value. The caller hands
/// both to the launched relay (id + token in its environment); the ledger keeps
/// only the token's SHA-256.
#[derive(Debug, Clone)]
pub struct Minted {
    /// The newly assigned relay id.
    pub relay_id: RelayId,
    /// The one-time enroll token, in the clear. Never stored; presented once by
    /// the relay at first enroll.
    pub token: String,
}

/// A ledger row's relay id paired with the provisioner task recorded for it (if
/// any). The reconcile sweeps read these: an expired launching id, a bound id
/// whose relay is gone, or an id whose task must be stopped as it is retired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProvisionedTask {
    /// The relay id the row minted.
    pub relay_id: RelayId,
    /// The provisioner task recorded for the id, or `None` if no task was ever
    /// recorded (an id that enrolled on its self-reported addresses).
    pub task_arn: Option<String>,
}

/// The ledger authorized an enroll — how it did so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorized {
    /// The relay's certificate was bound to its id for the first time: the
    /// one-time token was consumed and the fingerprint recorded.
    FirstEnroll,
    /// The relay re-presented the certificate already bound to its id — its own
    /// reconnect — authorized without consuming any token.
    Reenroll,
}

/// Why the ledger refused an enroll. Each variant is a distinct class the
/// coordinator logs for operators; on the wire they all collapse to one generic
/// refusal, so a caller cannot tell which id exists or whether a token was
/// near-valid.
#[derive(Debug, thiserror::Error)]
pub enum EnrollRefusal {
    /// No row for the claimed relay id — an id this ledger never minted.
    #[error("relay id is not present in the ledger")]
    UnknownId,
    /// The id carries a retirement tombstone; it is refused forever.
    #[error("relay id is retired")]
    Retired,
    /// The id records an expected peer address the connection did not come from
    /// (or the connection's peer address was unavailable). Applies to a first
    /// enroll and every reconnect.
    #[error("connecting peer address does not match the ledger's expected address for this id")]
    IpMismatch,
    /// The id is already bound to a different certificate than the one presented
    /// — a second relay colliding on a live id, not the bound relay reconnecting.
    #[error("presented certificate does not match the fingerprint bound to this relay id")]
    FingerprintMismatch,
    /// The id has no bound certificate yet and the enroll presented no token, so
    /// there is nothing to authorize a first bind.
    #[error("a first enroll for this relay id requires its one-time token")]
    TokenRequired,
    /// A token was presented for an unbound id but it did not match, had already
    /// been consumed, or had expired.
    #[error("enroll token is invalid, already consumed, or expired")]
    TokenInvalid,
    /// The ledger's storage failed while deciding — treated as a refusal so a
    /// storage fault fails closed rather than admitting an enroll.
    #[error("relay ledger storage error during enroll authorization: {0}")]
    Storage(#[from] LedgerError),
}

impl From<rusqlite::Error> for EnrollRefusal {
    fn from(error: rusqlite::Error) -> Self {
        EnrollRefusal::Storage(LedgerError::Sqlite(error))
    }
}

/// A persistent record of the relay identities this coordinator has minted, the
/// one-time tokens that authorize their first enroll, and the certificate
/// fingerprint each id is bound to. See the module docs for the id lifecycle and
/// the concurrency model.
pub struct RelayLedger {
    conn: Mutex<Connection>,
}

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

    /// Mints a fresh relay identity: assigns the next id, generates a one-time
    /// token, and records the id as launching (token unconsumed, certificate
    /// unbound) with the token expiring `token_ttl` from now. Returns the id and
    /// the token in the clear; only the token's SHA-256 is stored.
    pub fn mint(
        &self,
        region: Option<&RegionId>,
        token_ttl: Duration,
    ) -> Result<Minted, LedgerError> {
        self.mint_at(unix_now(), region, token_ttl)
    }

    /// [`mint`](Self::mint) with the launch instant supplied, so tests can pin
    /// the token's expiry deterministically.
    ///
    /// Fails closed on an unusable clock: `now` of `u64::MAX` (what
    /// [`unix_now`] yields pre-epoch or on error) would store an expiry that
    /// reads back as "never expires" — a token minted from a clock that cannot
    /// be trusted must not outlive every deadline, so it is not minted at all.
    pub(crate) fn mint_at(
        &self,
        now: u64,
        region: Option<&RegionId>,
        token_ttl: Duration,
    ) -> Result<Minted, LedgerError> {
        if now == u64::MAX {
            return Err(LedgerError::Clock);
        }
        let mut token_bytes = [0u8; TOKEN_BYTES];
        SystemRandom::new()
            .fill(&mut token_bytes)
            .map_err(|_| LedgerError::Rng)?;
        // URL-safe, unpadded base64: the token rides an environment variable to
        // the launched relay and back up a `Hello` field, so it must survive both
        // without escaping.
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
        let token_hash = sha256(token.as_bytes());
        let expires_at = now.saturating_add(token_ttl.as_secs());

        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO provisioned_relays (region, token_hash, token_expires_at, launched_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                region.map(|r| r.as_ref()),
                token_hash.as_slice(),
                as_i64(expires_at),
                as_i64(now),
            ],
        )?;
        let relay_id = RelayId(conn.last_insert_rowid() as u64);
        Ok(Minted { relay_id, token })
    }

    /// Decides whether a proof-of-possession-verified enroll may proceed for
    /// `relay_id`, presenting `cert_fingerprint` (the SHA-256 of the enroll
    /// certificate's DER, the same digest the registry computes), the enroll
    /// `token` if any, and the connecting `peer_ip` if the server records it.
    ///
    /// A first enroll consumes the id's one-time token and binds the fingerprint
    /// in one atomic step; a reconnect re-presents the bound fingerprint and needs
    /// no token. See [`EnrollRefusal`] for the refusal classes.
    pub fn authorize_enroll(
        &self,
        relay_id: RelayId,
        cert_fingerprint: [u8; 32],
        token: Option<&str>,
        peer_ip: Option<IpAddr>,
    ) -> Result<Authorized, EnrollRefusal> {
        self.authorize_enroll_at(unix_now(), relay_id, cert_fingerprint, token, peer_ip)
    }

    /// [`authorize_enroll`](Self::authorize_enroll) with the current time
    /// supplied, so a caller can pin token expiry and exercise the fail-closed
    /// broken-clock path deterministically.
    pub(crate) fn authorize_enroll_at(
        &self,
        now: u64,
        relay_id: RelayId,
        cert_fingerprint: [u8; 32],
        token: Option<&str>,
        peer_ip: Option<IpAddr>,
    ) -> Result<Authorized, EnrollRefusal> {
        let conn = self.conn.lock();
        let row = conn
            .query_row(
                "SELECT retired_at, cert_fingerprint, token_hash, token_expires_at,
                        token_consumed_at, expected_ips
                 FROM provisioned_relays WHERE relay_id = ?1",
                params![as_i64(relay_id.0)],
                |row| {
                    Ok(LedgerRow {
                        retired_at: row.get(0)?,
                        cert_fingerprint: row.get(1)?,
                        token_hash: row.get(2)?,
                        token_expires_at: row.get(3)?,
                        expected_ips: row.get(5)?,
                    })
                },
            )
            .optional()?;

        let Some(row) = row else {
            return Err(EnrollRefusal::UnknownId);
        };
        if row.retired_at.is_some() {
            return Err(EnrollRefusal::Retired);
        }
        // The expected-address gate applies to a first enroll AND every
        // reconnect, so it precedes the bound/unbound split. A relay may enroll
        // from any address in the recorded set; an empty or absent set gates
        // nothing, and a non-empty set still refuses a connection whose peer
        // address the server could not record. It presumes the coordinator is
        // directly exposed (the connection's transport-level peer address is the
        // relay's real one, not a reverse proxy's).
        let expected = parse_expected_ips(row.expected_ips.as_deref())?;
        if !expected.is_empty() {
            let matches = peer_ip.is_some_and(|ip| expected.contains(&ip));
            if !matches {
                return Err(EnrollRefusal::IpMismatch);
            }
        }

        match row.cert_fingerprint {
            // Bound already: this is a reconnect. The token (if any) is ignored;
            // only the certificate matters, and it must be the bound one.
            Some(bound) => {
                if constant_time_eq(&bound, &cert_fingerprint) {
                    Ok(Authorized::Reenroll)
                } else {
                    Err(EnrollRefusal::FingerprintMismatch)
                }
            }
            // Unbound: a first enroll, which the one-time token authorizes.
            None => {
                let Some(token) = token else {
                    return Err(EnrollRefusal::TokenRequired);
                };
                // Fail closed on a broken clock: `unix_now` is `u64::MAX` on a
                // pre-epoch or errored system clock, so a token whose age cannot
                // be trusted is refused rather than read as still valid.
                if now > as_u64(row.token_expires_at) {
                    return Err(EnrollRefusal::TokenInvalid);
                }
                let presented = sha256(token.as_bytes());
                // Constant-time digest comparison, so a near-miss token leaks no
                // timing signal. The atomic UPDATE re-checks the same hash under
                // the lock; this is the cheap constant-time gate in front of it.
                if !constant_time_eq(&presented, &row.token_hash) {
                    return Err(EnrollRefusal::TokenInvalid);
                }
                // Consume the token and bind the fingerprint in one statement,
                // gated on the token still being unconsumed. Two enrolls racing on
                // one token bind at most one certificate: the loser matches zero
                // rows and is refused.
                let affected = conn.execute(
                    "UPDATE provisioned_relays
                        SET token_consumed_at = ?1, cert_fingerprint = ?2, enrolled_at = ?1
                      WHERE relay_id = ?3 AND token_consumed_at IS NULL AND token_hash = ?4",
                    params![
                        as_i64(now),
                        cert_fingerprint.as_slice(),
                        as_i64(relay_id.0),
                        presented.as_slice(),
                    ],
                )?;
                if affected == 1 {
                    Ok(Authorized::FirstEnroll)
                } else {
                    Err(EnrollRefusal::TokenInvalid)
                }
            }
        }
    }

    /// Retires `relay_id`, setting a tombstone that refuses it forever.
    /// Idempotent: retiring an already-retired (or unknown) id is a harmless
    /// no-op that leaves the original tombstone in place.
    pub fn retire(&self, relay_id: RelayId) -> Result<(), LedgerError> {
        let now = unix_now();
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE provisioned_relays SET retired_at = ?1
              WHERE relay_id = ?2 AND retired_at IS NULL",
            params![as_i64(now), as_i64(relay_id.0)],
        )?;
        Ok(())
    }

    /// Records the launch-provisioner details for `relay_id`: the ECS task ARN it
    /// runs as, the set of peer addresses the coordinator should accept it
    /// enrolling from (any one of which matches), and the coordinator-resolved
    /// advertise-address set clients and peers reach it at. Both sets are stored
    /// as a JSON array of strings — canonical IPs for the expected set, `"ip:port"`
    /// for the advertise set. The advertise set later overrides a hello's
    /// self-reported addresses at enroll ([`advertised_addrs`](Self::advertised_addrs)),
    /// and the expected set gates every enroll ([`authorize_enroll`](Self::authorize_enroll)).
    pub fn record_task(
        &self,
        relay_id: RelayId,
        task_arn: &str,
        expected_ips: &[IpAddr],
        addrs: &[SocketAddr],
    ) -> Result<(), LedgerError> {
        let expected_json = serde_json::to_string(
            &expected_ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>(),
        )?;
        let addrs_json =
            serde_json::to_string(&addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>())?;
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE provisioned_relays SET task_arn = ?1, expected_ips = ?2, addrs = ?3
              WHERE relay_id = ?4",
            params![task_arn, expected_json, addrs_json, as_i64(relay_id.0)],
        )?;
        Ok(())
    }

    /// The coordinator-resolved advertise-address set recorded for `relay_id`, in
    /// stored order (first is the primary), or `None` when none was recorded — a
    /// relay whose addresses were never set through
    /// [`record_task`](Self::record_task), which then enrolls with its
    /// self-reported hello addresses.
    pub fn advertised_addrs(
        &self,
        relay_id: RelayId,
    ) -> Result<Option<Vec<SocketAddr>>, LedgerError> {
        let conn = self.conn.lock();
        let stored: Option<String> = conn
            .query_row(
                "SELECT addrs FROM provisioned_relays WHERE relay_id = ?1",
                params![as_i64(relay_id.0)],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        let Some(json) = stored else {
            return Ok(None);
        };
        let strings: Vec<String> = serde_json::from_str(&json)?;
        let addrs = strings
            .iter()
            .map(|s| s.parse::<SocketAddr>())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(addrs))
    }

    /// The number of ids in `region` that are still launching at `now`: minted,
    /// not retired, not yet bound to a certificate, and whose token has not
    /// expired. This is the count of in-flight launches a reconcile pass credits
    /// against a region's target so it does not double-launch while a task is
    /// still coming up. `region` of `None` counts the untagged ids. A token
    /// already past its expiry is excluded — it can no longer bind, so it is not
    /// a live launch — and is instead the launch-deadline sweep's concern
    /// ([`expired_launching`](Self::expired_launching)).
    pub(crate) fn count_launching(
        &self,
        region: Option<&RegionId>,
        now: u64,
    ) -> Result<usize, LedgerError> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM provisioned_relays
              WHERE retired_at IS NULL AND cert_fingerprint IS NULL
                AND token_expires_at >= ?1 AND region IS ?2",
            params![as_i64(now), region.map(|r| r.as_ref())],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Every id still launching at `now` whose token has expired: minted, not
    /// retired, never bound to a certificate, and past its token expiry. The
    /// relay never enrolled and its token can no longer bind, so the id is dead —
    /// the launch-deadline sweep stops the recorded task (if any) and retires it.
    pub(crate) fn expired_launching(&self, now: u64) -> Result<Vec<ProvisionedTask>, LedgerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT relay_id, task_arn FROM provisioned_relays
              WHERE retired_at IS NULL AND cert_fingerprint IS NULL
                AND token_expires_at < ?1",
        )?;
        let rows = stmt
            .query_map(params![as_i64(now)], row_to_provisioned_task)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Every id that is bound to a certificate and not retired, paired with the
    /// task recorded for it. The vanished-task sweep reads these to find a bound
    /// id whose relay is no longer enrolled and whose task has stopped — a relay
    /// that died — so the id can be retired and never claimed again.
    pub(crate) fn bound_unretired(&self) -> Result<Vec<ProvisionedTask>, LedgerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT relay_id, task_arn FROM provisioned_relays
              WHERE retired_at IS NULL AND cert_fingerprint IS NOT NULL",
        )?;
        let rows = stmt
            .query_map([], row_to_provisioned_task)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The set of task identifiers recorded on ids that are not retired. The
    /// orphan sweep subtracts this from the tasks the provisioner still lists: a
    /// running task no live id references is a launch the ledger lost track of and
    /// must be stopped so it does not run unaccounted.
    pub(crate) fn referenced_task_arns(&self) -> Result<Vec<String>, LedgerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT task_arn FROM provisioned_relays
              WHERE retired_at IS NULL AND task_arn IS NOT NULL",
        )?;
        let arns = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(arns)
    }

    /// The provisioner task recorded for `relay_id`, or `None` when the id is
    /// unknown or never had a task recorded. A scale-down reads this to find the
    /// task it must stop as it retires the id.
    pub(crate) fn task_arn(&self, relay_id: RelayId) -> Result<Option<String>, LedgerError> {
        let conn = self.conn.lock();
        let arn: Option<Option<String>> = conn
            .query_row(
                "SELECT task_arn FROM provisioned_relays WHERE relay_id = ?1",
                params![as_i64(relay_id.0)],
                |row| row.get(0),
            )
            .optional()?;
        Ok(arn.flatten())
    }

    /// Records `rtt_ms` for one direction of the canonical region pair
    /// `(region_a, region_b)` — the caller orders them `region_a <= region_b` —
    /// measured from `origin` (one of the pair's two regions), stamped `measured_at` in
    /// Unix seconds. Upserts on the (pair, origin) primary key, so the two ends of a
    /// link persist as two rows and a later report for one direction overwrites only
    /// that direction. The coordinator calls this only when the in-memory value for
    /// that direction actually changed, so a steady-state re-report every heartbeat
    /// costs no write.
    pub fn record_direction_rtt(
        &self,
        region_a: &RegionId,
        region_b: &RegionId,
        origin: &RegionId,
        rtt_ms: u32,
        measured_at: u64,
    ) -> Result<(), LedgerError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO region_direction_rtts (region_a, region_b, origin, rtt_ms, measured_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(region_a, region_b, origin)
             DO UPDATE SET rtt_ms = excluded.rtt_ms, measured_at = excluded.measured_at",
            params![
                region_a.as_ref(),
                region_b.as_ref(),
                origin.as_ref(),
                as_i64(u64::from(rtt_ms)),
                as_i64(measured_at),
            ],
        )?;
        Ok(())
    }

    /// Every stored per-direction round-trip, as canonical rows tagged with the origin
    /// that measured each — the startup load the coordinator seeds its in-memory table
    /// from so last-known directional values survive a restart. Unordered; the seed
    /// places each row into the directional slot its origin selects.
    pub fn direction_rtts(&self) -> Result<Vec<DirectionRttRow>, LedgerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT region_a, region_b, origin, rtt_ms, measured_at FROM region_direction_rtts",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(DirectionRttRow {
                    a: RegionId(row.get::<_, String>(0)?),
                    b: RegionId(row.get::<_, String>(1)?),
                    origin: RegionId(row.get::<_, String>(2)?),
                    rtt_ms: as_u64(row.get::<_, i64>(3)?) as u32,
                    measured_at: as_u64(row.get::<_, i64>(4)?),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

/// Maps a `(relay_id, task_arn)` row to a [`ProvisionedTask`], shared by the
/// sweeps' queries so the id-reinterpretation and column order live in one place.
fn row_to_provisioned_task(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProvisionedTask> {
    Ok(ProvisionedTask {
        relay_id: RelayId(as_u64(row.get(0)?)),
        task_arn: row.get(1)?,
    })
}

/// The columns [`RelayLedger::authorize_enroll_at`] reads for its decision.
struct LedgerRow {
    retired_at: Option<i64>,
    cert_fingerprint: Option<Vec<u8>>,
    token_hash: Vec<u8>,
    token_expires_at: i64,
    expected_ips: Option<String>,
}

/// Parses the stored expected-peer-IP set — a JSON array of canonical IP strings,
/// or an absent column — into the addresses a relay may enroll from. Both an
/// absent column and an empty array yield an empty set, which gates nothing.
fn parse_expected_ips(stored: Option<&str>) -> Result<Vec<IpAddr>, LedgerError> {
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
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

/// The SHA-256 digest of `bytes` — the form the ledger stores a token in and
/// compares a presented token against, so the token plaintext never lands on
/// disk.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
    out
}

/// Constant-time equality over two byte slices, so a token or fingerprint
/// comparison leaks no timing signal that would let it be probed a byte at a
/// time. A length mismatch short-circuits (already a non-match); equal-length
/// inputs are compared with no data-dependent branch.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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
fn as_i64(value: u64) -> i64 {
    value as i64
}

/// The inverse of [`as_i64`]: reinterprets a stored SQLite `INTEGER` as the
/// `u64` it was written from.
fn as_u64(value: i64) -> u64 {
    value as u64
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    /// A distinct 32-byte certificate fingerprint per test seed value.
    fn fingerprint(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// An in-memory ledger with the schema applied — a fresh, isolated store per
    /// test.
    fn ledger() -> RelayLedger {
        RelayLedger::open(Path::new(":memory:")).expect("an in-memory ledger opens")
    }

    /// A day, the token TTL most tests mint with.
    const DAY: Duration = Duration::from_secs(86_400);

    #[test]
    fn mint_then_authorize_binds_consumes_and_records_enrolled() {
        let ledger = ledger();
        let minted = ledger.mint_at(1_000, None, DAY).unwrap();

        let outcome = ledger
            .authorize_enroll_at(
                1_100,
                minted.relay_id,
                fingerprint(0xA1),
                Some(&minted.token),
                None,
            )
            .unwrap();
        assert_eq!(outcome, Authorized::FirstEnroll);

        // The row now records the binding, the consumption, and the enroll time.
        let conn = ledger.conn.lock();
        let (consumed, bound, enrolled): (Option<i64>, Option<Vec<u8>>, Option<i64>) = conn
            .query_row(
                "SELECT token_consumed_at, cert_fingerprint, enrolled_at
                 FROM provisioned_relays WHERE relay_id = ?1",
                params![as_i64(minted.relay_id.0)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(consumed, Some(1_100));
        assert_eq!(enrolled, Some(1_100));
        assert_eq!(bound.as_deref(), Some(fingerprint(0xA1).as_slice()));
    }

    #[test]
    fn the_same_token_binds_at_most_one_fingerprint() {
        // The atomic-UPDATE property: two enrolls presenting the same token with
        // different certificates leave exactly one bound. The first wins; the
        // second finds the id already bound and is refused.
        let ledger = ledger();
        let minted = ledger.mint_at(1_000, None, DAY).unwrap();

        let first = ledger
            .authorize_enroll_at(
                1_010,
                minted.relay_id,
                fingerprint(0xAA),
                Some(&minted.token),
                None,
            )
            .unwrap();
        assert_eq!(first, Authorized::FirstEnroll);

        let second = ledger.authorize_enroll_at(
            1_020,
            minted.relay_id,
            fingerprint(0xBB),
            Some(&minted.token),
            None,
        );
        assert!(matches!(second, Err(EnrollRefusal::FingerprintMismatch)));

        // The winner's certificate is the one that stuck.
        let reconnect = ledger
            .authorize_enroll_at(1_030, minted.relay_id, fingerprint(0xAA), None, None)
            .unwrap();
        assert_eq!(reconnect, Authorized::Reenroll);
    }

    #[test]
    fn a_consumed_token_cannot_be_reused_to_bind() {
        // The atomic UPDATE's `token_consumed_at IS NULL` guard: an id whose token
        // was consumed but (contrived here) left unbound refuses a second use of
        // that token with TokenInvalid, never a second bind.
        let ledger = ledger();
        let minted = ledger.mint_at(1_000, None, DAY).unwrap();
        {
            let conn = ledger.conn.lock();
            conn.execute(
                "UPDATE provisioned_relays SET token_consumed_at = 1500
                  WHERE relay_id = ?1",
                params![as_i64(minted.relay_id.0)],
            )
            .unwrap();
        }
        let outcome = ledger.authorize_enroll_at(
            1_600,
            minted.relay_id,
            fingerprint(0xC1),
            Some(&minted.token),
            None,
        );
        assert!(matches!(outcome, Err(EnrollRefusal::TokenInvalid)));
    }

    #[test]
    fn a_wrong_token_on_an_unbound_id_is_token_invalid() {
        let ledger = ledger();
        let minted = ledger.mint_at(1_000, None, DAY).unwrap();
        let outcome = ledger.authorize_enroll_at(
            1_010,
            minted.relay_id,
            fingerprint(0xC2),
            Some("not-the-real-token"),
            None,
        );
        assert!(matches!(outcome, Err(EnrollRefusal::TokenInvalid)));
    }

    #[test]
    fn an_expired_token_is_refused() {
        let ledger = ledger();
        // A short-lived token: minted at t=1000 with a 10-second TTL.
        let minted = ledger
            .mint_at(1_000, None, Duration::from_secs(10))
            .unwrap();
        let outcome = ledger.authorize_enroll_at(
            2_000, // well past expiry
            minted.relay_id,
            fingerprint(0xC3),
            Some(&minted.token),
            None,
        );
        assert!(matches!(outcome, Err(EnrollRefusal::TokenInvalid)));
    }

    #[test]
    fn a_broken_clock_refuses_enrollment() {
        // `unix_now` yields u64::MAX on a pre-epoch/errored clock; a `now` of
        // u64::MAX makes every finite expiry read as passed, so enrollment fails
        // closed rather than treating an unverifiable-age token as valid.
        let ledger = ledger();
        let minted = ledger.mint_at(1_000, None, DAY).unwrap();
        let outcome = ledger.authorize_enroll_at(
            u64::MAX,
            minted.relay_id,
            fingerprint(0xC4),
            Some(&minted.token),
            None,
        );
        assert!(matches!(outcome, Err(EnrollRefusal::TokenInvalid)));
    }

    #[test]
    fn a_reenroll_with_the_same_fingerprint_needs_no_token() {
        let ledger = ledger();
        let minted = ledger.mint_at(1_000, None, DAY).unwrap();
        ledger
            .authorize_enroll_at(
                1_010,
                minted.relay_id,
                fingerprint(0xD0),
                Some(&minted.token),
                None,
            )
            .unwrap();

        // A reconnect presents the bound certificate and no token.
        let outcome = ledger
            .authorize_enroll_at(1_020, minted.relay_id, fingerprint(0xD0), None, None)
            .unwrap();
        assert_eq!(outcome, Authorized::Reenroll);
    }

    #[test]
    fn a_reenroll_with_a_different_fingerprint_is_refused() {
        let ledger = ledger();
        let minted = ledger.mint_at(1_000, None, DAY).unwrap();
        ledger
            .authorize_enroll_at(
                1_010,
                minted.relay_id,
                fingerprint(0xD0),
                Some(&minted.token),
                None,
            )
            .unwrap();

        let outcome =
            ledger.authorize_enroll_at(1_020, minted.relay_id, fingerprint(0xEE), None, None);
        assert!(matches!(outcome, Err(EnrollRefusal::FingerprintMismatch)));
    }

    #[test]
    fn a_retired_id_is_refused_even_with_a_valid_token_and_retire_is_idempotent() {
        let ledger = ledger();
        let minted = ledger.mint_at(1_000, None, DAY).unwrap();
        ledger.retire(minted.relay_id).unwrap();

        let outcome = ledger.authorize_enroll_at(
            1_010,
            minted.relay_id,
            fingerprint(0xF0),
            Some(&minted.token),
            None,
        );
        assert!(matches!(outcome, Err(EnrollRefusal::Retired)));

        // Retiring again is a harmless no-op.
        ledger.retire(minted.relay_id).unwrap();
        let again = ledger.authorize_enroll_at(
            1_020,
            minted.relay_id,
            fingerprint(0xF0),
            Some(&minted.token),
            None,
        );
        assert!(matches!(again, Err(EnrollRefusal::Retired)));
    }

    #[test]
    fn an_unknown_id_is_refused() {
        let ledger = ledger();
        let outcome =
            ledger.authorize_enroll_at(1_000, RelayId(999), fingerprint(0x01), Some("x"), None);
        assert!(matches!(outcome, Err(EnrollRefusal::UnknownId)));
    }

    #[test]
    fn a_tokenless_first_enroll_requires_a_token() {
        let ledger = ledger();
        let minted = ledger.mint_at(1_000, None, DAY).unwrap();
        let outcome =
            ledger.authorize_enroll_at(1_010, minted.relay_id, fingerprint(0x02), None, None);
        assert!(matches!(outcome, Err(EnrollRefusal::TokenRequired)));
    }

    #[test]
    fn expected_ip_gates_first_and_reenroll() {
        let ledger = ledger();
        let minted = ledger.mint_at(1_000, None, DAY).unwrap();
        let expected: IpAddr = Ipv4Addr::new(203, 0, 113, 7).into();
        let other: IpAddr = Ipv4Addr::new(198, 51, 100, 9).into();
        ledger
            .record_task(minted.relay_id, "arn:aws:ecs:task/abc", &[expected], &[])
            .unwrap();

        // A mismatched peer is refused before the token is even consulted.
        let mismatch = ledger.authorize_enroll_at(
            1_010,
            minted.relay_id,
            fingerprint(0x10),
            Some(&minted.token),
            Some(other),
        );
        assert!(matches!(mismatch, Err(EnrollRefusal::IpMismatch)));
        // An absent peer address (server records none) is likewise refused.
        let absent = ledger.authorize_enroll_at(
            1_010,
            minted.relay_id,
            fingerprint(0x10),
            Some(&minted.token),
            None,
        );
        assert!(matches!(absent, Err(EnrollRefusal::IpMismatch)));

        // The matching peer enrolls.
        let ok = ledger
            .authorize_enroll_at(
                1_010,
                minted.relay_id,
                fingerprint(0x10),
                Some(&minted.token),
                Some(expected),
            )
            .unwrap();
        assert_eq!(ok, Authorized::FirstEnroll);

        // The gate still applies on reconnect: a mismatched peer with the bound
        // certificate is refused.
        let reconnect_mismatch = ledger.authorize_enroll_at(
            1_020,
            minted.relay_id,
            fingerprint(0x10),
            None,
            Some(other),
        );
        assert!(matches!(reconnect_mismatch, Err(EnrollRefusal::IpMismatch)));
        let reconnect_ok = ledger
            .authorize_enroll_at(
                1_020,
                minted.relay_id,
                fingerprint(0x10),
                None,
                Some(expected),
            )
            .unwrap();
        assert_eq!(reconnect_ok, Authorized::Reenroll);
    }

    #[test]
    fn enroll_matches_any_ip_in_the_expected_set() {
        // A dual-stack task records both its public IPv4 and its IPv6; a connection
        // from either address enrolls, and one from neither is refused.
        let ledger = ledger();
        let minted = ledger.mint_at(1_000, None, DAY).unwrap();
        let v4: IpAddr = Ipv4Addr::new(203, 0, 113, 7).into();
        let v6: IpAddr = "2001:db8::7".parse().unwrap();
        let other: IpAddr = Ipv4Addr::new(198, 51, 100, 9).into();
        ledger
            .record_task(minted.relay_id, "arn:aws:ecs:task/dual", &[v4, v6], &[])
            .unwrap();

        // Enroll over IPv6 (binds the cert).
        let over_v6 = ledger
            .authorize_enroll_at(
                1_010,
                minted.relay_id,
                fingerprint(0x20),
                Some(&minted.token),
                Some(v6),
            )
            .unwrap();
        assert_eq!(over_v6, Authorized::FirstEnroll);

        // Reconnect over the other family in the set is accepted too.
        let over_v4 = ledger
            .authorize_enroll_at(1_020, minted.relay_id, fingerprint(0x20), None, Some(v4))
            .unwrap();
        assert_eq!(over_v4, Authorized::Reenroll);

        // An address outside the set is refused.
        let outside = ledger.authorize_enroll_at(
            1_030,
            minted.relay_id,
            fingerprint(0x20),
            None,
            Some(other),
        );
        assert!(matches!(outside, Err(EnrollRefusal::IpMismatch)));
    }

    #[test]
    fn an_empty_expected_set_gates_nothing() {
        // Recording an empty expected set leaves the gate open: any peer, or none,
        // enrolls — the posture for a substrate that resolves no address.
        let ledger = ledger();
        let minted = ledger.mint_at(1_000, None, DAY).unwrap();
        ledger
            .record_task(minted.relay_id, "arn:aws:ecs:task/none", &[], &[])
            .unwrap();
        let any_peer: IpAddr = Ipv4Addr::new(198, 51, 100, 3).into();
        let ok = ledger
            .authorize_enroll_at(
                1_010,
                minted.relay_id,
                fingerprint(0x21),
                Some(&minted.token),
                Some(any_peer),
            )
            .unwrap();
        assert_eq!(ok, Authorized::FirstEnroll);
    }

    #[test]
    fn mint_after_retire_yields_a_fresh_id() {
        // AUTOINCREMENT: a retired id's number is never handed out again, so a
        // tombstone can never be shadowed by a reused id.
        let ledger = ledger();
        let first = ledger.mint_at(1_000, None, DAY).unwrap();
        ledger.retire(first.relay_id).unwrap();
        let second = ledger.mint_at(1_001, None, DAY).unwrap();
        assert_ne!(
            first.relay_id, second.relay_id,
            "a mint after a retire must not reuse the retired id",
        );
    }

    #[test]
    fn record_task_and_advertised_addrs_roundtrip() {
        let ledger = ledger();
        let minted = ledger.mint_at(1_000, None, DAY).unwrap();
        // A freshly minted id has no recorded advertise set.
        assert_eq!(ledger.advertised_addrs(minted.relay_id).unwrap(), None);

        let v4: SocketAddr = "203.0.113.7:14900".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::7]:14900".parse().unwrap();
        ledger
            .record_task(minted.relay_id, "arn:aws:ecs:task/xyz", &[], &[v4, v6])
            .unwrap();
        assert_eq!(
            ledger.advertised_addrs(minted.relay_id).unwrap(),
            Some(vec![v4, v6]),
            "the advertise set round-trips in stored order",
        );
    }

    #[test]
    fn a_broken_clock_refuses_minting() {
        // A `now` of u64::MAX (the fail-closed unusable-clock value) must refuse
        // the mint outright: stored as a signed integer it would read back as a
        // never-expiring token, inverting the fail-closed intent.
        let ledger = ledger();
        let outcome = ledger.mint_at(u64::MAX, None, DAY);
        assert!(matches!(outcome, Err(LedgerError::Clock)));
    }

    #[test]
    fn minted_tokens_are_distinct() {
        let ledger = ledger();
        let a = ledger.mint_at(1_000, None, DAY).unwrap();
        let b = ledger.mint_at(1_000, None, DAY).unwrap();
        assert_ne!(a.token, b.token, "each mint draws a fresh random token");
        assert_ne!(a.relay_id, b.relay_id);
    }

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
}
