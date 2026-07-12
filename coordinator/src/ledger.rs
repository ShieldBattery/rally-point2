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

/// How long a blocked writer waits for the database lock before erroring, rather
/// than failing instantly on transient contention.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The number of random bytes behind each minted enroll token, before encoding —
/// 256 bits, so a token is unguessable and its SHA-256 has no meaningful
/// collision risk.
const TOKEN_BYTES: usize = 32;

/// The initial schema, applied once to a fresh database (one whose
/// `user_version` is still 0) and stamping it `user_version = 1`. A later build
/// that adds a migration bumps that number and keys its migration off the value
/// [`RelayLedger::open`] reads. `AUTOINCREMENT` on the primary key guarantees a
/// retired id is never handed out again, so a tombstone can never be shadowed by
/// a freshly minted relay reusing the number.
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS provisioned_relays (
  relay_id          INTEGER PRIMARY KEY AUTOINCREMENT,
  region            TEXT,
  token_hash        BLOB NOT NULL,
  token_expires_at  INTEGER NOT NULL,
  token_consumed_at INTEGER,
  cert_fingerprint  BLOB,
  task_arn          TEXT,
  expected_ip       TEXT,
  addrs             TEXT,
  launched_at       INTEGER NOT NULL,
  enrolled_at       INTEGER,
  retired_at        INTEGER
);
PRAGMA user_version = 1;";

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
    /// Opens (creating if absent) the ledger database at `path`, applying the
    /// schema to a fresh file and leaving an already-initialized one untouched.
    /// Runs in WAL journal mode with a bounded busy timeout, so a reader never
    /// blocks the single writer and transient lock contention waits rather than
    /// erroring.
    pub fn open(path: &Path) -> Result<Self, LedgerError> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version == 0 {
            conn.execute_batch(SCHEMA)?;
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
                        token_consumed_at, expected_ip
                 FROM provisioned_relays WHERE relay_id = ?1",
                params![as_i64(relay_id.0)],
                |row| {
                    Ok(LedgerRow {
                        retired_at: row.get(0)?,
                        cert_fingerprint: row.get(1)?,
                        token_hash: row.get(2)?,
                        token_expires_at: row.get(3)?,
                        expected_ip: row.get(5)?,
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
        // reconnect, so it precedes the bound/unbound split. It presumes the
        // coordinator is directly exposed (the connection's transport-level peer
        // address is the relay's real one, not a reverse proxy's).
        if let Some(expected) = &row.expected_ip {
            let matches = peer_ip.is_some_and(|ip| ip.to_string() == *expected);
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
    /// runs as, the peer address the coordinator should see it enroll from (when
    /// known), and the coordinator-resolved advertise-address set clients and
    /// peers reach it at. The advertise set is stored as a JSON array of
    /// `"ip:port"` strings and later overrides a hello's self-reported addresses
    /// at enroll ([`advertised_addrs`](Self::advertised_addrs)).
    pub fn record_task(
        &self,
        relay_id: RelayId,
        task_arn: &str,
        expected_ip: Option<IpAddr>,
        addrs: &[SocketAddr],
    ) -> Result<(), LedgerError> {
        let addrs_json =
            serde_json::to_string(&addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>())?;
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE provisioned_relays SET task_arn = ?1, expected_ip = ?2, addrs = ?3
              WHERE relay_id = ?4",
            params![
                task_arn,
                expected_ip.map(|ip| ip.to_string()),
                addrs_json,
                as_i64(relay_id.0),
            ],
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
    expected_ip: Option<String>,
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
            .record_task(minted.relay_id, "arn:aws:ecs:task/abc", Some(expected), &[])
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
            .record_task(minted.relay_id, "arn:aws:ecs:task/xyz", None, &[v4, v6])
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
        ledger.record_task(a.relay_id, "task/a", None, &[]).unwrap();

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
        ledger.record_task(a.relay_id, "task/a", None, &[]).unwrap();
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
        ledger.record_task(a.relay_id, "task/a", None, &[]).unwrap();
        ledger.record_task(b.relay_id, "task/b", None, &[]).unwrap();
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
        ledger.record_task(a.relay_id, "task/a", None, &[]).unwrap();
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
}
