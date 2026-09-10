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
//!
//! # File map
//!
//! - `mod.rs` (this file) — the errors, the id-lifecycle types, and both
//!   `RelayLedger` impl blocks (mint/enroll, then task/ip bookkeeping).
//! - `schema` — schema versioning/migration (including `open`) and the small
//!   storage helpers (row parsing, the clock read, digests, int reinterpretation).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use base64::Engine as _;
use parking_lot::Mutex;
use rally_point_proto::control::RegionId;
use rally_point_proto::ids::RelayId;
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{Connection, OptionalExtension, params};

use crate::pair_rtts::DirectionRttRow;

mod schema;

use schema::{
    LedgerRow, TOKEN_BYTES, as_i64, as_u64, constant_time_eq, parse_expected_ips,
    row_to_provisioned_task, sha256, unix_now,
};
// Test-only: not needed by this file's own code, only by `tests`' `use
// super::*;` picking them up the same way it would if this were still one
// file.
#[cfg(test)]
use schema::{SCHEMA_V1, SCHEMA_V2};

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
    /// The region the id was minted for, or `None` for an untagged id.
    pub region: Option<RegionId>,
}

/// The ledger authorized an enroll — how it did so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorized {
    /// The relay's certificate was bound to its id for the first time: the
    /// one-time token was consumed and the fingerprint recorded.
    FirstEnroll {
        /// Seconds from the id's launch to this first enroll — the relay's
        /// cold-start duration — or `None` when the clock could not be trusted
        /// to measure it. Only meaningful on a first enroll (a reconnect is not
        /// a cold start).
        cold_start_secs: Option<u64>,
    },
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
                        token_consumed_at, expected_ips, launched_at
                 FROM provisioned_relays WHERE relay_id = ?1",
                params![as_i64(relay_id.0)],
                |row| {
                    Ok(LedgerRow {
                        retired_at: row.get(0)?,
                        cert_fingerprint: row.get(1)?,
                        token_hash: row.get(2)?,
                        token_expires_at: row.get(3)?,
                        expected_ips: row.get(5)?,
                        launched_at: row.get(6)?,
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
                    // The relay's cold-start duration: launch to this first enroll.
                    // Guard the unusable-clock sentinel so a broken clock reports no
                    // measurement rather than a nonsense delta.
                    let cold_start_secs =
                        (now != u64::MAX).then(|| now.saturating_sub(as_u64(row.launched_at)));
                    Ok(Authorized::FirstEnroll { cold_start_secs })
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
}

impl RelayLedger {
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
            "SELECT relay_id, task_arn, region FROM provisioned_relays
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
            "SELECT relay_id, task_arn, region FROM provisioned_relays
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

#[cfg(test)]
mod tests;
