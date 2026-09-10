//! Shared fixtures for the ledger tests: `fingerprint` (a distinct 32-byte
//! cert per seed), `ledger` (a fresh in-memory store), and `DAY` (the token
//! TTL most tests mint with), used by both topic files below via
//! `use super::*;`. Split by topic: `enrollment` (mint/authorize/retire),
//! `bookkeeping` (the reconcile-sweep queries, RTT storage, and schema
//! migration).

use std::net::Ipv4Addr;
use std::path::Path;

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

mod bookkeeping;
mod enrollment;
