//! Fixtures shared across the coordinator's unit tests: the builders every
//! area otherwise re-declares (ids, regions, descriptors, relay hellos, fleets)
//! and the webhook receiver the api / lifecycle / notify tests all stand up.
//! Test-only; integration suites under `coordinator/tests/` keep their own
//! `common` module because they see only the public API.

pub(crate) mod fixtures;
pub(crate) mod webhook;

#[allow(unused_imports)]
pub(crate) use fixtures::*;
#[allow(unused_imports)]
pub(crate) use webhook::*;

// Production periodic dispatch has a process-wide budget. Tests that exercise
// that budget through the lifecycle must not consume each other's reservations.
pub(crate) static PERIODIC_WEBHOOK_TEST_LOCK: tokio::sync::Mutex<()> =
    tokio::sync::Mutex::const_new(());
