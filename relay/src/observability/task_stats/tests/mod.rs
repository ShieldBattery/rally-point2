//! Task-stats unit tests: shared fixtures (a nanosecond epoch constant and a
//! sample builder pinned to a synthetic timestamp) plus the two topic
//! modules below, split by which non-test module they exercise.

use super::*;

const NANOS_PER_SEC: i128 = 1_000_000_000;

fn sample_at(seconds: i128, mut sample: Sample) -> Sample {
    sample.provider_read_unix_ns = seconds * NANOS_PER_SEC;
    sample
}

mod derive;
mod fetch;
