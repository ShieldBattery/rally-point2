//! The wall clock as Unix time, with the clock-fault policy in the name.
//!
//! Every component stamps or compares Unix timestamps somewhere — token expiry,
//! descriptor staging stamps, warm-relay deadlines, request signatures — and
//! each site used to spell out the same `SystemTime::now().duration_since(UNIX_EPOCH)`
//! with its own answer to "what if the clock is before the epoch or unreadable".
//! That answer is a policy decision, so the three helpers here make it explicit
//! at the call site instead of hiding it in an `unwrap_or` at the bottom of a
//! private function.

use std::time::{SystemTime, UNIX_EPOCH};

/// Unix time in milliseconds. A clock before the epoch reads as `0`: the
/// callers stamping lag measurements and staging times tolerate a zero stamp
/// (it reads as "unstamped" and the derived lag is discarded), so a clock fault
/// degrades to a missing sample rather than a wrong one.
pub fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Unix time in seconds, **failing closed**: a clock before the epoch reads as
/// `u64::MAX`. Use it where a bogus timestamp must *refuse* rather than admit —
/// a token would never expire, a deadline would never pass, a hold would wedge
/// forever — so the caller sees a value it can only treat as unusable.
pub fn unix_secs_fail_closed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX)
}

/// Unix time in seconds, **failing open**: a clock before the epoch reads as
/// `0`, so every stored deadline compares as still in the future. Use it only
/// where erring toward "keep going" is the safe direction (keeping a relay warm
/// never strands a player); anything that admits or refuses on the value wants
/// [`unix_secs_fail_closed`].
pub fn unix_secs_fail_open() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
