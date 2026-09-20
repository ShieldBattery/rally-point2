//! Coverage-guided fuzzing of the relay's attacker-facing turn validator.
//!
//! `validate_turn` parses attacker-controlled bytes on every turn a client
//! submits, so its contract is absolute: never panic, never read past a
//! command's declared length, and hand onward only bytes that are safe to
//! forward. Beyond crash-hunting, this target asserts the properties the rest
//! of the relay leans on — binding, no amplification, fixpoint, attribution.
//!
//! Those assertions are not written here: they live in
//! `rally_point_relay::validation::assert_validate_turn_invariants`, which
//! documents each of them and which the always-on randomized property tests
//! in `relay/src/validation.rs` call too. This harness is a separate
//! workspace, built with nightly and sanitizer flags, so a second copy of a
//! security-critical assertion set would be free to drift out of step with
//! the one CI runs on stable; calling the same function makes that
//! impossible. What this target adds is the coverage-guided search for the
//! inputs to feed it.
//!
//! Run with `cargo +nightly fuzz run validate_turn` from `relay/`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rally_point_proto::ids::SlotId;
use rally_point_relay::validation::assert_validate_turn_invariants;

fuzz_target!(|commands: &[u8]| {
    assert_validate_turn_invariants(SlotId(3), 7, Some(41), commands);
});
