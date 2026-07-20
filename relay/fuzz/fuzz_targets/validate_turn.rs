//! Coverage-guided fuzzing of the relay's attacker-facing turn validator.
//!
//! `validate_turn` parses attacker-controlled bytes on every turn a client
//! submits, so its contract is absolute: never panic, never read past a
//! command's declared length, and hand onward only bytes that are safe to
//! forward. Beyond crash-hunting, this target asserts the properties the rest
//! of the relay leans on:
//!
//! - **Binding**: the validated payload carries the authorized slot and the
//!   caller's `seq`/frame verbatim — nothing derived from the input bytes.
//! - **No amplification**: the sanitized command stream never grows.
//! - **Fixpoint**: the sanitized output is itself a valid turn that
//!   re-validates with nothing further stripped, byte-for-byte identical. A
//!   peer relay or client re-parsing forwarded bytes must never see something
//!   the ingress validator wouldn't accept — a sanitizer whose output fails
//!   its own check is exactly the parser-differential bug class this exists
//!   to catch.
//! - **Attribution**: a rejection names an offset inside the input, so abuse
//!   diagnostics always point at real bytes.
//!
//! The same invariants run on stable in CI as a randomized property test in
//! `relay/src/validation.rs`; this harness is the coverage-guided deep end.
//! Run with `cargo +nightly fuzz run validate_turn` from `relay/`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::Payload;
use rally_point_relay::validation::{ValidationError, validate_turn};

fuzz_target!(|commands: &[u8]| {
    let slot = SlotId(3);
    let payload = Payload {
        seq: 7,
        slot: u32::MAX,
        commands: commands.to_vec().into(),
        game_frame_count: Some(41),
        buffer_directive: None,
    };
    match validate_turn(slot, payload) {
        Ok(validated) => {
            assert_eq!(validated.payload.slot, u32::from(slot.0));
            assert_eq!(validated.payload.seq, 7);
            assert_eq!(validated.payload.game_frame_count, Some(41));
            assert_eq!(validated.payload.buffer_directive, None);
            assert!(validated.payload.commands.len() <= commands.len());
            if validated.stripped_control == 0 {
                assert_eq!(&validated.payload.commands[..], commands);
            }

            let again = validate_turn(slot, validated.payload.clone())
                .expect("sanitized output must re-validate");
            assert_eq!(again.stripped_control, 0, "sanitizing must be complete");
            assert_eq!(
                again.payload.commands, validated.payload.commands,
                "sanitized output must be a fixpoint",
            );
        }
        Err(
            ValidationError::UnknownOpcode { offset, .. }
            | ValidationError::Truncated { offset, .. },
        ) => {
            assert!(offset < commands.len(), "rejection must point inside the turn");
        }
    }
});
