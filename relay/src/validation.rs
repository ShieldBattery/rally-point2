//! Turn-command validation — the relay's defensive gate over client turns.
//!
//! A validating relay is not a dumb forwarder: before a client's turn is
//! accepted onto the mesh and fanned out to the other players, the relay walks
//! its native SC:R command bytes and:
//!
//! - **binds the turn to the slot the client is authorized for** — the slot the
//!   client puts on the wire is never trusted; the authoritative slot comes from
//!   the client's token and is stamped here. This prevents one client from
//!   submitting turns as another.
//! - **bounds-checks every command** against the SC:R length table and the
//!   variable-length rules, so a truncated or over-long command can't slip
//!   through and crash a peer's parser (a parser-crash desync, or worse).
//! - **rejects commands it can't bound-check** — an opcode the SC:R length table
//!   can't classify has an unknown length, so it can't be safely parsed and the
//!   whole turn is refused. This is also where save/load lands: they're real
//!   multiplayer commands, but ShieldBattery deliberately doesn't support saving
//!   or loading games (see below), so the table doesn't model them.
//! - **strips commands a live client turn shouldn't carry** — two kinds.
//!   *Relay-owned pacing* (added-latency, set/dynamic turn-rate) must change on
//!   the same turn for every player, so the relay — the one vantage point that
//!   sees all the links — decides it and originates it on its outbound fan-out; an
//!   inbound client copy could only shift everyone's pacing unilaterally.
//!   *Replay-playback* commands (set-speed, seek, the leave marker) only mean
//!   something while a replay plays. This is an *ingress* rule: the relay-
//!   originated pacing copies going back out aren't stripped, and a replay session
//!   (below) keeps the playback commands.
//!
//! Three things are deliberately out of scope here:
//!
//! - **Where latency/leave intent enters.** A manual latency change or a player's
//!   intent to leave reaches the relay out of band — a control-plane message, or
//!   the QUIC connection simply dropping — and is folded into the relay's
//!   coordinated decision, not carried as a client turn command. Until that path
//!   exists, stripping pacing on ingress leaves a manual latency change with
//!   nowhere to go.
//! - **Multiplayer save/load (`0x06`/`0x07`).** Real commands a live game can
//!   carry, but ShieldBattery doesn't support saving or loading games today — no
//!   load path through SB, and in-game save is unused and broken (it drops you
//!   from the game). So the command table doesn't model them and the validator
//!   refuses the turn. A deliberate product decision, not an oversight; revisit
//!   only if SB brings save/load back, which means modeling their variable-length
//!   null-terminated-string form (and accepting the extra parse surface).
//! - **Replay-watching sessions.** The replay-playback commands are stripped here
//!   on the assumption every session is a live game. A shared-replay session
//!   inverts that — those commands are the point and must pass through — but
//!   nothing yet tags a connection as live-game vs. replay, so that gating waits
//!   for the session-kind work.
//!
//! This runs on attacker-controlled bytes on every turn, so it never panics and
//! never reads past what a command declares. It is pure and synchronous — the
//! connection handling, token check, and fan-out live elsewhere and call in here.

use rally_point_proto::commands::{CommandId, CommandLength, classify};
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::Payload;

/// Relay-owned pacing opcodes a client may not originate in its turn stream:
/// added-latency (`0x55`), set-turn-rate (`0x5f`), and dynamic-turn-rate (`0x66`,
/// which also re-issues a latency change). Each shifts pacing for every player and
/// must take effect on the same turn, so the relay decides it and originates it on
/// its outbound fan-out; an inbound copy from a client could only move everyone's
/// latency or turn rate unilaterally. Stripping salvages the rest of the turn
/// instead of rejecting it.
const RELAY_OWNED_PACING: [u8; 3] = [0x55, 0x5f, 0x66];

/// Replay-playback opcodes: set-speed (`0x56`), seek (`0x5d`), and the
/// player-leave marker (`0x57`). They drive an observer client through a replay,
/// so shared replay-watching needs them synced across watchers — but in a live
/// game they're out of place (the leave marker is a no-op live; seek and speed
/// have nothing to act on).
///
/// Stripping them is correct only because every session today is a live game.
/// When a connection is tagged live-game vs. replay, a replay session must invert
/// this — these become the stream's purpose and pass through — while live-game
/// turns keep stripping them.
const REPLAY_ONLY: [u8; 3] = [0x56, 0x5d, 0x57];

/// Whether `opcode` must be stripped from a live-game client turn: a relay-owned
/// pacing control or a replay-playback command. Neither belongs in a live turn,
/// though for different reasons (see each set).
fn is_stripped_from_live_turn(opcode: u8) -> bool {
    RELAY_OWNED_PACING.contains(&opcode) || REPLAY_ONLY.contains(&opcode)
}

/// A client turn that passed validation: the sanitized payload to forward, plus
/// how many commands were stripped out of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTurn {
    /// The payload to fan out. Its `slot` is bound to the authorized slot (never
    /// the client-sent value), its `commands` are the client's bytes with the
    /// commands a live turn shouldn't carry (relay-owned pacing and
    /// replay-playback) removed, and its `seq` is the client's origin identity —
    /// preserved verbatim. The seq is the turn's identity across the whole mesh:
    /// assigned by the sending client and honored by every hop, so the relay
    /// forwards it untouched rather than restamping.
    pub payload: Payload,
    /// How many commands were stripped — relay-owned pacing or replay-playback.
    /// Non-zero means the client emitted something a live turn has no business
    /// carrying, a signal worth recording for abuse attribution even though the
    /// turn itself is salvaged.
    pub stripped_control: u32,
}

/// Why a client turn was rejected. Every variant carries the byte `offset` of the
/// offending command within the turn and its leading `opcode`, so a rejection can
/// be attributed to a specific command for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// The opcode isn't in the command-length table, so its length is unknown and
    /// the command can't be bounds-checked — garbage bytes, or save/load
    /// (`0x06`/`0x07`), which the table deliberately doesn't model because SB
    /// doesn't support saving/loading games (see the module docs). Either way the
    /// turn is refused.
    #[error("unknown command opcode {opcode:#04x} at offset {offset}")]
    UnknownOpcode { offset: usize, opcode: u8 },
    /// A well-known opcode whose command runs past the end of the turn: either a
    /// variable-length command missing its count byte, or a command whose
    /// declared length exceeds the bytes that remain.
    #[error("command {opcode:#04x} at offset {offset} runs past the end of the turn")]
    Truncated { offset: usize, opcode: u8 },
}
/// Validates and sanitizes one client turn, binding it to `slot`.
///
/// `commands` is the raw native SC:R command stream the client submitted (with
/// no transport framing), and `seq` is the turn's origin identity — assigned by
/// the sending client and preserved end-to-end. On success the returned
/// [`ValidatedTurn`] holds a payload safe to forward: bound to `slot`, the
/// client's `seq` preserved verbatim, every command length-checked, and the
/// commands a live turn shouldn't carry (relay-owned pacing, replay-playback)
/// stripped. An empty `commands` (a bare turn signal, or a turn that stripped
/// down to nothing) is valid and yields an empty payload.
///
/// `game_frame_count` is the consensus coordinate — which simulated step the
/// turn belongs to. Like `seq`, it is preserved verbatim across the seam: a
/// forwarded turn carries the sender's frame, never a relay-stamped one, so the
/// relay never silently strips the coordinate the latency-buffer and leave
/// consensus engines key on. `None` means the payload has no consensus coordinate
/// (lobby turns); those don't participate in apply-at-turn-N decisions.
///
/// This is the attacker-facing parse: it never panics and never reads beyond a
/// command's declared length.
pub fn validate_turn(
    slot: SlotId,
    seq: u64,
    game_frame_count: Option<u32>,
    commands: &[u8],
) -> Result<ValidatedTurn, ValidationError> {
    let mut forwarded = Vec::with_capacity(commands.len());
    let mut stripped_control: u32 = 0;
    let mut offset = 0;

    while offset < commands.len() {
        let rest = &commands[offset..];
        let opcode = rest[0];
        let id = CommandId(opcode);

        let length = match classify(id) {
            None => return Err(ValidationError::UnknownOpcode { offset, opcode }),
            Some(CommandLength::Fixed(n)) => usize::from(n),
            Some(CommandLength::Variable { stride }) => {
                let count = *rest
                    .get(1)
                    .ok_or(ValidationError::Truncated { offset, opcode })?;
                2 + usize::from(stride) * usize::from(count)
            }
        };

        let command = rest
            .get(..length)
            .ok_or(ValidationError::Truncated { offset, opcode })?;

        if is_stripped_from_live_turn(opcode) {
            stripped_control += 1;
        } else {
            forwarded.extend_from_slice(command);
        }

        offset += length;
    }

    Ok(ValidatedTurn {
        payload: Payload {
            seq,
            slot: u32::from(slot.0),
            game_frame_count,
            // A freshly validated client turn carries no buffer directive: the
            // relay stamps those onto turns it forwards, never onto ingress.
            buffer_directive: None,
            commands: forwarded.into(),
        },
        stripped_control,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT: SlotId = SlotId(3);
    /// Validate `commands` for [`SLOT`] with `seq` and unwrap the sanitized turn.
    fn validated(commands: &[u8]) -> ValidatedTurn {
        validated_with_seq(SLOT, 0, commands)
    }

    /// Validate `commands` for `slot` with `seq` and unwrap the sanitized turn.
    fn validated_with_seq(slot: SlotId, seq: u64, commands: &[u8]) -> ValidatedTurn {
        validate_turn(slot, seq, None, commands).expect("turn should validate")
    }

    #[test]
    fn empty_turn_is_valid_and_bound_to_slot() {
        let turn = validated(&[]);
        assert_eq!(turn.payload.slot, u32::from(SLOT.0));
        assert!(turn.payload.commands.is_empty());
        assert_eq!(turn.stripped_control, 0);
        // seq is preserved verbatim from the client, not assigned here.
        assert_eq!(turn.payload.seq, 0);
    }

    #[test]
    fn preserves_the_client_seq_verbatim() {
        // The seq is the turn's origin identity: assigned by the client and
        // honored untouched, never restamped by the validator.
        for seq in [0u64, 1, 42, 0x100, u64::MAX] {
            let turn = validated_with_seq(SLOT, seq, &[0x05]);
            assert_eq!(turn.payload.seq, seq);
        }
    }

    #[test]
    fn preserves_the_game_frame_count_verbatim() {
        // The frame is the consensus coordinate — which simulated step the turn
        // belongs to. Like seq, the relay forwards the sender's frame untouched,
        // never dropping or restamping it, so the latency-buffer and leave
        // consensus engines can key on it. A None (lobby turn) stays None.
        for frame in [None, Some(0u32), Some(1), Some(42), Some(u32::MAX)] {
            let turn = validate_turn(SLOT, 0, frame, &[0x05]).unwrap();
            assert_eq!(turn.payload.game_frame_count, frame);
        }
    }

    #[test]
    fn binds_to_the_authorized_slot() {
        // A keep-alive carries no slot of its own, and the turn never does on the
        // wire either — the relay always stamps the authorized slot.
        for slot in [0u8, 1, 7, 255] {
            let turn = validate_turn(SlotId(slot), 0, None, &[0x05]).unwrap();
            assert_eq!(turn.payload.slot, u32::from(slot));
        }
    }

    #[test]
    fn forwards_a_fixed_length_command_verbatim() {
        // Build (0x0C) is 8 bytes including the opcode.
        let build = [0x0C, 1, 2, 3, 4, 5, 6, 7];
        let turn = validated(&build);
        assert_eq!(&turn.payload.commands[..], &build);
        assert_eq!(turn.stripped_control, 0);
    }

    #[test]
    fn forwards_a_variable_length_command_verbatim() {
        // Classic select (0x09): 2 + 2 * count. count = 2 → 6 bytes.
        let select = [0x09, 2, 0xAA, 0xBB, 0xCC, 0xDD];
        let turn = validated(&select);
        assert_eq!(&turn.payload.commands[..], &select);
    }

    #[test]
    fn forwards_a_run_of_commands_in_order() {
        // KeepAlive (1) + Vision (3) + Build (8) back to back.
        let mut stream = Vec::new();
        stream.extend_from_slice(&[0x05]);
        stream.extend_from_slice(&[0x0D, 0, 1]);
        stream.extend_from_slice(&[0x0C, 1, 2, 3, 4, 5, 6, 7]);

        let turn = validated(&stream);
        assert_eq!(&turn.payload.commands[..], &stream[..]);
        assert_eq!(turn.stripped_control, 0);
    }

    #[test]
    fn strips_relay_owned_pacing_commands() {
        // Latency (0x55, 2), SetTurnRate (0x5f, 2), DynamicTurnRate (0x66, 4).
        for control in [vec![0x55, 0x00], vec![0x5f, 0x00], vec![0x66, 0, 0, 0]] {
            let turn = validated(&control);
            assert!(turn.payload.commands.is_empty(), "{control:?} not stripped");
            assert_eq!(turn.stripped_control, 1);
        }
    }

    #[test]
    fn strips_replay_playback_commands_from_a_live_turn() {
        // ReplaySetSpeed (0x56, 10), ReplaySeek (0x5d, 5), and the leave marker
        // (0x57, 2). These belong only in a replay session; a live turn drops
        // them. 0x56/0x5d classify as ordinary fixed-length commands, so without
        // this they would otherwise be forwarded.
        for control in [
            vec![0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            vec![0x5d, 0, 0, 0, 0],
            vec![0x57, 0x00],
        ] {
            let turn = validated(&control);
            assert!(turn.payload.commands.is_empty(), "{control:?} not stripped");
            assert_eq!(turn.stripped_control, 1);
        }
    }

    #[test]
    fn strips_control_but_keeps_surrounding_gameplay() {
        // KeepAlive, then a client-injected latency change, then a Build. Only the
        // latency command is removed; the rest forwards untouched.
        let mut stream = Vec::new();
        stream.extend_from_slice(&[0x05]);
        stream.extend_from_slice(&[0x55, 0x02]);
        stream.extend_from_slice(&[0x0C, 1, 2, 3, 4, 5, 6, 7]);

        let turn = validated(&stream);

        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x05]);
        expected.extend_from_slice(&[0x0C, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(&turn.payload.commands[..], &expected[..]);
        assert_eq!(turn.stripped_control, 1);
    }

    #[test]
    fn a_turn_that_is_all_control_strips_to_empty() {
        let stream = [0x55, 0x02, 0x66, 0, 0, 0, 0x57, 0x00];
        let turn = validated(&stream);
        assert!(turn.payload.commands.is_empty());
        assert_eq!(turn.stripped_control, 3);
    }

    #[test]
    fn rejects_an_unknown_opcode() {
        // 0x00 is a hole in the table; the whole turn is refused.
        let err = validate_turn(SLOT, 0, None, &[0x00]).unwrap_err();
        assert_eq!(
            err,
            ValidationError::UnknownOpcode {
                offset: 0,
                opcode: 0x00
            }
        );
    }

    #[test]
    fn rejects_unsupported_save_load() {
        // Save/load (0x06/0x07) are real multiplayer commands, but ShieldBattery
        // deliberately doesn't support saving or loading games, so the command
        // table doesn't model them and the validator refuses the turn. A product
        // decision to revisit only if SB brings save/load back — not a claim that
        // the commands are inherently invalid.
        for opcode in [0x06u8, 0x07] {
            let err = validate_turn(SLOT, 0, None, &[opcode]).unwrap_err();
            assert_eq!(err, ValidationError::UnknownOpcode { offset: 0, opcode });
        }
    }

    #[test]
    fn reports_the_offset_of_a_bad_opcode_mid_stream() {
        // A valid KeepAlive, then garbage: the error points at the garbage.
        let stream = [0x05, 0xFF];
        let err = validate_turn(SLOT, 0, None, &stream).unwrap_err();
        assert_eq!(
            err,
            ValidationError::UnknownOpcode {
                offset: 1,
                opcode: 0xFF
            }
        );
    }

    #[test]
    fn rejects_a_fixed_command_that_overruns_the_turn() {
        // Build claims 8 bytes but only 4 are present.
        let err = validate_turn(SLOT, 0, None, &[0x0C, 1, 2, 3]).unwrap_err();
        assert_eq!(
            err,
            ValidationError::Truncated {
                offset: 0,
                opcode: 0x0C
            }
        );
    }

    #[test]
    fn rejects_a_variable_command_missing_its_count_byte() {
        // Classic select with no count byte at all.
        let err = validate_turn(SLOT, 0, None, &[0x09]).unwrap_err();
        assert_eq!(
            err,
            ValidationError::Truncated {
                offset: 0,
                opcode: 0x09
            }
        );
    }

    #[test]
    fn rejects_a_variable_command_whose_count_overruns_the_turn() {
        // Select claims 3 entries (2 + 2*3 = 8 bytes) but only carries one.
        let err = validate_turn(SLOT, 0, None, &[0x09, 3, 0xAA, 0xBB]).unwrap_err();
        assert_eq!(
            err,
            ValidationError::Truncated {
                offset: 0,
                opcode: 0x09
            }
        );
    }

    #[test]
    fn a_zero_entry_variable_command_is_valid() {
        // count = 0 → just opcode + count byte, and it forwards verbatim.
        let turn = validated(&[0x09, 0]);
        assert_eq!(&turn.payload.commands[..], &[0x09, 0]);
    }

    /// The invariants the validator owes the rest of the relay on *any* input,
    /// asserted for one turn. Shared by the randomized tests below; the
    /// coverage-guided fuzz target (`relay/fuzz/fuzz_targets/validate_turn.rs`)
    /// asserts the same set.
    fn assert_validator_invariants(commands: &[u8]) {
        match validate_turn(SLOT, 7, Some(41), commands) {
            Ok(validated) => {
                // Binding: everything but the command bytes comes from the
                // caller, never from the attacker-controlled input.
                assert_eq!(validated.payload.slot, u32::from(SLOT.0));
                assert_eq!(validated.payload.seq, 7);
                assert_eq!(validated.payload.game_frame_count, Some(41));
                assert_eq!(validated.payload.buffer_directive, None);
                // No amplification, and stripping is the only rewrite.
                assert!(validated.payload.commands.len() <= commands.len());
                if validated.stripped_control == 0 {
                    assert_eq!(&validated.payload.commands[..], commands);
                }
                // Fixpoint: what the relay forwards must itself validate
                // clean, byte-for-byte — a peer re-parsing forwarded bytes
                // must never disagree with the ingress validator.
                let again = validate_turn(SLOT, 7, Some(41), &validated.payload.commands)
                    .expect("sanitized output must re-validate");
                assert_eq!(again.stripped_control, 0, "sanitizing must be complete");
                assert_eq!(again.payload.commands, validated.payload.commands);
            }
            Err(
                ValidationError::UnknownOpcode { offset, .. }
                | ValidationError::Truncated { offset, .. },
            ) => {
                // Attribution: a rejection names real bytes of the turn.
                assert!(offset < commands.len());
            }
        }
    }

    /// A tiny deterministic xorshift so the randomized tests need no dev
    /// dependency and every run covers the same inputs (a failure reproduces).
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn byte(&mut self) -> u8 {
            (self.next() >> 32) as u8
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    #[test]
    fn random_bytes_never_panic_and_uphold_the_invariants() {
        // Pure noise: almost every case rejects at the first unknown opcode,
        // but the walk to that rejection must stay in bounds and attributed.
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..20_000 {
            let len = rng.below(64) as usize;
            let commands: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
            assert_validator_invariants(&commands);
        }
    }

    #[test]
    fn random_command_streams_never_panic_and_uphold_the_invariants() {
        // Structured noise: streams assembled *from the command table* (with
        // occasional corruption), so the deep paths — variable lengths, strip
        // sets, multi-command walks, mid-stream truncation — are all reached
        // rather than dying on byte one like pure noise does.
        let mut rng = Rng(0x0123_4567_89AB_CDEF);
        for _ in 0..20_000 {
            let mut commands = Vec::new();
            for _ in 0..rng.below(6) {
                let opcode = rng.byte();
                match classify(CommandId(opcode)) {
                    Some(CommandLength::Fixed(n)) => {
                        commands.push(opcode);
                        for _ in 1..n {
                            commands.push(rng.byte());
                        }
                    }
                    Some(CommandLength::Variable { stride }) => {
                        let count = rng.below(5) as u8;
                        commands.push(opcode);
                        commands.push(count);
                        for _ in 0..(usize::from(stride) * usize::from(count)) {
                            commands.push(rng.byte());
                        }
                    }
                    // An opcode the table can't classify: include it sometimes
                    // (the whole turn must reject), skip it otherwise.
                    None => {
                        if rng.below(4) == 0 {
                            commands.push(opcode);
                        }
                    }
                }
            }
            // Sometimes truncate the tail, corrupting the final command's
            // declared length mid-stream.
            if rng.below(3) == 0 && !commands.is_empty() {
                let cut = rng.below(commands.len() as u64) as usize;
                commands.truncate(cut);
            }
            assert_validator_invariants(&commands);
        }
    }
}
