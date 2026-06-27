//! SC:R turn-command table: `command_lengths` + variable-length rules.
//!
//! The validating relay parses native SC:R command bytes to:
//! bounds-check every command against the length table + var-length rules, bind
//! it to the sender's slot, allowlist live command ids, and strip
//! client-originated control commands (`0x55` / `0x66` / `0x5f` / `0x57` /
//! replay cmds). The client crate needs the same table to frame turns, so it
//! lives here and is shared.
//!
//! [`command_name`]s come from the `broodrep` replay parser; the
//! `0x37` `Sync` name is from `screp`. Save/load (`0x06`/`0x07`) are
//! variable-length, null-terminated-string commands that *can* appear in a live
//! multiplayer game, but ShieldBattery deliberately does not support saving or
//! loading games right now — there is no load path through SB, and in-game save
//! is effectively unused (and likely already broken) — so they are rejected here
//! (`None`) rather than parsed. Bringing them back means modeling their
//! null-terminated string form, which adds attacker-facing parse surface; make
//! that trade only if SB restores save/load.

use serde::{Deserialize, Serialize};

/// A single SC:R turn-command opcode (the leading byte of a command).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommandId(pub u8);

/// How long a command is, given its opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandLength {
    /// A fixed total length in bytes, including the opcode.
    Fixed(u16),
    /// A count-prefixed command: the second byte is an entry count and the total
    /// length is `2 + stride * count` (opcode + count byte + `count` entries of
    /// `stride` bytes each). Used by the six SC:R select opcodes.
    Variable { stride: u16 },
}

/// Fixed command lengths indexed by opcode, from the live `process_commands`
/// dispatcher (see module docs). `0` marks an opcode the live dispatcher rejects,
/// or that we reject (save/load `0x06`/`0x07`). The six variable-length select
/// opcodes (`0x09`–`0x0b`, `0x63`–`0x65`) read `0` here and are resolved by
/// [`classify`] instead.
#[rustfmt::skip]
static FIXED_LEN: [u8; 0x68] = [
    //    0x_0  0x_1  0x_2  0x_3  0x_4  0x_5  0x_6  0x_7  0x_8  0x_9  0x_a  0x_b  0x_c  0x_d  0x_e  0x_f
    /*0x00*/ 0,    0,    0,    0,    0,    1,    0,    0,    1,    0,    0,    0,    8,    3,    5,    2,
    /*0x10*/ 1,    1,    5,    3,   10,   11,    0,    0,    1,    1,    2,    1,    1,    1,    2,    3,
    /*0x20*/ 3,    2,    2,    3,    0,    2,    2,    1,    2,    3,    1,    2,    2,    2,    1,    5,
    /*0x30*/ 2,    1,    2,    1,    1,    3,    1,    7,    0,    0,    0,    0,    0,    0,    0,    0,
    /*0x40*/ 0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    /*0x50*/ 0,    0,    0,    0,    0,    2,   10,    2,    5,    0,    1,    0,   82,    5,    0,    2,
    /*0x60*/ 12,  13,    5,    0,    0,    0,    4,    0,
];

/// Classify an opcode into its length rule, or `None` if the opcode is not a
/// known SC:R command.
pub fn classify(id: CommandId) -> Option<CommandLength> {
    match id.0 {
        // Classic select / shift-select / shift-deselect (2-byte unit ids).
        0x09..=0x0B => Some(CommandLength::Variable { stride: 2 }),
        // SC:R extended select variants (4-byte unit ids).
        0x63..=0x65 => Some(CommandLength::Variable { stride: 4 }),
        op => match FIXED_LEN.get(op as usize).copied().unwrap_or(0) {
            0 => None,
            n => Some(CommandLength::Fixed(u16::from(n))),
        },
    }
}

/// Total serialized length, in bytes, of the command at the start of `buf`
/// (opcode included), or `None` if the opcode is invalid or `buf` is too short
/// to determine the length of a variable-length command.
///
/// This never reads past what it returns and never panics, so it is safe to run
/// directly on attacker-controlled bytes on the relay. The caller is still
/// responsible for checking the returned length against the bytes that actually
/// remain in the turn.
pub fn command_length(buf: &[u8]) -> Option<usize> {
    let id = CommandId(*buf.first()?);
    match classify(id)? {
        CommandLength::Fixed(n) => Some(usize::from(n)),
        CommandLength::Variable { stride } => {
            let count = usize::from(*buf.get(1)?);
            Some(2 + usize::from(stride) * count)
        }
    }
}

/// Human-readable name for an opcode, for logging/correlation, or
/// `None` for invalid opcodes and a few unnamed control/rare commands (`0x08`
/// restart, `0x56`, `0x5d`, `0x5f`, `0x66`).
///
/// Names are from the `broodrep` replay parser (`../broodrep`), except `0x37`
/// (`Sync`), which is from `screp`.
pub fn command_name(id: CommandId) -> Option<&'static str> {
    Some(match id.0 {
        0x05 => "KeepAlive",
        0x09 => "Select",
        0x0A => "SelectAdd",
        0x0B => "SelectRemove",
        0x0C => "Build",
        0x0D => "Vision",
        0x0E => "Alliance",
        0x0F => "GameSpeed",
        0x10 => "Pause",
        0x11 => "Resume",
        0x12 => "Cheat",
        0x13 => "Hotkey",
        0x14 => "RightClick",
        0x15 => "TargetedOrder",
        0x18 => "CancelBuild",
        0x19 => "CancelMorph",
        0x1A => "Stop",
        0x1B => "CarrierStop",
        0x1C => "ReaverStop",
        0x1D => "OrderNothing",
        0x1E => "ReturnCargo",
        0x1F => "Train",
        0x20 => "CancelTrain",
        0x21 => "Cloak",
        0x22 => "Decloak",
        0x23 => "UnitMorph",
        0x25 => "Unsiege",
        0x26 => "Siege",
        0x27 => "TrainFighter",
        0x28 => "UnloadAll",
        0x29 => "Unload",
        0x2A => "MergeArchon",
        0x2B => "HoldPosition",
        0x2C => "Burrow",
        0x2D => "Unburrow",
        0x2E => "CancelNuke",
        0x2F => "LiftOff",
        0x30 => "Tech",
        0x31 => "CancelTech",
        0x32 => "Upgrade",
        0x33 => "CancelUpgrade",
        0x34 => "CancelAddon",
        0x35 => "BuildingMorph",
        0x36 => "Stim",
        0x37 => "Sync",
        0x55 => "Latency",
        0x57 => "LeaveGame",
        0x58 => "MinimapPing",
        0x5A => "MergeDarkArchon",
        0x5C => "Chat",
        0x60 => "RightClick121",
        0x61 => "TargetedOrder121",
        0x62 => "Unload121",
        0x63 => "Select121",
        0x64 => "SelectAdd121",
        0x65 => "SelectRemove121",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_fixed_lengths() {
        // Spot-checks of the classic command set, length-verified above.
        for (op, len) in [
            (0x0C, 8),  // Build
            (0x0D, 3),  // Vision
            (0x0E, 5),  // Alliance
            (0x13, 3),  // Hotkey
            (0x14, 10), // Right Click
            (0x15, 11), // Targeted Order
            (0x37, 7),  // Sync (diverges from the replay-skip table, which says 1)
            // SC:R extended-unit-id variants.
            (0x60, 12), // Right Click (extended)
            (0x61, 13), // Targeted Order (extended)
            // Largest fixed command + the last valid opcode.
            (0x5C, 82),
            (0x66, 4),
        ] {
            assert_eq!(command_length(&[op]), Some(len), "opcode {op:#04x}");
            assert_eq!(
                classify(CommandId(op)),
                Some(CommandLength::Fixed(len as u16))
            );
        }
    }

    #[test]
    fn variable_lengths() {
        // Classic select: 2 + 2 * count.
        assert_eq!(
            classify(CommandId(0x09)),
            Some(CommandLength::Variable { stride: 2 })
        );
        assert_eq!(command_length(&[0x09, 0]), Some(2));
        assert_eq!(command_length(&[0x0A, 3]), Some(8));
        assert_eq!(command_length(&[0x0B, 12]), Some(26));
        // SC:R extended select: 2 + 4 * count.
        assert_eq!(
            classify(CommandId(0x63)),
            Some(CommandLength::Variable { stride: 4 })
        );
        assert_eq!(command_length(&[0x63, 3]), Some(14));
        assert_eq!(command_length(&[0x65, 12]), Some(50));
    }

    #[test]
    fn invalid_opcodes_are_rejected() {
        // Holes inside the table, opcodes the live dispatcher rejects (0x24) or
        // that we reject (0x06/0x07 save/load), the gap above 0x66, and
        // out-of-array opcodes.
        for op in [
            0x00, 0x04, 0x06, 0x07, 0x16, 0x17, 0x24, 0x38, 0x40, 0x54, 0x59, 0x67, 0xFF,
        ] {
            assert_eq!(command_length(&[op]), None, "opcode {op:#04x}");
            assert_eq!(classify(CommandId(op)), None, "opcode {op:#04x}");
        }
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert_eq!(command_length(&[]), None); // no opcode
        assert_eq!(command_length(&[0x09]), None); // variable cmd missing its count byte
        assert_eq!(command_length(&[0x63]), None);
    }

    #[test]
    fn every_named_opcode_is_a_valid_command() {
        // A name must never be attached to an opcode the binary rejects, or the
        // two sources have drifted.
        for op in 0u16..=0xFF {
            let id = CommandId(op as u8);
            if let Some(name) = command_name(id) {
                assert!(
                    classify(id).is_some(),
                    "named opcode {op:#04x} ({name}) is not valid"
                );
            }
        }
    }

    #[test]
    fn classify_and_command_length_agree() {
        // The single-byte opcode is enough to resolve every fixed command; the
        // two derivations must never disagree about validity.
        for op in 0u16..=0xFF {
            let op = op as u8;
            match classify(CommandId(op)) {
                Some(CommandLength::Fixed(n)) => {
                    assert_eq!(
                        command_length(&[op]),
                        Some(usize::from(n)),
                        "opcode {op:#04x}"
                    );
                }
                Some(CommandLength::Variable { .. }) => {
                    assert!(
                        command_length(&[op]).is_none(),
                        "opcode {op:#04x} needs a count byte"
                    );
                    assert!(command_length(&[op, 0]).is_some(), "opcode {op:#04x}");
                }
                None => assert_eq!(command_length(&[op]), None, "opcode {op:#04x}"),
            }
        }
    }
}
