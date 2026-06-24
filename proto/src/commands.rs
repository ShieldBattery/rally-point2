//! SC:R turn-command table: `command_lengths` + variable-length rules.
//!
//! The validating relay (**D10**) parses native SC:R command bytes to:
//! bounds-check every command against the length table + var-length rules, bind
//! it to the sender's slot, allowlist live command ids, and strip
//! client-originated control commands (`0x55` / `0x66` / `0x5f` / `0x57` /
//! replay cmds). The client crate needs the same table to frame turns, so it
//! lives here and is shared.
//!
//! TODO(phase-0): port the `command_lengths` table and the variable-length
//! parsing rules from the SC:R binary via samase (`../samase_scarf`) — see build
//! plan Phase 0 and guide §5.6/§5.7. Deliberately left as types-only until
//! ported against the binary so we never ship fabricated lengths. The parser is
//! attacker-facing and must be fuzzed (**D10**, Phase 6).

use serde::{Deserialize, Serialize};

/// A single SC:R turn-command opcode (the leading byte of a command).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommandId(pub u8);

/// How long a command is, given its opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandLength {
    /// A fixed total length in bytes, including the opcode.
    Fixed(u16),
    /// Length depends on the command body (e.g. a count-prefixed payload) and is
    /// resolved by a per-opcode rule while parsing.
    Variable,
}
