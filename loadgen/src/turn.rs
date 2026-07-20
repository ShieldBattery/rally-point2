//! The synthetic turn stream: a validator-clean SC:R command stream every
//! generated turn carries, shaped exactly like a live game's.
//!
//! Each turn is one 7-byte `0x37` sync command followed by `0x05` keepalive
//! padding to a target byte size. The sync command carries a ring nibble, a hash
//! kind locked to the ring's parity, and a 16-bit `hash16` derived from a
//! per-session seed and the turn ordinal — so every player in one session emits
//! byte-identical hashes and the relay's desync comparator sees a healthy game.
//! A player configured to diverge XORs its `hash16` from a chosen ordinal onward,
//! which is what the `--desync-fraction` scenario exercises.
//!
//! The `0x37` layout mirrors the relay's own comparator (`relay/src/consensus.rs`):
//! byte `[0]` is the opcode, `[1]` is `(ring << 4) | kind` with `kind` 1 on even
//! rings and 2 on odd rings, `[2:3]` is `hash16` little-endian (the only bytes the
//! comparator reads), and `[4..7)` is per-sender fog/vision data the comparator
//! ignores.

/// The SC:R sync-command opcode: a 7-byte command emitted once per network turn
/// while the game's sync check is active.
const SYNC_OPCODE: u8 = 0x37;
/// The total length of a `0x37` sync command. This is the minimum turn size; a
/// `--turn-bytes` below it yields a bare sync command with no padding.
const SYNC_LEN: usize = 7;
/// A one-byte keepalive command, used as padding to reach the target turn size.
/// Each is an independently valid command the relay's validator accepts.
const KEEPALIVE: u8 = 0x05;
/// The sync command's ring nibble is a 16-entry ring, advancing `+1 mod 16` per
/// turn.
const RING_MODULUS: u8 = 16;
/// The `0x37` low nibble's hash kind on an even ring (the per-unit hash).
const KIND_UNITS: u8 = 1;
/// The `0x37` low nibble's hash kind on an odd ring (the game-header/rng hash).
const KIND_HEADER: u8 = 2;
/// The value a diverging player XORs into its `hash16` to force the relay's
/// comparator to observe a disagreement. Any nonzero constant works — this just
/// has to differ from the agreed hash.
const DESYNC_HASH_XOR: u16 = 0x5A5A;
/// The turn ordinal a diverging player starts perturbing its hash from. Past the
/// ring's first wrap (~turn 15 in a real game the ring starts at 1), so the
/// startup-burst window agrees before the divergence begins.
pub const DESYNC_FROM_ORDINAL: u64 = 8;

/// The `(ring << 4) | kind` byte for a ring index: `kind` is 1 on even rings and
/// 2 on odd rings, so the byte walks the fixed 16-value sequence `0x01, 0x12,
/// 0x21, 0x32, …, 0xF2`.
fn ring_kind_byte(ring: u8) -> u8 {
    let kind = if ring.is_multiple_of(2) {
        KIND_UNITS
    } else {
        KIND_HEADER
    };
    (ring << 4) | kind
}

/// The ring index a turn ordinal uses: the ring starts at 1 for the first turn
/// (matching the game's sync-enable burst) and advances `+1 mod 16` per turn.
fn ring_for_ordinal(ordinal: u64) -> u8 {
    ((ordinal + 1) % u64::from(RING_MODULUS)) as u8
}

/// A deterministic 16-bit hash for `(session_seed, ordinal)`, so every player in
/// a session produces the identical value for a given ordinal. This is not a real
/// game checksum — it only needs to be stable per session and to vary across
/// ordinals and sessions, which a SplitMix-style integer mix gives cheaply.
fn hash16(session_seed: u64, ordinal: u64) -> u16 {
    let mut x = session_seed ^ ordinal.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x ^= x >> 33;
    x = x.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    x ^= x >> 33;
    x as u16
}

/// Builds one player's per-turn command stream for a session.
///
/// All players in a session share a `session_seed`, so their hashes agree turn
/// for turn — unless a player is given `desync_from`, in which case it perturbs
/// its `hash16` from that ordinal onward (the deliberate-divergence scenario).
#[derive(Debug, Clone)]
pub struct TurnBuilder {
    session_seed: u64,
    turn_bytes: usize,
    /// When set, this player XORs its `hash16` with [`DESYNC_HASH_XOR`] on every
    /// turn at or past this ordinal.
    desync_from: Option<u64>,
}

impl TurnBuilder {
    /// A builder for a player that agrees with the rest of its session.
    pub fn new(session_seed: u64, turn_bytes: usize) -> Self {
        Self {
            session_seed,
            turn_bytes,
            desync_from: None,
        }
    }

    /// A builder for the one player in a session chosen to diverge: it agrees
    /// through `from - 1` and perturbs its hash from ordinal `from` onward.
    pub fn desyncing(session_seed: u64, turn_bytes: usize, from: u64) -> Self {
        Self {
            session_seed,
            turn_bytes,
            desync_from: Some(from),
        }
    }

    /// The `hash16` this player emits for `ordinal` — the shared value, XOR-ed
    /// with [`DESYNC_HASH_XOR`] once a diverging player reaches its start ordinal.
    fn hash_for(&self, ordinal: u64) -> u16 {
        let base = hash16(self.session_seed, ordinal);
        match self.desync_from {
            Some(from) if ordinal >= from => base ^ DESYNC_HASH_XOR,
            _ => base,
        }
    }

    /// The command-stream bytes for turn `ordinal`: a 7-byte `0x37` sync command
    /// then `0x05` keepalive padding to `--turn-bytes`. Never shorter than the
    /// sync command itself.
    pub fn turn(&self, ordinal: u64) -> Vec<u8> {
        let ring = ring_for_ordinal(ordinal);
        let hash = self.hash_for(ordinal);
        let [hash_lo, hash_hi] = hash.to_le_bytes();

        let mut out = Vec::with_capacity(self.turn_bytes.max(SYNC_LEN));
        // Bytes [4..7) are per-sender fog/vision data the comparator never reads.
        out.extend_from_slice(&[SYNC_OPCODE, ring_kind_byte(ring), hash_lo, hash_hi, 0, 0, 0]);
        while out.len() < self.turn_bytes {
            out.push(KEEPALIVE);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical 16-value ring/kind sequence the `0x37` command cycles
    /// through, from `relay/src/consensus.rs`'s layout note.
    const DOCUMENTED_RING_BYTES: [u8; 16] = [
        0x01, 0x12, 0x21, 0x32, 0x41, 0x52, 0x61, 0x72, 0x81, 0x92, 0xA1, 0xB2, 0xC1, 0xD2, 0xE1,
        0xF2,
    ];

    #[test]
    fn ring_kind_byte_matches_the_documented_sequence() {
        for (ring, &expected) in DOCUMENTED_RING_BYTES.iter().enumerate() {
            assert_eq!(ring_kind_byte(ring as u8), expected, "ring {ring}");
        }
    }

    #[test]
    fn per_turn_ring_starts_at_one_and_advances_mod_16() {
        let builder = TurnBuilder::new(0xABCD, 16);
        // Over 20+ turns the ring nibble follows ring = (1 + ordinal) mod 16, so
        // byte [1] walks the documented sequence starting at its ring-1 entry.
        for ordinal in 0..40u64 {
            let expected_ring = ((ordinal + 1) % 16) as usize;
            let turn = builder.turn(ordinal);
            assert_eq!(turn[0], SYNC_OPCODE);
            assert_eq!(
                turn[1], DOCUMENTED_RING_BYTES[expected_ring],
                "ordinal {ordinal}"
            );
        }
    }

    #[test]
    fn all_players_in_a_session_emit_identical_hashes() {
        let seed = 0x1234_5678_9ABC_DEF0;
        let a = TurnBuilder::new(seed, 16);
        let b = TurnBuilder::new(seed, 24);
        for ordinal in 0..50u64 {
            // The hash16 bytes ([2:3]) must match even when the padded sizes differ.
            assert_eq!(
                a.turn(ordinal)[2..4],
                b.turn(ordinal)[2..4],
                "ordinal {ordinal}"
            );
        }
    }

    #[test]
    fn different_sessions_produce_different_hash_streams() {
        let a = TurnBuilder::new(1, 16);
        let b = TurnBuilder::new(2, 16);
        // At least one ordinal must differ (they are near-certain to differ often).
        let any_different = (0..64u64).any(|o| a.turn(o)[2..4] != b.turn(o)[2..4]);
        assert!(any_different);
    }

    #[test]
    fn a_desync_player_agrees_before_and_diverges_after_its_start_ordinal() {
        let seed = 0xDEAD_BEEF_CAFE_F00D;
        let honest = TurnBuilder::new(seed, 16);
        let diverging = TurnBuilder::desyncing(seed, 16, DESYNC_FROM_ORDINAL);

        for ordinal in 0..DESYNC_FROM_ORDINAL {
            assert_eq!(
                honest.turn(ordinal)[2..4],
                diverging.turn(ordinal)[2..4],
                "ordinal {ordinal} should still agree"
            );
        }
        for ordinal in DESYNC_FROM_ORDINAL..(DESYNC_FROM_ORDINAL + 16) {
            assert_ne!(
                honest.turn(ordinal)[2..4],
                diverging.turn(ordinal)[2..4],
                "ordinal {ordinal} should diverge"
            );
        }
    }

    #[test]
    fn padding_reaches_turn_bytes_and_the_floor_is_the_sync_command() {
        let builder = TurnBuilder::new(7, 32);
        let turn = builder.turn(3);
        assert_eq!(turn.len(), 32);
        // Everything past the 7-byte sync command is keepalive padding.
        assert!(turn[SYNC_LEN..].iter().all(|&b| b == KEEPALIVE));

        // A target below the sync command's own length can't truncate it.
        let tiny = TurnBuilder::new(7, 4);
        assert_eq!(tiny.turn(0).len(), SYNC_LEN);
    }

    #[test]
    fn every_generated_turn_validates_clean_on_the_relay() {
        // The relay's ingress validator is what each turn actually faces on the
        // wire: every generated turn must pass with nothing stripped, and the
        // forwarded bytes must be identical (the fixpoint the validator promises
        // when stripped_control is 0).
        use rally_point_proto::ids::SlotId;
        use rally_point_proto::messages::Payload;
        use rally_point_relay::validation::validate_turn;

        let honest = TurnBuilder::new(0x99, 24);
        let diverging = TurnBuilder::desyncing(0x99, 24, DESYNC_FROM_ORDINAL);
        for ordinal in 0..64u64 {
            for builder in [&honest, &diverging] {
                let commands = builder.turn(ordinal);
                let payload = Payload {
                    seq: 0,
                    slot: u32::MAX,
                    commands: commands.clone().into(),
                    game_frame_count: Some(ordinal as u32),
                    buffer_directive: None,
                };
                let validated = validate_turn(SlotId(0), payload)
                    .expect("a generated turn must validate on the relay");
                assert_eq!(
                    validated.stripped_control, 0,
                    "no command should be stripped from a generated turn (ordinal {ordinal})"
                );
                assert_eq!(&validated.payload.commands[..], &commands[..]);
            }
        }
    }
}
