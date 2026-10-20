//! Lobby commands across reconnects: the commands this client authored, kept
//! so every new control stream can carry them again, paced so a relay admits
//! them all, and the per-author record that keeps a command another member
//! authored from reaching the game twice.
//!
//! A control-stream write carries no acknowledgment. A command written onto a
//! connection whose path has silently died succeeds locally and is lost with
//! the connection, which only times out seconds later; nothing reports it. So
//! the driver numbers each command it authors with an origin seq and writes
//! every retained command again, oldest first, on each new control stream. A
//! relay drops a seq it already accepted from this author and accepts any
//! other whenever it arrives, so each command reaches every member at most
//! once, eventually, but not necessarily in the order it was authored: one the
//! relay's rate cap refused the first time lands on a later re-send, after
//! commands authored behind it. The channel's one consumer does not need the
//! order: a ShieldBattery game applies only the host's single game-init record
//! and drops every other lobby command.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use rally_point_proto::ids::SlotId;
use rally_point_proto::lobby;
use rally_point_proto::messages::LobbyCommand;
use rally_point_transport::control::{ControlSendError, send_control_lobby};
use rally_point_transport::noq;
use tokio::time::Instant;

/// The pacer's burst: half the relay's per-slot burst.
///
/// The relay meters arrivals, the pacer meters writes, and the two differ by
/// however much the path's delay varies (an ordered stream can hold a run of
/// commands back and release them together). Writes paced to burst `b` and one
/// per `r` arrive inside the relay's burst `B` and one per `R` whenever
/// `r >= R` and `b + jitter / r <= B`. Half the burst at half the rate
/// tolerates 16 × 400 ms = 6.4 s of jitter. A path that stalls longer, but not
/// the 10 s it takes the idle timeout to end it, can release a run the relay
/// partly rate-drops; those commands land on the next reconnect's re-send, and
/// nothing behind them waits on them.
pub(super) const PACE_BURST: u32 = lobby::RATE_BURST / 2;

/// The pacer's refill interval: twice the relay's, so half its rate. See
/// [`PACE_BURST`].
pub(super) const PACE_REFILL: Duration =
    Duration::from_nanos(lobby::RATE_REFILL.as_nanos() as u64 * 2);

/// Every lobby command this client authored in the session, oldest first, each
/// stamped with its origin seq, and the pacing every write of them goes
/// through.
///
/// Kept for the whole session rather than released at some milestone, because
/// nothing this client observes proves every member applied a command: neither
/// its own game loop starting (the host's can start before the game-init it
/// wrote reached anyone, and that is exactly the command a dead link loses) nor
/// the relay's session-start directive (which only says every member connected,
/// and precedes setup). Holding them costs a few re-sent frames per reconnect,
/// which every relay that already has them drops, and so does every receiving
/// client that already handed them to its game.
///
/// Retention is always the whole history from seq 0: any command a relay has
/// not accepted yet may be the one a member is waiting on. It stops at the
/// relay's whole-session lobby log ceiling rather than dropping the oldest:
/// past that ceiling no relay accepts another command, so one authored there
/// is dropped unsent.
///
/// Every write, first sends and re-sends alike, takes a token from one pacer
/// that lives for the session, so the commands a relay must accept never
/// outrun its rate cap, not even when a reconnect re-sends a history longer
/// than the cap's burst to a relay that has never seen it.
pub(super) struct LobbyOutbox {
    commands: Vec<LobbyCommand>,
    bytes: usize,
    pacer: LobbyPacer,
}

impl LobbyOutbox {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            commands: Vec::new(),
            bytes: 0,
            pacer: LobbyPacer::new(now),
        }
    }

    /// Stamps `bytes` with the next origin seq and queues the command behind
    /// every earlier one. Returns `false`, keeping nothing, when the command
    /// would take retention past what any relay logs for a whole session. The
    /// `slot` is left `0`: the relay stamps the authenticated slot and ignores
    /// the client's.
    pub(super) fn author(&mut self, bytes: Vec<u8>) -> bool {
        if self.commands.len() >= lobby::LOG_MAX_COMMANDS
            || self.bytes.saturating_add(bytes.len()) > lobby::LOG_MAX_BYTES
        {
            tracing::warn!(
                commands = self.commands.len(),
                bytes = self.bytes,
                "lobby command past the relay's session log ceiling; dropping it unsent"
            );
            return false;
        }
        self.bytes += bytes.len();
        let seq = self.commands.len() as u64;
        self.commands.push(LobbyCommand {
            slot: 0,
            payload: bytes.into(),
            seq: Some(seq),
        });
        true
    }

    /// The retained commands, oldest first: the order they are written in.
    #[cfg(test)]
    pub(super) fn retained(&self) -> impl Iterator<Item = &LobbyCommand> {
        self.commands.iter()
    }

    /// When the next unwritten command may go out, given that this stream has
    /// carried the first `sent`; `None` when nothing is left to write.
    pub(super) fn next_due(&self, sent: usize) -> Option<Instant> {
        (sent < self.commands.len()).then(|| self.pacer.next_token_at())
    }

    /// Writes the commands this stream has not carried up `control_send`,
    /// oldest first, as far as the pacer allows, advancing `sent` (how many
    /// this stream has carried) past each. A failed write leaves `sent` short
    /// of it; the next stream starts over from the first command anyway.
    pub(super) async fn send_due(
        &mut self,
        control_send: &mut noq::SendStream,
        sent: &mut usize,
    ) -> Result<(), ControlSendError> {
        let now = Instant::now();
        while let Some(command) = self.commands.get(*sent) {
            if !self.pacer.try_take(now) {
                break;
            }
            send_control_lobby(control_send, command.clone()).await?;
            *sent += 1;
        }
        Ok(())
    }
}

/// A token bucket over this client's lobby writes, [`PACE_BURST`] deep and
/// regaining one token per [`PACE_REFILL`]. Starts full, as the relay's does.
pub(super) struct LobbyPacer {
    tokens: u32,
    last_refill: Instant,
}

impl LobbyPacer {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            tokens: PACE_BURST,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        let whole = u32::try_from(elapsed.as_nanos() / PACE_REFILL.as_nanos()).unwrap_or(u32::MAX);
        self.tokens = self.tokens.saturating_add(whole).min(PACE_BURST);
        if self.tokens == PACE_BURST {
            self.last_refill = now;
        } else {
            self.last_refill += PACE_REFILL * whole;
        }
    }

    pub(super) fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    /// The earliest instant a token is available.
    pub(super) fn next_token_at(&self) -> Instant {
        if self.tokens > 0 {
            self.last_refill
        } else {
            self.last_refill + PACE_REFILL
        }
    }
}

/// Per authoring slot, every origin seq of a lobby command already handed to
/// the game.
///
/// The relay replays its whole lobby log to a member every time that member's
/// control stream registers, so a client that reconnects is sent every command
/// again; and a relay that took the session over without ever having seen an
/// author's earlier commands accepts that author's re-send as new. Dropping a
/// command whose seq is already recorded keeps both from reaching the game
/// twice. A set rather than a high-water mark because commands need not arrive
/// in the author's order: one a relay rate-dropped arrives after later ones.
/// Bounded like the relay's log, whose ceiling caps how many commands a
/// session ever carries. Unsequenced commands (from a client that predates the
/// seq, or through a relay that drops it) always pass.
#[derive(Default)]
pub(super) struct LobbyReceipts {
    delivered: HashMap<SlotId, HashSet<u64>>,
}

impl LobbyReceipts {
    /// Whether a command `author` sent with origin `seq` is new to the game,
    /// recording it as delivered if so.
    pub(super) fn admit(&mut self, author: SlotId, seq: Option<u64>) -> bool {
        let Some(seq) = seq else {
            return true;
        };
        self.delivered.entry(author).or_default().insert(seq)
    }
}
