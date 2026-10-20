//! Lobby commands across reconnects: the commands this client authored, kept
//! so every new control stream can carry them again, and the per-author cursor
//! that keeps a command another member authored from reaching the game twice.
//!
//! A control-stream write carries no acknowledgment. A command written onto a
//! connection whose path has silently died succeeds locally and is lost with
//! the connection, which only times out seconds later; nothing reports it. So
//! the driver numbers each command it authors with an origin seq and writes
//! every retained command again, in order, on each new control stream. Every
//! relay that already accepted one drops the repeat by `(slot, seq)`, so the
//! re-send delivers only what was lost.

use std::collections::{HashMap, VecDeque};

use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::LobbyCommand;
use rally_point_transport::control::{ControlSendError, send_control_lobby};
use rally_point_transport::noq;

/// How many authored lobby commands [`LobbyRetention`] keeps. A full 8-player
/// lobby's setup (slot, color, race and team assignments plus the game-init) is
/// on the order of thirty commands, and a ShieldBattery game authors only a
/// handful, so this is a backstop against a runaway author, not a tuned depth.
pub(super) const LOBBY_RETENTION_CAP: usize = 256;

/// The byte ceiling on [`LobbyRetention`], enforced alongside
/// [`LOBBY_RETENTION_CAP`]. It matches the relay's whole-session lobby log
/// ceiling: a relay refuses commands past that anyway, so retaining more could
/// never get them delivered.
const LOBBY_RETENTION_BYTE_CAP: usize = 256 * 1024;

/// Every lobby command this client authored in the session, oldest first, each
/// stamped with its origin seq.
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
/// Past either cap the oldest command is dropped from retention (it was still
/// sent once). The seq counter never rewinds, so what remains keeps its
/// identity.
#[derive(Default)]
pub(super) struct LobbyRetention {
    commands: VecDeque<LobbyCommand>,
    bytes: usize,
    next_seq: u64,
}

impl LobbyRetention {
    /// Stamps `bytes` with the next origin seq, retains the command, and hands
    /// back the frame to write. The `slot` is left `0`: the relay stamps the
    /// authenticated slot and ignores the client's.
    pub(super) fn author(&mut self, bytes: Vec<u8>) -> LobbyCommand {
        let command = LobbyCommand {
            slot: 0,
            payload: bytes.into(),
            seq: Some(self.next_seq),
        };
        self.next_seq += 1;
        self.bytes += command.payload.len();
        self.commands.push_back(command.clone());
        while self.commands.len() > LOBBY_RETENTION_CAP
            || (self.bytes > LOBBY_RETENTION_BYTE_CAP && self.commands.len() > 1)
        {
            let Some(dropped) = self.commands.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(dropped.payload.len());
            tracing::warn!(
                seq = dropped.seq,
                "lobby retention over its cap; the oldest command is no longer re-sent"
            );
        }
        command
    }

    /// The retained commands, oldest first: the order they must be re-sent in.
    pub(super) fn retained(&self) -> impl Iterator<Item = &LobbyCommand> {
        self.commands.iter()
    }

    /// Writes every retained command up `control_send`, oldest first. A failed
    /// write leaves retention as it was, so the next stream carries the whole
    /// set again.
    pub(super) async fn resend(
        &self,
        control_send: &mut noq::SendStream,
    ) -> Result<(), ControlSendError> {
        for command in self.retained() {
            send_control_lobby(control_send, command.clone()).await?;
        }
        Ok(())
    }
}

/// Per authoring slot, the highest origin seq of a lobby command already handed
/// to the game.
///
/// The relay replays its whole lobby log to a member every time that member's
/// control stream registers, so a client that reconnects is sent every command
/// again; and a relay that took the session over without ever having seen an
/// author's earlier commands accepts that author's re-send as new. Dropping a
/// command at or below the author's high-water mark keeps both from reaching
/// the game twice. A relay never accepts an author's commands out of seq order,
/// so its log, and any replay of it, carries each author's seqs climbing.
/// Unsequenced commands (from a client that predates the seq, or through a
/// relay that drops it) always pass.
#[derive(Default)]
pub(super) struct LobbyReceipts {
    delivered_through: HashMap<SlotId, u64>,
}

impl LobbyReceipts {
    /// Whether a command `author` sent with origin `seq` is new to the game,
    /// recording it as delivered if so.
    pub(super) fn admit(&mut self, author: SlotId, seq: Option<u64>) -> bool {
        let Some(seq) = seq else {
            return true;
        };
        match self.delivered_through.get(&author) {
            Some(&through) if seq <= through => false,
            _ => {
                self.delivered_through.insert(author, seq);
                true
            }
        }
    }
}
