//! One session's slice of a mesh link: the ack manager and dedup state that
//! belong to a single game on a connection shared by many.
//!
//! It sits in its own file because it is the unit the mesh link multiplexes —
//! everything here is per-session, and nothing here knows the session's id,
//! its tenant, or that any other session exists.

use rally_point_proto::messages::Packet;

use crate::ack_manager::AckManager;
use crate::link::{Dedup, LinkError, Received, retain_fresh_payloads};

/// One session's per-link transport state on a mesh link: its own
/// [`AckManager`] and `Dedup`, independent of every other session's. The
/// `(slot, seq)` identity is unambiguous within an instance because the
/// instance only ever sees one session's payloads.
pub struct SessionLink {
    pub(super) acks: AckManager,
    pub(super) dedup: Dedup,
}

impl SessionLink {
    /// Folds a decoded packet's acks into the manager and returns its delivery.
    /// Mirrors [`Link::process_incoming`](crate::Link) but on the per-session
    /// state this struct owns.
    pub(super) fn process_incoming(&mut self, mut packet: Packet) -> Result<Received, LinkError> {
        self.acks.handle_incoming(&packet)?;

        // Whether the peer is waiting on an ack for delivered turns: a packet
        // that carried payloads (even all-redundant ones) needs an ack back,
        // while an ack-only packet does not.
        let carried_payloads = !packet.payloads.is_empty();

        // Shared with the client edge so sorting, malformed-slot handling,
        // transactional rollback, and in-place compaction cannot drift between
        // the two receive paths.
        retain_fresh_payloads(&mut self.dedup, &mut packet.payloads)?;
        Ok(Received {
            fresh: packet.payloads,
            carried_payloads,
        })
    }
}
