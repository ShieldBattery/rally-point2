//! One transport link: a QUIC connection married to its [`AckManager`].
//!
//! A `Link` is the unit both the client and relay instantiate per connection
//! (client ↔ home relay, relay ↔ relay across the mesh). It drives the
//! redundancy/ack state over real QUIC datagrams: [`send`](Link::send) builds a
//! packet sized to the live datagram budget and puts it on the wire, and
//! [`recv`](Link::recv) decodes an incoming packet, folds its acks into the
//! manager, and returns the payloads not seen before.
//!
//! Dedup is the link's job. netcode v2 removes Storm's transport layer, which
//! used to drop the redundant copies; redundancy means the same payload arrives
//! in several packets, so [`recv`](Link::recv) returns each payload exactly once.
//! A payload's identity is `(slot, seq)` — its origin identity, assigned by the
//! sending client and preserved end-to-end — so dedup tracks the contiguous run
//! of delivered seqs *per slot* plus a bounded set of out-of-order ones above
//! it, so a fresh high seq never masks an older redundant one that simply hasn't
//! arrived yet. Each call returns a packet's new payloads in seq order, but
//! successive calls follow packet arrival, so the delivered stream isn't
//! globally ordered — true in-order reassembly (holding a seq until the gap below
//! it fills, as Storm did) is a layer above this.
//!
//! The link also exposes the two halves of the ack-beacon side-channel the
//! driver wires: [`delivered_through`](Link::delivered_through) is the per-slot
//! cursor the driver pushes to the peer over a reliable uni-stream, and
//! [`retire_through`](Link::retire_through) force-advances one slot's unacked
//! window when the peer's cursor arrives. The link owns no stream I/O — the
//! driver opens the streams and runs the cancel-safe read loop — but it does
//! guard `retire_through` monotonically (per slot) so a desynced cursor can't
//! retire turns the peer never confirmed.

use prost::Message;
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{Packet, Payload};

use crate::ack_manager::{AckError, AckManager, PacketSeqExhausted};

mod dedup;

pub(crate) use dedup::{Dedup, Delivery, retain_fresh_payloads};
// `SlotDedup` is named in the signature of `Dedup`'s crate-visible snapshot and
// restore pair, so it stays reachable beside them even while every caller of
// that pair only passes the snapshot along without naming its type.
#[allow(unused_imports)]
pub(crate) use dedup::SlotDedup;

/// How far ahead of the contiguous delivered prefix a peer's payload seq may be
/// before the link is treated as broken. The redundancy stream keeps that prefix
/// advancing, so legitimately reaching this bound means the low seqs have been
/// lost for a long run (minutes at the turn rate) — a dead link, not reorder. It
/// also bounds the out-of-order set to at most this many entries per slot.
const RECEIVE_WINDOW: u64 = 4096;

/// A single transport link over one QUIC connection.
pub struct Link {
    connection: noq::Connection,
    acks: AckManager,
    dedup: Dedup,
    /// The slot every incoming payload on this link is authorized as, or `None` on
    /// a link that genuinely carries more than one slot. When set, each incoming
    /// payload's wire slot is rewritten to this before dedup keys on it — the wire
    /// slot is an untrusted client claim (see
    /// [`with_ingress_slot`](Link::with_ingress_slot)).
    ingress_slot: Option<SlotId>,
}

/// A send or receive on a link failed.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// The peer never advertised QUIC datagram support, so this link can't carry
    /// turns at all — a configuration/peer mismatch, not a transient failure.
    #[error("peer does not support QUIC datagrams")]
    DatagramsUnsupported,
    /// The QUIC connection ended.
    #[error("QUIC connection lost: {0}")]
    Connection(#[from] noq::ConnectionError),
    /// A datagram could not be queued for sending.
    #[error("sending datagram failed: {0}")]
    Send(#[from] noq::SendDatagramError),
    /// A datagram did not fit the path's current budget, so it was refused. With the
    /// tiny turns of a lockstep game this should never happen; it is surfaced (rather
    /// than retried forever) so the caller fails fast — an undeliverable turn can't
    /// simply be dropped.
    #[error("datagram of {needed} bytes exceeds the {budget}-byte path budget")]
    PayloadTooLarge { needed: usize, budget: usize },
    /// A received datagram was not a well-formed packet.
    #[error("decoding incoming packet failed: {0}")]
    Decode(#[from] prost::DecodeError),
    /// A payload's seq was further ahead of our contiguous delivered prefix than
    /// the receive window allows — the peer is racing too far ahead (a dead link
    #[error("payload (slot {}, seq {seq}) is beyond the receive window", slot.0)]
    PayloadOutOfWindow { slot: SlotId, seq: u64 },
    /// A payload's wire slot does not fit in a [`SlotId`] (0..=255). A live game
    /// never has more than 256 slots, so this is a malformed or hostile packet —
    /// narrowing it with a raw cast instead would truncate/alias it onto a
    /// different, valid slot's dedup and receive-window state. Refused like
    /// [`PayloadOutOfWindow`](Self::PayloadOutOfWindow): the whole packet is
    /// rejected and the link closed, rather than silently dropping just this
    /// payload and risking a permanent gap in that slot's seq stream.
    #[error("payload names slot {0}, out of range for a SlotId (0..=255)")]
    MalformedSlot(u32),
    /// A received packet's acks were internally inconsistent. Attacker-facing
    /// callers (the relay) typically drop the peer on this.
    #[error(transparent)]
    Ack(#[from] AckError),
    /// The connection's `u32` packet sequence space is exhausted — every seq has
    /// been assigned. Unreachable within one game at the turn rate (years of
    /// play), so it means the connection is broken: terminal, and the reconnect
    /// machinery must reset onto a fresh connection (a new seq space) rather than
    /// wrap, which would silently corrupt acking.
    #[error(transparent)]
    PacketSeqExhausted(#[from] PacketSeqExhausted),
}

impl Link {
    /// Wraps an established QUIC connection as a transport link that trusts the
    /// wire slot on each payload to demux slots.
    ///
    /// This is the constructor for links that genuinely carry many slots: the game
    /// client's fan-in link (which receives every peer's turns over one connection)
    /// and the relay↔relay mesh links (which trust their peer relay's per-slot
    /// demux). A single-slot ingress edge — the relay's link to one authorized game
    /// client — uses [`with_ingress_slot`](Self::with_ingress_slot) instead.
    pub fn new(connection: noq::Connection) -> Self {
        Self {
            connection,
            acks: AckManager::new(),
            dedup: Dedup::new(),
            ingress_slot: None,
        }
    }

    /// Wraps an established QUIC connection as a single-slot ingress edge: every
    /// incoming payload is authorized as `slot`, and its wire slot field is
    /// rewritten to `slot` before anything keys on it.
    ///
    /// The slot a client stamps on the wire is an untrusted claim — the real game
    /// client leaves it at 0 on every outbound turn regardless of which slot it
    /// actually holds. Dedup and the receive-window anchor, though, key on the
    /// *authorized* slot: a same-relay resume anchors this edge's window for the
    /// authorized slot (see [`anchor_receive_window`](Self::anchor_receive_window)),
    /// keyed on that slot. If dedup kept keying on the wire claim, the anchor would
    /// land on the authorized slot while the resumed stream deduped under a phantom
    /// slot-0 key with a from-zero window — making the anchor a silent no-op and
    /// rejecting the first resumed turn past the window as
    /// [`PayloadOutOfWindow`](LinkError::PayloadOutOfWindow), fatally closing a
    /// resumed link for any authorized slot other than 0. Rewriting the wire slot to
    /// `slot` here keeps the dedup key, the returned fresh payloads, and the window
    /// anchor all on the one authorized slot. It also closes off a lying client
    /// opening extra per-slot dedup key spaces by claiming slots it was not
    /// authorized for.
    ///
    /// Only single-ingress edges rebind; the multi-slot links built by
    /// [`new`](Self::new) must not, as they legitimately demux several slots off the
    /// wire slot.
    pub fn with_ingress_slot(connection: noq::Connection, slot: SlotId) -> Self {
        Self {
            connection,
            acks: AckManager::new(),
            dedup: Dedup::new(),
            ingress_slot: Some(slot),
        }
    }

    /// The underlying QUIC connection.
    pub fn connection(&self) -> &noq::Connection {
        &self.connection
    }

    /// Rebinds this link to a freshly dialed connection after the previous one
    /// failed, resuming the same session rather than starting a new one.
    ///
    /// The per-connection send/ack state resets (see
    /// [`AckManager::reset_connection`](crate::ack_manager::AckManager::reset_connection)),
    /// but the still-unacked payloads carry over so redundancy re-delivers any turn
    /// that was in flight when the link dropped. The receive-side dedup is preserved
    /// whole: its per-slot delivered prefix keeps anchoring the receive window — so
    /// the relay's post-reconnect replay of mid-game seqs is not rejected as beyond
    /// the window that a fresh dedup, starting from seq 0, would impose — and it
    /// dedups that replay against turns already delivered. Payload seqs are origin
    /// identities carried end-to-end, so the dedup keyed on them stays valid across
    /// the connection swap.
    ///
    /// A rebind target's datagram budget always covers the preserved window:
    /// every establishment path refuses a connection whose budget undercuts
    /// the guaranteed floor
    /// ([`verify_datagram_budget`](crate::quic::verify_datagram_budget)), and
    /// every preserved payload was admitted against that same floor.
    pub fn rebind(&mut self, connection: noq::Connection) {
        self.connection = connection;
        self.acks.reset_connection();
        // dedup preserved: it is what makes the reconnect a resume, not a restart.
        // ingress_slot preserved: the connection swapped, but the slot this edge is
        // authorized for did not, so the wire-slot rewrite must keep applying.
    }

    /// Payloads sent but not yet known-delivered — the in-flight depth, and the
    /// overflow signal the driver watches under sustained loss.
    pub fn payloads_in_flight(&self) -> usize {
        self.acks.payloads_in_flight()
    }

    /// Packets the peer sent that never arrived, cumulative for this
    /// connection. QUIC's own path stats measure only the direction *we* send,
    /// so this is the sole view of loss on the way *in* — the direction that,
    /// for a client link, carries the turns everyone else in the lockstep is
    /// waiting on.
    ///
    /// Derived from gaps in the peer's own packet numbering, so a peer that
    /// skips seqs overstates its own loss and no one else's. Observability
    /// only: nothing that sizes a buffer or decides a session may read it
    /// without treating it as the client-influenceable input it is.
    pub fn upstream_lost_packets(&self) -> u64 {
        self.acks.upstream_lost_packets()
    }

    /// The lowest still-unacked payload seq this link's datagram redundancy
    /// will replay for `slot`, or `None` if nothing is in flight — the
    /// **same-relay** resume anchor. The unacked window is sparse (selective
    /// packet acks leave holes), so the contiguity a receive-window anchor
    /// promises holds on a same-relay resume only because the relay seeds the
    /// fresh window from its session-lifetime receipt records (every acked
    /// hole is a seq it received and recorded; see
    /// [`seed_delivered`](Self::seed_delivered)). A re-home to a relay with
    /// no first-hand ack history must anchor with
    /// [`contiguous_replayable_anchor`](Self::contiguous_replayable_anchor)
    /// instead. See
    /// [`AckManager::oldest_replayable_seq`](crate::ack_manager::AckManager::oldest_replayable_seq).
    pub fn oldest_replayable_seq(&self, slot: SlotId) -> Option<u64> {
        self.acks.oldest_replayable_seq(slot)
    }

    /// The lowest anchor a re-home resume may advertise for `slot`: the
    /// retention `front` extended downward only through contiguously unacked
    /// seqs. See
    /// [`AckManager::contiguous_replayable_anchor`](crate::ack_manager::AckManager::contiguous_replayable_anchor)
    /// for why a fresh relay's window must never be anchored below an acked
    /// hole.
    pub fn contiguous_replayable_anchor(&self, slot: SlotId, front: u64) -> u64 {
        self.acks.contiguous_replayable_anchor(slot, front)
    }

    /// Marks `seq` as already delivered for `slot` without a payload arriving —
    /// the resume-time seed for receipts that predate this connection. A relay
    /// resuming a client seeds the fresh receive window with the seqs it has
    /// already received from the slot (its session-lifetime receipt records),
    /// so the acked holes above the client's anchor (selective packet acks
    /// make the unacked window sparse, and the client only replays what is
    /// still unacked) don't wedge the window's contiguous prefix — and with it
    /// the beacon cursor, and eventually the window itself, when the live
    /// stream runs a full receive window past the stuck base.
    pub fn seed_delivered(&mut self, slot: SlotId, seq: u64) {
        self.dedup.mark_delivered(slot, seq);
    }

    /// The bulk form of [`seed_delivered`](Self::seed_delivered): marks every
    /// seq up to and including `through` delivered for `slot` in one step, so
    /// seeding a long contiguous receipt prefix costs O(out-of-order seeds)
    /// rather than one call per seq. Never rewinds: a prefix already past
    /// `through` is left where it is.
    pub fn seed_delivered_through(&mut self, slot: SlotId, through: u64) {
        self.dedup.mark_delivered_through(slot, through);
    }

    /// The top of the contiguous run of payloads this link has delivered to its
    /// consumer for `slot` (the highest seq such that every seq up to it has been
    /// delivered for that slot), or `None` before the first payload for that slot
    /// arrives. This is the per-slot cursor the beacon side-channel pushes to the
    /// peer so it can force-advance its unacked window past turns it now knows
    /// were received.
    pub fn delivered_through(&self, slot: SlotId) -> Option<u64> {
        self.dedup.delivered_through(slot)
    }

    /// Force-retires every unacked payload in `slot` up to `through_seq`,
    /// returning how many were dropped, *unless* `through_seq` is not strictly
    /// greater than the last cursor applied for that slot. A monotonic guard:
    /// the beacon stream is reliable-ordered, so cursors arrive in order, but a
    /// stream framing desync (partial read handed to the codec) could produce a
    /// garbage `u64` — retiring turns the peer never confirmed would desync
    /// lockstep silently. Rejecting anything not strictly advancing turns such a
    /// desync into a harmless no-op rather than a desync.
    ///
    /// For the guard to hold, the reader must assemble complete frames off a
    /// cancel-safe path (a dedicated read-loop task forwarding over a channel),
    /// never a `read_exact` dropped mid-frame inside a `select!`.
    pub fn retire_through(&mut self, slot: SlotId, through_seq: u64) -> usize {
        if self.dedup.advance_retired_through(slot, through_seq) {
            self.acks.retire_payloads_through(slot, through_seq)
        } else {
            0
        }
    }

    /// Re-registers a turn this client sent as still-unacked so the redundancy
    /// pass re-carries it over the current connection, without sending a packet —
    /// the re-inject half of a coordinator-mediated re-home. A replacement relay's
    /// turn ring is empty, so turns the old relay already acked (retired from the
    /// window) are re-injected here after a rehome [`rebind`](Self::rebind), letting
    /// the next packet's redundancy carry them to the new relay, which fans them out
    /// to peers (each deduping by origin `(slot, seq)`). A turn still in flight at
    /// the drop is already unacked and left untouched.
    pub fn reinject_unacked(&mut self, payload: Payload) {
        self.acks.reinject_unacked(payload);
    }

    /// The budget a payload must fit alone (under worst-case header state) to
    /// be admitted for datagram carriage on this link — the single admission
    /// number [`payload_fits`](Self::payload_fits) answers with and
    /// [`send`](Self::send) enforces, computed in one place so the two can
    /// never disagree (a fits-then-refused skew would drop the fresh turn:
    /// the driver treats `send`'s refusal as a recoverable bundle race, and
    /// the turn would be neither registered for re-carry nor diverted).
    ///
    /// Both components are constant for the connection's life, so admission
    /// never flips. The
    /// [`GUARANTEED_DATAGRAM_BUDGET`](crate::ack_manager::GUARANTEED_DATAGRAM_BUDGET)
    /// floor covers the path-MTU component of the live `max_datagram_size()`,
    /// which discovery raises and the black-hole detector shrinks back — but
    /// never below the floor. The live value's *other* component, the peer's
    /// advertised datagram limit, is a handshake transport parameter noq
    /// permits to be arbitrarily small; it never changes after the handshake,
    /// so taking the minimum keeps admission both safe against a small peer
    /// limit and stable over time.
    fn datagram_admission_budget(&self) -> Result<usize, LinkError> {
        let live = self
            .connection
            .max_datagram_size()
            .ok_or(LinkError::DatagramsUnsupported)?;
        Ok(live.min(crate::ack_manager::GUARANTEED_DATAGRAM_BUDGET))
    }

    /// Whether `payload` can ride datagrams on this link for the rest of the
    /// connection's life: a packet carrying it alone, under worst-case header
    /// state, fits the link-lifetime admission budget — a
    /// connection-lifetime constant, deliberately not the live
    /// `max_datagram_size()` (see the helper's docs for why each of its
    /// components must be pinned). The caller's pre-check for the
    /// divert-to-stream path — a payload this returns `false` for must go
    /// over the reliable control stream, never into [`send`](Self::send)
    /// (which would refuse it anyway, but by then the caller has lost the
    /// payload to the move).
    pub fn payload_fits(&self, payload: &Payload) -> Result<bool, LinkError> {
        Ok(crate::ack_manager::lone_packet_len(payload) <= self.datagram_admission_budget()?)
    }

    /// Anchors this link's receive window for `slot` to `anchor`, treating every
    /// seq below `anchor` as already delivered so the window's base is `anchor`
    /// rather than 0.
    ///
    /// A fresh link's `Dedup` anchors the receive window at seq 0 — correct for a
    /// client whose slot stream genuinely starts there. But a session **re-homed**
    /// onto a fresh relay resumes its slot's seq stream mid-way (it kept counting
    /// across the move and re-injects only a recent retention ring, never seq 0
    /// onward), so a from-zero base would hold the delivered prefix at `None`
    /// forever and reject the resumed stream as
    /// [`PayloadOutOfWindow`](LinkError::PayloadOutOfWindow) the moment its seq
    /// passed the window — dropping the link. Anchoring the window at the resume
    /// point (the oldest seq the client will re-send) lets the resumed stream be
    /// accepted and the prefix advance normally from there.
    ///
    /// Only meaningful on a pristine slot (nothing received yet); it never rewinds a
    /// prefix already forming, and an `anchor` of 0 is a no-op (the default base).
    pub fn anchor_receive_window(&mut self, slot: SlotId, anchor: u64) {
        self.dedup.anchor(slot, anchor);
    }

    /// Folds a payload that arrived *outside* the datagram path — the reliable
    /// control stream, where oversize turns ride — into this link's receive
    /// state: the same per-slot dedup and delivered-prefix bookkeeping a
    /// datagram delivery runs, with no ack-state change (QUIC's stream
    /// reliability already guarantees the delivery; there is nothing to ack or
    /// retire). Keeping the two paths on one `Dedup` is what lets the
    /// delivered-through cursor advance across a stream-delivered seq —
    /// otherwise the beacon would stall at the gap forever — and what makes a
    /// duplicate (a turn somehow sent both ways) collapse to one delivery.
    ///
    /// Returns whether the payload is new (`true`) or an already-delivered
    /// duplicate (`false`). A seq beyond the receive window is an error, as on
    /// the datagram path.
    pub fn deliver_external(&mut self, slot: SlotId, seq: u64) -> Result<bool, LinkError> {
        match self.dedup.accept(slot, seq) {
            Delivery::New => Ok(true),
            Delivery::Duplicate => Ok(false),
            Delivery::OutOfWindow => Err(LinkError::PayloadOutOfWindow { slot, seq }),
        }
    }

    /// Builds the next packet — `payload` plus redundant unacked ones, or a
    /// redundancy/ack flush when `payload` is `None` — sends it as one QUIC
    /// datagram, and returns how many still-unacked turns it re-carried (the
    /// fresh turn, if any, is not counted). A no-payload call is ack-only when
    /// there is no unacked redundancy to pack.
    ///
    /// That count lets a caller tell whether retransmission is already riding the
    /// outbound stream (redundancy carried) or whether it must schedule a standalone
    /// flush — a near-MTU turn fills the datagram and re-carries nothing.
    ///
    /// The bundle is sized to the connection's live `max_datagram_size()`, so it
    /// tracks path-MTU changes. A datagram that does not fit the path is surfaced as
    /// [`PayloadTooLarge`](LinkError::PayloadTooLarge) — with the tiny turns of a
    /// lockstep game this should never happen, but it is reported (not retried
    /// forever) so the caller fails fast instead of silently stalling the stream.
    pub fn send(&mut self, payload: Option<Payload>) -> Result<usize, LinkError> {
        let budget = self
            .connection
            .max_datagram_size()
            .ok_or(LinkError::DatagramsUnsupported)?;
        let had_fresh = payload.is_some();

        // A payload that might someday be unable to ride a datagram is refused
        // *before* it is registered as unacked — against the static
        // [`GUARANTEED_DATAGRAM_BUDGET`] floor, not the live budget, which
        // path-MTU shrink can pull below what it reads today (see
        // [`payload_fits`](Self::payload_fits)). Registered, such a payload
        // would poison recovery: every rebuilt bundle would try and fail to
        // carry it, and its seq would hold a permanent gap in the peer's
        // delivered prefix. Refused here, the caller diverts it (the reliable
        // control stream) or fails fast. This is distinct from a *bundle* that
        // outgrew a shrunken path below — that payload fit the floor when
        // checked, is registered, and its refusal is a recoverable loss the
        // next (smaller) bundle re-carries.
        if let Some(p) = &payload {
            // A wire slot that doesn't fit a `SlotId` can't be tracked without
            // narrowing it onto a different, valid slot's bookkeeping, so it is
            // refused whole before any send-side state is built for it — the
            // outbound mirror of the ingress path's rejection of an out-of-range
            // received slot. The real game client only ever stamps its own in-range
            // slot, so this is a malformed or hostile payload.
            if u8::try_from(p.slot).is_err() {
                return Err(LinkError::MalformedSlot(p.slot));
            }
            let needed = crate::ack_manager::lone_packet_len(p);
            let admission = self.datagram_admission_budget()?;
            if needed > admission {
                return Err(LinkError::PayloadTooLarge {
                    needed,
                    budget: admission,
                });
            }
        }

        let packet = self.acks.build_outgoing(payload, budget)?;
        // Everything in the packet except the fresh turn is a redundant re-carry.
        let redundant = packet.payloads.len() - usize::from(had_fresh);
        let encoded = packet.encode_to_vec();
        let datagram_len = encoded.len();
        match self.connection.send_datagram(encoded.into()) {
            // Carry bookkeeping describes what reached the wire, so it is
            // recorded only once the transport accepts the datagram: a refused
            // send (a path-MTU race, a dying connection) leaves the carried
            // payloads' re-carry schedules undisturbed and nothing for an
            // impossible ack to retire.
            Ok(()) => {
                self.acks.record_sent(&packet);
                Ok(redundant)
            }
            Err(noq::SendDatagramError::TooLarge) => Err(LinkError::PayloadTooLarge {
                needed: datagram_len,
                budget,
            }),
            Err(error) => Err(error.into()),
        }
    }

    /// Awaits the next datagram, folds its acks into the manager, and returns what
    /// it delivered: the payloads not seen before (redundant copies dropped, in
    /// ascending seq order within each slot) plus whether the packet carried any
    /// payloads at all.
    pub async fn recv(&mut self) -> Result<Received, LinkError> {
        let datagram = self.connection.read_datagram().await?;
        let packet = Packet::decode(datagram)?;
        self.process_incoming(packet)
    }

    /// Folds a decoded packet's acks into the manager and returns its delivery.
    /// Split out from [`recv`](Link::recv) so the dedup is exercised without a live
    /// connection.
    fn process_incoming(&mut self, mut packet: Packet) -> Result<Received, LinkError> {
        self.acks.handle_incoming(&packet)?;

        // Whether the peer is waiting on an ack for delivered turns: a packet that
        // carried payloads (even all-redundant ones) needs an ack back so the peer
        // can retire them, while an ack-only packet does not — acking it would only
        // provoke another ack-only packet in return, forever.
        let carried_payloads = !packet.payloads.is_empty();

        // On a single-ingress edge the wire slot is an untrusted client claim (the
        // real game client always sends 0), so rewrite every payload to the
        // authorized slot before dedup keys on it. This keeps the dedup key, the
        // returned fresh payloads, and the receive-window anchor all on the one
        // authorized slot — without it a nonzero-slot client's resumed stream would
        // dedup under a phantom slot-0 key while its anchor sat on the authorized
        // slot, so the anchor would be a silent no-op and the first resumed turn
        // past the window would fatally close the link. Multi-slot links (fan-in,
        // mesh) leave this unset and demux by the wire slot as before.
        if let Some(ingress) = self.ingress_slot {
            let wire_slot = u32::from(ingress.0);
            for payload in &mut packet.payloads {
                payload.slot = wire_slot;
            }
        }

        retain_fresh_payloads(&mut self.dedup, &mut packet.payloads)?;
        Ok(Received {
            // Dedup compacts the decoded protobuf vector in place, so delivery
            // reuses its allocation rather than copying fresh payloads into a
            // second vector.
            fresh: packet.payloads,
            carried_payloads,
        })
    }
}

/// What one [`recv`](Link::recv) delivered.
#[derive(Debug)]
pub struct Received {
    /// Payloads delivered for the first time, ascending by `(slot, seq)`;
    /// redundant copies of already-delivered payloads are dropped.
    pub fresh: Vec<Payload>,
    /// Whether the packet carried any payload elements (new or redundant). An
    /// ack-only packet carried none, and the peer is not waiting for it to be acked —
    /// so the receiver must not schedule an ack in return, or two idle links would
    /// ack each other's acks forever.
    pub carried_payloads: bool,
}

#[cfg(test)]
mod tests;
