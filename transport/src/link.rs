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

use std::collections::{BTreeSet, HashMap};

use prost::Message;
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{Packet, Payload};

use crate::ack_manager::{AckError, AckManager};

/// How far ahead of the contiguous delivered prefix a peer's payload seq may be
/// before the link is treated as broken. The redundancy stream keeps that prefix
/// advancing, so legitimately reaching this bound means the low seqs have been
/// lost for a long run (minutes at the turn rate) — a dead link, not reorder. It
/// also bounds the out-of-order set to at most this many entries per slot.
const RECEIVE_WINDOW: u64 = 4096;

/// A single transport link over one QUIC connection.
pub struct Link {
    connection: quinn::Connection,
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
    Connection(#[from] quinn::ConnectionError),
    /// A datagram could not be queued for sending.
    #[error("sending datagram failed: {0}")]
    Send(#[from] quinn::SendDatagramError),
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
    pub fn new(connection: quinn::Connection) -> Self {
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
    pub fn with_ingress_slot(connection: quinn::Connection, slot: SlotId) -> Self {
        Self {
            connection,
            acks: AckManager::new(),
            dedup: Dedup::new(),
            ingress_slot: Some(slot),
        }
    }

    /// The underlying QUIC connection.
    pub fn connection(&self) -> &quinn::Connection {
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
    pub fn rebind(&mut self, connection: quinn::Connection) {
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

    /// The lowest still-unacked payload seq this link holds for `slot`, or `None`
    /// if nothing is in flight for it. It is the oldest seq the redundancy pass will
    /// re-carry over a rebound connection, so a driver presents it as its own-slot
    /// resume anchor on a same-relay re-dial: the fresh relay bases the slot's
    /// receive window there (see [`anchor_receive_window`](Self::anchor_receive_window))
    /// rather than at 0, which a session past the window would otherwise trip.
    pub fn oldest_unacked_seq(&self, slot: SlotId) -> Option<u64> {
        self.acks.oldest_unacked_seq(slot)
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

    /// Whether `payload` can ever ride a datagram on this link's current path:
    /// a packet carrying it alone, under worst-case header state, fits the live
    /// `max_datagram_size()`. The caller's pre-check for the divert-to-stream
    /// path — a payload this returns `false` for must go over the reliable
    /// control stream, never into [`send`](Self::send) (which would refuse it
    /// anyway, but by then the caller has lost the payload to the move).
    pub fn payload_fits(&self, payload: &Payload) -> Result<bool, LinkError> {
        let budget = self
            .connection
            .max_datagram_size()
            .ok_or(LinkError::DatagramsUnsupported)?;
        Ok(crate::ack_manager::lone_packet_len(payload) <= budget)
    }

    /// Anchors this link's receive window for `slot` to `anchor`, treating every
    /// seq below `anchor` as already delivered so the window's base is `anchor`
    /// rather than 0.
    ///
    /// A fresh link's [`Dedup`] anchors the receive window at seq 0 — correct for a
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

    /// Builds the next packet — `payload` plus redundant unacked ones, or
    /// ack-only when `payload` is `None` — sends it as one QUIC datagram, and
    /// returns how many still-unacked turns it re-carried as redundancy (the fresh
    /// turn, if any, is not counted).
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

        // A payload that can never ride any datagram is refused *before* it is
        // registered as unacked. Registered, it would poison recovery: every
        // rebuilt bundle would try and fail to carry it, and its seq would hold
        // a permanent gap in the peer's delivered prefix. Refused here, the
        // caller diverts it (the reliable control stream) or fails fast. This
        // is distinct from a *bundle* that outgrew a shrunken path below —
        // that payload fit when checked, is registered, and its refusal is a
        // recoverable loss the next (smaller) bundle re-carries.
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
            if needed > budget {
                return Err(LinkError::PayloadTooLarge { needed, budget });
            }
        }

        let packet = self.acks.build_outgoing(payload, budget);
        // Everything in the packet except the fresh turn is a redundant re-carry.
        let redundant = packet.payloads.len() - usize::from(had_fresh);
        let encoded = packet.encode_to_vec();
        let datagram_len = encoded.len();
        match self.connection.send_datagram(encoded.into()) {
            Ok(()) => Ok(redundant),
            Err(quinn::SendDatagramError::TooLarge) => Err(LinkError::PayloadTooLarge {
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

        // Process payloads low-seq first within each slot. A packet leads with its
        // fresh (highest) seq per slot, so without this a deep-loss packet's high
        // seq could shut the window on the older redundant seqs it carries
        // alongside.
        packet.payloads.sort_by_key(|p| (p.slot, p.seq));

        // Transactional commit: snapshot every slot this packet's payloads
        // name (before any of them are `accept`ed) so a payload that fails
        // partway through the packet — out of window, or a malformed slot —
        // can be rolled back cleanly, restoring dedup to exactly the state it
        // was in before this packet. Without this, an earlier payload in the
        // SAME packet that was already `accept`ed (and so is remembered as
        // delivered) would be dropped from the returned `fresh` on the error
        // return below, while dedup keeps believing it reached the consumer
        // — a permanent, silent gap: a later reconnect's replay re-sends that
        // seq, dedup rejects it as a duplicate, and the consumer never
        // receives a turn it was never actually handed. Malformed payloads
        // don't themselves touch dedup, but an earlier payload in the same
        // packet may already have, so the same rollback applies to that path
        // too.
        let touched: Vec<SlotId> = {
            let mut seen = std::collections::BTreeSet::new();
            packet
                .payloads
                .iter()
                .filter_map(|p| u8::try_from(p.slot).ok().map(SlotId))
                .filter(|slot| seen.insert(*slot))
                .collect()
        };
        let snapshot = self.dedup.snapshot(&touched);

        let mut fresh = Vec::new();
        for payload in packet.payloads {
            // A truncating cast would alias an out-of-range wire slot onto a
            // different, valid slot's dedup key — corrupting that slot's
            // window instead of merely rejecting the malformed one.
            let Ok(slot) = u8::try_from(payload.slot).map(SlotId) else {
                self.dedup.restore(snapshot);
                return Err(LinkError::MalformedSlot(payload.slot));
            };
            match self.dedup.accept(slot, payload.seq) {
                Delivery::New => fresh.push(payload),
                Delivery::Duplicate => {}
                Delivery::OutOfWindow => {
                    self.dedup.restore(snapshot);
                    return Err(LinkError::PayloadOutOfWindow {
                        slot,
                        seq: payload.seq,
                    });
                }
            }
        }
        Ok(Received {
            fresh,
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

/// The outcome of offering a received payload `(slot, seq)` to the dedup state.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Delivery {
    /// First time this `(slot, seq)` has been delivered — hand it to the caller.
    New,
    /// Already delivered (at/below the contiguous prefix, or seen out of order).
    Duplicate,
    /// Beyond the receive window — the peer is racing too far ahead.
    OutOfWindow,
}

/// Receive-side payload dedup, per slot.
///
/// Each slot has its own contiguous delivered prefix (`delivered_through`) plus
/// an `ahead` set of delivered seqs above it waiting for the gaps below to fill,
/// because each slot carries its own monotonic seq space starting at 0 — a
/// single global cursor would conflate one slot's progress with another's. A seq
/// is a duplicate only if it's within that slot's known-delivered state — never
/// merely because a higher seq arrived first — so a redundant low seq is never
/// mistaken for one that aged out.
///
/// Shared by the client-edge [`Link`] and the mesh `MeshLink`: both own one
/// instance per connection and feed it received payloads, so `(slot, seq)` is
/// unambiguous within an instance. The client edge has one game per connection
/// by nature; the mesh shares one connection across sessions but gives each its
/// own instance, so the session never enters the key.
pub(crate) struct Dedup {
    /// Per-slot dedup state.
    slots: HashMap<SlotId, SlotDedup>,
    /// The highest per-slot cursor force-retired via [`Link::retire_through`], so
    /// a desynced or replayed cursor can't retire turns the peer never confirmed.
    /// Inbound cursors are applied only when strictly greater than this; anything
    /// else is a no-op. Without it, a stream framing desync handing a garbage
    /// `u64` to `retire_through` could retire turns the peer never received —
    /// silent lockstep desync, worse than a crash.
    retired_through: HashMap<SlotId, u64>,
    /// How far above the prefix a seq may sit before it's rejected.
    window: u64,
}

/// One slot's receive-side dedup state.
#[derive(Clone)]
pub(crate) struct SlotDedup {
    /// Top of the contiguous delivered prefix; `None` until seq 0 is delivered.
    delivered_through: Option<u64>,
    /// Delivered seqs above the prefix, kept until the gaps below them fill.
    ahead: BTreeSet<u64>,
}

impl Dedup {
    pub(crate) fn new() -> Self {
        Self::with_window(RECEIVE_WINDOW)
    }

    pub(crate) fn with_window(window: u64) -> Self {
        Self {
            slots: HashMap::new(),
            retired_through: HashMap::new(),
            window,
        }
    }

    /// The top of the contiguous delivered prefix for `slot`, or `None` before
    /// the slot's first payload arrives.
    pub(crate) fn delivered_through(&self, slot: SlotId) -> Option<u64> {
        self.slots.get(&slot).and_then(|s| s.delivered_through)
    }

    /// Every slot's delivered-through cursor, for slots that have delivered at
    /// least one payload. Unlike the client edge (which tracks its own set of
    /// known peer slots independently, from the turns it produces), a mesh
    /// link's driver has no such side list of "which remote slots does this
    /// session carry" -- the slots this returns are exactly the ones this
    /// `Dedup` instance has actually seen traffic for, which is the complete
    /// and only set the mesh ack-cursor push needs.
    pub(crate) fn delivered_through_all(&self) -> Vec<(SlotId, u64)> {
        self.slots
            .iter()
            .filter_map(|(&slot, s)| s.delivered_through.map(|cursor| (slot, cursor)))
            .collect()
    }

    /// Records `(slot, seq)` as delivered and reports whether it's new, a
    /// duplicate, or out of the receive window.
    pub(crate) fn accept(&mut self, slot: SlotId, seq: u64) -> Delivery {
        let state = self.slots.entry(slot).or_insert_with(|| SlotDedup {
            delivered_through: None,
            ahead: BTreeSet::new(),
        });

        // A seq at or below the contiguous delivered prefix has already been
        // handed to the consumer. Comparing against `delivered_through` directly,
        // rather than a "next expected" seq derived by adding one, is what keeps a
        // prefix top of `u64::MAX` a duplicate when it repeats: there is no seq
        // above `u64::MAX` for a "next expected" to hold, so deriving one would
        // have to clamp back onto `u64::MAX` and misread the repeat as new. A
        // `u64::MAX` prefix is itself a value no real game can reach (that many
        // turns dwarfs any session's lifetime by orders of magnitude); the real
        // gate against it is the relay's resume-cursor anchor validation (see
        // `Link::anchor_receive_window`'s caller in `routing.rs`), which clamps a
        // client-supplied anchor before it can reach here. This is the
        // defense-in-depth backstop for the fold itself.
        if let Some(delivered) = state.delivered_through
            && seq <= delivered
        {
            return Delivery::Duplicate;
        }

        // The lowest seq not yet part of the contiguous delivered prefix. `seq` is
        // strictly above any existing prefix top (checked above), so that top is
        // below `u64::MAX` and this `+ 1` cannot overflow.
        let base = state.delivered_through.map_or(0, |t| t + 1);

        if seq - base >= self.window {
            return Delivery::OutOfWindow;
        }
        if !state.ahead.insert(seq) {
            return Delivery::Duplicate;
        }

        // Absorb any now-contiguous run into the delivered prefix. Stops rather
        // than overflows if the run reaches `u64::MAX`; there is no valid seq
        // beyond it to keep absorbing anyway.
        let mut next = base;
        loop {
            if !state.ahead.remove(&next) {
                break;
            }
            state.delivered_through = Some(next);
            let Some(after) = next.checked_add(1) else {
                break;
            };
            next = after;
        }
        Delivery::New
    }

    /// Snapshots the current dedup state for exactly `slots`, so a caller that
    /// provisionally mutates some of them while processing a batch (a packet's
    /// payloads, sorted and `accept`ed one at a time) can undo the whole batch
    /// atomically with [`restore`](Self::restore) if a later entry in the same
    /// batch turns out invalid. `None` for a slot with no entry yet, so a
    /// restore can tell "existed but was empty" from "was created by this
    /// batch and must be removed outright."
    pub(crate) fn snapshot(&self, slots: &[SlotId]) -> Vec<(SlotId, Option<SlotDedup>)> {
        slots
            .iter()
            .map(|&slot| (slot, self.slots.get(&slot).cloned()))
            .collect()
    }

    /// Restores exactly the slots a prior [`snapshot`](Self::snapshot) captured
    /// to their captured state, removing an entry that did not exist when the
    /// snapshot was taken. Slots outside the snapshot are untouched.
    pub(crate) fn restore(&mut self, snapshot: Vec<(SlotId, Option<SlotDedup>)>) {
        for (slot, state) in snapshot {
            match state {
                Some(state) => {
                    self.slots.insert(slot, state);
                }
                None => {
                    self.slots.remove(&slot);
                }
            }
        }
    }

    /// Anchors `slot`'s receive window at `anchor`: sets the delivered prefix top to
    /// `anchor - 1` so the window's base becomes `anchor` and seqs below it are
    /// treated as already delivered. See [`Link::anchor_receive_window`] for why a
    /// re-homed session needs this. A no-op when `anchor` is 0 (the default base is
    /// already 0) or when the slot has already received something — anchoring only a
    /// pristine slot means it never rewinds a prefix that is already forming.
    pub(crate) fn anchor(&mut self, slot: SlotId, anchor: u64) {
        let Some(prefix_top) = anchor.checked_sub(1) else {
            return;
        };
        let state = self.slots.entry(slot).or_insert_with(|| SlotDedup {
            delivered_through: None,
            ahead: BTreeSet::new(),
        });
        if state.delivered_through.is_none() && state.ahead.is_empty() {
            state.delivered_through = Some(prefix_top);
        }
    }

    /// Advances the per-slot retired-through guard, returning whether the cursor
    /// was strictly greater than the last one applied for `slot` (so the caller
    /// should retire). A cursor not strictly advancing is a no-op.
    pub(crate) fn advance_retired_through(&mut self, slot: SlotId, through_seq: u64) -> bool {
        if matches!(self.retired_through.get(&slot), Some(prev) if *prev >= through_seq) {
            false
        } else {
            self.retired_through.insert(slot, through_seq);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use super::*;
    use crate::quic::{client_config, server_config};

    #[test]
    fn dedup_returns_each_seq_once_per_slot() {
        let mut dedup = Dedup::with_window(8);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::Duplicate);
        assert_eq!(dedup.accept(SlotId(0), 1), Delivery::New);
        assert_eq!(dedup.accept(SlotId(0), 1), Delivery::Duplicate);
    }

    #[test]
    fn dedup_keeps_slots_independent() {
        // Two slots both have seq 0; both are new — the identity is (slot, seq).
        let mut dedup = Dedup::with_window(8);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New);
        assert_eq!(dedup.accept(SlotId(1), 0), Delivery::New);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::Duplicate);
        assert_eq!(dedup.accept(SlotId(1), 0), Delivery::Duplicate);
    }

    #[test]
    fn dedup_handles_out_of_order_within_window() {
        let mut dedup = Dedup::with_window(8);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New);
        assert_eq!(dedup.accept(SlotId(0), 3), Delivery::New); // gap at 1, 2
        assert_eq!(dedup.accept(SlotId(0), 3), Delivery::Duplicate);
        assert_eq!(dedup.accept(SlotId(0), 1), Delivery::New);
        assert_eq!(dedup.accept(SlotId(0), 2), Delivery::New); // closes the gap; 3 folds in
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::Duplicate); // below the prefix now
    }

    #[test]
    fn dedup_does_not_drop_a_low_seq_after_a_high_one() {
        // The regression: a high seq arriving first must not push an older, not
        // yet delivered seq out as "too old". Both are new deliveries.
        let mut dedup = Dedup::with_window(8);
        assert_eq!(dedup.accept(SlotId(0), 7), Delivery::New);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New);
    }

    #[test]
    fn dedup_rejects_seq_beyond_window() {
        let mut dedup = Dedup::with_window(8);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New); // prefix top = 0, base = 1
        assert_eq!(dedup.accept(SlotId(0), 9), Delivery::OutOfWindow); // 9 - 1 >= 8
        assert_eq!(dedup.accept(SlotId(0), 8), Delivery::New); // 8 - 1 < 8, still in window
    }

    /// An anchor at the u64 ceiling, followed by a payload at the u64 ceiling,
    /// must not panic (debug) or silently wrap the window (release) — the
    /// defense-in-depth backstop for a resume anchor that somehow reaches
    /// this far unclamped (the real gate is the relay's own anchor
    /// validation; this only proves the fold itself can't be driven into
    /// undefined-by-overflow territory if that gate were ever bypassed).
    #[test]
    fn accept_and_anchor_never_overflow_at_the_u64_ceiling() {
        let mut dedup = Dedup::with_window(8);
        dedup.anchor(SlotId(0), u64::MAX);
        // Anchoring at u64::MAX sets delivered_through to u64::MAX - 1, so the
        // window's base is u64::MAX. A payload at u64::MAX itself is exactly
        // at that base (seq - base == 0), so it's accepted, and the absorb
        // loop's `next.checked_add(1)` must stop cleanly at the ceiling
        // rather than overflow.
        assert_eq!(dedup.accept(SlotId(0), u64::MAX), Delivery::New);
        assert_eq!(dedup.delivered_through(SlotId(0)), Some(u64::MAX));
        // A repeat at the exact ceiling is a duplicate: it sits at the prefix
        // top, which is compared directly rather than against a "one past
        // u64::MAX" that can't be represented. State is unchanged.
        assert_eq!(dedup.accept(SlotId(0), u64::MAX), Delivery::Duplicate);
        assert_eq!(dedup.delivered_through(SlotId(0)), Some(u64::MAX));
    }

    #[test]
    fn a_repeated_u64_max_seq_is_a_duplicate_not_a_fresh_delivery() {
        // With the prefix top anchored at the u64 ceiling, a re-sent seq at the
        // ceiling must dedup as a duplicate, not be re-delivered as new every
        // time it arrives. Deriving a "next expected" seq by adding one to the
        // prefix top would have to clamp back onto the ceiling and then read the
        // repeat as a fresh delivery.
        let mut dedup = Dedup::with_window(8);
        dedup.anchor(SlotId(0), u64::MAX);
        assert_eq!(dedup.accept(SlotId(0), u64::MAX), Delivery::New);
        assert_eq!(dedup.accept(SlotId(0), u64::MAX), Delivery::Duplicate);
        assert_eq!(dedup.accept(SlotId(0), u64::MAX), Delivery::Duplicate);
        assert_eq!(dedup.delivered_through(SlotId(0)), Some(u64::MAX));
    }

    #[test]
    fn anchored_window_accepts_a_resumed_high_seq_stream() {
        // A session re-homed onto a fresh dedup resumes its slot mid-stream. Without
        // an anchor the base is 0, so a seq at/beyond the window is rejected and the
        // prefix never forms. Anchored at the resume point, the resumed stream is
        // accepted and the prefix advances from there.
        let mut dedup = Dedup::with_window(8);

        // Unanchored: the resumed seq 20 is far beyond the from-zero window.
        assert_eq!(dedup.accept(SlotId(0), 20), Delivery::OutOfWindow);

        // Anchor slot 1 at its resume point (20): base becomes 20.
        dedup.anchor(SlotId(1), 20);
        assert_eq!(dedup.accept(SlotId(1), 20), Delivery::New);
        assert_eq!(dedup.accept(SlotId(1), 21), Delivery::New);
        // Seqs below the anchor are already-delivered (never re-delivered to the game).
        assert_eq!(dedup.accept(SlotId(1), 19), Delivery::Duplicate);
        // The prefix advanced from the anchor, so the window slides: a seq that would
        // be out-of-window against a from-zero base is fine here.
        assert_eq!(dedup.delivered_through(SlotId(1)), Some(21));
        assert_eq!(dedup.accept(SlotId(1), 25), Delivery::New);
    }

    #[test]
    fn anchor_is_a_no_op_on_zero_or_an_already_active_slot() {
        let mut dedup = Dedup::with_window(8);
        // Anchor 0 leaves the default from-zero base.
        dedup.anchor(SlotId(0), 0);
        assert_eq!(dedup.accept(SlotId(0), 0), Delivery::New);
        // Once a slot has received, a later anchor never rewinds its prefix.
        assert_eq!(dedup.accept(SlotId(0), 1), Delivery::New);
        dedup.anchor(SlotId(0), 100);
        assert_eq!(dedup.accept(SlotId(0), 2), Delivery::New);
        assert_eq!(dedup.delivered_through(SlotId(0)), Some(2));
    }

    #[tokio::test]
    async fn same_relay_resume_anchor_from_oldest_unacked_accepts_a_past_window_stream() {
        // The same-relay reconnect fix, end to end at the transport layer: a client
        // deep into a game (unacked turns at a high absolute seq) sources its own-slot
        // resume anchor from `oldest_unacked_seq` — exactly what the driver presents on
        // a same-relay dial — and a fresh relay-side dedup anchored there accepts the
        // resumed stream that a from-zero window would reject as out-of-window (the
        // production blocker for any game past ~4096 turns).
        let (mut sender, _peer, _ea, _eb) = connected_links().await;

        let high = |seq: u64| Payload {
            seq,
            slot: 0,
            commands: vec![0u8; 4].into(),
            ..Default::default()
        };
        // The peer never acks, so these stay in flight — the window the redundancy
        // pass re-carries over a rebound connection, oldest-first.
        for seq in [8000u64, 8001, 8002] {
            sender.send(Some(high(seq))).unwrap();
        }
        let anchor = sender
            .oldest_unacked_seq(SlotId(0))
            .expect("turns are in flight");
        assert_eq!(
            anchor, 8000,
            "the same-relay anchor is the oldest unacked seq"
        );

        // The relay builds a fresh dedup on the re-dial. From zero the resumed seq is
        // far beyond the window (the bug); anchored at the resume point it is accepted
        // and the delivered prefix advances from there.
        let mut unanchored = Dedup::with_window(RECEIVE_WINDOW);
        assert_eq!(
            unanchored.accept(SlotId(0), anchor),
            Delivery::OutOfWindow,
            "without the anchor a fresh relay rejects the resumed stream",
        );

        let mut anchored = Dedup::with_window(RECEIVE_WINDOW);
        anchored.anchor(SlotId(0), anchor);
        for seq in [8000u64, 8001, 8002] {
            assert_eq!(anchored.accept(SlotId(0), seq), Delivery::New);
        }
        assert_eq!(anchored.delivered_through(SlotId(0)), Some(8002));
    }

    #[tokio::test]
    async fn ingress_slot_rebinds_a_wire_slot_zero_payload_to_the_authorized_slot() {
        // A relay's client edge authorizes one slot. The real game client leaves the
        // wire slot at 0 on every turn, but dedup and the receive-window anchor key
        // on the authorized slot. An ingress link rewrites the wire slot before
        // dedup, so a resumed high-seq stream anchored on the authorized slot is
        // accepted — not rejected as out-of-window under a phantom slot-0 key.
        let (raw, _peer, _ea, _eb) = connected_connections().await;
        let mut link = Link::with_ingress_slot(raw, SlotId(1));
        link.anchor_receive_window(SlotId(1), 8000);

        let packet = Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: vec![Payload {
                seq: 8000,
                slot: 0, // the untrusted wire claim the real client always sends
                commands: vec![0x05].into(),
                ..Default::default()
            }],
        };
        let received = link.process_incoming(packet).unwrap();
        assert_eq!(received.fresh.len(), 1);
        // Rebound to the authorized slot, both in the dedup key and on the payload.
        assert_eq!(received.fresh[0].slot, 1);
        assert_eq!(link.delivered_through(SlotId(1)), Some(8000));
        // Nothing was ever keyed under the wire slot 0.
        assert_eq!(link.delivered_through(SlotId(0)), None);
    }

    /// A packet whose earlier payloads are genuinely in-window but whose LAST
    /// payload is out of window must not leave dedup believing the earlier
    /// ones were delivered: the whole packet rolls back, so the caller can
    /// re-receive them later rather than losing them to a permanent silent
    /// gap. This is the core transactional-recv regression: the old code
    /// committed each payload to dedup as it went and only bailed on the
    /// offending one, discarding the already-accepted payloads from the
    /// return value while dedup kept them marked delivered.
    #[tokio::test]
    async fn a_mid_packet_out_of_window_payload_rolls_back_the_whole_packets_dedup_commit() {
        let (raw, _peer, _ea, _eb) = connected_connections().await;
        let mut link = Link::new(raw);

        let packet = Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: vec![
                // Genuinely in-window and would be delivered on its own.
                Payload {
                    seq: 0,
                    slot: 0,
                    commands: vec![0xAA].into(),
                    ..Default::default()
                },
                // Far beyond the receive window -- the whole packet fails.
                Payload {
                    seq: u64::MAX,
                    slot: 0,
                    commands: vec![0xBB].into(),
                    ..Default::default()
                },
            ],
        };
        match link.process_incoming(packet) {
            Err(LinkError::PayloadOutOfWindow { slot, seq }) => {
                assert_eq!(slot, SlotId(0));
                assert_eq!(seq, u64::MAX);
            }
            other => panic!("expected PayloadOutOfWindow, got {other:?}"),
        }

        // The rollback: slot 0 must show no delivered prefix at all -- the
        // seq-0 payload was never actually handed to a caller (it's absent
        // from every `Received.fresh` this test ever saw), so dedup must not
        // remember it as delivered either.
        assert_eq!(
            link.delivered_through(SlotId(0)),
            None,
            "the in-window payload's provisional accept must be rolled back \
             along with the packet that failed",
        );

        // Proof it's genuinely recoverable: the same seq, redelivered alone
        // in a fresh packet, is accepted as new -- not rejected as a
        // duplicate of something the caller never actually received.
        let retry = Packet {
            seq: 1,
            ack: None,
            ack_bits: 0,
            payloads: vec![Payload {
                seq: 0,
                slot: 0,
                commands: vec![0xAA].into(),
                ..Default::default()
            }],
        };
        let received = link.process_incoming(retry).unwrap();
        assert_eq!(received.fresh.len(), 1, "the payload is deliverable again");
        assert_eq!(link.delivered_through(SlotId(0)), Some(0));
    }

    /// The same rollback, but the packet-ending failure is a malformed slot
    /// (out of `u8` range) rather than an out-of-window seq -- an earlier
    /// payload for a DIFFERENT, valid slot in the same packet must also be
    /// rolled back, not left half-committed.
    #[tokio::test]
    async fn a_trailing_malformed_slot_rolls_back_an_earlier_valid_slots_commit_too() {
        let (raw, _peer, _ea, _eb) = connected_connections().await;
        let mut link = Link::new(raw);

        let packet = Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: vec![
                Payload {
                    seq: 0,
                    slot: 0,
                    commands: vec![0xAA].into(),
                    ..Default::default()
                },
                Payload {
                    seq: 0,
                    slot: 300, // out of u8 range
                    commands: vec![0xBB].into(),
                    ..Default::default()
                },
            ],
        };
        match link.process_incoming(packet) {
            Err(LinkError::MalformedSlot(300)) => {}
            other => panic!("expected MalformedSlot(300), got {other:?}"),
        }
        assert_eq!(
            link.delivered_through(SlotId(0)),
            None,
            "slot 0's earlier commit rolls back alongside the malformed payload",
        );
    }

    #[tokio::test]
    async fn a_non_ingress_link_keeps_per_wire_slot_demux() {
        // A link with no ingress slot (the fan-in and mesh links) trusts the wire
        // slot: two payloads with different wire slots dedup independently, each
        // under its own key. This is the behavior the ingress rebind must not
        // disturb on multi-slot links.
        let (raw, _peer, _ea, _eb) = connected_connections().await;
        let mut link = Link::new(raw);

        let packet = Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: vec![
                Payload {
                    seq: 0,
                    slot: 0,
                    commands: vec![0xA0].into(),
                    ..Default::default()
                },
                Payload {
                    seq: 0,
                    slot: 1,
                    commands: vec![0xB0].into(),
                    ..Default::default()
                },
            ],
        };
        let received = link.process_incoming(packet).unwrap();
        assert_eq!(received.fresh.len(), 2);
        // Each wire slot advanced its own prefix; neither collapsed into the other.
        assert_eq!(link.delivered_through(SlotId(0)), Some(0));
        assert_eq!(link.delivered_through(SlotId(1)), Some(0));
    }

    #[tokio::test]
    async fn same_relay_resume_on_a_nonzero_slot_accepts_a_wire_slot_zero_stream() {
        // The exact production regression, one layer below the relay: the resuming
        // client is authorized on a NONZERO slot but — like the real DLL — stamps
        // wire slot 0 on every turn. The same-relay anchor is keyed on the authorized
        // slot, so a relay edge that keyed dedup on the wire slot would anchor slot N
        // yet dedup slot 0, making the anchor a silent no-op and rejecting the first
        // resumed turn past the window. The ingress-slot rebind keeps both on slot N.
        let (raw_sender, raw_relay, _ea, _eb) = connected_connections().await;
        let mut sender = Link::new(raw_sender);

        // The client counts its own seqs across the move but always sends wire slot 0.
        let turn = |seq: u64| Payload {
            seq,
            slot: 0,
            commands: vec![0u8; 4].into(),
            ..Default::default()
        };
        for seq in [8000u64, 8001, 8002] {
            sender.send(Some(turn(seq))).unwrap();
        }
        let anchor = sender
            .oldest_unacked_seq(SlotId(0))
            .expect("turns are in flight");
        assert_eq!(
            anchor, 8000,
            "the same-relay anchor is the oldest unacked seq"
        );

        // The fresh relay edge authorizes this client as slot 1 and anchors slot 1 at
        // the resume point. Even though every incoming payload claims wire slot 0, the
        // rebind keys them under slot 1, where the anchor lives.
        let mut relay = Link::with_ingress_slot(raw_relay, SlotId(1));
        relay.anchor_receive_window(SlotId(1), anchor);
        for seq in [8000u64, 8001, 8002] {
            let packet = Packet {
                seq: 0,
                ack: None,
                ack_bits: 0,
                payloads: vec![turn(seq)],
            };
            let received = relay.process_incoming(packet).unwrap();
            assert_eq!(received.fresh.len(), 1);
            assert_eq!(received.fresh[0].slot, 1, "rebound to the authorized slot");
        }
        assert_eq!(relay.delivered_through(SlotId(1)), Some(8002));

        // The bug shape for contrast: a wire-slot-keyed edge (no ingress rebind)
        // anchors slot 1 but dedups the wire-slot-0 payload under slot 0's from-zero
        // window, so it rejects the very first resumed turn and would close the link.
        let (raw_bad, _peer, _ec, _ed) = connected_connections().await;
        let mut buggy = Link::new(raw_bad);
        buggy.anchor_receive_window(SlotId(1), anchor);
        let packet = Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: vec![turn(8000)],
        };
        match buggy.process_incoming(packet) {
            Err(LinkError::PayloadOutOfWindow { slot, seq }) => {
                assert_eq!(slot, SlotId(0));
                assert_eq!(seq, 8000);
            }
            other => panic!("expected the wire-slot-keyed edge to reject, got {other:?}"),
        }
    }

    fn self_signed() -> (
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        CertificateDer<'static>,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
        (vec![cert_der.clone()], key, cert_der)
    }

    /// Brings up a loopback QUIC connection, returning both raw ends plus the
    /// endpoints (kept alive by the caller). The caller wraps each connection as a
    /// [`Link`] however the test needs — [`Link::new`] or [`Link::with_ingress_slot`].
    async fn connected_connections() -> (
        quinn::Connection,
        quinn::Connection,
        quinn::Endpoint,
        quinn::Endpoint,
    ) {
        let (chain, key, ca) = self_signed();
        let server_cfg = server_config(chain, key).unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let client_cfg = client_config(roots).unwrap();

        let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let server = quinn::Endpoint::server(server_cfg, bind).unwrap();
        let server_addr = server.local_addr().unwrap();
        let mut client = quinn::Endpoint::client(bind).unwrap();
        client.set_default_client_config(client_cfg);

        let accept = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await.unwrap().await.unwrap() })
        };
        let client_conn = client
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let server_conn = accept.await.unwrap();

        (client_conn, server_conn, client, server)
    }

    /// Brings up a loopback QUIC connection and wraps each end in a plain [`Link`].
    /// The endpoints are returned so the caller keeps them alive for the test.
    async fn connected_links() -> (Link, Link, quinn::Endpoint, quinn::Endpoint) {
        let (client_conn, server_conn, client, server) = connected_connections().await;
        (
            Link::new(client_conn),
            Link::new(server_conn),
            client,
            server,
        )
    }

    fn turn(slot: u8, seq: u64, byte: u8) -> Payload {
        Payload {
            seq,
            slot: u32::from(slot),
            commands: vec![byte].into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn delivers_each_payload_once_and_retires_on_ack() {
        let (mut client, mut server, _client_ep, _server_ep) = connected_links().await;

        for i in 0..5u8 {
            client.send(Some(turn(0, i as u64, i))).unwrap();
        }
        assert_eq!(client.payloads_in_flight(), 5);

        // Each packet re-carries earlier unacked payloads, but every payload is
        // returned exactly once, in order, with its bytes intact.
        let mut delivered = Vec::new();
        while delivered.len() < 5 {
            delivered.extend(server.recv().await.unwrap().fresh);
        }
        let seqs: Vec<u64> = delivered.iter().map(|p| p.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4]);
        let bytes: Vec<u8> = delivered.iter().map(|p| p.commands[0]).collect();
        assert_eq!(bytes, vec![0, 1, 2, 3, 4]);

        // The server's ack-only reply retires everything the client had in flight.
        server.send(None).unwrap();
        client.recv().await.unwrap();
        assert_eq!(client.payloads_in_flight(), 0);
    }

    #[tokio::test]
    async fn preserves_game_frame_count_across_send_and_recv() {
        // The frame is a consensus annotation, not a transport key: the link
        // dedups and retires by (slot, seq) and must carry the frame through
        // verbatim so the relay and decision-maker can key on it. A None (lobby
        // turn) survives too — absent is a valid state, not zero.
        let (mut client, mut server, _client_ep, _server_ep) = connected_links().await;

        client
            .send(Some(Payload {
                seq: 0,
                slot: 0,
                game_frame_count: Some(1337),
                commands: vec![0x05].into(),
                ..Default::default()
            }))
            .unwrap();
        client
            .send(Some(Payload {
                seq: 1,
                slot: 0,
                commands: vec![0x05].into(),
                ..Default::default()
            }))
            .unwrap();

        let mut delivered = Vec::new();
        while delivered.len() < 2 {
            delivered.extend(server.recv().await.unwrap().fresh);
        }
        delivered.sort_by_key(|p| p.seq);
        assert_eq!(delivered[0].game_frame_count, Some(1337));
        assert_eq!(delivered[1].game_frame_count, None);
    }

    #[tokio::test]
    async fn preserves_buffer_directive_across_send_and_recv() {
        // A relay-authored buffer change rides the Payload envelope, so the link
        // must carry it through verbatim like any other payload field — it is not
        // a transport key (dedup and retirement stay on (slot, seq)), just metadata
        // the game applies out of band. Absent is the common case and survives too.
        use rally_point_proto::messages::BufferDirective;
        let (mut client, mut server, _client_ep, _server_ep) = connected_links().await;

        client
            .send(Some(Payload {
                seq: 0,
                slot: 0,
                game_frame_count: Some(500),
                buffer_directive: Some(BufferDirective {
                    buffer_turns: 6,
                    apply_at_frame: 512,
                    decision_seq: 3,
                    authority_relay_id: None,
                }),
                commands: vec![0x0C].into(),
            }))
            .unwrap();
        client
            .send(Some(Payload {
                seq: 1,
                slot: 0,
                game_frame_count: Some(501),
                commands: vec![0x0C].into(),
                ..Default::default()
            }))
            .unwrap();

        let mut delivered = Vec::new();
        while delivered.len() < 2 {
            delivered.extend(server.recv().await.unwrap().fresh);
        }
        delivered.sort_by_key(|p| p.seq);
        assert_eq!(
            delivered[0].buffer_directive,
            Some(BufferDirective {
                buffer_turns: 6,
                apply_at_frame: 512,
                decision_seq: 3,
                authority_relay_id: None,
            }),
        );
        assert_eq!(delivered[1].buffer_directive, None);
    }

    #[tokio::test]
    async fn delivers_each_slot_independently() {
        // Two slots' turns interleave on the wire; each is dedup'd by (slot, seq).
        let (mut client, mut server, _client_ep, _server_ep) = connected_links().await;

        client.send(Some(turn(0, 0, 0xA0))).unwrap();
        client.send(Some(turn(1, 0, 0xB0))).unwrap();
        client.send(Some(turn(0, 1, 0xA1))).unwrap();
        client.send(Some(turn(1, 1, 0xB1))).unwrap();

        let mut delivered = Vec::new();
        while delivered.len() < 4 {
            delivered.extend(server.recv().await.unwrap().fresh);
        }

        // Slot 0's turns and slot 1's turns each arrive in their own seq order;
        // the two streams are independent.
        let slot0: Vec<u8> = delivered
            .iter()
            .filter(|p| p.slot == 0)
            .map(|p| p.commands[0])
            .collect();
        let slot1: Vec<u8> = delivered
            .iter()
            .filter(|p| p.slot == 1)
            .map(|p| p.commands[0])
            .collect();
        assert_eq!(slot0, vec![0xA0, 0xA1]);
        assert_eq!(slot1, vec![0xB0, 0xB1]);
    }

    #[tokio::test]
    async fn delivers_a_redundant_low_seq_carried_after_a_high_fresh_one() {
        let (client, mut server, _client_ep, _server_ep) = connected_links().await;

        // A deep-loss packet leads with a high fresh seq and re-carries an older
        // unacked one. Both must be delivered — the low seq is not dropped.
        let packet = Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: vec![
                Payload {
                    seq: RECEIVE_WINDOW,
                    slot: 0,
                    commands: vec![0xAA].into(),
                    ..Default::default()
                },
                Payload {
                    seq: 0,
                    slot: 0,
                    commands: vec![0xBB].into(),
                    ..Default::default()
                },
            ],
        };
        client
            .connection()
            .send_datagram(packet.encode_to_vec().into())
            .unwrap();

        let delivered = server.recv().await.unwrap().fresh;
        let seqs: Vec<u64> = delivered.iter().map(|p| p.seq).collect();
        assert_eq!(seqs, vec![0, RECEIVE_WINDOW]);
    }

    #[tokio::test]
    async fn rejects_payload_seq_beyond_the_window() {
        let (client, mut server, _client_ep, _server_ep) = connected_links().await;

        // A seq racing far past our contiguous progress must be rejected, not
        // panic the receiver.
        let malformed = Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: vec![Payload {
                seq: u64::MAX,
                slot: 0,
                commands: vec![1].into(),
                ..Default::default()
            }],
        };
        client
            .connection()
            .send_datagram(malformed.encode_to_vec().into())
            .unwrap();

        match server.recv().await {
            Err(LinkError::PayloadOutOfWindow { slot, seq }) => {
                assert_eq!(slot, SlotId(0));
                assert_eq!(seq, u64::MAX);
            }
            other => panic!("expected PayloadOutOfWindow, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_a_payload_whose_wire_slot_does_not_fit_a_slot_id() {
        let (client, mut server, _client_ep, _server_ep) = connected_links().await;

        // A wire slot past `u8` range must be refused, not silently truncated
        // onto a different, valid slot's dedup state (`300 as u8` would alias
        // onto slot 44).
        let malformed = Packet {
            seq: 0,
            ack: None,
            ack_bits: 0,
            payloads: vec![Payload {
                seq: 0,
                slot: 300,
                commands: vec![1].into(),
                ..Default::default()
            }],
        };
        client
            .connection()
            .send_datagram(malformed.encode_to_vec().into())
            .unwrap();

        match server.recv().await {
            Err(LinkError::MalformedSlot(slot)) => assert_eq!(slot, 300),
            other => panic!("expected MalformedSlot, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_rejects_a_payload_whose_wire_slot_does_not_fit_a_slot_id() {
        let (mut client, _server, _client_ep, _server_ep) = connected_links().await;

        // A wire slot past `u8` range is refused before any send-side state is
        // built for it, rather than narrowed onto a different, valid slot's
        // bookkeeping (`300 as u8` would alias onto slot 44).
        let malformed = Payload {
            seq: 0,
            slot: 300,
            commands: vec![1].into(),
            ..Default::default()
        };
        match client.send(Some(malformed)) {
            Err(LinkError::MalformedSlot(slot)) => assert_eq!(slot, 300),
            other => panic!("expected MalformedSlot, got {other:?}"),
        }
        // Nothing was tracked: the refused turn never entered the unacked window.
        assert_eq!(client.payloads_in_flight(), 0);
    }

    #[tokio::test]
    async fn surfaces_a_turn_too_large_for_a_datagram() {
        let (mut client, _server, _client_ep, _server_ep) = connected_links().await;

        let budget = client
            .connection()
            .max_datagram_size()
            .expect("loopback supports datagrams");

        // A turn whose own bytes dwarf the datagram budget can ride no datagram, so
        // send surfaces it as an error rather than silently stalling. With the tiny
        // turns of a lockstep game this never happens.
        let oversize = Payload {
            seq: 0,
            slot: 0,
            commands: vec![0u8; budget + 1].into(),
            ..Default::default()
        };
        match client.send(Some(oversize)) {
            Err(LinkError::PayloadTooLarge {
                needed,
                budget: reported,
            }) => {
                assert_eq!(reported, budget);
                assert!(needed > budget);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }
}
