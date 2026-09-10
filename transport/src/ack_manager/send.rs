//! The send half of the manager: building a packet, choosing which unacked
//! payloads ride along as redundancy, and recording what actually reached the
//! wire.
//!
//! Grouped apart from the receive half because everything here grows or
//! re-carries the unacked window, where the receive side retires it.

use prost::Message;
use rally_point_proto::ids::SlotId;
use rally_point_proto::messages::{Packet, Payload};

use super::AckManager;
use super::sent::{PacketSeqExhausted, SentPacket, SentPayload, payload_element_len};

impl AckManager {
    /// Builds the next outgoing [`Packet`].
    ///
    /// The packet is stamped with the next packet seq and the current ack state.
    /// If `payload` is `Some`, it is included verbatim — its `(slot, seq)` is its
    /// origin identity, already assigned by the sending client and preserved
    /// untouched here — always included (even if it alone exceeds `max_packet_len`
    /// — the current turn is never dropped), and tracked for re-sending until
    /// acked. The remaining space is then filled with still-unacked payloads for
    /// redundancy, as the manager's [`RecarryPolicy`] directs: only payloads due
    /// under its spacing schedule compete, its byte budget caps what they may
    /// collectively spend (the first element exempt, so a wide payload stays
    /// re-carryable), and `max_packet_len` bounds everything. If `payload` is
    /// `None`, there is no fresh payload, but due payloads are packed as
    /// redundancy the same way. The result is truly ack-only only when nothing
    /// is due (or none of it fits).
    ///
    /// `max_packet_len` is the live datagram budget (e.g. noq's
    /// `max_datagram_size()`); pass the current value each call so the bundle
    /// tracks path MTU changes.
    ///
    /// Building **selects but does not record**: the carry bookkeeping (each
    /// carried payload's count and stamp, and the sent-set entry that lets an
    /// ack retire the packet) describes what reached the wire, so the caller
    /// applies it by passing the sent packet to
    /// [`record_sent`](Self::record_sent) once the transport accepts it — and
    /// simply doesn't when the send fails (a path-MTU race, a dying
    /// connection). A built-but-unsent packet therefore leaves no trace beyond
    /// its consumed seq: its payloads' re-carry schedules are undisturbed, and
    /// no ack can retire what never rode the wire. The fresh payload is the
    /// deliberate exception — it is registered in the unacked window here, at
    /// build, because a fresh turn whose datagram fails needs future re-carry
    /// more, not less.
    ///
    /// Returns [`PacketSeqExhausted`] if the connection's `u32` packet seq space
    /// is used up. This is unreachable within a game at the turn rate (see the
    /// `packet_seq` field docs); it is surfaced rather than
    /// wrapped (which would silently break acking) so the caller can tear the
    /// connection down and reset rather than the process aborting on a panic. No
    /// state is mutated when it is returned, so a caller that resets can retry.
    ///
    /// [`RecarryPolicy`]: super::RecarryPolicy
    pub fn build_outgoing(
        &mut self,
        payload: Option<Payload>,
        max_packet_len: usize,
    ) -> Result<Packet, PacketSeqExhausted> {
        // Reserve the next packet seq before mutating anything else: a wrapped
        // packet seq would silently break acking, so exhaustion is terminal for
        // the connection and surfaced (not wrapped, not panicked) here, before any
        // state changes, so a caller that resets starts clean.
        let advanced = self.packet_seq.checked_add(1).ok_or(PacketSeqExhausted)?;

        let mut packet = Packet {
            seq: self.packet_seq,
            ack: self.last_seen_remote().map(|s| s as u32),
            ack_bits: self.ack_bits(),
            payloads: Vec::new(),
        };
        self.packet_seq = advanced;

        // Running size of the encoded packet, kept in step with `packet.payloads`
        // so we never overrun the datagram budget.
        let mut used = packet.encoded_len();

        // The fresh payload is included verbatim. Its `(slot, seq)` origin identity
        // is already assigned upstream and is never rewritten here. Its wire slot
        // must fit a `SlotId` to be tracked without aliasing onto a different
        // slot's bookkeeping: a truncating narrowing would map slot `256 + n` onto
        // slot `n`'s window while the wire payload kept its original value. The send
        // layer refuses an out-of-range slot before building a packet for it, so a
        // payload reaching here with one is malformed and is dropped from both the
        // wire and the bookkeeping together — never tracked under an aliased key
        // while riding a datagram.
        let fresh = payload.and_then(|p| match u8::try_from(p.slot) {
            Ok(raw) => {
                let len = p.encoded_len();
                Some((SlotId(raw), p, len))
            }
            Err(_) => {
                tracing::debug!(
                    slot = p.slot,
                    "dropping outbound payload whose slot is out of SlotId range"
                );
                None
            }
        });
        if let Some((_, p, len)) = &fresh {
            used += payload_element_len(*len);
            packet.payloads.push(p.clone());
        }

        // The cap redundancy may fill to: the datagram budget, tightened by the
        // policy's per-packet redundancy byte budget when one is set. The fresh
        // payload is exempt (it was pushed above, before this cap is computed),
        // so the budget only ever limits re-carries.
        let redundancy_cap = match self.policy.redundancy_byte_budget {
            Some(budget) => max_packet_len.min(used.saturating_add(budget)),
            None => max_packet_len,
        };
        let spacing = self.policy.spacing;
        let building_seq = packet.seq;

        // When no spacing schedule filters the window and the whole window fits
        // under the cap, ranking cannot affect coverage: every candidate rides
        // this packet. Check that case from the cached encoded lengths and
        // refill directly in the BTreeMap's stable `(slot, seq)` order,
        // avoiding both the temporary candidate allocation and its sort on the
        // common small-window path.
        let unacked_payload_wire_len = self.unacked_payload_wire_len();
        let all_candidates_fit = redundancy_cap
            .checked_sub(used)
            .is_some_and(|remaining| unacked_payload_wire_len <= remaining);
        if spacing.is_none() && all_candidates_fit {
            packet.payloads.reserve(self.unacked_payloads.len());
            for sent in self.unacked_payloads.values() {
                packet.payloads.push(sent.payload.clone());
            }
        } else {
            // Only payloads due under the spacing schedule compete for the
            // cap. First pass: the due set's size and total wire cost.
            let mut due_wire_len = 0usize;
            let mut due_count = 0usize;
            for sent in self.unacked_payloads.values() {
                if sent.is_due(spacing, building_seq) {
                    due_wire_len += sent.wire_len;
                    due_count += 1;
                }
            }
            let all_due_fit = redundancy_cap
                .checked_sub(used)
                .is_some_and(|remaining| due_wire_len <= remaining);
            if all_due_fit {
                // Every due candidate rides, so ranking cannot affect coverage:
                // carry them in the BTreeMap's stable `(slot, seq)` order with
                // no candidate allocation — the common shape once spacing has
                // thinned the set.
                packet.payloads.reserve(due_count);
                for sent in self.unacked_payloads.values() {
                    if !sent.is_due(spacing, building_seq) {
                        continue;
                    }
                    packet.payloads.push(sent.payload.clone());
                }
            } else {
                // A constrained packet serves the longest-waiting carry first.
                // The ranking key must be one that *grows* for a candidate that
                // gets passed over — ranking by a static property (send count
                // was tried) starves under pressure: continuous fresh traffic
                // introduces new better-ranked candidates every packet, so a
                // due-but-outranked payload below the budget cutoff could stay
                // there indefinitely while its retirement (and with it the
                // peer's delivered prefix, which its seq gates) never advances.
                // The waiting age (packets since last carry, or since entering
                // the window for a payload nothing has carried yet — see
                // [`SentPayload::waiting_age`]) is monotone in exactly the
                // right way: a skipped candidate only ranks higher next
                // packet, and every *arrival* — a recorded fresh send and a
                // never-carried registration alike — enters at the bottom, so
                // no arrival pattern (continuous fresh traffic, recurring
                // refused builds) can indefinitely outrank a payload whose
                // wait keeps growing. Every payload is served while any
                // redundancy flows at all. Under scarcity that order is also
                // the *correct* priority: it approximates oldest-first, and
                // the oldest missing seq is what gates lockstep. The stable
                // sort keeps tied candidates in the BTreeMap's underlying
                // `(slot, seq)` order, oldest per slot first, which also
                // spreads coverage across slots. The fresh payload isn't in
                // `unacked_payloads` yet, so it cannot double up.
                let mut candidates: Vec<&SentPayload> = self
                    .unacked_payloads
                    .values()
                    .filter(|sent| sent.is_due(spacing, building_seq))
                    .collect();
                candidates.sort_by_key(|sent| std::cmp::Reverse(sent.waiting_age(building_seq)));
                // The first (most overdue) candidate is capped by the datagram
                // budget alone, not the policy budget: a payload wider than
                // the policy budget could otherwise never be re-carried by any
                // packet — including the standalone flushes that exist to
                // retransmit it — and a lost wide turn would stall lockstep
                // unrecoverably. The exemption admits at most one over-budget
                // element per packet, so the aggregate stays bounded by
                // budget + one payload.
                //
                // And when even the datagram budget cannot fit that first
                // candidate (a wide turn sharing a packet with a fresh one),
                // the packet deliberately carries **no redundancy at all**
                // rather than serving smaller, lower-priority candidates
                // around it. Both drivers arm their maintenance flush exactly
                // when a send re-carried nothing, and a flush packet — no
                // fresh payload — always has room for any registered payload:
                // the send layers admit datagram payloads against
                // [`GUARANTEED_DATAGRAM_BUDGET`], the budget no legal path MTU
                // can undercut, and divert larger ones to the reliable streams
                // before they are ever registered. Packing around a blocked
                // head of line instead would keep resetting that flush from
                // packets the wide payload can never ride, stranding it behind
                // traffic indefinitely.
                let mut packed_redundancy = false;
                for sent in candidates {
                    let element = sent.wire_len;
                    if !packed_redundancy {
                        if used + element > max_packet_len {
                            if fresh.is_none() {
                                // A fresh-free packet is the roomiest this
                                // connection builds; its head not fitting
                                // means a payload wider than the admission
                                // floor was registered — a caller bug the
                                // admission cap exists to prevent, and one
                                // that strands the payload (every flush from
                                // here on goes out ack-only).
                                tracing::warn!(
                                    element,
                                    max_packet_len,
                                    "unacked payload is too wide for even a fresh-free packet; \
                                     it can never be re-carried",
                                );
                            }
                            break;
                        }
                    } else if used + element > redundancy_cap {
                        continue;
                    }
                    packed_redundancy = true;
                    used += element;
                    packet.payloads.push(sent.payload.clone());
                }
            }
        }

        // Register the fresh payload as unacked — after the redundancy pass so
        // it cannot double up, and unconditionally (not in `record_sent`): even
        // if this packet's send fails, the fresh turn must sit in the window
        // for future re-carry. Its carry count starts at zero; `record_sent`
        // credits its ride along with every other carried payload's.
        if let Some((slot, p, len)) = fresh {
            self.insert_unacked(
                (slot, p.seq),
                SentPayload {
                    send_count: 0,
                    last_carried_packet_seq: None,
                    registered_at_packet_seq: building_seq,
                    wire_len: payload_element_len(len),
                    payload: p,
                },
            );
        }

        Ok(packet)
    }

    /// Records that a packet [`build_outgoing`](Self::build_outgoing) returned
    /// actually reached the wire: each carried payload's coverage advances (its
    /// carry count and spacing stamp), and the packet enters the sent set so a
    /// later ack can retire everything it carried.
    ///
    /// Call this with the built packet after the transport accepts the
    /// datagram, and not otherwise — the bookkeeping describes what went out,
    /// so a refused send (a path-MTU race, a dying connection) is simply never
    /// recorded, leaving the carried payloads' re-carry schedules undisturbed
    /// and nothing for an impossible ack to retire.
    pub fn record_sent(&mut self, packet: &Packet) {
        let mut payload_keys: Vec<(SlotId, u64)> = Vec::with_capacity(packet.payloads.len());
        for p in &packet.payloads {
            // Out-of-range wire slots never survive `build_outgoing`, so this
            // narrowing cannot fail for a packet it built; skipping (rather
            // than truncating) keeps a malformed input from aliasing another
            // slot's bookkeeping all the same.
            let Ok(raw) = u8::try_from(p.slot) else {
                continue;
            };
            let key = (SlotId(raw), p.seq);
            if let Some(sent) = self.unacked_payloads.get_mut(&key) {
                sent.send_count += 1;
                sent.last_carried_packet_seq = Some(packet.seq);
            }
            payload_keys.push(key);
        }
        self.sent_packets.insert(
            u64::from(packet.seq),
            SentPacket {
                payload_slots_seqs: payload_keys.into(),
            },
        );
    }

    /// Re-registers a payload as still-unacked so the redundancy pass re-carries
    /// it, **without** sending a packet — the re-inject half of a coordinator-
    /// mediated re-home.
    ///
    /// After a client re-homes onto a replacement relay, that relay's turn ring is
    /// empty: turns the client sent that the *old* relay had already acked (and so
    /// were retired from this window) would otherwise never reach the new relay to
    /// be fanned out to peers. Re-injecting them here puts them back in the unacked
    /// set so the next packet's redundancy carries them over the new connection,
    /// where peers dedup by origin `(slot, seq)`. A payload already unacked (one in
    /// flight at the drop, kept by [`reset_connection`](Self::reset_connection)) is
    /// left untouched, so a re-inject never resets its `send_count` or double-tracks
    /// it.
    pub fn reinject_unacked(&mut self, payload: Payload) {
        // The wire slot must fit a `SlotId` to be tracked without aliasing onto a
        // different slot's window: a truncating narrowing would map slot `256 + n`
        // onto slot `n`. A turn a client produced always names its own in-range
        // slot, so one that does not is malformed and is dropped rather than
        // re-injected under an aliased key.
        let Ok(raw) = u8::try_from(payload.slot) else {
            tracing::debug!(
                slot = payload.slot,
                "dropping re-injected payload whose slot is out of SlotId range"
            );
            return;
        };
        let key = (SlotId(raw), payload.seq);
        if !self.unacked_payloads.contains_key(&key) {
            let encoded_len = payload.encoded_len();
            let registered_at_packet_seq = self.packet_seq;
            self.insert_unacked(
                key,
                SentPayload {
                    send_count: 0,
                    last_carried_packet_seq: None,
                    registered_at_packet_seq,
                    wire_len: payload_element_len(encoded_len),
                    payload,
                },
            );
        }
    }

    /// Inserts or replaces one unacked payload while keeping the aggregate wire
    /// size exact. Replacement is defensive; normal origin seqs are unique.
    fn insert_unacked(&mut self, key: (SlotId, u64), sent: SentPayload) {
        let new_len = sent.wire_len;
        if let Some(previous) = self.unacked_payloads.insert(key, sent)
            && let Some(total) = self.unacked_payload_wire_len.as_mut()
        {
            *total = total.saturating_sub(previous.wire_len);
        }
        if let Some(total) = self.unacked_payload_wire_len.as_mut() {
            *total = total.saturating_add(new_len);
        }
    }
}
