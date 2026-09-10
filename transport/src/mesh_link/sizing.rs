//! How much of a datagram the `MeshPacket` wrapper costs, and what a payload
//! must fit inside to be admitted for datagram carriage.
//!
//! Grouped together because they are one calculation split three ways: the
//! send path and the `payload_fits` pre-check must agree byte for byte, or a
//! turn a caller was told would fit gets refused on the wire instead.

use prost::Message;
use rally_point_proto::messages::LinkConditions;

/// Worst-case byte overhead a `MeshPacket` adds around the inner `Packet` when
/// the wrapper carries no conditions sidecar and no tenant: the session field
/// tag (1) + its varint (≤10 for a u64, but a real session id fits in ≤5),
/// plus the inner `Packet` field tag (1) + its length prefix (≤3 for any
/// packet under ~16MB). 16 covers the worst case with margin.
///
/// When conditions or a tenant are attached, [`MeshLink::send`] measures each
/// one's exact wire cost with a prost `encoded_len` probe (conditions) or a
/// direct length computation (the tenant string) rather than reserving a fixed
/// worst case, so the redundancy budget that defends lockstep latency is never
/// stolen by a reservation for a field that may be small or absent (ack-only
/// flushes carry no conditions; a tenant-less send carries no tenant). The
/// inner `Packet` field's own tag + length prefix is the one part that can't
/// be probed without the packet itself, so it stays in this const — it is
/// bounded and small.
///
/// [`MeshLink::send`]: super::MeshLink::send
pub(super) const MESH_PACKET_OVERHEAD: usize = 16;

/// The exact wire cost of embedding `conditions` as the `MeshPacket.conditions`
/// field: the field's own tag (1 byte -- field number 3 fits a 1-byte tag),
/// its length-delimiter varint, and its encoded body. `LinkConditions::encoded_len`
/// alone -- what [`MeshLink::send`] and [`MeshLink::payload_fits`] used to
/// budget against -- is only the body; a prost message's `encoded_len` never
/// includes the tag/length-prefix that wraps it when it's embedded as a field
/// of another message, so using it bare under-counted this field's real wire
/// cost by a few bytes. Not a live bug: [`MESH_PACKET_OVERHEAD`]'s own margin
/// (worst case ~10 bytes, budgeted at 16) has always absorbed the shortfall,
/// but the accounting was wrong on its own terms, not merely generous.
///
/// [`MeshLink::send`]: super::MeshLink::send
/// [`MeshLink::payload_fits`]: super::MeshLink::payload_fits
pub(super) fn conditions_element_len(conditions: &LinkConditions) -> usize {
    let body_len = conditions.encoded_len();
    1 + prost::encoding::encoded_len_varint(body_len as u64) + body_len
}

/// The exact wire cost of embedding `tenant` as the `MeshPacket.tenant` field:
/// the field's own tag (1 byte — field number 4 fits a 1-byte tag), its
/// length-delimiter varint, and the string's raw byte length. Mirrors
/// [`conditions_element_len`] for the same reason: a tenant id can run up to
/// 255 bytes (`token::MAX_STRING_LEN`), far past [`MESH_PACKET_OVERHEAD`]'s
/// fixed margin, so its wire cost is measured exactly rather than guessed at.
pub(super) fn tenant_element_len(tenant: &str) -> usize {
    let body_len = tenant.len();
    1 + prost::encoding::encoded_len_varint(body_len as u64) + body_len
}

/// The inner-`Packet` budget a payload must fit alone to be admitted for
/// datagram carriage on a session — guaranteed to hold for the rest of the
/// connection's life, and computed identically by
/// [`MeshLink::payload_fits`] and [`MeshLink::send`] so the two can never
/// disagree.
///
/// It is the outer datagram floor —
/// [`GUARANTEED_DATAGRAM_BUDGET`](crate::ack_manager::GUARANTEED_DATAGRAM_BUDGET),
/// further capped by the live budget's peer-advertised component, a
/// handshake constant noq permits to be arbitrarily small — minus the
/// wrapper costs that accompany *every* one of the session's packets: the
/// `MeshPacket` overhead and the session's own tenant framing (up to 258
/// bytes for a maximum-length 255-byte tenant id, which would otherwise eat
/// the floor's whole safety margin). The conditions sidecar is deliberately
/// *not* reserved: it is optional per send, and the fresh-free, sidecar-free
/// maintenance flush whose room this floor guarantees never carries one.
///
/// [`MeshLink::send`]: super::MeshLink::send
/// [`MeshLink::payload_fits`]: super::MeshLink::payload_fits
pub(super) fn packet_admission_floor(live_datagram_budget: usize, tenant: Option<&str>) -> usize {
    crate::ack_manager::GUARANTEED_DATAGRAM_BUDGET
        .min(live_datagram_budget)
        .saturating_sub(MESH_PACKET_OVERHEAD)
        .saturating_sub(tenant.map(tenant_element_len).unwrap_or(0))
}
