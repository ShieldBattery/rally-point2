//! The one SHA-256 the coordinator hashes with.
//!
//! A relay certificate fingerprint and a stored enrollment-token digest are the
//! same thing — 32 bytes over raw input — and both are compared byte-for-byte
//! against a digest computed somewhere else: a relay's mesh acceptor hashes a
//! dialing peer's certificate, and an enrolling relay re-presents a token the
//! ledger only ever stored hashed. Two copies of the body could drift apart and
//! leave the two sides disagreeing, so there is one. The constant-time compare
//! the digests are checked with lives here for the same reason. It is written
//! out rather than taken from `ring`, whose `verify_slices_are_equal` is
//! deprecated as an internal helper with no side-channel promise.

/// The SHA-256 digest of `bytes`.
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref());
    out
}

/// Constant-time equality over two byte slices, so a token, secret, or
/// fingerprint comparison leaks no timing signal that would let it be probed a
/// byte at a time. A length mismatch short-circuits (already a non-match);
/// equal-length inputs are compared with no data-dependent branch.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
