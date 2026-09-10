//! Flight-recorder unit tests: shared fixtures (a session key builder, a
//! capturing sink, and a sink slower than any test deadline) plus the two
//! topic modules below. Split from one inline `mod tests` so each topic
//! stays a manageable size; every helper here is used by both.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use super::*;
use rally_point_proto::control::TenantId;
use rally_point_proto::ids::SessionId;

pub(super) fn key(session: u64) -> SessionKey {
    SessionKey {
        tenant: TenantId("sb-test".to_owned()),
        session: SessionId(session),
    }
}

/// A sink that captures every stored blob for assertions.
#[derive(Default)]
pub(super) struct CaptureSink {
    pub(super) blobs: Mutex<Vec<FlightBlob>>,
}

impl FlightSink for CaptureSink {
    fn store<'a>(
        &'a self,
        blob: &'a FlightBlob,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.blobs.lock().push(blob.clone());
            Ok(())
        })
    }
}

/// A sink slower than any deadline a test hands the drain flush.
pub(super) struct SlowSink;

impl FlightSink for SlowSink {
    fn store<'a>(
        &'a self,
        _blob: &'a FlightBlob,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<()>> + Send + 'a>> {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(())
        })
    }
}

/// Builds a `len`-byte string of high-entropy ASCII over a 64-symbol alphabet, so
/// zstd finds no structure to exploit and its output stays near the input size —
/// used to force the compressed-size backstop to trip in a test without a
/// multi-megabyte genuinely-recorded blob.
pub(super) fn incompressible_string(len: usize) -> String {
    // A 64-char JSON-safe alphabet: 6 bits of entropy per symbol.
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        // xorshift64: high-entropy output zstd finds no structure in.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push(ALPHABET[(state & 63) as usize] as char);
    }
    out
}

mod recording;
mod sinks;
