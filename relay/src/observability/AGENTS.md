# observability/

## File map
- `flight_recorder/`: `mod.rs` (`FlightRecorder` handle, create-on-first-
  touch, close-seal lifecycle, `run_sampler`) · `events.rs` (record/sample/
  blob shapes, pure data) · `sinks.rs` (`FlightSink`, `FileSink`,
  `CoordinatorSink`/`FlightShipment`, shipping constants) · `recording.rs`
  (`SessionRecording` rings + hot-path `SlotCounters`, `RelayWorkSnapshot`,
  `FlushOutcome`) · `flush.rs` (2nd `impl FlightRecorder`: `take_blob`/
  `flush_session`/`flush_all`).
- `flight_upload.rs` (sibling of `flight_recorder/`) — the presigned-URL PUT.
- `task_stats/`: `mod.rs` (`spawn_if_enabled` + poll loop) · `fetch.rs`
  (ECS GETs, JSON shapes, `Sample`/`TaskLimits`) · `derive.rs` (pure
  `derive`/`derive_work` rate math).

## Recording: what and bounds
Events + link-health samples + turn-stream counters — summaries only (seqs,
frames, slots, counts); raw turn/command bytes and chat are never recorded.
Rings are capped (`MAX_EVENTS_PER_SESSION` 1024, `MAX_SAMPLES_PER_SESSION`
512, oldest-first eviction, drop counts ride the blob).

## Flush, seals, and shipping
Flushes on session close and on drain (`DRAIN_FLUSH_CONCURRENCY`-wide,
`DRAIN_FLUSH_TIMEOUT`-bounded). A close plants a close seal (`CloseSeals`)
so a straggler can't conjure a replacement that would displace the real
blob — one storage key per session; seals clear only on retirement, never a
replayed push. `CoordinatorSink` zstd-compresses the blob, refuses one over
`MAX_SHIPPED_BLOB_BYTES` (4 MiB compressed), hands a `FlightShipment` to
the control connection, which gets a presigned URL and calls
`flight_upload::spawn_put` to PUT straight to storage (3 attempts, 20s
each) — never over the control socket. The `sent` oneshot fires only once
stored; a dropped sender means lost.

## task_stats and tests
No-op unless `ECS_CONTAINER_METADATA_URI_V4` is set (Fargate only).
`derive.rs` keys rate math off the provider's own `read` timestamps, not
the poll interval, since the provider caches its response and the interval
would alias against that cadence. Run just this area:
`cargo test -p rally-point-relay --lib observability::flight_recorder::` /
`observability::task_stats::`.
