//! What the relay reports about itself: per-game and per-task telemetry.
//!
//! The flight recorder accumulates a bounded per-session record (events,
//! link-health samples, turn-stream counters — summaries only, never payload
//! bytes) and the upload half ships each finished blob off the relay. Task
//! stats are the process's own view of its Fargate resources, independent of
//! any external metrics pipeline.

pub mod flight_recorder;
pub mod flight_upload;
pub mod task_stats;
