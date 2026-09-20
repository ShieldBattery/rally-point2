//! What the relay reports about itself: per-game and per-task telemetry.
//!
//! The flight recorder accumulates a bounded per-session record (events,
//! link-health samples, turn-stream counters — summaries only, never payload
//! bytes) and the upload half ships each finished blob off the relay. Task
//! stats are the process's own view of its Fargate resources, independent of
//! any external metrics pipeline.
//!
//! `events` is the record vocabulary on its own — plain data plus the
//! [`FlightEvents`](events::FlightEvents) sink trait, depending on nothing
//! else in the relay — so a module that only emits events (the consensus
//! decision paths, routing's teardowns) names it rather than the recorder,
//! which needs the mesh conditions registry and the session gates to do its
//! own job.

pub mod events;
pub mod flight_recorder;
pub mod flight_upload;
pub mod task_stats;
