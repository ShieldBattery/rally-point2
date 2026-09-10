//! `fetch.rs` behavior: task-limit response merging and the Docker
//! container-stats JSON parse, including its optional-field fallbacks.

use super::super::fetch::{StatsResponse, TaskMetadataResponse};
use super::*;

#[test]
fn parses_task_level_cpu_and_memory_limits() {
    let parsed: TaskMetadataResponse = serde_json::from_str(
        r#"{
            "TaskARN": "arn:aws:ecs:us-west-2:123:task/cluster/id",
            "Limits": { "CPU": 0.5, "Memory": 1024 }
        }"#,
    )
    .unwrap();

    assert_eq!(
        TaskLimits::from_response(parsed),
        TaskLimits {
            cpu_vcpus: Some(0.5),
            memory_mib: Some(1024.0),
        },
    );
}

#[test]
fn task_limits_merge_partial_responses_until_complete() {
    let mut limits = TaskLimits::default();
    assert!(!limits.is_complete());

    limits.merge(TaskLimits {
        cpu_vcpus: Some(0.5),
        memory_mib: None,
    });
    assert_eq!(limits.cpu_vcpus, Some(0.5));
    assert!(!limits.is_complete());

    limits.merge(TaskLimits {
        cpu_vcpus: None,
        memory_mib: Some(1024.0),
    });
    assert_eq!(
        limits,
        TaskLimits {
            cpu_vcpus: Some(0.5),
            memory_mib: Some(1024.0),
        },
    );
    assert!(limits.is_complete());
}

#[test]
fn parses_a_representative_docker_stats_payload() {
    let json = r#"{
        "read": "2026-07-18T00:00:00.000000000Z",
        "preread": "2026-07-17T23:59:50.000000000Z",
        "cpu_stats": {
            "cpu_usage": {
                "total_usage": 1500000000,
                "percpu_usage": [400000000, 380000000, 360000000, 360000000]
            },
            "system_cpu_usage": 12000000000,
            "online_cpus": 4,
            "throttling_data": { "periods": 0, "throttled_periods": 0, "throttled_time": 0 }
        },
        "precpu_stats": {
            "cpu_usage": { "total_usage": 1000000000 },
            "system_cpu_usage": 10000000000,
            "online_cpus": 4
        },
        "memory_stats": {
            "usage": 209715200,
            "limit": 536870912,
            "stats": {
                "inactive_file": 104857600,
                "active_anon": 12345
            }
        },
        "networks": {
            "eth0": { "rx_bytes": 1048576, "tx_bytes": 524288, "rx_packets": 100 },
            "eth1": { "rx_bytes": 2097152, "tx_bytes": 1048576 }
        },
        "pids_stats": { "current": 12 }
    }"#;

    let parsed: StatsResponse = serde_json::from_str(json).unwrap();
    let sample = Sample::from_stats_response(&parsed).unwrap();

    assert_eq!(
        sample.provider_read_unix_ns - sample.provider_preread_unix_ns.unwrap(),
        10 * NANOS_PER_SEC,
    );
    assert_eq!(sample.cpu_total_usage, 1_500_000_000);
    assert_eq!(sample.cpu_previous_total_usage, Some(1_000_000_000));
    assert_eq!(sample.cpu_system_usage, Some(12_000_000_000));
    assert_eq!(sample.online_cpus, 4);
    assert_eq!(sample.mem_usage, 209_715_200);
    assert_eq!(sample.mem_inactive_file, 104_857_600);
    assert_eq!(sample.mem_limit, 536_870_912);
    // Summed across both interfaces: rx 1 MiB + 2 MiB, tx 512 KiB + 1 MiB.
    assert_eq!(sample.net_rx_bytes, Some(1_048_576 + 2_097_152));
    assert_eq!(sample.net_tx_bytes, Some(524_288 + 1_048_576));
}

#[test]
fn falls_back_to_percpu_usage_length_when_online_cpus_is_absent() {
    let json = r#"{
        "read": "2026-07-18T00:00:00Z",
        "cpu_stats": {
            "cpu_usage": {
                "total_usage": 1000,
                "percpu_usage": [100, 100, 100]
            },
            "system_cpu_usage": 5000
        },
        "memory_stats": { "usage": 100, "limit": 200 },
        "networks": {}
    }"#;

    let parsed: StatsResponse = serde_json::from_str(json).unwrap();
    let sample = Sample::from_stats_response(&parsed).unwrap();

    assert_eq!(sample.online_cpus, 3);
}

#[test]
fn omitted_system_cpu_counters_preserve_primary_cpu_cores() {
    let json = r#"{
        "read": "2026-07-18T00:00:20Z",
        "preread": "2026-07-18T00:00:10Z",
        "cpu_stats": {
            "cpu_usage": { "total_usage": 8000000000 },
            "online_cpus": 4
        },
        "precpu_stats": {
            "cpu_usage": { "total_usage": 3000000000 },
            "online_cpus": 4
        },
        "memory_stats": { "usage": 100, "limit": 200 }
    }"#;

    let parsed: StatsResponse = serde_json::from_str(json).unwrap();
    let sample = Sample::from_stats_response(&parsed).unwrap();
    let derived = derive(None, &sample, TaskLimits::default());

    assert_eq!(sample.cpu_system_usage, None);
    assert_eq!(sample.cpu_previous_system_usage, None);
    assert_eq!(derived.cpu_cores_used, Some(0.5));
    assert_eq!(derived.cpu_pct, None);
}

#[test]
fn defaults_missing_optional_fields_to_unknown_or_zero_as_appropriate() {
    // No `networks`, no `memory_stats.stats`, no `online_cpus`, no
    // `percpu_usage` — every optional field absent at once.
    let json = r#"{
        "read": "2026-07-18T00:00:00Z",
        "cpu_stats": {
            "cpu_usage": { "total_usage": 1000 },
            "system_cpu_usage": 5000
        },
        "memory_stats": { "usage": 100, "limit": 200 }
    }"#;

    let parsed: StatsResponse = serde_json::from_str(json).unwrap();
    let sample = Sample::from_stats_response(&parsed).unwrap();

    assert_eq!(sample.online_cpus, 0);
    assert_eq!(sample.mem_inactive_file, 0);
    assert_eq!(sample.net_rx_bytes, None);
    assert_eq!(sample.net_tx_bytes, None);
}
