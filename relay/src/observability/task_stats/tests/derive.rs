//! `derive()` and `derive_work()` behavior: CPU%/cores from synthetic
//! provider samples, relay-work rates and estimated CPU-per-work-unit,
//! memory working-set conversion, and network throughput rates.

use super::*;

#[test]
fn cpu_pct_is_none_with_no_previous_sample() {
    let curr = Sample {
        cpu_total_usage: 1_500_000_000,
        cpu_system_usage: Some(12_000_000_000),
        online_cpus: 4,
        ..Default::default()
    };
    let derived = derive(None, &curr, TaskLimits::default());
    assert_eq!(derived.cpu_pct, None);
    assert_eq!(derived.cpu_cores_used, None);
}

#[test]
fn cpu_pct_computes_from_two_synthetic_samples() {
    // 500ms of container CPU time out of 2s of system CPU time, on 4
    // online CPUs: (0.5e9 / 2e9) * 4 * 100 = 100%.
    let prev = Sample {
        provider_read_unix_ns: 10 * NANOS_PER_SEC,
        cpu_total_usage: 1_000_000_000,
        cpu_system_usage: Some(10_000_000_000),
        online_cpus: 4,
        ..Default::default()
    };
    let curr = Sample {
        provider_read_unix_ns: 12 * NANOS_PER_SEC,
        cpu_total_usage: 1_500_000_000,
        cpu_system_usage: Some(12_000_000_000),
        online_cpus: 4,
        ..Default::default()
    };
    let derived = derive(Some(&prev), &curr, TaskLimits::default());
    assert_eq!(derived.cpu_pct, Some(100.0));
    assert_eq!(derived.cpu_cores_used, Some(0.25));
}

#[test]
fn cpu_pct_is_none_on_a_zero_system_delta() {
    let prev = Sample {
        provider_read_unix_ns: 10 * NANOS_PER_SEC,
        cpu_total_usage: 1_000_000_000,
        cpu_system_usage: Some(10_000_000_000),
        online_cpus: 4,
        ..Default::default()
    };
    let curr = Sample {
        provider_read_unix_ns: 12 * NANOS_PER_SEC,
        cpu_total_usage: 1_500_000_000,
        cpu_system_usage: Some(10_000_000_000),
        online_cpus: 4,
        ..Default::default()
    };
    let derived = derive(Some(&prev), &curr, TaskLimits::default());
    assert_eq!(derived.cpu_pct, None);
}

#[test]
fn cpu_pct_is_none_on_a_negative_system_delta() {
    // A reversed/reset system counter must not underflow into a huge
    // bogus percentage.
    let prev = Sample {
        provider_read_unix_ns: 10 * NANOS_PER_SEC,
        cpu_total_usage: 1_000_000_000,
        cpu_system_usage: Some(12_000_000_000),
        online_cpus: 4,
        ..Default::default()
    };
    let curr = Sample {
        provider_read_unix_ns: 12 * NANOS_PER_SEC,
        cpu_total_usage: 1_500_000_000,
        cpu_system_usage: Some(10_000_000_000),
        online_cpus: 4,
        ..Default::default()
    };
    let derived = derive(Some(&prev), &curr, TaskLimits::default());
    assert_eq!(derived.cpu_pct, None);
}

#[test]
fn cpu_cores_used_is_none_on_zero_elapsed_or_a_reset_container_counter() {
    let prev = Sample {
        provider_read_unix_ns: 10 * NANOS_PER_SEC,
        cpu_total_usage: 1_000,
        ..Default::default()
    };
    let advanced = Sample {
        provider_read_unix_ns: 10 * NANOS_PER_SEC,
        cpu_total_usage: 2_000,
        ..Default::default()
    };
    assert_eq!(
        derive(Some(&prev), &advanced, TaskLimits::default()).cpu_cores_used,
        None,
    );

    let reset = Sample {
        provider_read_unix_ns: 11 * NANOS_PER_SEC,
        cpu_total_usage: 500,
        ..Default::default()
    };
    assert_eq!(
        derive(Some(&prev), &reset, TaskLimits::default()).cpu_cores_used,
        None,
    );
}

#[test]
fn cached_duplicate_is_stale_and_catch_up_uses_provider_elapsed() {
    let prev = sample_at(
        10,
        Sample {
            cpu_total_usage: 5_000_000_000,
            cpu_system_usage: Some(100_000_000_000),
            online_cpus: 4,
            ..Default::default()
        },
    );
    let duplicate = prev;

    let stale = derive(Some(&prev), &duplicate, TaskLimits::default());
    assert!(stale.provider_sample_stale);
    assert_eq!(stale.provider_interval_ms, None);
    assert_eq!(stale.cpu_cores_used, None);
    assert_eq!(stale.cpu_pct, None);

    // The provider next catches up by 10 CPU-seconds across 20 seconds of
    // its own clock. Dividing by the relay's 10-second poll interval would
    // falsely report one full core; provider time correctly reports 0.5.
    let catch_up = sample_at(
        30,
        Sample {
            cpu_total_usage: 15_000_000_000,
            cpu_system_usage: Some(180_000_000_000),
            online_cpus: 4,
            ..Default::default()
        },
    );
    let derived = derive(Some(&prev), &catch_up, TaskLimits::default());
    assert!(!derived.provider_sample_stale);
    assert_eq!(derived.provider_interval_ms, Some(20_000.0));
    assert_eq!(derived.cpu_cores_used, Some(0.5));
}

#[test]
fn embedded_preread_and_precpu_supply_the_provider_interval() {
    let curr = Sample {
        provider_read_unix_ns: 20 * NANOS_PER_SEC,
        provider_preread_unix_ns: Some(10 * NANOS_PER_SEC),
        cpu_total_usage: 8_000_000_000,
        cpu_previous_total_usage: Some(3_000_000_000),
        cpu_system_usage: Some(50_000_000_000),
        cpu_previous_system_usage: Some(30_000_000_000),
        online_cpus: 4,
        ..Default::default()
    };

    let derived = derive(None, &curr, TaskLimits::default());
    assert_eq!(derived.provider_interval_ms, Some(10_000.0));
    assert_eq!(derived.cpu_cores_used, Some(0.5));
    assert_eq!(derived.cpu_pct, Some(100.0));
}

#[test]
fn ingress_total_combines_local_and_mesh_without_overflow() {
    let work = WorkSnapshot {
        client_turns_validated: 7,
        mesh_ingress_turns: 5,
        ..Default::default()
    };
    assert_eq!(work.ingress_turns(), 12);

    let saturated = WorkSnapshot {
        client_turns_validated: u64::MAX,
        mesh_ingress_turns: 1,
        ..Default::default()
    };
    assert_eq!(saturated.ingress_turns(), u64::MAX);
}

#[test]
fn work_rates_and_cpu_efficiency_difference_cumulative_snapshots() {
    let prev_work = WorkSnapshot {
        client_turns_validated: 100,
        local_turn_deliveries: 300,
        oversize_diverts: 4,
        mesh_ingress_turns: 10,
    };
    let curr_work = WorkSnapshot {
        client_turns_validated: 140,
        local_turn_deliveries: 420,
        oversize_diverts: 10,
        mesh_ingress_turns: 30,
    };
    let derived = derive_work(
        &prev_work,
        &curr_work,
        Some(0.3),
        Some(2_000_000_000),
        Duration::from_secs(2),
    );
    assert_eq!(derived.validated_turns_per_sec, Some(20.0));
    assert_eq!(derived.mesh_ingress_turns_per_sec, Some(10.0));
    assert_eq!(derived.ingress_turns_per_sec, Some(30.0));
    assert_eq!(derived.local_deliveries_per_sec, Some(60.0));
    assert_eq!(derived.oversize_diverts_per_sec, Some(3.0));
    assert!(derived.cpu_work_intervals_aligned);
    assert_eq!(
        derived.estimated_cpu_ns_per_validated_turn,
        Some(15_000_000.0),
    );
    assert_eq!(
        derived.estimated_cpu_ns_per_ingress_turn,
        Some(10_000_000.0),
    );
    assert_eq!(
        derived.estimated_cpu_ns_per_local_delivery,
        Some(5_000_000.0),
    );
}

#[test]
fn mismatched_cpu_and_work_intervals_suppress_cpu_efficiency_estimates() {
    let prev_work = WorkSnapshot::default();
    let curr_work = WorkSnapshot {
        client_turns_validated: 10,
        local_turn_deliveries: 20,
        mesh_ingress_turns: 5,
        ..Default::default()
    };
    let derived = derive_work(
        &prev_work,
        &curr_work,
        Some(0.5),
        Some(20_000_000_000),
        Duration::from_secs(10),
    );

    assert_eq!(derived.validated_turns_per_sec, Some(1.0));
    assert_eq!(derived.ingress_turns_per_sec, Some(1.5));
    assert!(!derived.cpu_work_intervals_aligned);
    assert_eq!(derived.estimated_cpu_ns_per_validated_turn, None);
    assert_eq!(derived.estimated_cpu_ns_per_ingress_turn, None);
    assert_eq!(derived.estimated_cpu_ns_per_local_delivery, None);
}

#[test]
fn zero_work_denominators_report_zero_rates_without_fabricated_cpu_ratios() {
    let work = WorkSnapshot {
        client_turns_validated: 100,
        local_turn_deliveries: 300,
        oversize_diverts: 4,
        mesh_ingress_turns: 25,
    };
    let derived = derive_work(
        &work,
        &work,
        Some(0.3),
        Some(2_000_000_000),
        Duration::from_secs(2),
    );
    assert_eq!(derived.validated_turns_per_sec, Some(0.0));
    assert_eq!(derived.mesh_ingress_turns_per_sec, Some(0.0));
    assert_eq!(derived.ingress_turns_per_sec, Some(0.0));
    assert_eq!(derived.local_deliveries_per_sec, Some(0.0));
    assert_eq!(derived.oversize_diverts_per_sec, Some(0.0));
    assert!(derived.cpu_work_intervals_aligned);
    assert_eq!(derived.estimated_cpu_ns_per_validated_turn, None);
    assert_eq!(derived.estimated_cpu_ns_per_ingress_turn, None);
    assert_eq!(derived.estimated_cpu_ns_per_local_delivery, None);
}

#[test]
fn work_rates_survive_a_cpu_counter_reset_but_cpu_ratios_do_not() {
    let prev_work = WorkSnapshot::default();
    let curr_work = WorkSnapshot {
        client_turns_validated: 10,
        local_turn_deliveries: 20,
        oversize_diverts: 0,
        mesh_ingress_turns: 5,
    };
    let derived = derive_work(
        &prev_work,
        &curr_work,
        None,
        Some(1_000_000_000),
        Duration::from_secs(1),
    );
    assert_eq!(derived.validated_turns_per_sec, Some(10.0));
    assert_eq!(derived.mesh_ingress_turns_per_sec, Some(5.0));
    assert_eq!(derived.ingress_turns_per_sec, Some(15.0));
    assert_eq!(derived.local_deliveries_per_sec, Some(20.0));
    assert!(derived.cpu_work_intervals_aligned);
    assert_eq!(derived.estimated_cpu_ns_per_validated_turn, None);
    assert_eq!(derived.estimated_cpu_ns_per_ingress_turn, None);
    assert_eq!(derived.estimated_cpu_ns_per_local_delivery, None);
}

#[test]
fn mesh_only_work_still_has_an_ingress_cpu_denominator() {
    let prev_work = WorkSnapshot {
        mesh_ingress_turns: 100,
        ..Default::default()
    };
    let curr_work = WorkSnapshot {
        mesh_ingress_turns: 110,
        ..Default::default()
    };
    let derived = derive_work(
        &prev_work,
        &curr_work,
        Some(0.000_000_5),
        Some(2_000_000_000),
        Duration::from_secs(2),
    );
    assert_eq!(derived.validated_turns_per_sec, Some(0.0));
    assert_eq!(derived.mesh_ingress_turns_per_sec, Some(5.0));
    assert_eq!(derived.ingress_turns_per_sec, Some(5.0));
    assert_eq!(derived.estimated_cpu_ns_per_validated_turn, None);
    assert_eq!(derived.estimated_cpu_ns_per_ingress_turn, Some(100.0));
}

#[test]
fn memory_working_set_subtracts_inactive_file_and_converts_to_mib() {
    // usage 200 MiB, inactive_file 100 MiB -> working set 100 MiB; limit
    // exactly 512 MiB.
    let curr = Sample {
        mem_usage: 200 * 1024 * 1024,
        mem_inactive_file: 100 * 1024 * 1024,
        mem_limit: 512 * 1024 * 1024,
        ..Default::default()
    };
    let derived = derive(None, &curr, TaskLimits::default());
    assert_eq!(derived.mem_working_set_mib, 100.0);
    assert_eq!(derived.mem_limit_mib, Some(512.0));
}

#[test]
fn memory_working_set_saturates_when_inactive_file_exceeds_usage() {
    // Never observed in practice, but the subtraction must not underflow.
    let curr = Sample {
        mem_usage: 10,
        mem_inactive_file: 20,
        ..Default::default()
    };
    let derived = derive(None, &curr, TaskLimits::default());
    assert_eq!(derived.mem_working_set_mib, 0.0);
}

#[test]
fn task_memory_limit_replaces_the_cgroup_unlimited_sentinel() {
    let curr = Sample {
        mem_limit: 9_223_372_036_854_771_712,
        ..Default::default()
    };

    let unknown = derive(None, &curr, TaskLimits::default());
    assert_eq!(unknown.mem_limit_mib, None);

    let task_limits = TaskLimits {
        cpu_vcpus: Some(0.5),
        memory_mib: Some(1024.0),
    };
    let allocated = derive(None, &curr, task_limits);
    assert_eq!(allocated.mem_limit_mib, Some(1024.0));
}

#[test]
fn network_rate_is_none_with_no_previous_sample() {
    let curr = Sample {
        net_rx_bytes: Some(3 * 1024 * 1024),
        net_tx_bytes: Some(2 * 1024 * 1024),
        ..Default::default()
    };
    let derived = derive(None, &curr, TaskLimits::default());
    assert_eq!(derived.net_rx_mibps, None);
    assert_eq!(derived.net_tx_mibps, None);
}

#[test]
fn network_rate_computes_delta_over_elapsed_time() {
    // rx grows by 2 MiB and tx by 1 MiB over 2 seconds -> 1.0 and 0.5 MiB/s.
    let prev = sample_at(
        10,
        Sample {
            net_rx_bytes: Some(1024 * 1024),
            net_tx_bytes: Some(1024 * 1024),
            ..Default::default()
        },
    );
    let curr = sample_at(
        12,
        Sample {
            net_rx_bytes: Some(3 * 1024 * 1024),
            net_tx_bytes: Some(2 * 1024 * 1024),
            ..Default::default()
        },
    );
    let derived = derive(Some(&prev), &curr, TaskLimits::default());
    assert_eq!(derived.net_rx_mibps, Some(1.0));
    assert_eq!(derived.net_tx_mibps, Some(0.5));
}

#[test]
fn network_rate_is_none_on_a_zero_elapsed_time() {
    let prev = sample_at(
        10,
        Sample {
            net_rx_bytes: Some(1024 * 1024),
            net_tx_bytes: Some(1024 * 1024),
            ..Default::default()
        },
    );
    let curr = sample_at(
        10,
        Sample {
            net_rx_bytes: Some(3 * 1024 * 1024),
            net_tx_bytes: Some(2 * 1024 * 1024),
            ..Default::default()
        },
    );
    let derived = derive(Some(&prev), &curr, TaskLimits::default());
    assert_eq!(derived.net_rx_mibps, None);
    assert_eq!(derived.net_tx_mibps, None);
}

#[test]
fn omitted_network_counters_do_not_create_a_spike_when_they_reappear() {
    let present = sample_at(
        10,
        Sample {
            net_rx_bytes: Some(1024 * 1024),
            net_tx_bytes: Some(1024 * 1024),
            ..Default::default()
        },
    );
    let omitted = sample_at(11, Sample::default());
    let reappeared = sample_at(
        12,
        Sample {
            net_rx_bytes: Some(100 * 1024 * 1024),
            net_tx_bytes: Some(50 * 1024 * 1024),
            ..Default::default()
        },
    );
    let next = sample_at(
        13,
        Sample {
            net_rx_bytes: Some(101 * 1024 * 1024),
            net_tx_bytes: Some(51 * 1024 * 1024),
            ..Default::default()
        },
    );

    let disappearance = derive(Some(&present), &omitted, TaskLimits::default());
    assert_eq!(disappearance.net_rx_mibps, None);
    assert_eq!(disappearance.net_tx_mibps, None);

    let reappearance = derive(Some(&omitted), &reappeared, TaskLimits::default());
    assert_eq!(reappearance.net_rx_mibps, None);
    assert_eq!(reappearance.net_tx_mibps, None);

    let stable = derive(Some(&reappeared), &next, TaskLimits::default());
    assert_eq!(stable.net_rx_mibps, Some(1.0));
    assert_eq!(stable.net_tx_mibps, Some(1.0));
}
