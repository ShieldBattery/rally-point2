//! Exercises the mapping logic in `mod.rs`/`api` — status classification,
//! ENI-to-address assembly and ordering, launch override construction,
//! task-ARN parsing, and list pagination — against `FakeEcsApi`, a scripted
//! [`EcsApi`], plus the config load/validate error paths. No live AWS.

use std::collections::HashSet;

use parking_lot::Mutex;
use rally_point_proto::control::RegionId;
use rally_point_proto::ids::RelayId;

use super::*;

/// A scripted, inspectable [`EcsApi`]: it records the launch requests it
/// receives and returns a synthesized ARN, and serves task, ENI, and list
/// results from maps the test plants, so the mapping logic is exercised with
/// no live AWS.
#[derive(Default)]
struct FakeEcsApi {
    state: Mutex<FakeState>,
}

#[derive(Default)]
struct FakeState {
    run_requests: Vec<RunTaskRequest>,
    next_task_seq: u64,
    fail_run: bool,
    /// Task ARN → the description `describe_task` returns (absent ⇒ `None`).
    tasks: HashMap<String, TaskDescription>,
    /// ENI id → the addresses `describe_eni` returns (absent ⇒ `None`).
    enis: HashMap<String, EniAddresses>,
    /// Task ARNs whose `stop_task` reports the task already gone.
    missing_on_stop: HashSet<String>,
    /// Task ARNs `stop_task` was called on, in order.
    stops: Vec<String>,
    /// `(aws_region, cluster, next_token)` → the page `list_tasks` returns.
    list_pages: HashMap<(String, String, Option<String>), TaskPage>,
}

impl FakeEcsApi {
    fn new() -> Self {
        Self::default()
    }

    fn set_task(&self, arn: &str, description: TaskDescription) {
        self.state.lock().tasks.insert(arn.to_owned(), description);
    }

    fn set_eni(&self, eni_id: &str, addresses: EniAddresses) {
        self.state.lock().enis.insert(eni_id.to_owned(), addresses);
    }

    fn set_missing_on_stop(&self, arn: &str) {
        self.state.lock().missing_on_stop.insert(arn.to_owned());
    }

    fn set_list_page(&self, aws_region: &str, cluster: &str, token: Option<&str>, page: TaskPage) {
        self.state.lock().list_pages.insert(
            (
                aws_region.to_owned(),
                cluster.to_owned(),
                token.map(str::to_owned),
            ),
            page,
        );
    }

    fn run_requests(&self) -> Vec<RunTaskRequest> {
        self.state.lock().run_requests.clone()
    }

    fn stops(&self) -> Vec<String> {
        self.state.lock().stops.clone()
    }
}

impl EcsApi for FakeEcsApi {
    async fn run_task(&self, request: RunTaskRequest) -> Result<String, EcsError> {
        let mut state = self.state.lock();
        if state.fail_run {
            return Err(EcsError::Backend("run failed".into()));
        }
        let arn = format!(
            "arn:aws:ecs:{}:123456789012:task/{}/task-{}",
            request.aws_region, request.cluster, state.next_task_seq
        );
        state.next_task_seq += 1;
        state.run_requests.push(request);
        Ok(arn)
    }

    async fn describe_task(
        &self,
        _aws_region: &str,
        _cluster: &str,
        task_arn: &str,
    ) -> Result<Option<TaskDescription>, EcsError> {
        Ok(self.state.lock().tasks.get(task_arn).cloned())
    }

    async fn describe_eni(
        &self,
        _aws_region: &str,
        eni_id: &str,
    ) -> Result<Option<EniAddresses>, EcsError> {
        Ok(self.state.lock().enis.get(eni_id).cloned())
    }

    async fn stop_task(
        &self,
        _aws_region: &str,
        _cluster: &str,
        task_arn: &str,
        _reason: &str,
    ) -> Result<(), EcsError> {
        let mut state = self.state.lock();
        if state.missing_on_stop.contains(task_arn) {
            return Err(EcsError::TaskNotFound);
        }
        state.stops.push(task_arn.to_owned());
        Ok(())
    }

    async fn list_tasks(
        &self,
        aws_region: &str,
        cluster: &str,
        _started_by: &str,
        next_token: Option<String>,
    ) -> Result<TaskPage, EcsError> {
        let state = self.state.lock();
        Ok(state
            .list_pages
            .get(&(aws_region.to_owned(), cluster.to_owned(), next_token))
            .cloned()
            .unwrap_or_default())
    }
}

/// A one-region config: SB region `us-east` on AWS `us-east-1`, cluster
/// `rp2-relays`, with a public IP assigned.
fn one_region_config() -> EcsConfig {
    EcsConfig::from_json(
        r#"{
            "started_by": "rp2-coordinator-test",
            "regions": {
                "us-east": {
                    "aws_region": "us-east-1",
                    "cluster": "rp2-relays",
                    "task_definition": "rp2-relay",
                    "subnets": ["subnet-a", "subnet-b"],
                    "security_groups": ["sg-1"],
                    "assign_public_ip": true
                }
            }
        }"#,
    )
    .expect("a valid one-region config")
}

fn core(api: FakeEcsApi) -> EcsCore<FakeEcsApi> {
    EcsCore {
        config: one_region_config(),
        api,
    }
}

fn launch_spec(region: Option<&str>) -> LaunchSpec {
    LaunchSpec {
        relay_id: RelayId(42),
        enroll_token: "the-one-time-token".to_owned(),
        region: region.map(|name| RegionId(name.to_owned())),
    }
}

#[tokio::test]
async fn launch_builds_overrides_with_exact_env_and_network_config() {
    let core = core(FakeEcsApi::new());
    let task = core.launch(&launch_spec(Some("us-east"))).await.unwrap();

    // The ARN comes back verbatim as the task handle.
    assert_eq!(
        task.0,
        "arn:aws:ecs:us-east-1:123456789012:task/rp2-relays/task-0"
    );

    let requests = core.api.run_requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.aws_region, "us-east-1");
    assert_eq!(request.cluster, "rp2-relays");
    assert_eq!(request.task_definition, "rp2-relay");
    assert_eq!(request.started_by, "rp2-coordinator-test");
    assert_eq!(request.container, "relay");
    assert_eq!(request.subnets, vec!["subnet-a", "subnet-b"]);
    assert_eq!(request.security_groups, vec!["sg-1"]);
    assert!(request.assign_public_ip);

    // The three environment overrides, by exact name and value.
    assert_eq!(
        request.env,
        vec![
            ("RELAY_ID".to_owned(), "42".to_owned()),
            (
                "RELAY_ENROLL_TOKEN".to_owned(),
                "the-one-time-token".to_owned()
            ),
            ("RELAY_REGION".to_owned(), "us-east".to_owned()),
        ],
    );
}

#[tokio::test]
async fn launch_defaults_container_when_config_omits_it() {
    // A config without a `container` field defaults the override target.
    let config = EcsConfig::from_json(
        r#"{
            "started_by": "rp2-coordinator-test",
            "regions": {
                "us-east": {
                    "aws_region": "us-east-1",
                    "cluster": "c",
                    "task_definition": "td",
                    "subnets": ["subnet-a"]
                }
            }
        }"#,
    )
    .unwrap();
    let core = EcsCore {
        config,
        api: FakeEcsApi::new(),
    };
    core.launch(&launch_spec(Some("us-east"))).await.unwrap();
    assert_eq!(core.api.run_requests()[0].container, "relay");
    assert!(!core.api.run_requests()[0].assign_public_ip);
}

#[tokio::test]
async fn launch_into_an_unknown_or_absent_region_fails() {
    let core = core(FakeEcsApi::new());

    let unknown = core.launch(&launch_spec(Some("eu-west"))).await;
    assert!(matches!(unknown, Err(ProvisionError::Backend(_))));

    let region_blind = core.launch(&launch_spec(None)).await;
    assert!(matches!(region_blind, Err(ProvisionError::Backend(_))));

    // Neither attempt reached the substrate.
    assert!(core.api.run_requests().is_empty());
}

#[tokio::test]
async fn state_reports_running_when_the_eni_is_addressed_while_provisioning() {
    let api = FakeEcsApi::new();
    let arn = "arn:aws:ecs:us-east-1:123456789012:task/rp2-relays/t1";
    // The task is still PROVISIONING, but its interface has already attached
    // and carries a public IPv4.
    api.set_task(
        arn,
        TaskDescription {
            last_status: Some("PROVISIONING".to_owned()),
            eni_id: Some("eni-1".to_owned()),
        },
    );
    api.set_eni(
        "eni-1",
        EniAddresses {
            public_ipv4: Some("203.0.113.7".to_owned()),
            ipv6: vec![],
        },
    );
    let core = core(api);

    let state = core.state(&TaskId(arn.to_owned())).await.unwrap();
    assert_eq!(
        state,
        TaskState::Running {
            expected_ips: vec!["203.0.113.7".parse().unwrap()],
            addrs: vec!["203.0.113.7:14900".parse().unwrap()],
        },
    );
}

#[tokio::test]
async fn state_is_starting_before_the_eni_attaches_and_before_it_is_addressed() {
    let api = FakeEcsApi::new();
    let no_eni = "arn:aws:ecs:us-east-1:123456789012:task/rp2-relays/t1";
    let eni_unaddressed = "arn:aws:ecs:us-east-1:123456789012:task/rp2-relays/t2";
    // No interface attached yet.
    api.set_task(
        no_eni,
        TaskDescription {
            last_status: Some("PENDING".to_owned()),
            eni_id: None,
        },
    );
    // Interface attached, but no public address associated yet.
    api.set_task(
        eni_unaddressed,
        TaskDescription {
            last_status: Some("PENDING".to_owned()),
            eni_id: Some("eni-2".to_owned()),
        },
    );
    api.set_eni("eni-2", EniAddresses::default());
    let core = core(api);

    assert_eq!(
        core.state(&TaskId(no_eni.to_owned())).await.unwrap(),
        TaskState::Starting,
    );
    assert_eq!(
        core.state(&TaskId(eni_unaddressed.to_owned()))
            .await
            .unwrap(),
        TaskState::Starting,
    );
}

#[tokio::test]
async fn state_maps_missing_and_stopped_family_statuses_to_stopped() {
    let api = FakeEcsApi::new();
    let deactivating = "arn:aws:ecs:us-east-1:123456789012:task/rp2-relays/t0";
    let stopping = "arn:aws:ecs:us-east-1:123456789012:task/rp2-relays/t1";
    let deprovisioning = "arn:aws:ecs:us-east-1:123456789012:task/rp2-relays/t2";
    let stopped = "arn:aws:ecs:us-east-1:123456789012:task/rp2-relays/t3";
    // A missing task (never planted) also reads Stopped.
    let missing = "arn:aws:ecs:us-east-1:123456789012:task/rp2-relays/t4";
    for (arn, status) in [
        (deactivating, "DEACTIVATING"),
        (stopping, "STOPPING"),
        (deprovisioning, "DEPROVISIONING"),
        (stopped, "STOPPED"),
    ] {
        api.set_task(
            arn,
            TaskDescription {
                last_status: Some(status.to_owned()),
                // Even with an addressed ENI, a stopped-family status wins.
                eni_id: Some("eni-x".to_owned()),
            },
        );
    }
    api.set_eni(
        "eni-x",
        EniAddresses {
            public_ipv4: Some("203.0.113.9".to_owned()),
            ipv6: vec![],
        },
    );
    let core = core(api);

    for arn in [deactivating, stopping, deprovisioning, stopped, missing] {
        assert_eq!(
            core.state(&TaskId(arn.to_owned())).await.unwrap(),
            TaskState::Stopped,
            "status for {arn} maps to Stopped",
        );
    }
}

#[tokio::test]
async fn state_assembles_dual_stack_addresses_ipv6_first() {
    let api = FakeEcsApi::new();
    let arn = "arn:aws:ecs:us-east-1:123456789012:task/rp2-relays/t1";
    api.set_task(
        arn,
        TaskDescription {
            last_status: Some("RUNNING".to_owned()),
            eni_id: Some("eni-1".to_owned()),
        },
    );
    api.set_eni(
        "eni-1",
        EniAddresses {
            public_ipv4: Some("203.0.113.7".to_owned()),
            ipv6: vec!["2001:db8::1".to_owned(), "2001:db8::2".to_owned()],
        },
    );
    let core = core(api);

    let state = core.state(&TaskId(arn.to_owned())).await.unwrap();
    // IPv6 addresses first (in report order), then the public IPv4; both the
    // advertise set and the expected-peer set share the ordering, each address
    // paired with the relay port.
    let v6a: IpAddr = "2001:db8::1".parse().unwrap();
    let v6b: IpAddr = "2001:db8::2".parse().unwrap();
    let v4: IpAddr = "203.0.113.7".parse().unwrap();
    assert_eq!(
        state,
        TaskState::Running {
            expected_ips: vec![v6a, v6b, v4],
            addrs: vec![
                "[2001:db8::1]:14900".parse().unwrap(),
                "[2001:db8::2]:14900".parse().unwrap(),
                "203.0.113.7:14900".parse().unwrap(),
            ],
        },
    );
}

#[tokio::test]
async fn stop_is_idempotent_on_a_missing_task() {
    let api = FakeEcsApi::new();
    let present = "arn:aws:ecs:us-east-1:123456789012:task/rp2-relays/t1";
    let missing = "arn:aws:ecs:us-east-1:123456789012:task/rp2-relays/t2";
    api.set_missing_on_stop(missing);
    let core = core(api);

    core.stop(&TaskId(present.to_owned())).await.unwrap();
    core.stop(&TaskId(missing.to_owned())).await.unwrap();

    // Only the present task recorded a stop; the missing one succeeded silently.
    assert_eq!(core.api.stops(), vec![present.to_owned()]);
}

#[tokio::test]
async fn list_folds_pages_and_aggregates_across_regions() {
    // Two SB regions on distinct AWS regions/clusters, one of them paginated.
    let config = EcsConfig::from_json(
        r#"{
            "started_by": "rp2-coordinator-test",
            "regions": {
                "us-east": {
                    "aws_region": "us-east-1",
                    "cluster": "east",
                    "task_definition": "td",
                    "subnets": ["subnet-a"]
                },
                "eu-west": {
                    "aws_region": "eu-west-1",
                    "cluster": "west",
                    "task_definition": "td",
                    "subnets": ["subnet-b"]
                }
            }
        }"#,
    )
    .unwrap();
    let api = FakeEcsApi::new();
    // us-east-1/east paginates across two pages.
    api.set_list_page(
        "us-east-1",
        "east",
        None,
        TaskPage {
            task_arns: vec!["arn-a".to_owned(), "arn-b".to_owned()],
            next_token: Some("page-2".to_owned()),
        },
    );
    api.set_list_page(
        "us-east-1",
        "east",
        Some("page-2"),
        TaskPage {
            task_arns: vec!["arn-c".to_owned()],
            next_token: None,
        },
    );
    // eu-west-1/west is a single page.
    api.set_list_page(
        "eu-west-1",
        "west",
        None,
        TaskPage {
            task_arns: vec!["arn-d".to_owned()],
            next_token: None,
        },
    );
    let core = EcsCore { config, api };

    let mut tasks: Vec<String> = core
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.0)
        .collect();
    tasks.sort();
    assert_eq!(
        tasks,
        vec![
            "arn-a".to_owned(),
            "arn-b".to_owned(),
            "arn-c".to_owned(),
            "arn-d".to_owned(),
        ],
    );
}

#[test]
fn expects_public_ipv4_reflects_the_region_configs_flag() {
    let core = core(FakeEcsApi::new());
    assert!(
        core.expects_public_ipv4(Some(&RegionId("us-east".to_owned()))),
        "the one-region config assigns a public IPv4",
    );
    assert!(
        !core.expects_public_ipv4(Some(&RegionId("eu-west".to_owned()))),
        "an unconfigured region never expects one",
    );
    assert!(
        !core.expects_public_ipv4(None),
        "a region-blind query never expects one",
    );
}

#[test]
fn parse_task_arn_extracts_region_and_cluster() {
    let parsed =
        parse_task_arn("arn:aws:ecs:us-east-1:123456789012:task/rp2-relays/abc123").unwrap();
    assert_eq!(parsed.region, "us-east-1");
    assert_eq!(parsed.cluster, "rp2-relays");
}

#[test]
fn parse_task_arn_rejects_non_task_and_clusterless_arns() {
    // Not an ECS task ARN.
    assert!(parse_task_arn("arn:aws:ec2:us-east-1:123456789012:instance/i-abc").is_err());
    // The old clusterless task ARN form cannot address a stop/describe.
    assert!(parse_task_arn("arn:aws:ecs:us-east-1:123456789012:task/abc123").is_err());
    // Not an ARN at all.
    assert!(parse_task_arn("proc-1").is_err());
}

#[test]
fn config_rejects_missing_regions_and_subnets() {
    // No regions.
    assert!(matches!(
        EcsConfig::from_json(r#"{"started_by": "x", "regions": {}}"#),
        Err(EcsConfigError::Invalid(_)),
    ));
    // A region with no subnet.
    assert!(matches!(
        EcsConfig::from_json(
            r#"{"started_by":"x","regions":{"r":{"aws_region":"us-east-1","cluster":"c","task_definition":"td","subnets":[]}}}"#
        ),
        Err(EcsConfigError::Invalid(_)),
    ));
    // An empty launcher tag.
    assert!(matches!(
        EcsConfig::from_json(
            r#"{"started_by":"","regions":{"r":{"aws_region":"us-east-1","cluster":"c","task_definition":"td","subnets":["s"]}}}"#
        ),
        Err(EcsConfigError::Invalid(_)),
    ));
}

#[test]
fn config_rejects_an_unknown_top_level_field() {
    // A misspelled top-level field (`started_bye` for `started_by`) must
    // surface as a parse error rather than silently defaulting `started_by`
    // to nothing and leaving the typo unread.
    assert!(matches!(
        EcsConfig::from_json(
            r#"{"started_bye":"x","regions":{"r":{"aws_region":"us-east-1","cluster":"c","task_definition":"td","subnets":["s"]}}}"#
        ),
        Err(EcsConfigError::Json(_)),
    ));
}

#[test]
fn config_rejects_an_unknown_per_region_field() {
    // A misspelled region field (e.g. `security_group` for
    // `security_groups`) must fail loudly rather than silently launching
    // with no security groups applied.
    assert!(matches!(
        EcsConfig::from_json(
            r#"{"started_by":"x","regions":{"r":{"aws_region":"us-east-1","cluster":"c","task_definition":"td","subnets":["s"],"security_group":["sg-1"]}}}"#
        ),
        Err(EcsConfigError::Json(_)),
    ));
}
