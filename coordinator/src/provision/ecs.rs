//! [`EcsProvisioner`]: a [`Provisioner`] that launches relay tasks on AWS Fargate
//! via ECS and resolves their public addresses from the attached EC2 network
//! interface.
//!
//! A launch runs one Fargate task from a per-region task definition, passing the
//! minted id, enroll token, and region as container environment overrides. A
//! task's state is read from `DescribeTasks`: a stopped-family status (or a task
//! ECS no longer knows) reports [`TaskState::Stopped`]; otherwise the task's
//! elastic network interface is resolved through `DescribeNetworkInterfaces` to
//! its public IPv4 and IPv6 addresses. The ENI carries an address as soon as it
//! attaches — which happens while the task is still provisioning — so a task
//! whose interface has a public address reports [`TaskState::Running`] even before
//! its status reaches RUNNING, letting the reconcile loop record the address set
//! before the relay process can enroll. A task whose ENI has not attached, or has
//! no public address yet, reports [`TaskState::Starting`].
//!
//! The SDK calls sit behind [`EcsApi`], a thin internal trait, so the mapping
//! logic — status classification, ENI-to-address assembly and ordering, launch
//! override construction, task-ARN parsing, and list pagination — is exercised
//! against a scripted fake with no live AWS.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use rally_point_proto::control::RegionId;
use serde::Deserialize;

use super::{LaunchSpec, ProvisionError, Provisioner, TaskId, TaskState};

/// The relay's default listen port, and the port a resolved advertise address is
/// paired with when the config does not override it.
const DEFAULT_RELAY_PORT: u16 = 14900;

/// The default container name a task's environment overrides target, when the
/// config does not name one.
const DEFAULT_CONTAINER: &str = "relay";

/// Environment variable a launched relay reads its minted id from.
const ENV_RELAY_ID: &str = "RELAY_ID";
/// Environment variable a launched relay reads its one-time enroll token from.
const ENV_RELAY_ENROLL_TOKEN: &str = "RELAY_ENROLL_TOKEN";
/// Environment variable a launched relay reads the region it serves from.
const ENV_RELAY_REGION: &str = "RELAY_REGION";

/// The reason string attached to a coordinator-initiated task stop.
const STOP_REASON: &str = "coordinator scale-down";

/// The ECS attachment type that names a task's elastic network interface.
const ENI_ATTACHMENT_TYPE: &str = "ElasticNetworkInterface";
/// The attachment detail key carrying the elastic network interface's id.
const ENI_ID_DETAIL_KEY: &str = "networkInterfaceId";

/// The EC2 error code returned when a network interface id does not resolve — a
/// transient state between an interface attaching and its record being queryable.
const ENI_NOT_FOUND_CODE: &str = "InvalidNetworkInterfaceID.NotFound";

/// Static configuration for an [`EcsProvisioner`], loaded from a JSON file: the
/// launcher tag every task carries, the container and port the task advertises,
/// and one entry per placement region mapping it to its AWS region and Fargate
/// networking.
///
/// `started_by` scopes the orphan sweep to the tasks this coordinator launched,
/// so it must be unique per coordinator deployment — a staging and a production
/// coordinator sharing a `started_by` would sweep each other's tasks.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcsConfig {
    /// The `startedBy` tag stamped on every launched task and filtered on when
    /// listing this coordinator's tasks. Unique per coordinator deployment.
    pub started_by: String,
    /// The container name a task's environment overrides target — the relay
    /// container in the task definition.
    #[serde(default = "default_container")]
    pub container: String,
    /// The port every resolved advertise address is paired with, matching the
    /// port the relay listens on.
    #[serde(default = "default_relay_port")]
    pub relay_port: u16,
    /// Placement regions keyed by their coordinator region id (the id a
    /// [`LaunchSpec`] carries), each mapped to its AWS region and networking.
    pub regions: HashMap<String, EcsRegionConfig>,
}

/// The default container name when the config omits `container`.
fn default_container() -> String {
    DEFAULT_CONTAINER.to_owned()
}

/// The default relay port when the config omits `relay_port`.
fn default_relay_port() -> u16 {
    DEFAULT_RELAY_PORT
}

/// Per-region ECS placement: the AWS region, cluster, and task definition a relay
/// for this region runs in, plus its Fargate `awsvpc` networking.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcsRegionConfig {
    /// The AWS region the cluster lives in (e.g. `us-east-1`).
    pub aws_region: String,
    /// The ECS cluster tasks are launched into.
    pub cluster: String,
    /// The task definition (family or family:revision) a relay runs.
    pub task_definition: String,
    /// The subnets a task's network interface may attach in — at least one.
    #[serde(default)]
    pub subnets: Vec<String>,
    /// The security groups applied to a task's network interface. Empty applies
    /// the VPC's default security group.
    #[serde(default)]
    pub security_groups: Vec<String>,
    /// Whether the task's network interface is assigned a public IPv4 address.
    #[serde(default)]
    pub assign_public_ip: bool,
}

/// A failure loading or validating an [`EcsConfig`].
#[derive(Debug, thiserror::Error)]
pub enum EcsConfigError {
    /// The config file could not be read.
    #[error("reading ECS provisioner config: {0}")]
    Io(#[from] std::io::Error),
    /// The config file was not valid JSON, or did not match the schema.
    #[error("parsing ECS provisioner config JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The config parsed but is internally invalid (an empty required field or no
    /// regions), so a launch could never succeed. Named so startup can fail loud.
    #[error("invalid ECS provisioner config: {0}")]
    Invalid(String),
}

impl EcsConfig {
    /// Loads and validates the config from the JSON file at `path`.
    pub fn load(path: &Path) -> Result<Self, EcsConfigError> {
        let text = std::fs::read_to_string(path)?;
        Self::from_json(&text)
    }

    /// Parses and validates the config from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, EcsConfigError> {
        let config: EcsConfig = serde_json::from_str(json)?;
        config.validate()?;
        Ok(config)
    }

    /// Rejects a config that could never launch a task: an empty launcher tag, no
    /// regions, or a region missing its AWS region, cluster, task definition, or a
    /// subnet (a Fargate `awsvpc` task cannot attach without one).
    fn validate(&self) -> Result<(), EcsConfigError> {
        if self.started_by.trim().is_empty() {
            return Err(EcsConfigError::Invalid(
                "started_by must be non-empty".into(),
            ));
        }
        if self.container.trim().is_empty() {
            return Err(EcsConfigError::Invalid(
                "container must be non-empty".into(),
            ));
        }
        if self.regions.is_empty() {
            return Err(EcsConfigError::Invalid(
                "at least one region must be configured".into(),
            ));
        }
        for (id, region) in &self.regions {
            let require = |value: &str, field: &str| {
                if value.trim().is_empty() {
                    Err(EcsConfigError::Invalid(format!(
                        "region {id}: {field} must be non-empty"
                    )))
                } else {
                    Ok(())
                }
            };
            require(&region.aws_region, "aws_region")?;
            require(&region.cluster, "cluster")?;
            require(&region.task_definition, "task_definition")?;
            if region.subnets.is_empty() {
                return Err(EcsConfigError::Invalid(format!(
                    "region {id}: at least one subnet is required"
                )));
            }
        }
        Ok(())
    }
}

/// A relay-task launch reduced to the fields the ECS `RunTask` call needs — the
/// shape [`EcsCore`] hands to [`EcsApi::run_task`], so the override and
/// network-configuration assembly is testable without the SDK.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RunTaskRequest {
    aws_region: String,
    cluster: String,
    task_definition: String,
    started_by: String,
    container: String,
    subnets: Vec<String>,
    security_groups: Vec<String>,
    assign_public_ip: bool,
    /// Container environment overrides in application order: `(name, value)`.
    env: Vec<(String, String)>,
}

/// A task as `DescribeTasks` reports it, reduced to the fields the state mapping
/// reads: its last status and the id of its attached elastic network interface
/// (absent until the `awsvpc` interface attaches).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TaskDescription {
    last_status: Option<String>,
    eni_id: Option<String>,
}

/// An elastic network interface's public addressing as
/// `DescribeNetworkInterfaces` reports it: the public IPv4 from its association
/// (if any) and its globally routable IPv6 addresses, as raw strings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct EniAddresses {
    public_ipv4: Option<String>,
    ipv6: Vec<String>,
}

/// One page of a `ListTasks` call: the task ARNs on the page and the token to
/// fetch the next page (absent on the last page).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TaskPage {
    task_arns: Vec<String>,
    next_token: Option<String>,
}

/// A failure from the ECS/EC2 substrate.
#[derive(Debug, thiserror::Error)]
enum EcsError {
    /// The named task no longer exists — a `StopTask` on a task ECS does not know.
    /// The provisioner treats this as an idempotent success.
    #[error("task not found")]
    TaskNotFound,
    /// Any other backend failure, carrying the SDK's message for the operator log.
    #[error("{0}")]
    Backend(String),
}

impl From<EcsError> for ProvisionError {
    fn from(error: EcsError) -> Self {
        match error {
            EcsError::TaskNotFound => ProvisionError::Backend("task not found".into()),
            EcsError::Backend(message) => ProvisionError::Backend(message),
        }
    }
}

/// The SDK operations the provisioner drives, behind a trait so the mapping logic
/// is testable against a scripted fake. The real implementation ([`EcsClients`])
/// holds one ECS and one EC2 client per AWS region and dispatches by the
/// `aws_region` each call names; every method is trivial SDK glue.
trait EcsApi: Send + Sync {
    /// Runs one task and returns its ARN.
    fn run_task(
        &self,
        request: RunTaskRequest,
    ) -> impl Future<Output = Result<String, EcsError>> + Send;

    /// Describes `task_arn` in `cluster`, or `None` if ECS no longer knows it.
    fn describe_task(
        &self,
        aws_region: &str,
        cluster: &str,
        task_arn: &str,
    ) -> impl Future<Output = Result<Option<TaskDescription>, EcsError>> + Send;

    /// Resolves `eni_id`'s addresses, or `None` if the interface does not resolve.
    fn describe_eni(
        &self,
        aws_region: &str,
        eni_id: &str,
    ) -> impl Future<Output = Result<Option<EniAddresses>, EcsError>> + Send;

    /// Stops `task_arn` in `cluster` with `reason`.
    fn stop_task(
        &self,
        aws_region: &str,
        cluster: &str,
        task_arn: &str,
        reason: &str,
    ) -> impl Future<Output = Result<(), EcsError>> + Send;

    /// Lists one page of `cluster`'s tasks tagged `started_by`, from `next_token`.
    fn list_tasks(
        &self,
        aws_region: &str,
        cluster: &str,
        started_by: &str,
        next_token: Option<String>,
    ) -> impl Future<Output = Result<TaskPage, EcsError>> + Send;
}

/// A [`Provisioner`] backed by AWS Fargate. Constructed from an [`EcsConfig`]; the
/// per-region ECS and EC2 clients are built once at construction from the default
/// credential chain.
pub struct EcsProvisioner {
    inner: EcsCore<EcsClients>,
}

impl EcsProvisioner {
    /// Builds a provisioner from `config`, constructing one ECS and one EC2 client
    /// per distinct AWS region. Clients resolve credentials lazily from the default
    /// chain (environment, shared config files, container/instance roles), so no
    /// credentials are read here.
    pub async fn new(config: EcsConfig) -> Self {
        let api = EcsClients::from_config(&config).await;
        Self {
            inner: EcsCore { config, api },
        }
    }
}

impl Provisioner for EcsProvisioner {
    async fn launch(&self, spec: &LaunchSpec) -> Result<TaskId, ProvisionError> {
        self.inner.launch(spec).await
    }

    async fn state(&self, task: &TaskId) -> Result<TaskState, ProvisionError> {
        self.inner.state(task).await
    }

    async fn stop(&self, task: &TaskId) -> Result<(), ProvisionError> {
        self.inner.stop(task).await
    }

    async fn list(&self) -> Result<Vec<TaskId>, ProvisionError> {
        self.inner.list().await
    }

    fn expects_public_ipv4(&self, region: Option<&RegionId>) -> bool {
        self.inner.expects_public_ipv4(region)
    }
}

/// The substrate-independent core: it turns a [`LaunchSpec`] into a launch, an ECS
/// task into a [`TaskState`], and the configured clusters into the orphan sweep's
/// task list, driving the SDK only through an [`EcsApi`]. Generic over the API so
/// it dispatches statically to the real clients in production and to a scripted
/// fake under test.
struct EcsCore<Api> {
    config: EcsConfig,
    api: Api,
}

impl<Api: EcsApi> EcsCore<Api> {
    /// Launches a Fargate task for `spec`'s region, passing the minted id, enroll
    /// token, and region as container environment overrides. A region-blind spec,
    /// or one naming a region this config does not cover, fails — the loop only
    /// launches for warmed configured regions, so either is a config mismatch.
    async fn launch(&self, spec: &LaunchSpec) -> Result<TaskId, ProvisionError> {
        let region_id = spec.region.as_ref().ok_or_else(|| {
            ProvisionError::Backend("ECS launch requires a region; the spec named none".into())
        })?;
        let region = self.config.regions.get(region_id.as_ref()).ok_or_else(|| {
            ProvisionError::Backend(format!("no ECS config for region {}", region_id.as_ref()))
        })?;
        let request = RunTaskRequest {
            aws_region: region.aws_region.clone(),
            cluster: region.cluster.clone(),
            task_definition: region.task_definition.clone(),
            started_by: self.config.started_by.clone(),
            container: self.config.container.clone(),
            subnets: region.subnets.clone(),
            security_groups: region.security_groups.clone(),
            assign_public_ip: region.assign_public_ip,
            env: vec![
                (ENV_RELAY_ID.to_owned(), spec.relay_id.0.to_string()),
                (ENV_RELAY_ENROLL_TOKEN.to_owned(), spec.enroll_token.clone()),
                (ENV_RELAY_REGION.to_owned(), region_id.as_ref().to_owned()),
            ],
        };
        let arn = self.api.run_task(request).await?;
        Ok(TaskId(arn))
    }

    /// Reports `task`'s state. A stopped-family status, or a task ECS no longer
    /// knows, is [`TaskState::Stopped`]. Otherwise the task's network interface is
    /// resolved: a public address reports [`TaskState::Running`] (even before the
    /// task's status reaches RUNNING, since the interface carries the address as
    /// soon as it attaches), and no interface or no public address yet reports
    /// [`TaskState::Starting`].
    async fn state(&self, task: &TaskId) -> Result<TaskState, ProvisionError> {
        let parsed = parse_task_arn(&task.0)?;
        let Some(description) = self
            .api
            .describe_task(&parsed.region, &parsed.cluster, &task.0)
            .await?
        else {
            return Ok(TaskState::Stopped);
        };
        if is_stopped_status(description.last_status.as_deref()) {
            return Ok(TaskState::Stopped);
        }
        let Some(eni_id) = description.eni_id else {
            return Ok(TaskState::Starting);
        };
        let Some(eni) = self.api.describe_eni(&parsed.region, &eni_id).await? else {
            return Ok(TaskState::Starting);
        };
        let resolved = resolve_addresses(&eni, self.config.relay_port);
        if resolved.expected_ips.is_empty() {
            return Ok(TaskState::Starting);
        }
        Ok(TaskState::Running {
            expected_ips: resolved.expected_ips,
            addrs: resolved.addrs,
        })
    }

    /// Stops `task`. A task ECS no longer knows is an idempotent success.
    async fn stop(&self, task: &TaskId) -> Result<(), ProvisionError> {
        let parsed = parse_task_arn(&task.0)?;
        match self
            .api
            .stop_task(&parsed.region, &parsed.cluster, &task.0, STOP_REASON)
            .await
        {
            Ok(()) | Err(EcsError::TaskNotFound) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Lists every task this coordinator launched that the substrate still knows,
    /// across every distinct configured `(aws_region, cluster)` pair, following
    /// each cluster's pagination and aggregating the results.
    async fn list(&self) -> Result<Vec<TaskId>, ProvisionError> {
        let mut pairs: Vec<(&str, &str)> = self
            .config
            .regions
            .values()
            .map(|region| (region.aws_region.as_str(), region.cluster.as_str()))
            .collect();
        pairs.sort_unstable();
        pairs.dedup();

        let mut tasks = Vec::new();
        for (aws_region, cluster) in pairs {
            let mut next_token = None;
            loop {
                let page = self
                    .api
                    .list_tasks(aws_region, cluster, &self.config.started_by, next_token)
                    .await?;
                tasks.extend(page.task_arns.into_iter().map(TaskId));
                match page.next_token {
                    Some(token) => next_token = Some(token),
                    None => break,
                }
            }
        }
        Ok(tasks)
    }

    /// Whether `region`'s Fargate networking assigns a public IPv4 address to a
    /// launched task's network interface — the same flag [`launch`](Self::launch)
    /// passes through as `assign_public_ip`. A region-blind query, or one naming a
    /// region this config does not cover, never expects one.
    fn expects_public_ipv4(&self, region: Option<&RegionId>) -> bool {
        region
            .and_then(|region_id| self.config.regions.get(region_id.as_ref()))
            .is_some_and(|region| region.assign_public_ip)
    }
}

/// A task ARN split into the parts an ECS/EC2 call addresses it by.
struct ParsedArn {
    region: String,
    cluster: String,
}

/// Parses `arn:aws:ecs:<region>:<account>:task/<cluster>/<task-id>` into its
/// region and cluster — the two an operation on the task must name. Rejects an ARN
/// that is not an ECS task ARN or lacks the cluster segment (a task this
/// coordinator launched always carries it).
fn parse_task_arn(arn: &str) -> Result<ParsedArn, ProvisionError> {
    let fields: Vec<&str> = arn.splitn(6, ':').collect();
    let not_a_task_arn = || ProvisionError::Backend(format!("not an ECS task ARN: {arn}"));
    if fields.len() != 6 || fields[0] != "arn" || fields[2] != "ecs" {
        return Err(not_a_task_arn());
    }
    let region = fields[3];
    let mut resource = fields[5].split('/');
    let (kind, cluster, task_id) = (resource.next(), resource.next(), resource.next());
    match (kind, cluster, task_id) {
        (Some("task"), Some(cluster), Some(task_id))
            if !region.is_empty() && !cluster.is_empty() && !task_id.is_empty() =>
        {
            Ok(ParsedArn {
                region: region.to_owned(),
                cluster: cluster.to_owned(),
            })
        }
        _ => Err(not_a_task_arn()),
    }
}

/// Whether a task's last status means it is gone or on its way out — the statuses
/// that map to [`TaskState::Stopped`] rather than an address resolution. The
/// shutdown sequence (`DEACTIVATING` → `STOPPING` → `DEPROVISIONING` → `STOPPED`)
/// never reverses, so every status on it reads as stopped: resolving and
/// recording addresses for a task that is already leaving would only be undone.
fn is_stopped_status(status: Option<&str>) -> bool {
    matches!(
        status,
        Some("DEACTIVATING" | "STOPPING" | "DEPROVISIONING" | "STOPPED")
    )
}

/// The address set resolved from an ENI: the advertise addresses (each public IP
/// paired with the relay port) and the expected peer IPs (the same IPs). Both are
/// IPv6-first — a dual-stack advertise prefers the IPv6 path — then IPv4.
struct ResolvedAddresses {
    expected_ips: Vec<IpAddr>,
    addrs: Vec<SocketAddr>,
}

/// Assembles an ENI's public addresses into the advertise and expected-peer sets,
/// IPv6 addresses first (in report order) then the public IPv4. An address string
/// that does not parse is skipped; the substrate only ever reports canonical
/// addresses, so a skip means an interface that is not yet fully addressed.
fn resolve_addresses(eni: &EniAddresses, port: u16) -> ResolvedAddresses {
    let mut ips: Vec<IpAddr> = eni
        .ipv6
        .iter()
        .filter_map(|value| value.parse::<Ipv6Addr>().ok().map(IpAddr::from))
        .collect();
    if let Some(ipv4) = eni
        .public_ipv4
        .as_ref()
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
    {
        ips.push(IpAddr::from(ipv4));
    }
    let addrs = ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
    ResolvedAddresses {
        expected_ips: ips,
        addrs,
    }
}

/// The real [`EcsApi`]: one ECS and one EC2 client per AWS region, keyed by the
/// region string. Both clients share a single ring-backed HTTPS connector.
struct EcsClients {
    regions: HashMap<String, RegionClients>,
}

/// The ECS and EC2 clients for one AWS region.
struct RegionClients {
    ecs: aws_sdk_ecs::Client,
    ec2: aws_sdk_ec2::Client,
}

impl EcsClients {
    /// Builds a client pair for each distinct AWS region named in `config`. The
    /// HTTPS connector is pinned to the rustls **ring** provider, matching the
    /// workspace's single crypto backend.
    async fn from_config(config: &EcsConfig) -> Self {
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https();

        let mut regions = HashMap::new();
        for region in config.regions.values() {
            if regions.contains_key(&region.aws_region) {
                continue;
            }
            let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_config::Region::new(region.aws_region.clone()))
                .http_client(http.clone())
                .load()
                .await;
            regions.insert(
                region.aws_region.clone(),
                RegionClients {
                    ecs: aws_sdk_ecs::Client::new(&shared),
                    ec2: aws_sdk_ec2::Client::new(&shared),
                },
            );
        }
        Self { regions }
    }

    /// The ECS client for `aws_region`, or a backend error naming an unconfigured
    /// region (a launch/list only ever names a region built at construction).
    fn ecs(&self, aws_region: &str) -> Result<&aws_sdk_ecs::Client, EcsError> {
        self.regions
            .get(aws_region)
            .map(|clients| &clients.ecs)
            .ok_or_else(|| EcsError::Backend(format!("no ECS client for region {aws_region}")))
    }

    /// The EC2 client for `aws_region`, or a backend error naming an unconfigured
    /// region.
    fn ec2(&self, aws_region: &str) -> Result<&aws_sdk_ec2::Client, EcsError> {
        self.regions
            .get(aws_region)
            .map(|clients| &clients.ec2)
            .ok_or_else(|| EcsError::Backend(format!("no EC2 client for region {aws_region}")))
    }
}

/// The ENI id from a task's `awsvpc` attachment, if one has attached.
fn extract_eni_id(task: &aws_sdk_ecs::types::Task) -> Option<String> {
    task.attachments()
        .iter()
        .filter(|attachment| attachment.r#type() == Some(ENI_ATTACHMENT_TYPE))
        .find_map(|attachment| {
            attachment
                .details()
                .iter()
                .find(|detail| detail.name() == Some(ENI_ID_DETAIL_KEY))
                .and_then(|detail| detail.value())
                .map(str::to_owned)
        })
}

impl EcsApi for EcsClients {
    async fn run_task(&self, request: RunTaskRequest) -> Result<String, EcsError> {
        use aws_sdk_ecs::error::DisplayErrorContext;
        use aws_sdk_ecs::types::{
            AssignPublicIp, AwsVpcConfiguration, ContainerOverride, KeyValuePair, LaunchType,
            NetworkConfiguration, TaskOverride,
        };

        let ecs = self.ecs(&request.aws_region)?;

        let mut container = ContainerOverride::builder().name(&request.container);
        for (name, value) in &request.env {
            container =
                container.environment(KeyValuePair::builder().name(name).value(value).build());
        }
        let overrides = TaskOverride::builder()
            .container_overrides(container.build())
            .build();

        let assign_public_ip = if request.assign_public_ip {
            AssignPublicIp::Enabled
        } else {
            AssignPublicIp::Disabled
        };
        let mut vpc = AwsVpcConfiguration::builder().assign_public_ip(assign_public_ip);
        for subnet in &request.subnets {
            vpc = vpc.subnets(subnet);
        }
        for group in &request.security_groups {
            vpc = vpc.security_groups(group);
        }
        let vpc = vpc.build().map_err(|error| {
            EcsError::Backend(format!("building network configuration: {error}"))
        })?;
        let network = NetworkConfiguration::builder()
            .awsvpc_configuration(vpc)
            .build();

        let output = ecs
            .run_task()
            .cluster(&request.cluster)
            .task_definition(&request.task_definition)
            .launch_type(LaunchType::Fargate)
            .started_by(&request.started_by)
            .count(1)
            .network_configuration(network)
            .overrides(overrides)
            .send()
            .await
            .map_err(|error| EcsError::Backend(format!("{}", DisplayErrorContext(&error))))?;

        if let Some(arn) = output.tasks().first().and_then(|task| task.task_arn()) {
            return Ok(arn.to_owned());
        }
        let failure = output
            .failures()
            .first()
            .map(|failure| format!("{:?}: {:?}", failure.reason(), failure.detail()))
            .unwrap_or_else(|| "no task and no failure reported".to_owned());
        Err(EcsError::Backend(format!(
            "run_task placed no task ({failure})"
        )))
    }

    async fn describe_task(
        &self,
        aws_region: &str,
        cluster: &str,
        task_arn: &str,
    ) -> Result<Option<TaskDescription>, EcsError> {
        use aws_sdk_ecs::error::DisplayErrorContext;

        let ecs = self.ecs(aws_region)?;
        let output = ecs
            .describe_tasks()
            .cluster(cluster)
            .tasks(task_arn)
            .send()
            .await
            .map_err(|error| EcsError::Backend(format!("{}", DisplayErrorContext(&error))))?;
        let Some(task) = output.tasks().first() else {
            return Ok(None);
        };
        Ok(Some(TaskDescription {
            last_status: task.last_status().map(str::to_owned),
            eni_id: extract_eni_id(task),
        }))
    }

    async fn describe_eni(
        &self,
        aws_region: &str,
        eni_id: &str,
    ) -> Result<Option<EniAddresses>, EcsError> {
        use aws_sdk_ec2::error::{DisplayErrorContext, ProvideErrorMetadata};

        let ec2 = self.ec2(aws_region)?;
        match ec2
            .describe_network_interfaces()
            .network_interface_ids(eni_id)
            .send()
            .await
        {
            Ok(output) => {
                let Some(interface) = output.network_interfaces().first() else {
                    return Ok(None);
                };
                let public_ipv4 = interface
                    .association()
                    .and_then(|association| association.public_ip())
                    .map(str::to_owned);
                let ipv6 = interface
                    .ipv6_addresses()
                    .iter()
                    .filter_map(|address| address.ipv6_address().map(str::to_owned))
                    .collect();
                Ok(Some(EniAddresses { public_ipv4, ipv6 }))
            }
            Err(error) => {
                let service_error = error.into_service_error();
                if service_error.code() == Some(ENI_NOT_FOUND_CODE) {
                    Ok(None)
                } else {
                    Err(EcsError::Backend(format!(
                        "{}",
                        DisplayErrorContext(&service_error)
                    )))
                }
            }
        }
    }

    async fn stop_task(
        &self,
        aws_region: &str,
        cluster: &str,
        task_arn: &str,
        reason: &str,
    ) -> Result<(), EcsError> {
        use aws_sdk_ecs::error::DisplayErrorContext;

        let ecs = self.ecs(aws_region)?;
        match ecs
            .stop_task()
            .cluster(cluster)
            .task(task_arn)
            .reason(reason)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(error) => {
                let service_error = error.into_service_error();
                if service_error.is_invalid_parameter_exception() {
                    Err(EcsError::TaskNotFound)
                } else {
                    Err(EcsError::Backend(format!(
                        "{}",
                        DisplayErrorContext(&service_error)
                    )))
                }
            }
        }
    }

    async fn list_tasks(
        &self,
        aws_region: &str,
        cluster: &str,
        started_by: &str,
        next_token: Option<String>,
    ) -> Result<TaskPage, EcsError> {
        use aws_sdk_ecs::error::DisplayErrorContext;

        let ecs = self.ecs(aws_region)?;
        let mut request = ecs.list_tasks().cluster(cluster).started_by(started_by);
        if let Some(token) = next_token {
            request = request.next_token(token);
        }
        let output = request
            .send()
            .await
            .map_err(|error| EcsError::Backend(format!("{}", DisplayErrorContext(&error))))?;
        Ok(TaskPage {
            task_arns: output.task_arns().to_vec(),
            next_token: output.next_token().map(str::to_owned),
        })
    }
}

#[cfg(test)]
mod tests {
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

        fn set_list_page(
            &self,
            aws_region: &str,
            cluster: &str,
            token: Option<&str>,
            page: TaskPage,
        ) {
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
}
