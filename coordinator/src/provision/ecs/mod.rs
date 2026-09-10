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
//! The SDK calls sit behind [`api::EcsApi`], a thin internal trait, so the mapping
//! logic — status classification, ENI-to-address assembly and ordering, launch
//! override construction, task-ARN parsing, and list pagination — is exercised
//! against a scripted fake with no live AWS. This file holds the config, the
//! errors, and the substrate-independent [`EcsCore`] mapping logic; `api` holds
//! the trait and its real (AWS SDK) implementation.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use rally_point_proto::control::RegionId;
use serde::Deserialize;

use super::{LaunchSpec, ProvisionError, Provisioner, TaskId, TaskState};

mod api;

use api::{EcsApi, EcsClients, EniAddresses, RunTaskRequest};
// Test-only: not needed by this file's own code (which never names these two
// response types), only by `tests`' `use super::*;` picking them up the same
// way it would if this were still one file.
#[cfg(test)]
use api::{TaskDescription, TaskPage};

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

#[cfg(test)]
mod tests;
