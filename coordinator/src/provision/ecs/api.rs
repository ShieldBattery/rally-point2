//! [`EcsApi`]: the SDK operations [`super::EcsCore`] drives, behind a trait so
//! the mapping logic is testable against a scripted fake with no live AWS.
//! [`EcsClients`] is the real implementation — one ECS and one EC2 client per
//! AWS region, dispatching by the `aws_region` each call names.

use std::collections::HashMap;
use std::future::Future;

use super::{ENI_ATTACHMENT_TYPE, ENI_ID_DETAIL_KEY, ENI_NOT_FOUND_CODE, EcsConfig, EcsError};

/// A relay-task launch reduced to the fields the ECS `RunTask` call needs — the
/// shape [`EcsCore`] hands to [`EcsApi::run_task`], so the override and
/// network-configuration assembly is testable without the SDK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RunTaskRequest {
    pub(super) aws_region: String,
    pub(super) cluster: String,
    pub(super) task_definition: String,
    pub(super) started_by: String,
    pub(super) container: String,
    pub(super) subnets: Vec<String>,
    pub(super) security_groups: Vec<String>,
    pub(super) assign_public_ip: bool,
    /// Container environment overrides in application order: `(name, value)`.
    pub(super) env: Vec<(String, String)>,
}

/// A task as `DescribeTasks` reports it, reduced to the fields the state mapping
/// reads: its last status and the id of its attached elastic network interface
/// (absent until the `awsvpc` interface attaches).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct TaskDescription {
    pub(super) last_status: Option<String>,
    pub(super) eni_id: Option<String>,
}

/// An elastic network interface's public addressing as
/// `DescribeNetworkInterfaces` reports it: the public IPv4 from its association
/// (if any) and its globally routable IPv6 addresses, as raw strings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct EniAddresses {
    pub(super) public_ipv4: Option<String>,
    pub(super) ipv6: Vec<String>,
}

/// One page of a `ListTasks` call: the task ARNs on the page and the token to
/// fetch the next page (absent on the last page).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct TaskPage {
    pub(super) task_arns: Vec<String>,
    pub(super) next_token: Option<String>,
}

/// The SDK operations the provisioner drives, behind a trait so the mapping logic
/// is testable against a scripted fake. The real implementation ([`EcsClients`])
/// holds one ECS and one EC2 client per AWS region and dispatches by the
/// `aws_region` each call names; every method is trivial SDK glue.
pub(super) trait EcsApi: Send + Sync {
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

/// The real [`EcsApi`]: one ECS and one EC2 client per AWS region, keyed by the
/// region string. Both clients share a single ring-backed HTTPS connector.
pub(super) struct EcsClients {
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
    pub(super) async fn from_config(config: &EcsConfig) -> Self {
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
