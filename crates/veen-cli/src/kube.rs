use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use humantime::parse_duration;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::batch::v1::{Job, JobSpec, JobStatus};
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, EnvVar as K8sEnvVar, Namespace, PersistentVolumeClaim,
    PersistentVolumeClaimVolumeSource, Pod, PodSpec, PodTemplateSpec, Secret, SecretVolumeSource,
    Service, ServiceAccount, Volume, VolumeMount,
};
use k8s_openapi::api::rbac::v1::{Role, RoleBinding};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, DeleteParams, ListParams, LogParams, Patch, PatchParams, PostParams};
use kube::config::KubeConfigOptions;
use kube::core::{ClusterResourceScope, NamespaceResourceScope};
use kube::{Client, ResourceExt};
use reqwest::Client as HttpClient;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use tokio::fs;
use tokio::time::sleep;
use tokio_stream::StreamExt;
use tokio_util::{compat::FuturesAsyncReadCompatExt, io::ReaderStream};

use crate::{read_env_descriptor, CliUsageError};

type JsonMap = serde_json::Map<String, JsonValue>;

const DEFAULT_PORT: u16 = 8080;
const HUB_CONFIG_KEY: &str = "hub-config.toml";
const HUB_SECRET_KEY: &str = "hub-key.cbor";
const APPLY_MANAGER: &str = "veen-cli";
const HEALTH_PATH: &str = "/tooling/healthz";
const DEFAULT_JOB_IMAGE: &str = "veen-cli:latest";
const JOB_SEND_GENERATE_NAME: &str = "veen-job-send-";
const JOB_STREAM_GENERATE_NAME: &str = "veen-job-stream-";
const CLIENT_STATE_PATH: &str = "/var/lib/veen-client";
const CLIENT_SECRET_PATH: &str = "/secrets/veen-client";
const CAP_STATE_PATH: &str = "/var/lib/veen-cap";
const CAP_SECRET_PATH: &str = "/secrets/veen-cap";
const CAP_FILE_PATH: &str = "/var/lib/veen-cap/cap.cbor";
const CLIENT_SECRET_VOLUME: &str = "client-secret";
const CLIENT_STATE_VOLUME: &str = "client-state";
const CAP_SECRET_VOLUME: &str = "cap-secret";
const CAP_STATE_VOLUME: &str = "cap-state";
const JOB_COMPLETION_TIMEOUT: Duration = Duration::from_secs(900);
const POD_START_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Subcommand, Debug)]
pub(crate) enum KubeCommand {
    /// Render manifests for VEEN hubs deployed to Kubernetes.
    Render(KubeRenderArgs),
    /// Apply manifests against the configured cluster.
    Apply(KubeApplyArgs),
    /// Remove hub resources from the cluster.
    Delete(KubeDeleteArgs),
    /// Inspect the current deployment state.
    Status(KubeStatusArgs),
    /// Stream logs from hub pods.
    Logs(KubeLogsArgs),
    /// Trigger a hub backup through the Service endpoint.
    Backup(KubeBackupArgs),
    /// Restore a hub snapshot and verify readiness.
    Restore(KubeRestoreArgs),
    /// Run disposable CLI jobs as Kubernetes workloads.
    #[command(subcommand)]
    Job(KubeJobCommand),
}

#[derive(Subcommand, Debug)]
pub(crate) enum KubeJobCommand {
    /// Dispatch a disposable Job that runs `veen send` from a secret-backed client directory.
    Send(KubeJobSendArgs),
    /// Dispatch a disposable Job that runs `veen stream` for the requested label.
    Stream(KubeJobStreamArgs),
}

async fn resolve_cluster_and_namespace(
    env: &Option<PathBuf>,
    cluster_context: &Option<String>,
    namespace: &Option<String>,
    require_namespace: bool,
) -> Result<(String, Option<String>)> {
    let descriptor = match env {
        Some(path) => Some(read_env_descriptor(path).await?),
        None => None,
    };

    let cluster_context = cluster_context
        .as_ref()
        .cloned()
        .or_else(|| descriptor.as_ref().map(|env| env.cluster_context.clone()))
        .ok_or_else(|| CliUsageError::new("cluster-context or env descriptor required".into()))?;

    let namespace = namespace
        .as_ref()
        .cloned()
        .or_else(|| descriptor.as_ref().map(|env| env.namespace.clone()));

    if require_namespace {
        let namespace = namespace
            .ok_or_else(|| CliUsageError::new("namespace or env descriptor required".into()))?;
        Ok((cluster_context, Some(namespace)))
    } else {
        Ok((cluster_context, namespace))
    }
}

fn require_namespace(namespace: Option<String>) -> Result<String> {
    Ok(namespace
        .ok_or_else(|| CliUsageError::new("namespace or env descriptor required".into()))?)
}

#[derive(Args, Debug, Clone)]
pub(crate) struct KubeRenderArgs {
    #[arg(long = "cluster-context")]
    pub(crate) cluster_context: Option<String>,
    #[arg(long)]
    pub(crate) namespace: Option<String>,
    #[arg(long)]
    pub(crate) env: Option<PathBuf>,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long)]
    pub(crate) image: String,
    #[arg(long = "data-pvc")]
    pub(crate) data_pvc: String,
    #[arg(long, default_value_t = 1)]
    pub(crate) replicas: u32,
    #[arg(long = "resources-cpu")]
    pub(crate) resources_cpu: Option<String>,
    #[arg(long = "resources-mem")]
    pub(crate) resources_mem: Option<String>,
    #[arg(long = "profile-id")]
    pub(crate) profile_id: Option<String>,
    #[arg(long = "config")]
    pub(crate) config: Option<PathBuf>,
    #[arg(long = "env-file")]
    pub(crate) env_file: Option<PathBuf>,
    #[arg(long = "pod-annotations")]
    pub(crate) pod_annotations: Option<PathBuf>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct KubeApplyArgs {
    #[arg(long = "cluster-context")]
    pub(crate) cluster_context: Option<String>,
    #[arg(long)]
    pub(crate) env: Option<PathBuf>,
    #[arg(long = "file")]
    pub(crate) file: PathBuf,
    #[arg(long = "wait-seconds")]
    pub(crate) wait_seconds: Option<u64>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct KubeDeleteArgs {
    #[arg(long = "cluster-context")]
    pub(crate) cluster_context: Option<String>,
    #[arg(long)]
    pub(crate) namespace: Option<String>,
    #[arg(long)]
    pub(crate) env: Option<PathBuf>,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long = "purge-pvcs")]
    pub(crate) purge_pvcs: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct KubeStatusArgs {
    #[arg(long = "cluster-context")]
    pub(crate) cluster_context: Option<String>,
    #[arg(long)]
    pub(crate) namespace: Option<String>,
    #[arg(long)]
    pub(crate) env: Option<PathBuf>,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct KubeLogsArgs {
    #[arg(long = "cluster-context")]
    pub(crate) cluster_context: Option<String>,
    #[arg(long)]
    pub(crate) namespace: Option<String>,
    #[arg(long)]
    pub(crate) env: Option<PathBuf>,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long = "pod")]
    pub(crate) pod: Option<String>,
    #[arg(long = "follow")]
    pub(crate) follow: bool,
    #[arg(long = "since")]
    pub(crate) since: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct KubeBackupArgs {
    #[arg(long = "cluster-context")]
    pub(crate) cluster_context: Option<String>,
    #[arg(long)]
    pub(crate) namespace: Option<String>,
    #[arg(long)]
    pub(crate) env: Option<PathBuf>,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long = "snapshot-name")]
    pub(crate) snapshot_name: String,
    #[arg(long = "target-uri")]
    pub(crate) target_uri: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct KubeRestoreArgs {
    #[arg(long = "cluster-context")]
    pub(crate) cluster_context: Option<String>,
    #[arg(long)]
    pub(crate) namespace: Option<String>,
    #[arg(long)]
    pub(crate) env: Option<PathBuf>,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long = "snapshot-name")]
    pub(crate) snapshot_name: String,
    #[arg(long = "source-uri")]
    pub(crate) source_uri: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct KubeJobSendArgs {
    #[arg(long = "cluster-context")]
    pub(crate) cluster_context: Option<String>,
    #[arg(long)]
    pub(crate) namespace: Option<String>,
    #[arg(long)]
    pub(crate) env: Option<PathBuf>,
    #[arg(long = "hub-service")]
    pub(crate) hub_service: String,
    #[arg(long = "client-secret")]
    pub(crate) client_secret: String,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long)]
    pub(crate) body: String,
    #[arg(long = "cap-secret")]
    pub(crate) cap_secret: Option<String>,
    #[arg(long = "profile-id")]
    pub(crate) profile_id: Option<String>,
    #[arg(long = "timeout-ms")]
    pub(crate) timeout_ms: Option<u64>,
    #[arg(long = "state-pvc")]
    pub(crate) state_pvc: Option<String>,
    #[arg(long = "image", default_value = DEFAULT_JOB_IMAGE)]
    pub(crate) image: String,
    #[arg(long = "env-file")]
    pub(crate) env_file: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct KubeJobStreamArgs {
    #[arg(long = "cluster-context")]
    pub(crate) cluster_context: Option<String>,
    #[arg(long)]
    pub(crate) namespace: Option<String>,
    #[arg(long)]
    pub(crate) env: Option<PathBuf>,
    #[arg(long = "hub-service")]
    pub(crate) hub_service: String,
    #[arg(long = "client-secret")]
    pub(crate) client_secret: String,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long = "from")]
    pub(crate) from: Option<u64>,
    #[arg(long = "with-proof")]
    pub(crate) with_proof: bool,
    #[arg(long = "state-pvc")]
    pub(crate) state_pvc: Option<String>,
    #[arg(long = "image", default_value = DEFAULT_JOB_IMAGE)]
    pub(crate) image: String,
    #[arg(long = "env-file")]
    pub(crate) env_file: Option<PathBuf>,
}

pub(crate) async fn handle_kube_command(cmd: KubeCommand) -> Result<()> {
    match cmd {
        KubeCommand::Render(args) => handle_render(args).await,
        KubeCommand::Apply(args) => handle_apply(args).await,
        KubeCommand::Delete(args) => handle_delete(args).await,
        KubeCommand::Status(args) => handle_status(args).await,
        KubeCommand::Logs(args) => handle_logs(args).await,
        KubeCommand::Backup(args) => handle_backup(args).await,
        KubeCommand::Restore(args) => handle_restore(args).await,
        KubeCommand::Job(cmd) => handle_job_command(cmd).await,
    }
}

async fn handle_job_command(cmd: KubeJobCommand) -> Result<()> {
    match cmd {
        KubeJobCommand::Send(args) => handle_job_send(args).await,
        KubeJobCommand::Stream(args) => handle_job_stream(args).await,
    }
}

#[derive(Debug, Clone)]
struct RenderSpec {
    namespace: String,
    name: String,
    image: String,
    data_pvc: String,
    replicas: u32,
    resources_cpu: Option<ResourceQuantity>,
    resources_mem: Option<ResourceQuantity>,
    profile_id: Option<String>,
    config_data: Option<String>,
    env: Vec<EnvVar>,
    pod_annotations: JsonMap,
}

#[derive(Debug, Clone)]
struct ResourceQuantity {
    request: String,
    limit: String,
}

#[derive(Debug, Clone)]
struct EnvVar {
    name: String,
    value: String,
}

async fn handle_render(args: KubeRenderArgs) -> Result<()> {
    let KubeRenderArgs {
        cluster_context,
        namespace,
        env,
        name,
        image,
        data_pvc,
        replicas,
        resources_cpu,
        resources_mem,
        profile_id,
        config,
        env_file,
        pod_annotations,
        json,
    } = args;
    if replicas == 0 {
        return Err(CliUsageError::new("--replicas must be >= 1".to_string()).into());
    }
    let (_cluster_context, namespace) =
        resolve_cluster_and_namespace(&env, &cluster_context, &namespace, true).await?;
    let namespace = require_namespace(namespace)?;
    let resources_cpu = parse_resource_quantity(resources_cpu.as_deref())?;
    let resources_mem = parse_resource_quantity(resources_mem.as_deref())?;
    let config_data = match config {
        Some(ref path) => Some(
            fs::read_to_string(path)
                .await
                .with_context(|| format!("reading config {}", path.display()))?,
        ),
        None => None,
    };
    let env_vars = load_env_vars(env_file.as_deref()).await?;
    let pod_annotations = if let Some(ref path) = pod_annotations {
        parse_annotations_file(path).await?
    } else {
        JsonMap::new()
    };

    let spec = RenderSpec {
        namespace,
        name,
        image,
        data_pvc,
        replicas,
        resources_cpu,
        resources_mem,
        profile_id,
        config_data,
        env: env_vars,
        pod_annotations,
    };

    let docs = build_manifests(&spec)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&docs)?);
    } else {
        let rendered = render_yaml_documents(&docs)?;
        print!("{}", rendered);
    }
    Ok(())
}

async fn handle_apply(args: KubeApplyArgs) -> Result<()> {
    let KubeApplyArgs {
        cluster_context,
        env,
        file,
        wait_seconds,
    } = args;
    let (cluster_context, _) =
        resolve_cluster_and_namespace(&env, &cluster_context, &None, false).await?;
    let client = kube_client(&cluster_context).await?;
    let docs = read_manifest_file(&file).await?;
    for doc in &docs {
        apply_manifest(&client, doc).await?;
    }
    let summary = manifest_summary(&docs)?;
    println!("applied manifests for namespace {}", summary.namespace);
    println!("service_dns: {}", summary.service_dns);

    if let Some(wait) = wait_seconds {
        wait_for_ready(
            &client,
            &summary.namespace,
            &summary.deployment_name,
            Duration::from_secs(wait),
        )
        .await?;
        println!("deployment ready");
    }
    Ok(())
}

async fn handle_delete(args: KubeDeleteArgs) -> Result<()> {
    let KubeDeleteArgs {
        cluster_context,
        namespace,
        env,
        name,
        purge_pvcs,
    } = args;
    let (cluster_context, namespace) =
        resolve_cluster_and_namespace(&env, &cluster_context, &namespace, true).await?;
    let namespace = require_namespace(namespace)?;
    let client = kube_client(&cluster_context).await?;
    let base = resource_names(&name);

    let mut deleted_any = false;
    deleted_any |= delete_namespaced::<Deployment>(&client, &namespace, &base.deployment).await?;
    deleted_any |= delete_namespaced::<Service>(&client, &namespace, &base.service).await?;
    deleted_any |= delete_namespaced::<Role>(&client, &namespace, &base.role).await?;
    deleted_any |=
        delete_namespaced::<RoleBinding>(&client, &namespace, &base.role_binding).await?;
    deleted_any |=
        delete_namespaced::<ServiceAccount>(&client, &namespace, &base.service_account).await?;

    if purge_pvcs {
        let pvc_names = collect_pvc_names(&client, &namespace, &base.deployment).await?;
        for pvc in pvc_names {
            deleted_any |=
                delete_namespaced::<PersistentVolumeClaim>(&client, &namespace, &pvc).await?;
        }
    }
    if deleted_any {
        println!("deleted hub {} in namespace {}", base.deployment, namespace);
    } else {
        println!("already deleted");
    }
    Ok(())
}

async fn handle_status(args: KubeStatusArgs) -> Result<()> {
    let KubeStatusArgs {
        cluster_context,
        namespace,
        env,
        name,
        json,
    } = args;
    let (cluster_context, namespace) =
        resolve_cluster_and_namespace(&env, &cluster_context, &namespace, true).await?;
    let namespace = require_namespace(namespace)?;
    let client = kube_client(&cluster_context).await?;
    let base = resource_names(&name);

    let deployment_api: Api<Deployment> = Api::namespaced(client.clone(), &namespace);
    let deployment = deployment_api
        .get(&base.deployment)
        .await
        .with_context(|| format!("fetching deployment {}", base.deployment))?;

    let desired = deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.replicas)
        .unwrap_or(1);
    let ready = deployment
        .status
        .as_ref()
        .and_then(|status| status.ready_replicas)
        .unwrap_or(0);

    let pods_api: Api<Pod> = Api::namespaced(client.clone(), &namespace);
    let selector = format!("veen.hub.name={name}");
    let pods = pods_api
        .list(&ListParams::default().labels(&selector))
        .await?;

    let mut pod_reports = Vec::new();
    for pod in pods {
        let pod_name = pod.name_any();
        let phase = pod
            .status
            .as_ref()
            .and_then(|status| status.phase.clone())
            .unwrap_or_else(|| "Unknown".to_string());
        let restarts = pod
            .status
            .as_ref()
            .and_then(|status| status.container_statuses.as_ref())
            .map(|statuses| statuses.iter().map(|c| c.restart_count).sum::<i32>())
            .unwrap_or(0);
        let (health_value, health_error) =
            if let Some(ip) = pod.status.as_ref().and_then(|status| status.pod_ip.clone()) {
                match query_pod_health(&ip).await {
                    Ok(value) => (Some(value), None),
                    Err(err) => (None, Some(err.to_string())),
                }
            } else {
                (None, Some("pod-ip-unavailable".to_string()))
            };
        pod_reports.push(PodReport {
            name: pod_name,
            phase,
            restarts,
            health: health_value,
            health_error,
        });
    }

    if json {
        let value = json!({
            "deployment_name": base.deployment,
            "namespace": namespace,
            "desired_replicas": desired,
            "ready_replicas": ready,
            "pods": pod_reports,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("deployment: {}", base.deployment);
        println!("namespace: {}", namespace);
        println!("desired replicas: {}", desired);
        println!("ready replicas: {}", ready);
        for pod in &pod_reports {
            println!(
                "pod: {} phase={} restarts={}",
                pod.name, pod.phase, pod.restarts
            );
            match (&pod.health, &pod.health_error) {
                (Some(status), _) => println!("  health: {}", status),
                (_, Some(err)) => println!("  health: {err}"),
                _ => println!("  health: unknown"),
            }
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct PodReport {
    name: String,
    phase: String,
    restarts: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    health: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    health_error: Option<String>,
}

async fn handle_logs(args: KubeLogsArgs) -> Result<()> {
    let KubeLogsArgs {
        cluster_context,
        namespace,
        env,
        name,
        pod,
        follow,
        since,
    } = args;
    let (cluster_context, namespace) =
        resolve_cluster_and_namespace(&env, &cluster_context, &namespace, true).await?;
    let namespace = require_namespace(namespace)?;
    let client = kube_client(&cluster_context).await?;
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), &namespace);

    let pods = if let Some(pod) = pod {
        vec![pod]
    } else {
        let selector = format!("veen.hub.name={name}");
        pods_api
            .list(&ListParams::default().labels(&selector))
            .await?
            .into_iter()
            .map(|pod| pod.name_any())
            .collect()
    };

    if pods.is_empty() {
        println!("no pods found for hub {name}");
        return Ok(());
    }

    for pod_name in pods {
        println!("==> logs for pod {pod_name}");
        let mut params = LogParams {
            follow,
            ..LogParams::default()
        };
        if let Some(since) = since.as_deref() {
            let duration = parse_duration(since)
                .map_err(|_| CliUsageError::new("invalid --since duration".to_string()))?;
            params.since_seconds = Some(duration.as_secs() as i64);
        }
        let reader = pods_api.log_stream(&pod_name, &params).await?;
        let mut stream = ReaderStream::new(reader.compat());
        while let Some(chunk) = stream.next().await {
            let data = chunk?;
            print!("{}", String::from_utf8_lossy(&data));
        }
    }

    Ok(())
}

async fn handle_backup(args: KubeBackupArgs) -> Result<()> {
    let KubeBackupArgs {
        cluster_context,
        namespace,
        env,
        name,
        snapshot_name,
        target_uri,
    } = args;
    let (_cluster_context, namespace) =
        resolve_cluster_and_namespace(&env, &cluster_context, &namespace, true).await?;
    let namespace = require_namespace(namespace)?;
    let client = HttpClient::new();
    let endpoint = format!("http://{}/admin/backup", hub_service_dns(&namespace, &name));
    let payload = json!({
        "snapshot_name": snapshot_name,
        "target_uri": target_uri,
    });
    let response = client.post(endpoint).json(&payload).send().await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("hub backup failed: {}", body);
    }
    store_snapshot(&target_uri, &body).await?;
    println!("backup stored at {target_uri}");
    Ok(())
}

async fn handle_restore(args: KubeRestoreArgs) -> Result<()> {
    let KubeRestoreArgs {
        cluster_context,
        namespace,
        env,
        name,
        snapshot_name,
        source_uri,
    } = args;
    let (cluster_context, namespace) =
        resolve_cluster_and_namespace(&env, &cluster_context, &namespace, true).await?;
    let namespace = require_namespace(namespace)?;
    let kube = kube_client(&cluster_context).await?;
    let base = resource_names(&name);
    let deployment_api: Api<Deployment> = Api::namespaced(kube.clone(), &namespace);
    let deployment = deployment_api.get(&base.deployment).await?;
    let original_replicas = deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.replicas)
        .unwrap_or(1)
        .max(0);

    if original_replicas > 0 {
        scale_deployment(&deployment_api, &base.deployment, 0).await?;
        wait_for_ready(
            &kube,
            &namespace,
            &base.deployment,
            Duration::from_secs(120),
        )
        .await?;
    }

    let client = HttpClient::new();
    let endpoint = format!(
        "http://{}/admin/restore",
        hub_service_dns(&namespace, &name)
    );
    let snapshot_payload = load_snapshot(&source_uri).await?;
    let payload = json!({
        "snapshot_name": snapshot_name,
        "source_uri": source_uri,
        "snapshot_payload": snapshot_payload,
    });
    let response = client.post(endpoint).json(&payload).send().await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("hub restore failed: {}", body);
    }

    if original_replicas > 0 {
        scale_deployment(&deployment_api, &base.deployment, original_replicas).await?;
        wait_for_ready(
            &kube,
            &namespace,
            &base.deployment,
            Duration::from_secs(300),
        )
        .await?;
    }

    println!("restore completed: {}", body);
    Ok(())
}

async fn handle_job_send(mut args: KubeJobSendArgs) -> Result<()> {
    let env = load_env_vars(args.env_file.as_deref()).await?;
    let (cluster_context, namespace) =
        resolve_cluster_and_namespace(&args.env, &args.cluster_context, &args.namespace, true)
            .await?;
    let namespace = require_namespace(namespace)?;
    args.cluster_context = Some(cluster_context.clone());
    args.namespace = Some(namespace);
    let job = build_job_send_manifest(&args, &env)?;
    run_job(&cluster_context, job).await
}

async fn handle_job_stream(mut args: KubeJobStreamArgs) -> Result<()> {
    let env = load_env_vars(args.env_file.as_deref()).await?;
    let (cluster_context, namespace) =
        resolve_cluster_and_namespace(&args.env, &args.cluster_context, &args.namespace, true)
            .await?;
    let namespace = require_namespace(namespace)?;
    args.cluster_context = Some(cluster_context.clone());
    args.namespace = Some(namespace);
    let job = build_job_stream_manifest(&args, &env)?;
    run_job(&cluster_context, job).await
}

async fn store_snapshot(uri: &str, body: &str) -> Result<()> {
    let path = snapshot_path(uri)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    fs::write(&path, body)
        .await
        .with_context(|| format!("writing snapshot to {}", path.display()))?;
    Ok(())
}

async fn load_snapshot(uri: &str) -> Result<String> {
    let path = snapshot_path(uri)?;
    let data = fs::read_to_string(&path)
        .await
        .with_context(|| format!("reading snapshot from {}", path.display()))?;
    Ok(data)
}

fn snapshot_path(uri: &str) -> Result<PathBuf> {
    if let Some(path) = uri.strip_prefix("file://") {
        return Ok(PathBuf::from(path));
    }
    Ok(PathBuf::from(uri))
}

async fn scale_deployment(api: &Api<Deployment>, name: &str, replicas: i32) -> Result<()> {
    let patch = json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "spec": {"replicas": replicas},
    });
    api.patch(
        name,
        &PatchParams::apply(APPLY_MANAGER).force(),
        &Patch::Apply(patch),
    )
    .await?;
    Ok(())
}

fn parse_env_line(line: &str, line_number: usize) -> Result<Option<EnvVar>> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    if let Some((key, value)) = trimmed.split_once('=') {
        let name = key.trim();
        if name.is_empty() {
            return Err(CliUsageError::new(format!(
                "invalid env-file line {line_number}: empty key"
            ))
            .into());
        }
        return Ok(Some(EnvVar {
            name: name.to_string(),
            value: value.trim().to_string(),
        }));
    }
    Err(CliUsageError::new(format!(
        "invalid env-file line {line_number}: expected KEY=VALUE"
    ))
    .into())
}

async fn parse_env_file(path: &Path) -> Result<Vec<EnvVar>> {
    let contents = fs::read_to_string(path)
        .await
        .with_context(|| format!("reading env file {}", path.display()))?;
    let mut vars = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        if let Some(var) = parse_env_line(line, idx + 1)? {
            vars.push(var);
        }
    }
    Ok(vars)
}

async fn load_env_vars(env_file: Option<&Path>) -> Result<Vec<EnvVar>> {
    match env_file {
        Some(path) => parse_env_file(path).await,
        None => Ok(Vec::new()),
    }
}

async fn run_job(cluster_context: &str, job: Job) -> Result<()> {
    let namespace = job
        .metadata
        .namespace
        .clone()
        .ok_or_else(|| CliUsageError::new("job manifest missing namespace".to_string()))?;
    let client = kube_client(cluster_context).await?;
    let job_api: Api<Job> = Api::namespaced(client.clone(), &namespace);
    let created = job_api
        .create(&PostParams::default(), &job)
        .await
        .with_context(|| "creating Kubernetes Job")?;
    let job_name = created.name_any();
    println!("created Job {job_name} in namespace {namespace}");

    let pod_api: Api<Pod> = Api::namespaced(client.clone(), &namespace);
    let log_handle = tokio::spawn(stream_job_logs(pod_api.clone(), job_name.clone()));
    let outcome = wait_for_job_completion(job_api.clone(), job_name.clone()).await;

    match log_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => eprintln!("warning: failed to stream job logs: {err}"),
        Err(err) => eprintln!("warning: log streaming task ended unexpectedly: {err}"),
    }

    match outcome? {
        JobOutcome::Succeeded => {
            println!("job {job_name} completed successfully");
            Ok(())
        }
        JobOutcome::Failed { message } => {
            bail!("job {job_name} failed: {message}");
        }
    }
}

enum JobOutcome {
    Succeeded,
    Failed { message: String },
}

async fn wait_for_job_completion(job_api: Api<Job>, job_name: String) -> Result<JobOutcome> {
    let deadline = Instant::now() + JOB_COMPLETION_TIMEOUT;
    loop {
        let job = job_api.get(&job_name).await?;
        if let Some(status) = job.status.as_ref() {
            if status.succeeded.unwrap_or(0) > 0 {
                return Ok(JobOutcome::Succeeded);
            }
            if status.failed.unwrap_or(0) > 0 {
                let message = job_failure_message(status);
                return Ok(JobOutcome::Failed { message });
            }
        }
        if Instant::now() > deadline {
            bail!("timed out waiting for job {job_name} completion");
        }
        sleep(Duration::from_secs(5)).await;
    }
}

fn job_failure_message(status: &JobStatus) -> String {
    if let Some(conditions) = status.conditions.as_ref() {
        for condition in conditions {
            if condition.type_ == "Failed" && condition.status == "True" {
                if let Some(message) = condition.message.as_ref() {
                    return message.clone();
                }
                if let Some(reason) = condition.reason.as_ref() {
                    return reason.clone();
                }
            }
        }
    }
    "job reported failure".to_string()
}

async fn wait_for_job_pod(pod_api: &Api<Pod>, job_name: &str) -> Result<String> {
    let selector = format!("job-name={job_name}");
    let params = ListParams::default().labels(&selector);
    let deadline = Instant::now() + POD_START_TIMEOUT;
    loop {
        let pods = pod_api.list(&params).await?;
        if let Some(pod) = pods.items.into_iter().next() {
            return Ok(pod.name_any());
        }
        if Instant::now() > deadline {
            bail!("timed out waiting for pod spawned by job {job_name}");
        }
        sleep(Duration::from_secs(2)).await;
    }
}

async fn stream_job_logs(pod_api: Api<Pod>, job_name: String) -> Result<()> {
    let pod_name = wait_for_job_pod(&pod_api, &job_name).await?;
    let mut attempts = 0;
    loop {
        let params = LogParams {
            follow: true,
            ..Default::default()
        };
        match pod_api.log_stream(&pod_name, &params).await {
            Ok(reader) => {
                let mut stream = ReaderStream::new(reader.compat());
                while let Some(chunk) = stream.next().await {
                    let data = chunk?;
                    print!("{}", String::from_utf8_lossy(&data));
                }
                return Ok(());
            }
            Err(kube::Error::Api(status))
                if (status.code == 400 || status.code == 404) && attempts < 10 =>
            {
                attempts += 1;
                sleep(Duration::from_secs(2)).await;
            }
            Err(err) => return Err(err.into()),
        }
    }
}

async fn parse_annotations_file(path: &Path) -> Result<JsonMap> {
    let data = fs::read_to_string(path)
        .await
        .with_context(|| format!("reading annotations {}", path.display()))?;
    let value: JsonValue = serde_json::from_str(&data)?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| CliUsageError::new("pod annotations must be an object".to_string()))
        .map_err(anyhow::Error::from)
}

fn parse_resource_quantity(value: Option<&str>) -> Result<Option<ResourceQuantity>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let mut parts = value.split(',');
    let request = parts
        .next()
        .ok_or_else(|| CliUsageError::new("invalid resource request".to_string()))?;
    let limit = parts.next().unwrap_or(request);
    Ok(Some(ResourceQuantity {
        request: request.trim().to_string(),
        limit: limit.trim().to_string(),
    }))
}

fn format_hub_url(service: &str) -> String {
    if service.starts_with("http://") || service.starts_with("https://") {
        service.to_string()
    } else {
        format!("http://{service}")
    }
}

fn require_namespace_ref(namespace: Option<&str>) -> Result<&str> {
    namespace.ok_or_else(|| CliUsageError::new("namespace required for job manifest".into()).into())
}

struct CliJobConfig<'a> {
    namespace: &'a str,
    generate_name: &'a str,
    image: &'a str,
    env: &'a [EnvVar],
    client_secret: &'a str,
    cap_secret: Option<&'a str>,
    state_pvc: Option<&'a str>,
}

fn build_job_send_manifest(args: &KubeJobSendArgs, env: &[EnvVar]) -> Result<Job> {
    let namespace = require_namespace_ref(args.namespace.as_deref())?;
    build_cli_job(
        CliJobConfig {
            namespace,
            generate_name: JOB_SEND_GENERATE_NAME,
            image: &args.image,
            env,
            client_secret: &args.client_secret,
            cap_secret: args.cap_secret.as_deref(),
            state_pvc: args.state_pvc.as_deref(),
        },
        build_send_command_args(args),
    )
}

fn build_job_stream_manifest(args: &KubeJobStreamArgs, env: &[EnvVar]) -> Result<Job> {
    let namespace = require_namespace_ref(args.namespace.as_deref())?;
    build_cli_job(
        CliJobConfig {
            namespace,
            generate_name: JOB_STREAM_GENERATE_NAME,
            image: &args.image,
            env,
            client_secret: &args.client_secret,
            cap_secret: None,
            state_pvc: args.state_pvc.as_deref(),
        },
        build_stream_command_args(args),
    )
}

fn build_job_command_base(subcommand: &str, hub_service: &str, stream: &str) -> Vec<String> {
    vec![
        "placeholder".to_string(),
        "veen".to_string(),
        subcommand.to_string(),
        "--hub".to_string(),
        format_hub_url(hub_service),
        "--client".to_string(),
        CLIENT_STATE_PATH.to_string(),
        "--stream".to_string(),
        stream.to_string(),
    ]
}

fn build_send_command_args(args: &KubeJobSendArgs) -> Vec<String> {
    let mut command = build_job_command_base("send", &args.hub_service, &args.stream);
    command.push("--body".to_string());
    command.push(args.body.clone());
    if let Some(profile) = &args.profile_id {
        command.push("--profile-id".to_string());
        command.push(profile.clone());
    }
    if args.cap_secret.is_some() {
        command.push("--cap".to_string());
        command.push(CAP_FILE_PATH.to_string());
    }
    if let Some(timeout) = args.timeout_ms {
        command.push("--timeout-ms".to_string());
        command.push(timeout.to_string());
    }
    command
}

fn build_stream_command_args(args: &KubeJobStreamArgs) -> Vec<String> {
    let mut command = build_job_command_base("stream", &args.hub_service, &args.stream);
    if let Some(from) = args.from {
        command.push("--from".to_string());
        command.push(from.to_string());
    }
    if args.with_proof {
        command.push("--with-proof".to_string());
    }
    command
}

fn build_cli_job(config: CliJobConfig<'_>, cli_args: Vec<String>) -> Result<Job> {
    if config.client_secret.is_empty() {
        return Err(CliUsageError::new("--client-secret is required".to_string()).into());
    }
    let script = job_bootstrap_script(config.cap_secret.is_some());
    let mut container_args = Vec::new();
    container_args.push(script);
    container_args.extend(cli_args);

    let mut env_vars = Vec::new();
    for var in config.env {
        env_vars.push(K8sEnvVar {
            name: var.name.clone(),
            value: Some(var.value.clone()),
            ..Default::default()
        });
    }

    let mut volume_mounts = vec![
        VolumeMount {
            mount_path: CLIENT_SECRET_PATH.to_string(),
            name: CLIENT_SECRET_VOLUME.to_string(),
            read_only: Some(true),
            ..Default::default()
        },
        VolumeMount {
            mount_path: CLIENT_STATE_PATH.to_string(),
            name: CLIENT_STATE_VOLUME.to_string(),
            read_only: Some(false),
            ..Default::default()
        },
    ];
    let mut volumes = vec![
        Volume {
            name: CLIENT_SECRET_VOLUME.to_string(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(config.client_secret.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        },
        client_state_volume(config.state_pvc),
    ];

    if let Some(secret_name) = config.cap_secret {
        volume_mounts.push(VolumeMount {
            mount_path: CAP_SECRET_PATH.to_string(),
            name: CAP_SECRET_VOLUME.to_string(),
            read_only: Some(true),
            ..Default::default()
        });
        volume_mounts.push(VolumeMount {
            mount_path: CAP_STATE_PATH.to_string(),
            name: CAP_STATE_VOLUME.to_string(),
            read_only: Some(false),
            ..Default::default()
        });
        volumes.push(Volume {
            name: CAP_SECRET_VOLUME.to_string(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(secret_name.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        });
        volumes.push(Volume {
            name: CAP_STATE_VOLUME.to_string(),
            empty_dir: Some(Default::default()),
            ..Default::default()
        });
    }

    let mut labels = BTreeMap::new();
    labels.insert("app.kubernetes.io/name".to_string(), "veen-cli".to_string());
    labels.insert("app.kubernetes.io/component".to_string(), "job".to_string());

    let pod_spec = PodSpec {
        containers: vec![Container {
            name: "veen-cli".to_string(),
            image: Some(config.image.to_string()),
            command: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
            args: Some(container_args),
            env: if env_vars.is_empty() {
                None
            } else {
                Some(env_vars)
            },
            volume_mounts: Some(volume_mounts),
            ..Default::default()
        }],
        restart_policy: Some("Never".to_string()),
        volumes: Some(volumes),
        ..Default::default()
    };

    let job = Job {
        metadata: ObjectMeta {
            namespace: Some(config.namespace.to_string()),
            generate_name: Some(config.generate_name.to_string()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        spec: Some(JobSpec {
            backoff_limit: Some(0),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    ..Default::default()
                }),
                spec: Some(pod_spec),
            },
            ..Default::default()
        }),
        status: None,
    };

    Ok(job)
}

fn client_state_volume(state_pvc: Option<&str>) -> Volume {
    if let Some(pvc) = state_pvc {
        Volume {
            name: CLIENT_STATE_VOLUME.to_string(),
            persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                claim_name: pvc.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    } else {
        Volume {
            name: CLIENT_STATE_VOLUME.to_string(),
            empty_dir: Some(Default::default()),
            ..Default::default()
        }
    }
}

fn job_bootstrap_script(include_cap: bool) -> String {
    let mut script = format!(
        concat!(
            "set -euo pipefail\n",
            "if [ ! -f {client_secret}/keystore.enc ]; then\n",
            "  echo \"missing keystore.enc in {client_secret}\" >&2\n",
            "  exit 1\n",
            "fi\n",
            "if [ ! -f {client_secret}/identity_card.pub ]; then\n",
            "  echo \"missing identity_card.pub in {client_secret}\" >&2\n",
            "  exit 1\n",
            "fi\n",
            "mkdir -p {client_state}\n",
            "cp {client_secret}/keystore.enc {client_state}/keystore.enc\n",
            "cp {client_secret}/identity_card.pub {client_state}/identity_card.pub\n",
            "if [ -f {client_secret}/state.json ] && [ ! -f {client_state}/state.json ]; then\n",
            "  cp {client_secret}/state.json {client_state}/state.json\n",
            "fi\n"
        ),
        client_state = CLIENT_STATE_PATH,
        client_secret = CLIENT_SECRET_PATH,
    );
    if include_cap {
        script.push_str(&format!(
            concat!(
                "if [ ! -f {cap_secret}/cap.cbor ]; then\n",
                "  echo \"missing cap.cbor in {cap_secret}\" >&2\n",
                "  exit 1\n",
                "fi\n",
                "mkdir -p {cap_state}\n",
                "cp -R {cap_secret}/. {cap_state}/\n"
            ),
            cap_state = CAP_STATE_PATH,
            cap_secret = CAP_SECRET_PATH,
        ));
    }
    script.push_str("exec \"$@\"\n");
    script
}

fn build_manifests(spec: &RenderSpec) -> Result<Vec<JsonValue>> {
    let docs = vec![
        namespace_manifest(&spec.namespace),
        service_account_manifest(spec),
        role_manifest(spec),
        role_binding_manifest(spec),
        config_map_manifest(spec),
        secret_manifest(spec),
        deployment_manifest(spec),
        service_manifest(spec),
    ];
    Ok(docs)
}

fn namespace_manifest(namespace: &str) -> JsonValue {
    json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": namespace,
            "labels": {
                "app": "veen-hub",
            }
        }
    })
}

fn service_account_manifest(spec: &RenderSpec) -> JsonValue {
    json!({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": metadata(Some(&spec.namespace), &resource_names(&spec.name).service_account, &spec.name),
    })
}

fn role_manifest(spec: &RenderSpec) -> JsonValue {
    json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": metadata(Some(&spec.namespace), &resource_names(&spec.name).role, &spec.name),
        "rules": [
            {
                "apiGroups": [""],
                "resources": ["pods", "pods/log", "services", "endpoints", "secrets", "configmaps"],
                "verbs": ["get", "list", "watch"]
            }
        ]
    })
}

fn role_binding_manifest(spec: &RenderSpec) -> JsonValue {
    let names = resource_names(&spec.name);
    json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": metadata(Some(&spec.namespace), &names.role_binding, &spec.name),
        "subjects": [
            {
                "kind": "ServiceAccount",
                "name": names.service_account,
                "namespace": spec.namespace
            }
        ],
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": names.role
        }
    })
}

fn config_map_manifest(spec: &RenderSpec) -> JsonValue {
    let names = resource_names(&spec.name);
    let mut data = JsonMap::new();
    if let Some(ref config) = spec.config_data {
        data.insert(
            HUB_CONFIG_KEY.to_string(),
            JsonValue::String(config.clone()),
        );
    }
    json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": metadata(Some(&spec.namespace), &format!("{}-config", names.base), &spec.name),
        "data": data,
    })
}

fn secret_manifest(spec: &RenderSpec) -> JsonValue {
    let names = resource_names(&spec.name);
    json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": metadata(Some(&spec.namespace), &format!("{}-keys", names.base), &spec.name),
        "type": "Opaque",
        "stringData": {
            HUB_SECRET_KEY: ""
        }
    })
}

fn deployment_manifest(spec: &RenderSpec) -> JsonValue {
    let names = resource_names(&spec.name);
    let mut env = vec![
        json!({"name": "VEEN_HUB_NAME", "value": spec.name}),
        json!({"name": "VEEN_NAMESPACE", "value": spec.namespace}),
    ];
    for extra in &spec.env {
        env.push(json!({"name": extra.name, "value": extra.value}));
    }
    let volume_mounts = vec![
        json!({"name": "hub-config", "mountPath": "/etc/veen", "readOnly": true}),
        json!({"name": "hub-keys", "mountPath": "/etc/veen/keys", "readOnly": true}),
        json!({"name": "hub-data", "mountPath": "/var/lib/veen"}),
    ];
    let volumes = vec![
        json!({"name": "hub-config", "configMap": {"name": format!("{}-config", names.base)}}),
        json!({"name": "hub-keys", "secret": {"secretName": format!("{}-keys", names.base)}}),
        json!({"name": "hub-data", "persistentVolumeClaim": {"claimName": spec.data_pvc}}),
    ];
    let mut resources = JsonMap::new();
    if spec.resources_cpu.is_some() || spec.resources_mem.is_some() {
        let mut requests = JsonMap::new();
        let mut limits = JsonMap::new();
        if let Some(cpu) = &spec.resources_cpu {
            requests.insert("cpu".to_string(), JsonValue::String(cpu.request.clone()));
            limits.insert("cpu".to_string(), JsonValue::String(cpu.limit.clone()));
        }
        if let Some(mem) = &spec.resources_mem {
            requests.insert("memory".to_string(), JsonValue::String(mem.request.clone()));
            limits.insert("memory".to_string(), JsonValue::String(mem.limit.clone()));
        }
        resources.insert("requests".to_string(), JsonValue::Object(requests));
        resources.insert("limits".to_string(), JsonValue::Object(limits));
    }

    let mut args = vec![
        "hub".to_string(),
        "start".to_string(),
        "--listen".to_string(),
        format!("0.0.0.0:{}", DEFAULT_PORT),
        "--data-dir".to_string(),
        "/var/lib/veen".to_string(),
        "--config".to_string(),
        format!("/etc/veen/{HUB_CONFIG_KEY}"),
        "--foreground".to_string(),
    ];
    if let Some(profile) = &spec.profile_id {
        args.push("--profile-id".to_string());
        args.push(profile.clone());
    }

    let mut pod_annotations = JsonMap::new();
    pod_annotations.insert(
        "veen.hub.name".to_string(),
        JsonValue::String(spec.name.clone()),
    );
    pod_annotations.insert(
        "veen.hub.managed-by".to_string(),
        JsonValue::String("veen-cli".to_string()),
    );
    for (key, value) in spec.pod_annotations.iter() {
        pod_annotations.insert(key.clone(), value.clone());
    }

    let mut container = JsonMap::new();
    container.insert(
        "name".to_string(),
        JsonValue::String("veen-hub".to_string()),
    );
    container.insert("image".to_string(), JsonValue::String(spec.image.clone()));
    container.insert(
        "imagePullPolicy".to_string(),
        JsonValue::String("IfNotPresent".to_string()),
    );
    container.insert("command".to_string(), json!(["veen"]));
    container.insert(
        "args".to_string(),
        JsonValue::Array(args.into_iter().map(JsonValue::String).collect()),
    );
    container.insert("env".to_string(), JsonValue::Array(env));
    container.insert(
        "ports".to_string(),
        json!([{ "name": "http", "containerPort": DEFAULT_PORT }]),
    );
    container.insert("volumeMounts".to_string(), JsonValue::Array(volume_mounts));
    container.insert(
        "livenessProbe".to_string(),
        json!({
            "httpGet": {"path": HEALTH_PATH, "port": "http"},
            "initialDelaySeconds": 10,
            "periodSeconds": 10,
            "failureThreshold": 6
        }),
    );
    container.insert(
        "readinessProbe".to_string(),
        json!({
            "httpGet": {"path": HEALTH_PATH, "port": "http"},
            "initialDelaySeconds": 5,
            "periodSeconds": 10,
            "failureThreshold": 3,
            "successThreshold": 1
        }),
    );
    container.insert(
        "securityContext".to_string(),
        json!({
            "runAsNonRoot": true,
            "readOnlyRootFilesystem": true,
            "allowPrivilegeEscalation": false
        }),
    );
    if !resources.is_empty() {
        container.insert("resources".to_string(), JsonValue::Object(resources));
    }

    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": metadata(Some(&spec.namespace), &names.deployment, &spec.name),
        "spec": {
            "replicas": spec.replicas,
            "selector": {"matchLabels": selector_labels(&spec.name)},
            "template": {
                "metadata": {
                    "labels": selector_labels(&spec.name),
                    "annotations": JsonValue::Object(pod_annotations),
                },
                "spec": {
                    "serviceAccountName": names.service_account,
                    "containers": [JsonValue::Object(container)],
                    "volumes": JsonValue::Array(volumes),
                }
            }
        }
    })
}

fn service_manifest(spec: &RenderSpec) -> JsonValue {
    let names = resource_names(&spec.name);
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": metadata(Some(&spec.namespace), &names.service, &spec.name),
        "spec": {
            "selector": selector_labels(&spec.name),
            "ports": [{"name": "http", "port": DEFAULT_PORT, "targetPort": DEFAULT_PORT}],
            "type": "ClusterIP"
        }
    })
}

fn metadata(namespace: Option<&str>, name: &str, hub_name: &str) -> JsonValue {
    let mut labels = selector_labels(hub_name);
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        JsonValue::String("veen-cli".to_string()),
    );
    let mut meta = JsonMap::new();
    meta.insert("name".to_string(), JsonValue::String(name.to_string()));
    if let Some(ns) = namespace {
        meta.insert("namespace".to_string(), JsonValue::String(ns.to_string()));
    }
    meta.insert("labels".to_string(), JsonValue::Object(labels));
    JsonValue::Object(meta)
}

fn selector_labels(name: &str) -> JsonMap {
    let mut labels = JsonMap::new();
    labels.insert("app".to_string(), JsonValue::String("veen-hub".to_string()));
    labels.insert(
        "veen.hub.name".to_string(),
        JsonValue::String(name.to_string()),
    );
    labels
}

fn render_yaml_documents(docs: &[JsonValue]) -> Result<String> {
    let mut rendered = String::new();
    for (idx, doc) in docs.iter().enumerate() {
        if idx > 0 {
            rendered.push_str("---\n");
        }
        let serialized = serde_yaml::to_string(doc).context("serializing manifest")?;
        rendered.push_str(&serialized);
    }
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(rendered)
}

async fn read_manifest_file(path: &Path) -> Result<Vec<JsonValue>> {
    let contents = fs::read_to_string(path)
        .await
        .with_context(|| format!("reading manifest {}", path.display()))?;
    let docs = serde_yaml::Deserializer::from_str(&contents);
    let mut values = Vec::new();
    for doc in docs {
        let value = JsonValue::deserialize(doc)?;
        push_manifest_doc(value, &mut values);
    }
    Ok(values)
}

fn push_manifest_doc(doc: JsonValue, out: &mut Vec<JsonValue>) {
    match doc {
        JsonValue::Null => {}
        JsonValue::Array(items) => {
            for item in items {
                push_manifest_doc(item, out);
            }
        }
        other => out.push(other),
    }
}

async fn apply_manifest(client: &Client, doc: &JsonValue) -> Result<()> {
    let kind = doc
        .get("kind")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CliUsageError::new("manifest missing kind".to_string()))?;
    match kind {
        "Namespace" => apply_cluster_resource::<Namespace>(client, doc).await,
        "ServiceAccount" => apply_namespaced_resource::<ServiceAccount>(client, doc).await,
        "Role" => apply_namespaced_resource::<Role>(client, doc).await,
        "RoleBinding" => apply_namespaced_resource::<RoleBinding>(client, doc).await,
        "ConfigMap" => apply_namespaced_resource::<ConfigMap>(client, doc).await,
        "Secret" => apply_namespaced_resource::<Secret>(client, doc).await,
        "Deployment" => apply_namespaced_resource::<Deployment>(client, doc).await,
        "Service" => apply_namespaced_resource::<Service>(client, doc).await,
        other => Err(CliUsageError::new(format!("unsupported kind {other}")).into()),
    }
}

async fn apply_cluster_resource<T>(client: &Client, doc: &JsonValue) -> Result<()>
where
    T: Clone + DeserializeOwned + Serialize + kube::Resource<Scope = ClusterResourceScope> + Debug,
    <T as kube::Resource>::DynamicType: Default,
{
    let obj: T = serde_json::from_value(doc.clone())?;
    let name = obj.name_any();
    let api: Api<T> = Api::all(client.clone());
    api.patch(
        &name,
        &PatchParams::apply(APPLY_MANAGER).force(),
        &Patch::Apply(&obj),
    )
    .await?;
    Ok(())
}

async fn apply_namespaced_resource<T>(client: &Client, doc: &JsonValue) -> Result<()>
where
    T: Clone
        + DeserializeOwned
        + Serialize
        + kube::Resource<Scope = NamespaceResourceScope>
        + Debug,
    <T as kube::Resource>::DynamicType: Default,
{
    let obj: T = serde_json::from_value(doc.clone())?;
    let name = obj.name_any();
    let namespace = obj.meta().namespace.clone().ok_or_else(|| {
        CliUsageError::new("namespaced manifest missing metadata.namespace".to_string())
    })?;
    let api: Api<T> = Api::namespaced(client.clone(), &namespace);
    api.patch(
        &name,
        &PatchParams::apply(APPLY_MANAGER).force(),
        &Patch::Apply(&obj),
    )
    .await?;
    Ok(())
}

fn resource_names(name: &str) -> ResourceNames {
    ResourceNames {
        base: format!("veen-hub-{name}"),
        deployment: format!("veen-hub-{name}"),
        service: format!("veen-hub-{name}"),
        role: format!("veen-hub-{name}-role"),
        role_binding: format!("veen-hub-{name}-binding"),
        service_account: format!("veen-hub-{name}"),
    }
}

struct ResourceNames {
    base: String,
    deployment: String,
    service: String,
    role: String,
    role_binding: String,
    service_account: String,
}

struct ManifestSummary {
    namespace: String,
    deployment_name: String,
    service_dns: String,
}

fn manifest_summary(docs: &[JsonValue]) -> Result<ManifestSummary> {
    for doc in docs {
        if doc.get("kind").and_then(|k| k.as_str()) == Some("Service") {
            let metadata = doc
                .get("metadata")
                .and_then(|meta| meta.as_object())
                .ok_or_else(|| CliUsageError::new("service missing metadata".to_string()))?;
            let namespace = metadata
                .get("namespace")
                .and_then(|ns| ns.as_str())
                .ok_or_else(|| CliUsageError::new("service missing namespace".to_string()))?;
            let name = metadata
                .get("name")
                .and_then(|ns| ns.as_str())
                .ok_or_else(|| CliUsageError::new("service missing name".to_string()))?;
            let dns = hub_service_dns(namespace, name.trim_start_matches("veen-hub-"));
            return Ok(ManifestSummary {
                namespace: namespace.to_string(),
                deployment_name: format!("veen-hub-{}", name.trim_start_matches("veen-hub-")),
                service_dns: dns,
            });
        }
    }
    Err(CliUsageError::new("manifests missing Service".to_string()).into())
}

fn hub_service_dns(namespace: &str, name: &str) -> String {
    format!("veen-hub-{name}.{namespace}.svc.cluster.local:{DEFAULT_PORT}")
}

async fn kube_client(context: &str) -> Result<Client> {
    let options = KubeConfigOptions {
        context: Some(context.to_string()),
        ..Default::default()
    };
    let config = kube::Config::from_kubeconfig(&options).await?;
    Client::try_from(config).map_err(Into::into)
}

async fn wait_for_ready(
    client: &Client,
    namespace: &str,
    deployment_name: &str,
    timeout: Duration,
) -> Result<()> {
    let api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let deadline = Instant::now() + timeout;
    loop {
        let deployment = api.get(deployment_name).await?;
        let desired = deployment
            .spec
            .as_ref()
            .and_then(|spec| spec.replicas)
            .unwrap_or(1);
        let ready = deployment
            .status
            .as_ref()
            .and_then(|status| status.ready_replicas)
            .unwrap_or(0);
        if ready >= desired {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!("timed out waiting for deployment readiness");
        }
        sleep(Duration::from_secs(5)).await;
    }
}

async fn delete_namespaced<T>(client: &Client, namespace: &str, name: &str) -> Result<bool>
where
    T: Clone + DeserializeOwned + kube::Resource<Scope = NamespaceResourceScope> + Debug,
    <T as kube::Resource>::DynamicType: Default,
{
    let api: Api<T> = Api::namespaced(client.clone(), namespace);
    match api.delete(name, &DeleteParams::default()).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(status)) if status.code == 404 => Ok(false),
        Err(err) => Err(err.into()),
    }
}

async fn collect_pvc_names(
    client: &Client,
    namespace: &str,
    deployment: &str,
) -> Result<Vec<String>> {
    let api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let deployment = api.get(deployment).await?;
    let mut pvcs = BTreeSet::new();
    if let Some(spec) = deployment.spec.as_ref() {
        if let Some(template) = spec.template.spec.as_ref() {
            if let Some(volumes) = template.volumes.as_ref() {
                for volume in volumes {
                    if let Some(pvc) = &volume.persistent_volume_claim {
                        pvcs.insert(pvc.claim_name.clone());
                    }
                }
            }
        }
    }
    Ok(pvcs.into_iter().collect())
}

async fn query_pod_health(pod_ip: &str) -> Result<String> {
    let url = format!("http://{pod_ip}:{DEFAULT_PORT}{HEALTH_PATH}");
    let response = HttpClient::new().get(url).send().await?;
    let status = response.status();
    let body = response.text().await?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(anyhow!(body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn render_is_deterministic() {
        let spec = RenderSpec {
            namespace: "veen".to_string(),
            name: "alpha".to_string(),
            image: "hub:latest".to_string(),
            data_pvc: "alpha-pvc".to_string(),
            replicas: 1,
            resources_cpu: parse_resource_quantity(Some("250m,500m")).unwrap(),
            resources_mem: parse_resource_quantity(Some("256Mi,512Mi")).unwrap(),
            profile_id: Some("abcd".to_string()),
            config_data: Some("[hub]\nrole=tenant".to_string()),
            env: vec![EnvVar {
                name: "A".into(),
                value: "B".into(),
            }],
            pod_annotations: JsonMap::new(),
        };
        let first = build_manifests(&spec).unwrap();
        let second = build_manifests(&spec).unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn env_file_parser_rejects_invalid_lines() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        tokio::fs::write(tmp.path(), "GOOD=1\nBADLINE\n")
            .await
            .unwrap();
        let result = parse_env_file(tmp.path()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn cluster_and_namespace_can_be_loaded_from_env_descriptor() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let descriptor = json!({
            "version": 1u64,
            "name": "demo",
            "cluster_context": "env-ctx",
            "namespace": "env-ns",
            "hubs": {},
            "tenants": {}
        });
        tokio::fs::write(tmp.path(), serde_json::to_vec(&descriptor).unwrap())
            .await
            .unwrap();

        let (cluster_context, namespace) =
            resolve_cluster_and_namespace(&Some(tmp.path().to_path_buf()), &None, &None, true)
                .await
                .expect("resolve from env");

        assert_eq!(cluster_context, "env-ctx");
        assert_eq!(namespace.as_deref(), Some("env-ns"));
    }

    #[test]
    fn send_job_builds_capability_mounts() {
        let args = KubeJobSendArgs {
            cluster_context: Some("ctx".into()),
            namespace: Some("tenant-a".into()),
            env: None,
            hub_service: "veen-hub-tenant-a.tenant-a.svc.cluster.local:8080".into(),
            client_secret: "client-secret".into(),
            stream: "core/main".into(),
            body: "{\"text\":\"hi\"}".into(),
            cap_secret: Some("cap-secret".into()),
            profile_id: Some("abcd".into()),
            timeout_ms: Some(5000),
            state_pvc: None,
            image: "registry.example/veen-cli:v1".into(),
            env_file: None,
        };
        let job = build_job_send_manifest(&args, &[]).expect("job manifest");
        assert_eq!(job.metadata.namespace.as_deref(), Some("tenant-a"));
        assert_eq!(
            job.metadata.generate_name.as_deref(),
            Some(JOB_SEND_GENERATE_NAME)
        );
        let job_spec = job.spec.expect("job spec");
        let pod_spec = job_spec.template.spec.expect("pod spec");
        let container = pod_spec.containers.first().expect("container");
        let args = container.args.as_ref().expect("container args");
        assert!(args[0].contains("set -euo pipefail"));
        assert!(args.iter().any(|value| value == CAP_FILE_PATH));
        let volumes = pod_spec.volumes.expect("volumes");
        let cap_secret_volume = volumes
            .iter()
            .find(|volume| volume.name == CAP_SECRET_VOLUME)
            .expect("cap secret volume");
        let cap_state_volume = volumes
            .iter()
            .find(|volume| volume.name == CAP_STATE_VOLUME)
            .expect("cap state volume");
        assert_eq!(
            cap_secret_volume
                .secret
                .as_ref()
                .and_then(|secret| secret.secret_name.as_deref()),
            Some("cap-secret")
        );
        assert!(cap_state_volume.empty_dir.is_some());
    }

    #[test]
    fn stream_job_uses_state_pvc_when_requested() {
        let args = KubeJobStreamArgs {
            cluster_context: Some("ctx".into()),
            namespace: Some("tenant-a".into()),
            env: None,
            hub_service: "veen-hub".into(),
            client_secret: "client-secret".into(),
            stream: "core/main".into(),
            from: Some(10),
            with_proof: true,
            state_pvc: Some("client-state".into()),
            image: "registry.example/veen-cli:v1".into(),
            env_file: None,
        };
        let job = build_job_stream_manifest(&args, &[]).expect("job manifest");
        let job_spec = job.spec.expect("job spec");
        let pod_spec = job_spec.template.spec.expect("pod spec");
        let volumes = pod_spec.volumes.expect("volumes");
        let client_state = volumes
            .iter()
            .find(|volume| volume.name == CLIENT_STATE_VOLUME)
            .expect("client state volume");
        let pvc = client_state
            .persistent_volume_claim
            .as_ref()
            .expect("pvc source");
        assert_eq!(pvc.claim_name, "client-state");
    }

    #[test]
    fn job_env_vars_are_passed_to_container() {
        let args = KubeJobSendArgs {
            cluster_context: Some("ctx".into()),
            namespace: Some("tenant-a".into()),
            env: None,
            hub_service: "veen-hub".into(),
            client_secret: "client-secret".into(),
            stream: "core/main".into(),
            body: "{}".into(),
            cap_secret: None,
            profile_id: None,
            timeout_ms: None,
            state_pvc: None,
            image: DEFAULT_JOB_IMAGE.into(),
            env_file: None,
        };
        let env = vec![EnvVar {
            name: "VEEN_ROLE".into(),
            value: "operator".into(),
        }];
        let job = build_job_send_manifest(&args, &env).expect("job manifest");
        let job_spec = job.spec.expect("job spec");
        let pod_spec = job_spec.template.spec.expect("pod spec");
        let container = pod_spec.containers.first().expect("container");
        let container_env = container.env.as_ref().expect("env vars");
        assert_eq!(container_env[0].name, "VEEN_ROLE");
        assert_eq!(container_env[0].value.as_deref(), Some("operator"));
    }
}
