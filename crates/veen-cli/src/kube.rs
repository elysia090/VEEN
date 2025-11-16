use std::collections::BTreeSet;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use humantime::parse_duration;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{
    ConfigMap, Namespace, PersistentVolumeClaim, Pod, Secret, Service, ServiceAccount,
};
use k8s_openapi::api::rbac::v1::{Role, RoleBinding};
use kube::api::{Api, DeleteParams, ListParams, LogParams, Patch, PatchParams};
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

use crate::CliUsageError;

type JsonMap = serde_json::Map<String, JsonValue>;

const DEFAULT_PORT: u16 = 8080;
const HUB_CONFIG_KEY: &str = "hub-config.toml";
const HUB_SECRET_KEY: &str = "hub-key.cbor";
const APPLY_MANAGER: &str = "veen-cli";
const HEALTH_PATH: &str = "/healthz";

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
}

#[derive(Args, Debug, Clone)]
pub(crate) struct KubeRenderArgs {
    #[arg(long = "cluster-context")]
    pub(crate) cluster_context: String,
    #[arg(long)]
    pub(crate) namespace: String,
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
    pub(crate) cluster_context: String,
    #[arg(long = "file")]
    pub(crate) file: PathBuf,
    #[arg(long = "wait-seconds")]
    pub(crate) wait_seconds: Option<u64>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct KubeDeleteArgs {
    #[arg(long = "cluster-context")]
    pub(crate) cluster_context: String,
    #[arg(long)]
    pub(crate) namespace: String,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long = "purge-pvcs")]
    pub(crate) purge_pvcs: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct KubeStatusArgs {
    #[arg(long = "cluster-context")]
    pub(crate) cluster_context: String,
    #[arg(long)]
    pub(crate) namespace: String,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct KubeLogsArgs {
    #[arg(long = "cluster-context")]
    pub(crate) cluster_context: String,
    #[arg(long)]
    pub(crate) namespace: String,
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
    pub(crate) cluster_context: String,
    #[arg(long)]
    pub(crate) namespace: String,
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
    pub(crate) cluster_context: String,
    #[arg(long)]
    pub(crate) namespace: String,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long = "snapshot-name")]
    pub(crate) snapshot_name: String,
    #[arg(long = "source-uri")]
    pub(crate) source_uri: String,
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
    let _ = cluster_context;
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
    let env_vars = if let Some(ref path) = env_file {
        parse_env_file(path).await?
    } else {
        Vec::new()
    };
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
        file,
        wait_seconds,
    } = args;
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
        name,
        purge_pvcs,
    } = args;
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
        name,
        json,
    } = args;
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
        name,
        pod,
        follow,
        since,
    } = args;
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
        let mut params = LogParams::default();
        params.follow = follow;
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
        cluster_context: _,
        namespace,
        name,
        snapshot_name,
        target_uri,
    } = args;
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
        name,
        snapshot_name,
        source_uri,
    } = args;
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

fn handle_env_line(line: &str) -> Result<Option<EnvVar>> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    if let Some((key, value)) = trimmed.split_once('=') {
        return Ok(Some(EnvVar {
            name: key.trim().to_string(),
            value: value.trim().to_string(),
        }));
    }
    Err(CliUsageError::new("invalid env-file line".to_string()).into())
}

async fn parse_env_file(path: &Path) -> Result<Vec<EnvVar>> {
    let contents = fs::read_to_string(path)
        .await
        .with_context(|| format!("reading env file {}", path.display()))?;
    let mut vars = Vec::new();
    for line in contents.lines() {
        if let Some(var) = handle_env_line(line)? {
            vars.push(var);
        }
    }
    Ok(vars)
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

fn build_manifests(spec: &RenderSpec) -> Result<Vec<JsonValue>> {
    let mut docs = Vec::new();
    docs.push(namespace_manifest(&spec.namespace));
    docs.push(service_account_manifest(spec));
    docs.push(role_manifest(spec));
    docs.push(role_binding_manifest(spec));
    docs.push(config_map_manifest(spec));
    docs.push(secret_manifest(spec));
    docs.push(deployment_manifest(spec));
    docs.push(service_manifest(spec));
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
}
