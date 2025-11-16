use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use futures::{io::AsyncBufReadExt as FuturesAsyncBufReadExt, StreamExt};
use humantime::parse_duration;
use k8s_openapi::api::apps::v1::{Deployment, StatefulSet};
use k8s_openapi::api::core::v1::{
    ConfigMap, Namespace, PersistentVolumeClaim, Pod, PodSpec, Secret, Service, ServiceAccount,
};
use k8s_openapi::api::rbac::v1::{Role, RoleBinding};
use kube::api::{Api, DeleteParams, ListParams, LogParams, Patch, PatchParams};
use kube::config::KubeConfigOptions;
use kube::{Client as KubeClient, Config as KubeConfig, Error as KubeError};
use reqwest::{Client as HttpClient, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use serde_yaml::{self, Deserializer as YamlDeserializer, Value as YamlValue};
use tokio::fs;
use tokio::time::{sleep, Instant as TokioInstant};

use crate::JsonMap;
use crate::{
    build_http_client, json_output_enabled, log_cli_goal, CliUsageError, HubHttpClient,
    KubeApplyArgs, KubeBackupArgs, KubeDeleteArgs, KubeLogsArgs, KubeRenderArgs, KubeRestoreArgs,
    KubeStatusArgs, RemoteHealthStatus, RemoteObservabilityReport,
};
use toml::Value as TomlValue;

const HUB_HTTP_PORT: u16 = 8080;
const HUB_FIELD_MANAGER: &str = "veen-cli";

#[derive(Serialize)]
struct KubeStatusReport {
    deployment_name: String,
    namespace: String,
    desired_replicas: i32,
    ready_replicas: i32,
    pods: Vec<PodStatusReport>,
}

#[derive(Serialize)]
struct PodStatusReport {
    name: String,
    phase: Option<String>,
    restarts: i32,
    health: Option<String>,
}

struct WorkloadStatus {
    kind: &'static str,
    desired: i32,
    ready: i32,
}

#[derive(Serialize, Deserialize, Debug)]
struct RemoteBackupRequest {
    snapshot_name: String,
    target_uri: String,
}

#[derive(Deserialize, Debug)]
struct RemoteBackupResponse {
    ok: bool,
    snapshot_name: String,
    #[serde(default)]
    profile_id: Option<String>,
    #[serde(default)]
    last_stream_seq: BTreeMap<String, u64>,
    #[serde(default)]
    mmr_roots: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct RemoteRestoreRequest {
    snapshot_name: String,
    source_uri: String,
}

#[derive(Deserialize, Debug)]
struct RemoteRestoreResponse {
    ok: bool,
    snapshot_name: String,
    #[serde(default)]
    last_stream_seq: BTreeMap<String, u64>,
    #[serde(default)]
    mmr_roots: BTreeMap<String, String>,
}

pub(crate) async fn handle_kube_render(args: KubeRenderArgs) -> Result<()> {
    if args.namespace.trim().is_empty() {
        bail_usage!("namespace must not be empty");
    }
    if args.name.trim().is_empty() {
        bail_usage!("name must not be empty");
    }

    let docs = render_kube_manifests(&args).await?;
    if json_output_enabled(args.json) {
        let rendered = serde_json::to_string_pretty(&docs)
            .context("serializing rendered manifests to JSON")?;
        println!("{rendered}");
    } else {
        let rendered = render_yaml_documents(&docs)?;
        print!("{rendered}");
    }
    log_cli_goal("CLI.KUBE.RENDER");
    Ok(())
}

pub(crate) async fn handle_kube_apply(args: KubeApplyArgs) -> Result<()> {
    let client = build_kube_client(&args.cluster_context).await?;
    let manifests = load_rendered_manifests(&args.file).await?;
    let mut namespace = None;
    let mut deployment_name = None;
    let mut service_name = None;

    for manifest in &manifests {
        match manifest {
            KubeManifest::Deployment(deployment) => {
                namespace = namespace.or_else(|| deployment.metadata.namespace.clone());
                deployment_name = deployment_name.or_else(|| deployment.metadata.name.clone());
            }
            KubeManifest::StatefulSet(set) => {
                namespace = namespace.or_else(|| set.metadata.namespace.clone());
                deployment_name = deployment_name.or_else(|| set.metadata.name.clone());
            }
            KubeManifest::Service(service) => {
                namespace = namespace.or_else(|| service.metadata.namespace.clone());
                service_name = service_name.or_else(|| service.metadata.name.clone());
            }
            _ => {}
        }
    }

    for manifest in manifests {
        apply_manifest(&client, manifest).await?;
    }

    if let Some(wait) = args.wait_seconds {
        if let (Some(ns), Some(name)) = (&namespace, &deployment_name) {
            wait_for_deployment_ready(&client, ns, name, Duration::from_secs(wait)).await?;
        }
    }

    let ns = namespace.unwrap_or_else(|| "default".to_string());
    let svc = service_name
        .or_else(|| deployment_name.clone())
        .unwrap_or_else(|| format!("veen-hub-{}", args.file.display()));
    println!("namespace: {ns}");
    println!("service: {}", service_dns(&ns, &svc));
    log_cli_goal("CLI.KUBE.APPLY");
    Ok(())
}

pub(crate) async fn handle_kube_delete(args: KubeDeleteArgs) -> Result<()> {
    let client = build_kube_client(&args.cluster_context).await?;
    let names = KubeResourceNames::new(&args.name);
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), &args.namespace);
    let stateful_sets: Api<StatefulSet> = Api::namespaced(client.clone(), &args.namespace);
    let services: Api<Service> = Api::namespaced(client.clone(), &args.namespace);
    let roles: Api<Role> = Api::namespaced(client.clone(), &args.namespace);
    let role_bindings: Api<RoleBinding> = Api::namespaced(client.clone(), &args.namespace);
    let service_accounts: Api<ServiceAccount> = Api::namespaced(client.clone(), &args.namespace);
    let config_maps: Api<ConfigMap> = Api::namespaced(client.clone(), &args.namespace);
    let secrets: Api<Secret> = Api::namespaced(client.clone(), &args.namespace);

    let mut deleted_any = false;
    deleted_any |= delete_resource(&deployments, &names.hub).await?;
    deleted_any |= delete_resource(&stateful_sets, &names.hub).await?;
    deleted_any |= delete_resource(&services, &names.service).await?;
    deleted_any |= delete_resource(&roles, &names.role).await?;
    deleted_any |= delete_resource(&role_bindings, &names.role_binding).await?;
    deleted_any |= delete_resource(&service_accounts, &names.service_account).await?;
    deleted_any |= delete_resource(&config_maps, &names.config_map).await?;
    deleted_any |= delete_resource(&secrets, &names.secret).await?;

    if args.purge_pvcs {
        let pvc_names =
            collect_persistent_volume_claims(&client, &args.namespace, &names.hub).await?;
        let pvcs: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), &args.namespace);
        for pvc in pvc_names {
            deleted_any |= delete_resource(&pvcs, &pvc).await?;
        }
    }

    if deleted_any {
        println!("deleted Kubernetes resources for {}", names.hub);
    } else {
        println!("already deleted");
    }
    log_cli_goal("CLI.KUBE.DELETE");
    Ok(())
}

pub(crate) async fn handle_kube_status(args: KubeStatusArgs) -> Result<()> {
    let client = build_kube_client(&args.cluster_context).await?;
    let names = KubeResourceNames::new(&args.name);
    let workload = fetch_workload_status(&client, &args.namespace, &names.hub).await?;
    let selector = format!("veen.hub.name={}", args.name);
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), &args.namespace);
    let pods = pods_api
        .list(&ListParams::default().labels(&selector))
        .await
        .context("listing VEEN hub pods")?;
    let http = build_http_client()?;
    let mut reports = Vec::new();
    for pod in pods.items {
        let name = pod.metadata.name.clone().unwrap_or_default();
        let phase = pod.status.as_ref().and_then(|status| status.phase.clone());
        let restarts = pod
            .status
            .as_ref()
            .and_then(|status| status.container_statuses.clone())
            .map(|statuses| statuses.into_iter().map(|s| s.restart_count).sum())
            .unwrap_or(0);
        let health = fetch_pod_health(&http, pod.status.as_ref(), HUB_HTTP_PORT).await;
        reports.push(PodStatusReport {
            name,
            phase,
            restarts,
            health,
        });
    }
    let status = KubeStatusReport {
        deployment_name: names.hub.clone(),
        namespace: args.namespace.clone(),
        desired_replicas: workload.desired,
        ready_replicas: workload.ready,
        pods: reports,
    };
    if json_output_enabled(args.json) {
        let rendered =
            serde_json::to_string_pretty(&status).context("serializing kube status to JSON")?;
        println!("{rendered}");
    } else {
        println!("deployment: {} ({})", status.deployment_name, workload.kind);
        println!("namespace: {}", status.namespace);
        println!("desired_replicas: {}", status.desired_replicas);
        println!("ready_replicas: {}", status.ready_replicas);
        if status.pods.is_empty() {
            println!("pods: (none)");
        } else {
            println!("pods:");
            for pod in &status.pods {
                let phase = pod.phase.clone().unwrap_or_else(|| "unknown".to_string());
                let health = pod
                    .health
                    .clone()
                    .unwrap_or_else(|| "unreachable".to_string());
                println!(
                    "  {}: phase={phase} restarts={} health={health}",
                    pod.name, pod.restarts
                );
            }
        }
    }
    log_cli_goal("CLI.KUBE.STATUS");
    Ok(())
}

pub(crate) async fn handle_kube_logs(args: KubeLogsArgs) -> Result<()> {
    let client = build_kube_client(&args.cluster_context).await?;
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), &args.namespace);
    let since = parse_duration(&args.since)
        .with_context(|| format!("parsing --since value {}", args.since))?;
    let since_seconds = since.as_secs().min(i64::MAX as u64) as i64;
    let mut params = LogParams::default();
    params.follow = args.follow;
    params.since_seconds = Some(since_seconds);

    if let Some(pod) = args.pod.as_ref() {
        stream_pod_logs(&pods_api, pod, &params).await?;
    } else {
        let selector = format!("veen.hub.name={}", args.name);
        let mut pods = pods_api
            .list(&ListParams::default().labels(&selector))
            .await
            .context("listing pods for logs")?
            .items
            .into_iter()
            .filter_map(|pod| pod.metadata.name)
            .collect::<Vec<_>>();
        if pods.is_empty() {
            bail_usage!("no pods found for hub {}", args.name);
        }
        pods.sort();
        let multi = pods.len() > 1;
        for pod in pods {
            if multi {
                println!("==> pod {pod} <==");
            }
            stream_pod_logs(&pods_api, &pod, &params).await?;
        }
    }
    log_cli_goal("CLI.KUBE.LOGS");
    Ok(())
}

pub(crate) async fn handle_kube_backup(args: KubeBackupArgs) -> Result<()> {
    let client = build_kube_client(&args.cluster_context).await?;
    let names = KubeResourceNames::new(&args.name);
    ensure_workload_exists(&client, &args.namespace, &names.hub).await?;
    let base_url = hub_service_base_url(&args.namespace, &names.service)?;
    let hub_client = HubHttpClient::new(base_url, build_http_client()?);
    wait_for_hub_health(&hub_client, Duration::from_secs(60)).await?;
    let request = RemoteBackupRequest {
        snapshot_name: args.snapshot_name.clone(),
        target_uri: args.target_uri.clone(),
    };
    let response: RemoteBackupResponse = hub_client.post_json("/admin/backup", &request).await?;
    if !response.ok {
        bail_usage!(
            "hub backup request for {} was rejected",
            response.snapshot_name
        );
    }
    println!("snapshot: {}", response.snapshot_name);
    if let Some(profile) = response.profile_id.as_deref() {
        println!("profile_id: {profile}");
    }
    if response.last_stream_seq.is_empty() {
        println!("last_stream_seq: (none)");
    } else {
        println!("last_stream_seq:");
        for (label, seq) in response.last_stream_seq.iter() {
            println!("  {label}: {seq}");
        }
    }
    if response.mmr_roots.is_empty() {
        println!("mmr_roots: (none)");
    } else {
        println!("mmr_roots:");
        for (label, root) in response.mmr_roots.iter() {
            println!("  {label}: {root}");
        }
    }
    log_cli_goal("CLI.KUBE.BACKUP");
    Ok(())
}

pub(crate) async fn handle_kube_restore(args: KubeRestoreArgs) -> Result<()> {
    let client = build_kube_client(&args.cluster_context).await?;
    let names = KubeResourceNames::new(&args.name);
    ensure_workload_exists(&client, &args.namespace, &names.hub).await?;
    let base_url = hub_service_base_url(&args.namespace, &names.service)?;
    let hub_client = HubHttpClient::new(base_url, build_http_client()?);
    let request = RemoteRestoreRequest {
        snapshot_name: args.snapshot_name.clone(),
        source_uri: args.source_uri.clone(),
    };
    let response: RemoteRestoreResponse = hub_client.post_json("/admin/restore", &request).await?;
    if !response.ok {
        bail_usage!(
            "hub restore request for {} was rejected",
            response.snapshot_name
        );
    }
    wait_for_hub_health(&hub_client, Duration::from_secs(120)).await?;
    let metrics: RemoteObservabilityReport = hub_client.get_json("/metrics", &[]).await?;
    verify_restore_state(&response, &metrics)?;
    println!("restore applied: {}", response.snapshot_name);
    log_cli_goal("CLI.KUBE.RESTORE");
    Ok(())
}

async fn render_kube_manifests(args: &KubeRenderArgs) -> Result<Vec<JsonValue>> {
    let config_contents = fs::read_to_string(&args.config)
        .await
        .with_context(|| format!("reading hub config {}", args.config.display()))?;
    let env_pairs = if let Some(path) = &args.env_file {
        Some(parse_env_file(path).await?)
    } else {
        None
    };
    let annotation_overrides = if let Some(path) = &args.pod_annotations {
        Some(parse_annotation_file(path).await?)
    } else {
        None
    };
    let profile_id = args
        .profile_id
        .clone()
        .or_else(|| detect_profile_id(&config_contents));
    let names = KubeResourceNames::new(&args.name);
    let mut docs = Vec::new();
    docs.push(namespace_manifest_value(&args.namespace, &args.name));
    docs.push(service_account_manifest_value(
        &names.logical,
        &names.service_account,
        &args.namespace,
    ));
    docs.push(role_manifest_value(
        &names.logical,
        &names.role,
        &args.namespace,
    ));
    docs.push(role_binding_manifest_value(
        &names.logical,
        &names.role_binding,
        &args.namespace,
        &names.role,
        &names.service_account,
    ));
    docs.push(config_map_manifest_value(
        &names.logical,
        &names.config_map,
        &args.namespace,
        &config_contents,
    ));
    docs.push(secret_template_manifest_value(
        &names.logical,
        &names.secret,
        &args.namespace,
    ));
    docs.push(deployment_manifest_value(
        &names,
        args,
        env_pairs.as_deref(),
        annotation_overrides.as_ref(),
        profile_id.as_deref(),
    )?);
    docs.push(service_manifest_value(
        &names.logical,
        &names.service,
        &args.namespace,
    ));
    Ok(docs)
}

async fn parse_env_file(path: &Path) -> Result<Vec<(String, String)>> {
    let contents = fs::read_to_string(path)
        .await
        .with_context(|| format!("reading env file {}", path.display()))?;
    let mut pairs = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (key, value) = trimmed.split_once('=').ok_or_else(|| {
            CliUsageError::new(format!(
                "invalid env entry on line {} of {}",
                idx + 1,
                path.display()
            ))
        })?;
        if key.trim().is_empty() {
            bail_usage!(
                "invalid env entry on line {} of {}: key is empty",
                idx + 1,
                path.display()
            );
        }
        pairs.push((key.trim().to_string(), value.trim().to_string()));
    }
    Ok(pairs)
}

async fn parse_annotation_file(path: &Path) -> Result<BTreeMap<String, String>> {
    let contents = fs::read_to_string(path)
        .await
        .with_context(|| format!("reading annotation file {}", path.display()))?;
    let value: JsonValue = serde_json::from_str(&contents)
        .with_context(|| format!("parsing JSON annotations in {}", path.display()))?;
    let obj = value
        .as_object()
        .ok_or_else(|| CliUsageError::new("pod annotations must be a JSON object".to_string()))?;
    let mut map = BTreeMap::new();
    for (key, val) in obj {
        let value_str = val
            .as_str()
            .ok_or_else(|| CliUsageError::new(format!("annotation {key} must be a string")))?;
        map.insert(key.clone(), value_str.to_string());
    }
    Ok(map)
}

fn detect_profile_id(contents: &str) -> Option<String> {
    let Ok(value) = toml::from_str::<TomlValue>(contents) else {
        return None;
    };
    value
        .get("profile_id")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
}

async fn load_rendered_manifests(path: &Path) -> Result<Vec<KubeManifest>> {
    let contents = fs::read_to_string(path)
        .await
        .with_context(|| format!("reading manifest file {}", path.display()))?;
    let mut manifests = Vec::new();
    for document in YamlDeserializer::from_str(&contents) {
        let value =
            YamlValue::deserialize(document).context("parsing Kubernetes manifest document")?;
        match value {
            YamlValue::Sequence(items) => {
                for item in items {
                    if item.is_null() {
                        continue;
                    }
                    manifests.push(decode_manifest(item)?);
                }
            }
            other if other.is_null() => {}
            other => manifests.push(decode_manifest(other)?),
        }
    }
    Ok(manifests)
}

enum KubeManifest {
    Namespace(Namespace),
    ServiceAccount(ServiceAccount),
    Role(Role),
    RoleBinding(RoleBinding),
    ConfigMap(ConfigMap),
    Secret(Secret),
    Deployment(Deployment),
    StatefulSet(StatefulSet),
    Service(Service),
}

fn decode_manifest(value: YamlValue) -> Result<KubeManifest> {
    let kind = value
        .get("kind")
        .and_then(|k| k.as_str())
        .ok_or_else(|| anyhow!("manifest is missing kind"))?;
    match kind {
        "Namespace" => Ok(KubeManifest::Namespace(serde_yaml::from_value(value)?)),
        "ServiceAccount" => Ok(KubeManifest::ServiceAccount(serde_yaml::from_value(value)?)),
        "Role" => Ok(KubeManifest::Role(serde_yaml::from_value(value)?)),
        "RoleBinding" => Ok(KubeManifest::RoleBinding(serde_yaml::from_value(value)?)),
        "ConfigMap" => Ok(KubeManifest::ConfigMap(serde_yaml::from_value(value)?)),
        "Secret" => Ok(KubeManifest::Secret(serde_yaml::from_value(value)?)),
        "Deployment" => Ok(KubeManifest::Deployment(serde_yaml::from_value(value)?)),
        "StatefulSet" => Ok(KubeManifest::StatefulSet(serde_yaml::from_value(value)?)),
        "Service" => Ok(KubeManifest::Service(serde_yaml::from_value(value)?)),
        other => bail_usage!("unsupported manifest kind {other}"),
    }
}

async fn apply_manifest(client: &KubeClient, manifest: KubeManifest) -> Result<()> {
    match manifest {
        KubeManifest::Namespace(namespace) => {
            let api: Api<Namespace> = Api::all(client.clone());
            let name = namespace
                .metadata
                .name
                .clone()
                .ok_or_else(|| anyhow!("namespace manifest missing metadata.name"))?;
            api.patch(&name, &kube_patch_params(), &Patch::Apply(&namespace))
                .await
                .context("applying Namespace")?;
        }
        KubeManifest::ServiceAccount(account) => {
            let namespace = account
                .metadata
                .namespace
                .clone()
                .ok_or_else(|| anyhow!("service account missing namespace"))?;
            let name = account
                .metadata
                .name
                .clone()
                .ok_or_else(|| anyhow!("service account missing name"))?;
            let api: Api<ServiceAccount> = Api::namespaced(client.clone(), &namespace);
            api.patch(&name, &kube_patch_params(), &Patch::Apply(&account))
                .await
                .context("applying ServiceAccount")?;
        }
        KubeManifest::Role(role) => {
            let namespace = role
                .metadata
                .namespace
                .clone()
                .ok_or_else(|| anyhow!("role missing namespace"))?;
            let name = role
                .metadata
                .name
                .clone()
                .ok_or_else(|| anyhow!("role missing name"))?;
            let api: Api<Role> = Api::namespaced(client.clone(), &namespace);
            api.patch(&name, &kube_patch_params(), &Patch::Apply(&role))
                .await
                .context("applying Role")?;
        }
        KubeManifest::RoleBinding(binding) => {
            let namespace = binding
                .metadata
                .namespace
                .clone()
                .ok_or_else(|| anyhow!("role binding missing namespace"))?;
            let name = binding
                .metadata
                .name
                .clone()
                .ok_or_else(|| anyhow!("role binding missing name"))?;
            let api: Api<RoleBinding> = Api::namespaced(client.clone(), &namespace);
            api.patch(&name, &kube_patch_params(), &Patch::Apply(&binding))
                .await
                .context("applying RoleBinding")?;
        }
        KubeManifest::ConfigMap(config_map) => {
            let namespace = config_map
                .metadata
                .namespace
                .clone()
                .ok_or_else(|| anyhow!("configmap missing namespace"))?;
            let name = config_map
                .metadata
                .name
                .clone()
                .ok_or_else(|| anyhow!("configmap missing name"))?;
            let api: Api<ConfigMap> = Api::namespaced(client.clone(), &namespace);
            api.patch(&name, &kube_patch_params(), &Patch::Apply(&config_map))
                .await
                .context("applying ConfigMap")?;
        }
        KubeManifest::Secret(secret) => {
            let namespace = secret
                .metadata
                .namespace
                .clone()
                .ok_or_else(|| anyhow!("secret missing namespace"))?;
            let name = secret
                .metadata
                .name
                .clone()
                .ok_or_else(|| anyhow!("secret missing name"))?;
            let api: Api<Secret> = Api::namespaced(client.clone(), &namespace);
            api.patch(&name, &kube_patch_params(), &Patch::Apply(&secret))
                .await
                .context("applying Secret")?;
        }
        KubeManifest::Deployment(deployment) => {
            let namespace = deployment
                .metadata
                .namespace
                .clone()
                .ok_or_else(|| anyhow!("deployment missing namespace"))?;
            let name = deployment
                .metadata
                .name
                .clone()
                .ok_or_else(|| anyhow!("deployment missing name"))?;
            let api: Api<Deployment> = Api::namespaced(client.clone(), &namespace);
            api.patch(&name, &kube_patch_params(), &Patch::Apply(&deployment))
                .await
                .context("applying Deployment")?;
        }
        KubeManifest::StatefulSet(set) => {
            let namespace = set
                .metadata
                .namespace
                .clone()
                .ok_or_else(|| anyhow!("statefulset missing namespace"))?;
            let name = set
                .metadata
                .name
                .clone()
                .ok_or_else(|| anyhow!("statefulset missing name"))?;
            let api: Api<StatefulSet> = Api::namespaced(client.clone(), &namespace);
            api.patch(&name, &kube_patch_params(), &Patch::Apply(&set))
                .await
                .context("applying StatefulSet")?;
        }
        KubeManifest::Service(service) => {
            let namespace = service
                .metadata
                .namespace
                .clone()
                .ok_or_else(|| anyhow!("service missing namespace"))?;
            let name = service
                .metadata
                .name
                .clone()
                .ok_or_else(|| anyhow!("service missing name"))?;
            let api: Api<Service> = Api::namespaced(client.clone(), &namespace);
            api.patch(&name, &kube_patch_params(), &Patch::Apply(&service))
                .await
                .context("applying Service")?;
        }
    }
    Ok(())
}

async fn delete_resource<T>(api: &Api<T>, name: &str) -> Result<bool>
where
    T: Clone + DeserializeOwned + Serialize + std::fmt::Debug,
{
    match api.delete(name, &DeleteParams::default()).await {
        Ok(_) => Ok(true),
        Err(KubeError::Api(err)) if err.code == 404 => Ok(false),
        Err(err) => Err(err.into()),
    }
}

fn kube_patch_params() -> PatchParams {
    let mut params = PatchParams::apply(HUB_FIELD_MANAGER);
    params.force = true;
    params
}

async fn collect_persistent_volume_claims(
    client: &KubeClient,
    namespace: &str,
    name: &str,
) -> Result<Vec<String>> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    if let Ok(deployment) = deployments.get(name).await {
        if let Some(spec) = deployment.spec.and_then(|spec| spec.template.spec) {
            return Ok(collect_claims_from_spec(spec));
        }
    }
    let sets: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);
    if let Ok(set) = sets.get(name).await {
        if let Some(spec) = set.spec.and_then(|spec| spec.template.spec) {
            return Ok(collect_claims_from_spec(spec));
        }
    }
    Ok(Vec::new())
}

fn collect_claims_from_spec(spec: PodSpec) -> Vec<String> {
    spec.volumes
        .unwrap_or_default()
        .into_iter()
        .filter_map(|volume| volume.persistent_volume_claim)
        .map(|claim| claim.claim_name)
        .collect()
}

async fn fetch_workload_status(
    client: &KubeClient,
    namespace: &str,
    name: &str,
) -> Result<WorkloadStatus> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    match deployments.get(name).await {
        Ok(deployment) => {
            let desired = deployment.spec.and_then(|spec| spec.replicas).unwrap_or(1);
            let ready = deployment
                .status
                .and_then(|status| status.ready_replicas)
                .unwrap_or(0);
            return Ok(WorkloadStatus {
                kind: "Deployment",
                desired,
                ready,
            });
        }
        Err(KubeError::Api(err)) if err.code == 404 => {}
        Err(err) => return Err(err.into()),
    }
    let sets: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);
    match sets.get(name).await {
        Ok(set) => {
            let desired = set.spec.and_then(|spec| spec.replicas).unwrap_or(1);
            let ready = set
                .status
                .and_then(|status| status.ready_replicas)
                .unwrap_or(0);
            Ok(WorkloadStatus {
                kind: "StatefulSet",
                desired,
                ready,
            })
        }
        Err(KubeError::Api(err)) if err.code == 404 => {
            bail_usage!("deployment or statefulset {name} not found in {namespace}");
        }
        Err(err) => Err(err.into()),
    }
}

async fn wait_for_deployment_ready(
    client: &KubeClient,
    namespace: &str,
    name: &str,
    timeout: Duration,
) -> Result<()> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let deadline = TokioInstant::now() + timeout;
    loop {
        match deployments.get(name).await {
            Ok(deployment) => {
                let desired = deployment.spec.and_then(|spec| spec.replicas).unwrap_or(1);
                let ready = deployment
                    .status
                    .and_then(|status| status.ready_replicas)
                    .unwrap_or(0);
                if ready >= desired {
                    return Ok(());
                }
            }
            Err(err) => return Err(err.into()),
        }
        if TokioInstant::now() >= deadline {
            bail_usage!("timed out waiting for deployment {name} to become ready");
        }
        sleep(Duration::from_secs(2)).await;
    }
}

async fn fetch_pod_health(
    http: &HttpClient,
    status: Option<&k8s_openapi::api::core::v1::PodStatus>,
    port: u16,
) -> Option<String> {
    let ip = status?.pod_ip.as_deref()?;
    let url = format!("http://{ip}:{port}/healthz");
    match http.get(&url).send().await {
        Ok(response) => match response.json::<RemoteHealthStatus>().await {
            Ok(health) => Some(if health.ok {
                "ok".to_string()
            } else {
                "unhealthy".to_string()
            }),
            Err(err) => Some(format!("health decode failed: {err}")),
        },
        Err(err) => Some(format!("{err}")),
    }
}

async fn stream_pod_logs(api: &Api<Pod>, pod: &str, params: &LogParams) -> Result<()> {
    if params.follow {
        let mut stream = api
            .log_stream(pod, params)
            .await
            .context("streaming pod logs")?
            .lines();
        while let Some(line) = stream.next().await {
            let line = line.context("reading streamed pod logs")?;
            println!("{line}");
        }
    } else {
        let logs = api.logs(pod, params).await.context("fetching pod logs")?;
        print!("{logs}");
    }
    Ok(())
}

async fn ensure_workload_exists(client: &KubeClient, namespace: &str, name: &str) -> Result<()> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    if deployments.get(name).await.is_ok() {
        return Ok(());
    }
    let sets: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);
    if sets.get(name).await.is_ok() {
        return Ok(());
    }
    bail_usage!("hub workload {name} not found in namespace {namespace}");
}

fn hub_service_base_url(namespace: &str, service: &str) -> Result<Url> {
    let host = format!("{}.{}", service, namespace);
    Url::parse(&format!("http://{host}.svc.cluster.local:{HUB_HTTP_PORT}/"))
        .context("constructing hub service URL")
}

fn service_dns(namespace: &str, service: &str) -> String {
    format!("{service}.{namespace}.svc.cluster.local:{}", HUB_HTTP_PORT)
}

async fn wait_for_hub_health(client: &HubHttpClient, timeout: Duration) -> Result<()> {
    let deadline = TokioInstant::now() + timeout;
    let mut last_err = None;
    loop {
        match client.get_json::<RemoteHealthStatus>("/healthz", &[]).await {
            Ok(health) if health.ok => return Ok(()),
            Ok(_) => {}
            Err(err) => last_err = Some(err),
        }
        if TokioInstant::now() >= deadline {
            if let Some(err) = last_err {
                return Err(err);
            }
            bail_usage!("hub did not become ready before timeout");
        }
        sleep(Duration::from_secs(2)).await;
    }
}

fn verify_restore_state(
    response: &RemoteRestoreResponse,
    metrics: &RemoteObservabilityReport,
) -> Result<()> {
    for (label, seq) in response.last_stream_seq.iter() {
        let observed = metrics
            .last_stream_seq
            .get(label)
            .copied()
            .unwrap_or_default();
        if observed != *seq {
            bail_usage!("label {label} seq mismatch: expected {seq}, observed {observed}");
        }
    }
    for (label, root) in response.mmr_roots.iter() {
        let observed = metrics.mmr_roots.get(label).cloned().unwrap_or_default();
        if observed != *root {
            bail_usage!("label {label} mmr mismatch");
        }
    }
    Ok(())
}

async fn build_kube_client(context: &str) -> Result<KubeClient> {
    let options = KubeConfigOptions {
        context: Some(context.to_string()),
        ..KubeConfigOptions::default()
    };
    let config = KubeConfig::from_kubeconfig(&options)
        .await
        .context("loading kubeconfig")?;
    KubeClient::try_from(config).context("building Kubernetes client")
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

#[derive(Clone)]
struct KubeResourceNames {
    logical: String,
    hub: String,
    service: String,
    service_account: String,
    role: String,
    role_binding: String,
    config_map: String,
    secret: String,
}

impl KubeResourceNames {
    fn new(logical: &str) -> Self {
        let hub = format!("veen-hub-{logical}");
        Self {
            logical: logical.to_string(),
            service: hub.clone(),
            service_account: hub.clone(),
            role: format!("{hub}-role"),
            role_binding: format!("{hub}-binding"),
            config_map: format!("{hub}-config"),
            secret: format!("{hub}-keys"),
            hub,
        }
    }
}

struct ResourceQuantity {
    request: String,
    limit: String,
}

fn parse_resource_quantity(input: &Option<String>) -> Result<Option<ResourceQuantity>> {
    if let Some(value) = input {
        let mut parts = value.split(',');
        let request = parts
            .next()
            .ok_or_else(|| anyhow!("missing resource request"))?
            .trim();
        let limit = parts.next().map(|v| v.trim()).unwrap_or(request);
        if request.is_empty() {
            bail_usage!("resource request must not be empty");
        }
        Ok(Some(ResourceQuantity {
            request: request.to_string(),
            limit: limit.to_string(),
        }))
    } else {
        Ok(None)
    }
}

fn base_labels(logical: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("app".to_string(), "veen-hub".to_string());
    labels.insert("veen.hub.name".to_string(), logical.to_string());
    labels
}

fn namespace_manifest_value(namespace: &str, logical: &str) -> JsonValue {
    let mut labels = BTreeMap::new();
    labels.insert("app.kubernetes.io/part-of".to_string(), "veen".to_string());
    labels.insert("veen.hub.name".to_string(), logical.to_string());
    let annotations = base_annotations();
    json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": metadata_value(Some(namespace), None, &labels, &annotations)
    })
}

fn service_account_manifest_value(logical: &str, name: &str, namespace: &str) -> JsonValue {
    let labels = base_labels(logical);
    let annotations = base_annotations();
    json!({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": metadata_value(Some(name), Some(namespace), &labels, &annotations)
    })
}

fn role_manifest_value(logical: &str, name: &str, namespace: &str) -> JsonValue {
    let labels = base_labels(logical);
    let annotations = base_annotations();
    json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": metadata_value(Some(name), Some(namespace), &labels, &annotations),
        "rules": [
            {
                "apiGroups": [""],
                "resources": ["pods", "services", "configmaps", "secrets", "persistentvolumeclaims"],
                "verbs": ["get", "list", "watch"]
            }
        ]
    })
}

fn role_binding_manifest_value(
    logical: &str,
    name: &str,
    namespace: &str,
    role: &str,
    service_account: &str,
) -> JsonValue {
    let labels = base_labels(logical);
    let annotations = base_annotations();
    json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": metadata_value(Some(name), Some(namespace), &labels, &annotations),
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "Role",
            "name": role
        },
        "subjects": [
            {"kind": "ServiceAccount", "name": service_account, "namespace": namespace}
        ]
    })
}

fn config_map_manifest_value(
    logical: &str,
    name: &str,
    namespace: &str,
    contents: &str,
) -> JsonValue {
    let labels = base_labels(logical);
    let annotations = base_annotations();
    let mut data = JsonMap::new();
    data.insert(
        crate::HUB_CONFIG_FILE.to_string(),
        JsonValue::String(contents.to_string()),
    );
    json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": metadata_value(Some(name), Some(namespace), &labels, &annotations),
        "data": data
    })
}

fn secret_template_manifest_value(logical: &str, name: &str, namespace: &str) -> JsonValue {
    let labels = base_labels(logical);
    let annotations = base_annotations();
    let mut string_data = JsonMap::new();
    string_data.insert("hub.keys".to_string(), JsonValue::String(String::new()));
    json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": metadata_value(Some(name), Some(namespace), &labels, &annotations),
        "type": "Opaque",
        "stringData": string_data
    })
}

fn deployment_manifest_value(
    names: &KubeResourceNames,
    args: &KubeRenderArgs,
    env_pairs: Option<&[(String, String)]>,
    annotation_overrides: Option<&BTreeMap<String, String>>,
    profile_id: Option<&str>,
) -> Result<JsonValue> {
    let labels = base_labels(&names.logical);
    let mut annotations = base_annotations();
    if let Some(overrides) = annotation_overrides {
        for (key, value) in overrides.iter() {
            annotations.insert(key.clone(), value.clone());
        }
    }
    let mut hub_args = vec![
        "hub".to_string(),
        "start".to_string(),
        "--listen".to_string(),
        format!("0.0.0.0:{HUB_HTTP_PORT}"),
        "--data-dir".to_string(),
        "/var/lib/veen".to_string(),
        "--config".to_string(),
        format!("/etc/veen/{}", crate::HUB_CONFIG_FILE),
        "--foreground".to_string(),
    ];
    if let Some(profile) = profile_id {
        hub_args.push("--profile-id".to_string());
        hub_args.push(profile.to_string());
    }
    let env = build_container_env(env_pairs);
    let cpu = parse_resource_quantity(&args.resources_cpu)?;
    let mem = parse_resource_quantity(&args.resources_mem)?;
    let resources = build_resource_block(cpu.as_ref(), mem.as_ref());
    let volume_mounts = vec![
        json!({"name": "veen-config", "mountPath": "/etc/veen", "readOnly": true}),
        json!({"name": "veen-keys", "mountPath": "/etc/veen/keys", "readOnly": true}),
        json!({"name": "veen-data", "mountPath": "/var/lib/veen"}),
    ];
    let volumes = vec![
        json!({"name": "veen-config", "configMap": {"name": names.config_map}}),
        json!({"name": "veen-keys", "secret": {"secretName": names.secret}}),
        json!({
            "name": "veen-data",
            "persistentVolumeClaim": {"claimName": args.data_pvc}
        }),
    ];
    let selector = JsonValue::Object(to_json_map(&labels));
    let pod_metadata = metadata_value(None, None, &labels, &annotations);
    let metadata = metadata_value(
        Some(&names.hub),
        Some(&args.namespace),
        &labels,
        &annotations,
    );
    Ok(json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": metadata,
        "spec": {
            "replicas": args.replicas,
            "selector": {"matchLabels": selector},
            "template": {
                "metadata": pod_metadata,
                "spec": {
                    "serviceAccountName": names.service_account,
                    "containers": [{
                        "name": names.hub,
                        "image": args.image,
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["veen"],
                        "args": hub_args,
                        "env": env,
                        "ports": [{"name": "http", "containerPort": HUB_HTTP_PORT}],
                        "resources": resources,
                        "volumeMounts": volume_mounts,
                        "livenessProbe": {
                            "httpGet": {"path": "/healthz", "port": "http"},
                            "initialDelaySeconds": 10,
                            "periodSeconds": 10,
                            "failureThreshold": 6
                        },
                        "readinessProbe": {
                            "httpGet": {"path": "/healthz", "port": "http"},
                            "initialDelaySeconds": 5,
                            "periodSeconds": 10,
                            "failureThreshold": 3,
                            "successThreshold": 1
                        },
                        "securityContext": {
                            "runAsNonRoot": true,
                            "readOnlyRootFilesystem": true,
                            "allowPrivilegeEscalation": false
                        }
                    }],
                    "volumes": volumes
                }
            }
        }
    }))
}

fn service_manifest_value(logical: &str, name: &str, namespace: &str) -> JsonValue {
    let labels = base_labels(logical);
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": metadata_value(Some(name), Some(namespace), &labels, &base_annotations()),
        "spec": {
            "selector": to_json_map(&labels),
            "ports": [{"name": "http", "port": HUB_HTTP_PORT, "targetPort": HUB_HTTP_PORT}],
            "type": "ClusterIP"
        }
    })
}

fn build_container_env(pairs: Option<&[(String, String)]>) -> Vec<JsonValue> {
    let mut env = Vec::new();
    if let Some(pairs) = pairs {
        for (key, value) in pairs {
            env.push(json!({"name": key, "value": value}));
        }
    }
    env
}

fn build_resource_block(
    cpu: Option<&ResourceQuantity>,
    mem: Option<&ResourceQuantity>,
) -> JsonValue {
    let mut requests = JsonMap::new();
    let mut limits = JsonMap::new();
    if let Some(cpu) = cpu {
        requests.insert("cpu".to_string(), JsonValue::String(cpu.request.clone()));
        limits.insert("cpu".to_string(), JsonValue::String(cpu.limit.clone()));
    }
    if let Some(mem) = mem {
        requests.insert("memory".to_string(), JsonValue::String(mem.request.clone()));
        limits.insert("memory".to_string(), JsonValue::String(mem.limit.clone()));
    }
    json!({"requests": requests, "limits": limits})
}

fn metadata_value(
    name: Option<&str>,
    namespace: Option<&str>,
    labels: &BTreeMap<String, String>,
    annotations: &BTreeMap<String, String>,
) -> JsonValue {
    let mut meta = JsonMap::new();
    if let Some(name) = name {
        meta.insert("name".to_string(), JsonValue::String(name.to_string()));
    }
    if let Some(namespace) = namespace {
        meta.insert(
            "namespace".to_string(),
            JsonValue::String(namespace.to_string()),
        );
    }
    if !labels.is_empty() {
        meta.insert("labels".to_string(), JsonValue::Object(to_json_map(labels)));
    }
    if !annotations.is_empty() {
        meta.insert(
            "annotations".to_string(),
            JsonValue::Object(to_json_map(annotations)),
        );
    }
    JsonValue::Object(meta)
}

fn to_json_map(map: &BTreeMap<String, String>) -> JsonMap {
    map.iter()
        .map(|(k, v)| (k.clone(), JsonValue::String(v.clone())))
        .collect()
}

fn base_annotations() -> BTreeMap<String, String> {
    let mut annotations = BTreeMap::new();
    annotations.insert(
        "app.kubernetes.io/managed-by".to_string(),
        HUB_FIELD_MANAGER.to_string(),
    );
    annotations
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[tokio::test]
    async fn render_manifests_are_deterministic() {
        let tmp = tempdir().unwrap();
        let config_path = tmp.path().join("hub-config.toml");
        fs::write(
            &config_path,
            "profile_id = \"0123456789abcdef0123456789abcdef\"",
        )
        .unwrap();
        let env_path = tmp.path().join("hub.env");
        fs::write(&env_path, "FOO=bar\nBAR=baz\n").unwrap();
        let annotations_path = tmp.path().join("annotations.json");
        fs::write(&annotations_path, "{\"hub.veen.dev/debug\":\"true\"}").unwrap();
        let args = KubeRenderArgs {
            cluster_context: "dev".into(),
            namespace: "test-ns".into(),
            name: "alpha".into(),
            image: "ghcr.io/veen/hub:latest".into(),
            data_pvc: "hub-data".into(),
            replicas: 2,
            resources_cpu: Some("250m,500m".into()),
            resources_mem: Some("256Mi,512Mi".into()),
            profile_id: None,
            config: config_path,
            env_file: Some(env_path),
            pod_annotations: Some(annotations_path),
            json: false,
        };
        let first = render_kube_manifests(&args).await.unwrap();
        let second = render_kube_manifests(&args).await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn load_rendered_accepts_json_arrays() {
        let tmp = tempdir().unwrap();
        let manifest_path = tmp.path().join("hub.json");
        let docs = json!([
            {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {"name": "alpha"}
            },
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {"name": "alpha", "namespace": "alpha"}
            }
        ]);
        fs::write(&manifest_path, serde_json::to_string(&docs).unwrap()).unwrap();
        let manifests = load_rendered_manifests(&manifest_path).await.unwrap();
        assert_eq!(manifests.len(), 2);
    }
}
