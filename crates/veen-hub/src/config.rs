use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tokio::fs;

/// Runtime configuration for the VEEN hub process.
#[derive(Debug, Clone)]
pub struct HubRuntimeConfig {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub role: HubRole,
    pub profile_id: Option<String>,
    pub anchors: AnchorConfig,
    pub observability: ObservabilityConfig,
    pub admission: AdmissionConfig,
    pub federation: FederationConfig,
    pub config_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubRole {
    Primary,
    Replica,
}

#[derive(Debug, Clone, Default)]
pub struct AnchorConfig {
    pub enabled: bool,
    pub backend: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ObservabilityConfig {
    pub enable_metrics: bool,
    pub enable_logs: bool,
}

#[derive(Debug, Clone)]
pub struct AdmissionConfig {
    pub capability_gating_enabled: bool,
    pub max_client_id_lifetime_sec: Option<u64>,
    pub max_msgs_per_client_id_per_label: Option<u64>,
    pub pow_difficulty: Option<u8>,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            capability_gating_enabled: true,
            max_client_id_lifetime_sec: None,
            max_msgs_per_client_id_per_label: None,
            pow_difficulty: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FederationConfig {
    pub replica_targets: Vec<String>,
}

#[derive(Debug, Default)]
pub struct HubConfigOverrides {
    pub profile_id: Option<String>,
    pub anchors_enabled: Option<bool>,
    pub anchor_backend: Option<String>,
    pub enable_metrics: Option<bool>,
    pub enable_logs: Option<bool>,
    pub capability_gating_enabled: Option<bool>,
    pub max_client_id_lifetime_sec: Option<u64>,
    pub max_msgs_per_client_id_per_label: Option<u64>,
    pub replica_targets: Option<Vec<String>>,
    pub pow_difficulty: Option<u8>,
}

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    listen: Option<SocketAddr>,
    profile_id: Option<String>,
    #[serde(default)]
    anchor: AnchorSection,
    #[serde(default)]
    observability: ObservabilitySection,
    #[serde(default)]
    admission: AdmissionSection,
    #[serde(default)]
    federation: FederationSection,
}

#[derive(Debug, Deserialize, Default)]
struct AnchorSection {
    enabled: Option<bool>,
    backend: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ObservabilitySection {
    enable_metrics: Option<bool>,
    enable_logs: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
struct AdmissionSection {
    capability_gating_enabled: Option<bool>,
    max_client_id_lifetime_sec: Option<u64>,
    max_msgs_per_client_id_per_label: Option<u64>,
    pow_difficulty: Option<u8>,
}

#[derive(Debug, Deserialize, Default)]
struct FederationSection {
    replica_targets: Option<Vec<String>>,
}

impl HubRuntimeConfig {
    pub async fn from_sources(
        listen: SocketAddr,
        data_dir: PathBuf,
        config_path: Option<PathBuf>,
        role: HubRole,
        overrides: HubConfigOverrides,
    ) -> Result<Self> {
        let file_cfg = if let Some(path) = config_path.as_ref() {
            let contents = fs::read_to_string(path)
                .await
                .with_context(|| format!("reading hub configuration from {}", path.display()))?;
            parse_config(&contents, path)?
        } else {
            FileConfig::default()
        };

        let resolved_listen = file_cfg.listen.unwrap_or(listen);
        let profile_id = overrides.profile_id.or(file_cfg.profile_id);
        let anchors = AnchorConfig {
            enabled: overrides
                .anchors_enabled
                .unwrap_or_else(|| file_cfg.anchor.enabled.unwrap_or(true)),
            backend: overrides.anchor_backend.or(file_cfg.anchor.backend),
        };
        let observability = ObservabilityConfig {
            enable_metrics: overrides
                .enable_metrics
                .unwrap_or_else(|| file_cfg.observability.enable_metrics.unwrap_or(true)),
            enable_logs: overrides
                .enable_logs
                .unwrap_or_else(|| file_cfg.observability.enable_logs.unwrap_or(true)),
        };
        let admission = AdmissionConfig {
            capability_gating_enabled: overrides
                .capability_gating_enabled
                .unwrap_or_else(|| file_cfg.admission.capability_gating_enabled.unwrap_or(true)),
            max_client_id_lifetime_sec: overrides
                .max_client_id_lifetime_sec
                .or(file_cfg.admission.max_client_id_lifetime_sec),
            max_msgs_per_client_id_per_label: overrides
                .max_msgs_per_client_id_per_label
                .or(file_cfg.admission.max_msgs_per_client_id_per_label),
            pow_difficulty: overrides
                .pow_difficulty
                .or(file_cfg.admission.pow_difficulty),
        };
        let federation = FederationConfig {
            replica_targets: overrides
                .replica_targets
                .or(file_cfg.federation.replica_targets)
                .unwrap_or_default(),
        };

        if matches!(role, HubRole::Replica) && federation.replica_targets.is_empty() {
            bail!("replica hubs require at least one replica target to be configured");
        }

        Ok(Self {
            listen: resolved_listen,
            data_dir,
            role,
            profile_id,
            anchors,
            observability,
            admission,
            federation,
            config_path,
        })
    }
}

fn parse_config(contents: &str, path: &Path) -> Result<FileConfig> {
    let deserializer = toml::Deserializer::new(contents);
    let parsed = serde_path_to_error::deserialize(deserializer)
        .with_context(|| format!("parsing hub configuration at {}", path.display()))?;
    Ok(parsed)
}
