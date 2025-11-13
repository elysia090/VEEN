use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::fs;

/// Runtime configuration for the VEEN hub process.
#[derive(Debug, Clone)]
pub struct HubRuntimeConfig {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub profile_id: Option<String>,
    pub anchors: AnchorConfig,
    pub observability: ObservabilityConfig,
    pub config_path: Option<PathBuf>,
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

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    listen: Option<SocketAddr>,
    profile_id: Option<String>,
    #[serde(default)]
    anchor: AnchorSection,
    #[serde(default)]
    observability: ObservabilitySection,
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

impl HubRuntimeConfig {
    pub async fn from_sources(
        listen: SocketAddr,
        data_dir: PathBuf,
        config_path: Option<PathBuf>,
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
        let profile_id = file_cfg.profile_id;
        let anchors = AnchorConfig {
            enabled: file_cfg.anchor.enabled.unwrap_or(true),
            backend: file_cfg.anchor.backend,
        };
        let observability = ObservabilityConfig {
            enable_metrics: file_cfg.observability.enable_metrics.unwrap_or(true),
            enable_logs: file_cfg.observability.enable_logs.unwrap_or(true),
        };

        Ok(Self {
            listen: resolved_listen,
            data_dir,
            profile_id,
            anchors,
            observability,
            config_path,
        })
    }
}

fn parse_config(contents: &str, path: &PathBuf) -> Result<FileConfig> {
    let deserializer = toml::Deserializer::new(contents);
    let parsed = serde_path_to_error::deserialize(deserializer)
        .with_context(|| format!("parsing hub configuration at {}", path.display()))?;
    Ok(parsed)
}
