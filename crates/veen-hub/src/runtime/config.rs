use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use tokio::fs;

/// Runtime configuration for the VEEN hub process.
#[derive(Debug, Clone)]
pub struct HubRuntimeConfig {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub role: HubRole,
    pub profile_id: Option<String>,
    pub tooling_enabled: bool,
    pub anchors: AnchorConfig,
    pub observability: ObservabilityConfig,
    pub dedup: DedupConfig,
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
pub struct DedupConfig {
    pub bloom_capacity: usize,
    pub bloom_false_positive_rate: f64,
    pub lru_capacity: usize,
}

impl Default for DedupConfig {
    fn default() -> Self {
        Self {
            bloom_capacity: 10_000,
            bloom_false_positive_rate: 0.01,
            lru_capacity: 4096,
        }
    }
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

#[derive(Debug, Default, Clone)]
pub struct HubConfigOverrides {
    pub profile_id: Option<String>,
    pub anchors_enabled: Option<bool>,
    pub anchor_backend: Option<String>,
    pub enable_metrics: Option<bool>,
    pub enable_logs: Option<bool>,
    pub tooling_enabled: Option<bool>,
    pub bloom_capacity: Option<usize>,
    pub bloom_false_positive_rate: Option<f64>,
    pub lru_capacity: Option<usize>,
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
    tooling: ToolingSection,
    #[serde(default)]
    anchor: AnchorSection,
    #[serde(default)]
    observability: ObservabilitySection,
    #[serde(default)]
    dedup: DedupSection,
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
struct ToolingSection {
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
struct ObservabilitySection {
    enable_metrics: Option<bool>,
    enable_logs: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
struct DedupSection {
    bloom_capacity: Option<usize>,
    bloom_false_positive_rate: Option<f64>,
    lru_capacity: Option<usize>,
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
        let tooling_enabled = overrides
            .tooling_enabled
            .unwrap_or_else(|| file_cfg.tooling.enabled.unwrap_or(false));
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
        let dedup = DedupConfig {
            bloom_capacity: overrides
                .bloom_capacity
                .or(file_cfg.dedup.bloom_capacity)
                .unwrap_or_else(|| DedupConfig::default().bloom_capacity),
            bloom_false_positive_rate: overrides
                .bloom_false_positive_rate
                .or(file_cfg.dedup.bloom_false_positive_rate)
                .unwrap_or_else(|| DedupConfig::default().bloom_false_positive_rate),
            lru_capacity: overrides
                .lru_capacity
                .or(file_cfg.dedup.lru_capacity)
                .unwrap_or_else(|| DedupConfig::default().lru_capacity),
        };
        validate_dedup_config(&dedup).context("validating dedup configuration")?;
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
            tooling_enabled,
            anchors,
            observability,
            dedup,
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

fn validate_dedup_config(dedup: &DedupConfig) -> Result<()> {
    ensure!(
        dedup.bloom_capacity > 0,
        "dedup bloom_capacity must be greater than 0 (got {})",
        dedup.bloom_capacity
    );
    ensure!(
        dedup.lru_capacity > 0,
        "dedup lru_capacity must be greater than 0 (got {})",
        dedup.lru_capacity
    );
    ensure!(
        dedup.bloom_false_positive_rate.is_finite()
            && dedup.bloom_false_positive_rate > 0.0
            && dedup.bloom_false_positive_rate < 1.0,
        "dedup bloom_false_positive_rate must be between 0 and 1 (exclusive); got {}",
        dedup.bloom_false_positive_rate
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn default_listen() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 37411))
    }

    #[test]
    fn dedup_defaults_are_valid() {
        let dedup = DedupConfig::default();
        assert_eq!(dedup.bloom_capacity, 10_000);
        assert_eq!(dedup.lru_capacity, 4096);
        assert!(validate_dedup_config(&dedup).is_ok());
    }

    #[test]
    fn dedup_rejects_zero_bloom_capacity() {
        let dedup = DedupConfig {
            bloom_capacity: 0,
            ..DedupConfig::default()
        };
        assert!(validate_dedup_config(&dedup).is_err());
    }

    #[test]
    fn dedup_rejects_zero_lru_capacity() {
        let dedup = DedupConfig {
            lru_capacity: 0,
            ..DedupConfig::default()
        };
        assert!(validate_dedup_config(&dedup).is_err());
    }

    #[test]
    fn dedup_rejects_fp_rate_out_of_bounds() {
        for &rate in &[0.0, 1.0, -0.1, f64::NAN, f64::INFINITY] {
            let dedup = DedupConfig {
                bloom_false_positive_rate: rate,
                ..DedupConfig::default()
            };
            assert!(validate_dedup_config(&dedup).is_err(), "rate {rate} should fail");
        }
    }

    #[test]
    fn dedup_accepts_valid_fp_rate() {
        for &rate in &[0.001, 0.01, 0.5, 0.999] {
            let dedup = DedupConfig {
                bloom_false_positive_rate: rate,
                ..DedupConfig::default()
            };
            assert!(validate_dedup_config(&dedup).is_ok(), "rate {rate} should pass");
        }
    }

    #[test]
    fn parse_empty_config() {
        let parsed = parse_config("", Path::new("test.toml"));
        assert!(parsed.is_ok());
        let cfg = parsed.unwrap();
        assert!(cfg.listen.is_none());
        assert!(cfg.profile_id.is_none());
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
listen = "0.0.0.0:9999"
profile_id = "test-hub"

[tooling]
enabled = true

[anchor]
enabled = false
backend = "file"

[observability]
enable_metrics = true
enable_logs = false

[dedup]
bloom_capacity = 50000
bloom_false_positive_rate = 0.001
lru_capacity = 8192

[admission]
capability_gating_enabled = false
max_client_id_lifetime_sec = 3600
max_msgs_per_client_id_per_label = 100
pow_difficulty = 16

[federation]
replica_targets = ["https://replica1.example.com"]
"#;
        let cfg = parse_config(toml, Path::new("test.toml")).unwrap();
        assert_eq!(cfg.listen.unwrap().port(), 9999);
        assert_eq!(cfg.profile_id.as_deref(), Some("test-hub"));
        assert_eq!(cfg.tooling.enabled, Some(true));
        assert_eq!(cfg.anchor.enabled, Some(false));
        assert_eq!(cfg.anchor.backend.as_deref(), Some("file"));
        assert_eq!(cfg.observability.enable_metrics, Some(true));
        assert_eq!(cfg.observability.enable_logs, Some(false));
        assert_eq!(cfg.dedup.bloom_capacity, Some(50000));
        assert_eq!(cfg.admission.pow_difficulty, Some(16));
        assert_eq!(cfg.federation.replica_targets.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn parse_rejects_invalid_toml() {
        let result = parse_config("listen = not_valid", Path::new("bad.toml"));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn from_sources_defaults_without_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = HubRuntimeConfig::from_sources(
            default_listen(),
            dir.path().to_path_buf(),
            None,
            HubRole::Primary,
            HubConfigOverrides::default(),
        )
        .await
        .unwrap();
        assert_eq!(cfg.listen, default_listen());
        assert!(cfg.anchors.enabled);
        assert!(cfg.observability.enable_metrics);
        assert!(cfg.admission.capability_gating_enabled);
        assert!(!cfg.tooling_enabled);
    }

    #[tokio::test]
    async fn from_sources_overrides_take_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let overrides = HubConfigOverrides {
            tooling_enabled: Some(true),
            anchors_enabled: Some(false),
            bloom_capacity: Some(999),
            ..Default::default()
        };
        let cfg = HubRuntimeConfig::from_sources(
            default_listen(),
            dir.path().to_path_buf(),
            None,
            HubRole::Primary,
            overrides,
        )
        .await
        .unwrap();
        assert!(cfg.tooling_enabled);
        assert!(!cfg.anchors.enabled);
        assert_eq!(cfg.dedup.bloom_capacity, 999);
    }

    #[tokio::test]
    async fn from_sources_replica_requires_targets() {
        let dir = tempfile::tempdir().unwrap();
        let result = HubRuntimeConfig::from_sources(
            default_listen(),
            dir.path().to_path_buf(),
            None,
            HubRole::Replica,
            HubConfigOverrides::default(),
        )
        .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("replica target"));
    }

    #[tokio::test]
    async fn from_sources_with_toml_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("hub.toml");
        tokio::fs::write(&config_path, "profile_id = \"file-profile\"\n")
            .await
            .unwrap();
        let cfg = HubRuntimeConfig::from_sources(
            default_listen(),
            dir.path().to_path_buf(),
            Some(config_path),
            HubRole::Primary,
            HubConfigOverrides::default(),
        )
        .await
        .unwrap();
        assert_eq!(cfg.profile_id.as_deref(), Some("file-profile"));
    }
}
