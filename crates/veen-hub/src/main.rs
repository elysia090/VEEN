use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use tokio::signal;
use tracing_subscriber::EnvFilter;

use veen_hub::runtime::HubRuntime;
use veen_hub::runtime::{HubConfigOverrides, HubRole, HubRuntimeConfig};

#[derive(Parser)]
#[command(name = "veen-hub", version, about = "Run the VEEN hub runtime", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the VEEN hub service.
    Run(RunCommand),
}

#[derive(Args, Debug)]
struct RunCommand {
    /// Socket address to listen on for hub HTTP APIs.
    #[arg(long, value_parser = clap::value_parser!(SocketAddr))]
    listen: SocketAddr,
    /// Directory for persisting hub state.
    #[arg(long)]
    data_dir: PathBuf,
    /// Optional path to a configuration file describing the runtime overlays.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Optional profile_id to enforce for admitted messages (hex-encoded 32 bytes).
    #[arg(long = "profile-id", value_parser = parse_profile_id)]
    profile_id: Option<String>,
    /// Role to run the hub as.
    #[arg(long, value_enum, default_value_t = HubRoleArg::Primary)]
    role: HubRoleArg,
    /// Disable anchoring regardless of configuration files.
    #[arg(long = "disable-anchors")]
    disable_anchors: bool,
    /// Disable capability gating checks for submit requests.
    #[arg(long = "disable-capability-gating")]
    disable_capability_gating: bool,
    /// Anchor backend identifier to use (e.g. "file" or "dummy").
    #[arg(long = "anchor-backend", conflicts_with = "disable_anchors")]
    anchor_backend: Option<String>,
    /// Disable exporting Prometheus metrics.
    #[arg(long = "disable-metrics")]
    disable_metrics: bool,
    /// Disable structured log emission.
    #[arg(long = "disable-logs")]
    disable_logs: bool,
    /// Enable non-core tooling endpoints (health, metrics, admission helpers).
    #[arg(long = "enable-tooling")]
    enable_tooling: bool,
    /// Maximum lifetime in seconds for any observed client_id before rotation is required.
    #[arg(long = "max-client-id-lifetime-sec")]
    max_client_id_lifetime_sec: Option<u64>,
    /// Maximum number of messages a client_id may send per label before rotation is required.
    #[arg(long = "max-msgs-per-client-id-per-label")]
    max_msgs_per_client_id_per_label: Option<u64>,
    /// Upstream primary hubs that this replica should follow.
    #[arg(long = "replica-target", value_name = "URL")]
    replica_targets: Vec<String>,
    /// Require submitters to present a proof-of-work cookie meeting this difficulty.
    #[arg(long = "pow-difficulty")]
    pow_difficulty: Option<u8>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum HubRoleArg {
    Primary,
    Replica,
}

impl From<HubRoleArg> for HubRole {
    fn from(value: HubRoleArg) -> Self {
        match value {
            HubRoleArg::Primary => HubRole::Primary,
            HubRoleArg::Replica => HubRole::Replica,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(cmd) => run_hub(cmd).await,
    }
}

fn init_tracing() {
    let subscriber = tracing_subscriber::fmt().with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    );
    let _ = subscriber.try_init();
}

async fn run_hub(cmd: RunCommand) -> Result<()> {
    cmd.validate()?;
    let overrides = cmd.as_config_overrides();

    let runtime_config = HubRuntimeConfig::from_sources(
        cmd.listen,
        cmd.data_dir,
        cmd.config,
        cmd.role.into(),
        overrides,
    )
    .await?;
    tracing::info!(
        listen = %runtime_config.listen,
        data_dir = %runtime_config.data_dir.display(),
        "initialising VEEN hub runtime"
    );

    let runtime = HubRuntime::start(runtime_config).await?;
    println!("VEEN hub listening on {}", runtime.listen_addr());
    println!("data_dir: {}", runtime.data_dir().display());
    println!("press Ctrl+C to stop the hub");

    signal::ctrl_c().await?;

    tracing::info!("shutdown signal received; flushing hub storage");
    runtime.shutdown().await?;
    tracing::info!("hub runtime stopped cleanly");
    println!("VEEN hub stopped cleanly");

    Ok(())
}

impl RunCommand {
    fn validate(&self) -> Result<()> {
        if matches!(self.role, HubRoleArg::Replica)
            && self.replica_targets.is_empty()
            && self.config.is_none()
        {
            bail!("replica role requires at least one --replica-target or configuration file");
        }
        Ok(())
    }

    fn as_config_overrides(&self) -> HubConfigOverrides {
        HubConfigOverrides {
            profile_id: self.profile_id.clone(),
            anchors_enabled: self.disable_anchors.then_some(false),
            anchor_backend: self.anchor_backend.clone(),
            enable_metrics: self.disable_metrics.then_some(false),
            enable_logs: self.disable_logs.then_some(false),
            tooling_enabled: self.enable_tooling.then_some(true),
            bloom_capacity: None,
            bloom_false_positive_rate: None,
            lru_capacity: None,
            capability_gating_enabled: self.disable_capability_gating.then_some(false),
            max_client_id_lifetime_sec: self.max_client_id_lifetime_sec,
            max_msgs_per_client_id_per_label: self.max_msgs_per_client_id_per_label,
            replica_targets: if self.replica_targets.is_empty() {
                None
            } else {
                Some(self.replica_targets.clone())
            },
            pow_difficulty: self.pow_difficulty,
        }
    }
}

fn parse_profile_id(raw: &str) -> Result<String, String> {
    if raw.len() != 64 {
        return Err("profile-id must be 64 hexadecimal characters".into());
    }
    if hex::decode(raw).is_err() {
        return Err("profile-id must be valid hexadecimal".into());
    }
    Ok(raw.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempfile::tempdir;

    #[test]
    fn replica_without_targets_is_rejected() {
        let temp = tempdir().unwrap();
        let args = [
            "veen-hub",
            "run",
            "--listen",
            "127.0.0.1:9000",
            "--data-dir",
            temp.path().to_str().unwrap(),
            "--role",
            "replica",
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        let Commands::Run(cmd) = cli.command;
        let err = cmd.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("replica role requires at least one --replica-target"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn replica_with_target_is_accepted() {
        let temp = tempdir().unwrap();
        let args = [
            "veen-hub",
            "run",
            "--listen",
            "127.0.0.1:9000",
            "--data-dir",
            temp.path().to_str().unwrap(),
            "--role",
            "replica",
            "--replica-target",
            "http://127.0.0.1:8080",
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        let Commands::Run(cmd) = cli.command;
        cmd.validate().unwrap();
    }

    #[test]
    fn profile_id_parser_rejects_invalid_length() {
        let err = parse_profile_id("abc").unwrap_err();
        assert!(err.contains("64"));
    }

    #[test]
    fn profile_id_parser_accepts_hex() {
        let value = "aa".repeat(32);
        let parsed = parse_profile_id(&value).unwrap();
        assert_eq!(parsed, value);
    }
}
