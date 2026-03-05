use super::*;

#[derive(Subcommand)]
pub(crate) enum HubCommand {
    /// Start the VEEN hub runtime.
    Start(HubStartArgs),
    /// Stop a running VEEN hub instance.
    Stop(HubStopArgs),
    /// Fetch high level status from a hub (non-core tooling endpoints).
    Status(HubStatusArgs),
    /// Fetch the hub's public key information.
    Key(HubKeyArgs),
    /// Verify rotation witnesses between hub keys.
    #[command(name = "verify-rotation")]
    VerifyRotation(HubVerifyRotationArgs),
    /// Fetch hub health information (non-core tooling endpoint).
    Health(HubHealthArgs),
    /// Fetch hub metrics (non-core tooling endpoint).
    Metrics(HubMetricsArgs),
    /// Fetch hub capability profile details (non-core tooling endpoint).
    Profile(HubProfileArgs),
    /// Inspect hub role information (non-core tooling endpoint).
    Role(HubRoleArgs),
    /// Inspect hub key and capability lifecycle policy (non-core tooling endpoint).
    #[command(name = "kex-policy")]
    KexPolicy(HubKexPolicyArgs),
    /// Inspect TLS configuration for a hub endpoint (non-core tooling endpoint).
    #[command(name = "tls-info")]
    TlsInfo(HubTlsInfoArgs),
    /// Inspect admission pipeline configuration and metrics (non-core tooling endpoint).
    Admission(HubAdmissionArgs),
    /// Inspect recent admission failures (non-core tooling endpoint).
    #[command(name = "admission-log")]
    AdmissionLog(HubAdmissionLogArgs),
    /// Fetch the latest checkpoint from a hub (non-core tooling endpoint).
    #[command(name = "checkpoint-latest")]
    CheckpointLatest(HubCheckpointLatestArgs),
    /// Fetch checkpoints within an epoch range from a hub (non-core tooling endpoint).
    #[command(name = "checkpoint-range")]
    CheckpointRange(HubCheckpointRangeArgs),
}

#[derive(Subcommand)]
pub(crate) enum HubTlsCommand {
    /// Inspect TLS configuration for a hub endpoint.
    #[command(name = "tls-info")]
    TlsInfo(HubTlsInfoArgs),
}

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum HubLogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl fmt::Display for HubLogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let level = match self {
            HubLogLevel::Debug => "debug",
            HubLogLevel::Info => "info",
            HubLogLevel::Warn => "warn",
            HubLogLevel::Error => "error",
        };
        f.write_str(level)
    }
}

#[derive(Args, Clone)]
pub(crate) struct HubStartArgs {
    /// Listen address for the hub HTTP API (for example: 127.0.0.1:8080).
    #[arg(long, value_parser = clap::value_parser!(SocketAddr))]
    pub(crate) listen: SocketAddr,
    /// Data directory for hub runtime state and append-only storage.
    #[arg(long)]
    pub(crate) data_dir: PathBuf,
    /// Optional path to a hub configuration file.
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,
    /// Override profile identifier (64 hex characters).
    #[arg(long, value_name = "HEX32")]
    pub(crate) profile_id: Option<String>,
    /// Run in the foreground instead of daemonizing.
    #[arg(long)]
    pub(crate) foreground: bool,
    /// Hub log verbosity level.
    #[arg(long, value_enum, value_name = "LEVEL")]
    pub(crate) log_level: Option<HubLogLevel>,
    /// Require proof-of-work from clients before accepting submissions.
    #[arg(long, value_name = "BITS")]
    pub(crate) pow_difficulty: Option<u8>,
    /// Enable non-core tooling endpoints (health, metrics, admission helpers).
    #[arg(long = "enable-tooling")]
    pub(crate) enable_tooling: bool,
}

#[derive(Args)]
pub(crate) struct HubStopArgs {
    /// Data directory used by the running hub instance.
    #[arg(long)]
    pub(crate) data_dir: PathBuf,
}

#[derive(Args)]
pub(crate) struct HubStatusArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
}

#[derive(Args)]
pub(crate) struct HubKeyArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
}

#[derive(Args)]
pub(crate) struct HubVerifyRotationArgs {
    /// Checkpoint file containing witness signatures.
    #[arg(long)]
    pub(crate) checkpoint: PathBuf,
    /// Previous hub key (64 hex characters).
    #[arg(long, value_name = "OLD_HEX32")]
    pub(crate) old_key: String,
    /// Replacement hub key (64 hex characters).
    #[arg(long, value_name = "NEW_HEX32")]
    pub(crate) new_key: String,
}

#[derive(Args)]
pub(crate) struct HubHealthArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    /// Emit machine-readable JSON output.
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct HubMetricsArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    /// Print raw histogram distributions instead of summary metrics.
    #[arg(long)]
    pub(crate) raw: bool,
}

#[derive(Args)]
pub(crate) struct HubProfileArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    /// Emit machine-readable JSON output.
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct HubRoleArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    /// Filter role lookup by realm identifier (64 hex characters).
    #[arg(long, value_name = "HEX32")]
    pub(crate) realm: Option<String>,
    /// Filter role lookup by stream name.
    #[arg(long)]
    pub(crate) stream: Option<String>,
    /// Emit machine-readable JSON output.
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct HubKexPolicyArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    /// Emit machine-readable JSON output.
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct HubAdmissionArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    /// Emit machine-readable JSON output.
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct HubAdmissionLogArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    /// Maximum number of admission events to return.
    #[arg(long)]
    pub(crate) limit: Option<u64>,
    /// Comma-separated error codes to include.
    #[arg(long)]
    pub(crate) codes: Option<String>,
    /// Emit machine-readable JSON output.
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct HubCheckpointLatestArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
}

#[derive(Args)]
pub(crate) struct HubCheckpointRangeArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    /// Start epoch (inclusive).
    #[arg(long, value_name = "EPOCH")]
    pub(crate) from_epoch: Option<u64>,
    /// End epoch (inclusive).
    #[arg(long, value_name = "EPOCH")]
    pub(crate) to_epoch: Option<u64>,
}

#[derive(Args)]
pub(crate) struct HubTlsInfoArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
}
