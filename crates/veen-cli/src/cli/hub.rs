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
    #[arg(long, value_parser = clap::value_parser!(SocketAddr))]
    listen: SocketAddr,
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, value_name = "HEX32")]
    profile_id: Option<String>,
    #[arg(long)]
    foreground: bool,
    #[arg(long, value_enum, value_name = "LEVEL")]
    log_level: Option<HubLogLevel>,
    /// Require proof-of-work from clients before accepting submissions.
    #[arg(long, value_name = "BITS")]
    pow_difficulty: Option<u8>,
    /// Enable non-core tooling endpoints (health, metrics, admission helpers).
    #[arg(long = "enable-tooling")]
    enable_tooling: bool,
}

#[derive(Args)]
pub(crate) struct HubStopArgs {
    #[arg(long)]
    data_dir: PathBuf,
}

#[derive(Args)]
pub(crate) struct HubStatusArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
}

#[derive(Args)]
pub(crate) struct HubKeyArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
}

#[derive(Args)]
pub(crate) struct HubVerifyRotationArgs {
    #[arg(long)]
    checkpoint: PathBuf,
    #[arg(long, value_name = "OLD_HEX32")]
    old_key: String,
    #[arg(long, value_name = "NEW_HEX32")]
    new_key: String,
}

#[derive(Args)]
pub(crate) struct HubHealthArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub(crate) struct HubMetricsArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    raw: bool,
}

#[derive(Args)]
pub(crate) struct HubProfileArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub(crate) struct HubRoleArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long, value_name = "HEX32")]
    realm: Option<String>,
    #[arg(long)]
    stream: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub(crate) struct HubKexPolicyArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub(crate) struct HubAdmissionArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub(crate) struct HubAdmissionLogArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    limit: Option<u64>,
    #[arg(long)]
    codes: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub(crate) struct HubCheckpointLatestArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
}

#[derive(Args)]
pub(crate) struct HubCheckpointRangeArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long, value_name = "EPOCH")]
    from_epoch: Option<u64>,
    #[arg(long, value_name = "EPOCH")]
    to_epoch: Option<u64>,
}

#[derive(Args)]
pub(crate) struct HubTlsInfoArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
}
