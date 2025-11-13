use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::json;
use tokio::{fs, signal};
use tracing_subscriber::EnvFilter;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use veen_core::{
    hub::HubId,
    wire::{checkpoint::CHECKPOINT_VERSION, Checkpoint},
    Profile,
};

const CLIENT_KEY_VERSION: u8 = 1;
const CLIENT_STATE_VERSION: u8 = 1;
const HUB_STATE_VERSION: u8 = 1;
const HUB_KEY_VERSION: u8 = 1;

const HUB_STATE_FILE: &str = "hub_state.json";
const HUB_KEY_FILE: &str = "hub_key.cbor";
const HUB_PID_FILE: &str = "hub.pid";
const RECEIPTS_FILE: &str = "receipts.cborseq";
const PAYLOADS_FILE: &str = "payloads.cborseq";
const CHECKPOINTS_FILE: &str = "checkpoints.cborseq";
const ANCHORS_DIR: &str = "anchors";
const STATE_DIR: &str = "state";

#[derive(Parser)]
#[command(
    name = "veen",
    version,
    about = "VEEN v0.0.1 command line interface",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Hub lifecycle and observability commands.
    #[command(subcommand)]
    Hub(HubCommand),
    /// Generate a new VEEN client identity bundle.
    Keygen(KeygenArgs),
    /// Inspect or rotate client identity material.
    #[command(subcommand)]
    Id(IdCommand),
    /// Send an encrypted message to a stream.
    Send(SendArgs),
    /// Stream and decrypt messages from the hub.
    Stream(StreamArgs),
    /// Attachment tooling.
    #[command(subcommand)]
    Attachment(AttachmentCommand),
    /// Capability management.
    #[command(subcommand)]
    Cap(CapCommand),
    /// Resynchronise durable state from the hub.
    Resync(ResyncArgs),
    /// Verify local state against hub checkpoints.
    #[command(name = "verify-state")]
    VerifyState(VerifyStateArgs),
    /// Explain VEEN error codes.
    #[command(name = "explain-error")]
    ExplainError(ExplainErrorArgs),
    /// RPC overlay helpers.
    #[command(subcommand)]
    Rpc(RpcCommand),
    /// CRDT overlay helpers.
    #[command(subcommand)]
    Crdt(CrdtCommand),
    /// Anchor inspection helpers.
    #[command(subcommand)]
    Anchor(AnchorCommand),
    /// Retention inspection commands.
    #[command(subcommand)]
    Retention(RetentionCommand),
    /// TLS hardening and verification.
    #[command(subcommand)]
    HubTls(HubTlsCommand),
    /// Run VEEN self-test suites.
    #[command(subcommand)]
    Selftest(SelftestCommand),
}

#[derive(Subcommand)]
enum HubCommand {
    /// Start the VEEN hub runtime.
    Start(HubStartArgs),
    /// Stop a running VEEN hub instance.
    Stop(HubStopArgs),
    /// Fetch high level status from a hub.
    Status(HubStatusArgs),
    /// Fetch the hub's public key information.
    Key(HubKeyArgs),
    /// Verify rotation witnesses between hub keys.
    #[command(name = "verify-rotation")]
    VerifyRotation(HubVerifyRotationArgs),
    /// Fetch hub health information.
    Health(HubHealthArgs),
    /// Fetch hub metrics.
    Metrics(HubMetricsArgs),
}

#[derive(Subcommand)]
enum HubTlsCommand {
    /// Inspect TLS configuration for a hub endpoint.
    #[command(name = "tls-info")]
    TlsInfo(HubTlsInfoArgs),
}

#[derive(Subcommand)]
enum IdCommand {
    /// Show a client identity summary.
    Show(IdShowArgs),
    /// Rotate the client identifier key material.
    Rotate(IdRotateArgs),
}

#[derive(Subcommand)]
enum AttachmentCommand {
    /// Verify an attachment against a stored message bundle.
    Verify(AttachmentVerifyArgs),
}

#[derive(Subcommand)]
enum CapCommand {
    /// Issue a capability token.
    Issue(CapIssueArgs),
    /// Authorise a capability token with the hub.
    Authorize(CapAuthorizeArgs),
}

#[derive(Subcommand)]
enum RpcCommand {
    /// Invoke an RPC method through VEEN messaging flows.
    Call(RpcCallArgs),
}

#[derive(Subcommand)]
enum CrdtCommand {
    /// LWW register helpers.
    #[command(subcommand)]
    Lww(CrdtLwwCommand),
    /// OR-set helpers.
    #[command(subcommand)]
    Orset(CrdtOrsetCommand),
    /// Grow-only counter helpers.
    #[command(subcommand)]
    Counter(CrdtCounterCommand),
}

#[derive(Subcommand)]
enum CrdtLwwCommand {
    /// Update a key within an LWW register.
    Set(CrdtLwwSetArgs),
    /// Fetch the current value from an LWW register.
    Get(CrdtLwwGetArgs),
}

#[derive(Subcommand)]
enum CrdtOrsetCommand {
    /// Add an element to an OR-set.
    Add(CrdtOrsetAddArgs),
    /// Remove an element from an OR-set.
    Remove(CrdtOrsetRemoveArgs),
    /// List the contents of an OR-set.
    List(CrdtOrsetListArgs),
}

#[derive(Subcommand)]
enum CrdtCounterCommand {
    /// Add a delta to a grow-only counter.
    Add(CrdtCounterAddArgs),
    /// Fetch the value of a grow-only counter.
    Get(CrdtCounterGetArgs),
}

#[derive(Subcommand)]
enum AnchorCommand {
    /// Request that the hub publishes an anchor for a stream.
    Publish(AnchorPublishArgs),
    /// Verify a checkpoint anchor reference.
    Verify(AnchorVerifyArgs),
}

#[derive(Subcommand)]
enum RetentionCommand {
    /// Show configured on-disk retention for a hub data directory.
    Show(RetentionShowArgs),
}

#[derive(Subcommand)]
enum SelftestCommand {
    /// Run the VEEN core self-test suite.
    Core,
    /// Run property-based tests.
    Props,
    /// Run fuzz tests against VEEN wire objects.
    Fuzz,
    /// Run the full test suite (core + props + fuzz).
    All,
}

#[derive(ValueEnum, Clone, Debug)]
enum HubLogLevel {
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

#[derive(Args)]
struct HubStartArgs {
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
}

#[derive(Args)]
struct HubStopArgs {
    #[arg(long)]
    data_dir: PathBuf,
}

#[derive(Args)]
struct HubStatusArgs {
    #[arg(long)]
    hub: String,
}

#[derive(Args)]
struct HubKeyArgs {
    #[arg(long)]
    hub: String,
}

#[derive(Args)]
struct HubVerifyRotationArgs {
    #[arg(long)]
    checkpoint: PathBuf,
    #[arg(long, value_name = "OLD_HEX32")]
    old_key: String,
    #[arg(long, value_name = "NEW_HEX32")]
    new_key: String,
}

#[derive(Args)]
struct HubHealthArgs {
    #[arg(long)]
    hub: String,
}

#[derive(Args)]
struct HubMetricsArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    raw: bool,
}

#[derive(Args)]
struct HubTlsInfoArgs {
    #[arg(long)]
    hub: String,
}

#[derive(Args)]
struct KeygenArgs {
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct IdShowArgs {
    #[arg(long)]
    client: PathBuf,
}

#[derive(Args)]
struct IdRotateArgs {
    #[arg(long)]
    client: PathBuf,
}

#[derive(Args)]
struct SendArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    body: String,
    #[arg(long, value_name = "HEX32")]
    schema: Option<String>,
    #[arg(long, value_name = "UNIX_TS")]
    expires_at: Option<u64>,
    #[arg(long)]
    cap: Option<PathBuf>,
    #[arg(long)]
    parent: Option<String>,
    #[arg(long)]
    attach: Vec<PathBuf>,
    #[arg(long)]
    no_store_body: bool,
}

#[derive(Args)]
struct StreamArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long, default_value_t = 0)]
    from: u64,
    #[arg(long)]
    with_proof: bool,
}

#[derive(Args)]
struct AttachmentVerifyArgs {
    #[arg(long)]
    msg: PathBuf,
    #[arg(long)]
    file: PathBuf,
    #[arg(long)]
    index: u64,
}

#[derive(Args)]
struct CapIssueArgs {
    #[arg(long)]
    issuer: PathBuf,
    #[arg(long)]
    subject: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    ttl: u64,
    #[arg(long)]
    rate: Option<String>,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct CapAuthorizeArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    cap: PathBuf,
}

#[derive(Args)]
struct ResyncArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
}

#[derive(Args)]
struct VerifyStateArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
}

#[derive(Args)]
struct ExplainErrorArgs {
    #[arg(value_name = "CODE")]
    code: String,
}

#[derive(Args)]
struct RpcCallArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    method: String,
    #[arg(long)]
    args: String,
    #[arg(long, value_name = "MS")]
    timeout_ms: Option<u64>,
    #[arg(long)]
    idem: Option<u64>,
}

#[derive(Args)]
struct CrdtLwwSetArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    key: String,
    #[arg(long)]
    value: String,
    #[arg(long)]
    ts: Option<u64>,
}

#[derive(Args)]
struct CrdtLwwGetArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    key: String,
}

#[derive(Args)]
struct CrdtOrsetAddArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    elem: String,
}

#[derive(Args)]
struct CrdtOrsetRemoveArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    elem: String,
}

#[derive(Args)]
struct CrdtOrsetListArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
}

#[derive(Args)]
struct CrdtCounterAddArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    delta: u64,
}

#[derive(Args)]
struct CrdtCounterGetArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
}

#[derive(Args)]
struct AnchorPublishArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    epoch: Option<u64>,
    #[arg(long)]
    ts: Option<u64>,
    #[arg(long, value_name = "HEX")]
    nonce: Option<String>,
}

#[derive(Args)]
struct AnchorVerifyArgs {
    #[arg(long)]
    checkpoint: PathBuf,
}

#[derive(Args)]
struct RetentionShowArgs {
    #[arg(long)]
    data_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HubRuntimeState {
    version: u8,
    data_dir: String,
    listen: Option<String>,
    profile_id: Option<String>,
    hub_id: Option<String>,
    log_level: Option<String>,
    started_at: Option<u64>,
    stopped_at: Option<u64>,
    uptime_accum: u64,
    running: bool,
    peaks_count: u64,
    last_stream_seq: BTreeMap<String, u64>,
    pid: Option<u32>,
    last_started_foreground: bool,
    metrics: HubMetricsSnapshot,
}

struct HubStartContext<'a> {
    data_dir: &'a Path,
    listen: SocketAddr,
    profile_id: String,
    hub_id: String,
    log_level: Option<String>,
    now: u64,
    pid: u32,
    foreground: bool,
}

impl Default for HubRuntimeState {
    fn default() -> Self {
        Self {
            version: HUB_STATE_VERSION,
            data_dir: String::new(),
            listen: None,
            profile_id: None,
            hub_id: None,
            log_level: None,
            started_at: None,
            stopped_at: None,
            uptime_accum: 0,
            running: false,
            peaks_count: 0,
            last_stream_seq: BTreeMap::new(),
            pid: None,
            last_started_foreground: false,
            metrics: HubMetricsSnapshot::default(),
        }
    }
}

impl HubRuntimeState {
    fn new(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_string_lossy().into_owned(),
            ..Self::default()
        }
    }

    fn record_start(&mut self, ctx: HubStartContext<'_>) -> Result<()> {
        let HubStartContext {
            data_dir,
            listen,
            profile_id,
            hub_id,
            log_level,
            now,
            pid,
            foreground,
        } = ctx;
        if self.running {
            bail!("hub in {} is already marked as running", data_dir.display());
        }

        self.data_dir = data_dir.to_string_lossy().into_owned();
        self.listen = Some(listen.to_string());
        self.profile_id = Some(profile_id);
        self.hub_id = Some(hub_id);
        self.log_level = log_level;
        self.started_at = Some(now);
        self.stopped_at = None;
        self.running = true;
        self.pid = Some(pid);
        self.last_started_foreground = foreground;
        Ok(())
    }

    fn record_stop(&mut self, stop_ts: u64) {
        if self.running {
            if let Some(started_at) = self.started_at {
                self.uptime_accum = self
                    .uptime_accum
                    .saturating_add(stop_ts.saturating_sub(started_at));
            }
        }
        self.running = false;
        self.pid = None;
        self.started_at = None;
        self.stopped_at = Some(stop_ts);
    }

    fn uptime(&self, now: u64) -> u64 {
        if self.running {
            if let Some(started_at) = self.started_at {
                return self
                    .uptime_accum
                    .saturating_add(now.saturating_sub(started_at));
            }
        }
        self.uptime_accum
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct HubMetricsSnapshot {
    submit_ok_total: u64,
    submit_err_total: BTreeMap<String, u64>,
    verify_latency_ms: HistogramSnapshot,
    commit_latency_ms: HistogramSnapshot,
    end_to_end_latency_ms: HistogramSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HistogramSnapshot {
    count: u64,
    sum: f64,
    min: Option<f64>,
    max: Option<f64>,
}

impl Default for HistogramSnapshot {
    fn default() -> Self {
        Self {
            count: 0,
            sum: 0.0,
            min: None,
            max: None,
        }
    }
}

impl HistogramSnapshot {
    fn average(&self) -> Option<f64> {
        if self.count == 0 {
            None
        } else {
            Some(self.sum / self.count as f64)
        }
    }
}

#[derive(Debug, Clone)]
struct HubKeyInfo {
    hub_id_hex: String,
    public_key_hex: String,
    created_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct HubKeyMaterial {
    version: u8,
    created_at: u64,
    #[serde(with = "serde_bytes")]
    public_key: ByteBuf,
    #[serde(with = "serde_bytes")]
    secret_key: ByteBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct ClientSecretBundle {
    version: u8,
    created_at: u64,
    #[serde(with = "serde_bytes")]
    client_id: ByteBuf,
    #[serde(with = "serde_bytes")]
    dh_public: ByteBuf,
    #[serde(with = "serde_bytes")]
    signing_key: ByteBuf,
    #[serde(with = "serde_bytes")]
    dh_secret: ByteBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct ClientPublicBundle {
    version: u8,
    created_at: u64,
    #[serde(with = "serde_bytes")]
    client_id: ByteBuf,
    #[serde(with = "serde_bytes")]
    dh_public: ByteBuf,
}

#[derive(Serialize, Deserialize)]
struct ClientStateFile {
    version: u8,
    profile_id: Option<String>,
    hubs: Vec<ClientStateHubPin>,
    labels: BTreeMap<String, ClientLabelState>,
    #[serde(default)]
    rotation_history: Vec<ClientRotationRecord>,
}

#[derive(Serialize, Deserialize)]
struct ClientStateHubPin {
    hub: String,
    profile_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ClientLabelState {
    last_stream_seq: u64,
    last_mmr_root: String,
    prev_ack: u64,
}

#[derive(Serialize, Deserialize)]
struct ClientRotationRecord {
    rotated_at: u64,
    previous_client_id: String,
    previous_dh_public: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Command::Hub(cmd) => match cmd {
            HubCommand::Start(args) => handle_hub_start(args).await,
            HubCommand::Stop(args) => handle_hub_stop(args).await,
            HubCommand::Status(args) => handle_hub_status(args).await,
            HubCommand::Key(args) => handle_hub_key(args).await,
            HubCommand::VerifyRotation(args) => handle_hub_verify_rotation(args).await,
            HubCommand::Health(args) => handle_hub_health(args).await,
            HubCommand::Metrics(args) => handle_hub_metrics(args).await,
        },
        Command::Keygen(args) => handle_keygen(args).await,
        Command::Id(cmd) => match cmd {
            IdCommand::Show(args) => handle_id_show(args).await,
            IdCommand::Rotate(args) => handle_id_rotate(args).await,
        },
        Command::Send(args) => handle_send(args).await,
        Command::Stream(args) => handle_stream(args).await,
        Command::Attachment(cmd) => match cmd {
            AttachmentCommand::Verify(args) => handle_attachment_verify(args).await,
        },
        Command::Cap(cmd) => match cmd {
            CapCommand::Issue(args) => handle_cap_issue(args).await,
            CapCommand::Authorize(args) => handle_cap_authorize(args).await,
        },
        Command::Resync(args) => handle_resync(args).await,
        Command::VerifyState(args) => handle_verify_state(args).await,
        Command::ExplainError(args) => handle_explain_error(args).await,
        Command::Rpc(cmd) => match cmd {
            RpcCommand::Call(args) => handle_rpc_call(args).await,
        },
        Command::Crdt(cmd) => match cmd {
            CrdtCommand::Lww(sub) => match sub {
                CrdtLwwCommand::Set(args) => handle_crdt_lww_set(args).await,
                CrdtLwwCommand::Get(args) => handle_crdt_lww_get(args).await,
            },
            CrdtCommand::Orset(sub) => match sub {
                CrdtOrsetCommand::Add(args) => handle_crdt_orset_add(args).await,
                CrdtOrsetCommand::Remove(args) => handle_crdt_orset_remove(args).await,
                CrdtOrsetCommand::List(args) => handle_crdt_orset_list(args).await,
            },
            CrdtCommand::Counter(sub) => match sub {
                CrdtCounterCommand::Add(args) => handle_crdt_counter_add(args).await,
                CrdtCounterCommand::Get(args) => handle_crdt_counter_get(args).await,
            },
        },
        Command::Anchor(cmd) => match cmd {
            AnchorCommand::Publish(args) => handle_anchor_publish(args).await,
            AnchorCommand::Verify(args) => handle_anchor_verify(args).await,
        },
        Command::Retention(cmd) => match cmd {
            RetentionCommand::Show(args) => handle_retention_show(args).await,
        },
        Command::HubTls(cmd) => match cmd {
            HubTlsCommand::TlsInfo(args) => handle_hub_tls_info(args).await,
        },
        Command::Selftest(cmd) => match cmd {
            SelftestCommand::Core => handle_selftest_core().await,
            SelftestCommand::Props => handle_selftest_props().await,
            SelftestCommand::Fuzz => handle_selftest_fuzz().await,
            SelftestCommand::All => handle_selftest_all().await,
        },
    }
}

fn init_tracing() {
    let subscriber = tracing_subscriber::fmt().with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    );
    let _ = subscriber.try_init();
}

async fn handle_hub_start(args: HubStartArgs) -> Result<()> {
    if let Some(ref config) = args.config {
        if !fs::try_exists(config)
            .await
            .with_context(|| format!("checking config {}", config.display()))?
        {
            bail!("config file {} does not exist", config.display());
        }
    }

    ensure_data_dir_layout(&args.data_dir).await?;

    let profile_id = resolve_profile_id(args.profile_id)?;
    let log_level = args.log_level.as_ref().map(ToString::to_string);

    let key_info = ensure_hub_key_material(&args.data_dir).await?;

    let mut state = load_hub_state(&args.data_dir).await?;
    let now = current_unix_timestamp()?;
    state
        .record_start(HubStartContext {
            data_dir: &args.data_dir,
            listen: args.listen,
            profile_id: profile_id.clone(),
            hub_id: key_info.hub_id_hex.clone(),
            log_level: log_level.clone(),
            now,
            pid: process::id(),
            foreground: args.foreground,
        })
        .with_context(|| format!("updating hub state in {}", args.data_dir.display()))?;

    save_hub_state(&args.data_dir, &state).await?;
    write_pid_file(&args.data_dir, process::id()).await?;

    tracing::info!(
        listen = %args.listen,
        data_dir = %args.data_dir.display(),
        profile_id,
        hub_id = %key_info.hub_id_hex,
        "started VEEN hub metadata runtime"
    );

    println!("hub_id: {}", key_info.hub_id_hex);
    println!("listen: {}", args.listen);
    println!("profile_id: {}", profile_id);
    println!("data_dir: {}", args.data_dir.display());
    if let Some(level) = log_level {
        println!("log_level: {level}");
    }

    if args.foreground {
        println!("running hub in foreground; press Ctrl+C to stop");
        signal::ctrl_c()
            .await
            .context("waiting for Ctrl+C to stop the hub")?;
        println!("received Ctrl+C; stopping hub");
        let stop_ts = current_unix_timestamp()?;
        state.record_stop(stop_ts);
        save_hub_state(&args.data_dir, &state).await?;
        remove_pid_file(&args.data_dir).await?;
        println!("hub stopped at {stop_ts}");
    } else {
        println!(
            "hub metadata recorded. use `veen hub stop --data-dir {}` to mark it stopped.",
            args.data_dir.display()
        );
    }

    Ok(())
}

async fn handle_hub_stop(args: HubStopArgs) -> Result<()> {
    let mut state = load_hub_state(&args.data_dir).await?;
    if !state.running {
        bail!(
            "hub in {} is not marked as running",
            args.data_dir.display()
        );
    }

    let stop_ts = current_unix_timestamp()?;
    state.record_stop(stop_ts);
    save_hub_state(&args.data_dir, &state).await?;
    remove_pid_file(&args.data_dir).await?;

    println!("hub stopped. uptime_sec={}", state.uptime(stop_ts));
    Ok(())
}

async fn handle_hub_status(args: HubStatusArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?;
    let state = load_hub_state(&data_dir).await?;

    let profile_id = state
        .profile_id
        .as_deref()
        .with_context(|| format!("hub in {} has not been initialised", data_dir.display()))?;

    let now = current_unix_timestamp()?;

    println!("role: standalone");
    println!("profile_id: {profile_id}");
    println!("peaks_count: {}", state.peaks_count);
    if state.last_stream_seq.is_empty() {
        println!("last_stream_seq: (none)");
    } else {
        println!("last_stream_seq:");
        for (label, seq) in state.last_stream_seq.iter() {
            println!("  {label}: {seq}");
        }
    }
    println!("uptime_sec: {}", state.uptime(now));
    println!("data_dir: {}", state.data_dir);
    if let Some(ref listen) = state.listen {
        println!("listen: {listen}");
    }
    if let Some(ref hub_id) = state.hub_id {
        println!("hub_id: {hub_id}");
    }
    if let Some(pid) = state.pid {
        println!("pid: {pid}");
    }

    Ok(())
}

async fn handle_hub_key(args: HubKeyArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?;
    let key_info = read_hub_key_material(&data_dir).await?;

    println!("hub_id: {}", key_info.hub_id_hex);
    println!("hub_pk: {}", key_info.public_key_hex);
    println!("created_at: {}", key_info.created_at);

    Ok(())
}

async fn handle_hub_verify_rotation(args: HubVerifyRotationArgs) -> Result<()> {
    let checkpoint: Checkpoint = read_cbor_file(&args.checkpoint).await?;

    if !checkpoint.has_valid_version() {
        bail!(
            "checkpoint declares unsupported version {} (expected {})",
            checkpoint.ver,
            CHECKPOINT_VERSION
        );
    }

    let digest = checkpoint
        .signing_tagged_hash()
        .context("computing checkpoint signing digest")?;

    let new_hub_pk = parse_hex_key::<32>(&args.new_key).context("parsing new hub public key")?;
    let old_hub_pk = parse_hex_key::<32>(&args.old_key).context("parsing old hub public key")?;

    checkpoint
        .verify_signature(&new_hub_pk)
        .context("checkpoint hub_sig did not verify with the new hub key")?;

    let witnesses = checkpoint
        .witness_sigs
        .as_ref()
        .context("checkpoint does not contain witness signatures")?;

    if witnesses.len() < 2 {
        bail!(
            "expected at least two witness signatures (old and new hub keys); found {}",
            witnesses.len()
        );
    }

    let mut old_verified = false;
    let mut new_verified = false;
    for witness in witnesses {
        if witness.verify(&old_hub_pk, digest.as_ref()).is_ok() {
            old_verified = true;
        }
        if witness.verify(&new_hub_pk, digest.as_ref()).is_ok() {
            new_verified = true;
        }
    }

    if !old_verified {
        bail!("no witness signature validated with the supplied old hub key");
    }
    if !new_verified {
        bail!("no witness signature validated with the supplied new hub key");
    }

    println!(
        "checkpoint rotation verified: hub_sig (new key) and witness_sigs (old+new) are valid"
    );
    Ok(())
}

async fn handle_hub_health(args: HubHealthArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?;
    let state = load_hub_state(&data_dir).await?;
    let now = current_unix_timestamp()?;

    if state.running {
        println!("status: running");
        println!("uptime_sec: {}", state.uptime(now));
    } else {
        println!("status: stopped");
        if let Some(stopped_at) = state.stopped_at {
            println!("stopped_at: {stopped_at}");
        }
    }

    if let Some(ref profile_id) = state.profile_id {
        println!("profile_id: {profile_id}");
    }
    if let Some(ref hub_id) = state.hub_id {
        println!("hub_id: {hub_id}");
    }

    Ok(())
}

async fn handle_hub_metrics(args: HubMetricsArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?;
    let state = load_hub_state(&data_dir).await?;
    let metrics = state.metrics.clone();

    if args.raw {
        print_metrics_raw(&metrics);
    } else {
        print_metrics_summary(&metrics);
    }

    Ok(())
}

async fn handle_hub_tls_info(_args: HubTlsInfoArgs) -> Result<()> {
    not_implemented("hub tls-info")
}

async fn handle_keygen(args: KeygenArgs) -> Result<()> {
    let client_dir = args.out;
    ensure_clean_directory(&client_dir).await?;

    let keystore_path = client_dir.join("keystore.enc");
    let identity_path = client_dir.join("identity_card.pub");
    let state_path = client_dir.join("state.json");

    ensure_absent(&keystore_path).await?;
    ensure_absent(&identity_path).await?;
    ensure_absent(&state_path).await?;

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let dh_secret = StaticSecret::random_from_rng(rng);
    let dh_public = X25519PublicKey::from(&dh_secret);

    let created_at = current_unix_timestamp()?;
    let client_id_bytes = verifying_key.to_bytes();
    let dh_public_bytes = dh_public.to_bytes();
    let signing_key_bytes = signing_key.to_bytes();
    let dh_secret_bytes = dh_secret.to_bytes();

    let secret_bundle = ClientSecretBundle {
        version: CLIENT_KEY_VERSION,
        created_at,
        client_id: ByteBuf::from(client_id_bytes.to_vec()),
        dh_public: ByteBuf::from(dh_public_bytes.to_vec()),
        signing_key: ByteBuf::from(signing_key_bytes.to_vec()),
        dh_secret: ByteBuf::from(dh_secret_bytes.to_vec()),
    };

    let public_bundle = ClientPublicBundle {
        version: CLIENT_KEY_VERSION,
        created_at,
        client_id: ByteBuf::from(client_id_bytes.to_vec()),
        dh_public: ByteBuf::from(dh_public_bytes.to_vec()),
    };

    let state = ClientStateFile {
        version: CLIENT_STATE_VERSION,
        profile_id: None,
        hubs: Vec::new(),
        labels: BTreeMap::new(),
        rotation_history: Vec::new(),
    };

    write_cbor_file(&keystore_path, &secret_bundle)
        .await
        .with_context(|| {
            format!(
                "writing private key material to {}",
                keystore_path.display()
            )
        })?;
    restrict_private_permissions(&keystore_path).await?;

    write_cbor_file(&identity_path, &public_bundle)
        .await
        .with_context(|| format!("writing public identity to {}", identity_path.display()))?;

    write_json_file(&state_path, &json!(state))
        .await
        .with_context(|| format!("writing client state to {}", state_path.display()))?;

    tracing::info!(
        client_id = %hex::encode(client_id_bytes),
        keystore = %keystore_path.display(),
        identity = %identity_path.display(),
        state = %state_path.display(),
        "generated VEEN client identity"
    );

    Ok(())
}

async fn handle_id_show(args: IdShowArgs) -> Result<()> {
    let client_dir = args.client;
    let identity_path = client_dir.join("identity_card.pub");
    let state_path = client_dir.join("state.json");

    let identity: ClientPublicBundle = read_cbor_file(&identity_path).await?;
    let state: ClientStateFile = read_json_file(&state_path).await?;

    let client_id_hex = hex::encode(identity.client_id.as_ref());
    let id_sign_hex = client_id_hex.clone();
    let id_dh_hex = hex::encode(identity.dh_public.as_ref());

    println!("client_id: {client_id_hex}");
    println!("id_sign_public: {id_sign_hex}");
    println!("id_dh_public: {id_dh_hex}");

    match state.profile_id {
        Some(profile) => println!("profile_id: {profile}"),
        None => println!("profile_id: (not pinned)"),
    }

    if state.labels.is_empty() {
        println!("labels: (none)");
    } else {
        println!("labels:");
        for (label, info) in state.labels.iter() {
            println!(
                "  {label}: last_stream_seq={}, last_mmr_root={}, prev_ack={}",
                info.last_stream_seq, info.last_mmr_root, info.prev_ack
            );
        }
    }

    if state.rotation_history.is_empty() {
        println!("rotation_history: (none)");
    } else {
        println!("rotation_history:");
        for record in state.rotation_history.iter() {
            println!(
                "  rotated_at={}: previous_client_id={}, previous_dh_public={}",
                record.rotated_at, record.previous_client_id, record.previous_dh_public
            );
        }
    }

    Ok(())
}

async fn handle_id_rotate(args: IdRotateArgs) -> Result<()> {
    let client_dir = args.client;
    let keystore_path = client_dir.join("keystore.enc");
    let identity_path = client_dir.join("identity_card.pub");
    let state_path = client_dir.join("state.json");

    let mut secret_bundle: ClientSecretBundle = read_cbor_file(&keystore_path).await?;
    let mut state: ClientStateFile = read_json_file(&state_path).await?;

    let previous_client_id = secret_bundle.client_id.clone();
    let previous_dh_public = secret_bundle.dh_public.clone();

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let dh_secret = StaticSecret::random_from_rng(rng);
    let dh_public = X25519PublicKey::from(&dh_secret);

    let rotated_at = current_unix_timestamp()?;

    let new_client_id = ByteBuf::from(verifying_key.to_bytes().to_vec());
    let new_dh_public = ByteBuf::from(dh_public.to_bytes().to_vec());
    let new_signing_key = ByteBuf::from(signing_key.to_bytes().to_vec());
    let new_dh_secret = ByteBuf::from(dh_secret.to_bytes().to_vec());

    secret_bundle.created_at = rotated_at;
    secret_bundle.client_id = new_client_id.clone();
    secret_bundle.dh_public = new_dh_public.clone();
    secret_bundle.signing_key = new_signing_key;
    secret_bundle.dh_secret = new_dh_secret;

    write_cbor_file(&keystore_path, &secret_bundle)
        .await
        .with_context(|| {
            format!(
                "writing rotated private keys to {}",
                keystore_path.display()
            )
        })?;
    restrict_private_permissions(&keystore_path).await?;

    let public_bundle = ClientPublicBundle {
        version: secret_bundle.version,
        created_at: rotated_at,
        client_id: new_client_id.clone(),
        dh_public: new_dh_public.clone(),
    };

    write_cbor_file(&identity_path, &public_bundle)
        .await
        .with_context(|| format!("writing rotated identity to {}", identity_path.display()))?;

    state.rotation_history.push(ClientRotationRecord {
        rotated_at,
        previous_client_id: hex::encode(previous_client_id.as_ref()),
        previous_dh_public: hex::encode(previous_dh_public.as_ref()),
    });

    write_json_file(&state_path, &json!(state))
        .await
        .with_context(|| format!("updating client state in {}", state_path.display()))?;

    let new_client_id_hex = hex::encode(new_client_id.as_ref());
    tracing::info!(client_id = %new_client_id_hex, "rotated VEEN client identity");
    println!("rotated client identity. new client_id: {new_client_id_hex}");

    Ok(())
}

async fn handle_send(_args: SendArgs) -> Result<()> {
    not_implemented("send")
}

async fn handle_stream(_args: StreamArgs) -> Result<()> {
    not_implemented("stream")
}

async fn handle_attachment_verify(_args: AttachmentVerifyArgs) -> Result<()> {
    not_implemented("attachment verify")
}

async fn handle_cap_issue(_args: CapIssueArgs) -> Result<()> {
    not_implemented("cap issue")
}

async fn handle_cap_authorize(_args: CapAuthorizeArgs) -> Result<()> {
    not_implemented("cap authorize")
}

async fn handle_resync(_args: ResyncArgs) -> Result<()> {
    not_implemented("resync")
}

async fn handle_verify_state(_args: VerifyStateArgs) -> Result<()> {
    not_implemented("verify-state")
}

async fn handle_explain_error(args: ExplainErrorArgs) -> Result<()> {
    let code = args.code.trim().to_ascii_uppercase();
    let description = match code.as_str() {
        "E.SIG" => "signature failure (including hub_sig or MSG.sig)",
        "E.SIZE" => "bounds violation (including MAX_* limits)",
        "E.SEQ" => "sequence invariant violation (including I6, I8, I9, I12)",
        "E.CAP" => "capability failure (including invalid sig_chain, expired ttl)",
        "E.AUTH" => "missing or invalid authorization record",
        "E.RATE" => "rate limit exceeded",
        "E.PROFILE" => "unsupported profile_id",
        "E.DUP" => "duplicate leaf or message",
        "E.TIME" => "epoch or time-related failure",
        other => {
            bail!("unknown VEEN error code `{other}`");
        }
    };

    println!("{code}: {description}");
    Ok(())
}

async fn handle_rpc_call(_args: RpcCallArgs) -> Result<()> {
    not_implemented("rpc call")
}

async fn handle_crdt_lww_set(_args: CrdtLwwSetArgs) -> Result<()> {
    not_implemented("crdt lww set")
}

async fn handle_crdt_lww_get(_args: CrdtLwwGetArgs) -> Result<()> {
    not_implemented("crdt lww get")
}

async fn handle_crdt_orset_add(_args: CrdtOrsetAddArgs) -> Result<()> {
    not_implemented("crdt orset add")
}

async fn handle_crdt_orset_remove(_args: CrdtOrsetRemoveArgs) -> Result<()> {
    not_implemented("crdt orset remove")
}

async fn handle_crdt_orset_list(_args: CrdtOrsetListArgs) -> Result<()> {
    not_implemented("crdt orset list")
}

async fn handle_crdt_counter_add(_args: CrdtCounterAddArgs) -> Result<()> {
    not_implemented("crdt counter add")
}

async fn handle_crdt_counter_get(_args: CrdtCounterGetArgs) -> Result<()> {
    not_implemented("crdt counter get")
}

async fn handle_anchor_publish(_args: AnchorPublishArgs) -> Result<()> {
    not_implemented("anchor publish")
}

async fn handle_anchor_verify(_args: AnchorVerifyArgs) -> Result<()> {
    not_implemented("anchor verify")
}

async fn handle_retention_show(_args: RetentionShowArgs) -> Result<()> {
    not_implemented("retention show")
}

async fn handle_selftest_core() -> Result<()> {
    println!("running VEEN core self-tests...");
    veen_selftest::run_core()
}

async fn handle_selftest_props() -> Result<()> {
    println!("running VEEN property self-tests...");
    veen_selftest::run_props()
}

async fn handle_selftest_fuzz() -> Result<()> {
    println!("running VEEN fuzz self-tests...");
    veen_selftest::run_fuzz()
}

async fn handle_selftest_all() -> Result<()> {
    println!("running full VEEN self-test suite...");
    veen_selftest::run_all()
}

fn not_implemented(command: &str) -> Result<()> {
    tracing::debug!(command = command, "invoked VEEN CLI placeholder");
    bail!(
        "`veen {command}` is a scaffold. Implement the workflow described in doc/CLI-GOAL.txt to make this command functional."
    );
}

async fn ensure_data_dir_layout(data_dir: &Path) -> Result<()> {
    fs::create_dir_all(data_dir)
        .await
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;

    ensure_file(&data_dir.join(RECEIPTS_FILE)).await?;
    ensure_file(&data_dir.join(PAYLOADS_FILE)).await?;
    ensure_file(&data_dir.join(CHECKPOINTS_FILE)).await?;
    fs::create_dir_all(data_dir.join(ANCHORS_DIR))
        .await
        .with_context(|| format!("creating anchors dir under {}", data_dir.display()))?;
    fs::create_dir_all(data_dir.join(STATE_DIR))
        .await
        .with_context(|| format!("creating state dir under {}", data_dir.display()))?;

    Ok(())
}

async fn ensure_file(path: &Path) -> Result<()> {
    if fs::try_exists(path)
        .await
        .with_context(|| format!("checking {}", path.display()))?
    {
        return Ok(());
    }

    fs::write(path, &[])
        .await
        .with_context(|| format!("initialising {}", path.display()))?;
    Ok(())
}

async fn load_hub_state(data_dir: &Path) -> Result<HubRuntimeState> {
    let state_path = data_dir.join(HUB_STATE_FILE);
    if fs::try_exists(&state_path)
        .await
        .with_context(|| format!("checking hub state in {}", state_path.display()))?
    {
        let mut state: HubRuntimeState = read_json_file(&state_path).await?;
        if state.data_dir.is_empty() {
            state.data_dir = data_dir.to_string_lossy().into_owned();
        }
        Ok(state)
    } else {
        Ok(HubRuntimeState::new(data_dir))
    }
}

async fn save_hub_state(data_dir: &Path, state: &HubRuntimeState) -> Result<()> {
    let state_path = data_dir.join(HUB_STATE_FILE);
    write_json_file(&state_path, state)
        .await
        .with_context(|| format!("persisting hub state to {}", state_path.display()))?;
    Ok(())
}

async fn write_pid_file(data_dir: &Path, pid: u32) -> Result<()> {
    let pid_path = data_dir.join(HUB_PID_FILE);
    fs::write(&pid_path, pid.to_string())
        .await
        .with_context(|| format!("writing pid file {}", pid_path.display()))?;
    restrict_private_permissions(&pid_path).await?;
    Ok(())
}

async fn remove_pid_file(data_dir: &Path) -> Result<()> {
    let pid_path = data_dir.join(HUB_PID_FILE);
    if fs::try_exists(&pid_path)
        .await
        .with_context(|| format!("checking pid file {}", pid_path.display()))?
    {
        fs::remove_file(&pid_path)
            .await
            .with_context(|| format!("removing pid file {}", pid_path.display()))?;
    }
    Ok(())
}

fn resolve_profile_id(profile: Option<String>) -> Result<String> {
    match profile {
        Some(value) => {
            let trimmed = value.trim().to_ascii_lowercase();
            if trimmed.len() != 64 {
                bail!(
                    "profile identifier must be 64 hex characters (32 bytes); got {}",
                    trimmed.len()
                );
            }
            if !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
                bail!("profile identifier must contain only hexadecimal characters");
            }
            Ok(trimmed)
        }
        None => {
            let profile_id = Profile::default()
                .id_hex()
                .context("computing default profile identifier")?;
            Ok(profile_id)
        }
    }
}

async fn ensure_hub_key_material(data_dir: &Path) -> Result<HubKeyInfo> {
    if fs::try_exists(&data_dir.join(HUB_KEY_FILE))
        .await
        .with_context(|| format!("checking hub key in {}", data_dir.display()))?
    {
        return read_hub_key_material(data_dir).await;
    }

    let created_at = current_unix_timestamp()?;
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let material = HubKeyMaterial {
        version: HUB_KEY_VERSION,
        created_at,
        public_key: ByteBuf::from(verifying_key.to_bytes().to_vec()),
        secret_key: ByteBuf::from(signing_key.to_bytes().to_vec()),
    };

    let key_path = data_dir.join(HUB_KEY_FILE);
    write_cbor_file(&key_path, &material)
        .await
        .with_context(|| format!("writing hub key material to {}", key_path.display()))?;
    restrict_private_permissions(&key_path).await?;

    read_hub_key_material(data_dir).await
}

async fn read_hub_key_material(data_dir: &Path) -> Result<HubKeyInfo> {
    let key_path = data_dir.join(HUB_KEY_FILE);
    let material: HubKeyMaterial = read_cbor_file(&key_path).await?;

    if material.version != HUB_KEY_VERSION {
        bail!(
            "unsupported hub key version {} (expected {})",
            material.version,
            HUB_KEY_VERSION
        );
    }

    let pk: [u8; 32] = material
        .public_key
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("hub public key must be 32 bytes"))?;
    let hub_id = HubId::derive(pk).context("deriving hub identifier from public key")?;

    Ok(HubKeyInfo {
        hub_id_hex: hex::encode(hub_id.as_ref()),
        public_key_hex: hex::encode(pk),
        created_at: material.created_at,
    })
}

fn parse_hub_reference(reference: &str) -> Result<PathBuf> {
    if let Some(path) = reference.strip_prefix("file://") {
        Ok(PathBuf::from(path))
    } else if reference.contains("://") {
        bail!(
            "network hubs are not supported by this CLI implementation; provide a data directory path or file:// URI"
        );
    } else {
        Ok(PathBuf::from(reference))
    }
}

fn print_metrics_summary(metrics: &HubMetricsSnapshot) {
    println!("submit_ok_total: {}", metrics.submit_ok_total);
    if metrics.submit_err_total.is_empty() {
        println!("submit_err_total: (none)");
    } else {
        println!("submit_err_total:");
        for (code, count) in metrics.submit_err_total.iter() {
            println!("  {code}: {count}");
        }
    }
    println!(
        "verify_latency_ms: {}",
        format_histogram(&metrics.verify_latency_ms)
    );
    println!(
        "commit_latency_ms: {}",
        format_histogram(&metrics.commit_latency_ms)
    );
    println!(
        "end_to_end_latency_ms: {}",
        format_histogram(&metrics.end_to_end_latency_ms)
    );
}

fn print_metrics_raw(metrics: &HubMetricsSnapshot) {
    println!("veen_submit_ok_total {}", metrics.submit_ok_total);
    if metrics.submit_err_total.is_empty() {
        println!("veen_submit_err_total{{code=\"none\"}} 0");
    } else {
        for (code, count) in metrics.submit_err_total.iter() {
            println!("veen_submit_err_total{{code=\"{code}\"}} {count}");
        }
    }
    println!(
        "veen_verify_latency_ms_count {}",
        metrics.verify_latency_ms.count
    );
    println!(
        "veen_verify_latency_ms_sum {}",
        metrics.verify_latency_ms.sum
    );
    println!(
        "veen_commit_latency_ms_count {}",
        metrics.commit_latency_ms.count
    );
    println!(
        "veen_commit_latency_ms_sum {}",
        metrics.commit_latency_ms.sum
    );
    println!(
        "veen_end_to_end_latency_ms_count {}",
        metrics.end_to_end_latency_ms.count
    );
    println!(
        "veen_end_to_end_latency_ms_sum {}",
        metrics.end_to_end_latency_ms.sum
    );
}

fn format_histogram(hist: &HistogramSnapshot) -> String {
    if hist.count == 0 {
        return "count=0 (no samples)".to_string();
    }

    let avg = hist.average().unwrap_or(0.0);
    let min = hist.min.unwrap_or(avg);
    let max = hist.max.unwrap_or(avg);
    format!(
        "count={} min={min:.2} max={max:.2} avg={avg:.2}",
        hist.count
    )
}

fn parse_hex_key<const N: usize>(input: &str) -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    let data =
        hex::decode(input.trim()).with_context(|| format!("decoding {N}-byte hex string"))?;
    if data.len() != N {
        bail!(
            "expected {N} bytes ({} hex chars), got {} bytes",
            N * 2,
            data.len()
        );
    }
    bytes.copy_from_slice(&data);
    Ok(bytes)
}

async fn ensure_clean_directory(path: &Path) -> Result<()> {
    match fs::metadata(path).await {
        Ok(metadata) => {
            if !metadata.is_dir() {
                bail!("{} exists and is not a directory", path.display());
            }
            let mut entries = fs::read_dir(path)
                .await
                .with_context(|| format!("reading directory {}", path.display()))?;
            if entries
                .next_entry()
                .await
                .with_context(|| format!("checking contents of {}", path.display()))?
                .is_some()
            {
                bail!("refusing to reuse non-empty directory {}", path.display());
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .await
                .with_context(|| format!("creating directory {}", path.display()))?;
        }
        Err(err) => {
            return Err(anyhow!(err)).context(format!("checking {}", path.display()));
        }
    }
    Ok(())
}

async fn ensure_absent(path: &Path) -> Result<()> {
    if fs::try_exists(path)
        .await
        .with_context(|| format!("checking existence of {}", path.display()))?
    {
        bail!("refusing to overwrite existing file {}", path.display());
    }
    Ok(())
}

fn current_unix_timestamp() -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| anyhow!("system clock is before Unix epoch: {err}"))?;
    Ok(now.as_secs())
}

async fn write_cbor_file<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize,
{
    let mut buffer = Vec::new();
    ciborium::ser::into_writer(value, &mut buffer)
        .map_err(|err| anyhow!("failed to encode CBOR for {}: {err}", path.display()))?;
    fs::write(path, buffer)
        .await
        .with_context(|| format!("persisting {}", path.display()))?;
    Ok(())
}

async fn write_json_file<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize,
{
    let data = serde_json::to_vec_pretty(value)
        .with_context(|| format!("serialising JSON for {}", path.display()))?;
    fs::write(path, data)
        .await
        .with_context(|| format!("persisting {}", path.display()))?;
    Ok(())
}

async fn read_cbor_file<T>(path: &Path) -> Result<T>
where
    T: DeserializeOwned,
{
    let data = fs::read(path)
        .await
        .with_context(|| format!("reading {}", path.display()))?;
    let value = ciborium::de::from_reader(data.as_slice())
        .map_err(|err| anyhow!("failed to decode CBOR from {}: {err}", path.display()))?;
    Ok(value)
}

async fn read_json_file<T>(path: &Path) -> Result<T>
where
    T: DeserializeOwned,
{
    let data = fs::read(path)
        .await
        .with_context(|| format!("reading {}", path.display()))?;
    let value = serde_json::from_slice(&data)
        .with_context(|| format!("parsing JSON from {}", path.display()))?;
    Ok(value)
}

async fn restrict_private_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let permissions = std::fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, permissions)
            .await
            .with_context(|| format!("setting permissions on {}", path.display()))?;
    }

    #[cfg(not(unix))]
    let _ = path;

    Ok(())
}
