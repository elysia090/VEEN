use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::json;
use tokio::fs;
use tracing_subscriber::EnvFilter;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const CLIENT_KEY_VERSION: u8 = 1;
const CLIENT_STATE_VERSION: u8 = 1;

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

#[derive(Serialize)]
struct ClientStateFile {
    version: u8,
    profile_id: Option<String>,
    hubs: Vec<ClientStateHubPin>,
    labels: BTreeMap<String, ClientLabelState>,
}

#[derive(Serialize)]
struct ClientStateHubPin {
    hub: String,
    profile_id: Option<String>,
}

#[derive(Serialize)]
struct ClientLabelState {
    last_stream_seq: u64,
    last_mmr_root: String,
    prev_ack: u64,
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

async fn handle_hub_start(_args: HubStartArgs) -> Result<()> {
    not_implemented("hub start")
}

async fn handle_hub_stop(_args: HubStopArgs) -> Result<()> {
    not_implemented("hub stop")
}

async fn handle_hub_status(_args: HubStatusArgs) -> Result<()> {
    not_implemented("hub status")
}

async fn handle_hub_key(_args: HubKeyArgs) -> Result<()> {
    not_implemented("hub key")
}

async fn handle_hub_verify_rotation(_args: HubVerifyRotationArgs) -> Result<()> {
    not_implemented("hub verify-rotation")
}

async fn handle_hub_health(_args: HubHealthArgs) -> Result<()> {
    not_implemented("hub health")
}

async fn handle_hub_metrics(_args: HubMetricsArgs) -> Result<()> {
    not_implemented("hub metrics")
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

async fn handle_id_show(_args: IdShowArgs) -> Result<()> {
    not_implemented("id show")
}

async fn handle_id_rotate(_args: IdRotateArgs) -> Result<()> {
    not_implemented("id rotate")
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
        "E.SIG" => "signature verification failed",
        "E.SIZE" => "message exceeded configured bounds",
        "E.SEQ" => "sequence violation for client_id/client_seq",
        "E.CAP" => "capability token invalid or expired",
        "E.AUTH" => "authorization required or denied",
        "E.RATE" => "rate limit exceeded",
        "E.PROFILE" => "profile mismatch or unsupported profile",
        "E.DUP" => "duplicate message detected",
        "E.TIME" => "message outside acceptable time window",
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
    not_implemented("selftest core")
}

async fn handle_selftest_props() -> Result<()> {
    not_implemented("selftest props")
}

async fn handle_selftest_fuzz() -> Result<()> {
    not_implemented("selftest fuzz")
}

async fn handle_selftest_all() -> Result<()> {
    not_implemented("selftest all")
}

fn not_implemented(command: &str) -> Result<()> {
    tracing::debug!(command = command, "invoked VEEN CLI placeholder");
    bail!(
        "`veen {command}` is a scaffold. Implement the workflow described in doc/CLI-GOAL.txt to make this command functional."
    );
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
