use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ciborium::value::Value as CborValue;
use clap::{Args, Parser, Subcommand, ValueEnum};
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use reqwest::{Client as HttpClient, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::signal;
use tracing_subscriber::EnvFilter;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use veen_core::CAP_TOKEN_VERSION;
use veen_core::{
    cap_stream_id_from_label,
    hub::{HubId, HUB_ID_LEN},
    label::{Label, StreamId},
    wire::{checkpoint::CHECKPOINT_VERSION, Checkpoint, ClientId},
    AuthorityPolicy, AuthorityRecord, CapToken, CapTokenAllow, CapTokenRate, LabelClassRecord,
    Profile, RealmId, RevocationKind, RevocationRecord, RevocationTarget, SchemaDescriptor,
    SchemaId, SchemaOwner, TransferId, WalletId, WalletTransferEvent,
};
use veen_core::{h, ht};
use veen_core::{
    schema_fed_authority, schema_label_class, schema_meta_schema, schema_revocation,
    schema_wallet_transfer, REVOCATION_TARGET_LEN, SCHEMA_ID_LEN, TRANSFER_ID_LEN, WALLET_ID_LEN,
};
use veen_hub::pipeline::{
    AttachmentUpload, AuthorizeResponse as RemoteAuthorizeResponse,
    HubStreamState as RemoteHubStreamState, StoredAttachment as RemoteStoredAttachment,
    StoredMessage as RemoteStoredMessage, SubmitRequest as RemoteSubmitRequest,
    SubmitResponse as RemoteSubmitResponse,
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
const STREAMS_DIR: &str = "streams";
const MESSAGES_DIR: &str = "messages";
const CAP_TOKENS_DIR: &str = "capabilities";
const CRDT_DIR: &str = "crdt";
const ANCHOR_LOG_FILE: &str = "anchor_log.json";
const RETENTION_CONFIG_FILE: &str = "retention.json";
const TLS_INFO_FILE: &str = "tls_info.json";
const ATTACHMENTS_DIR: &str = "attachments";

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
    /// Authorize a capability token with the hub.
    Authorize(CapAuthorizeArgs),
    /// Stream and decrypt messages from the hub.
    Stream(StreamArgs),
    /// Attachment tooling.
    #[command(subcommand)]
    Attachment(AttachmentCommand),
    /// Capability management.
    #[command(subcommand)]
    Cap(CapCommand),
    /// Federation and authority helpers.
    #[command(subcommand)]
    Authority(AuthorityCommand),
    /// Label classification helpers.
    #[command(subcommand, name = "label-class")]
    LabelClass(LabelClassCommand),
    /// Schema registry helpers.
    #[command(subcommand)]
    Schema(SchemaCommand),
    /// Wallet overlay helpers.
    #[command(subcommand)]
    Wallet(WalletCommand),
    /// Revocation helpers.
    #[command(subcommand)]
    Revoke(RevokeCommand),
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
enum AuthorityCommand {
    /// Publish an authority record for a stream.
    Set(AuthoritySetArgs),
}

#[derive(Subcommand)]
enum LabelClassCommand {
    /// Publish a label classification record.
    Set(LabelClassSetArgs),
}

#[derive(Subcommand)]
enum SchemaCommand {
    /// Compute the canonical schema identifier for a name.
    Id(SchemaIdArgs),
    /// Register or update schema metadata.
    Register(SchemaRegisterArgs),
    /// Fetch schema descriptors from the hub.
    List(SchemaListArgs),
}

#[derive(Subcommand)]
enum WalletCommand {
    /// Emit a wallet transfer event.
    Transfer(WalletTransferArgs),
}

#[derive(Subcommand)]
enum RevokeCommand {
    /// Publish a revocation record.
    Publish(RevokePublishArgs),
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
struct AuthoritySetArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    signer: PathBuf,
    #[arg(long)]
    realm: String,
    #[arg(long)]
    stream: String,
    #[arg(long, value_enum, default_value_t = AuthorityPolicyValue::SinglePrimary)]
    policy: AuthorityPolicyValue,
    #[arg(long = "primary-hub")]
    primary_hub: String,
    #[arg(long = "replica-hub")]
    replica_hubs: Vec<String>,
    #[arg(long)]
    ttl: Option<u64>,
    #[arg(long)]
    ts: Option<u64>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum AuthorityPolicyValue {
    SinglePrimary,
    MultiPrimary,
}

#[derive(Args)]
struct LabelClassSetArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    signer: PathBuf,
    #[arg(long)]
    realm: String,
    #[arg(long)]
    label: String,
    #[arg(long)]
    class: String,
    #[arg(long)]
    sensitivity: Option<String>,
    #[arg(long = "retention-hint")]
    retention_hint: Option<u64>,
}

#[derive(Args)]
struct SchemaIdArgs {
    /// Schema name used for hashing.
    name: String,
}

#[derive(Args)]
struct SchemaRegisterArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    signer: PathBuf,
    #[arg(long = "schema-id")]
    schema_id: String,
    #[arg(long)]
    name: String,
    #[arg(long)]
    version: String,
    #[arg(long = "doc-url")]
    doc_url: Option<String>,
    #[arg(long)]
    owner: Option<String>,
    #[arg(long)]
    ts: Option<u64>,
}

#[derive(Args)]
struct SchemaListArgs {
    #[arg(long)]
    hub: String,
}

#[derive(Args)]
struct WalletTransferArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    signer: PathBuf,
    #[arg(long = "wallet-id")]
    wallet_id: String,
    #[arg(long = "to-wallet-id")]
    to_wallet_id: String,
    #[arg(long)]
    amount: u64,
    #[arg(long)]
    ts: Option<u64>,
    #[arg(long = "transfer-id")]
    transfer_id: Option<String>,
    #[arg(long)]
    metadata: Option<String>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum RevocationKindValue {
    #[clap(name = "client-id")]
    ClientId,
    #[clap(name = "auth-ref")]
    AuthRef,
    #[clap(name = "cap-token")]
    CapToken,
}

#[derive(Args)]
struct RevokePublishArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    signer: PathBuf,
    #[arg(long, value_enum)]
    kind: RevocationKindValue,
    #[arg(long)]
    target: String,
    #[arg(long)]
    reason: Option<String>,
    #[arg(long)]
    ttl: Option<u64>,
    #[arg(long)]
    ts: Option<u64>,
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

    fn record_message(&mut self, stream: &str, seq: u64, now: u64) {
        self.peaks_count = self.peaks_count.max(seq);
        self.last_stream_seq.insert(stream.to_string(), seq);
        self.metrics.submit_ok_total = self.metrics.submit_ok_total.saturating_add(1);
        self.metrics.verify_latency_ms.record(0.5);
        self.metrics.commit_latency_ms.record(0.5);
        self.metrics.end_to_end_latency_ms.record(1.0);
        if self.started_at.is_none() {
            self.started_at = Some(now);
        }
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

    fn record(&mut self, value: f64) {
        self.count = self.count.saturating_add(1);
        self.sum += value;
        self.min = Some(match self.min {
            Some(current) => current.min(value),
            None => value,
        });
        self.max = Some(match self.max {
            Some(current) => current.max(value),
            None => value,
        });
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

impl Default for ClientLabelState {
    fn default() -> Self {
        Self {
            last_stream_seq: 0,
            last_mmr_root: "0".repeat(64),
            prev_ack: 0,
        }
    }
}

impl ClientStateFile {
    fn ensure_label_state(&mut self, label: &str) -> &mut ClientLabelState {
        self.labels.entry(label.to_string()).or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct HubStreamState {
    messages: Vec<StoredMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMessage {
    stream: String,
    seq: u64,
    sent_at: u64,
    client_id: String,
    schema: Option<String>,
    expires_at: Option<u64>,
    parent: Option<String>,
    body: Option<String>,
    body_digest: Option<String>,
    attachments: Vec<StoredAttachment>,
    auth_ref: Option<String>,
    idem: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAttachment {
    name: String,
    digest: String,
    size: u64,
    stored_path: String,
}

impl From<RemoteStoredAttachment> for StoredAttachment {
    fn from(remote: RemoteStoredAttachment) -> Self {
        Self {
            name: remote.name,
            digest: remote.digest,
            size: remote.size,
            stored_path: remote.stored_path,
        }
    }
}

impl From<RemoteStoredMessage> for StoredMessage {
    fn from(remote: RemoteStoredMessage) -> Self {
        Self {
            stream: remote.stream,
            seq: remote.seq,
            sent_at: remote.sent_at,
            client_id: remote.client_id,
            schema: remote.schema,
            expires_at: remote.expires_at,
            parent: remote.parent,
            body: remote.body,
            body_digest: remote.body_digest,
            attachments: remote
                .attachments
                .into_iter()
                .map(StoredAttachment::from)
                .collect(),
            auth_ref: remote.auth_ref,
            idem: remote.idem,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct LwwRegisterState {
    entries: BTreeMap<String, LwwRegisterValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LwwRegisterValue {
    value: String,
    timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct OrsetState {
    elements: Vec<OrsetElement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OrsetElement {
    value: String,
    added_at: u64,
    removed_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CounterState {
    value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AnchorLog {
    entries: Vec<AnchorRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnchorRecord {
    stream: String,
    epoch: Option<u64>,
    ts: u64,
    nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlsInfoSnapshot {
    version: String,
    cipher: String,
    aead: bool,
    compression: bool,
}

impl Default for TlsInfoSnapshot {
    fn default() -> Self {
        Self {
            version: "TLS 1.3".to_string(),
            cipher: "TLS_AES_256_GCM_SHA384".to_string(),
            aead: true,
            compression: false,
        }
    }
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
        Command::Authorize(args) => handle_cap_authorize(args).await,
        Command::Stream(args) => handle_stream(args).await,
        Command::Attachment(cmd) => match cmd {
            AttachmentCommand::Verify(args) => handle_attachment_verify(args).await,
        },
        Command::Cap(cmd) => match cmd {
            CapCommand::Issue(args) => handle_cap_issue(args).await,
            CapCommand::Authorize(args) => handle_cap_authorize(args).await,
        },
        Command::Authority(cmd) => match cmd {
            AuthorityCommand::Set(args) => handle_authority_set(args).await,
        },
        Command::LabelClass(cmd) => match cmd {
            LabelClassCommand::Set(args) => handle_label_class_set(args).await,
        },
        Command::Schema(cmd) => match cmd {
            SchemaCommand::Id(args) => handle_schema_id(args).await,
            SchemaCommand::Register(args) => handle_schema_register(args).await,
            SchemaCommand::List(args) => handle_schema_list(args).await,
        },
        Command::Wallet(cmd) => match cmd {
            WalletCommand::Transfer(args) => handle_wallet_transfer(args).await,
        },
        Command::Revoke(cmd) => match cmd {
            RevokeCommand::Publish(args) => handle_revoke_publish(args).await,
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
    ensure_tls_info(&args.data_dir).await?;

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

    flush_hub_storage(&args.data_dir).await?;

    let stop_ts = current_unix_timestamp()?;
    state.record_stop(stop_ts);
    save_hub_state(&args.data_dir, &state).await?;
    remove_pid_file(&args.data_dir).await?;

    println!("hub stopped. uptime_sec={}", state.uptime(stop_ts));
    Ok(())
}

async fn handle_hub_status(args: HubStatusArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?.into_local()?;
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
    let data_dir = parse_hub_reference(&args.hub)?.into_local()?;
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
    let data_dir = parse_hub_reference(&args.hub)?.into_local()?;
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
    let data_dir = parse_hub_reference(&args.hub)?.into_local()?;
    let state = load_hub_state(&data_dir).await?;
    let metrics = state.metrics.clone();

    if args.raw {
        print_metrics_raw(&metrics);
    } else {
        print_metrics_summary(&metrics);
    }

    Ok(())
}

async fn handle_hub_tls_info(args: HubTlsInfoArgs) -> Result<()> {
    let hub = parse_hub_reference(&args.hub)?.into_local()?;
    let tls_info_path = hub.join(STATE_DIR).join(TLS_INFO_FILE);
    if !fs::try_exists(&tls_info_path)
        .await
        .with_context(|| format!("checking TLS metadata in {}", tls_info_path.display()))?
    {
        bail!(
            "hub at {} does not expose TLS metadata; start the hub at least once to bootstrap",
            hub.display()
        );
    }

    let info: TlsInfoSnapshot = read_json_file(&tls_info_path).await?;
    println!("tls_version: {}", info.version);
    println!("cipher_suite: {}", info.cipher);
    println!("aead: {}", if info.aead { "yes" } else { "no" });
    println!(
        "compression: {}",
        if info.compression {
            "enabled"
        } else {
            "disabled"
        }
    );
    Ok(())
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

async fn handle_send(args: SendArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Local(data_dir) => handle_send_local(data_dir, args).await,
        HubReference::Remote(client) => handle_send_remote(client, args).await,
    }
}

async fn handle_send_local(data_dir: PathBuf, args: SendArgs) -> Result<()> {
    ensure_data_dir_layout(&data_dir).await?;

    let mut hub_state = load_hub_state(&data_dir).await?;
    let mut stream_state = load_stream_state(&data_dir, &args.stream).await?;

    let stream_id = cap_stream_id_from_label(&args.stream)
        .with_context(|| format!("deriving stream identifier for {}", args.stream))?;

    let client_bundle: ClientPublicBundle = read_cbor_file(&args.client.join("identity_card.pub"))
        .await
        .with_context(|| {
            format!(
                "reading client identity card from {}",
                args.client.join("identity_card.pub").display()
            )
        })?;
    let client_id = ClientId::from_slice(client_bundle.client_id.as_ref())
        .context("client identity card contains malformed client_id")?;
    let client_id_hex = hex::encode(client_id.as_ref());

    if let Some(ref schema) = args.schema {
        if schema.len() != 32 && schema.len() != 64 {
            bail!("schema identifiers must be 32 or 64 hex characters");
        }
        if !schema.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("schema identifiers must be hexadecimal");
        }
    }

    if let Some(ref cap_path) = args.cap {
        if !fs::try_exists(cap_path)
            .await
            .with_context(|| format!("checking capability file {}", cap_path.display()))?
        {
            bail!("capability file {} does not exist", cap_path.display());
        }
    }

    let now = current_unix_timestamp()?;
    let seq = stream_state.messages.last().map(|m| m.seq + 1).unwrap_or(1);

    let body_digest = if args.no_store_body {
        Some(compute_digest_hex(args.body.as_bytes()))
    } else {
        None
    };

    let body_to_store = if args.no_store_body {
        None
    } else {
        Some(args.body.clone())
    };

    let attachments_dir = attachments_storage_dir(&data_dir);
    let mut stored_attachments = Vec::new();
    for attachment in &args.attach {
        let data = fs::read(attachment)
            .await
            .with_context(|| format!("reading attachment {}", attachment.display()))?;
        let digest = compute_digest_hex(&data);
        let stored_path = attachments_dir.join(format!("{digest}.bin"));
        fs::write(&stored_path, &data)
            .await
            .with_context(|| format!("writing attachment {}", stored_path.display()))?;
        let attachment_record = StoredAttachment {
            name: attachment
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("attachment")
                .to_string(),
            digest,
            size: data.len() as u64,
            stored_path: stored_path.to_string_lossy().into_owned(),
        };
        append_receipt(&data_dir, PAYLOADS_FILE, &attachment_record).await?;
        stored_attachments.push(attachment_record);
    }

    let auth_ref_hex = if let Some(cap_path) = &args.cap {
        let token: CapToken = read_cbor_file(cap_path).await?;
        token
            .verify()
            .map_err(|err| anyhow!("capability token verification failed: {err}"))?;
        ensure_capability_matches(&token, &client_id, &stream_id)?;
        let auth_ref = token.auth_ref().context("computing capability auth_ref")?;
        Some(hex::encode(auth_ref.as_ref()))
    } else {
        None
    };

    let message = StoredMessage {
        stream: args.stream.clone(),
        seq,
        sent_at: now,
        client_id: client_id_hex.clone(),
        schema: args.schema.clone(),
        expires_at: args.expires_at,
        parent: args.parent.clone(),
        body: body_to_store,
        body_digest,
        attachments: stored_attachments.clone(),
        auth_ref: auth_ref_hex.clone(),
        idem: None,
    };

    stream_state.messages.push(message.clone());
    save_stream_state(&data_dir, &args.stream, &stream_state).await?;

    let bundle_path = message_bundle_path(&data_dir, &args.stream, seq);
    write_json_file(&bundle_path, &message).await?;
    append_receipt(&data_dir, RECEIPTS_FILE, &message).await?;

    hub_state.record_message(&args.stream, seq, now);
    save_hub_state(&data_dir, &hub_state).await?;

    let mut client_state: ClientStateFile = read_json_file(&args.client.join("state.json")).await?;
    let label_state = client_state.ensure_label_state(&args.stream);
    label_state.last_stream_seq = seq;
    label_state.prev_ack = seq;
    write_json_file(&args.client.join("state.json"), &client_state).await?;

    println!(
        "sent message seq={seq} stream={} client_id={client_id_hex}",
        args.stream
    );
    println!("bundle: {}", bundle_path.display());
    if !stored_attachments.is_empty() {
        println!("attachments recorded: {}", stored_attachments.len());
        for attachment in stored_attachments {
            println!(
                "  {} ({} bytes) -> {}",
                attachment.name, attachment.size, attachment.digest
            );
        }
    }
    Ok(())
}

async fn handle_send_remote(client: HubHttpClient, args: SendArgs) -> Result<()> {
    let identity_path = args.client.join("identity_card.pub");
    let stream_id = cap_stream_id_from_label(&args.stream)
        .with_context(|| format!("deriving stream identifier for {}", args.stream))?;

    let client_bundle: ClientPublicBundle =
        read_cbor_file(&identity_path).await.with_context(|| {
            format!(
                "reading client identity card from {}",
                identity_path.display()
            )
        })?;
    let client_id = ClientId::from_slice(client_bundle.client_id.as_ref())
        .context("client identity card contains malformed client_id")?;
    let client_id_hex = hex::encode(client_id.as_ref());

    if let Some(ref schema) = args.schema {
        if schema.len() != 32 && schema.len() != 64 {
            bail!("schema identifiers must be 32 or 64 hex characters");
        }
        if !schema.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("schema identifiers must be hexadecimal");
        }
    }

    let attachments = if args.attach.is_empty() {
        None
    } else {
        let mut uploads = Vec::new();
        for attachment in &args.attach {
            let data = fs::read(attachment)
                .await
                .with_context(|| format!("reading attachment {}", attachment.display()))?;
            let encoded = BASE64_STANDARD.encode(data);
            uploads.push(AttachmentUpload {
                name: attachment
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(ToString::to_string),
                data: encoded,
            });
        }
        Some(uploads)
    };

    let auth_ref_hex = if let Some(ref cap_path) = args.cap {
        let token: CapToken = read_cbor_file(cap_path).await?;
        token
            .verify()
            .map_err(|err| anyhow!("capability token verification failed: {err}"))?;
        ensure_capability_matches(&token, &client_id, &stream_id)?;
        let auth_ref = token.auth_ref().context("computing capability auth_ref")?;
        Some(hex::encode(auth_ref.as_ref()))
    } else {
        None
    };

    let payload = serde_json::from_str(&args.body).unwrap_or_else(|_| json!(args.body));

    let request = RemoteSubmitRequest {
        stream: args.stream.clone(),
        client_id: client_id_hex.clone(),
        payload,
        attachments,
        auth_ref: auth_ref_hex,
        expires_at: args.expires_at,
        schema: args.schema.clone(),
        idem: None,
    };

    let response: RemoteSubmitResponse = client
        .post_json("/submit", &request)
        .await
        .context("submitting message to hub")?;

    println!(
        "sent message seq={} stream={} client_id={}",
        response.seq, response.stream, client_id_hex
    );
    if !response.stored_attachments.is_empty() {
        println!("attachments stored: {}", response.stored_attachments.len());
        for attachment in response.stored_attachments {
            println!(
                "  {} ({} bytes) -> {}",
                attachment.name, attachment.size, attachment.digest
            );
        }
    }

    Ok(())
}

async fn handle_stream(args: StreamArgs) -> Result<()> {
    let hub = parse_hub_reference(&args.hub)?;
    match hub {
        HubReference::Local(data_dir) => {
            let stream_state = load_stream_state(&data_dir, &args.stream).await?;

            let mut emitted = false;
            for message in stream_state.messages.iter().filter(|m| m.seq >= args.from) {
                emitted = true;
                println!("seq: {}", message.seq);
                println!("sent_at: {}", message.sent_at);
                println!("client_id: {}", message.client_id);
                if let Some(ref schema) = message.schema {
                    println!("schema: {schema}");
                }
                if let Some(expires_at) = message.expires_at {
                    println!("expires_at: {expires_at}");
                }
                if let Some(ref parent) = message.parent {
                    println!("parent: {parent}");
                }
                if let Some(ref auth_ref) = message.auth_ref {
                    println!("auth_ref: {auth_ref}");
                }
                match (&message.body, &message.body_digest) {
                    (Some(body), _) => println!("body: {body}"),
                    (None, Some(digest)) => println!("body_digest: {digest}"),
                    _ => println!("body: (omitted)"),
                }
                if message.attachments.is_empty() {
                    println!("attachments: (none)");
                } else {
                    println!("attachments:");
                    for attachment in &message.attachments {
                        println!(
                            "  {} ({} bytes) digest={} stored={}",
                            attachment.name,
                            attachment.size,
                            attachment.digest,
                            attachment.stored_path
                        );
                    }
                }
                if args.with_proof {
                    let proof = compute_message_proof(message)?;
                    println!("proof: {proof}");
                }
                println!("---");
            }

            if !emitted {
                println!(
                    "no messages in stream {} from seq {}",
                    args.stream, args.from
                );
            }

            Ok(())
        }
        HubReference::Remote(client) => handle_stream_remote(client, args).await,
    }
}

async fn handle_stream_remote(client: HubHttpClient, args: StreamArgs) -> Result<()> {
    let mut query: Vec<(&str, String)> = vec![("stream", args.stream.clone())];
    if args.from > 0 {
        query.push(("from", args.from.to_string()));
    }

    let remote_messages: Vec<RemoteStoredMessage> = client
        .get_json("/stream", &query)
        .await
        .context("fetching stream messages")?;

    if remote_messages.is_empty() {
        println!(
            "no messages in stream {} from seq {}",
            args.stream, args.from
        );
        return Ok(());
    }

    for remote in remote_messages {
        let message: StoredMessage = remote.into();
        println!("seq: {}", message.seq);
        println!("sent_at: {}", message.sent_at);
        println!("client_id: {}", message.client_id);
        if let Some(ref schema) = message.schema {
            println!("schema: {schema}");
        }
        if let Some(expires_at) = message.expires_at {
            println!("expires_at: {expires_at}");
        }
        if let Some(ref parent) = message.parent {
            println!("parent: {parent}");
        }
        if let Some(ref auth_ref) = message.auth_ref {
            println!("auth_ref: {auth_ref}");
        }
        match (&message.body, &message.body_digest) {
            (Some(body), _) => println!("body: {body}"),
            (None, Some(digest)) => println!("body_digest: {digest}"),
            _ => println!("body: (omitted)"),
        }
        if message.attachments.is_empty() {
            println!("attachments: (none)");
        } else {
            println!("attachments:");
            for attachment in &message.attachments {
                println!(
                    "  {} ({} bytes) digest={} stored={}",
                    attachment.name, attachment.size, attachment.digest, attachment.stored_path
                );
            }
        }
        if args.with_proof {
            let proof = compute_message_proof(&message)?;
            println!("proof: {proof}");
        }
        println!("---");
    }

    Ok(())
}

async fn handle_attachment_verify(args: AttachmentVerifyArgs) -> Result<()> {
    let message: StoredMessage = read_json_file(&args.msg).await?;
    let index: usize = args.index as usize;
    if index >= message.attachments.len() {
        bail!(
            "message bundle {} does not have an attachment at index {}",
            args.msg.display(),
            args.index
        );
    }

    let attachment = &message.attachments[index];
    let data = fs::read(&args.file)
        .await
        .with_context(|| format!("reading attachment {}", args.file.display()))?;
    let digest = compute_digest_hex(&data);

    if digest != attachment.digest {
        bail!(
            "attachment digest mismatch: expected {}, computed {}",
            attachment.digest,
            digest
        );
    }

    println!(
        "attachment verified. digest={} size={} stored={}",
        attachment.digest, attachment.size, attachment.stored_path
    );
    Ok(())
}

async fn handle_cap_issue(args: CapIssueArgs) -> Result<()> {
    if args.ttl == 0 {
        bail!("ttl must be greater than zero seconds");
    }

    let issuer_keystore = args.issuer.join("keystore.enc");
    let issuer_secret: ClientSecretBundle = read_cbor_file(&issuer_keystore)
        .await
        .with_context(|| format!("reading issuer keystore from {}", issuer_keystore.display()))?;
    let signing_key_bytes: [u8; 32] = issuer_secret
        .signing_key
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("issuer signing key has invalid length"))?;
    let issuer_signing_key = SigningKey::from_bytes(&signing_key_bytes);

    let subject_bundle: ClientPublicBundle =
        read_cbor_file(&args.subject.join("identity_card.pub"))
            .await
            .with_context(|| format!("reading subject identity from {}", args.subject.display()))?;
    let subject_pk = ClientId::from_slice(subject_bundle.client_id.as_ref())
        .context("subject identity card contains malformed client_id")?;

    let stream_id = cap_stream_id_from_label(&args.stream)
        .with_context(|| format!("deriving stream identifier for {}", args.stream))?;

    let mut allow = CapTokenAllow::new(vec![stream_id], args.ttl);
    if let Some(rate) = args.rate.as_deref() {
        allow.rate = Some(parse_cap_rate(rate)?);
    }

    let token = CapToken::issue(&issuer_signing_key, subject_pk, allow)
        .context("issuing capability token")?;
    token
        .verify()
        .map_err(|err| anyhow!("capability token verification failed: {err}"))?;
    let auth_ref = token.auth_ref().context("computing capability auth_ref")?;

    write_cbor_file(&args.out, &token)
        .await
        .with_context(|| format!("writing capability token to {}", args.out.display()))?;

    println!("issued capability token (ver {CAP_TOKEN_VERSION})");
    println!("  issuer_pk: {}", hex::encode(token.issuer_pk.as_ref()));
    println!("  subject_pk: {}", hex::encode(token.subject_pk.as_ref()));
    println!("  stream_id: {}", hex::encode(stream_id.as_ref()));
    println!("  ttl: {} seconds", token.allow.ttl);
    if let Some(rate) = &token.allow.rate {
        println!("  rate: {}/{}", rate.per_sec, rate.burst);
    }
    println!("  auth_ref: {}", hex::encode(auth_ref.as_ref()));
    println!("  saved to {}", args.out.display());

    Ok(())
}

async fn handle_cap_authorize(args: CapAuthorizeArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Local(_) => {
            bail!("cap authorize requires an HTTP hub endpoint (e.g. http://host:port)")
        }
        HubReference::Remote(client) => handle_cap_authorize_remote(client, args).await,
    }
}

async fn handle_cap_authorize_remote(client: HubHttpClient, args: CapAuthorizeArgs) -> Result<()> {
    let token: CapToken = read_cbor_file(&args.cap)
        .await
        .with_context(|| format!("reading capability token from {}", args.cap.display()))?;
    token
        .verify()
        .map_err(|err| anyhow!("capability token verification failed: {err}"))?;
    let expected_auth_ref = token.auth_ref().context("computing capability auth_ref")?;
    let expected_hex = hex::encode(expected_auth_ref.as_ref());
    let encoded = token
        .to_cbor()
        .context("serializing capability token for submission")?;

    let response: RemoteAuthorizeResponse = client
        .post_cbor("/authorize", &encoded)
        .await
        .context("authorizing capability with hub")?;

    if response.auth_ref != expected_hex {
        bail!(
            "hub returned mismatched auth_ref {}; expected {expected_hex}",
            response.auth_ref
        );
    }

    println!("authorised capability");
    println!("  auth_ref: {}", response.auth_ref);
    println!("  expires_at: {}", response.expires_at);
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedEnvelope<T> {
    #[serde(with = "serde_bytes")]
    schema: ByteBuf,
    body: T,
    #[serde(with = "serde_bytes")]
    signature: ByteBuf,
}

const ADMIN_SIGNING_DOMAIN: &str = "veen/admin";
const WALLET_TRANSFER_DOMAIN: &str = "veen/cli-wallet-transfer";

async fn handle_authority_set(args: AuthoritySetArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => handle_authority_set_remote(client, args).await,
        HubReference::Local(_) => {
            bail!("authority set requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    }
}

async fn handle_authority_set_remote(client: HubHttpClient, args: AuthoritySetArgs) -> Result<()> {
    let signing_key = load_signing_key_from_dir(&args.signer).await?;
    let realm_id = RealmId::derive(&args.realm);
    let stream_id = cap_stream_id_from_label(&args.stream)
        .with_context(|| format!("deriving stream identifier for {}", args.stream))?;
    let primary_hub = parse_hub_id_hex(&args.primary_hub)?;
    let mut replica_hubs = Vec::new();
    for hub in &args.replica_hubs {
        replica_hubs.push(parse_hub_id_hex(hub)?);
    }

    if matches!(args.policy, AuthorityPolicyValue::MultiPrimary) && replica_hubs.is_empty() {
        bail!("multi-primary policy requires at least one replica hub");
    }

    let policy = match args.policy {
        AuthorityPolicyValue::SinglePrimary => AuthorityPolicy::SinglePrimary,
        AuthorityPolicyValue::MultiPrimary => AuthorityPolicy::MultiPrimary,
    };

    let ttl = args.ttl.unwrap_or(0);
    let ts = args.ts.unwrap_or(current_unix_timestamp()?);

    let record = AuthorityRecord {
        realm_id,
        stream_id,
        primary_hub,
        replica_hubs,
        policy,
        ts,
        ttl,
    };

    let payload = encode_signed_envelope(schema_fed_authority(), &record, &signing_key)?;
    submit_signed_payload(&client, "/authority", &payload).await?;

    println!("published authority record");
    println!("  realm: {}", args.realm);
    println!("  stream: {}", args.stream);
    println!("  policy: {:?}", args.policy);
    println!("  ttl: {}", ttl);
    Ok(())
}

fn encode_signed_envelope<T>(
    schema: [u8; 32],
    body: &T,
    signing_key: &SigningKey,
) -> Result<Vec<u8>>
where
    T: Serialize + Clone,
{
    let mut body_bytes = Vec::new();
    ciborium::ser::into_writer(body, &mut body_bytes)
        .map_err(|err| anyhow!("failed to encode payload body to CBOR: {err}"))?;

    let mut signing_input = Vec::with_capacity(schema.len() + body_bytes.len());
    signing_input.extend_from_slice(&schema);
    signing_input.extend_from_slice(&body_bytes);
    let digest = ht(ADMIN_SIGNING_DOMAIN, &signing_input);

    let signature = signing_key.sign(digest.as_ref());
    let envelope = SignedEnvelope {
        schema: ByteBuf::from(schema.to_vec()),
        body: body.clone(),
        signature: ByteBuf::from(signature.to_bytes().to_vec()),
    };

    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut encoded)
        .map_err(|err| anyhow!("failed to encode signed envelope to CBOR: {err}"))?;
    Ok(encoded)
}

async fn submit_signed_payload(client: &HubHttpClient, path: &str, payload: &[u8]) -> Result<()> {
    client.post_cbor_unit(path, payload).await
}

async fn load_signing_key_from_dir(dir: &Path) -> Result<SigningKey> {
    let keystore = dir.join("keystore.enc");
    let secret: ClientSecretBundle = read_cbor_file(&keystore)
        .await
        .with_context(|| format!("reading signing key from {}", keystore.display()))?;
    let signing_key_bytes: [u8; 32] = secret
        .signing_key
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("signing key has invalid length"))?;
    Ok(SigningKey::from_bytes(&signing_key_bytes))
}

fn parse_hub_id_hex(input: &str) -> Result<HubId> {
    let bytes = parse_hex_key::<{ HUB_ID_LEN }>(input)?;
    Ok(HubId::from(bytes))
}

fn parse_schema_id_hex(input: &str) -> Result<SchemaId> {
    let bytes = parse_hex_key::<{ SCHEMA_ID_LEN }>(input)?;
    Ok(SchemaId::from(bytes))
}

fn parse_schema_owner(input: &str) -> Result<SchemaOwner> {
    let data = if let Ok(contents) = std::fs::read_to_string(input) {
        contents.trim().to_string()
    } else {
        input.to_string()
    };
    let bytes = parse_hex_key::<{ SCHEMA_ID_LEN }>(&data)?;
    Ok(SchemaOwner::from(bytes))
}

fn parse_wallet_id_hex(input: &str) -> Result<WalletId> {
    let bytes = parse_hex_key::<{ WALLET_ID_LEN }>(input)?;
    Ok(WalletId::from(bytes))
}

fn parse_transfer_id_hex(input: &str) -> Result<TransferId> {
    let bytes = parse_hex_key::<{ TRANSFER_ID_LEN }>(input)?;
    Ok(TransferId::from(bytes))
}

fn parse_revocation_target_hex(input: &str) -> Result<RevocationTarget> {
    let bytes = parse_hex_key::<{ REVOCATION_TARGET_LEN }>(input)?;
    Ok(RevocationTarget::from(bytes))
}

fn parse_metadata_value(input: Option<String>) -> Result<Option<CborValue>> {
    if let Some(raw) = input {
        let json_value: serde_json::Value =
            serde_json::from_str(&raw).with_context(|| "metadata must be valid JSON")?;
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&json_value, &mut buf)
            .map_err(|err| anyhow!("failed to encode metadata to CBOR: {err}"))?;
        let value = ciborium::de::from_reader(buf.as_slice())
            .map_err(|err| anyhow!("failed to decode metadata CBOR value: {err}"))?;
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

async fn handle_label_class_set(args: LabelClassSetArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => handle_label_class_set_remote(client, args).await,
        HubReference::Local(_) => {
            bail!("label-class set requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    }
}

async fn handle_label_class_set_remote(
    client: HubHttpClient,
    args: LabelClassSetArgs,
) -> Result<()> {
    let signing_key = load_signing_key_from_dir(&args.signer).await?;
    let stream_id = cap_stream_id_from_label(&args.label)
        .with_context(|| format!("deriving stream identifier for {}", args.label))?;
    let label = Label::derive([], stream_id, 0);

    let record = LabelClassRecord {
        label,
        class: args.class.clone(),
        sensitivity: args.sensitivity.clone(),
        retention_hint: args.retention_hint,
    };

    let payload = encode_signed_envelope(schema_label_class(), &record, &signing_key)?;
    submit_signed_payload(&client, "/label-class", &payload).await?;

    println!("published label class");
    println!("  label: {}", args.label);
    println!("  class: {}", args.class);
    if let Some(sensitivity) = &args.sensitivity {
        println!("  sensitivity: {sensitivity}");
    }
    if let Some(retention) = args.retention_hint {
        println!("  retention_hint: {retention}");
    }
    Ok(())
}

async fn handle_schema_id(args: SchemaIdArgs) -> Result<()> {
    let digest = compute_schema_identifier(&args.name);
    println!("{}", hex::encode(digest));
    Ok(())
}

async fn handle_schema_register(args: SchemaRegisterArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => handle_schema_register_remote(client, args).await,
        HubReference::Local(_) => {
            bail!("schema register requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    }
}

async fn handle_schema_register_remote(
    client: HubHttpClient,
    args: SchemaRegisterArgs,
) -> Result<()> {
    let signing_key = load_signing_key_from_dir(&args.signer).await?;
    let schema_id = parse_schema_id_hex(&args.schema_id)?;
    let owner = match args.owner {
        Some(ref value) => Some(parse_schema_owner(value)?),
        None => None,
    };
    let ts = args.ts.unwrap_or(current_unix_timestamp()?);

    let descriptor = SchemaDescriptor {
        schema_id,
        name: args.name.clone(),
        version: args.version.clone(),
        doc_url: args.doc_url.clone(),
        owner,
        ts,
    };

    let payload = encode_signed_envelope(schema_meta_schema(), &descriptor, &signing_key)?;
    submit_signed_payload(&client, "/schema", &payload).await?;

    println!("registered schema");
    println!("  schema_id: {}", args.schema_id);
    println!("  name: {}", args.name);
    println!("  version: {}", args.version);
    Ok(())
}

async fn handle_schema_list(args: SchemaListArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => handle_schema_list_remote(client).await,
        HubReference::Local(_) => {
            bail!("schema list requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    }
}

async fn handle_schema_list_remote(client: HubHttpClient) -> Result<()> {
    let descriptors = fetch_schema_descriptors(&client).await?;

    if descriptors.is_empty() {
        println!("no schemas registered");
    } else {
        for descriptor in descriptors {
            println!(
                "schema_id: {}",
                hex::encode(descriptor.schema_id.as_bytes())
            );
            println!("  name: {}", descriptor.name);
            println!("  version: {}", descriptor.version);
            if let Some(doc_url) = descriptor.doc_url.as_deref() {
                println!("  doc_url: {doc_url}");
            }
            if let Some(owner) = descriptor.owner {
                println!("  owner: {}", hex::encode(owner.as_bytes()));
            }
            println!("  ts: {}", descriptor.ts);
        }
    }
    Ok(())
}

fn compute_schema_identifier(name: &str) -> [u8; 32] {
    h(name.as_bytes())
}

async fn fetch_schema_descriptors(client: &HubHttpClient) -> Result<Vec<SchemaDescriptor>> {
    client
        .get_json("/schema", &[])
        .await
        .context("fetching schema descriptors from hub")
}

async fn handle_wallet_transfer(args: WalletTransferArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => handle_wallet_transfer_remote(client, args).await,
        HubReference::Local(_) => {
            bail!("wallet transfer requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    }
}

async fn handle_wallet_transfer_remote(
    client: HubHttpClient,
    args: WalletTransferArgs,
) -> Result<()> {
    let signing_key = load_signing_key_from_dir(&args.signer).await?;
    let wallet_id = parse_wallet_id_hex(&args.wallet_id)?;
    let to_wallet_id = parse_wallet_id_hex(&args.to_wallet_id)?;
    let ts = args.ts.unwrap_or(current_unix_timestamp()?);
    let metadata = parse_metadata_value(args.metadata.clone())?;
    let transfer_id = if let Some(ref explicit) = args.transfer_id {
        parse_transfer_id_hex(explicit)?
    } else {
        let mut seed = Vec::new();
        seed.extend_from_slice(wallet_id.as_bytes());
        seed.extend_from_slice(to_wallet_id.as_bytes());
        seed.extend_from_slice(&args.amount.to_be_bytes());
        seed.extend_from_slice(&ts.to_be_bytes());
        TransferId::from(ht(WALLET_TRANSFER_DOMAIN, &seed))
    };

    let record = WalletTransferEvent {
        wallet_id,
        to_wallet_id,
        amount: args.amount,
        ts,
        transfer_id,
        metadata,
    };

    let payload = encode_signed_envelope(schema_wallet_transfer(), &record, &signing_key)?;
    submit_signed_payload(&client, "/wallet/transfer", &payload).await?;

    println!("submitted wallet transfer");
    println!("  wallet_id: {}", args.wallet_id);
    println!("  to_wallet_id: {}", args.to_wallet_id);
    println!("  amount: {}", args.amount);
    println!("  transfer_id: {}", hex::encode(transfer_id.as_bytes()));
    Ok(())
}

async fn handle_revoke_publish(args: RevokePublishArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => handle_revoke_publish_remote(client, args).await,
        HubReference::Local(_) => {
            bail!("revoke publish requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    }
}

async fn handle_revoke_publish_remote(
    client: HubHttpClient,
    args: RevokePublishArgs,
) -> Result<()> {
    let signing_key = load_signing_key_from_dir(&args.signer).await?;
    let target = parse_revocation_target_hex(&args.target)?;
    let kind = match args.kind {
        RevocationKindValue::ClientId => RevocationKind::ClientId,
        RevocationKindValue::AuthRef => RevocationKind::AuthRef,
        RevocationKindValue::CapToken => RevocationKind::CapToken,
    };
    let ts = args.ts.unwrap_or(current_unix_timestamp()?);

    let record = RevocationRecord {
        kind,
        target,
        reason: args.reason.clone(),
        ts,
        ttl: args.ttl,
    };

    let payload = encode_signed_envelope(schema_revocation(), &record, &signing_key)?;
    submit_signed_payload(&client, "/revoke", &payload).await?;

    println!("published revocation");
    println!("  kind: {:?}", args.kind);
    println!("  target: {}", args.target);
    if let Some(reason) = &args.reason {
        println!("  reason: {reason}");
    }
    if let Some(ttl) = args.ttl {
        println!("  ttl: {ttl}");
    }
    Ok(())
}

async fn handle_resync(args: ResyncArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Local(data_dir) => handle_resync_local(data_dir, args).await,
        HubReference::Remote(client) => handle_resync_remote(client, args).await,
    }
}

async fn handle_resync_local(data_dir: PathBuf, args: ResyncArgs) -> Result<()> {
    let hub_state = load_hub_state(&data_dir).await?;
    let profile_id = hub_state.profile_id.clone().unwrap_or_default();

    let seq = hub_state
        .last_stream_seq
        .get(&args.stream)
        .copied()
        .unwrap_or(0);
    let mut client_state: ClientStateFile = read_json_file(&args.client.join("state.json")).await?;

    if let Some(existing_profile) = &client_state.profile_id {
        if !existing_profile.is_empty() && *existing_profile != profile_id {
            bail!(
                "client profile {} does not match hub profile {}",
                existing_profile,
                profile_id
            );
        }
    } else if !profile_id.is_empty() {
        client_state.profile_id = Some(profile_id.clone());
    }

    let label_state = client_state.ensure_label_state(&args.stream);
    label_state.last_stream_seq = seq;
    label_state.prev_ack = seq;
    write_json_file(&args.client.join("state.json"), &client_state).await?;

    println!("resynchronised stream {} to seq {}", args.stream, seq);
    Ok(())
}

async fn handle_resync_remote(client: HubHttpClient, args: ResyncArgs) -> Result<()> {
    #[derive(Serialize)]
    struct ResyncRequestPayload {
        stream: String,
    }

    let payload = ResyncRequestPayload {
        stream: args.stream.clone(),
    };

    let remote_state: RemoteHubStreamState = client
        .post_json("/resync", &payload)
        .await
        .context("requesting resync from hub")?;

    let seq = remote_state.messages.last().map(|msg| msg.seq).unwrap_or(0);

    let mut client_state: ClientStateFile = read_json_file(&args.client.join("state.json")).await?;
    let label_state = client_state.ensure_label_state(&args.stream);
    label_state.last_stream_seq = seq;
    label_state.prev_ack = seq;
    write_json_file(&args.client.join("state.json"), &client_state).await?;

    println!("resynchronised stream {} to seq {}", args.stream, seq);
    Ok(())
}

async fn handle_verify_state(args: VerifyStateArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?.into_local()?;
    let hub_state = load_hub_state(&data_dir).await?;
    let client_state: ClientStateFile = read_json_file(&args.client.join("state.json")).await?;

    let hub_seq = hub_state
        .last_stream_seq
        .get(&args.stream)
        .copied()
        .unwrap_or(0);
    let client_seq = client_state
        .labels
        .get(&args.stream)
        .map(|label| label.last_stream_seq)
        .unwrap_or(0);

    if client_seq > hub_seq {
        bail!(
            "client sequence {} is ahead of hub {} for stream {}",
            client_seq,
            hub_seq,
            args.stream
        );
    }

    println!("hub seq: {hub_seq}");
    println!("client seq: {client_seq}");
    println!("state verified: client is synchronised with hub");
    Ok(())
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

async fn handle_rpc_call(args: RpcCallArgs) -> Result<()> {
    let parsed_args: serde_json::Value = match serde_json::from_str(&args.args) {
        Ok(value) => value,
        Err(_) => json!(args.args),
    };

    let payload = json!({
        "method": args.method,
        "args": parsed_args,
        "timeout_ms": args.timeout_ms,
        "idem": args.idem,
    })
    .to_string();

    let now = current_unix_timestamp()?;
    let send_args = SendArgs {
        hub: args.hub,
        client: args.client,
        stream: args.stream,
        body: payload,
        schema: Some(format!("rpc0:{}", compute_digest_hex(b"rpc"))),
        expires_at: args.timeout_ms.map(|ms| now + ms / 1000),
        cap: None,
        parent: None,
        attach: Vec::new(),
        no_store_body: false,
    };

    handle_send(send_args).await
}

async fn handle_crdt_lww_set(args: CrdtLwwSetArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?.into_local()?;
    ensure_crdt_stream_dir(&data_dir, &args.stream).await?;
    let mut state = load_lww_state(&data_dir, &args.stream).await?;
    let timestamp = args.ts.unwrap_or(current_unix_timestamp()?);
    ensure_client_label_exists(&args.client, &args.stream).await?;

    state.entries.insert(
        args.key.clone(),
        LwwRegisterValue {
            value: args.value.clone(),
            timestamp,
        },
    );
    save_lww_state(&data_dir, &args.stream, &state).await?;

    println!(
        "lww set stream={} key={} value={} ts={}",
        args.stream, args.key, args.value, timestamp
    );
    Ok(())
}

async fn handle_crdt_lww_get(args: CrdtLwwGetArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?.into_local()?;
    ensure_client_label_exists(&args.client, &args.stream).await?;
    let state = load_lww_state(&data_dir, &args.stream).await?;
    if let Some(value) = state.entries.get(&args.key) {
        println!("value: {}", value.value);
        println!("timestamp: {}", value.timestamp);
    } else {
        println!("value: (none)");
    }
    Ok(())
}

async fn handle_crdt_orset_add(args: CrdtOrsetAddArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?.into_local()?;
    ensure_crdt_stream_dir(&data_dir, &args.stream).await?;
    let mut state = load_orset_state(&data_dir, &args.stream).await?;
    let now = current_unix_timestamp()?;
    ensure_client_label_exists(&args.client, &args.stream).await?;
    state.elements.push(OrsetElement {
        value: args.elem.clone(),
        added_at: now,
        removed_at: None,
    });
    save_orset_state(&data_dir, &args.stream, &state).await?;
    println!(
        "orset add stream={} elem={} ts={}",
        args.stream, args.elem, now
    );
    Ok(())
}

async fn handle_crdt_orset_remove(args: CrdtOrsetRemoveArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?.into_local()?;
    ensure_client_label_exists(&args.client, &args.stream).await?;
    let mut state = load_orset_state(&data_dir, &args.stream).await?;
    let now = current_unix_timestamp()?;
    let mut removed = false;
    for element in state.elements.iter_mut().rev() {
        if element.value == args.elem && element.removed_at.is_none() {
            element.removed_at = Some(now);
            removed = true;
            break;
        }
    }
    if !removed {
        bail!("element {} not present in OR-set", args.elem);
    }
    save_orset_state(&data_dir, &args.stream, &state).await?;
    println!(
        "orset removed stream={} elem={} ts={}",
        args.stream, args.elem, now
    );
    Ok(())
}

async fn handle_crdt_orset_list(args: CrdtOrsetListArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?.into_local()?;
    ensure_client_label_exists(&args.client, &args.stream).await?;
    let state = load_orset_state(&data_dir, &args.stream).await?;
    let mut visible: BTreeSet<&String> = BTreeSet::new();
    for element in state.elements.iter() {
        if element.removed_at.is_none() {
            visible.insert(&element.value);
        }
    }
    if visible.is_empty() {
        println!("orset elements: (empty)");
    } else {
        println!("orset elements:");
        for value in visible {
            println!("  {value}");
        }
    }
    Ok(())
}

async fn handle_crdt_counter_add(args: CrdtCounterAddArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?.into_local()?;
    ensure_crdt_stream_dir(&data_dir, &args.stream).await?;
    ensure_client_label_exists(&args.client, &args.stream).await?;
    let mut state = load_counter_state(&data_dir, &args.stream).await?;
    state.value = state.value.saturating_add(args.delta);
    save_counter_state(&data_dir, &args.stream, &state).await?;
    println!("counter value={} after adding {}", state.value, args.delta);
    Ok(())
}

async fn handle_crdt_counter_get(args: CrdtCounterGetArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?.into_local()?;
    ensure_client_label_exists(&args.client, &args.stream).await?;
    let state = load_counter_state(&data_dir, &args.stream).await?;
    println!("counter value={}", state.value);
    Ok(())
}

async fn handle_anchor_publish(args: AnchorPublishArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?.into_local()?;
    let mut log = load_anchor_log(&data_dir).await?;
    let ts = args.ts.unwrap_or(current_unix_timestamp()?);

    let record = AnchorRecord {
        stream: args.stream.clone(),
        epoch: args.epoch,
        ts,
        nonce: args.nonce.clone(),
    };
    log.entries.push(record);
    save_anchor_log(&data_dir, &log).await?;

    println!(
        "queued anchor publication for stream {} at ts {}",
        args.stream, ts
    );
    Ok(())
}

async fn handle_anchor_verify(args: AnchorVerifyArgs) -> Result<()> {
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
        .context("computing checkpoint digest")?;

    println!("checkpoint version: {}", checkpoint.ver);
    println!(
        "label_prev: {}",
        hex::encode(checkpoint.label_prev.as_ref())
    );
    println!(
        "label_curr: {}",
        hex::encode(checkpoint.label_curr.as_ref())
    );
    println!("upto_seq: {}", checkpoint.upto_seq);
    println!("epoch: {}", checkpoint.epoch);
    println!("mmr_root: {}", hex::encode(checkpoint.mmr_root.as_ref()));
    println!("digest: {}", hex::encode(digest));
    println!(
        "witness_sigs: {}",
        checkpoint
            .witness_sigs
            .as_ref()
            .map(|w| w.len())
            .unwrap_or(0)
    );
    println!("anchor verification complete (signature validation requires hub public key)");
    Ok(())
}

async fn handle_retention_show(args: RetentionShowArgs) -> Result<()> {
    let data_dir = &args.data_dir;
    let retention_path = data_dir.join(STATE_DIR).join(RETENTION_CONFIG_FILE);
    let retention: serde_json::Value = if fs::try_exists(&retention_path)
        .await
        .with_context(|| format!("checking retention config {}", retention_path.display()))?
    {
        read_json_file(&retention_path).await?
    } else {
        json!({
            "receipts": "indefinite",
            "payloads": "indefinite",
            "checkpoints": "indefinite"
        })
    };

    let retention_pretty =
        serde_json::to_string_pretty(&retention).context("formatting retention configuration")?;
    println!("configured retention: {retention_pretty}");

    let receipts = file_stats(&data_dir.join(RECEIPTS_FILE)).await?;
    let payloads = file_stats(&data_dir.join(PAYLOADS_FILE)).await?;
    let checkpoints = file_stats(&data_dir.join(CHECKPOINTS_FILE)).await?;

    print_retention_entry("receipts", receipts);
    print_retention_entry("payloads", payloads);
    print_retention_entry("checkpoints", checkpoints);

    Ok(())
}

async fn handle_selftest_core() -> Result<()> {
    println!("running VEEN core self-tests...");
    veen_selftest::run_core().await
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
    veen_selftest::run_all().await
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
    let state_dir = data_dir.join(STATE_DIR);
    fs::create_dir_all(&state_dir)
        .await
        .with_context(|| format!("creating state dir under {}", data_dir.display()))?;
    fs::create_dir_all(state_dir.join(STREAMS_DIR))
        .await
        .with_context(|| format!("creating streams dir under {}", data_dir.display()))?;
    fs::create_dir_all(state_dir.join(MESSAGES_DIR))
        .await
        .with_context(|| format!("creating messages dir under {}", data_dir.display()))?;
    fs::create_dir_all(state_dir.join(CAP_TOKENS_DIR))
        .await
        .with_context(|| format!("creating capabilities dir under {}", data_dir.display()))?;
    fs::create_dir_all(state_dir.join(CRDT_DIR))
        .await
        .with_context(|| format!("creating CRDT dir under {}", data_dir.display()))?;
    fs::create_dir_all(state_dir.join(ATTACHMENTS_DIR))
        .await
        .with_context(|| format!("creating attachments dir under {}", data_dir.display()))?;

    Ok(())
}

async fn flush_hub_storage(data_dir: &Path) -> Result<()> {
    flush_file_if_exists(&data_dir.join(RECEIPTS_FILE)).await?;
    flush_file_if_exists(&data_dir.join(PAYLOADS_FILE)).await?;
    flush_file_if_exists(&data_dir.join(CHECKPOINTS_FILE)).await?;
    flush_file_if_exists(&data_dir.join(STATE_DIR).join(ANCHOR_LOG_FILE)).await?;
    Ok(())
}

async fn flush_file_if_exists(path: &Path) -> Result<()> {
    if !fs::try_exists(path)
        .await
        .with_context(|| format!("checking {} before flush", path.display()))?
    {
        return Ok(());
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .await
        .with_context(|| format!("opening {} for flush", path.display()))?;
    file.sync_all()
        .await
        .with_context(|| format!("flushing {}", path.display()))?;
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

async fn ensure_tls_info(data_dir: &Path) -> Result<()> {
    let path = data_dir.join(STATE_DIR).join(TLS_INFO_FILE);
    if fs::try_exists(&path)
        .await
        .with_context(|| format!("checking TLS info file {}", path.display()))?
    {
        return Ok(());
    }

    let info = TlsInfoSnapshot::default();
    write_json_file(&path, &info)
        .await
        .with_context(|| format!("writing TLS metadata to {}", path.display()))?;
    Ok(())
}

fn stream_storage_name(stream: &str) -> String {
    let mut safe = String::with_capacity(stream.len());
    for ch in stream.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            safe.push(ch);
        } else if ch.is_whitespace() {
            safe.push('_');
        } else {
            safe.push('-');
        }
    }
    if safe.is_empty() {
        safe.push_str("stream");
    }
    let digest = Sha256::digest(stream.as_bytes());
    let suffix = hex::encode(&digest[..8]);
    format!("{safe}-{suffix}")
}

fn stream_state_path(data_dir: &Path, stream: &str) -> PathBuf {
    let name = stream_storage_name(stream);
    data_dir
        .join(STATE_DIR)
        .join(STREAMS_DIR)
        .join(format!("{name}.json"))
}

fn message_bundle_path(data_dir: &Path, stream: &str, seq: u64) -> PathBuf {
    let name = stream_storage_name(stream);
    data_dir
        .join(STATE_DIR)
        .join(MESSAGES_DIR)
        .join(format!("{name}-{seq:08}.json"))
}

fn attachments_storage_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(STATE_DIR).join(ATTACHMENTS_DIR)
}

fn crdt_stream_dir(data_dir: &Path, stream: &str) -> PathBuf {
    let name = stream_storage_name(stream);
    data_dir.join(STATE_DIR).join(CRDT_DIR).join(name)
}

fn lww_state_path(data_dir: &Path, stream: &str) -> PathBuf {
    crdt_stream_dir(data_dir, stream).join("lww.json")
}

fn orset_state_path(data_dir: &Path, stream: &str) -> PathBuf {
    crdt_stream_dir(data_dir, stream).join("orset.json")
}

fn counter_state_path(data_dir: &Path, stream: &str) -> PathBuf {
    crdt_stream_dir(data_dir, stream).join("counter.json")
}

async fn ensure_crdt_stream_dir(data_dir: &Path, stream: &str) -> Result<()> {
    let dir = crdt_stream_dir(data_dir, stream);
    fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("ensuring CRDT directory {}", dir.display()))?;
    Ok(())
}

async fn load_lww_state(data_dir: &Path, stream: &str) -> Result<LwwRegisterState> {
    let path = lww_state_path(data_dir, stream);
    if fs::try_exists(&path)
        .await
        .with_context(|| format!("checking LWW state {}", path.display()))?
    {
        read_json_file(&path).await
    } else {
        Ok(LwwRegisterState::default())
    }
}

async fn save_lww_state(data_dir: &Path, stream: &str, state: &LwwRegisterState) -> Result<()> {
    let path = lww_state_path(data_dir, stream);
    write_json_file(&path, state)
        .await
        .with_context(|| format!("writing LWW state to {}", path.display()))
}

async fn load_orset_state(data_dir: &Path, stream: &str) -> Result<OrsetState> {
    let path = orset_state_path(data_dir, stream);
    if fs::try_exists(&path)
        .await
        .with_context(|| format!("checking OR-set state {}", path.display()))?
    {
        read_json_file(&path).await
    } else {
        Ok(OrsetState::default())
    }
}

async fn save_orset_state(data_dir: &Path, stream: &str, state: &OrsetState) -> Result<()> {
    let path = orset_state_path(data_dir, stream);
    write_json_file(&path, state)
        .await
        .with_context(|| format!("writing OR-set state to {}", path.display()))
}

async fn load_counter_state(data_dir: &Path, stream: &str) -> Result<CounterState> {
    let path = counter_state_path(data_dir, stream);
    if fs::try_exists(&path)
        .await
        .with_context(|| format!("checking counter state {}", path.display()))?
    {
        read_json_file(&path).await
    } else {
        Ok(CounterState::default())
    }
}

async fn save_counter_state(data_dir: &Path, stream: &str, state: &CounterState) -> Result<()> {
    let path = counter_state_path(data_dir, stream);
    write_json_file(&path, state)
        .await
        .with_context(|| format!("writing counter state to {}", path.display()))
}

async fn load_anchor_log(data_dir: &Path) -> Result<AnchorLog> {
    let path = data_dir.join(ANCHORS_DIR).join(ANCHOR_LOG_FILE);
    if fs::try_exists(&path)
        .await
        .with_context(|| format!("checking anchor log {}", path.display()))?
    {
        read_json_file(&path).await
    } else {
        Ok(AnchorLog::default())
    }
}

async fn save_anchor_log(data_dir: &Path, log: &AnchorLog) -> Result<()> {
    let path = data_dir.join(ANCHORS_DIR).join(ANCHOR_LOG_FILE);
    write_json_file(&path, log)
        .await
        .with_context(|| format!("writing anchor log to {}", path.display()))
}

async fn file_stats(path: &Path) -> Result<Option<(u64, u64)>> {
    match fs::metadata(path).await {
        Ok(metadata) => {
            if !metadata.is_file() {
                return Ok(None);
            }
            let size = metadata.len();
            let mtime = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            Ok(Some((size, mtime)))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(anyhow!(err)).context(format!("reading metadata for {}", path.display())),
    }
}

fn print_retention_entry(name: &str, stats: Option<(u64, u64)>) {
    if let Some((size, mtime)) = stats {
        println!("{name}: size={} bytes last_modified={} (unix)", size, mtime);
    } else {
        println!("{name}: (absent)");
    }
}

async fn ensure_client_label_exists(client_dir: &Path, stream: &str) -> Result<()> {
    let state_path = client_dir.join("state.json");
    if !fs::try_exists(&state_path)
        .await
        .with_context(|| format!("checking client state {}", state_path.display()))?
    {
        return Ok(());
    }

    let mut state: ClientStateFile = read_json_file(&state_path).await?;
    state.ensure_label_state(stream);
    write_json_file(&state_path, &state).await?;
    Ok(())
}

async fn load_stream_state(data_dir: &Path, stream: &str) -> Result<HubStreamState> {
    let path = stream_state_path(data_dir, stream);
    if fs::try_exists(&path)
        .await
        .with_context(|| format!("checking stream state {}", path.display()))?
    {
        read_json_file(&path).await
    } else {
        Ok(HubStreamState::default())
    }
}

async fn save_stream_state(data_dir: &Path, stream: &str, state: &HubStreamState) -> Result<()> {
    let path = stream_state_path(data_dir, stream);
    write_json_file(&path, state)
        .await
        .with_context(|| format!("persisting stream state to {}", path.display()))
}

async fn append_receipt<T>(data_dir: &Path, file: &str, value: &T) -> Result<()>
where
    T: Serialize,
{
    let path = data_dir.join(file);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(value, &mut encoded)
        .map_err(|err| anyhow!("serialising CBOR sequence for {}: {err}", path.display()))?;
    let mut handle = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
        .with_context(|| format!("opening {} for append", path.display()))?;
    handle
        .write_all(&encoded)
        .await
        .with_context(|| format!("appending CBOR sequence to {}", path.display()))?;
    Ok(())
}

fn compute_digest_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

fn compute_message_proof(message: &StoredMessage) -> Result<String> {
    let encoded = serde_json::to_vec(message).context("encoding message for proof computation")?;
    Ok(compute_digest_hex(&encoded))
}

fn parse_cap_rate(input: &str) -> Result<CapTokenRate> {
    let parts: Vec<&str> = input.split(',').collect();
    if parts.len() != 2 {
        bail!("rate must be provided as per_sec,burst");
    }
    let per_sec = parts[0]
        .trim()
        .parse::<u64>()
        .context("parsing rate per_sec component")?;
    let burst = parts[1]
        .trim()
        .parse::<u64>()
        .context("parsing rate burst component")?;
    Ok(CapTokenRate::new(per_sec, burst))
}

fn ensure_capability_matches(
    token: &CapToken,
    subject: &ClientId,
    stream_id: &StreamId,
) -> Result<()> {
    if &token.subject_pk != subject {
        bail!("capability subject does not match client identity");
    }
    if !token.allow.stream_ids.iter().any(|id| id == stream_id) {
        bail!(
            "capability does not permit stream {}; allowed={:?}",
            hex::encode(stream_id.as_ref()),
            token
                .allow
                .stream_ids
                .iter()
                .map(|id| hex::encode(id.as_ref()))
                .collect::<Vec<_>>()
        );
    }
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

#[derive(Clone)]
enum HubReference {
    Local(PathBuf),
    Remote(HubHttpClient),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::de::from_reader;
    use ed25519_dalek::{Signature, Verifier};
    use hyper::body::to_bytes;
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request as HyperRequest, Response as HyperResponse, Server, StatusCode};
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::sync::mpsc;
    use tokio::time::sleep;
    use veen_hub::config::{HubConfigOverrides, HubRole, HubRuntimeConfig};
    use veen_hub::runtime::HubRuntime;

    async fn spawn_cbor_capture_server(
        path: &'static str,
    ) -> anyhow::Result<(String, mpsc::Receiver<Vec<u8>>, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr: SocketAddr = listener.local_addr()?;
        let (tx, rx) = mpsc::channel(1);
        let service = make_service_fn(move |_| {
            let tx = tx.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |mut req: HyperRequest<Body>| {
                    let tx = tx.clone();
                    async move {
                        assert_eq!(req.uri().path(), path);
                        let body = to_bytes(req.body_mut()).await.unwrap().to_vec();
                        tx.send(body).await.unwrap();
                        Ok::<_, Infallible>(
                            HyperResponse::builder()
                                .status(StatusCode::OK)
                                .body(Body::from("null"))
                                .unwrap(),
                        )
                    }
                }))
            }
        });
        let server = Server::from_tcp(listener)?.serve(service);
        let handle = tokio::spawn(async move {
            if let Err(err) = server.await {
                eprintln!("capture server error: {err}");
            }
        });
        Ok((format!("http://{}", addr), rx, handle))
    }

    async fn spawn_fixed_response_server(
        path: &'static str,
        body: Vec<u8>,
    ) -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr: SocketAddr = listener.local_addr()?;
        let body = Arc::new(body);
        let service = make_service_fn(move |_| {
            let body = body.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req: HyperRequest<Body>| {
                    let body = body.clone();
                    async move {
                        assert_eq!(req.uri().path(), path);
                        Ok::<_, Infallible>(
                            HyperResponse::builder()
                                .status(StatusCode::OK)
                                .body(Body::from(body.as_ref().clone()))
                                .unwrap(),
                        )
                    }
                }))
            }
        });
        let server = Server::from_tcp(listener)?.serve(service);
        let handle = tokio::spawn(async move {
            if let Err(err) = server.await {
                eprintln!("fixed response server error: {err}");
            }
        });
        Ok((format!("http://{}", addr), handle))
    }

    fn verify_envelope_signature<T>(
        envelope: &SignedEnvelope<T>,
        schema: [u8; 32],
        signing_key: &SigningKey,
    ) -> anyhow::Result<()>
    where
        T: Serialize,
    {
        let verifying_key = signing_key.verifying_key();
        let mut body_bytes = Vec::new();
        ciborium::ser::into_writer(&envelope.body, &mut body_bytes)?;
        let mut signing_input = Vec::with_capacity(schema.len() + body_bytes.len());
        signing_input.extend_from_slice(&schema);
        signing_input.extend_from_slice(&body_bytes);
        let digest = ht(ADMIN_SIGNING_DOMAIN, &signing_input);
        let signature_bytes: [u8; 64] = envelope
            .signature
            .as_ref()
            .try_into()
            .map_err(|_| anyhow!("invalid signature length"))?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify(digest.as_ref(), &signature)
            .map_err(|err| anyhow!("signature verification failed: {err}"))?;
        Ok(())
    }

    #[tokio::test]
    async fn http_send_stream_and_resync() -> anyhow::Result<()> {
        let hub_dir = tempdir()?;
        let client_dir = tempdir()?;

        let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let listen: SocketAddr = socket.local_addr()?;
        drop(socket);
        let config = HubRuntimeConfig::from_sources(
            listen,
            hub_dir.path().to_path_buf(),
            None,
            HubRole::Primary,
            HubConfigOverrides {
                capability_gating_enabled: Some(false),
                ..Default::default()
            },
        )
        .await?;
        let runtime = HubRuntime::start(config).await?;
        let hub_url = format!("http://{}", listen);

        sleep(Duration::from_millis(50)).await;

        handle_keygen(KeygenArgs {
            out: client_dir.path().to_path_buf(),
        })
        .await?;

        handle_send(SendArgs {
            hub: hub_url.clone(),
            client: client_dir.path().to_path_buf(),
            stream: "test".to_string(),
            body: json!({ "msg": "hello" }).to_string(),
            schema: None,
            expires_at: None,
            cap: None,
            parent: None,
            attach: Vec::new(),
            no_store_body: false,
        })
        .await?;

        handle_stream(StreamArgs {
            hub: hub_url.clone(),
            client: client_dir.path().to_path_buf(),
            stream: "test".to_string(),
            from: 0,
            with_proof: false,
        })
        .await?;

        handle_resync(ResyncArgs {
            hub: hub_url,
            client: client_dir.path().to_path_buf(),
            stream: "test".to_string(),
        })
        .await?;

        let state_path = client_dir.path().join("state.json");
        let state: ClientStateFile = read_json_file(&state_path).await?;
        let seq = state
            .labels
            .get("test")
            .map(|label| label.last_stream_seq)
            .unwrap_or(0);
        assert_eq!(seq, 1);

        runtime.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn write_json_file_creates_parent_directories() -> anyhow::Result<()> {
        let temp = tempdir()?;
        let path = temp.path().join("nested").join("dir").join("config.json");
        let payload = json!({ "hello": "world" });

        write_json_file(&path, &payload).await?;
        let roundtrip: Value = read_json_file(&path).await?;

        assert_eq!(roundtrip, payload);
        Ok(())
    }

    #[tokio::test]
    async fn write_cbor_file_creates_parent_directories() -> anyhow::Result<()> {
        let temp = tempdir()?;
        let path = temp.path().join("nested").join("dir").join("payload.cbor");
        let mut payload = BTreeMap::new();
        payload.insert(String::from("value"), 42u32);

        write_cbor_file(&path, &payload).await?;
        let roundtrip: BTreeMap<String, u32> = read_cbor_file(&path).await?;

        assert_eq!(roundtrip, payload);
        Ok(())
    }

    #[tokio::test]
    async fn authority_set_produces_signed_payload() -> anyhow::Result<()> {
        let signer_dir = tempdir()?;
        handle_keygen(KeygenArgs {
            out: signer_dir.path().to_path_buf(),
        })
        .await?;

        let (url, mut body_rx, server) = spawn_cbor_capture_server("/authority").await?;
        let client = HubHttpClient::new(Url::parse(&url)?, HttpClient::builder().build()?);
        let primary_hex = hex::encode([0x11u8; HUB_ID_LEN]);
        let replica_hex = hex::encode([0x22u8; HUB_ID_LEN]);
        let args = AuthoritySetArgs {
            hub: url.clone(),
            signer: signer_dir.path().to_path_buf(),
            realm: "default".to_string(),
            stream: "fed/chat".to_string(),
            policy: AuthorityPolicyValue::SinglePrimary,
            primary_hub: primary_hex.clone(),
            replica_hubs: vec![replica_hex.clone()],
            ttl: Some(3_600),
            ts: Some(1_234_567),
        };

        handle_authority_set_remote(client, args).await?;
        let body = body_rx.recv().await.expect("payload captured");
        server.abort();

        let envelope: SignedEnvelope<AuthorityRecord> = from_reader(body.as_slice())?;
        assert_eq!(envelope.schema.as_ref(), schema_fed_authority().as_slice());
        assert_eq!(envelope.body.primary_hub, parse_hub_id_hex(&primary_hex)?);
        assert_eq!(envelope.body.replica_hubs.len(), 1);
        assert_eq!(
            envelope.body.replica_hubs[0],
            parse_hub_id_hex(&replica_hex)?
        );
        assert_eq!(envelope.body.policy, AuthorityPolicy::SinglePrimary);
        assert_eq!(envelope.body.ttl, 3_600);
        assert_eq!(envelope.body.ts, 1_234_567);

        let keystore = signer_dir.path().join("keystore.enc");
        let secret: ClientSecretBundle = read_cbor_file(&keystore).await?;
        let signing_key_bytes: [u8; 32] = secret.signing_key.as_ref().try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        verify_envelope_signature(&envelope, schema_fed_authority(), &signing_key)?;

        Ok(())
    }

    #[tokio::test]
    async fn label_class_set_produces_signed_payload() -> anyhow::Result<()> {
        let signer_dir = tempdir()?;
        handle_keygen(KeygenArgs {
            out: signer_dir.path().to_path_buf(),
        })
        .await?;

        let (url, mut body_rx, server) = spawn_cbor_capture_server("/label-class").await?;
        let client = HubHttpClient::new(Url::parse(&url)?, HttpClient::builder().build()?);
        let args = LabelClassSetArgs {
            hub: url.clone(),
            signer: signer_dir.path().to_path_buf(),
            realm: "default".to_string(),
            label: "chat/general".to_string(),
            class: "user".to_string(),
            sensitivity: Some("medium".to_string()),
            retention_hint: Some(86_400),
        };

        handle_label_class_set_remote(client, args).await?;
        let body = body_rx.recv().await.expect("payload captured");
        server.abort();

        let envelope: SignedEnvelope<LabelClassRecord> = from_reader(body.as_slice())?;
        assert_eq!(envelope.schema.as_ref(), schema_label_class().as_slice());
        assert_eq!(envelope.body.class, "user");
        assert_eq!(envelope.body.sensitivity.as_deref(), Some("medium"));
        assert_eq!(envelope.body.retention_hint, Some(86_400));
        let stream_id = cap_stream_id_from_label("chat/general")?;
        let expected_label = Label::derive([], stream_id, 0);
        assert_eq!(envelope.body.label, expected_label);

        let keystore = signer_dir.path().join("keystore.enc");
        let secret: ClientSecretBundle = read_cbor_file(&keystore).await?;
        let signing_key_bytes: [u8; 32] = secret.signing_key.as_ref().try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        verify_envelope_signature(&envelope, schema_label_class(), &signing_key)?;

        Ok(())
    }

    #[tokio::test]
    async fn schema_register_produces_signed_payload() -> anyhow::Result<()> {
        let signer_dir = tempdir()?;
        handle_keygen(KeygenArgs {
            out: signer_dir.path().to_path_buf(),
        })
        .await?;

        let (url, mut body_rx, server) = spawn_cbor_capture_server("/schema").await?;
        let client = HubHttpClient::new(Url::parse(&url)?, HttpClient::builder().build()?);
        let schema_id_hex = hex::encode([0xAAu8; SCHEMA_ID_LEN]);
        let args = SchemaRegisterArgs {
            hub: url.clone(),
            signer: signer_dir.path().to_path_buf(),
            schema_id: schema_id_hex.clone(),
            name: "wallet.transfer.v1".to_string(),
            version: "v1".to_string(),
            doc_url: Some("https://example.com".to_string()),
            owner: None,
            ts: Some(99),
        };

        handle_schema_register_remote(client, args).await?;
        let body = body_rx.recv().await.expect("payload captured");
        server.abort();

        let envelope: SignedEnvelope<SchemaDescriptor> = from_reader(body.as_slice())?;
        assert_eq!(envelope.schema.as_ref(), schema_meta_schema().as_slice());
        assert_eq!(
            hex::encode(envelope.body.schema_id.as_bytes()),
            schema_id_hex
        );
        assert_eq!(envelope.body.name, "wallet.transfer.v1");
        assert_eq!(envelope.body.version, "v1");
        assert_eq!(
            envelope.body.doc_url.as_deref(),
            Some("https://example.com")
        );
        assert_eq!(envelope.body.owner, None);
        assert_eq!(envelope.body.ts, 99);

        let keystore = signer_dir.path().join("keystore.enc");
        let secret: ClientSecretBundle = read_cbor_file(&keystore).await?;
        let signing_key_bytes: [u8; 32] = secret.signing_key.as_ref().try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        verify_envelope_signature(&envelope, schema_meta_schema(), &signing_key)?;

        Ok(())
    }

    #[tokio::test]
    async fn wallet_transfer_produces_signed_payload() -> anyhow::Result<()> {
        let signer_dir = tempdir()?;
        handle_keygen(KeygenArgs {
            out: signer_dir.path().to_path_buf(),
        })
        .await?;

        let (url, mut body_rx, server) = spawn_cbor_capture_server("/wallet/transfer").await?;
        let client = HubHttpClient::new(Url::parse(&url)?, HttpClient::builder().build()?);
        let wallet_hex = hex::encode([0x55u8; WALLET_ID_LEN]);
        let to_wallet_hex = hex::encode([0x66u8; WALLET_ID_LEN]);
        let args = WalletTransferArgs {
            hub: url.clone(),
            signer: signer_dir.path().to_path_buf(),
            wallet_id: wallet_hex.clone(),
            to_wallet_id: to_wallet_hex.clone(),
            amount: 123,
            ts: Some(777),
            transfer_id: None,
            metadata: Some("{\"note\":\"hello\"}".to_string()),
        };

        handle_wallet_transfer_remote(client, args).await?;
        let body = body_rx.recv().await.expect("payload captured");
        server.abort();

        let envelope: SignedEnvelope<WalletTransferEvent> = from_reader(body.as_slice())?;
        assert_eq!(hex::encode(envelope.body.wallet_id.as_bytes()), wallet_hex);
        assert_eq!(
            hex::encode(envelope.body.to_wallet_id.as_bytes()),
            to_wallet_hex
        );
        assert_eq!(envelope.body.amount, 123);
        assert_eq!(envelope.body.ts, 777);
        assert!(matches!(envelope.body.metadata, Some(CborValue::Map(_))));

        let keystore = signer_dir.path().join("keystore.enc");
        let secret: ClientSecretBundle = read_cbor_file(&keystore).await?;
        let signing_key_bytes: [u8; 32] = secret.signing_key.as_ref().try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        verify_envelope_signature(&envelope, schema_wallet_transfer(), &signing_key)?;

        Ok(())
    }

    #[tokio::test]
    async fn revoke_publish_produces_signed_payload() -> anyhow::Result<()> {
        let signer_dir = tempdir()?;
        handle_keygen(KeygenArgs {
            out: signer_dir.path().to_path_buf(),
        })
        .await?;

        let (url, mut body_rx, server) = spawn_cbor_capture_server("/revoke").await?;
        let client = HubHttpClient::new(Url::parse(&url)?, HttpClient::builder().build()?);
        let target_hex = hex::encode([0x77u8; REVOCATION_TARGET_LEN]);
        let args = RevokePublishArgs {
            hub: url.clone(),
            signer: signer_dir.path().to_path_buf(),
            kind: RevocationKindValue::ClientId,
            target: target_hex.clone(),
            reason: Some("compromised".to_string()),
            ttl: Some(1_000),
            ts: Some(55),
        };

        handle_revoke_publish_remote(client, args).await?;
        let body = body_rx.recv().await.expect("payload captured");
        server.abort();

        let envelope: SignedEnvelope<RevocationRecord> = from_reader(body.as_slice())?;
        assert_eq!(envelope.schema.as_ref(), schema_revocation().as_slice());
        assert_eq!(envelope.body.kind, RevocationKind::ClientId);
        assert_eq!(hex::encode(envelope.body.target.as_bytes()), target_hex);
        assert_eq!(envelope.body.reason.as_deref(), Some("compromised"));
        assert_eq!(envelope.body.ttl, Some(1_000));
        assert_eq!(envelope.body.ts, 55);

        let keystore = signer_dir.path().join("keystore.enc");
        let secret: ClientSecretBundle = read_cbor_file(&keystore).await?;
        let signing_key_bytes: [u8; 32] = secret.signing_key.as_ref().try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        verify_envelope_signature(&envelope, schema_revocation(), &signing_key)?;

        Ok(())
    }

    #[test]
    fn schema_identifier_matches_hash() {
        let expected = h(b"wallet.transfer.v1");
        assert_eq!(compute_schema_identifier("wallet.transfer.v1"), expected);
    }

    #[tokio::test]
    async fn schema_list_fetches_descriptors() -> anyhow::Result<()> {
        let schema_id_bytes = [0x12; SCHEMA_ID_LEN];
        let descriptor = SchemaDescriptor {
            schema_id: SchemaId::from(schema_id_bytes),
            name: "example".to_string(),
            version: "1".to_string(),
            doc_url: Some("https://schemas".to_string()),
            owner: None,
            ts: 42,
        };
        let body_bytes = serde_json::to_vec(&vec![descriptor.clone()])?;
        let (url, server) = spawn_fixed_response_server("/schema", body_bytes).await?;
        let client = HubHttpClient::new(Url::parse(&url)?, HttpClient::builder().build()?);
        let fetched = fetch_schema_descriptors(&client).await?;
        server.abort();
        assert_eq!(fetched, vec![descriptor]);
        Ok(())
    }
}

impl HubReference {
    fn into_local(self) -> Result<PathBuf> {
        match self {
            HubReference::Local(path) => Ok(path),
            HubReference::Remote(_) => {
                bail!("command requires a local hub data directory reference")
            }
        }
    }
}

#[derive(Clone)]
struct HubHttpClient {
    base_url: Url,
    http: HttpClient,
}

impl HubHttpClient {
    fn new(base_url: Url, http: HttpClient) -> Self {
        Self { base_url, http }
    }

    fn url(&self, path: &str) -> Result<Url> {
        self.base_url
            .join(path)
            .with_context(|| format!("constructing hub url {}", path))
    }

    async fn get_json<T>(&self, path: &str, query: &[(&str, String)]) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let mut url = self.url(path)?;
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())));
        }
        let response = self
            .http
            .get(url)
            .send()
            .await
            .context("performing hub GET request")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<failed to decode response>".to_string());
            bail!("hub GET {path} failed with {status}: {body}");
        }
        response
            .json::<T>()
            .await
            .context("decoding hub response body")
    }

    async fn post_json<T, R>(&self, path: &str, body: &T) -> Result<R>
    where
        T: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let url = self.url(path)?;
        let response = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .context("performing hub POST request")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<failed to decode response>".to_string());
            bail!("hub POST {path} failed with {status}: {body}");
        }
        response
            .json::<R>()
            .await
            .context("decoding hub response body")
    }

    async fn post_cbor_unit(&self, path: &str, body: &[u8]) -> Result<()> {
        let url = self.url(path)?;
        let response = self
            .http
            .post(url)
            .header("Content-Type", "application/cbor")
            .body(body.to_vec())
            .send()
            .await
            .context("performing hub POST request")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<failed to decode response>".to_string());
            bail!("hub POST {path} failed with {status}: {body}");
        }
        Ok(())
    }

    async fn post_cbor<R>(&self, path: &str, body: &[u8]) -> Result<R>
    where
        R: DeserializeOwned,
    {
        let url = self.url(path)?;
        let response = self
            .http
            .post(url)
            .header("Content-Type", "application/cbor")
            .body(body.to_vec())
            .send()
            .await
            .context("performing hub POST request")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<failed to decode response>".to_string());
            bail!("hub POST {path} failed with {status}: {body}");
        }
        response
            .json::<R>()
            .await
            .context("decoding hub response body")
    }
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

fn parse_hub_reference(reference: &str) -> Result<HubReference> {
    if let Some(path) = reference.strip_prefix("file://") {
        return Ok(HubReference::Local(PathBuf::from(path)));
    }

    if reference.contains("://") {
        let url =
            Url::parse(reference).with_context(|| format!("parsing hub endpoint {reference}"))?;
        match url.scheme() {
            "http" | "https" => {
                let client = HttpClient::builder()
                    .build()
                    .context("constructing HTTP client")?;
                return Ok(HubReference::Remote(HubHttpClient::new(url, client)));
            }
            other => {
                bail!("unsupported hub scheme `{other}`; expected http or https");
            }
        }
    }

    Ok(HubReference::Local(PathBuf::from(reference)))
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
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
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
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
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
