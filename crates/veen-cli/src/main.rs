use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::env;
use std::fmt;
use std::io::Cursor;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{self, Command as StdCommand, Stdio};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ciborium::{de::Error as CborDeError, ser::Error as CborSerError, value::Value as CborValue};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use reqwest::{Client as HttpClient, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::signal;
use tokio::time::sleep;
use tracing_subscriber::EnvFilter;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use veen_core::CAP_TOKEN_VERSION;
use veen_core::{
    cap_stream_id_from_label,
    hub::{HubId, HUB_ID_LEN},
    label::{Label, StreamId},
    wire::{
        checkpoint::CHECKPOINT_VERSION,
        mmr::Mmr,
        proof::MmrProof,
        types::{ClientId, LeafHash, MmrRoot},
        Checkpoint,
    },
    AuthorityPolicy, AuthorityRecord, CapToken, CapTokenAllow, CapTokenRate, LabelClassRecord,
    OperationId, PowCookie, Profile, RealmId, RevocationKind, RevocationRecord, RevocationTarget,
    SchemaDescriptor, SchemaId, SchemaOwner, TransferId, WalletId, WalletTransferEvent,
};
use veen_core::{h, ht};
use veen_core::{
    schema_fed_authority, schema_label_class, schema_meta_schema, schema_revocation,
    schema_wallet_transfer, REALM_ID_LEN, REVOCATION_TARGET_LEN, SCHEMA_ID_LEN, TRANSFER_ID_LEN,
    WALLET_ID_LEN,
};
use veen_hub::config::{HubConfigOverrides, HubRole, HubRuntimeConfig};
use veen_hub::runtime::HubRuntime;

#[cfg(unix)]
use nix::errno::Errno;
#[cfg(unix)]
use nix::sys::signal::{kill, Signal};
#[cfg(unix)]
use nix::unistd::Pid;
#[cfg(unix)]
use std::time::Instant;
#[cfg(unix)]
use tokio::signal::unix::{signal as unix_signal, SignalKind};
use veen_hub::pipeline::{
    AnchorRequest, AttachmentUpload, AuthorizeResponse as RemoteAuthorizeResponse,
    HubStreamState as RemoteHubStreamState, PowCookieEnvelope,
    StoredAttachment as RemoteStoredAttachment, StoredMessage as RemoteStoredMessage,
    StreamMessageWithProof as RemoteStreamMessageWithProof, StreamProof as RemoteStreamProof,
    StreamReceipt as RemoteStreamReceipt, SubmitRequest as RemoteSubmitRequest,
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
const HUB_CONFIG_FILE: &str = "hub-config.toml";
const REVOCATIONS_FILE: &str = "revocations.json";

type JsonMap = serde_json::Map<String, JsonValue>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliExitKind {
    Usage,
    Network,
    Protocol,
    Hub,
    Selftest,
    Other { code: i32, label: &'static str },
}

impl CliExitKind {
    fn exit_code(self) -> i32 {
        match self {
            CliExitKind::Usage => 1,
            CliExitKind::Network => 2,
            CliExitKind::Protocol => 3,
            CliExitKind::Hub => 4,
            CliExitKind::Selftest => 5,
            CliExitKind::Other { code, .. } => code,
        }
    }

    fn label(self) -> &'static str {
        match self {
            CliExitKind::Usage => "E.USAGE",
            CliExitKind::Network => "E.NETWORK",
            CliExitKind::Protocol => "E.PROTOCOL",
            CliExitKind::Hub => "E.HUB",
            CliExitKind::Selftest => "E.SELFTEST",
            CliExitKind::Other { label, .. } => label,
        }
    }
}

#[derive(Debug)]
struct CliUsageError {
    message: String,
}

impl CliUsageError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl fmt::Display for CliUsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CliUsageError {}

#[derive(Debug)]
struct HubResponseError {
    path: String,
    status: reqwest::StatusCode,
    body: String,
}

impl HubResponseError {
    fn new(path: &str, status: reqwest::StatusCode, body: String) -> Self {
        Self {
            path: path.to_string(),
            status,
            body,
        }
    }
}

impl fmt::Display for HubResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hub {path} failed with {status}: {body}",
            path = self.path,
            status = self.status,
            body = self.body
        )
    }
}

impl std::error::Error for HubResponseError {}

#[derive(Debug)]
struct HubOperationError {
    message: String,
}

impl HubOperationError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl fmt::Display for HubOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for HubOperationError {}

#[derive(Debug)]
struct SelftestFailure {
    inner: anyhow::Error,
}

impl SelftestFailure {
    fn new(inner: anyhow::Error) -> Self {
        Self { inner }
    }
}

impl fmt::Display for SelftestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "self-test failure: {}", self.inner)
    }
}

impl std::error::Error for SelftestFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.inner.as_ref())
    }
}

#[derive(Debug)]
struct ProtocolError {
    message: String,
}

impl ProtocolError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ProtocolError {}

macro_rules! bail_usage {
    ($($arg:tt)*) => {{
        return Err(anyhow::Error::new(CliUsageError::new(format!($($arg)*))));
    }};
}

macro_rules! bail_hub {
    ($($arg:tt)*) => {{
        return Err(anyhow::Error::new(HubOperationError::new(format!($($arg)*))));
    }};
}

macro_rules! bail_protocol {
    ($($arg:tt)*) => {{
        return Err(anyhow::Error::new(ProtocolError::new(format!($($arg)*))));
    }};
}

#[derive(Debug, Clone, Default, Args)]
struct GlobalOptions {
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    quiet: bool,
    #[arg(long, value_name = "MS", global = true)]
    timeout_ms: Option<u64>,
}

#[derive(Parser)]
#[command(
    name = "veen",
    version,
    about = "VEEN v0.0.1 command line interface",
    long_about = None
)]
struct Cli {
    #[command(flatten)]
    global: GlobalOptions,
    #[command(subcommand)]
    command: Command,
}

static GLOBAL_OPTIONS: OnceLock<RwLock<GlobalOptions>> = OnceLock::new();

fn global_options_lock() -> &'static RwLock<GlobalOptions> {
    GLOBAL_OPTIONS.get_or_init(|| RwLock::new(GlobalOptions::default()))
}

fn set_global_options(options: GlobalOptions) {
    *global_options_lock()
        .write()
        .expect("global options lock poisoned") = options;
}

fn global_options() -> GlobalOptions {
    global_options_lock()
        .read()
        .expect("global options lock poisoned")
        .clone()
}

fn json_output_enabled(explicit: bool) -> bool {
    explicit || global_options().json
}

fn emit_cli_error(code: &str, detail: Option<&str>, use_json: bool) {
    if use_json {
        let mut root = JsonMap::new();
        root.insert("ok".to_string(), JsonValue::Bool(false));
        root.insert("code".to_string(), JsonValue::String(code.to_string()));
        match detail {
            Some(value) => {
                root.insert("detail".to_string(), JsonValue::String(value.to_string()));
            }
            None => {
                root.insert("detail".to_string(), JsonValue::Null);
            }
        }
        match serde_json::to_string_pretty(&JsonValue::Object(root)) {
            Ok(rendered) => {
                eprintln!("{rendered}");
            }
            Err(_) => {
                eprintln!("{{\"ok\":false,\"code\":\"{code}\"}}");
            }
        }
    } else if let Some(detail) = detail {
        eprintln!("{code}: {detail}");
    } else {
        eprintln!("{code}");
    }
}

fn log_cli_goal(goal: &str) {
    if global_options().quiet {
        return;
    }
    eprintln!("goal: {goal}");
}

fn pretty_json(value: JsonValue) -> String {
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
}

fn format_hub_profile_output(
    ok: bool,
    version: &str,
    profile_id: &str,
    hub_id: &str,
    features: &RemoteHubProfileFeatures,
    use_json: bool,
) -> String {
    if use_json {
        let mut root = JsonMap::new();
        root.insert("ok".to_string(), JsonValue::Bool(ok));
        root.insert(
            "version".to_string(),
            JsonValue::String(version.to_string()),
        );
        root.insert(
            "profile_id".to_string(),
            JsonValue::String(profile_id.to_string()),
        );
        root.insert("hub_id".to_string(), JsonValue::String(hub_id.to_string()));
        let mut feature_map = JsonMap::new();
        feature_map.insert("core".to_string(), JsonValue::Bool(features.core));
        feature_map.insert("fed1".to_string(), JsonValue::Bool(features.fed1));
        feature_map.insert("auth1".to_string(), JsonValue::Bool(features.auth1));
        feature_map.insert("kex1_plus".to_string(), JsonValue::Bool(features.kex1_plus));
        feature_map.insert("sh1_plus".to_string(), JsonValue::Bool(features.sh1_plus));
        feature_map.insert("lclass0".to_string(), JsonValue::Bool(features.lclass0));
        feature_map.insert(
            "meta0_plus".to_string(),
            JsonValue::Bool(features.meta0_plus),
        );
        root.insert("features".to_string(), JsonValue::Object(feature_map));
        pretty_json(JsonValue::Object(root))
    } else {
        [
            format!("version: {version}"),
            format!("profile_id: {profile_id}"),
            format!("hub_id: {hub_id}"),
            "features:".to_string(),
            format!("  core: {}", features.core),
            format!("  fed1: {}", features.fed1),
            format!("  auth1: {}", features.auth1),
            format!("  kex1_plus: {}", features.kex1_plus),
            format!("  sh1_plus: {}", features.sh1_plus),
            format!("  lclass0: {}", features.lclass0),
            format!("  meta0_plus: {}", features.meta0_plus),
        ]
        .join("\n")
    }
}

fn format_hub_role_output(
    ok: bool,
    hub_id: &str,
    role: &str,
    stream: Option<&RemoteHubRoleStream>,
    use_json: bool,
) -> String {
    if use_json {
        let mut root = JsonMap::new();
        root.insert("ok".to_string(), JsonValue::Bool(ok));
        root.insert("hub_id".to_string(), JsonValue::String(hub_id.to_string()));
        root.insert("role".to_string(), JsonValue::String(role.to_string()));
        if let Some(stream) = stream {
            let mut stream_map = JsonMap::new();
            if let Some(value) = &stream.realm_id {
                stream_map.insert("realm_id".to_string(), JsonValue::String(value.clone()));
            } else {
                stream_map.insert("realm_id".to_string(), JsonValue::Null);
            }
            stream_map.insert(
                "stream_id".to_string(),
                JsonValue::String(stream.stream_id.clone()),
            );
            stream_map.insert("label".to_string(), JsonValue::String(stream.label.clone()));
            stream_map.insert(
                "policy".to_string(),
                JsonValue::String(stream.policy.clone()),
            );
            if let Some(primary) = &stream.primary_hub {
                stream_map.insert(
                    "primary_hub".to_string(),
                    JsonValue::String(primary.clone()),
                );
            } else {
                stream_map.insert("primary_hub".to_string(), JsonValue::Null);
            }
            stream_map.insert(
                "local_is_primary".to_string(),
                JsonValue::Bool(stream.local_is_primary),
            );
            root.insert("stream".to_string(), JsonValue::Object(stream_map));
        }
        pretty_json(JsonValue::Object(root))
    } else if let Some(stream) = stream {
        let realm_out = stream
            .realm_id
            .clone()
            .unwrap_or_else(|| "unspecified".to_string());
        let primary = stream
            .primary_hub
            .clone()
            .unwrap_or_else(|| "none".to_string());
        [
            format!("hub_id: {hub_id}"),
            format!("role: {role}"),
            format!("realm_id: {realm_out}"),
            format!("stream_id: {}", stream.stream_id),
            format!("label: {}", stream.label),
            format!("policy: {}", stream.policy),
            format!("primary_hub: {primary}"),
            format!("local_is_primary: {}", stream.local_is_primary),
        ]
        .join("\n")
    } else {
        [format!("role: {role}"), format!("hub_id: {hub_id}")].join("\n")
    }
}

fn format_authority_record_output(
    descriptor: &RemoteAuthorityRecordDescriptor,
    use_json: bool,
) -> String {
    if use_json {
        let output = json!({
            "ok": true,
            "realm_id": descriptor.realm_id,
            "stream_id": descriptor.stream_id,
            "primary_hub": descriptor.primary_hub,
            "replica_hubs": descriptor.replica_hubs,
            "policy": descriptor.policy,
            "ts": descriptor.ts,
            "ttl": descriptor.ttl,
            "expires_at": descriptor.expires_at,
            "active_now": descriptor.active_now,
        });
        pretty_json(output)
    } else {
        let primary = descriptor
            .primary_hub
            .clone()
            .unwrap_or_else(|| "none".to_string());
        let replicas = if descriptor.replica_hubs.is_empty() {
            "[]".to_string()
        } else {
            format!("[{}]", descriptor.replica_hubs.join(","))
        };
        let expires = descriptor
            .expires_at
            .map(|value| value.to_string())
            .unwrap_or_else(|| "0".to_string());
        [
            format!("realm_id: {}", descriptor.realm_id),
            format!("stream_id: {}", descriptor.stream_id),
            format!("primary_hub: {primary}"),
            format!("replica_hubs: {replicas}"),
            format!("policy: {}", descriptor.policy),
            format!("ts: {}", descriptor.ts),
            format!("ttl: {}", descriptor.ttl),
            format!("expires_at: {expires}"),
            format!("active_now: {}", descriptor.active_now),
        ]
        .join("\n")
    }
}

fn format_label_authority_output(
    descriptor: &RemoteLabelAuthorityDescriptor,
    use_json: bool,
) -> String {
    if use_json {
        let output = json!({
            "ok": true,
            "label": descriptor.label,
            "realm_id": descriptor.realm_id,
            "stream_id": descriptor.stream_id,
            "policy": descriptor.policy,
            "primary_hub": descriptor.primary_hub,
            "replica_hubs": descriptor.replica_hubs,
            "local_hub_id": descriptor.local_hub_id,
            "locally_authorized": descriptor.local_is_authorized,
        });
        pretty_json(output)
    } else {
        let realm_display = descriptor
            .realm_id
            .clone()
            .unwrap_or_else(|| "unspecified".to_string());
        let primary = descriptor
            .primary_hub
            .clone()
            .unwrap_or_else(|| "none".to_string());
        [
            format!("label: {}", descriptor.label),
            format!("realm_id: {realm_display}"),
            format!("stream_id: {}", descriptor.stream_id),
            format!("policy: {}", descriptor.policy),
            format!("primary_hub: {primary}"),
            format!("local_hub_id: {}", descriptor.local_hub_id),
            format!("locally_authorized: {}", descriptor.local_is_authorized),
        ]
        .join("\n")
    }
}

#[cfg(test)]
fn json_output_enabled_with(explicit: bool, global: &GlobalOptions) -> bool {
    explicit || global.json
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
    /// Proof-of-work helpers.
    #[command(subcommand)]
    Pow(PowCommand),
    /// Federation and authority helpers.
    #[command(subcommand)]
    Fed(FedCommand),
    /// Label helpers.
    #[command(subcommand)]
    Label(LabelCommand),
    /// Label classification helpers.
    #[command(subcommand, name = "label-class")]
    LabelClass(LabelClassCommand),
    /// Schema registry helpers.
    #[command(subcommand)]
    Schema(SchemaCommand),
    /// Wallet overlay helpers.
    #[command(subcommand)]
    Wallet(WalletCommand),
    /// Operation overlay helpers.
    #[command(subcommand)]
    Operation(OperationCommand),
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
    /// Render Kubernetes manifests for VEEN profiles.
    #[command(subcommand)]
    Kube(KubeCommand),
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
    /// Fetch hub capability profile details.
    Profile(HubProfileArgs),
    /// Inspect hub role information.
    Role(HubRoleArgs),
    /// Inspect hub key and capability lifecycle policy.
    #[command(name = "kex-policy")]
    KexPolicy(HubKexPolicyArgs),
    /// Inspect admission pipeline configuration and metrics.
    Admission(HubAdmissionArgs),
    /// Inspect recent admission failures.
    #[command(name = "admission-log")]
    AdmissionLog(HubAdmissionLogArgs),
    /// Fetch the latest checkpoint from a hub.
    #[command(name = "checkpoint-latest")]
    CheckpointLatest(HubCheckpointLatestArgs),
    /// Fetch checkpoints within an epoch range from a hub.
    #[command(name = "checkpoint-range")]
    CheckpointRange(HubCheckpointRangeArgs),
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
    /// Inspect client identifier usage statistics.
    Usage(IdUsageArgs),
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
    /// Inspect hub view for a capability token.
    Status(CapStatusArgs),
    /// Publish a revocation record via the capability surface.
    Revoke(RevokePublishArgs),
    /// Inspect revocation records.
    Revocations(CapRevocationsArgs),
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
enum FedCommand {
    /// Federation authority helpers.
    #[command(subcommand)]
    Authority(FedAuthorityCommand),
}

#[derive(Subcommand)]
enum FedAuthorityCommand {
    /// Publish an authority record for a stream.
    Publish(FedAuthorityPublishArgs),
    /// Show the active authority record for a stream.
    Show(FedAuthorityShowArgs),
}

#[derive(Subcommand)]
enum LabelCommand {
    /// Inspect label authority information.
    Authority(LabelAuthorityArgs),
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
enum OperationCommand {
    /// Compute derived identifiers for stored operation messages.
    #[command(name = "id")]
    Id(OperationIdArgs),
}

#[derive(Subcommand)]
enum RevokeCommand {
    /// Publish a revocation record.
    Publish(RevokePublishArgs),
}

#[derive(Subcommand)]
enum PowCommand {
    /// Request a proof-of-work challenge from a hub.
    Request(PowRequestArgs),
    /// Solve a proof-of-work challenge locally.
    Solve(PowSolveArgs),
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

#[derive(Subcommand)]
enum KubeCommand {
    /// Render manifests for the authority hub profile.
    Authority(KubeAuthorityArgs),
    /// Render manifests for a tenant hub profile.
    Tenant(KubeTenantArgs),
}

#[derive(Args)]
struct KubeAuthorityArgs {
    /// Universe identifier assigned to the VEEN deployment.
    #[arg(long)]
    universe_id: String,
    /// Semantic version that should be attached to rendered resources.
    #[arg(long)]
    version: String,
    /// Optional override for the Kubernetes namespace. Defaults to veen-system.
    #[arg(long)]
    namespace: Option<String>,
    /// Path to the authority hub configuration file that becomes hub-config.toml.
    #[arg(long)]
    config: PathBuf,
    /// Path to the authority hub key bundle encoded into the Secret.
    #[arg(long)]
    keys: PathBuf,
    /// Container image reference for the hub runtime.
    #[arg(long)]
    image: Option<String>,
    /// Container image reference for the authority self-test job.
    #[arg(long)]
    selftest_image: Option<String>,
    /// Kubernetes storage class for the PersistentVolumeClaim.
    #[arg(long)]
    storage_class: Option<String>,
    /// Requested storage capacity for the PersistentVolumeClaim (for example 10Gi).
    #[arg(long, default_value = "10Gi")]
    storage_size: String,
    /// Logical port exposed by the hub Service and container.
    #[arg(long, default_value_t = 8080)]
    port: u16,
    /// Log level exported via VEEN_LOG_LEVEL.
    #[arg(long, default_value = "info")]
    log_level: String,
    /// Optional profile identifier override (HEX32).
    #[arg(long, value_name = "HEX32")]
    profile_id: Option<String>,
}

#[derive(Args)]
struct KubeTenantArgs {
    /// Tenant identifier used for labels and the namespace default.
    #[arg(long)]
    tenant_id: String,
    /// Universe identifier assigned to the VEEN deployment.
    #[arg(long)]
    universe_id: String,
    /// Semantic version that should be attached to rendered resources.
    #[arg(long)]
    version: String,
    /// Optional override for the namespace. Defaults to veen-tenant-<tenant-id>.
    #[arg(long)]
    namespace: Option<String>,
    /// Path to the tenant hub configuration file rendered as hub-config.toml.
    #[arg(long)]
    config: PathBuf,
    /// Path to the tenant hub key bundle encoded into the Secret.
    #[arg(long)]
    keys: PathBuf,
    /// Container image reference for the hub runtime.
    #[arg(long)]
    hub_image: Option<String>,
    /// Container image reference for the self-test job.
    #[arg(long)]
    selftest_image: Option<String>,
    /// Request an additional PersistentVolumeClaim instead of emptyDir storage.
    #[arg(long, default_value_t = false)]
    persistent_storage: bool,
    /// Requested storage capacity for the optional PersistentVolumeClaim.
    #[arg(long, default_value = "1Gi")]
    storage_size: String,
    /// Kubernetes storage class for the optional PersistentVolumeClaim.
    #[arg(long)]
    storage_class: Option<String>,
    /// Logical port exposed by the hub Service and container.
    #[arg(long, default_value_t = 8080)]
    port: u16,
    /// Log level exported via VEEN_LOG_LEVEL.
    #[arg(long, default_value = "info")]
    log_level: String,
    /// Optional profile identifier override (HEX32).
    #[arg(long, value_name = "HEX32")]
    profile_id: Option<String>,
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

#[derive(Args, Clone)]
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
struct HubProfileArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct HubRoleArgs {
    #[arg(long)]
    hub: String,
    #[arg(long, value_name = "HEX32")]
    realm: Option<String>,
    #[arg(long)]
    stream: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct HubKexPolicyArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct HubAdmissionArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct HubAdmissionLogArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    limit: Option<u64>,
    #[arg(long)]
    codes: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct HubCheckpointLatestArgs {
    #[arg(long)]
    hub: String,
}

#[derive(Args)]
struct HubCheckpointRangeArgs {
    #[arg(long)]
    hub: String,
    #[arg(long, value_name = "EPOCH")]
    from_epoch: Option<u64>,
    #[arg(long, value_name = "EPOCH")]
    to_epoch: Option<u64>,
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
struct IdUsageArgs {
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    hub: Option<String>,
    #[arg(long)]
    json: bool,
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
    #[arg(long, value_name = "BITS")]
    pow_difficulty: Option<u8>,
    #[arg(long, value_name = "HEX")]
    pow_challenge: Option<String>,
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
struct CapStatusArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    cap: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct CapRevocationsArgs {
    #[arg(long)]
    hub: String,
    #[arg(long, value_enum)]
    kind: Option<RevocationKindValue>,
    #[arg(long)]
    since: Option<u64>,
    #[arg(long)]
    active_only: bool,
    #[arg(long)]
    limit: Option<u64>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct FedAuthorityPublishArgs {
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
    #[arg(long)]
    json: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum AuthorityPolicyValue {
    SinglePrimary,
    MultiPrimary,
}

#[derive(Args)]
struct FedAuthorityShowArgs {
    #[arg(long)]
    hub: String,
    #[arg(long, value_name = "HEX32")]
    realm: String,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct LabelAuthorityArgs {
    #[arg(long)]
    hub: String,
    #[arg(long, value_name = "HEX32")]
    label: String,
    #[arg(long)]
    json: bool,
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

#[derive(Args)]
struct OperationIdArgs {
    #[arg(long)]
    bundle: PathBuf,
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

impl RevocationKindValue {
    fn as_str(&self) -> &'static str {
        match self {
            RevocationKindValue::ClientId => "client-id",
            RevocationKindValue::AuthRef => "auth-ref",
            RevocationKindValue::CapToken => "cap-token",
        }
    }
}

impl From<RevocationKindValue> for RevocationKind {
    fn from(value: RevocationKindValue) -> Self {
        match value {
            RevocationKindValue::ClientId => RevocationKind::ClientId,
            RevocationKindValue::AuthRef => RevocationKind::AuthRef,
            RevocationKindValue::CapToken => RevocationKind::CapToken,
        }
    }
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
struct PowRequestArgs {
    #[arg(long)]
    hub: String,
    #[arg(long, value_name = "BITS")]
    difficulty: Option<u8>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct PowSolveArgs {
    #[arg(long, value_name = "HEX")]
    challenge: String,
    #[arg(long, value_name = "BITS")]
    difficulty: u8,
    #[arg(long)]
    max_iterations: Option<u64>,
    #[arg(long)]
    json: bool,
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
            bail_usage!("hub in {} is already marked as running", data_dir.display());
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

impl HubMetricsSnapshot {
    fn from_remote(report: &RemoteObservabilityReport) -> Self {
        Self {
            submit_ok_total: report.submit_ok_total,
            submit_err_total: report.submit_err_total.clone(),
            verify_latency_ms: HistogramSnapshot::default(),
            commit_latency_ms: HistogramSnapshot::default(),
            end_to_end_latency_ms: HistogramSnapshot::default(),
        }
    }
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

#[derive(Debug, Deserialize)]
struct RemoteObservabilityReport {
    #[serde(with = "humantime_serde")]
    uptime: Duration,
    submit_ok_total: u64,
    submit_err_total: BTreeMap<String, u64>,
    last_stream_seq: BTreeMap<String, u64>,
    mmr_roots: BTreeMap<String, String>,
    peaks_count: u64,
    profile_id: Option<String>,
    hub_id: Option<String>,
    hub_public_key: Option<String>,
    role: String,
    data_dir: String,
}

#[derive(Debug, Deserialize)]
struct RemoteHubProfileDescriptor {
    ok: bool,
    version: String,
    profile_id: Option<String>,
    hub_id: String,
    features: RemoteHubProfileFeatures,
}

#[derive(Debug, Deserialize)]
struct RemoteHubProfileFeatures {
    core: bool,
    fed1: bool,
    auth1: bool,
    kex1_plus: bool,
    sh1_plus: bool,
    lclass0: bool,
    meta0_plus: bool,
}

#[derive(Debug, Deserialize)]
struct RemoteHubRoleDescriptor {
    ok: bool,
    hub_id: String,
    role: String,
    stream: Option<RemoteHubRoleStream>,
}

#[derive(Debug, Deserialize)]
struct RemoteHubRoleStream {
    realm_id: Option<String>,
    stream_id: String,
    label: String,
    policy: String,
    primary_hub: Option<String>,
    local_is_primary: bool,
}

#[derive(Debug, Deserialize)]
struct RemoteKexPolicyDescriptor {
    ok: bool,
    max_client_id_lifetime_sec: Option<u64>,
    max_msgs_per_client_id_per_label: Option<u64>,
    default_cap_ttl_sec: Option<u64>,
    max_cap_ttl_sec: Option<u64>,
    revocation_stream: Option<String>,
    rotation_window_sec: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RemoteAdmissionReport {
    ok: bool,
    stages: Vec<RemoteAdmissionStage>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RemoteAdmissionStage {
    name: String,
    enabled: bool,
    responsibilities: Vec<String>,
    queue_depth: u64,
    max_queue_depth: u64,
    recent_err_rates: BTreeMap<String, f64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RemoteAdmissionLogResponse {
    ok: bool,
    events: Vec<RemoteAdmissionEvent>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RemoteAdmissionEvent {
    ts: u64,
    code: String,
    label_prefix: String,
    client_id_prefix: String,
    detail: String,
}

#[derive(Debug, Deserialize)]
struct RemotePowChallenge {
    ok: bool,
    challenge: String,
    difficulty: u8,
}

#[derive(Debug, Deserialize)]
struct RemoteCapStatusResponse {
    ok: bool,
    #[allow(dead_code)]
    auth_ref: String,
    hub_known: bool,
    currently_valid: bool,
    revoked: bool,
    expires_at: Option<u64>,
    revocation_kind: Option<String>,
    revocation_ts: Option<u64>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RemoteRevocationList {
    ok: bool,
    revocations: Vec<RemoteRevocationEntry>,
}

#[derive(Debug, Deserialize)]
struct RemoteRevocationEntry {
    kind: String,
    target: String,
    ts: u64,
    ttl: Option<u64>,
    reason: Option<String>,
    active_now: bool,
}

#[derive(Debug, Deserialize)]
struct RemoteAuthorityRecordDescriptor {
    ok: bool,
    realm_id: String,
    stream_id: String,
    primary_hub: Option<String>,
    replica_hubs: Vec<String>,
    policy: String,
    ts: u64,
    ttl: u64,
    expires_at: Option<u64>,
    active_now: bool,
}

#[derive(Debug, Deserialize)]
struct RemoteLabelAuthorityDescriptor {
    ok: bool,
    label: String,
    realm_id: Option<String>,
    stream_id: String,
    policy: String,
    primary_hub: Option<String>,
    replica_hubs: Vec<String>,
    local_hub_id: String,
    #[serde(rename = "local_is_authorized")]
    local_is_authorized: bool,
}

#[derive(Debug, Deserialize)]
struct RemoteHealthStatus {
    ok: bool,
    #[serde(with = "humantime_serde")]
    uptime: Duration,
    submit_ok_total: u64,
    submit_err_total: BTreeMap<String, u64>,
    last_stream_seq: BTreeMap<String, u64>,
    mmr_roots: BTreeMap<String, String>,
    peaks_count: u64,
    profile_id: Option<String>,
    hub_id: Option<String>,
    hub_public_key: Option<String>,
    role: String,
    data_dir: String,
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
    #[serde(default)]
    msgs_sent: u64,
    #[serde(default)]
    first_sent_at: Option<u64>,
    #[serde(default)]
    last_sent_at: Option<u64>,
}

impl Default for ClientLabelState {
    fn default() -> Self {
        Self {
            last_stream_seq: 0,
            last_mmr_root: "0".repeat(64),
            prev_ack: 0,
            msgs_sent: 0,
            first_sent_at: None,
            last_sent_at: None,
        }
    }
}

impl ClientStateFile {
    fn ensure_label_state(&mut self, label: &str) -> &mut ClientLabelState {
        self.labels.entry(label.to_string()).or_default()
    }
}

impl ClientLabelState {
    fn record_send(&mut self, seq: u64, sent_at: u64) {
        self.last_stream_seq = seq;
        self.prev_ack = seq;
        self.msgs_sent = self.msgs_sent.saturating_add(1);
        if self.first_sent_at.is_none() {
            self.first_sent_at = Some(sent_at);
        }
        self.last_sent_at = Some(sent_at);
    }

    fn record_sync(&mut self, seq: u64) {
        self.last_stream_seq = seq;
        self.prev_ack = seq;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StreamReceipt {
    seq: u64,
    leaf_hash: String,
    mmr_root: String,
    hub_ts: u64,
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

impl From<RemoteStreamReceipt> for StreamReceipt {
    fn from(remote: RemoteStreamReceipt) -> Self {
        Self {
            seq: remote.seq,
            leaf_hash: remote.leaf_hash,
            mmr_root: remote.mmr_root,
            hub_ts: remote.hub_ts,
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

struct KexPolicyThresholds {
    max_client_id_lifetime_sec: Option<u64>,
    max_msgs_per_client_id_per_label: Option<u64>,
}

struct IdUsageEntry {
    stream: String,
    label_hex: String,
    client_id: String,
    created_at: u64,
    msgs_sent: u64,
    approx_lifetime_sec: u64,
    exceeds_msg_bound: bool,
    exceeds_lifetime_bound: bool,
    rotation_recommended: bool,
}

fn revocation_kind_label(kind: RevocationKind) -> &'static str {
    match kind {
        RevocationKind::ClientId => "client-id",
        RevocationKind::AuthRef => "auth-ref",
        RevocationKind::CapToken => "cap-token",
    }
}

#[derive(Serialize)]
struct RenderedRevocation {
    kind: String,
    target: String,
    ts: u64,
    ttl: Option<u64>,
    reason: Option<String>,
    active_now: bool,
}

#[tokio::main]
async fn main() {
    let exit_code = match run_cli().await {
        Ok(()) => 0,
        Err(err) => {
            let classification = classify_error(&err);
            let detail = err.to_string();
            let use_json = json_output_enabled(false);
            emit_cli_error(classification.label(), Some(&detail), use_json);
            classification.exit_code()
        }
    };
    process::exit(exit_code);
}

async fn run_cli() -> Result<()> {
    let Cli { global, command } = Cli::parse();
    set_global_options(global);
    init_tracing();

    match command {
        Command::Hub(cmd) => match cmd {
            HubCommand::Start(args) => handle_hub_start(args).await,
            HubCommand::Stop(args) => handle_hub_stop(args).await,
            HubCommand::Status(args) => handle_hub_status(args).await,
            HubCommand::Key(args) => handle_hub_key(args).await,
            HubCommand::VerifyRotation(args) => handle_hub_verify_rotation(args).await,
            HubCommand::Health(args) => handle_hub_health(args).await,
            HubCommand::Metrics(args) => handle_hub_metrics(args).await,
            HubCommand::Profile(args) => handle_hub_profile(args).await,
            HubCommand::Role(args) => handle_hub_role(args).await,
            HubCommand::KexPolicy(args) => handle_hub_kex_policy(args).await,
            HubCommand::Admission(args) => handle_hub_admission(args).await,
            HubCommand::AdmissionLog(args) => handle_hub_admission_log(args).await,
            HubCommand::CheckpointLatest(args) => {
                handle_hub_checkpoint_latest(args).await.map(|_| ())
            }
            HubCommand::CheckpointRange(args) => {
                handle_hub_checkpoint_range(args).await.map(|_| ())
            }
        },
        Command::Keygen(args) => handle_keygen(args).await,
        Command::Id(cmd) => match cmd {
            IdCommand::Show(args) => handle_id_show(args).await,
            IdCommand::Rotate(args) => handle_id_rotate(args).await,
            IdCommand::Usage(args) => handle_id_usage(args).await,
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
            CapCommand::Status(args) => handle_cap_status(args).await,
            CapCommand::Revoke(args) => handle_revoke_publish(args).await,
            CapCommand::Revocations(args) => handle_cap_revocations(args).await,
        },
        Command::Pow(cmd) => match cmd {
            PowCommand::Request(args) => handle_pow_request(args).await,
            PowCommand::Solve(args) => handle_pow_solve(args).await,
        },
        Command::Fed(cmd) => match cmd {
            FedCommand::Authority(sub) => match sub {
                FedAuthorityCommand::Publish(args) => handle_fed_authority_publish(args).await,
                FedAuthorityCommand::Show(args) => handle_fed_authority_show(args).await,
            },
        },
        Command::Label(cmd) => match cmd {
            LabelCommand::Authority(args) => handle_label_authority(args).await,
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
        Command::Operation(cmd) => match cmd {
            OperationCommand::Id(args) => handle_operation_id(args).await,
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
        Command::Kube(cmd) => match cmd {
            KubeCommand::Authority(args) => handle_kube_authority(args).await,
            KubeCommand::Tenant(args) => handle_kube_tenant(args).await,
        },
        Command::Selftest(cmd) => match cmd {
            SelftestCommand::Core => handle_selftest_core().await,
            SelftestCommand::Props => handle_selftest_props().await,
            SelftestCommand::Fuzz => handle_selftest_fuzz().await,
            SelftestCommand::All => handle_selftest_all().await,
        },
    }
}

struct ErrorClassification {
    kind: CliExitKind,
}

impl ErrorClassification {
    fn new(kind: CliExitKind) -> Self {
        Self { kind }
    }

    fn exit_code(&self) -> i32 {
        self.kind.exit_code()
    }

    fn label(&self) -> &'static str {
        self.kind.label()
    }
}

fn classify_error(err: &anyhow::Error) -> ErrorClassification {
    if error_chain_contains::<CliUsageError>(err) {
        return ErrorClassification::new(CliExitKind::Usage);
    }
    if error_chain_contains::<SelftestFailure>(err) {
        return ErrorClassification::new(CliExitKind::Selftest);
    }
    if error_chain_contains::<HubResponseError>(err)
        || error_chain_contains::<HubOperationError>(err)
    {
        return ErrorClassification::new(CliExitKind::Hub);
    }
    if let Some(req_err) = find_reqwest_error(err) {
        if req_err.is_connect() || req_err.is_timeout() || req_err.is_request() {
            return ErrorClassification::new(CliExitKind::Network);
        }
    }
    if error_chain_contains::<ProtocolError>(err)
        || error_chain_contains::<serde_json::Error>(err)
        || error_chain_contains::<CborDeError<std::io::Error>>(err)
        || error_chain_contains::<CborSerError<std::io::Error>>(err)
    {
        return ErrorClassification::new(CliExitKind::Protocol);
    }

    ErrorClassification::new(CliExitKind::Other {
        code: 70,
        label: "E.CLI",
    })
}

fn error_chain_contains<T>(err: &anyhow::Error) -> bool
where
    T: std::error::Error + 'static,
{
    err.chain().any(|cause| cause.is::<T>())
}

fn find_reqwest_error(err: &anyhow::Error) -> Option<&reqwest::Error> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<reqwest::Error>())
}

async fn handle_kube_authority(args: KubeAuthorityArgs) -> Result<()> {
    let KubeAuthorityArgs {
        universe_id,
        version,
        namespace,
        config,
        keys,
        image,
        selftest_image,
        storage_class,
        storage_size,
        port,
        log_level,
        profile_id,
    } = args;

    let namespace = namespace.unwrap_or_else(|| "veen-system".to_string());
    let image = image.unwrap_or_else(|| format!("veen-hub:{version}"));
    let selftest_image = selftest_image.unwrap_or_else(|| format!("veen-selftest:{version}"));
    let profile_id = normalize_optional_profile_id(profile_id)?;

    let config_contents = fs::read_to_string(&config)
        .await
        .with_context(|| format!("reading authority config {}", config.display()))?;
    let key_bytes = fs::read(&keys)
        .await
        .with_context(|| format!("reading authority keys {}", keys.display()))?;

    let config_hash = sha256_hex(config_contents.as_bytes());
    let key_hash = sha256_hex(&key_bytes);
    let combined_hash = sha256_hex_multi(&[config_contents.as_bytes(), key_bytes.as_slice()]);
    let key_b64 = BASE64_STANDARD.encode(key_bytes);

    let mut docs = Vec::new();
    docs.push(namespace_manifest(
        &namespace,
        &universe_id,
        &version,
        "authority",
        None,
    ));

    let base_labels = standard_labels("hub", "authority", &universe_id, None);

    docs.push(config_map_manifest(
        "veen-authority-config",
        &namespace,
        base_labels.clone(),
        default_annotations("authority", &version, Some(&config_hash)),
        HUB_CONFIG_FILE,
        &config_contents,
    ));

    docs.push(secret_manifest(
        "veen-authority-keys",
        &namespace,
        base_labels.clone(),
        default_annotations("authority", &version, Some(&key_hash)),
        "hub-key.cbor",
        &key_b64,
    ));

    docs.push(pvc_manifest(
        "veen-authority-data",
        &namespace,
        base_labels.clone(),
        default_annotations("authority", &version, None),
        &storage_size,
        storage_class.as_deref(),
    ));

    docs.push(service_manifest(
        "veen-authority",
        &namespace,
        base_labels.clone(),
        default_annotations("authority", &version, None),
        base_labels.clone(),
        port,
    ));

    let pod_annotations = default_annotations("authority", &version, Some(&combined_hash));
    let mut hub_args = vec![
        "hub".to_string(),
        "start".to_string(),
        "--listen".to_string(),
        format!("0.0.0.0:{port}"),
        "--data-dir".to_string(),
        "/var/lib/veen".to_string(),
        "--config".to_string(),
        format!("/etc/veen/{HUB_CONFIG_FILE}"),
        "--foreground".to_string(),
    ];
    if let Some(ref profile) = profile_id {
        hub_args.push("--profile-id".to_string());
        hub_args.push(profile.clone());
    }

    let container = json!({
        "name": "veen-authority-hub",
        "image": image,
        "imagePullPolicy": "IfNotPresent",
        "command": ["veen"],
        "args": hub_args,
        "env": [
            {"name": "VEEN_ROLE", "value": "authority"},
            {"name": "VEEN_UNIVERSE_ID", "value": universe_id.clone()},
            {"name": "VEEN_LOG_LEVEL", "value": log_level.clone()}
        ],
        "ports": [
            {"name": "http", "containerPort": port}
        ],
        "volumeMounts": [
            {"name": "veen-config", "mountPath": "/etc/veen", "readOnly": true},
            {"name": "veen-keys", "mountPath": "/etc/veen/keys", "readOnly": true},
            {"name": "veen-data", "mountPath": "/var/lib/veen"}
        ],
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
    });

    let volumes = vec![
        json!({"name": "veen-config", "configMap": {"name": "veen-authority-config"}}),
        json!({"name": "veen-keys", "secret": {"secretName": "veen-authority-keys"}}),
        json!({"name": "veen-data", "persistentVolumeClaim": {"claimName": "veen-authority-data"}}),
    ];

    docs.push(statefulset_manifest(
        ManifestMetadata::new(
            "veen-authority-hub",
            &namespace,
            base_labels.clone(),
            default_annotations("authority", &version, Some(&combined_hash)),
        ),
        base_labels.clone(),
        pod_annotations,
        container,
        volumes,
        "veen-authority",
    ));

    let job_labels = standard_labels("selftest", "selftest", &universe_id, None);
    let job_annotations = default_annotations("selftest", &version, None);
    let hub_url = format!("http://veen-authority:{port}");
    let job_container = json!({
        "name": "veen-selftest-authority",
        "image": selftest_image,
        "imagePullPolicy": "IfNotPresent",
        "command": ["veen-selftest", "authority", "--hub", hub_url],
        "env": [
            {"name": "VEEN_ROLE", "value": "selftest"},
            {"name": "VEEN_UNIVERSE_ID", "value": universe_id.clone()}
        ],
        "volumeMounts": [
            {"name": "work", "mountPath": "/work"}
        ]
    });
    let job_volumes = vec![json!({"name": "work", "emptyDir": {}})];

    docs.push(job_manifest(
        "veen-selftest-authority",
        &namespace,
        job_labels,
        job_annotations,
        job_container,
        job_volumes,
    ));

    let output = render_yaml_documents(&docs)?;
    print!("{}", output);
    log_cli_goal("CLI.KUBE.AUTHORITY_RENDER");
    Ok(())
}

async fn handle_kube_tenant(args: KubeTenantArgs) -> Result<()> {
    let KubeTenantArgs {
        tenant_id,
        universe_id,
        version,
        namespace,
        config,
        keys,
        hub_image,
        selftest_image,
        persistent_storage,
        storage_size,
        storage_class,
        port,
        log_level,
        profile_id,
    } = args;

    let namespace = namespace.unwrap_or_else(|| format!("veen-tenant-{tenant_id}"));
    let hub_image = hub_image.unwrap_or_else(|| format!("veen-hub:{version}"));
    let selftest_image = selftest_image.unwrap_or_else(|| format!("veen-selftest:{version}"));
    let profile_id = normalize_optional_profile_id(profile_id)?;

    let config_contents = fs::read_to_string(&config)
        .await
        .with_context(|| format!("reading tenant config {}", config.display()))?;
    let key_bytes = fs::read(&keys)
        .await
        .with_context(|| format!("reading tenant keys {}", keys.display()))?;

    let config_hash = sha256_hex(config_contents.as_bytes());
    let key_hash = sha256_hex(&key_bytes);
    let combined_hash = sha256_hex_multi(&[config_contents.as_bytes(), key_bytes.as_slice()]);
    let key_b64 = BASE64_STANDARD.encode(key_bytes);

    let mut docs = Vec::new();
    docs.push(namespace_manifest(
        &namespace,
        &universe_id,
        &version,
        "tenant",
        Some(&tenant_id),
    ));

    let base_labels = standard_labels("hub", "tenant", &universe_id, Some(&tenant_id));

    docs.push(config_map_manifest(
        "veen-hub-config",
        &namespace,
        base_labels.clone(),
        default_annotations("tenant", &version, Some(&config_hash)),
        HUB_CONFIG_FILE,
        &config_contents,
    ));

    docs.push(secret_manifest(
        "veen-hub-keys",
        &namespace,
        base_labels.clone(),
        default_annotations("tenant", &version, Some(&key_hash)),
        "hub-key.cbor",
        &key_b64,
    ));

    if persistent_storage {
        docs.push(pvc_manifest(
            "veen-hub-data",
            &namespace,
            base_labels.clone(),
            default_annotations("tenant", &version, None),
            &storage_size,
            storage_class.as_deref(),
        ));
    }

    docs.push(service_manifest(
        "veen-hub",
        &namespace,
        base_labels.clone(),
        default_annotations("tenant", &version, None),
        base_labels.clone(),
        port,
    ));

    let pod_annotations = default_annotations("tenant", &version, Some(&combined_hash));
    let mut volume_mounts = vec![
        json!({"name": "veen-config", "mountPath": "/etc/veen", "readOnly": true}),
        json!({"name": "veen-keys", "mountPath": "/etc/veen/keys", "readOnly": true}),
    ];
    volume_mounts.push(json!({"name": "veen-data", "mountPath": "/var/lib/veen"}));

    let mut hub_args = vec![
        "hub".to_string(),
        "start".to_string(),
        "--listen".to_string(),
        format!("0.0.0.0:{port}"),
        "--data-dir".to_string(),
        "/var/lib/veen".to_string(),
        "--config".to_string(),
        format!("/etc/veen/{HUB_CONFIG_FILE}"),
        "--foreground".to_string(),
    ];
    if let Some(ref profile) = profile_id {
        hub_args.push("--profile-id".to_string());
        hub_args.push(profile.clone());
    }

    let container = json!({
        "name": "veen-tenant-hub",
        "image": hub_image,
        "imagePullPolicy": "IfNotPresent",
        "command": ["veen"],
        "args": hub_args,
        "env": [
            {"name": "VEEN_ROLE", "value": "tenant"},
            {"name": "VEEN_TENANT_ID", "value": tenant_id.clone()},
            {"name": "VEEN_UNIVERSE_ID", "value": universe_id.clone()},
            {"name": "VEEN_LOG_LEVEL", "value": log_level.clone()}
        ],
        "ports": [
            {"name": "http", "containerPort": port}
        ],
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
    });

    let mut volumes = vec![
        json!({"name": "veen-config", "configMap": {"name": "veen-hub-config"}}),
        json!({"name": "veen-keys", "secret": {"secretName": "veen-hub-keys"}}),
    ];
    if persistent_storage {
        volumes.push(json!({
            "name": "veen-data",
            "persistentVolumeClaim": {"claimName": "veen-hub-data"}
        }));
    } else {
        volumes.push(json!({"name": "veen-data", "emptyDir": {}}));
    }

    docs.push(deployment_manifest(
        ManifestMetadata::new(
            "veen-hub",
            &namespace,
            base_labels.clone(),
            default_annotations("tenant", &version, Some(&combined_hash)),
        ),
        base_labels.clone(),
        pod_annotations,
        container,
        volumes,
    ));

    let job_labels = standard_labels("selftest", "selftest", &universe_id, Some(&tenant_id));
    let job_annotations = default_annotations("selftest", &version, None);
    let hub_url = format!("http://veen-hub:{port}");
    let job_container = json!({
        "name": "veen-selftest-core",
        "image": selftest_image,
        "imagePullPolicy": "IfNotPresent",
        "command": ["veen-selftest", "core", "--hub", hub_url],
        "env": [
            {"name": "VEEN_ROLE", "value": "selftest"},
            {"name": "VEEN_TENANT_ID", "value": tenant_id.clone()},
            {"name": "VEEN_UNIVERSE_ID", "value": universe_id.clone()}
        ],
        "volumeMounts": [
            {"name": "work", "mountPath": "/work"}
        ]
    });
    let job_volumes = vec![json!({"name": "work", "emptyDir": {}})];

    docs.push(job_manifest(
        "veen-selftest-core",
        &namespace,
        job_labels,
        job_annotations,
        job_container,
        job_volumes,
    ));

    let output = render_yaml_documents(&docs)?;
    print!("{}", output);
    log_cli_goal("CLI.KUBE.TENANT_RENDER");
    Ok(())
}

fn namespace_manifest(
    name: &str,
    universe_id: &str,
    version: &str,
    profile: &str,
    tenant_id: Option<&str>,
) -> JsonValue {
    let mut labels = JsonMap::new();
    labels.insert("app.kubernetes.io/part-of".to_string(), json!("veen"));
    labels.insert(
        "veen.io/universe-id".to_string(),
        json!(universe_id.to_string()),
    );
    if let Some(tenant) = tenant_id {
        labels.insert("veen.io/tenant-id".to_string(), json!(tenant.to_string()));
    }
    let annotations = default_annotations(profile, version, None);

    let mut root = JsonMap::new();
    root.insert("apiVersion".to_string(), json!("v1"));
    root.insert("kind".to_string(), json!("Namespace"));
    root.insert(
        "metadata".to_string(),
        metadata(Some(name), None, Some(labels), Some(annotations)),
    );
    JsonValue::Object(root)
}

fn config_map_manifest(
    name: &str,
    namespace: &str,
    labels: JsonMap,
    annotations: JsonMap,
    data_key: &str,
    data_value: &str,
) -> JsonValue {
    let mut data = JsonMap::new();
    data.insert(
        data_key.to_string(),
        JsonValue::String(data_value.to_string()),
    );

    let mut root = JsonMap::new();
    root.insert("apiVersion".to_string(), json!("v1"));
    root.insert("kind".to_string(), json!("ConfigMap"));
    root.insert(
        "metadata".to_string(),
        metadata(Some(name), Some(namespace), Some(labels), Some(annotations)),
    );
    root.insert("data".to_string(), JsonValue::Object(data));
    JsonValue::Object(root)
}

fn secret_manifest(
    name: &str,
    namespace: &str,
    labels: JsonMap,
    annotations: JsonMap,
    data_key: &str,
    data_value: &str,
) -> JsonValue {
    let mut data = JsonMap::new();
    data.insert(
        data_key.to_string(),
        JsonValue::String(data_value.to_string()),
    );

    let mut root = JsonMap::new();
    root.insert("apiVersion".to_string(), json!("v1"));
    root.insert("kind".to_string(), json!("Secret"));
    root.insert(
        "metadata".to_string(),
        metadata(Some(name), Some(namespace), Some(labels), Some(annotations)),
    );
    root.insert("type".to_string(), json!("Opaque"));
    root.insert("data".to_string(), JsonValue::Object(data));
    JsonValue::Object(root)
}

fn pvc_manifest(
    name: &str,
    namespace: &str,
    labels: JsonMap,
    annotations: JsonMap,
    storage_size: &str,
    storage_class: Option<&str>,
) -> JsonValue {
    let mut requests = JsonMap::new();
    requests.insert("storage".to_string(), json!(storage_size.to_string()));
    let mut resources = JsonMap::new();
    resources.insert("requests".to_string(), JsonValue::Object(requests));

    let mut spec = JsonMap::new();
    spec.insert("accessModes".to_string(), json!(["ReadWriteOnce"]));
    spec.insert("resources".to_string(), JsonValue::Object(resources));
    if let Some(class) = storage_class {
        spec.insert("storageClassName".to_string(), json!(class.to_string()));
    }

    let mut root = JsonMap::new();
    root.insert("apiVersion".to_string(), json!("v1"));
    root.insert("kind".to_string(), json!("PersistentVolumeClaim"));
    root.insert(
        "metadata".to_string(),
        metadata(Some(name), Some(namespace), Some(labels), Some(annotations)),
    );
    root.insert("spec".to_string(), JsonValue::Object(spec));
    JsonValue::Object(root)
}

fn service_manifest(
    name: &str,
    namespace: &str,
    labels: JsonMap,
    annotations: JsonMap,
    selector: JsonMap,
    port: u16,
) -> JsonValue {
    let mut spec = JsonMap::new();
    spec.insert("selector".to_string(), JsonValue::Object(selector));
    spec.insert(
        "ports".to_string(),
        json!([{ "name": "http", "port": port, "targetPort": port }]),
    );
    spec.insert("type".to_string(), json!("ClusterIP"));

    let mut root = JsonMap::new();
    root.insert("apiVersion".to_string(), json!("v1"));
    root.insert("kind".to_string(), json!("Service"));
    root.insert(
        "metadata".to_string(),
        metadata(Some(name), Some(namespace), Some(labels), Some(annotations)),
    );
    root.insert("spec".to_string(), JsonValue::Object(spec));
    JsonValue::Object(root)
}

struct ManifestMetadata {
    name: String,
    namespace: String,
    labels: JsonMap,
    annotations: JsonMap,
}

impl ManifestMetadata {
    fn new(name: &str, namespace: &str, labels: JsonMap, annotations: JsonMap) -> Self {
        Self {
            name: name.to_string(),
            namespace: namespace.to_string(),
            labels,
            annotations,
        }
    }

    fn metadata(&self) -> JsonValue {
        metadata(
            Some(&self.name),
            Some(&self.namespace),
            Some(self.labels.clone()),
            Some(self.annotations.clone()),
        )
    }
}

fn statefulset_manifest(
    resource_metadata: ManifestMetadata,
    selector_labels: JsonMap,
    pod_annotations: JsonMap,
    container: JsonValue,
    volumes: Vec<JsonValue>,
    service_name: &str,
) -> JsonValue {
    let mut spec = JsonMap::new();
    spec.insert("serviceName".to_string(), json!(service_name.to_string()));
    spec.insert("replicas".to_string(), json!(1));

    let mut selector = JsonMap::new();
    selector.insert(
        "matchLabels".to_string(),
        JsonValue::Object(selector_labels.clone()),
    );
    spec.insert("selector".to_string(), JsonValue::Object(selector));

    let template_metadata = metadata(None, None, Some(selector_labels), Some(pod_annotations));

    let mut template_spec = JsonMap::new();
    template_spec.insert("containers".to_string(), JsonValue::Array(vec![container]));
    template_spec.insert("volumes".to_string(), JsonValue::Array(volumes));

    let mut template = JsonMap::new();
    template.insert("metadata".to_string(), template_metadata);
    template.insert("spec".to_string(), JsonValue::Object(template_spec));

    spec.insert("template".to_string(), JsonValue::Object(template));

    let mut root = JsonMap::new();
    root.insert("apiVersion".to_string(), json!("apps/v1"));
    root.insert("kind".to_string(), json!("StatefulSet"));
    root.insert("metadata".to_string(), resource_metadata.metadata());
    root.insert("spec".to_string(), JsonValue::Object(spec));
    JsonValue::Object(root)
}

fn deployment_manifest(
    resource_metadata: ManifestMetadata,
    selector_labels: JsonMap,
    pod_annotations: JsonMap,
    container: JsonValue,
    volumes: Vec<JsonValue>,
) -> JsonValue {
    let mut spec = JsonMap::new();
    spec.insert("replicas".to_string(), json!(1));

    let mut selector = JsonMap::new();
    selector.insert(
        "matchLabels".to_string(),
        JsonValue::Object(selector_labels.clone()),
    );
    spec.insert("selector".to_string(), JsonValue::Object(selector));

    let template_metadata = metadata(None, None, Some(selector_labels), Some(pod_annotations));

    let mut template_spec = JsonMap::new();
    template_spec.insert("containers".to_string(), JsonValue::Array(vec![container]));
    template_spec.insert("volumes".to_string(), JsonValue::Array(volumes));

    let mut template = JsonMap::new();
    template.insert("metadata".to_string(), template_metadata);
    template.insert("spec".to_string(), JsonValue::Object(template_spec));

    spec.insert("template".to_string(), JsonValue::Object(template));

    let mut root = JsonMap::new();
    root.insert("apiVersion".to_string(), json!("apps/v1"));
    root.insert("kind".to_string(), json!("Deployment"));
    root.insert("metadata".to_string(), resource_metadata.metadata());
    root.insert("spec".to_string(), JsonValue::Object(spec));
    JsonValue::Object(root)
}

fn job_manifest(
    name: &str,
    namespace: &str,
    labels: JsonMap,
    annotations: JsonMap,
    container: JsonValue,
    volumes: Vec<JsonValue>,
) -> JsonValue {
    let pod_metadata = metadata(None, None, Some(labels.clone()), Some(annotations.clone()));

    let mut pod_spec = JsonMap::new();
    pod_spec.insert("containers".to_string(), JsonValue::Array(vec![container]));
    pod_spec.insert("volumes".to_string(), JsonValue::Array(volumes));
    pod_spec.insert("restartPolicy".to_string(), json!("Never"));

    let mut template = JsonMap::new();
    template.insert("metadata".to_string(), pod_metadata);
    template.insert("spec".to_string(), JsonValue::Object(pod_spec));

    let mut spec = JsonMap::new();
    spec.insert("template".to_string(), JsonValue::Object(template));
    spec.insert("backoffLimit".to_string(), json!(1));
    spec.insert("completions".to_string(), json!(1));
    spec.insert("parallelism".to_string(), json!(1));

    let mut root = JsonMap::new();
    root.insert("apiVersion".to_string(), json!("batch/v1"));
    root.insert("kind".to_string(), json!("Job"));
    root.insert(
        "metadata".to_string(),
        metadata(Some(name), Some(namespace), Some(labels), Some(annotations)),
    );
    root.insert("spec".to_string(), JsonValue::Object(spec));
    JsonValue::Object(root)
}

fn standard_labels(
    component: &str,
    role: &str,
    universe_id: &str,
    tenant_id: Option<&str>,
) -> JsonMap {
    let mut labels = JsonMap::new();
    labels.insert("app.kubernetes.io/part-of".to_string(), json!("veen"));
    labels.insert(
        "app.kubernetes.io/component".to_string(),
        json!(component.to_string()),
    );
    labels.insert("veen.io/role".to_string(), json!(role.to_string()));
    labels.insert(
        "veen.io/universe-id".to_string(),
        json!(universe_id.to_string()),
    );
    if let Some(tenant) = tenant_id {
        labels.insert("veen.io/tenant-id".to_string(), json!(tenant.to_string()));
    }
    labels
}

fn default_annotations(profile: &str, version: &str, config_hash: Option<&str>) -> JsonMap {
    let mut annotations = JsonMap::new();
    annotations.insert("veen.io/profile".to_string(), json!(profile.to_string()));
    annotations.insert("veen.io/version".to_string(), json!(version.to_string()));
    if let Some(hash) = config_hash {
        annotations.insert("veen.io/config-hash".to_string(), json!(hash.to_string()));
    }
    annotations
}

fn metadata(
    name: Option<&str>,
    namespace: Option<&str>,
    labels: Option<JsonMap>,
    annotations: Option<JsonMap>,
) -> JsonValue {
    let mut meta = JsonMap::new();
    if let Some(n) = name {
        meta.insert("name".to_string(), json!(n.to_string()));
    }
    if let Some(ns) = namespace {
        meta.insert("namespace".to_string(), json!(ns.to_string()));
    }
    if let Some(map) = labels {
        if !map.is_empty() {
            meta.insert("labels".to_string(), JsonValue::Object(map));
        }
    }
    if let Some(map) = annotations {
        if !map.is_empty() {
            meta.insert("annotations".to_string(), JsonValue::Object(map));
        }
    }
    JsonValue::Object(meta)
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

fn sha256_hex_multi(chunks: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hex::encode(hasher.finalize())
}

fn render_yaml_documents(docs: &[JsonValue]) -> Result<String> {
    let mut rendered = String::new();
    for (idx, doc) in docs.iter().enumerate() {
        if idx > 0 {
            rendered.push_str("---\n");
        }
        let serialized = serde_yaml::to_string(doc).context("serializing Kubernetes manifest")?;
        rendered.push_str(&serialized);
    }
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(rendered)
}

fn init_tracing() {
    let default_level = if global_options().quiet {
        "error"
    } else {
        "info"
    };
    let subscriber = tracing_subscriber::fmt().with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level)),
    );
    let _ = subscriber.try_init();
}

async fn handle_hub_start(args: HubStartArgs) -> Result<()> {
    if !args.foreground && env::var_os("VEEN_CLI_BACKGROUND").is_none() {
        spawn_background_hub(&args).await?;
        return Ok(());
    }

    run_hub_foreground(args).await
}

async fn run_hub_foreground(args: HubStartArgs) -> Result<()> {
    if let Some(ref config) = args.config {
        if !fs::try_exists(config)
            .await
            .with_context(|| format!("checking config {}", config.display()))?
        {
            bail_usage!("config file {} does not exist", config.display());
        }
    }

    ensure_data_dir_layout(&args.data_dir).await?;

    let HubStartArgs {
        listen,
        data_dir,
        config,
        profile_id,
        foreground,
        log_level,
    } = args;

    let profile_id = resolve_profile_id(profile_id)?;
    let log_level_str = log_level.as_ref().map(ToString::to_string);

    let key_info = ensure_hub_key_material(&data_dir).await?;

    let overrides = HubConfigOverrides {
        profile_id: Some(profile_id.clone()),
        ..HubConfigOverrides::default()
    };
    let runtime_config = HubRuntimeConfig::from_sources(
        listen,
        data_dir.clone(),
        config.clone(),
        HubRole::Primary,
        overrides,
    )
    .await?;
    let runtime = HubRuntime::start(runtime_config).await?;
    let actual_listen = runtime.listen_addr();

    let mut state = load_hub_state(&data_dir).await?;
    let now = current_unix_timestamp()?;
    let launched_in_background = env::var_os("VEEN_CLI_BACKGROUND").is_some();
    state
        .record_start(HubStartContext {
            data_dir: &data_dir,
            listen: actual_listen,
            profile_id: profile_id.clone(),
            hub_id: key_info.hub_id_hex.clone(),
            log_level: log_level_str.clone(),
            now,
            pid: process::id(),
            foreground: foreground && !launched_in_background,
        })
        .with_context(|| format!("updating hub state in {}", data_dir.display()))?;

    save_hub_state(&data_dir, &state).await?;
    write_pid_file(&data_dir, process::id()).await?;
    ensure_tls_info(&data_dir).await?;

    tracing::info!(
        listen = %actual_listen,
        data_dir = %data_dir.display(),
        profile_id,
        hub_id = %key_info.hub_id_hex,
        "started VEEN hub runtime",
    );

    if launched_in_background {
        tracing::info!("hub running in background; awaiting shutdown signal");
    } else {
        println!("hub_id: {}", key_info.hub_id_hex);
        println!("listen: {}", actual_listen);
        println!("profile_id: {}", profile_id);
        println!("data_dir: {}", data_dir.display());
        if let Some(level) = &log_level_str {
            println!("log_level: {level}");
        }
        println!("running hub in foreground; press Ctrl+C to stop");
    }

    wait_for_shutdown_signal().await?;
    println!("shutdown signal received; stopping hub");
    runtime.shutdown().await?;

    let stop_ts = current_unix_timestamp()?;
    state.record_stop(stop_ts);
    save_hub_state(&data_dir, &state).await?;
    remove_pid_file(&data_dir).await?;
    println!("hub stopped. uptime_sec={}", state.uptime(stop_ts));
    log_cli_goal("CLI.HUB0.START");
    Ok(())
}

async fn spawn_background_hub(args: &HubStartArgs) -> Result<()> {
    let exe = env::current_exe().context("locating veen executable")?;
    let mut command = StdCommand::new(exe);
    command.arg("hub").arg("start");
    command.arg("--listen").arg(args.listen.to_string());
    command.arg("--data-dir").arg(&args.data_dir);
    if let Some(ref config) = args.config {
        command.arg("--config").arg(config);
    }
    if let Some(ref profile_id) = args.profile_id {
        command.arg("--profile-id").arg(profile_id);
    }
    if let Some(ref level) = args.log_level {
        command.arg("--log-level").arg(level.to_string());
        command.env("RUST_LOG", format!("veen_hub={level}"));
    }
    command.arg("--foreground");
    command.env("VEEN_CLI_BACKGROUND", "1");
    command.stdin(Stdio::null());

    let mut child = command
        .spawn()
        .context("spawning VEEN hub background process")?;
    let pid = child.id();
    if let Some(status) = child
        .try_wait()
        .context("checking hub process status after spawn")?
    {
        bail_hub!("hub process exited immediately with status {status}");
    }
    drop(child);

    let ready_state = wait_for_hub_ready(&args.data_dir).await?;

    if let Some(ref hub_id) = ready_state.hub_id {
        println!("hub_id: {hub_id}");
    }
    if let Some(ref listen) = ready_state.listen {
        println!("listen: {listen}");
    }
    if let Some(ref profile) = ready_state.profile_id {
        println!("profile_id: {profile}");
    }
    println!("data_dir: {}", ready_state.data_dir);
    println!("hub running in background with pid={pid}");
    println!(
        "use `veen hub stop --data-dir {}` to stop the hub",
        args.data_dir.display()
    );

    Ok(())
}

async fn wait_for_hub_ready(data_dir: &Path) -> Result<HubRuntimeState> {
    const ATTEMPTS: u32 = 100;
    for attempt in 0..ATTEMPTS {
        let state = load_hub_state(data_dir).await?;
        if state.running && state.hub_id.is_some() && state.listen.is_some() {
            return Ok(state);
        }
        if attempt == ATTEMPTS - 1 {
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    bail_hub!(
        "hub process in {} did not report ready state within timeout",
        data_dir.display()
    );
}

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            unix_signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
        tokio::select! {
            res = signal::ctrl_c() => res.context("waiting for shutdown signal"),
            res = async {
                terminate.recv().await;
                Ok::<(), anyhow::Error>(())
            } => res,
        }
    }
    #[cfg(not(unix))]
    {
        signal::ctrl_c()
            .await
            .context("waiting for shutdown signal")?;
        Ok(())
    }
}

#[cfg(unix)]
async fn signal_and_wait_for_exit(pid: u32) -> Result<()> {
    let raw_pid = pid as i32;
    let pid = Pid::from_raw(raw_pid);
    kill(pid, Signal::SIGINT)
        .map_err(|err| anyhow!("failed to signal hub process {raw_pid}: {err}"))?;

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match kill(pid, None) {
            Ok(()) => {
                if Instant::now() >= deadline {
                    bail_hub!("hub process {raw_pid} did not exit within 30 seconds");
                }
                sleep(Duration::from_millis(100)).await;
            }
            Err(Errno::ESRCH) => break,
            Err(err) => {
                return Err(anyhow!(
                    "failed to check hub process {raw_pid} status: {err}"
                ));
            }
        }
    }

    Ok(())
}

#[cfg(not(unix))]
async fn signal_and_wait_for_exit(_pid: u32) -> Result<()> {
    bail_hub!("hub stop is not supported on this platform");
}

async fn handle_hub_stop(args: HubStopArgs) -> Result<()> {
    let state = load_hub_state(&args.data_dir).await?;
    if !state.running {
        bail_usage!(
            "hub in {} is not marked as running",
            args.data_dir.display()
        );
    }

    let pid = state.pid.with_context(|| {
        format!(
            "hub in {} does not have an active pid",
            args.data_dir.display()
        )
    })?;

    signal_and_wait_for_exit(pid).await?;

    flush_hub_storage(&args.data_dir).await?;

    let mut refreshed_state = load_hub_state(&args.data_dir).await?;
    let stop_ts = current_unix_timestamp()?;
    if refreshed_state.running {
        refreshed_state.record_stop(stop_ts);
        save_hub_state(&args.data_dir, &refreshed_state).await?;
    }
    remove_pid_file(&args.data_dir).await?;

    println!(
        "hub stopped. uptime_sec={}",
        refreshed_state.uptime(stop_ts)
    );
    log_cli_goal("CLI.HUB0.STOP");
    Ok(())
}

async fn handle_hub_status(args: HubStatusArgs) -> Result<()> {
    let result = match parse_hub_reference(&args.hub)? {
        HubReference::Local(data_dir) => {
            let state = load_hub_state(&data_dir).await?;

            let profile_id = state.profile_id.as_deref().with_context(|| {
                format!("hub in {} has not been initialised", data_dir.display())
            })?;

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
        HubReference::Remote(client) => {
            let report: RemoteObservabilityReport = client.get_json("/metrics", &[]).await?;

            println!("role: {}", report.role);
            if let Some(profile_id) = report.profile_id.as_deref() {
                println!("profile_id: {profile_id}");
            }
            println!("peaks_count: {}", report.peaks_count);
            if report.last_stream_seq.is_empty() {
                println!("last_stream_seq: (none)");
            } else {
                println!("last_stream_seq:");
                for (label, seq) in report.last_stream_seq.iter() {
                    println!("  {label}: {seq}");
                }
            }
            println!("uptime_sec: {}", report.uptime.as_secs());
            println!("data_dir: {}", report.data_dir);
            if let Some(hub_id) = report.hub_id.as_deref() {
                println!("hub_id: {hub_id}");
            }
            if let Some(hub_pk) = report.hub_public_key.as_deref() {
                println!("hub_pk: {hub_pk}");
            }
            Ok(())
        }
    };

    if result.is_ok() {
        log_cli_goal("CLI.HUB0.STATUS");
    }

    result
}

async fn handle_hub_key(args: HubKeyArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Local(data_dir) => {
            let key_info = read_hub_key_material(&data_dir).await?;

            println!("hub_id: {}", key_info.hub_id_hex);
            println!("hub_pk: {}", key_info.public_key_hex);
            println!("created_at: {}", key_info.created_at);

            log_cli_goal("CLI.KEX0.HUB_KEY");
            Ok(())
        }
        HubReference::Remote(client) => {
            let report: RemoteObservabilityReport = client.get_json("/metrics", &[]).await?;
            let hub_pk = report
                .hub_public_key
                .as_deref()
                .ok_or_else(|| anyhow!("remote hub did not return a public key"))?;
            println!("hub_pk: {hub_pk}");
            if let Some(hub_id) = report.hub_id.as_deref() {
                println!("hub_id: {hub_id}");
            }
            if let Some(profile_id) = report.profile_id.as_deref() {
                println!("profile_id: {profile_id}");
            }
            log_cli_goal("CLI.KEX0.HUB_KEY");
            Ok(())
        }
    }
}

async fn handle_hub_verify_rotation(args: HubVerifyRotationArgs) -> Result<()> {
    let checkpoint: Checkpoint = read_cbor_file(&args.checkpoint).await?;

    if !checkpoint.has_valid_version() {
        bail_protocol!(
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
        bail_protocol!(
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
        bail_protocol!("no witness signature validated with the supplied old hub key");
    }
    if !new_verified {
        bail_protocol!("no witness signature validated with the supplied new hub key");
    }

    println!(
        "checkpoint rotation verified: hub_sig (new key) and witness_sigs (old+new) are valid"
    );
    log_cli_goal("CLI.KEX0.VERIFY_ROTATION");
    Ok(())
}

async fn handle_hub_health(args: HubHealthArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Local(data_dir) => {
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
        }
        HubReference::Remote(client) => {
            let health: RemoteHealthStatus = client.get_json("/healthz", &[]).await?;
            println!("status: {}", if health.ok { "running" } else { "error" });
            println!("uptime_sec: {}", health.uptime.as_secs());
            println!("role: {}", health.role);
            println!("peaks_count: {}", health.peaks_count);
            if let Some(profile_id) = health.profile_id.as_deref() {
                println!("profile_id: {profile_id}");
            }
            if let Some(hub_id) = health.hub_id.as_deref() {
                println!("hub_id: {hub_id}");
            }
            if let Some(hub_pk) = health.hub_public_key.as_deref() {
                println!("hub_pk: {hub_pk}");
            }
            println!("submit_ok_total: {}", health.submit_ok_total);
            if health.submit_err_total.is_empty() {
                println!("submit_err_total: (none)");
            } else {
                println!("submit_err_total:");
                for (code, count) in health.submit_err_total.iter() {
                    println!("  {code}: {count}");
                }
            }
            if health.last_stream_seq.is_empty() {
                println!("last_stream_seq: (none)");
            } else {
                println!("last_stream_seq:");
                for (label, seq) in health.last_stream_seq.iter() {
                    println!("  {label}: {seq}");
                }
            }
            if health.mmr_roots.is_empty() {
                println!("mmr_roots: (none)");
            } else {
                println!("mmr_roots:");
                for (label, root) in health.mmr_roots.iter() {
                    println!("  {label}: {root}");
                }
            }
            println!("data_dir: {}", health.data_dir);
        }
    }

    log_cli_goal("CLI.OBS0.HEALTH");
    Ok(())
}

async fn handle_hub_metrics(args: HubMetricsArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Local(data_dir) => {
            let state = load_hub_state(&data_dir).await?;
            let metrics = state.metrics.clone();

            if args.raw {
                print_metrics_raw(&metrics);
            } else {
                print_metrics_summary(&metrics);
            }
        }
        HubReference::Remote(client) => {
            let report: RemoteObservabilityReport = client.get_json("/metrics", &[]).await?;
            let metrics = HubMetricsSnapshot::from_remote(&report);
            if args.raw {
                print_metrics_raw(&metrics);
            } else {
                print_metrics_summary(&metrics);
            }
        }
    }

    log_cli_goal("CLI.OBS0.METRICS");
    Ok(())
}

async fn handle_hub_profile(args: HubProfileArgs) -> Result<()> {
    let client = match parse_hub_reference(&args.hub)? {
        HubReference::Local(_) => {
            bail_usage!("hub profile requires an HTTP hub endpoint (e.g. http://host:port)");
        }
        HubReference::Remote(client) => client,
    };

    let use_json = json_output_enabled(args.json);
    let descriptor: RemoteHubProfileDescriptor = client.get_json("/profile", &[]).await?;
    let RemoteHubProfileDescriptor {
        ok,
        version,
        profile_id,
        hub_id,
        features,
    } = descriptor;

    if !ok {
        emit_cli_error(
            "E.PROFILE",
            Some("hub declined to provide a capability profile"),
            use_json,
        );
        process::exit(4);
    }

    let profile_id = match profile_id {
        Some(value) => value,
        None => {
            emit_cli_error(
                "E.PROFILE",
                Some("hub did not provide a profile identifier"),
                use_json,
            );
            process::exit(4);
        }
    };

    let output = format_hub_profile_output(ok, &version, &profile_id, &hub_id, &features, use_json);
    println!("{output}");

    log_cli_goal("CLI.V0_0_1_PP.PROFILE");
    Ok(())
}

async fn handle_hub_role(args: HubRoleArgs) -> Result<()> {
    let HubRoleArgs {
        hub,
        realm,
        stream,
        json,
    } = args;

    let client = match parse_hub_reference(&hub)? {
        HubReference::Local(_) => {
            bail_usage!("hub role requires an HTTP hub endpoint (e.g. http://host:port)");
        }
        HubReference::Remote(client) => client,
    };

    let realm_id = match realm {
        Some(value) => Some(parse_realm_id_hex(&value)?),
        None => None,
    };

    let stream_id = match stream {
        Some(ref value) => Some(
            cap_stream_id_from_label(value)
                .with_context(|| format!("deriving stream identifier for {value}"))?,
        ),
        None => None,
    };

    let mut query = Vec::new();
    if let Some(ref stream_id) = stream_id {
        query.push(("stream_id", hex::encode(stream_id.as_ref())));
    }
    if let Some(ref realm_id) = realm_id {
        query.push(("realm_id", hex::encode(realm_id.as_ref())));
    }

    let use_json = json_output_enabled(json);

    let response: RemoteHubRoleDescriptor = client.get_json("/role", &query).await?;
    let RemoteHubRoleDescriptor {
        ok,
        hub_id,
        role,
        stream: stream_info,
    } = response;

    if !ok {
        emit_cli_error(
            "E.PROFILE",
            Some("hub declined to provide role information"),
            use_json,
        );
        process::exit(4);
    }

    if stream_id.is_some() && stream_info.is_none() {
        emit_cli_error(
            "E.PROFILE",
            Some("hub did not return role information for the requested stream"),
            use_json,
        );
        process::exit(4);
    }

    let output = format_hub_role_output(ok, &hub_id, &role, stream_info.as_ref(), use_json);
    println!("{output}");

    log_cli_goal("CLI.AUTH1.ROLE");
    Ok(())
}

async fn handle_hub_kex_policy(args: HubKexPolicyArgs) -> Result<()> {
    let client = match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => client,
        HubReference::Local(_) => {
            bail_usage!("hub kex-policy requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    };

    let descriptor = fetch_remote_kex_policy_descriptor(&client).await?;
    render_kex_policy(&descriptor, json_output_enabled(args.json));
    log_cli_goal("CLI.KEX1_PLUS.POLICY");
    Ok(())
}

async fn handle_hub_admission(args: HubAdmissionArgs) -> Result<()> {
    let client = match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => client,
        HubReference::Local(_) => {
            bail_usage!("hub admission requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    };

    let report: RemoteAdmissionReport = client.get_json("/admission", &[]).await?;
    render_admission_report(&report, json_output_enabled(args.json));
    log_cli_goal("CLI.SH1_PLUS.ADMISSION");
    Ok(())
}

async fn handle_hub_admission_log(args: HubAdmissionLogArgs) -> Result<()> {
    let client = match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => client,
        HubReference::Local(_) => {
            bail_usage!("hub admission-log requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    };

    let mut query = Vec::new();
    if let Some(limit) = args.limit {
        query.push(("limit", limit.to_string()));
    }
    if let Some(codes) = args.codes {
        query.push(("codes", codes));
    }

    let response: RemoteAdmissionLogResponse = client.get_json("/admission_log", &query).await?;
    render_admission_log(&response, json_output_enabled(args.json));
    log_cli_goal("CLI.SH1_PLUS.ADMISSION_LOG");
    Ok(())
}

async fn fetch_remote_kex_policy_descriptor(
    client: &HubHttpClient,
) -> Result<RemoteKexPolicyDescriptor> {
    client.get_json("/kex_policy", &[]).await
}

fn render_kex_policy(descriptor: &RemoteKexPolicyDescriptor, use_json: bool) {
    if !descriptor.ok {
        emit_cli_error(
            "E.PROFILE",
            Some("hub declined to provide key lifecycle policy information"),
            use_json,
        );
        process::exit(4);
    }

    if use_json {
        let output = json!({
            "ok": true,
            "max_client_id_lifetime_sec": descriptor.max_client_id_lifetime_sec,
            "max_msgs_per_client_id_per_label": descriptor.max_msgs_per_client_id_per_label,
            "default_cap_ttl_sec": descriptor.default_cap_ttl_sec,
            "max_cap_ttl_sec": descriptor.max_cap_ttl_sec,
            "revocation_stream": descriptor.revocation_stream,
            "rotation_window_sec": descriptor.rotation_window_sec,
        });
        match serde_json::to_string_pretty(&output) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => println!("{output}"),
        }
    } else {
        println!(
            "max_client_id_lifetime_sec: {}",
            display_or_unspecified(descriptor.max_client_id_lifetime_sec)
        );
        println!(
            "max_msgs_per_client_id_per_label: {}",
            display_or_unspecified(descriptor.max_msgs_per_client_id_per_label)
        );
        println!(
            "default_cap_ttl_sec: {}",
            display_or_unspecified(descriptor.default_cap_ttl_sec)
        );
        println!(
            "max_cap_ttl_sec: {}",
            display_or_unspecified(descriptor.max_cap_ttl_sec)
        );
        println!(
            "revocation_stream: {}",
            descriptor
                .revocation_stream
                .clone()
                .unwrap_or_else(|| "unspecified".to_string())
        );
        println!(
            "rotation_window_sec: {}",
            display_or_unspecified(descriptor.rotation_window_sec)
        );
    }
}

fn render_admission_report(report: &RemoteAdmissionReport, use_json: bool) {
    if !report.ok {
        emit_cli_error(
            "E.PROFILE",
            Some("hub declined to provide admission data"),
            use_json,
        );
        process::exit(4);
    }

    if use_json {
        let output = json!({ "ok": true, "stages": report.stages });
        match serde_json::to_string_pretty(&output) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => println!("{output}"),
        }
    } else if report.stages.is_empty() {
        println!("admission stages: (none)");
    } else {
        println!("admission stages:");
        for stage in &report.stages {
            println!("- name: {}", stage.name);
            println!("  enabled: {}", stage.enabled);
            if stage.responsibilities.is_empty() {
                println!("  responsibilities: (none)");
            } else {
                println!("  responsibilities:");
                for resp in &stage.responsibilities {
                    println!("    - {resp}");
                }
            }
            println!("  queue_depth: {}", stage.queue_depth);
            println!("  max_queue_depth: {}", stage.max_queue_depth);
            if stage.recent_err_rates.is_empty() {
                println!("  recent_err_rates: (none)");
            } else {
                println!("  recent_err_rates:");
                for (code, rate) in stage.recent_err_rates.iter() {
                    println!("    {code}: {rate}");
                }
            }
        }
    }
}

fn render_admission_log(response: &RemoteAdmissionLogResponse, use_json: bool) {
    if !response.ok {
        emit_cli_error(
            "E.PROFILE",
            Some("hub declined to provide admission log data"),
            use_json,
        );
        process::exit(4);
    }

    if use_json {
        let output = json!({ "ok": true, "events": response.events });
        match serde_json::to_string_pretty(&output) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => println!("{output}"),
        }
    } else if response.events.is_empty() {
        println!("admission failures: (none)");
    } else {
        println!("admission failures:");
        for event in &response.events {
            println!("- ts: {}", event.ts);
            println!("  code: {}", event.code);
            println!("  label_prefix: {}", event.label_prefix);
            println!("  client_id_prefix: {}", event.client_id_prefix);
            println!("  detail: {}", event.detail);
        }
    }
}

fn display_or_unspecified<T>(value: Option<T>) -> String
where
    T: ToString,
{
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "unspecified".to_string())
}

async fn handle_hub_checkpoint_latest(args: HubCheckpointLatestArgs) -> Result<Checkpoint> {
    let client = match parse_hub_reference(&args.hub)? {
        HubReference::Local(_) => {
            bail_usage!("checkpoint commands require an HTTP hub endpoint (e.g. http://host:port)")
        }
        HubReference::Remote(client) => client,
    };

    let checkpoint: Checkpoint = client.get_cbor("/checkpoint_latest", &[]).await?;
    print_checkpoint_summary(&checkpoint);
    log_cli_goal("CLI.RESYNC0.CHECKPOINT_LATEST");
    Ok(checkpoint)
}

async fn handle_hub_checkpoint_range(args: HubCheckpointRangeArgs) -> Result<Vec<Checkpoint>> {
    let client = match parse_hub_reference(&args.hub)? {
        HubReference::Local(_) => {
            bail_usage!("checkpoint commands require an HTTP hub endpoint (e.g. http://host:port)")
        }
        HubReference::Remote(client) => client,
    };

    let mut query = Vec::new();
    if let Some(from) = args.from_epoch {
        query.push(("from_epoch", from.to_string()));
    }
    if let Some(to) = args.to_epoch {
        query.push(("to_epoch", to.to_string()));
    }

    let checkpoints: Vec<Checkpoint> = client.get_cbor("/checkpoint_range", &query).await?;
    if checkpoints.is_empty() {
        println!("no checkpoints returned");
    } else {
        for (index, checkpoint) in checkpoints.iter().enumerate() {
            println!("checkpoint[{index}]:");
            print_checkpoint_summary(checkpoint);
        }
    }
    log_cli_goal("CLI.RESYNC0.CHECKPOINT_RANGE");
    Ok(checkpoints)
}

fn print_checkpoint_summary(checkpoint: &Checkpoint) {
    println!("ver: {}", checkpoint.ver);
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
    println!(
        "witness_sigs: {}",
        checkpoint
            .witness_sigs
            .as_ref()
            .map(|w| w.len())
            .unwrap_or(0)
    );
}

async fn handle_hub_tls_info(args: HubTlsInfoArgs) -> Result<()> {
    let hub = parse_hub_reference(&args.hub)?.into_local()?;
    let tls_info_path = hub.join(STATE_DIR).join(TLS_INFO_FILE);
    if !fs::try_exists(&tls_info_path)
        .await
        .with_context(|| format!("checking TLS metadata in {}", tls_info_path.display()))?
    {
        bail_usage!(
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
    log_cli_goal("CLI.SH0.TLS_INFO");
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

    log_cli_goal("CLI.CORE.KEYGEN");
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

    log_cli_goal("CLI.KEX0.ID_SHOW");
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

    log_cli_goal("CLI.KEX0.ID_ROTATE");
    Ok(())
}

async fn handle_id_usage(args: IdUsageArgs) -> Result<()> {
    let client_dir = args.client;
    let identity_path = client_dir.join("identity_card.pub");
    let state_path = client_dir.join("state.json");

    let identity: ClientPublicBundle = read_cbor_file(&identity_path).await?;
    let state: ClientStateFile = read_json_file(&state_path).await?;

    let policy_descriptor = if let Some(hub) = args.hub.as_deref() {
        let client = match parse_hub_reference(hub)? {
            HubReference::Remote(client) => client,
            HubReference::Local(_) => {
                bail_usage!("id usage policy requires an HTTP hub endpoint (e.g. http://host:port)")
            }
        };
        Some(fetch_remote_kex_policy_descriptor(&client).await?)
    } else {
        None
    };

    if let Some(descriptor) = policy_descriptor.as_ref() {
        if !descriptor.ok {
            bail_hub!("hub declined to provide key lifecycle policy information");
        }
    }

    let policy = policy_descriptor
        .as_ref()
        .map(|descriptor| KexPolicyThresholds {
            max_client_id_lifetime_sec: descriptor.max_client_id_lifetime_sec,
            max_msgs_per_client_id_per_label: descriptor.max_msgs_per_client_id_per_label,
        });

    let now = current_unix_timestamp()?;
    let client_id_hex = hex::encode(identity.client_id.as_ref());
    let mut entries = Vec::new();
    for (stream, label_state) in state.labels.iter() {
        let label_hex = match cap_stream_id_from_label(stream) {
            Ok(stream_id) => hex::encode(stream_id.as_ref()),
            Err(_) => "unspecified".to_string(),
        };
        let approx_lifetime_sec = label_state
            .first_sent_at
            .map(|ts| now.saturating_sub(ts))
            .unwrap_or(0);
        let exceeds_msg_bound = policy
            .as_ref()
            .and_then(|p| p.max_msgs_per_client_id_per_label)
            .map(|max| label_state.msgs_sent > max)
            .unwrap_or(false);
        let exceeds_lifetime_bound = policy
            .as_ref()
            .and_then(|p| p.max_client_id_lifetime_sec)
            .map(|max| approx_lifetime_sec > max)
            .unwrap_or(false);
        entries.push(IdUsageEntry {
            stream: stream.clone(),
            label_hex,
            client_id: client_id_hex.clone(),
            created_at: identity.created_at,
            msgs_sent: label_state.msgs_sent,
            approx_lifetime_sec,
            exceeds_msg_bound,
            exceeds_lifetime_bound,
            rotation_recommended: exceeds_msg_bound || exceeds_lifetime_bound,
        });
    }

    render_id_usage(&entries, json_output_enabled(args.json));
    log_cli_goal("CLI.KEX1_PLUS.ID_USAGE");
    Ok(())
}

fn render_id_usage(entries: &[IdUsageEntry], use_json: bool) {
    if use_json {
        let rendered: Vec<_> = entries
            .iter()
            .map(|entry| {
                json!({
                    "stream": entry.stream,
                    "label": entry.label_hex,
                    "client_id": entry.client_id,
                    "created_at": entry.created_at,
                    "msgs_sent": entry.msgs_sent,
                    "approx_lifetime_sec": entry.approx_lifetime_sec,
                    "exceeds_msg_bound": entry.exceeds_msg_bound,
                    "exceeds_lifetime_bound": entry.exceeds_lifetime_bound,
                    "rotation_recommended": entry.rotation_recommended,
                })
            })
            .collect();
        let output = json!({ "ok": true, "entries": rendered });
        match serde_json::to_string_pretty(&output) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => println!("{output}"),
        }
    } else if entries.is_empty() {
        println!("client usage: (no recorded sends)");
    } else {
        println!("client usage:");
        for entry in entries {
            println!("- stream: {}", entry.stream);
            println!("  label: {}", entry.label_hex);
            println!("  client_id: {}", entry.client_id);
            println!("  created_at: {}", entry.created_at);
            println!("  msgs_sent: {}", entry.msgs_sent);
            println!("  approx_lifetime_sec: {}", entry.approx_lifetime_sec);
            println!("  exceeds_msg_bound: {}", entry.exceeds_msg_bound);
            println!("  exceeds_lifetime_bound: {}", entry.exceeds_lifetime_bound);
            println!("  rotation_recommended: {}", entry.rotation_recommended);
        }
    }
}

async fn handle_send(args: SendArgs) -> Result<()> {
    let result = match parse_hub_reference(&args.hub)? {
        HubReference::Local(data_dir) => handle_send_local(data_dir, args).await,
        HubReference::Remote(client) => handle_send_remote(client, args).await,
    };

    if result.is_ok() {
        log_cli_goal("CLI.CORE.SEND");
    }

    result
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
            bail_usage!("schema identifiers must be 32 or 64 hex characters");
        }
        if !schema.chars().all(|c| c.is_ascii_hexdigit()) {
            bail_usage!("schema identifiers must be hexadecimal");
        }
    }

    if let Some(ref cap_path) = args.cap {
        if !fs::try_exists(cap_path)
            .await
            .with_context(|| format!("checking capability file {}", cap_path.display()))?
        {
            bail_usage!("capability file {} does not exist", cap_path.display());
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

    update_client_label_send_state(&args.client, &args.stream, seq, now).await?;

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
    if args.pow_challenge.is_some() && args.pow_difficulty.is_none() {
        bail_usage!("--pow-challenge requires --pow-difficulty");
    }

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
            bail_usage!("schema identifiers must be 32 or 64 hex characters");
        }
        if !schema.chars().all(|c| c.is_ascii_hexdigit()) {
            bail_usage!("schema identifiers must be hexadecimal");
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

    let pow_cookie = if let Some(difficulty) = args.pow_difficulty {
        if difficulty == 0 {
            bail_usage!("--pow-difficulty must be greater than zero");
        }

        let challenge = if let Some(ref hex_value) = args.pow_challenge {
            let bytes = hex::decode(hex_value.trim())
                .with_context(|| format!("decoding pow challenge {hex_value}"))?;
            if bytes.is_empty() {
                bail_usage!("--pow-challenge must not be empty");
            }
            bytes
        } else {
            let mut bytes = vec![0u8; 32];
            OsRng.fill_bytes(&mut bytes);
            bytes
        };

        let cookie = solve_pow_cookie(challenge, difficulty)?;
        println!(
            "proof-of-work: nonce={} difficulty={} challenge={}",
            cookie.nonce,
            cookie.difficulty,
            hex::encode(&cookie.challenge)
        );

        Some(PowCookieEnvelope::from_cookie(&cookie))
    } else {
        None
    };

    let request = RemoteSubmitRequest {
        stream: args.stream.clone(),
        client_id: client_id_hex.clone(),
        payload,
        attachments,
        auth_ref: auth_ref_hex,
        expires_at: args.expires_at,
        schema: args.schema.clone(),
        idem: None,
        pow_cookie,
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

    let send_ts = current_unix_timestamp()?;
    update_client_label_send_state(&args.client, &args.stream, response.seq, send_ts).await?;

    Ok(())
}

fn solve_pow_cookie(challenge: Vec<u8>, difficulty: u8) -> Result<PowCookie> {
    solve_pow_cookie_with_limit(challenge, difficulty, None)
}

fn solve_pow_cookie_with_limit(
    challenge: Vec<u8>,
    difficulty: u8,
    max_iterations: Option<u64>,
) -> Result<PowCookie> {
    let mut cookie = PowCookie {
        challenge,
        nonce: 0,
        difficulty,
    };
    let mut attempts = 0u64;

    loop {
        if cookie.meets_difficulty() {
            return Ok(cookie);
        }
        attempts = attempts.saturating_add(1);
        if let Some(limit) = max_iterations {
            if attempts >= limit {
                bail_hub!(
                    "failed to find proof-of-work nonce within {limit} iterations (difficulty {difficulty})"
                );
            }
        }
        if cookie.nonce == u64::MAX {
            bail_hub!("failed to find proof-of-work nonce (difficulty {difficulty})");
        }
        cookie.nonce = cookie.nonce.checked_add(1).expect("nonce overflow checked");
    }
}

async fn update_client_label_send_state(
    client_dir: &Path,
    stream: &str,
    seq: u64,
    sent_at: u64,
) -> Result<()> {
    let state_path = client_dir.join("state.json");
    let mut client_state: ClientStateFile = read_json_file(&state_path).await?;
    let label_state = client_state.ensure_label_state(stream);
    label_state.record_send(seq, sent_at);
    write_json_file(&state_path, &client_state).await?;
    Ok(())
}

async fn load_local_revocations(data_dir: &Path) -> Result<Vec<RevocationRecord>> {
    let path = data_dir.join(STATE_DIR).join(REVOCATIONS_FILE);
    if !fs::try_exists(&path)
        .await
        .with_context(|| format!("checking revocation log {}", path.display()))?
    {
        return Ok(Vec::new());
    }
    read_json_file(&path).await
}

fn render_revocations(entries: &[RenderedRevocation], use_json: bool) {
    if use_json {
        let output = json!({ "ok": true, "revocations": entries });
        match serde_json::to_string_pretty(&output) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => println!("{output}"),
        }
    } else if entries.is_empty() {
        println!("revocations: (none)");
    } else {
        println!("revocations:");
        for entry in entries {
            println!("- kind: {}", entry.kind);
            println!("  target: {}", entry.target);
            println!("  ts: {}", entry.ts);
            if let Some(ttl) = entry.ttl {
                println!("  ttl: {}", ttl);
            } else {
                println!("  ttl: none");
            }
            println!("  active_now: {}", entry.active_now);
            if let Some(reason) = &entry.reason {
                println!("  reason: {}", reason);
            }
        }
    }
}

async fn handle_stream(args: StreamArgs) -> Result<()> {
    let hub = parse_hub_reference(&args.hub)?;
    let result = match hub {
        HubReference::Local(data_dir) => {
            let stream_state = load_stream_state(&data_dir, &args.stream).await?;
            if args.with_proof {
                let mut emitted = false;
                let mut mmr = Mmr::new();
                for message in &stream_state.messages {
                    let leaf = compute_message_leaf_hash(message)?;
                    let (_, root, mmr_proof) = mmr.append_with_proof(leaf);
                    if message.seq >= args.from {
                        emitted = true;
                        print_stream_message(message);
                        let receipt = StreamReceipt {
                            seq: message.seq,
                            leaf_hash: hex::encode(leaf.as_bytes()),
                            mmr_root: hex::encode(root.as_bytes()),
                            hub_ts: message.sent_at,
                        };
                        validate_stream_proof(message, &receipt, &mmr_proof)?;
                        print_stream_receipt(&receipt);
                        let proof_wire = RemoteStreamProof::from(mmr_proof.clone());
                        print_stream_proof(&proof_wire)?;
                        println!("---");
                    }
                }

                if !emitted {
                    println!(
                        "no messages in stream {} from seq {}",
                        args.stream, args.from
                    );
                }

                Ok(())
            } else {
                let mut emitted = false;
                for message in stream_state.messages.iter().filter(|m| m.seq >= args.from) {
                    emitted = true;
                    print_stream_message(message);
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
        }
        HubReference::Remote(client) => handle_stream_remote(client, args).await,
    };

    if result.is_ok() {
        log_cli_goal("CLI.CORE.STREAM");
    }

    result
}

async fn handle_stream_remote(client: HubHttpClient, args: StreamArgs) -> Result<()> {
    let mut query: Vec<(&str, String)> = vec![("stream", args.stream.clone())];
    if args.from > 0 {
        query.push(("from", args.from.to_string()));
    }

    if args.with_proof {
        query.push(("with_proof", "true".to_string()));
        let remote_messages: Vec<RemoteStreamMessageWithProof> = client
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
            let message: StoredMessage = remote.message.into();
            let receipt = StreamReceipt::from(remote.receipt);
            let proof_wire = remote.proof;
            let proof = proof_wire
                .clone()
                .try_into_mmr()
                .context("decoding stream proof")?;
            print_stream_message(&message);
            validate_stream_proof(&message, &receipt, &proof)?;
            print_stream_receipt(&receipt);
            print_stream_proof(&proof_wire)?;
            println!("---");
        }

        return Ok(());
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
        print_stream_message(&message);
        println!("---");
    }

    Ok(())
}

async fn handle_attachment_verify(args: AttachmentVerifyArgs) -> Result<()> {
    let message: StoredMessage = read_json_file(&args.msg).await?;
    let index: usize = args.index as usize;
    if index >= message.attachments.len() {
        bail_usage!(
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
        bail_protocol!(
            "attachment digest mismatch: expected {}, computed {}",
            attachment.digest,
            digest
        );
    }

    println!(
        "attachment verified. digest={} size={} stored={}",
        attachment.digest, attachment.size, attachment.stored_path
    );
    log_cli_goal("CLI.ATTACH0.VERIFY");
    Ok(())
}

async fn handle_cap_issue(args: CapIssueArgs) -> Result<()> {
    if args.ttl == 0 {
        bail_usage!("ttl must be greater than zero seconds");
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

    log_cli_goal("CLI.CAP0.ISSUE");
    Ok(())
}

async fn handle_cap_authorize(args: CapAuthorizeArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Local(_) => {
            bail_usage!("cap authorize requires an HTTP hub endpoint (e.g. http://host:port)")
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
    let encoded = token
        .to_cbor()
        .context("serializing capability token for submission")?;

    let response: RemoteAuthorizeResponse = client
        .post_cbor("/authorize", &encoded)
        .await
        .context("authorizing capability with hub")?;

    if response.auth_ref != expected_auth_ref {
        let got_hex = hex::encode(response.auth_ref.as_ref());
        let expected_hex = hex::encode(expected_auth_ref.as_ref());
        bail_hub!("hub returned mismatched auth_ref {got_hex}; expected {expected_hex}");
    }

    let auth_ref_hex = hex::encode(response.auth_ref.as_ref());
    println!("authorised capability");
    println!("  auth_ref: {}", auth_ref_hex);
    println!("  expires_at: {}", response.expires_at);
    log_cli_goal("CLI.CAP0.AUTHORIZE");
    Ok(())
}

async fn handle_cap_status(args: CapStatusArgs) -> Result<()> {
    let client = match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => client,
        HubReference::Local(_) => {
            bail_usage!("cap status requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    };

    let token: CapToken = read_cbor_file(&args.cap)
        .await
        .with_context(|| format!("reading capability token from {}", args.cap.display()))?;
    token
        .verify()
        .map_err(|err| anyhow!("capability token verification failed: {err}"))?;
    let auth_ref = token.auth_ref().context("computing capability auth_ref")?;
    let auth_ref_hex = hex::encode(auth_ref.as_ref());

    #[derive(Serialize)]
    struct CapStatusRequest {
        auth_ref: String,
    }

    let request = CapStatusRequest {
        auth_ref: auth_ref_hex.clone(),
    };

    let response: RemoteCapStatusResponse = client
        .post_json("/cap_status", &request)
        .await
        .context("requesting capability status from hub")?;
    render_cap_status(&response, &auth_ref_hex, json_output_enabled(args.json));
    log_cli_goal("CLI.KEX1_PLUS.CAP_STATUS");
    Ok(())
}

async fn handle_cap_revocations(args: CapRevocationsArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => handle_cap_revocations_remote(client, args).await?,
        HubReference::Local(data_dir) => handle_cap_revocations_local(data_dir, args).await?,
    };

    log_cli_goal("CLI.KEX1_PLUS.REVOCATIONS");
    Ok(())
}

async fn handle_cap_revocations_remote(
    client: HubHttpClient,
    args: CapRevocationsArgs,
) -> Result<()> {
    let CapRevocationsArgs {
        kind,
        since,
        active_only,
        limit,
        json,
        ..
    } = args;

    let mut query = Vec::new();
    if let Some(kind_value) = kind {
        query.push(("kind", kind_value.as_str().to_string()));
    }
    if let Some(since) = since {
        query.push(("since", since.to_string()));
    }
    if active_only {
        query.push(("active_only", "true".to_string()));
    }
    if let Some(limit) = limit {
        query.push(("limit", limit.to_string()));
    }

    let response: RemoteRevocationList = client.get_json("/revocations", &query).await?;
    if !response.ok {
        emit_cli_error(
            "E.PROFILE",
            Some("hub declined to provide revocation records"),
            json_output_enabled(json),
        );
        process::exit(4);
    }

    let entries: Vec<RenderedRevocation> = response
        .revocations
        .into_iter()
        .map(|record| RenderedRevocation {
            kind: record.kind,
            target: record.target,
            ts: record.ts,
            ttl: record.ttl,
            reason: record.reason,
            active_now: record.active_now,
        })
        .collect();
    render_revocations(&entries, json_output_enabled(json));
    Ok(())
}

async fn handle_cap_revocations_local(data_dir: PathBuf, args: CapRevocationsArgs) -> Result<()> {
    let CapRevocationsArgs {
        kind,
        since,
        active_only,
        limit,
        json,
        ..
    } = args;

    let records = load_local_revocations(&data_dir).await?;
    let now = current_unix_timestamp()?;
    let mut rendered = Vec::new();
    for record in records {
        if let Some(filter) = kind {
            if record.kind != RevocationKind::from(filter) {
                continue;
            }
        }
        if let Some(since_ts) = since {
            if record.ts < since_ts {
                continue;
            }
        }
        let active_now = record.is_active_at(now);
        if active_only && !active_now {
            continue;
        }
        rendered.push(RenderedRevocation {
            kind: revocation_kind_label(record.kind).to_string(),
            target: hex::encode(record.target.as_ref()),
            ts: record.ts,
            ttl: record.ttl,
            reason: record.reason.clone(),
            active_now,
        });
    }

    if let Some(limit) = limit {
        rendered.truncate(limit as usize);
    }

    render_revocations(&rendered, json_output_enabled(json));
    Ok(())
}

fn render_cap_status(response: &RemoteCapStatusResponse, auth_ref_hex: &str, use_json: bool) {
    if !response.ok {
        emit_cli_error(
            "E.PROFILE",
            Some("hub declined to provide capability status"),
            use_json,
        );
        process::exit(4);
    }

    let local_status = "unknown";
    if use_json {
        let output = json!({
            "ok": true,
            "auth_ref": auth_ref_hex,
            "locally_within_ttl": local_status,
            "hub_known": response.hub_known,
            "hub_currently_valid": response.currently_valid,
            "revoked": response.revoked,
            "expires_at": response.expires_at,
            "revocation_kind": response.revocation_kind,
            "revocation_ts": response.revocation_ts,
            "reason": response.reason,
        });
        match serde_json::to_string_pretty(&output) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => println!("{output}"),
        }
    } else {
        println!("auth_ref: {}", auth_ref_hex);
        println!("locally_within_ttl: {}", local_status);
        println!("hub_known: {}", response.hub_known);
        println!("hub_currently_valid: {}", response.currently_valid);
        println!("revoked: {}", response.revoked);
        if let Some(kind) = &response.revocation_kind {
            println!("revocation_kind: {}", kind);
        } else {
            println!("revocation_kind: none");
        }
        if let Some(ts) = response.revocation_ts {
            println!("revocation_ts: {}", ts);
        }
        if let Some(expiry) = response.expires_at {
            println!("expires_at: {}", expiry);
        } else {
            println!("expires_at: unknown");
        }
        if let Some(reason) = &response.reason {
            println!("reason: {}", reason);
        }
    }
}

async fn handle_pow_request(args: PowRequestArgs) -> Result<()> {
    let client = match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => client,
        HubReference::Local(_) => {
            bail_usage!("pow request requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    };

    let mut query = Vec::new();
    if let Some(difficulty) = args.difficulty {
        if difficulty == 0 {
            bail_usage!("difficulty must be greater than zero");
        }
        query.push(("difficulty", difficulty.to_string()));
    }

    let descriptor: RemotePowChallenge = client.get_json("/pow_request", &query).await?;
    render_pow_challenge(&descriptor, json_output_enabled(args.json));
    log_cli_goal("CLI.SH1_PLUS.POW_REQUEST");
    Ok(())
}

async fn handle_pow_solve(args: PowSolveArgs) -> Result<()> {
    if args.difficulty == 0 {
        bail_usage!("difficulty must be greater than zero");
    }
    let bytes = hex::decode(args.challenge.trim())
        .with_context(|| format!("decoding pow challenge {}", args.challenge))?;
    if bytes.is_empty() {
        bail_usage!("challenge must not be empty");
    }
    let cookie = solve_pow_cookie_with_limit(bytes, args.difficulty, args.max_iterations)?;
    render_pow_solution(&cookie, json_output_enabled(args.json));
    log_cli_goal("CLI.SH1_PLUS.POW_SOLVE");
    Ok(())
}

fn render_pow_challenge(descriptor: &RemotePowChallenge, use_json: bool) {
    if !descriptor.ok {
        emit_cli_error(
            "E.PROFILE",
            Some("hub declined to provide a proof-of-work challenge"),
            use_json,
        );
        process::exit(4);
    }

    if use_json {
        let output = json!({
            "ok": true,
            "challenge": descriptor.challenge,
            "difficulty": descriptor.difficulty,
        });
        match serde_json::to_string_pretty(&output) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => println!("{output}"),
        }
    } else {
        println!("challenge: {}", descriptor.challenge);
        println!("difficulty: {}", descriptor.difficulty);
    }
}

fn render_pow_solution(cookie: &PowCookie, use_json: bool) {
    if use_json {
        let output = json!({
            "ok": true,
            "challenge": hex::encode(&cookie.challenge),
            "difficulty": cookie.difficulty,
            "nonce": cookie.nonce,
            "nonce_hex": format!("{:#x}", cookie.nonce),
            "hash_prefix_ok": true,
        });
        match serde_json::to_string_pretty(&output) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => println!("{output}"),
        }
    } else {
        println!("challenge: {}", hex::encode(&cookie.challenge));
        println!("difficulty: {}", cookie.difficulty);
        println!("nonce: {}", cookie.nonce);
        println!("nonce_hex: {:#x}", cookie.nonce);
    }
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

async fn handle_fed_authority_publish(args: FedAuthorityPublishArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => handle_fed_authority_publish_remote(client, args).await,
        HubReference::Local(_) => {
            bail_usage!(
                "fed authority publish requires an HTTP hub endpoint (e.g. http://host:port)"
            )
        }
    }
}

async fn handle_fed_authority_publish_remote(
    client: HubHttpClient,
    args: FedAuthorityPublishArgs,
) -> Result<()> {
    let FedAuthorityPublishArgs {
        hub: _,
        signer,
        realm,
        stream,
        policy,
        primary_hub,
        replica_hubs,
        ttl,
        ts,
        json,
    } = args;

    let signing_key = load_signing_key_from_dir(&signer).await?;
    let realm_id = parse_realm_id_hex(&realm)?;
    let stream_id = cap_stream_id_from_label(&stream)
        .with_context(|| format!("deriving stream identifier for {stream}"))?;
    let primary_hub = parse_hub_id_hex(&primary_hub)?;
    let mut replica_ids = Vec::new();
    for hub in &replica_hubs {
        replica_ids.push(parse_hub_id_hex(hub)?);
    }

    if matches!(policy, AuthorityPolicyValue::MultiPrimary) && replica_ids.is_empty() {
        bail_usage!("multi-primary policy requires at least one replica hub");
    }

    let policy = match policy {
        AuthorityPolicyValue::SinglePrimary => AuthorityPolicy::SinglePrimary,
        AuthorityPolicyValue::MultiPrimary => AuthorityPolicy::MultiPrimary,
    };

    let ttl = ttl.unwrap_or(0);
    let ts = ts.unwrap_or(current_unix_timestamp()?);

    let record = AuthorityRecord {
        realm_id,
        stream_id,
        primary_hub,
        replica_hubs: replica_ids,
        policy,
        ts,
        ttl,
    };

    let payload = encode_signed_envelope(schema_fed_authority(), &record, &signing_key)?;
    submit_signed_payload(&client, "/authority", &payload).await?;

    let realm_hex = hex::encode(record.realm_id.as_ref());
    let stream_hex = hex::encode(record.stream_id.as_ref());
    let descriptor = fetch_authority_descriptor(&client, &realm_hex, &stream_hex).await?;
    render_authority_record(&descriptor, json_output_enabled(json));
    log_cli_goal("CLI.FED1.AUTHORITY_PUBLISH");
    Ok(())
}

async fn handle_fed_authority_show(args: FedAuthorityShowArgs) -> Result<()> {
    let FedAuthorityShowArgs {
        hub,
        realm,
        stream,
        json,
    } = args;

    let client = match parse_hub_reference(&hub)? {
        HubReference::Remote(client) => client,
        HubReference::Local(_) => {
            bail_usage!("fed authority show requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    };

    let realm_id = parse_realm_id_hex(&realm)?;
    let stream_id = cap_stream_id_from_label(&stream)
        .with_context(|| format!("deriving stream identifier for {stream}"))?;
    let realm_hex = hex::encode(realm_id.as_ref());
    let stream_hex = hex::encode(stream_id.as_ref());
    let descriptor = fetch_authority_descriptor(&client, &realm_hex, &stream_hex).await?;
    render_authority_record(&descriptor, json_output_enabled(json));
    log_cli_goal("CLI.FED1.AUTHORITY_SHOW");
    Ok(())
}

async fn handle_label_authority(args: LabelAuthorityArgs) -> Result<()> {
    let LabelAuthorityArgs { hub, label, json } = args;

    let client = match parse_hub_reference(&hub)? {
        HubReference::Remote(client) => client,
        HubReference::Local(_) => {
            bail_usage!("label authority requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    };

    let label_bytes = hex::decode(&label)
        .map_err(|err| CliUsageError::new(format!("label must be hex encoded: {err}")))?;
    let stream_id = StreamId::from_slice(&label_bytes).map_err(|err| {
        CliUsageError::new(format!("label must encode a 32-byte identifier: {err}"))
    })?;
    let label_hex = hex::encode(stream_id.as_ref());
    let descriptor = fetch_label_authority_descriptor(&client, &label_hex).await?;
    render_label_authority(&descriptor, json_output_enabled(json));
    log_cli_goal("CLI.AUTH1.LABEL_AUTHORITY");
    Ok(())
}

async fn fetch_authority_descriptor(
    client: &HubHttpClient,
    realm_hex: &str,
    stream_hex: &str,
) -> Result<RemoteAuthorityRecordDescriptor> {
    client
        .get_json(
            "/authority_view",
            &[
                ("realm_id", realm_hex.to_string()),
                ("stream_id", stream_hex.to_string()),
            ],
        )
        .await
}

async fn fetch_label_authority_descriptor(
    client: &HubHttpClient,
    label_hex: &str,
) -> Result<RemoteLabelAuthorityDescriptor> {
    client
        .get_json("/label_authority", &[("label", label_hex.to_string())])
        .await
}

fn render_authority_record(descriptor: &RemoteAuthorityRecordDescriptor, use_json: bool) {
    if !descriptor.ok {
        emit_cli_error(
            "E.PROFILE",
            Some("hub declined to provide authority information"),
            use_json,
        );
        process::exit(4);
    }

    let output = format_authority_record_output(descriptor, use_json);
    println!("{output}");
}

fn render_label_authority(descriptor: &RemoteLabelAuthorityDescriptor, use_json: bool) {
    if !descriptor.ok {
        emit_cli_error(
            "E.PROFILE",
            Some("hub declined to provide label authority information"),
            use_json,
        );
        process::exit(4);
    }

    let output = format_label_authority_output(descriptor, use_json);
    println!("{output}");
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

fn parse_realm_id_hex(input: &str) -> Result<RealmId> {
    let bytes = parse_hex_key::<{ REALM_ID_LEN }>(input)?;
    Ok(RealmId::from(bytes))
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
            bail_usage!("label-class set requires an HTTP hub endpoint (e.g. http://host:port)")
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
    log_cli_goal("CLI.LCLASS0.SET");
    Ok(())
}

async fn handle_schema_id(args: SchemaIdArgs) -> Result<()> {
    let digest = compute_schema_identifier(&args.name);
    println!("{}", hex::encode(digest));
    log_cli_goal("CLI.META0_PLUS.SCHEMA_ID");
    Ok(())
}

async fn handle_schema_register(args: SchemaRegisterArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => handle_schema_register_remote(client, args).await,
        HubReference::Local(_) => {
            bail_usage!("schema register requires an HTTP hub endpoint (e.g. http://host:port)")
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
    log_cli_goal("CLI.META0_PLUS.SCHEMA_REGISTER");
    Ok(())
}

async fn handle_schema_list(args: SchemaListArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => handle_schema_list_remote(client).await,
        HubReference::Local(_) => {
            bail_usage!("schema list requires an HTTP hub endpoint (e.g. http://host:port)")
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
    log_cli_goal("CLI.META0_PLUS.SCHEMA_LIST");
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
            bail_usage!("wallet transfer requires an HTTP hub endpoint (e.g. http://host:port)")
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
    log_cli_goal("CLI.WALLET.TRANSFER");
    Ok(())
}

async fn handle_operation_id(args: OperationIdArgs) -> Result<()> {
    let operation_id = operation_id_from_bundle(&args.bundle).await?;
    println!("operation_id: {}", hex::encode(operation_id.as_bytes()));
    log_cli_goal("CLI.OPERATION0.ID");
    Ok(())
}

async fn operation_id_from_bundle(path: &Path) -> Result<OperationId> {
    let message: StoredMessage = read_json_file(path).await?;
    let leaf_hash = compute_message_leaf_hash(&message)?;
    Ok(OperationId::from_leaf_hash(&leaf_hash))
}

async fn handle_revoke_publish(args: RevokePublishArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Remote(client) => handle_revoke_publish_remote(client, args).await,
        HubReference::Local(_) => {
            bail_usage!("revoke publish requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    }
}

async fn handle_revoke_publish_remote(
    client: HubHttpClient,
    args: RevokePublishArgs,
) -> Result<()> {
    let signing_key = load_signing_key_from_dir(&args.signer).await?;
    let target = parse_revocation_target_hex(&args.target)?;
    let kind = RevocationKind::from(args.kind);
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
    log_cli_goal("CLI.AUTH1.REVOKE_PUBLISH");
    Ok(())
}

async fn handle_resync(args: ResyncArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Local(data_dir) => {
            handle_resync_local(data_dir, args).await?;
        }
        HubReference::Remote(client) => {
            handle_resync_remote(client, args).await?;
        }
    }

    log_cli_goal("CLI.RESYNC0.RESYNC");
    Ok(())
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
            bail_usage!(
                "client profile {} does not match hub profile {}",
                existing_profile,
                profile_id
            );
        }
    } else if !profile_id.is_empty() {
        client_state.profile_id = Some(profile_id.clone());
    }

    let label_state = client_state.ensure_label_state(&args.stream);
    label_state.record_sync(seq);
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
    label_state.record_sync(seq);
    write_json_file(&args.client.join("state.json"), &client_state).await?;

    println!("resynchronised stream {} to seq {}", args.stream, seq);
    Ok(())
}

async fn handle_verify_state(args: VerifyStateArgs) -> Result<()> {
    let hub = parse_hub_reference(&args.hub)?;
    let client_state: ClientStateFile = read_json_file(&args.client.join("state.json")).await?;

    let hub_seq = match hub {
        HubReference::Local(data_dir) => {
            let stream_state = load_stream_state(&data_dir, &args.stream).await?;
            if let Some(last) = stream_state.messages.last() {
                last.seq
            } else {
                let hub_state = load_hub_state(&data_dir).await?;
                hub_state
                    .last_stream_seq
                    .get(&args.stream)
                    .copied()
                    .unwrap_or(0)
            }
        }
        HubReference::Remote(client) => {
            let report: RemoteObservabilityReport = client.get_json("/metrics", &[]).await?;
            report
                .last_stream_seq
                .get(&args.stream)
                .copied()
                .unwrap_or(0)
        }
    };

    let client_seq = client_state
        .labels
        .get(&args.stream)
        .map(|label| label.last_stream_seq)
        .unwrap_or(0);

    if client_seq > hub_seq {
        bail_hub!(
            "client sequence {} is ahead of hub {} for stream {}",
            client_seq,
            hub_seq,
            args.stream
        );
    }

    println!("hub seq: {hub_seq}");
    println!("client seq: {client_seq}");
    println!("state verified: client is synchronised with hub");
    log_cli_goal("CLI.RESYNC0.VERIFY_STATE");
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
            bail_usage!("unknown VEEN error code `{other}`");
        }
    };

    println!("{code}: {description}");
    log_cli_goal("CLI.CORE.EXPLAIN_ERROR");
    Ok(())
}

async fn handle_rpc_call(args: RpcCallArgs) -> Result<()> {
    let parsed_args: serde_json::Value = match serde_json::from_str(&args.args) {
        Ok(value) => value,
        Err(_) => json!(args.args),
    };

    let global_timeout_ms = global_options().timeout_ms;
    let timeout_ms = args.timeout_ms.or(global_timeout_ms);

    let payload = json!({
        "method": args.method,
        "args": parsed_args,
        "timeout_ms": timeout_ms,
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
        expires_at: timeout_ms.map(|ms| now + ms / 1000),
        cap: None,
        parent: None,
        attach: Vec::new(),
        no_store_body: false,
        pow_difficulty: None,
        pow_challenge: None,
    };

    let result = handle_send(send_args).await;
    if result.is_ok() {
        log_cli_goal("CLI.RPC0.CALL");
    }
    result
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
    log_cli_goal("CLI.CRDT0.LWW_SET");
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
    log_cli_goal("CLI.CRDT0.LWW_GET");
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
    log_cli_goal("CLI.CRDT0.ORSET_ADD");
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
        bail_usage!("element {} not present in OR-set", args.elem);
    }
    save_orset_state(&data_dir, &args.stream, &state).await?;
    println!(
        "orset removed stream={} elem={} ts={}",
        args.stream, args.elem, now
    );
    log_cli_goal("CLI.CRDT0.ORSET_REMOVE");
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
    log_cli_goal("CLI.CRDT0.ORSET_LIST");
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
    log_cli_goal("CLI.CRDT0.COUNTER_ADD");
    Ok(())
}

async fn handle_crdt_counter_get(args: CrdtCounterGetArgs) -> Result<()> {
    let data_dir = parse_hub_reference(&args.hub)?.into_local()?;
    ensure_client_label_exists(&args.client, &args.stream).await?;
    let state = load_counter_state(&data_dir, &args.stream).await?;
    println!("counter value={}", state.value);
    log_cli_goal("CLI.CRDT0.COUNTER_GET");
    Ok(())
}

async fn handle_anchor_publish(args: AnchorPublishArgs) -> Result<()> {
    match parse_hub_reference(&args.hub)? {
        HubReference::Local(data_dir) => {
            let mut log = load_anchor_log(&data_dir).await?;
            let ts = args.ts.unwrap_or(current_unix_timestamp()?);
            let mmr_root = compute_local_stream_mmr_root(&data_dir, &args.stream)
                .await?
                .ok_or_else(|| {
                    anyhow!(
                        "stream {} does not have committed messages to anchor",
                        args.stream
                    )
                })?;

            let record = AnchorRecord {
                stream: args.stream.clone(),
                epoch: args.epoch,
                ts,
                nonce: args.nonce.clone(),
            };
            log.entries.push(record);
            save_anchor_log(&data_dir, &log).await?;

            println!(
                "queued anchor publication for stream {} mmr_root {} at ts {}",
                args.stream, mmr_root, ts
            );
        }
        HubReference::Remote(client) => {
            let report: RemoteObservabilityReport = client.get_json("/metrics", &[]).await?;
            let mmr_root = report.mmr_roots.get(&args.stream).cloned().ok_or_else(|| {
                anyhow!(
                    "remote hub does not report an mmr_root for stream {}",
                    args.stream
                )
            })?;
            let request = AnchorRequest {
                stream: args.stream.clone(),
                mmr_root: mmr_root.clone(),
                backend: None,
            };
            client.post_json_unit("/anchor", &request).await?;
            println!(
                "requested anchor publication for stream {} mmr_root {}",
                args.stream, mmr_root
            );
        }
    }

    log_cli_goal("CLI.ANCHOR0.PUBLISH");
    Ok(())
}

async fn handle_anchor_verify(args: AnchorVerifyArgs) -> Result<()> {
    let checkpoint: Checkpoint = read_cbor_file(&args.checkpoint).await?;
    if !checkpoint.has_valid_version() {
        bail_protocol!(
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
    log_cli_goal("CLI.ANCHOR0.VERIFY");
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

    log_cli_goal("CLI.COMP0.RETENTION_SHOW");
    Ok(())
}

async fn handle_selftest_core() -> Result<()> {
    println!("running VEEN core self-tests...");
    match veen_selftest::run_core().await {
        Ok(()) => {
            log_cli_goal("CLI.SELFTEST.CORE");
            Ok(())
        }
        Err(err) => Err(anyhow::Error::new(SelftestFailure::new(err))),
    }
}

async fn handle_selftest_props() -> Result<()> {
    println!("running VEEN property self-tests...");
    match veen_selftest::run_props() {
        Ok(()) => {
            log_cli_goal("CLI.SELFTEST.PROPS");
            Ok(())
        }
        Err(err) => Err(anyhow::Error::new(SelftestFailure::new(err))),
    }
}

async fn handle_selftest_fuzz() -> Result<()> {
    println!("running VEEN fuzz self-tests...");
    match veen_selftest::run_fuzz() {
        Ok(()) => {
            log_cli_goal("CLI.SELFTEST.FUZZ");
            Ok(())
        }
        Err(err) => Err(anyhow::Error::new(SelftestFailure::new(err))),
    }
}

async fn handle_selftest_all() -> Result<()> {
    println!("running full VEEN self-test suite...");
    match veen_selftest::run_all().await {
        Ok(()) => {
            log_cli_goal("CLI.SELFTEST.ALL");
            Ok(())
        }
        Err(err) => Err(anyhow::Error::new(SelftestFailure::new(err))),
    }
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

async fn compute_local_stream_mmr_root(data_dir: &Path, stream: &str) -> Result<Option<String>> {
    let state = load_stream_state(data_dir, stream).await?;
    if state.messages.is_empty() {
        return Ok(None);
    }
    let mut mmr = Mmr::new();
    for message in &state.messages {
        let leaf = compute_message_leaf_hash(message)?;
        mmr.append(leaf);
    }
    Ok(mmr.root().map(|root| hex::encode(root.as_bytes())))
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

fn compute_message_leaf_hash(message: &StoredMessage) -> Result<LeafHash> {
    let encoded = serde_json::to_vec(message).context("encoding message for leaf hash")?;
    let digest = Sha256::digest(&encoded);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(LeafHash::new(bytes))
}

fn print_stream_message(message: &StoredMessage) {
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
}

fn print_stream_receipt(receipt: &StreamReceipt) {
    println!("receipt.seq: {}", receipt.seq);
    println!("receipt.hub_ts: {}", receipt.hub_ts);
    println!("receipt.leaf_hash: {}", receipt.leaf_hash);
    println!("receipt.mmr_root: {}", receipt.mmr_root);
}

fn print_stream_proof(proof: &RemoteStreamProof) -> Result<()> {
    let proof_json = serde_json::to_string(proof).context("serializing proof for display")?;
    println!("proof: {proof_json}");
    Ok(())
}

fn validate_stream_proof(
    message: &StoredMessage,
    receipt: &StreamReceipt,
    proof: &MmrProof,
) -> Result<MmrRoot> {
    let computed_leaf = compute_message_leaf_hash(message)?;
    let expected_leaf_hex = hex::encode(computed_leaf.as_bytes());
    if receipt.leaf_hash != expected_leaf_hex {
        bail_protocol!(
            "receipt leaf hash mismatch for {}#{}: expected {}, got {}",
            message.stream,
            message.seq,
            expected_leaf_hex,
            receipt.leaf_hash
        );
    }

    if proof.leaf_hash != computed_leaf {
        bail_protocol!(
            "proof leaf hash mismatch for {}#{}",
            message.stream,
            message.seq
        );
    }

    let mmr_root_bytes = hex::decode(&receipt.mmr_root)
        .with_context(|| format!("decoding mmr_root for {}#{}", message.stream, message.seq))?;
    let mmr_root = MmrRoot::from_slice(&mmr_root_bytes)
        .with_context(|| format!("parsing mmr_root for {}#{}", message.stream, message.seq))?;

    if !proof.verify(&mmr_root) {
        bail_protocol!(
            "mmr proof verification failed for {}#{}",
            message.stream,
            message.seq
        );
    }

    Ok(mmr_root)
}

fn parse_cap_rate(input: &str) -> Result<CapTokenRate> {
    let parts: Vec<&str> = input.split(',').collect();
    if parts.len() != 2 {
        bail_usage!("rate must be provided as per_sec,burst");
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
        bail_usage!("capability subject does not match client identity");
    }
    if !token.allow.stream_ids.iter().any(|id| id == stream_id) {
        bail_usage!(
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
    use anyhow::bail;
    use ciborium::de::from_reader;
    use ciborium::ser::into_writer;
    use ed25519_dalek::{Signature, Verifier};
    use hyper::body::to_bytes;
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{
        Body, Method, Request as HyperRequest, Response as HyperResponse, Server, StatusCode,
    };
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::sync::mpsc;
    use tokio::time::sleep;
    use veen_core::wire::types::{MmrRoot, Signature64};
    use veen_hub::config::{HubConfigOverrides, HubRole, HubRuntimeConfig};
    use veen_hub::pipeline::StreamResponse;
    use veen_hub::runtime::HubRuntime;

    async fn write_test_hub_key(data_dir: &Path) -> anyhow::Result<()> {
        let path = data_dir.join(HUB_KEY_FILE);
        if tokio::fs::try_exists(&path)
            .await
            .with_context(|| format!("checking hub key at {}", path.display()))?
        {
            return Ok(());
        }

        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let created_at = current_unix_timestamp()?;
        let material = HubKeyMaterial {
            version: HUB_KEY_VERSION,
            created_at,
            public_key: ByteBuf::from(verifying_key.to_bytes().to_vec()),
            secret_key: ByteBuf::from(signing_key.to_bytes().to_vec()),
        };

        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&material, &mut encoded)
            .context("serialising test hub key material")?;
        tokio::fs::write(&path, encoded)
            .await
            .with_context(|| format!("writing hub key material to {}", path.display()))?;
        Ok(())
    }

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

    #[test]
    fn json_output_enabled_uses_global_flag() {
        let global_json = GlobalOptions {
            json: true,
            quiet: false,
            timeout_ms: None,
        };
        assert!(super::json_output_enabled_with(false, &global_json));

        let global_text = GlobalOptions {
            json: false,
            quiet: false,
            timeout_ms: None,
        };
        assert!(super::json_output_enabled_with(true, &global_text));
        assert!(!super::json_output_enabled_with(false, &global_text));
    }

    #[test]
    fn hub_profile_output_matches_cli_goals() {
        let features = RemoteHubProfileFeatures {
            core: true,
            fed1: true,
            auth1: true,
            kex1_plus: true,
            sh1_plus: false,
            lclass0: false,
            meta0_plus: true,
        };

        let text = super::format_hub_profile_output(
            true,
            "veen-0.0.1+",
            "abcd",
            "hub-0001",
            &features,
            false,
        );
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "version: veen-0.0.1+");
        assert_eq!(lines[1], "profile_id: abcd");
        assert_eq!(lines[2], "hub_id: hub-0001");
        assert_eq!(lines[3], "features:");
        assert_eq!(lines[4], "  core: true");
        assert_eq!(lines[5], "  fed1: true");
        assert_eq!(lines[6], "  auth1: true");
        assert_eq!(lines[7], "  kex1_plus: true");
        assert_eq!(lines[8], "  sh1_plus: false");
        assert_eq!(lines[9], "  lclass0: false");
        assert_eq!(lines[10], "  meta0_plus: true");

        let json = super::format_hub_profile_output(
            true,
            "veen-0.0.1+",
            "abcd",
            "hub-0001",
            &features,
            true,
        );
        let value: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(value["version"], "veen-0.0.1+");
        assert_eq!(value["profile_id"], "abcd");
        assert_eq!(value["hub_id"], "hub-0001");
        assert_eq!(value["features"]["core"], Value::Bool(true));
        assert_eq!(value["features"]["sh1_plus"], Value::Bool(false));
    }

    #[test]
    fn hub_role_output_matches_cli_goals() {
        let stream = RemoteHubRoleStream {
            realm_id: Some("aaaa".to_string()),
            stream_id: "bbbb".to_string(),
            label: "fed/chat".to_string(),
            policy: "single-primary".to_string(),
            primary_hub: Some("hub-primary".to_string()),
            local_is_primary: true,
        };

        let text = super::format_hub_role_output(
            true,
            "hub-primary",
            "federated-primary",
            Some(&stream),
            false,
        );
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "hub_id: hub-primary");
        assert_eq!(lines[1], "role: federated-primary");
        assert_eq!(lines[2], "realm_id: aaaa");
        assert_eq!(lines[3], "stream_id: bbbb");
        assert_eq!(lines[4], "label: fed/chat");
        assert_eq!(lines[5], "policy: single-primary");
        assert_eq!(lines[6], "primary_hub: hub-primary");
        assert_eq!(lines[7], "local_is_primary: true");

        let stream_without_defaults = RemoteHubRoleStream {
            realm_id: None,
            stream_id: "cccc".to_string(),
            label: "fed/alt".to_string(),
            policy: "multi-primary".to_string(),
            primary_hub: None,
            local_is_primary: false,
        };
        let json = super::format_hub_role_output(
            true,
            "hub-observer",
            "observer",
            Some(&stream_without_defaults),
            true,
        );
        let value: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(value["hub_id"], "hub-observer");
        assert_eq!(value["role"], "observer");
        assert_eq!(value["stream"]["realm_id"], Value::Null);
        assert_eq!(value["stream"]["primary_hub"], Value::Null);
        assert_eq!(value["stream"]["local_is_primary"], Value::Bool(false));
    }

    #[test]
    fn authority_record_output_matches_cli_goals() {
        let descriptor = RemoteAuthorityRecordDescriptor {
            ok: true,
            realm_id: "aaaa".to_string(),
            stream_id: "bbbb".to_string(),
            primary_hub: Some("hub-primary".to_string()),
            replica_hubs: vec!["hub-replica-1".to_string(), "hub-replica-2".to_string()],
            policy: "single-primary".to_string(),
            ts: 1,
            ttl: 60,
            expires_at: Some(61),
            active_now: true,
        };

        let text = super::format_authority_record_output(&descriptor, false);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "realm_id: aaaa");
        assert_eq!(lines[1], "stream_id: bbbb");
        assert_eq!(lines[2], "primary_hub: hub-primary");
        assert_eq!(lines[3], "replica_hubs: [hub-replica-1,hub-replica-2]");
        assert_eq!(lines[4], "policy: single-primary");
        assert_eq!(lines[5], "ts: 1");
        assert_eq!(lines[6], "ttl: 60");
        assert_eq!(lines[7], "expires_at: 61");
        assert_eq!(lines[8], "active_now: true");
    }

    #[test]
    fn authority_record_json_output_matches_cli_goals() {
        let descriptor = RemoteAuthorityRecordDescriptor {
            ok: true,
            realm_id: "ffff".to_string(),
            stream_id: "eeee".to_string(),
            primary_hub: None,
            replica_hubs: Vec::new(),
            policy: "unspecified".to_string(),
            ts: 99,
            ttl: 0,
            expires_at: None,
            active_now: false,
        };

        let json = super::format_authority_record_output(&descriptor, true);
        let value: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(value["realm_id"], "ffff");
        assert_eq!(value["stream_id"], "eeee");
        assert_eq!(value["primary_hub"], Value::Null);
        assert_eq!(value["replica_hubs"], json!([]));
        assert_eq!(value["policy"], "unspecified");
        assert_eq!(value["ts"], 99);
        assert_eq!(value["ttl"], 0);
        assert_eq!(value["expires_at"], Value::Null);
        assert_eq!(value["active_now"], Value::Bool(false));
    }

    #[test]
    fn label_authority_output_matches_cli_goals() {
        let descriptor = RemoteLabelAuthorityDescriptor {
            ok: true,
            label: "fed/chat".to_string(),
            realm_id: None,
            stream_id: "bbbb".to_string(),
            policy: "single-primary".to_string(),
            primary_hub: None,
            replica_hubs: vec!["hub-replica".to_string()],
            local_hub_id: "hub-local".to_string(),
            local_is_authorized: true,
        };

        let json = super::format_label_authority_output(&descriptor, true);
        let value: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(value["label"], "fed/chat");
        assert_eq!(value["realm_id"], Value::Null);
        assert_eq!(value["stream_id"], "bbbb");
        assert_eq!(value["primary_hub"], Value::Null);
        assert_eq!(value["replica_hubs"], json!(["hub-replica"]));
        assert_eq!(value["locally_authorized"], Value::Bool(true));
    }

    #[test]
    fn label_authority_text_output_matches_cli_goals() {
        let descriptor = RemoteLabelAuthorityDescriptor {
            ok: true,
            label: "fed/debug".to_string(),
            realm_id: Some("bbbb".to_string()),
            stream_id: "cccc".to_string(),
            policy: "single-primary".to_string(),
            primary_hub: Some("hub-primary".to_string()),
            replica_hubs: vec![],
            local_hub_id: "hub-local".to_string(),
            local_is_authorized: false,
        };

        let text = super::format_label_authority_output(&descriptor, false);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "label: fed/debug");
        assert_eq!(lines[1], "realm_id: bbbb");
        assert_eq!(lines[2], "stream_id: cccc");
        assert_eq!(lines[3], "policy: single-primary");
        assert_eq!(lines[4], "primary_hub: hub-primary");
        assert_eq!(lines[5], "local_hub_id: hub-local");
        assert_eq!(lines[6], "locally_authorized: false");
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
        write_test_hub_key(hub_dir.path()).await?;
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
            pow_difficulty: None,
            pow_challenge: None,
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
    async fn stream_with_proofs_detects_tampering() -> anyhow::Result<()> {
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
        write_test_hub_key(hub_dir.path()).await?;
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
            stream: "proofs".to_string(),
            body: json!({ "msg": "hello" }).to_string(),
            schema: None,
            expires_at: None,
            cap: None,
            parent: None,
            attach: Vec::new(),
            no_store_body: false,
            pow_difficulty: None,
            pow_challenge: None,
        })
        .await?;

        handle_stream(StreamArgs {
            hub: hub_url.clone(),
            client: client_dir.path().to_path_buf(),
            stream: "proofs".to_string(),
            from: 0,
            with_proof: true,
        })
        .await?;

        let mut proven = match runtime.pipeline().stream("proofs", 0, true).await? {
            StreamResponse::Proven(items) => items,
            StreamResponse::Messages(_) => bail!("expected proofs in stream response"),
        };

        assert_eq!(proven.len(), 1);
        let original = proven.pop().expect("message");

        let mut tampered_receipt = StreamReceipt::from(original.receipt.clone());
        let mut root_bytes = hex::decode(&tampered_receipt.mmr_root)?;
        root_bytes[0] ^= 0xFF;
        tampered_receipt.mmr_root = hex::encode(root_bytes);

        let message: StoredMessage = original.message.into();
        let receipt = tampered_receipt;
        let proof = original
            .proof
            .clone()
            .try_into_mmr()
            .context("decoding stream proof")?;
        let err =
            validate_stream_proof(&message, &receipt, &proof).expect_err("tampered proof fails");
        assert!(err.to_string().contains("mmr proof verification failed"));

        runtime.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn http_checkpoint_fetch() -> anyhow::Result<()> {
        let hub_dir = tempdir()?;

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
        write_test_hub_key(hub_dir.path()).await?;
        let runtime = HubRuntime::start(config).await?;
        let hub_url = format!("http://{}", listen);

        sleep(Duration::from_millis(50)).await;

        let checkpoint1 = Checkpoint {
            ver: CHECKPOINT_VERSION,
            label_prev: Label::from([0x11; 32]),
            label_curr: Label::from([0x22; 32]),
            upto_seq: 5,
            mmr_root: MmrRoot::new([0x33; 32]),
            epoch: 1,
            hub_sig: Signature64::new([0x44; 64]),
            witness_sigs: None,
        };
        let checkpoint2 = Checkpoint {
            ver: CHECKPOINT_VERSION,
            label_prev: Label::from([0x55; 32]),
            label_curr: Label::from([0x66; 32]),
            upto_seq: 9,
            mmr_root: MmrRoot::new([0x77; 32]),
            epoch: 2,
            hub_sig: Signature64::new([0x88; 64]),
            witness_sigs: Some(vec![Signature64::new([0x99; 64])]),
        };

        let mut encoded = Vec::new();
        into_writer(&checkpoint1, &mut encoded)?;
        into_writer(&checkpoint2, &mut encoded)?;
        fs::write(hub_dir.path().join(CHECKPOINTS_FILE), &encoded).await?;

        sleep(Duration::from_millis(50)).await;

        let latest = handle_hub_checkpoint_latest(HubCheckpointLatestArgs {
            hub: hub_url.clone(),
        })
        .await?;
        assert_eq!(latest, checkpoint2);

        let range = handle_hub_checkpoint_range(HubCheckpointRangeArgs {
            hub: hub_url.clone(),
            from_epoch: Some(1),
            to_epoch: Some(3),
        })
        .await?;
        assert_eq!(range, vec![checkpoint1.clone(), checkpoint2.clone()]);

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

        let realm_id = RealmId::derive("default");
        let realm_hex = hex::encode(realm_id.as_ref());
        let primary_hex = hex::encode([0x11u8; HUB_ID_LEN]);
        let replica_hex = hex::encode([0x22u8; HUB_ID_LEN]);
        let stream_name = "fed/chat".to_string();
        let stream_id = cap_stream_id_from_label(&stream_name)?;
        let stream_hex = hex::encode(stream_id.as_ref());

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr: SocketAddr = listener.local_addr()?;
        let (tx, mut body_rx) = mpsc::channel(1);
        let response_realm = realm_hex.clone();
        let response_stream = stream_hex.clone();
        let response_primary = primary_hex.clone();
        let response_replica = replica_hex.clone();
        let service = make_service_fn(move |_| {
            let tx = tx.clone();
            let response_realm = response_realm.clone();
            let response_stream = response_stream.clone();
            let response_primary = response_primary.clone();
            let response_replica = response_replica.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |mut req: HyperRequest<Body>| {
                    let tx = tx.clone();
                    let response_realm = response_realm.clone();
                    let response_stream = response_stream.clone();
                    let response_primary = response_primary.clone();
                    let response_replica = response_replica.clone();
                    async move {
                        match (req.method(), req.uri().path()) {
                            (&Method::POST, "/authority") => {
                                let body = to_bytes(req.body_mut()).await.unwrap().to_vec();
                                tx.send(body).await.unwrap();
                                Ok::<_, Infallible>(
                                    HyperResponse::builder()
                                        .status(StatusCode::OK)
                                        .body(Body::from("null"))
                                        .unwrap(),
                                )
                            }
                            (&Method::GET, "/authority_view") => {
                                let payload = json!({
                                    "ok": true,
                                    "realm_id": response_realm,
                                    "stream_id": response_stream,
                                    "primary_hub": response_primary,
                                    "replica_hubs": [response_replica],
                                    "policy": "single-primary",
                                    "ts": 1_234_567u64,
                                    "ttl": 3_600u64,
                                    "expires_at": 1_238_167u64,
                                    "active_now": true,
                                });
                                let body = serde_json::to_string(&payload).unwrap();
                                Ok::<_, Infallible>(
                                    HyperResponse::builder()
                                        .status(StatusCode::OK)
                                        .body(Body::from(body))
                                        .unwrap(),
                                )
                            }
                            _ => Ok::<_, Infallible>(
                                HyperResponse::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Body::empty())
                                    .unwrap(),
                            ),
                        }
                    }
                }))
            }
        });
        let server = Server::from_tcp(listener)?.serve(service);
        let handle = tokio::spawn(async move {
            if let Err(err) = server.await {
                eprintln!("authority test server error: {err}");
            }
        });

        let url = format!("http://{}", addr);
        let client = HubHttpClient::new(Url::parse(&url)?, build_http_client()?);
        let args = FedAuthorityPublishArgs {
            hub: url.clone(),
            signer: signer_dir.path().to_path_buf(),
            realm: realm_hex,
            stream: stream_name,
            policy: AuthorityPolicyValue::SinglePrimary,
            primary_hub: primary_hex.clone(),
            replica_hubs: vec![replica_hex.clone()],
            ttl: Some(3_600),
            ts: Some(1_234_567),
            json: false,
        };

        handle_fed_authority_publish_remote(client, args).await?;
        let body = body_rx.recv().await.expect("payload captured");
        handle.abort();

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
        let client = HubHttpClient::new(Url::parse(&url)?, build_http_client()?);
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
        let client = HubHttpClient::new(Url::parse(&url)?, build_http_client()?);
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
        let client = HubHttpClient::new(Url::parse(&url)?, build_http_client()?);
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
    async fn operation_id_helper_matches_manual_hash() -> anyhow::Result<()> {
        let temp = tempdir()?;
        let path = temp.path().join("message.json");
        let message = StoredMessage {
            stream: "core/example".to_string(),
            seq: 5,
            sent_at: 1_700_000_000,
            client_id: hex::encode([0xAAu8; 32]),
            schema: Some("schema-id".to_string()),
            expires_at: Some(1_700_000_600),
            parent: None,
            body: Some("{\"key\":\"value\"}".to_string()),
            body_digest: None,
            attachments: Vec::new(),
            auth_ref: None,
            idem: None,
        };

        write_json_file(&path, &message).await?;

        let expected_leaf = compute_message_leaf_hash(&message)?;
        let expected = OperationId::from_leaf_hash(&expected_leaf);

        let computed = operation_id_from_bundle(&path).await?;
        assert_eq!(computed.as_bytes(), expected.as_bytes());

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
        let client = HubHttpClient::new(Url::parse(&url)?, build_http_client()?);
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
        let client = HubHttpClient::new(Url::parse(&url)?, build_http_client()?);
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
                bail_usage!("command requires a local hub data directory reference")
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
            return Err(anyhow::Error::new(HubResponseError::new(
                path, status, body,
            )));
        }
        response
            .json::<T>()
            .await
            .context("decoding hub response body")
    }

    async fn get_cbor<T>(&self, path: &str, query: &[(&str, String)]) -> Result<T>
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
            return Err(anyhow::Error::new(HubResponseError::new(
                path, status, body,
            )));
        }
        let bytes = response
            .bytes()
            .await
            .context("reading hub response body")?;
        let mut cursor = Cursor::new(bytes.as_ref());
        ciborium::de::from_reader(&mut cursor).context("decoding hub response body")
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
            return Err(anyhow::Error::new(HubResponseError::new(
                path, status, body,
            )));
        }
        response
            .json::<R>()
            .await
            .context("decoding hub response body")
    }

    async fn post_json_unit<T>(&self, path: &str, body: &T) -> Result<()>
    where
        T: Serialize + ?Sized,
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
            return Err(anyhow::Error::new(HubResponseError::new(
                path, status, body,
            )));
        }
        Ok(())
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
            return Err(anyhow::Error::new(HubResponseError::new(
                path, status, body,
            )));
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
            return Err(anyhow::Error::new(HubResponseError::new(
                path, status, body,
            )));
        }
        let bytes = response
            .bytes()
            .await
            .context("reading hub response body")?;
        let mut cursor = Cursor::new(bytes.as_ref());
        ciborium::de::from_reader(&mut cursor).context("decoding hub response body")
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

fn normalize_optional_profile_id(raw: Option<String>) -> Result<Option<String>> {
    raw.map(|value| {
        let trimmed = value.trim().to_ascii_lowercase();
        if trimmed.len() != 64 {
            bail_usage!(
                "profile identifier must be 64 hex characters (32 bytes); got {}",
                trimmed.len()
            );
        }
        if !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
            bail_usage!("profile identifier must contain only hexadecimal characters");
        }
        Ok(trimmed)
    })
    .transpose()
}

fn resolve_profile_id(profile: Option<String>) -> Result<String> {
    match profile {
        Some(value) => {
            let trimmed = value.trim().to_ascii_lowercase();
            if trimmed.len() != 64 {
                bail_usage!(
                    "profile identifier must be 64 hex characters (32 bytes); got {}",
                    trimmed.len()
                );
            }
            if !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
                bail_usage!("profile identifier must contain only hexadecimal characters");
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
        bail_usage!(
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
                let client = build_http_client()?;
                return Ok(HubReference::Remote(HubHttpClient::new(url, client)));
            }
            other => {
                bail_usage!("unsupported hub scheme `{other}`; expected http or https");
            }
        }
    }

    Ok(HubReference::Local(PathBuf::from(reference)))
}

fn build_http_client() -> Result<HttpClient> {
    let mut builder = HttpClient::builder();
    if let Some(timeout_ms) = global_options().timeout_ms {
        builder = builder.timeout(Duration::from_millis(timeout_ms));
    }
    builder
        .build()
        .context("constructing HTTP client with global options")
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
        bail_usage!(
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
                bail_usage!("{} exists and is not a directory", path.display());
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
                bail_usage!("refusing to reuse non-empty directory {}", path.display());
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
        bail_usage!("refusing to overwrite existing file {}", path.display());
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
