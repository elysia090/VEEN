use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::convert::{TryFrom, TryInto};
use std::env;
use std::fmt;
use std::fs::OpenOptions as StdOpenOptions;
use std::io::{Cursor, Write as StdWrite};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{self, Command as StdCommand, Stdio};
use std::str::FromStr;
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
use reqwest::{Client as HttpClient, Response, Url};
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

use crate::kube::{handle_kube_command, KubeCommand};

use veen_core::operation::{
    schema_access_grant, schema_access_revoke, schema_agreement_confirmation,
    schema_agreement_definition, schema_data_publication, schema_delegated_execution,
    schema_federation_mirror, schema_paid_operation, schema_query_audit, schema_recovery_approval,
    schema_recovery_execution, schema_recovery_request, schema_state_checkpoint, AccessGrant,
    AccessRevoke, AccountId, AgreementConfirmation, AgreementDefinition, DelegatedExecution,
    FederationMirror, OpaqueId, PaidOperation, QueryAuditLog, RecoveryApproval, RecoveryExecution,
    RecoveryRequest, StateCheckpoint, ACCOUNT_ID_LEN, OPERATION_ID_LEN,
};
use veen_core::CAP_TOKEN_VERSION;
use veen_core::{
    cap_stream_id_from_label,
    hub::{HubId, HUB_ID_LEN},
    identity::{GroupId, PrincipalId},
    label::{Label, StreamId, STREAM_ID_LEN},
    wire::{
        checkpoint::CHECKPOINT_VERSION,
        mmr::Mmr,
        proof::MmrProof,
        types::{AuthRef, ClientId, LeafHash, MmrRoot},
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
use veen_hub::storage::{
    self, stream_index, ANCHORS_DIR, ATTACHMENTS_DIR, CHECKPOINTS_FILE, CRDT_DIR, HUB_KEY_FILE,
    HUB_PID_FILE, MESSAGES_DIR, PAYLOADS_FILE, RECEIPTS_FILE, REVOCATIONS_FILE, STATE_DIR,
    STREAMS_DIR, TLS_INFO_FILE,
};
use veen_selftest::metrics::{HistogramSnapshot, HubMetricsSnapshot};

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
const ANCHOR_LOG_FILE: &str = "anchor_log.json";
const RETENTION_CONFIG_FILE: &str = "retention.json";
const ENV_DESCRIPTOR_VERSION: u64 = 1;

type JsonMap = serde_json::Map<String, JsonValue>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliExitKind {
    Usage,
    Network,
    Protocol,
    Hub,
    Selftest,
    Policy,
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
            CliExitKind::Policy => 6,
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
            CliExitKind::Policy => "E.POLICY",
            CliExitKind::Other { label, .. } => label,
        }
    }
}

#[derive(Debug)]
pub(crate) struct CliUsageError {
    message: String,
}

impl CliUsageError {
    pub(crate) fn new(message: String) -> Self {
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
struct AuditPolicyViolationError {
    violations: Vec<String>,
}

impl AuditPolicyViolationError {
    fn new(violations: Vec<String>) -> Self {
        Self { violations }
    }
}

impl fmt::Display for AuditPolicyViolationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.violations.is_empty() {
            write!(f, "audit policy violation")
        } else {
            write!(f, "audit policy violations: {}", self.violations.join(", "))
        }
    }
}

impl std::error::Error for AuditPolicyViolationError {}

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

fn format_label_class_descriptor_output(
    descriptor: &RemoteLabelClassDescriptor,
    use_json: bool,
) -> String {
    if use_json {
        let output = json!({
            "ok": true,
            "label": descriptor.label,
            "class": descriptor.class,
            "sensitivity": descriptor.sensitivity,
            "retention_hint": descriptor.retention_hint,
            "pad_block_effective": descriptor.pad_block_effective,
            "retention_policy": descriptor.retention_policy,
            "rate_policy": descriptor.rate_policy,
        });
        pretty_json(output)
    } else {
        let class = descriptor
            .class
            .clone()
            .unwrap_or_else(|| "unset".to_string());
        let sensitivity = descriptor
            .sensitivity
            .clone()
            .unwrap_or_else(|| "none".to_string());
        let retention_hint = descriptor
            .retention_hint
            .map(|value| value.to_string())
            .unwrap_or_else(|| "0".to_string());
        [
            format!("label: {}", descriptor.label),
            format!("class: {class}"),
            format!("sensitivity: {sensitivity}"),
            format!("retention_hint: {retention_hint}"),
            format!("pad_block_effective: {}", descriptor.pad_block_effective),
            format!("retention_policy: {}", descriptor.retention_policy),
            format!("rate_policy: {}", descriptor.rate_policy),
        ]
        .join("\n")
    }
}

fn format_label_class_list_output(list: &RemoteLabelClassList, use_json: bool) -> String {
    if use_json {
        let entries = list
            .entries
            .iter()
            .map(|entry| {
                json!({
                    "label": entry.label,
                    "class": entry.class,
                    "sensitivity": entry.sensitivity,
                    "retention_hint": entry.retention_hint,
                })
            })
            .collect::<Vec<_>>();
        let output = json!({ "ok": true, "entries": entries });
        pretty_json(output)
    } else if list.entries.is_empty() {
        "no label classifications found".to_string()
    } else {
        let mut rows = Vec::with_capacity(list.entries.len() + 1);
        rows.push(
            "label                                                             class      sensitivity retention_hint"
                .to_string(),
        );
        for entry in &list.entries {
            let sensitivity = entry
                .sensitivity
                .clone()
                .unwrap_or_else(|| "none".to_string());
            let retention_hint = entry
                .retention_hint
                .map(|value| value.to_string())
                .unwrap_or_else(|| "0".to_string());
            rows.push(format!(
                "{:<66} {:<10} {:<11} {}",
                entry.label, entry.class, sensitivity, retention_hint
            ));
        }
        rows.join("\n")
    }
}

fn format_schema_descriptor_output(
    descriptor: &RemoteSchemaDescriptorEntry,
    usage: Option<&RemoteSchemaUsage>,
    use_json: bool,
) -> String {
    if use_json {
        let usage_json = usage.map(|stats| {
            json!({
                "used_labels": stats.used_labels,
                "used_count": stats.used_count,
                "first_used_ts": stats.first_used_ts,
                "last_used_ts": stats.last_used_ts,
            })
        });
        let output = json!({
            "ok": true,
            "schema_id": descriptor.schema_id,
            "name": descriptor.name,
            "version": descriptor.version,
            "doc_url": descriptor.doc_url,
            "owner": descriptor.owner,
            "ts": descriptor.ts,
            "created_at": descriptor.created_at,
            "updated_at": descriptor.updated_at,
            "usage": usage_json,
        });
        pretty_json(output)
    } else {
        let doc_url = descriptor
            .doc_url
            .clone()
            .unwrap_or_else(|| "none".to_string());
        let owner = descriptor
            .owner
            .clone()
            .unwrap_or_else(|| "none".to_string());
        let created_at = descriptor
            .created_at
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let updated_at = descriptor
            .updated_at
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let usage_labels = usage
            .map(|stats| {
                if stats.used_labels.is_empty() {
                    "none".to_string()
                } else {
                    format!("[{}]", stats.used_labels.join(","))
                }
            })
            .unwrap_or_else(|| "none".to_string());
        let used_count = usage
            .and_then(|stats| stats.used_count)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "0".to_string());
        let first_used = usage
            .and_then(|stats| stats.first_used_ts)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let last_used = usage
            .and_then(|stats| stats.last_used_ts)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        [
            format!("schema_id: {}", descriptor.schema_id),
            format!("name: {}", descriptor.name),
            format!("version: {}", descriptor.version),
            format!("doc_url: {doc_url}"),
            format!("owner: {owner}"),
            format!("ts: {}", descriptor.ts),
            format!("created_at: {created_at}"),
            format!("updated_at: {updated_at}"),
            format!("used_labels: {usage_labels}"),
            format!("used_count: {used_count}"),
            format!("first_used_ts: {first_used}"),
            format!("last_used_ts: {last_used}"),
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
    /// Federation mirroring helpers.
    #[command(subcommand)]
    Federate(FederateCommand),
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
    /// Multi Party Agreement helpers.
    #[command(subcommand)]
    Agreement(AgreementCommand),
    /// State snapshot helpers.
    #[command(subcommand)]
    Snapshot(SnapshotCommand),
    /// Operation overlay helpers.
    #[command(subcommand)]
    Operation(OperationCommand),
    /// Recovery procedure helpers.
    #[command(subcommand)]
    Recovery(RecoveryCommand),
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
    /// Environment descriptor helpers.
    #[command(subcommand)]
    Env(EnvCommand),
    /// Render Kubernetes manifests for VEEN profiles.
    #[command(subcommand)]
    Kube(KubeCommand),
    /// Audit and compliance helpers.
    #[command(subcommand)]
    Audit(AuditCommand),
}

#[derive(Subcommand)]
enum EnvCommand {
    /// Initialise an environment descriptor.
    Init(EnvInitArgs),
    /// Insert or update a hub entry in the descriptor.
    #[command(name = "add-hub")]
    AddHub(EnvAddHubArgs),
    /// Insert or update a tenant entry in the descriptor.
    #[command(name = "add-tenant")]
    AddTenant(EnvAddTenantArgs),
    /// Show descriptor contents.
    Show(EnvShowArgs),
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Inspect query audit messages for a stream.
    Queries(AuditQueriesArgs),
    /// Summarise schemas and audit coverage for known streams.
    Summary(AuditSummaryArgs),
    /// Evaluate audit enforcement policy files.
    #[command(name = "enforce-check")]
    EnforceCheck(AuditEnforceCheckArgs),
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
    /// Inspect TLS configuration for a hub endpoint.
    #[command(name = "tls-info")]
    TlsInfo(HubTlsInfoArgs),
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
enum FederateCommand {
    /// Describe the work required to mirror a stream between hubs.
    #[command(name = "mirror-plan")]
    MirrorPlan(FederateMirrorPlanArgs),
    /// Execute a mirror plan by copying receipts into the target hub.
    #[command(name = "mirror-run")]
    MirrorRun(FederateMirrorRunArgs),
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
    /// Show the effective label classification for a label.
    Show(LabelClassShowArgs),
    /// List known label classifications.
    List(LabelClassListArgs),
}

#[derive(Subcommand)]
enum SchemaCommand {
    /// Compute the canonical schema identifier for a name.
    Id(SchemaIdArgs),
    /// Register or update schema metadata.
    Register(SchemaRegisterArgs),
    /// Show schema metadata and usage details.
    Show(SchemaShowArgs),
    /// Fetch schema descriptors from the hub.
    List(SchemaListArgs),
}

#[derive(Subcommand)]
enum WalletCommand {
    /// Emit a wallet transfer event.
    Transfer(WalletTransferArgs),
    /// Fold paid operations into account balances.
    Ledger(WalletLedgerArgs),
}

#[derive(Subcommand)]
enum AgreementCommand {
    /// Show agreement activity and party decisions.
    Status(AgreementStatusArgs),
}

#[derive(Subcommand)]
enum SnapshotCommand {
    /// Verify folded state against a state.checkpoint.v1 record.
    Verify(SnapshotVerifyArgs),
}

#[derive(Subcommand)]
enum OperationCommand {
    /// Compute derived identifiers for stored operation messages.
    #[command(name = "id")]
    Id(OperationIdArgs),
    /// Submit an arbitrary operation payload defined by its schema name.
    #[command(name = "send")]
    Send(OperationSendArgs),
    /// Submit a paid.operation.v1 payload.
    #[command(name = "paid")]
    Paid(OperationPaidArgs),
    /// Submit an access.grant.v1 payload.
    #[command(name = "access-grant")]
    AccessGrant(OperationAccessGrantArgs),
    /// Submit an access.revoke.v1 payload.
    #[command(name = "access-revoke")]
    AccessRevoke(OperationAccessRevokeArgs),
    /// Submit a delegated.execution.v1 payload.
    #[command(name = "delegated")]
    Delegated(OperationDelegatedArgs),
    /// Submit a recovery.request.v1 payload.
    #[command(name = "recovery-request")]
    RecoveryRequest(OperationRecoveryRequestArgs),
    /// Submit a recovery.approval.v1 payload.
    #[command(name = "recovery-approval")]
    RecoveryApproval(OperationRecoveryApprovalArgs),
    /// Submit a recovery.execution.v1 payload.
    #[command(name = "recovery-execution")]
    RecoveryExecution(OperationRecoveryExecutionArgs),
}

#[derive(Subcommand)]
enum RecoveryCommand {
    /// Show the recovery timeline for an identity.
    Timeline(RecoveryTimelineArgs),
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
    /// Configure on-disk retention for a hub data directory.
    Set(RetentionSetArgs),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RetentionValue {
    Indefinite,
    Seconds(u64),
}

impl FromStr for RetentionValue {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.eq_ignore_ascii_case("indefinite") {
            return Ok(Self::Indefinite);
        }

        input
            .parse::<u64>()
            .map(Self::Seconds)
            .map_err(|_| "expected <seconds> or 'indefinite'".to_string())
    }
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
    /// Exercise federated overlay scenarios (FED1/AUTH1).
    Federated,
    /// Exercise lifecycle and revocation checks (KEX1+).
    Kex1,
    /// Exercise hardening/PoW checks (SH1+).
    Hardened,
    /// Exercise label/schema overlays (META0+).
    Meta,
    /// Exercise recorder overlay scenarios.
    Recorder,
    /// Run every v0.0.1+ suite sequentially with aggregated reporting.
    Plus,
    /// Run the v0.0.1++ orchestration suite.
    #[command(name = "plus-plus")]
    PlusPlus,
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

#[derive(Debug, Clone, Default, Args)]
struct HubLocatorArgs {
    #[arg(long, value_name = "URL|PATH")]
    hub: Option<String>,
    #[arg(long, value_name = "PATH")]
    env: Option<PathBuf>,
    #[arg(long = "hub-name", value_name = "NAME")]
    hub_name: Option<String>,
}

impl HubLocatorArgs {
    #[cfg(test)]
    fn from_url(url: String) -> Self {
        Self {
            hub: Some(url),
            env: None,
            hub_name: None,
        }
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
    /// Require proof-of-work from clients before accepting submissions.
    #[arg(long, value_name = "BITS")]
    pow_difficulty: Option<u8>,
}

#[derive(Args)]
struct HubStopArgs {
    #[arg(long)]
    data_dir: PathBuf,
}

#[derive(Args)]
struct HubStatusArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
}

#[derive(Args)]
struct HubKeyArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
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
    #[command(flatten)]
    hub: HubLocatorArgs,
}

#[derive(Args)]
struct HubMetricsArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    raw: bool,
}

#[derive(Args)]
struct HubProfileArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct HubRoleArgs {
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
struct HubKexPolicyArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct HubAdmissionArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct HubAdmissionLogArgs {
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
struct HubCheckpointLatestArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
}

#[derive(Args)]
struct HubCheckpointRangeArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long, value_name = "EPOCH")]
    from_epoch: Option<u64>,
    #[arg(long, value_name = "EPOCH")]
    to_epoch: Option<u64>,
}

#[derive(Args)]
struct HubTlsInfoArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
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
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct SendArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
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
    /// Solve or supply a proof-of-work cookie requiring this difficulty (bits).
    #[arg(long, value_name = "BITS")]
    pow_difficulty: Option<u8>,
    /// Hex-encoded challenge to solve or re-use (requires --pow-difficulty).
    #[arg(long, value_name = "HEX")]
    pow_challenge: Option<String>,
    /// Pre-computed nonce for the supplied challenge (requires --pow-difficulty and --pow-challenge).
    #[arg(long, value_name = "NONCE")]
    pow_nonce: Option<u64>,
}

#[derive(Args)]
struct EnvInitArgs {
    #[arg(long)]
    root: PathBuf,
    #[arg(long)]
    name: String,
    #[arg(long, value_name = "CONTEXT")]
    cluster_context: String,
    #[arg(long)]
    namespace: String,
    #[arg(long)]
    description: Option<String>,
}

#[derive(Args)]
struct EnvAddHubArgs {
    #[arg(long)]
    env: PathBuf,
    #[arg(long = "hub-name")]
    hub_name: String,
    #[arg(long)]
    service_url: String,
    #[arg(long, value_name = "HEX32")]
    profile_id: String,
    #[arg(long, value_name = "HEX32")]
    realm: Option<String>,
}

#[derive(ValueEnum, Clone, Debug)]
enum EnvTenantLabelClass {
    User,
    Wallet,
    Log,
    Admin,
    Bulk,
}

impl EnvTenantLabelClass {
    fn as_str(&self) -> &'static str {
        match self {
            EnvTenantLabelClass::User => "user",
            EnvTenantLabelClass::Wallet => "wallet",
            EnvTenantLabelClass::Log => "log",
            EnvTenantLabelClass::Admin => "admin",
            EnvTenantLabelClass::Bulk => "bulk",
        }
    }
}

#[derive(Args)]
struct EnvAddTenantArgs {
    #[arg(long)]
    env: PathBuf,
    #[arg(long = "tenant-id")]
    tenant_id: String,
    #[arg(long = "stream-prefix")]
    stream_prefix: String,
    #[arg(long = "label-class", value_enum)]
    label_class: Option<EnvTenantLabelClass>,
}

#[derive(Args)]
struct EnvShowArgs {
    #[arg(long)]
    env: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct AuditQueriesArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    stream: String,
    #[arg(long = "resource-prefix")]
    resource_prefix: Option<String>,
    #[arg(long, value_name = "UNIX_TIME")]
    since: Option<u64>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct AuditSummaryArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    env: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct AuditEnforceCheckArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long = "policy-file")]
    policy_files: Vec<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct EnvDescriptor {
    version: u64,
    name: String,
    pub(crate) cluster_context: String,
    pub(crate) namespace: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    hubs: BTreeMap<String, EnvHubDescriptor>,
    #[serde(default)]
    tenants: BTreeMap<String, EnvTenantDescriptor>,
}

impl EnvDescriptor {
    fn validate(&self) -> Result<()> {
        if self.version != ENV_DESCRIPTOR_VERSION {
            bail_usage!(
                "unsupported env descriptor version {} (expected {})",
                self.version,
                ENV_DESCRIPTOR_VERSION
            );
        }
        if self.name.trim().is_empty() {
            bail_usage!("name must not be empty");
        }
        if self.cluster_context.trim().is_empty() {
            bail_usage!("cluster_context must not be empty");
        }
        if self.namespace.trim().is_empty() {
            bail_usage!("namespace must not be empty");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct EnvHubDescriptor {
    service_url: String,
    profile_id: String,
    #[serde(default)]
    realm_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct EnvTenantDescriptor {
    stream_prefix: String,
    label_class: String,
}

#[derive(Args)]
struct StreamArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
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
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    cap: PathBuf,
}

#[derive(Args)]
struct CapStatusArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    cap: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct CapRevocationsArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
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
    #[command(flatten)]
    hub: HubLocatorArgs,
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
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long, value_name = "HEX32")]
    realm: String,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args, Clone)]
struct FederateMirrorPlanArgs {
    #[arg(long, value_name = "URL")]
    source: String,
    #[arg(long, value_name = "URL")]
    target: String,
    #[arg(long)]
    stream: String,
    #[arg(long, value_name = "SEQ")]
    from: Option<u64>,
    #[arg(long, value_name = "SEQ")]
    upto: Option<u64>,
    #[arg(long = "label-map", value_name = "SRC=TARGET")]
    label_map: Vec<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args, Clone)]
struct FederateMirrorRunArgs {
    #[command(flatten)]
    plan: FederateMirrorPlanArgs,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    cap: Option<PathBuf>,
}

#[derive(Args)]
struct LabelAuthorityArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long, value_name = "HEX32")]
    label: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct LabelClassSetArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
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
struct LabelClassShowArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long, value_name = "HEX32")]
    label: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct LabelClassListArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long, value_name = "HEX32")]
    realm: Option<String>,
    #[arg(long)]
    class: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct SchemaIdArgs {
    /// Schema name used for hashing.
    name: String,
}

#[derive(Args)]
struct SchemaRegisterArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
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
struct SchemaShowArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long = "schema-id", value_name = "HEX32")]
    schema_id: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct SchemaListArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
}

#[derive(Args)]
struct WalletTransferArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
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
struct WalletLedgerArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    stream: String,
    #[arg(long = "since-stream-seq", default_value_t = 1)]
    since_stream_seq: u64,
    #[arg(long = "upto-stream-seq")]
    upto_stream_seq: Option<u64>,
    #[arg(long, value_name = "HEX32")]
    account: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct AgreementStatusArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    stream: String,
    #[arg(long = "agreement-id", value_name = "HEX32")]
    agreement_id: String,
    #[arg(long)]
    version: Option<u64>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct RecoveryTimelineArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    stream: String,
    #[arg(long = "target-identity", value_name = "HEX32")]
    target_identity: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct SnapshotVerifyArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    stream: String,
    #[arg(long = "state-id", value_name = "HEX32")]
    state_id: String,
    #[arg(long = "upto-stream-seq", value_name = "SEQ")]
    upto_stream_seq: u64,
    #[arg(long = "state-class", value_name = "CLASS_NAME")]
    state_class: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct OperationIdArgs {
    #[arg(long)]
    bundle: PathBuf,
}

#[derive(Args)]
struct OperationSendArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long = "schema-name")]
    schema_name: String,
    #[arg(long = "body-json")]
    body_json: String,
    #[arg(long)]
    cap: Option<PathBuf>,
    #[arg(long = "expires-at", value_name = "UNIX_TS")]
    expires_at: Option<u64>,
    #[arg(long = "parent-id", value_name = "HEX32")]
    parent_id: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct OperationPaidArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long = "op-type")]
    operation_type: String,
    #[arg(long = "payer", value_name = "HEX32")]
    payer: String,
    #[arg(long = "payee", value_name = "HEX32")]
    payee: String,
    #[arg(long)]
    amount: u64,
    #[arg(long = "currency-code")]
    currency_code: String,
    #[arg(long = "op-args-json")]
    operation_args: Option<String>,
    #[arg(long = "ttl-seconds")]
    ttl_seconds: Option<u64>,
    #[arg(long = "op-ref", value_name = "HEX32")]
    operation_reference: Option<String>,
    #[arg(long = "parent-op", value_name = "HEX32")]
    parent_operation: Option<String>,
    #[arg(long)]
    cap: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct OperationAccessGrantArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long = "admin")]
    admin: PathBuf,
    #[arg(long = "subject-identity", value_name = "HEX32")]
    subject_identity: String,
    #[arg(long)]
    stream: String,
    #[arg(long = "expiry-time", value_name = "UNIX_TS")]
    expiry_time: u64,
    #[arg(long = "allowed-stream", value_name = "HEX32")]
    allowed_streams: Vec<String>,
    #[arg(long = "max-rate-per-second")]
    max_rate_per_second: Option<u64>,
    #[arg(long = "max-burst")]
    max_burst: Option<u64>,
    #[arg(long = "max-amount")]
    max_amount: Option<u64>,
    #[arg(long = "currency-code")]
    currency_code: Option<String>,
    #[arg(long = "reason")]
    reason: Option<String>,
    #[arg(long = "parent-op", value_name = "HEX32")]
    parent_operation: Option<String>,
}

#[derive(Args)]
struct OperationAccessRevokeArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long = "admin")]
    admin: PathBuf,
    #[arg(long = "subject-identity", value_name = "HEX32")]
    subject_identity: String,
    #[arg(long)]
    stream: String,
    #[arg(long = "target-cap-ref", value_name = "HEX32")]
    target_capability_reference: Option<String>,
    #[arg(long = "reason")]
    reason: Option<String>,
    #[arg(long = "parent-op", value_name = "HEX32")]
    parent_operation: Option<String>,
}

#[derive(Args)]
struct OperationDelegatedArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long = "principal", value_name = "HEX32")]
    principal: String,
    #[arg(long = "agent", value_name = "HEX32")]
    agent: String,
    #[arg(
        long = "delegation-cap",
        value_name = "HEX32",
        value_delimiter = ',',
        num_args = 1..
    )]
    delegation_caps: Vec<String>,
    #[arg(long = "operation-schema-id", value_name = "HEX32")]
    operation_schema_id: String,
    #[arg(long = "operation-body-json")]
    operation_body_json: String,
    #[arg(long = "parent-op", value_name = "HEX32")]
    parent_operation: Option<String>,
}

#[derive(Args)]
struct OperationRecoveryRequestArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long = "target-identity", value_name = "HEX32")]
    target_identity: String,
    #[arg(long = "requested-new-identity", value_name = "HEX32")]
    requested_new_identity: String,
    #[arg(long)]
    reason: Option<String>,
    #[arg(long = "request-time", value_name = "UNIX_TS")]
    request_time: Option<u64>,
    #[arg(long = "metadata-json")]
    metadata_json: Option<String>,
    #[arg(long)]
    cap: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct OperationRecoveryApprovalArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long = "target-identity", value_name = "HEX32")]
    target_identity: String,
    #[arg(long = "requested-new-identity", value_name = "HEX32")]
    requested_new_identity: String,
    #[arg(long = "guardian-identity", value_name = "HEX32")]
    guardian_identity: String,
    #[arg(long = "policy-group-id", value_name = "HEX32")]
    policy_group_id: Option<String>,
    #[arg(long)]
    decision: String,
    #[arg(long = "decision-time", value_name = "UNIX_TS")]
    decision_time: Option<u64>,
    #[arg(long = "parent-op", value_name = "HEX32")]
    parent_operation: Option<String>,
    #[arg(long = "metadata-json")]
    metadata_json: Option<String>,
    #[arg(long)]
    cap: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct OperationRecoveryExecutionArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long = "target-identity", value_name = "HEX32")]
    target_identity: String,
    #[arg(long = "new-identity", value_name = "HEX32")]
    new_identity: String,
    #[arg(
        long = "approval-ref",
        value_name = "HEX32",
        value_delimiter = ',',
        num_args = 1..
    )]
    approval_references: Vec<String>,
    #[arg(long = "applied-time", value_name = "UNIX_TS")]
    applied_time: Option<u64>,
    #[arg(long = "metadata-json")]
    metadata_json: Option<String>,
    #[arg(long)]
    cap: Option<PathBuf>,
    #[arg(long)]
    json: bool,
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
    #[command(flatten)]
    hub: HubLocatorArgs,
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
    #[command(flatten)]
    hub: HubLocatorArgs,
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
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
}

#[derive(Args)]
struct VerifyStateArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
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
    #[command(flatten)]
    hub: HubLocatorArgs,
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
    /// Solve or supply a proof-of-work cookie requiring this difficulty (bits).
    #[arg(long, value_name = "BITS")]
    pow_difficulty: Option<u8>,
    /// Hex-encoded challenge to solve or re-use (requires --pow-difficulty).
    #[arg(long, value_name = "HEX")]
    pow_challenge: Option<String>,
    /// Pre-computed nonce for the supplied challenge (requires --pow-difficulty and --pow-challenge).
    #[arg(long, value_name = "NONCE")]
    pow_nonce: Option<u64>,
}

#[derive(Args)]
struct CrdtLwwSetArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
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
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    key: String,
}

#[derive(Args)]
struct CrdtOrsetAddArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    elem: String,
}

#[derive(Args)]
struct CrdtOrsetRemoveArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    elem: String,
}

#[derive(Args)]
struct CrdtOrsetListArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
}

#[derive(Args)]
struct CrdtCounterAddArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    delta: u64,
}

#[derive(Args)]
struct CrdtCounterGetArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
}

#[derive(Args)]
struct AnchorPublishArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
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
    #[arg(long, value_name = "DIR")]
    data_dir: PathBuf,
}

#[derive(Args, Clone, Debug)]
struct RetentionSetArgs {
    /// Hub data directory containing retention configuration.
    #[arg(long, value_name = "DIR")]
    data_dir: PathBuf,
    /// Retention window for receipts (seconds or "indefinite").
    #[arg(long, value_name = "SECONDS|indefinite")]
    receipts: Option<RetentionValue>,
    /// Retention window for payloads (seconds or "indefinite").
    #[arg(long, value_name = "SECONDS|indefinite")]
    payloads: Option<RetentionValue>,
    /// Retention window for checkpoints (seconds or "indefinite").
    #[arg(long, value_name = "SECONDS|indefinite")]
    checkpoints: Option<RetentionValue>,
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

fn hub_metrics_from_remote(report: &RemoteObservabilityReport) -> HubMetricsSnapshot {
    HubMetricsSnapshot {
        submit_ok_total: report.submit_ok_total,
        submit_err_total: report.submit_err_total.clone(),
        ..HubMetricsSnapshot::default()
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
struct RemoteLabelClassDescriptor {
    ok: bool,
    label: String,
    #[serde(default)]
    class: Option<String>,
    #[serde(default)]
    sensitivity: Option<String>,
    #[serde(default)]
    retention_hint: Option<u64>,
    pad_block_effective: u64,
    retention_policy: String,
    rate_policy: String,
}

#[derive(Debug, Deserialize)]
struct RemoteLabelClassList {
    ok: bool,
    entries: Vec<RemoteLabelClassEntry>,
}

#[derive(Debug, Deserialize)]
struct RemoteLabelClassEntry {
    label: String,
    class: String,
    #[serde(default)]
    sensitivity: Option<String>,
    #[serde(default)]
    retention_hint: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
struct RemoteSchemaRegistryEntry {
    ok: bool,
    #[serde(default)]
    descriptor: Option<RemoteSchemaDescriptorEntry>,
    #[serde(default)]
    usage: Option<RemoteSchemaUsage>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
struct RemoteSchemaDescriptorEntry {
    schema_id: String,
    name: String,
    version: String,
    #[serde(default)]
    doc_url: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    ts: u64,
    #[serde(default)]
    created_at: Option<u64>,
    #[serde(default)]
    updated_at: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Default)]
struct RemoteSchemaUsage {
    #[serde(default)]
    used_labels: Vec<String>,
    #[serde(default)]
    used_count: Option<u64>,
    #[serde(default)]
    first_used_ts: Option<u64>,
    #[serde(default)]
    last_used_ts: Option<u64>,
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

pub async fn cli_main() {
    let args: Vec<_> = env::args_os().collect();
    let exit_code = match Cli::try_parse_from(&args) {
        Ok(cli) => match run_cli(cli).await {
            Ok(()) => 0,
            Err(err) => {
                let classification = classify_error(&err);
                let detail = err.to_string();
                let use_json = json_output_enabled(false);
                emit_cli_error(classification.label(), Some(&detail), use_json);
                classification.exit_code()
            }
        },
        Err(err) => handle_parse_error(err, &args),
    };
    process::exit(exit_code);
}

async fn run_cli(cli: Cli) -> Result<()> {
    let Cli { global, command } = cli;
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
            HubCommand::TlsInfo(args) => handle_hub_tls_info(args).await,
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
        Command::Federate(cmd) => match cmd {
            FederateCommand::MirrorPlan(args) => handle_federate_mirror_plan(args).await,
            FederateCommand::MirrorRun(args) => handle_federate_mirror_run(args).await,
        },
        Command::Label(cmd) => match cmd {
            LabelCommand::Authority(args) => handle_label_authority(args).await,
        },
        Command::LabelClass(cmd) => match cmd {
            LabelClassCommand::Set(args) => handle_label_class_set(args).await,
            LabelClassCommand::Show(args) => handle_label_class_show(args).await,
            LabelClassCommand::List(args) => handle_label_class_list(args).await,
        },
        Command::Schema(cmd) => match cmd {
            SchemaCommand::Id(args) => handle_schema_id(args).await,
            SchemaCommand::Register(args) => handle_schema_register(args).await,
            SchemaCommand::Show(args) => handle_schema_show(args).await,
            SchemaCommand::List(args) => handle_schema_list(args).await,
        },
        Command::Wallet(cmd) => match cmd {
            WalletCommand::Transfer(args) => handle_wallet_transfer(args).await,
            WalletCommand::Ledger(args) => handle_wallet_ledger(args).await,
        },
        Command::Agreement(cmd) => match cmd {
            AgreementCommand::Status(args) => handle_agreement_status(args).await,
        },
        Command::Snapshot(cmd) => match cmd {
            SnapshotCommand::Verify(args) => handle_snapshot_verify(args).await,
        },
        Command::Operation(cmd) => match cmd {
            OperationCommand::Id(args) => handle_operation_id(args).await,
            OperationCommand::Send(args) => handle_operation_send(args).await,
            OperationCommand::Paid(args) => handle_operation_paid(args).await,
            OperationCommand::AccessGrant(args) => handle_operation_access_grant(args).await,
            OperationCommand::AccessRevoke(args) => handle_operation_access_revoke(args).await,
            OperationCommand::Delegated(args) => handle_operation_delegated(args).await,
            OperationCommand::RecoveryRequest(args) => {
                handle_operation_recovery_request(args).await
            }
            OperationCommand::RecoveryApproval(args) => {
                handle_operation_recovery_approval(args).await
            }
            OperationCommand::RecoveryExecution(args) => {
                handle_operation_recovery_execution(args).await
            }
        },
        Command::Recovery(cmd) => match cmd {
            RecoveryCommand::Timeline(args) => handle_recovery_timeline(args).await,
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
            RetentionCommand::Set(args) => handle_retention_set(args).await,
        },
        Command::HubTls(cmd) => match cmd {
            HubTlsCommand::TlsInfo(args) => handle_hub_tls_info(args).await,
        },
        Command::Env(cmd) => match cmd {
            EnvCommand::Init(args) => handle_env_init(args).await,
            EnvCommand::AddHub(args) => handle_env_add_hub(args).await,
            EnvCommand::AddTenant(args) => handle_env_add_tenant(args).await,
            EnvCommand::Show(args) => handle_env_show(args).await,
        },
        Command::Kube(cmd) => handle_kube_command(cmd).await,
        Command::Audit(cmd) => match cmd {
            AuditCommand::Queries(args) => handle_audit_queries(args).await,
            AuditCommand::Summary(args) => handle_audit_summary(args).await,
            AuditCommand::EnforceCheck(args) => handle_audit_enforce_check(args).await,
        },
        Command::Selftest(cmd) => match cmd {
            SelftestCommand::Core => handle_selftest_core().await,
            SelftestCommand::Props => handle_selftest_props().await,
            SelftestCommand::Fuzz => handle_selftest_fuzz().await,
            SelftestCommand::All => handle_selftest_all().await,
            SelftestCommand::Federated => handle_selftest_federated().await,
            SelftestCommand::Kex1 => handle_selftest_kex1().await,
            SelftestCommand::Hardened => handle_selftest_hardened().await,
            SelftestCommand::Meta => handle_selftest_meta().await,
            SelftestCommand::Recorder => handle_selftest_recorder().await,
            SelftestCommand::Plus => handle_selftest_plus().await,
            SelftestCommand::PlusPlus => handle_selftest_plus_plus().await,
        },
    }
}

fn handle_parse_error(err: clap::Error, args: &[std::ffi::OsString]) -> i32 {
    match err.kind() {
        clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
            let _ = err.print();
            0
        }
        _ => {
            let detail = err.to_string();
            let use_json = args_request_json_output(args);
            emit_cli_error(CliExitKind::Usage.label(), Some(detail.trim()), use_json);
            CliExitKind::Usage.exit_code()
        }
    }
}

fn args_request_json_output(args: &[std::ffi::OsString]) -> bool {
    args.iter().any(|arg| arg == std::ffi::OsStr::new("--json"))
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
    if error_chain_contains::<AuditPolicyViolationError>(err) {
        return ErrorClassification::new(CliExitKind::Policy);
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

fn validate_pow_difficulty(pow_difficulty: Option<u8>) -> Result<()> {
    if let Some(0) = pow_difficulty {
        bail_usage!("--pow-difficulty must be greater than zero");
    }

    Ok(())
}

fn hub_start_overrides(profile_id: &str, pow_difficulty: Option<u8>) -> Result<HubConfigOverrides> {
    validate_pow_difficulty(pow_difficulty)?;

    Ok(HubConfigOverrides {
        profile_id: Some(profile_id.to_string()),
        pow_difficulty,
        ..HubConfigOverrides::default()
    })
}

async fn handle_hub_start(args: HubStartArgs) -> Result<()> {
    validate_pow_difficulty(args.pow_difficulty)?;

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

    storage::ensure_data_dir_layout(&args.data_dir).await?;

    let HubStartArgs {
        listen,
        data_dir,
        config,
        profile_id,
        foreground,
        log_level,
        pow_difficulty,
    } = args;

    let profile_id = resolve_profile_id(profile_id)?;
    let log_level_str = log_level.as_ref().map(ToString::to_string);

    let overrides = hub_start_overrides(&profile_id, pow_difficulty)?;

    let key_info = ensure_hub_key_material(&data_dir).await?;

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
    storage::ensure_tls_snapshot(&data_dir).await?;

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
        if let Some(pow_difficulty) = pow_difficulty {
            println!("pow_difficulty: {pow_difficulty}");
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
    if let Some(pow_difficulty) = args.pow_difficulty {
        command
            .arg("--pow-difficulty")
            .arg(pow_difficulty.to_string());
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
    let reference = hub_reference_from_locator(&args.hub, "hub status").await?;
    let result = match reference {
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
    match hub_reference_from_locator(&args.hub, "hub key").await? {
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
    match hub_reference_from_locator(&args.hub, "hub health").await? {
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
    match hub_reference_from_locator(&args.hub, "hub metrics").await? {
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
            let metrics = hub_metrics_from_remote(&report);
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
    let client = match hub_reference_from_locator(&args.hub, "hub profile").await? {
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

    let client = match hub_reference_from_locator(&hub, "hub role").await? {
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
    let client = match hub_reference_from_locator(&args.hub, "hub kex-policy").await? {
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
    let client = match hub_reference_from_locator(&args.hub, "hub admission").await? {
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
    let client = match hub_reference_from_locator(&args.hub, "hub admission-log").await? {
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
    let client = match hub_reference_from_locator(&args.hub, "hub checkpoint-latest").await? {
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
    let client = match hub_reference_from_locator(&args.hub, "hub checkpoint-range").await? {
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
    let hub = hub_reference_from_locator(&args.hub, "hub tls-info")
        .await?
        .into_local()?;
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

    let policy_descriptor = if let Some(resolved) = resolve_optional_hub(&args.hub).await? {
        match resolved.reference {
            HubReference::Remote(client) => {
                Some(fetch_remote_kex_policy_descriptor(&client).await?)
            }
            HubReference::Local(_) => {
                bail_usage!("id usage policy requires an HTTP hub endpoint (e.g. http://host:port)")
            }
        }
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

struct SendOutcome {
    stream: String,
    seq: u64,
    client_id_hex: String,
    detail: SendOutcomeDetail,
}

enum SendOutcomeDetail {
    Local(Box<LocalSendDetail>),
    Remote(RemoteSendDetail),
}

struct LocalSendDetail {
    message: StoredMessage,
    bundle_path: PathBuf,
    receipt: StreamReceipt,
}

struct RemoteSendDetail {
    response: RemoteSubmitResponse,
}

fn render_send_outcome(outcome: &SendOutcome) {
    match &outcome.detail {
        SendOutcomeDetail::Local(detail) => {
            let detail = detail.as_ref();
            println!(
                "sent message seq={} stream={} client_id={}",
                outcome.seq, outcome.stream, outcome.client_id_hex
            );
            println!("bundle: {}", detail.bundle_path.display());
            if detail.message.attachments.is_empty() {
                return;
            }
            println!("attachments recorded: {}", detail.message.attachments.len());
            for attachment in &detail.message.attachments {
                println!(
                    "  {} ({} bytes) -> {}",
                    attachment.name, attachment.size, attachment.digest
                );
            }
        }
        SendOutcomeDetail::Remote(detail) => {
            println!(
                "sent message seq={} stream={} client_id={}",
                detail.response.seq, detail.response.stream, outcome.client_id_hex
            );
            if detail.response.stored_attachments.is_empty() {
                return;
            }
            println!(
                "attachments stored: {}",
                detail.response.stored_attachments.len()
            );
            for attachment in &detail.response.stored_attachments {
                println!(
                    "  {} ({} bytes) -> {}",
                    attachment.name, attachment.size, attachment.digest
                );
            }
        }
    }
}

async fn handle_send(args: SendArgs) -> Result<()> {
    let reference = hub_reference_from_locator(&args.hub, "send").await?;
    let outcome = send_message_with_reference(reference, args).await?;
    render_send_outcome(&outcome);
    log_cli_goal("CLI.CORE.SEND");
    Ok(())
}

async fn send_message_with_reference(
    reference: HubReference,
    args: SendArgs,
) -> Result<SendOutcome> {
    match reference {
        HubReference::Local(data_dir) => send_message_local(data_dir, args).await,
        HubReference::Remote(client) => send_message_remote(client, args).await,
    }
}

async fn send_message_local(data_dir: PathBuf, args: SendArgs) -> Result<SendOutcome> {
    storage::ensure_data_dir_layout(&data_dir).await?;

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

    let receipt = compute_local_stream_receipt(&stream_state, seq)?;

    Ok(SendOutcome {
        stream: args.stream,
        seq,
        client_id_hex,
        detail: SendOutcomeDetail::Local(Box::new(LocalSendDetail {
            message,
            bundle_path,
            receipt,
        })),
    })
}

fn compute_local_stream_receipt(stream_state: &HubStreamState, seq: u64) -> Result<StreamReceipt> {
    let mut mmr = Mmr::new();
    let mut receipt = None;
    for message in &stream_state.messages {
        let leaf = compute_message_leaf_hash(message)?;
        let (_, root) = mmr.append(leaf);
        if message.seq == seq {
            receipt = Some(StreamReceipt {
                seq,
                leaf_hash: hex::encode(leaf.as_bytes()),
                mmr_root: hex::encode(root.as_bytes()),
                hub_ts: message.sent_at,
            });
        }
    }

    receipt.ok_or_else(|| anyhow!("failed to compute receipt for seq {seq}"))
}

async fn send_message_remote(client: HubHttpClient, args: SendArgs) -> Result<SendOutcome> {
    if args.pow_challenge.is_some() && args.pow_difficulty.is_none() {
        bail_usage!("--pow-challenge requires --pow-difficulty");
    }
    if args.pow_nonce.is_some() && args.pow_difficulty.is_none() {
        bail_usage!("--pow-nonce requires --pow-difficulty");
    }
    if args.pow_nonce.is_some() && args.pow_challenge.is_none() {
        bail_usage!("--pow-nonce requires --pow-challenge");
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

        if let Some(nonce) = args.pow_nonce {
            let challenge_hex = args
                .pow_challenge
                .as_deref()
                .expect("pow_nonce requires pow_challenge");
            let challenge = decode_pow_challenge_hex(challenge_hex)?;
            let cookie = PowCookie {
                challenge,
                nonce,
                difficulty,
            };
            if !cookie.meets_difficulty() {
                bail_usage!(
                    "provided proof-of-work nonce does not satisfy difficulty {difficulty}"
                );
            }
            println!(
                "proof-of-work: nonce={} difficulty={} challenge={} (provided)",
                cookie.nonce,
                cookie.difficulty,
                hex::encode(&cookie.challenge)
            );
            Some(PowCookieEnvelope::from_cookie(&cookie))
        } else {
            let challenge = if let Some(ref hex_value) = args.pow_challenge {
                decode_pow_challenge_hex(hex_value)?
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
        }
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

    let send_ts = current_unix_timestamp()?;
    update_client_label_send_state(&args.client, &args.stream, response.seq, send_ts).await?;

    Ok(SendOutcome {
        stream: args.stream,
        seq: response.seq,
        client_id_hex,
        detail: SendOutcomeDetail::Remote(RemoteSendDetail { response }),
    })
}

fn decode_pow_challenge_hex(hex_value: &str) -> Result<Vec<u8>> {
    let trimmed = hex_value.trim();
    let bytes =
        hex::decode(trimmed).with_context(|| format!("decoding pow challenge {hex_value}"))?;
    if bytes.is_empty() {
        bail_usage!("--pow-challenge must not be empty");
    }
    Ok(bytes)
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
    let hub = hub_reference_from_locator(&args.hub, "stream").await?;
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
    match hub_reference_from_locator(&args.hub, "cap authorize").await? {
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
    let client = match hub_reference_from_locator(&args.hub, "cap status").await? {
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
    match hub_reference_from_locator(&args.hub, "cap revocations").await? {
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
    let client = match hub_reference_from_locator(&args.hub, "pow request").await? {
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
    match hub_reference_from_locator(&args.hub, "fed authority publish").await? {
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

    let client = match hub_reference_from_locator(&hub, "fed authority show").await? {
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

async fn handle_federate_mirror_plan(args: FederateMirrorPlanArgs) -> Result<()> {
    let context = compute_federate_mirror_plan(&args).await?;
    render_federate_mirror_plan(&context.plan, json_output_enabled(args.json));
    log_cli_goal("CLI.FED1.MIRROR_PLAN");
    Ok(())
}

async fn handle_federate_mirror_run(args: FederateMirrorRunArgs) -> Result<()> {
    let use_json = json_output_enabled(args.plan.json);
    let context = compute_federate_mirror_plan(&args.plan).await?;
    if !use_json {
        println!("mirror plan:");
        render_federate_mirror_plan(&context.plan, false);
    }

    if context.plan.pending == 0 {
        let output = FederateMirrorRunOutput {
            plan: context.plan.clone(),
            mirrored: Vec::new(),
        };
        render_federate_mirror_run_output(&output, use_json);
        log_cli_goal("CLI.FED1.MIRROR");
        return Ok(());
    }

    let mirrored = execute_federate_mirror_run(&context, &args, use_json).await?;
    let mut final_plan = context.plan.clone();
    if final_plan.pending >= mirrored.len() as u64 {
        final_plan.pending -= mirrored.len() as u64;
    } else {
        final_plan.pending = 0;
    }
    let output = FederateMirrorRunOutput {
        plan: final_plan,
        mirrored,
    };
    render_federate_mirror_run_output(&output, use_json);
    log_cli_goal("CLI.FED1.MIRROR");
    Ok(())
}

#[derive(Clone)]
struct FederateMirrorPlanContext {
    plan: FederateMirrorPlanOutput,
    source_client: HubHttpClient,
    target_client: HubHttpClient,
}

#[derive(Debug, Clone, Serialize)]
struct FederateMirrorPlanOutput {
    stream: String,
    target_label: String,
    copy_from_seq: u64,
    copy_upto_seq: u64,
    pending: u64,
    source: FederateMirrorEndpointPlan,
    target: FederateMirrorEndpointPlan,
    label_map: Vec<FederateMirrorLabelMapping>,
}

#[derive(Debug, Clone, Serialize)]
struct FederateMirrorEndpointPlan {
    url: String,
    hub_id: Option<String>,
    label: String,
    last_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    mmr_root: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct FederateMirrorLabelMapping {
    source: String,
    target: String,
}

#[derive(Debug, Clone, Serialize)]
struct FederateMirrorRunEntry {
    source_seq: u64,
    target_seq: u64,
    operation_id: String,
}

#[derive(Debug, Clone, Serialize)]
struct FederateMirrorRunOutput {
    plan: FederateMirrorPlanOutput,
    mirrored: Vec<FederateMirrorRunEntry>,
}

fn render_federate_mirror_plan(plan: &FederateMirrorPlanOutput, use_json: bool) {
    if use_json {
        match serde_json::to_string_pretty(plan) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => println!(
                "{}",
                serde_json::to_string(plan).unwrap_or_else(|_| "{}".to_string())
            ),
        }
        return;
    }

    println!("source.url: {}", plan.source.url);
    println!(
        "source.hub_id: {}",
        plan.source.hub_id.as_deref().unwrap_or("(unknown)")
    );
    println!("source.label: {}", plan.source.label);
    println!("source.last_seq: {}", plan.source.last_seq);
    println!(
        "source.mmr_root: {}",
        plan.source.mmr_root.as_deref().unwrap_or("(none)")
    );
    println!("target.url: {}", plan.target.url);
    println!(
        "target.hub_id: {}",
        plan.target.hub_id.as_deref().unwrap_or("(unknown)")
    );
    println!("target.label: {}", plan.target.label);
    println!("target.last_seq: {}", plan.target.last_seq);
    println!(
        "target.mmr_root: {}",
        plan.target.mmr_root.as_deref().unwrap_or("(none)")
    );
    println!("copy_from_seq: {}", plan.copy_from_seq);
    println!("copy_upto_seq: {}", plan.copy_upto_seq);
    println!("pending_messages: {}", plan.pending);
    println!("mirror.target_label: {}", plan.target_label);
    if plan.label_map.is_empty() {
        println!("label_map: (none)");
    } else {
        println!("label_map:");
        for mapping in &plan.label_map {
            println!("  {} -> {}", mapping.source, mapping.target);
        }
    }
}

fn render_federate_mirror_run_output(output: &FederateMirrorRunOutput, use_json: bool) {
    if use_json {
        match serde_json::to_string_pretty(output) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => println!(
                "{}",
                serde_json::to_string(output).unwrap_or_else(|_| "{}".to_string())
            ),
        }
        return;
    }

    if output.mirrored.is_empty() {
        println!("mirrored: (none)");
    } else {
        println!("mirrored:");
        for entry in &output.mirrored {
            println!("- source_seq: {}", entry.source_seq);
            println!("  target_seq: {}", entry.target_seq);
            println!("  operation_id: {}", entry.operation_id);
        }
    }
    println!("remaining_pending: {}", output.plan.pending);
}

async fn compute_federate_mirror_plan(
    args: &FederateMirrorPlanArgs,
) -> Result<FederateMirrorPlanContext> {
    let source_endpoint = args.source.trim();
    if source_endpoint.is_empty() {
        bail_usage!("--source must not be empty");
    }
    let target_endpoint = args.target.trim();
    if target_endpoint.is_empty() {
        bail_usage!("--target must not be empty");
    }
    let stream_label = args.stream.trim();
    if stream_label.is_empty() {
        bail_usage!("--stream must not be empty");
    }

    let mut label_map = parse_label_map_entries(&args.label_map)?;
    let source_label = stream_label.to_string();
    let target_label = label_map
        .entry(source_label.clone())
        .or_insert_with(|| source_label.clone())
        .clone();

    let source_client = parse_remote_hub_client(source_endpoint, "source hub")?;
    let target_client = parse_remote_hub_client(target_endpoint, "target hub")?;

    let source_plan = fetch_mirror_endpoint_plan(&source_client, &source_label)
        .await
        .with_context(|| format!("fetching source metrics for {}", source_label))?;
    let target_plan = fetch_mirror_endpoint_plan(&target_client, &target_label)
        .await
        .with_context(|| format!("fetching target metrics for {}", target_label))?;

    let requested_from = args
        .from
        .unwrap_or_else(|| target_plan.last_seq.saturating_add(1));
    let requested_upto = args.upto.unwrap_or(source_plan.last_seq);
    let copy_upto_seq = requested_upto.min(source_plan.last_seq);
    let copy_from_seq = requested_from;
    let pending = if copy_from_seq <= copy_upto_seq {
        copy_upto_seq - copy_from_seq + 1
    } else {
        0
    };

    let label_map_entries = label_map
        .into_iter()
        .map(|(source, target)| FederateMirrorLabelMapping { source, target })
        .collect();

    let plan = FederateMirrorPlanOutput {
        stream: source_label,
        target_label,
        copy_from_seq,
        copy_upto_seq,
        pending,
        source: source_plan,
        target: target_plan,
        label_map: label_map_entries,
    };

    Ok(FederateMirrorPlanContext {
        plan,
        source_client,
        target_client,
    })
}

async fn fetch_mirror_endpoint_plan(
    client: &HubHttpClient,
    label: &str,
) -> Result<FederateMirrorEndpointPlan> {
    let report: RemoteObservabilityReport = client
        .get_json("/metrics", &[])
        .await
        .context("fetching hub metrics for mirror plan")?;
    let last_seq = report.last_stream_seq.get(label).copied().unwrap_or(0);
    let mmr_root = report.mmr_roots.get(label).cloned();
    Ok(FederateMirrorEndpointPlan {
        url: client.endpoint().to_string(),
        hub_id: report.hub_id.clone(),
        label: label.to_string(),
        last_seq,
        mmr_root,
    })
}

async fn execute_federate_mirror_run(
    context: &FederateMirrorPlanContext,
    args: &FederateMirrorRunArgs,
    use_json: bool,
) -> Result<Vec<FederateMirrorRunEntry>> {
    let mut mirrored = Vec::new();
    let mut next_seq = context.plan.copy_from_seq;
    let upto_seq = context.plan.copy_upto_seq;
    let source_label = context.plan.stream.clone();
    let target_label = context.plan.target_label.clone();
    let source_identifier = context
        .plan
        .source
        .hub_id
        .clone()
        .unwrap_or_else(|| context.plan.source.url.clone());
    let target_reference = HubReference::Remote(context.target_client.clone());
    let target_locator = HubLocatorArgs {
        hub: Some(context.plan.target.url.clone()),
        env: None,
        hub_name: None,
    };

    while next_seq <= upto_seq {
        let query = vec![
            ("stream", source_label.clone()),
            ("from", next_seq.to_string()),
            ("with_proof", "true".to_string()),
        ];
        let remote_messages: Vec<RemoteStreamMessageWithProof> = context
            .source_client
            .get_json("/stream", &query)
            .await
            .with_context(|| {
                format!(
                    "fetching source stream {} from seq {}",
                    source_label, next_seq
                )
            })?;

        if remote_messages.is_empty() {
            bail_protocol!(
                "source hub returned no messages for {} from seq {}",
                source_label,
                next_seq
            );
        }

        let mut progressed = false;
        for remote in remote_messages {
            let message: StoredMessage = remote.message.into();
            if message.seq < next_seq {
                continue;
            }
            if message.seq > upto_seq {
                return Ok(mirrored);
            }
            if message.seq != next_seq {
                bail_protocol!(
                    "expected source seq {} but received {} while mirroring {}",
                    next_seq,
                    message.seq,
                    source_label
                );
            }

            let receipt = StreamReceipt::from(remote.receipt);
            let proof = remote
                .proof
                .clone()
                .try_into_mmr()
                .context("decoding stream proof")?;
            validate_stream_proof(&message, &receipt, &proof)?;

            let payload = encode_federation_mirror_payload(
                &source_identifier,
                &source_label,
                &target_label,
                message.seq,
                &receipt,
            )?;

            let send_args = SendArgs {
                hub: target_locator.clone(),
                client: args.client.clone(),
                stream: target_label.clone(),
                body: payload.json_body.clone(),
                schema: Some(payload.schema_hex()),
                expires_at: None,
                cap: args.cap.clone(),
                parent: None,
                attach: Vec::new(),
                no_store_body: false,
                pow_difficulty: None,
                pow_challenge: None,
                pow_nonce: None,
            };

            let outcome = send_message_with_reference(target_reference.clone(), send_args).await?;
            let submission = derive_operation_submission(
                target_reference.clone(),
                outcome,
                payload.schema_name.clone(),
                payload.schema_hex(),
            )
            .await?;

            let entry = FederateMirrorRunEntry {
                source_seq: message.seq,
                target_seq: submission.seq,
                operation_id: hex::encode(submission.operation_id.as_bytes()),
            };
            if !use_json {
                println!(
                    "mirrored {} seq {} -> target seq {} (operation_id {})",
                    source_label, entry.source_seq, entry.target_seq, entry.operation_id
                );
            }
            mirrored.push(entry);
            next_seq = next_seq.saturating_add(1);
            progressed = true;

            if next_seq > upto_seq {
                break;
            }
        }

        if !progressed {
            bail_protocol!(
                "source hub did not advance past seq {} while mirroring {}",
                next_seq,
                source_label
            );
        }
    }

    Ok(mirrored)
}

fn parse_label_map_entries(entries: &[String]) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for entry in entries {
        let (raw_source, raw_target) = entry.split_once('=').ok_or_else(|| {
            CliUsageError::new(format!(
                "--label-map entries must use source=target form: {entry}"
            ))
        })?;
        let source = raw_source.trim();
        let target = raw_target.trim();
        if source.is_empty() || target.is_empty() {
            bail_usage!("--label-map entries must not be empty: {entry}");
        }
        if map.insert(source.to_string(), target.to_string()).is_some() {
            bail_usage!("duplicate --label-map entry for {source}");
        }
    }
    Ok(map)
}

fn parse_leaf_hash_hex(value: &str) -> Result<LeafHash> {
    let bytes =
        hex::decode(value).with_context(|| format!("decoding receipt leaf hash {value}"))?;
    LeafHash::try_from(bytes.as_slice()).map_err(|err| anyhow!("invalid leaf hash: {err}"))
}

fn parse_mmr_root_hex(value: &str) -> Result<MmrRoot> {
    let bytes = hex::decode(value).with_context(|| format!("decoding receipt mmr root {value}"))?;
    MmrRoot::try_from(bytes.as_slice()).map_err(|err| anyhow!("invalid mmr root: {err}"))
}

fn derive_label_from_name(label: &str) -> Result<Label> {
    let stream_id = cap_stream_id_from_label(label)
        .with_context(|| format!("deriving stream identifier for {label}"))?;
    Ok(Label::derive([], stream_id, 0))
}

fn encode_federation_mirror_payload(
    source_identifier: &str,
    source_label: &str,
    target_label: &str,
    source_seq: u64,
    receipt: &StreamReceipt,
) -> Result<EncodedOperationPayload> {
    let leaf_hash = parse_leaf_hash_hex(&receipt.leaf_hash)?;
    let mmr_root = parse_mmr_root_hex(&receipt.mmr_root)?;
    let payload = FederationMirror {
        source_hub_identifier: source_identifier.to_string(),
        source_label: derive_label_from_name(source_label)?,
        source_stream_seq: source_seq,
        source_leaf_hash: leaf_hash,
        source_receipt_root: mmr_root,
        target_label: derive_label_from_name(target_label)?,
        mirror_time: Some(current_unix_timestamp()?),
        metadata: None,
    };
    encode_struct_operation_payload("federation.mirror.v1", schema_federation_mirror(), &payload)
}

fn parse_remote_hub_client(reference: &str, context: &str) -> Result<HubHttpClient> {
    match parse_hub_reference(reference)? {
        HubReference::Remote(client) => Ok(client),
        HubReference::Local(_) => {
            bail_usage!(
                "{context} must be specified as an http(s) URL",
                context = context
            )
        }
    }
}

async fn handle_label_authority(args: LabelAuthorityArgs) -> Result<()> {
    let LabelAuthorityArgs { hub, label, json } = args;

    let client = match hub_reference_from_locator(&hub, "label authority").await? {
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

async fn fetch_label_class_descriptor(
    client: &HubHttpClient,
    label_hex: &str,
) -> Result<RemoteLabelClassDescriptor> {
    let path = format!("/label-class/{label_hex}");
    client.get_json(&path, &[]).await
}

async fn fetch_label_class_list(
    client: &HubHttpClient,
    realm: Option<String>,
    class: Option<String>,
) -> Result<RemoteLabelClassList> {
    let mut query = Vec::new();
    if let Some(realm) = realm {
        query.push(("realm", realm));
    }
    if let Some(class) = class {
        query.push(("class", class));
    }
    client.get_json("/label-class", &query).await
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

fn render_label_class_descriptor(descriptor: &RemoteLabelClassDescriptor, use_json: bool) {
    if !descriptor.ok {
        emit_cli_error(
            "E.PROFILE",
            Some("hub declined to provide label classification"),
            use_json,
        );
        process::exit(4);
    }

    let output = format_label_class_descriptor_output(descriptor, use_json);
    println!("{output}");
}

fn render_label_class_list(list: &RemoteLabelClassList, use_json: bool) {
    if !list.ok {
        emit_cli_error(
            "E.PROFILE",
            Some("hub declined to provide label classifications"),
            use_json,
        );
        process::exit(4);
    }

    let output = format_label_class_list_output(list, use_json);
    println!("{output}");
}

fn render_schema_descriptor(response: &RemoteSchemaRegistryEntry, use_json: bool) {
    if !response.ok {
        emit_cli_error(
            "E.PROFILE",
            Some("hub declined to provide schema descriptor"),
            use_json,
        );
        process::exit(4);
    }

    let descriptor = match response.descriptor.as_ref() {
        Some(descriptor) => descriptor,
        None => {
            emit_cli_error(
                "E.SEQ",
                Some("schema identifier is not registered"),
                use_json,
            );
            process::exit(4);
        }
    };

    let output = format_schema_descriptor_output(descriptor, response.usage.as_ref(), use_json);
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
    match hub_reference_from_locator(&args.hub, "label-class set").await? {
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

async fn handle_label_class_show(args: LabelClassShowArgs) -> Result<()> {
    let LabelClassShowArgs { hub, label, json } = args;
    let client = match hub_reference_from_locator(&hub, "label-class show").await? {
        HubReference::Remote(client) => client,
        HubReference::Local(_) => {
            bail_usage!("label-class show requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    };

    let label_bytes = hex::decode(&label)
        .map_err(|err| CliUsageError::new(format!("label must be hex encoded: {err}")))?;
    let label_value = Label::from_slice(&label_bytes).map_err(|err| {
        CliUsageError::new(format!("label must encode a 32-byte identifier: {err}"))
    })?;
    let label_hex = hex::encode(label_value.as_bytes());
    let descriptor = fetch_label_class_descriptor(&client, &label_hex)
        .await
        .map_err(map_label_class_http_error)?;
    render_label_class_descriptor(&descriptor, json_output_enabled(json));
    log_cli_goal("CLI.LCLASS0.SHOW");
    Ok(())
}

async fn handle_label_class_list(args: LabelClassListArgs) -> Result<()> {
    let LabelClassListArgs {
        hub,
        realm,
        class,
        json,
    } = args;
    let client = match hub_reference_from_locator(&hub, "label-class list").await? {
        HubReference::Remote(client) => client,
        HubReference::Local(_) => {
            bail_usage!("label-class list requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    };

    let list = fetch_label_class_list(&client, realm.clone(), class.clone())
        .await
        .map_err(map_label_class_http_error)?;
    render_label_class_list(&list, json_output_enabled(json));
    log_cli_goal("CLI.LCLASS0.LIST");
    Ok(())
}

fn map_label_class_http_error(err: anyhow::Error) -> anyhow::Error {
    if let Some(response_err) = err.downcast_ref::<HubResponseError>() {
        if response_err.status == reqwest::StatusCode::NOT_FOUND
            || response_err.status == reqwest::StatusCode::METHOD_NOT_ALLOWED
        {
            return anyhow!(CliUsageError::new(
                "hub does not expose label classification endpoints; upgrade the hub".to_string(),
            ));
        }
    }
    err
}

async fn handle_schema_id(args: SchemaIdArgs) -> Result<()> {
    let digest = compute_schema_identifier(&args.name);
    println!("{}", hex::encode(digest));
    log_cli_goal("CLI.META0_PLUS.SCHEMA_ID");
    Ok(())
}

async fn handle_schema_register(args: SchemaRegisterArgs) -> Result<()> {
    match hub_reference_from_locator(&args.hub, "schema register").await? {
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

async fn handle_schema_show(args: SchemaShowArgs) -> Result<()> {
    let SchemaShowArgs {
        hub,
        schema_id,
        json,
    } = args;

    let client = match hub_reference_from_locator(&hub, "schema show").await? {
        HubReference::Remote(client) => client,
        HubReference::Local(_) => {
            bail_usage!("schema show requires an HTTP hub endpoint (e.g. http://host:port)")
        }
    };

    let schema = parse_schema_id_hex(&schema_id)?;
    let schema_hex = hex::encode(schema.as_bytes());
    let descriptor = fetch_schema_registry_entry(&client, &schema_hex).await?;
    render_schema_descriptor(&descriptor, json_output_enabled(json));
    log_cli_goal("CLI.META0_PLUS.SCHEMA_SHOW");
    Ok(())
}

async fn handle_schema_list(args: SchemaListArgs) -> Result<()> {
    match hub_reference_from_locator(&args.hub, "schema list").await? {
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

async fn fetch_schema_registry_entry(
    client: &HubHttpClient,
    schema_id_hex: &str,
) -> Result<RemoteSchemaRegistryEntry> {
    let path = format!("/schema/{schema_id_hex}");
    client
        .get_json(&path, &[])
        .await
        .context("fetching schema descriptor from hub registry")
}

async fn handle_wallet_transfer(args: WalletTransferArgs) -> Result<()> {
    match hub_reference_from_locator(&args.hub, "wallet transfer").await? {
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

async fn handle_wallet_ledger(args: WalletLedgerArgs) -> Result<()> {
    if args.since_stream_seq == 0 {
        bail_usage!("--since-stream-seq must be at least 1");
    }
    if let Some(upto) = args.upto_stream_seq {
        if upto < args.since_stream_seq {
            bail_usage!("--upto-stream-seq must be greater than or equal to --since-stream-seq");
        }
    }

    let use_json = json_output_enabled(args.json);
    let account_filter = if let Some(ref value) = args.account {
        let parsed = parse_account_id_hex(value)?;
        Some((parsed, hex::encode(parsed.as_bytes())))
    } else {
        None
    };

    let reference = hub_reference_from_locator(&args.hub, "wallet ledger").await?;
    let (messages, stream_tip) =
        load_stream_messages(reference, &args.stream, args.since_stream_seq).await?;

    let requested_upto = args.upto_stream_seq.unwrap_or(stream_tip);
    let effective_upto = requested_upto.min(stream_tip);

    let filter_ref = account_filter.as_ref().map(|(account, _)| account);
    let mut balances =
        fold_wallet_ledger(&messages, args.since_stream_seq, effective_upto, filter_ref)?;
    if let Some((_, ref hex_value)) = account_filter {
        balances.entry(hex_value.clone()).or_insert(0);
    }

    render_wallet_ledger(
        &args.stream,
        args.since_stream_seq,
        effective_upto,
        &balances,
        account_filter
            .as_ref()
            .map(|(_, hex_value)| hex_value.as_str()),
        use_json,
    );
    log_cli_goal("CLI.WALLET.LEDGER");
    Ok(())
}

fn render_wallet_ledger(
    stream: &str,
    from_seq: u64,
    upto_seq: u64,
    balances: &BTreeMap<String, i128>,
    account: Option<&str>,
    use_json: bool,
) {
    if use_json {
        let output = json!({
            "stream": stream,
            "from": from_seq,
            "upto": upto_seq,
            "balances": balances,
        });
        match serde_json::to_string_pretty(&output) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => println!("{output}"),
        }
        return;
    }

    println!("stream: {stream}");
    println!("from: {from_seq}");
    println!("upto: {upto_seq}");
    if let Some(account_hex) = account {
        let balance = balances.get(account_hex).copied().unwrap_or(0);
        println!("account: {account_hex}");
        println!("balance: {balance}");
        return;
    }

    if balances.is_empty() {
        println!("balances: (none)");
        return;
    }

    println!("balances:");
    for (account_hex, balance) in balances {
        println!("- {account_hex}: {balance}");
    }
}

fn fold_wallet_ledger<'a, I>(
    messages: I,
    from_seq: u64,
    upto_seq: u64,
    account_filter: Option<&AccountId>,
) -> Result<BTreeMap<String, i128>>
where
    I: IntoIterator<Item = &'a StoredMessage>,
{
    let mut balances = BTreeMap::new();
    let paid_schema_hex = hex::encode(schema_paid_operation());
    for message in messages {
        if message.seq < from_seq {
            continue;
        }
        if message.seq > upto_seq {
            break;
        }
        let schema_hex = match message.schema.as_deref() {
            Some(value) => value,
            None => continue,
        };
        if !schema_hex.eq_ignore_ascii_case(&paid_schema_hex) {
            continue;
        }
        let body = message.body.as_ref().ok_or_else(|| {
            ProtocolError::new(format!(
                "stream {}#{} does not contain stored body for paid operation",
                message.stream, message.seq
            ))
        })?;
        let payload: PaidOperation = serde_json::from_str(body).with_context(|| {
            format!(
                "decoding paid.operation.v1 payload for {}#{}",
                message.stream, message.seq
            )
        })?;
        let amount = payload.amount as i128;
        apply_balance_delta(
            &mut balances,
            &payload.payer_account,
            -amount,
            account_filter,
        )?;
        apply_balance_delta(
            &mut balances,
            &payload.payee_account,
            amount,
            account_filter,
        )?;
    }
    Ok(balances)
}

#[derive(Serialize)]
struct AgreementStatusPartyOutput {
    identity: String,
    decision: Option<String>,
    decision_time: Option<u64>,
}

#[derive(Serialize)]
struct AgreementStatusOutput {
    stream: String,
    agreement_id: String,
    version: u64,
    effective_time: Option<u64>,
    expiry_time: Option<u64>,
    active: bool,
    parties: Vec<AgreementStatusPartyOutput>,
}

#[derive(Clone)]
struct AgreementPartyFold {
    decision: String,
    decision_time: Option<u64>,
    seq: u64,
}

#[derive(Default)]
struct AgreementVersionFold {
    definition: Option<(AgreementDefinition, u64)>,
    confirmations: BTreeMap<String, AgreementPartyFold>,
}

async fn handle_agreement_status(args: AgreementStatusArgs) -> Result<()> {
    let agreement_id = parse_opaque_id_hex(&args.agreement_id)?;
    let use_json = json_output_enabled(args.json);
    let reference = hub_reference_from_locator(&args.hub, "agreement status").await?;
    let (messages, _) = load_stream_messages(reference, &args.stream, 0).await?;

    let versions = fold_agreement_versions(&messages, &agreement_id)?;
    let (version, state) = select_agreement_version(&versions, args.version)?;
    let (definition, _) = state.definition.clone().ok_or_else(|| {
        ProtocolError::new("agreement definition missing for requested version".to_string())
    })?;

    let mut seen_parties = BTreeSet::new();
    let mut parties = Vec::new();
    let mut all_parties_accept = true;
    for party in &definition.parties {
        let identity_hex = hex::encode(party.as_bytes());
        if !seen_parties.insert(identity_hex.clone()) {
            continue;
        }
        if let Some(status) = state.confirmations.get(&identity_hex) {
            if !status.decision.eq_ignore_ascii_case("accept") {
                all_parties_accept = false;
            }
            parties.push(AgreementStatusPartyOutput {
                identity: identity_hex,
                decision: Some(status.decision.clone()),
                decision_time: status.decision_time,
            });
        } else {
            all_parties_accept = false;
            parties.push(AgreementStatusPartyOutput {
                identity: identity_hex,
                decision: None,
                decision_time: None,
            });
        }
    }

    for (identity, status) in &state.confirmations {
        if seen_parties.contains(identity) {
            continue;
        }
        parties.push(AgreementStatusPartyOutput {
            identity: identity.clone(),
            decision: Some(status.decision.clone()),
            decision_time: status.decision_time,
        });
    }

    let now = current_unix_timestamp()?;
    let effective_time = definition.effective_time;
    let expiry_time = definition.expiry_time;
    let effective_ok = effective_time.is_none_or(|ts| now >= ts);
    let expiry_ok = expiry_time.is_none_or(|ts| now <= ts);
    let active = all_parties_accept && effective_ok && expiry_ok;

    let output = AgreementStatusOutput {
        stream: args.stream.clone(),
        agreement_id: hex::encode(definition.agreement_id.as_bytes()),
        version,
        effective_time,
        expiry_time,
        active,
        parties,
    };

    render_agreement_status(&output, use_json);
    log_cli_goal("CLI.MPA.STATUS");
    Ok(())
}

fn select_agreement_version(
    versions: &BTreeMap<u64, AgreementVersionFold>,
    requested: Option<u64>,
) -> Result<(u64, &AgreementVersionFold)> {
    if let Some(version) = requested {
        let state = versions.get(&version).ok_or_else(|| {
            ProtocolError::new(format!("no agreement entries found for version {version}"))
        })?;
        if state.definition.is_none() {
            bail_protocol!("agreement definition missing for version {version}");
        }
        return Ok((version, state));
    }

    for (&version, state) in versions.iter().rev() {
        if state.definition.is_some() {
            return Ok((version, state));
        }
    }

    bail_protocol!("no agreement definitions found in stream")
}

fn fold_agreement_versions<'a, I>(
    messages: I,
    target_id: &OpaqueId,
) -> Result<BTreeMap<u64, AgreementVersionFold>>
where
    I: IntoIterator<Item = &'a StoredMessage>,
{
    let mut versions = BTreeMap::new();
    let def_schema_hex = hex::encode(schema_agreement_definition());
    let conf_schema_hex = hex::encode(schema_agreement_confirmation());

    for message in messages {
        let schema_hex = match message.schema.as_deref() {
            Some(value) => value,
            None => continue,
        };
        if schema_hex.eq_ignore_ascii_case(&def_schema_hex) {
            let body = message.body.as_ref().ok_or_else(|| {
                ProtocolError::new(format!(
                    "stream {}#{} does not contain stored body for agreement definition",
                    message.stream, message.seq
                ))
            })?;
            let payload: AgreementDefinition = serde_json::from_str(body).with_context(|| {
                format!(
                    "decoding agreement.definition.v1 payload for {}#{}",
                    message.stream, message.seq
                )
            })?;
            if payload.agreement_id != *target_id {
                continue;
            }
            let entry = versions
                .entry(payload.version)
                .or_insert_with(AgreementVersionFold::default);
            entry.definition = Some((payload, message.seq));
        } else if schema_hex.eq_ignore_ascii_case(&conf_schema_hex) {
            let body = message.body.as_ref().ok_or_else(|| {
                ProtocolError::new(format!(
                    "stream {}#{} does not contain stored body for agreement confirmation",
                    message.stream, message.seq
                ))
            })?;
            let payload: AgreementConfirmation = serde_json::from_str(body).with_context(|| {
                format!(
                    "decoding agreement.confirmation.v1 payload for {}#{}",
                    message.stream, message.seq
                )
            })?;
            if payload.agreement_id != *target_id {
                continue;
            }
            let entry = versions
                .entry(payload.version)
                .or_insert_with(AgreementVersionFold::default);
            let identity_hex = hex::encode(payload.party_identity.as_bytes());
            let updated = AgreementPartyFold {
                decision: payload.decision,
                decision_time: payload.decision_time,
                seq: message.seq,
            };
            match entry.confirmations.entry(identity_hex) {
                Entry::Occupied(mut existing) => {
                    if message.seq >= existing.get().seq {
                        *existing.get_mut() = updated;
                    }
                }
                Entry::Vacant(slot) => {
                    slot.insert(updated);
                }
            }
        }
    }

    Ok(versions)
}

fn render_agreement_status(output: &AgreementStatusOutput, use_json: bool) {
    if use_json {
        match serde_json::to_string_pretty(output) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => match serde_json::to_string(output) {
                Ok(rendered) => println!("{rendered}"),
                Err(_) => println!("{{\"active\":false}}"),
            },
        }
        return;
    }

    println!("stream: {}", output.stream);
    println!("agreement_id: {}", output.agreement_id);
    println!("version: {}", output.version);
    match output.effective_time {
        Some(value) => println!("effective_time: {value}"),
        None => println!("effective_time: (none)"),
    }
    match output.expiry_time {
        Some(value) => println!("expiry_time: {value}"),
        None => println!("expiry_time: (none)"),
    }
    println!("active: {}", output.active);
    if output.parties.is_empty() {
        println!("parties: (none)");
        return;
    }
    println!("parties:");
    for party in &output.parties {
        println!("- identity: {}", party.identity);
        println!(
            "  decision: {}",
            party.decision.as_deref().unwrap_or("pending")
        );
        if let Some(ts) = party.decision_time {
            println!("  decision_time: {ts}");
        }
    }
}

async fn handle_recovery_timeline(args: RecoveryTimelineArgs) -> Result<()> {
    let target_identity = parse_principal_id_hex(&args.target_identity)?;
    let use_json = json_output_enabled(args.json);
    let reference = hub_reference_from_locator(&args.hub, "recovery timeline").await?;
    let (messages, _) = load_stream_messages(reference, &args.stream, 0).await?;
    let entries = build_recovery_timeline(&messages, &target_identity)?;
    let output = RecoveryTimelineOutput {
        stream: args.stream,
        target_identity: hex::encode(target_identity.as_bytes()),
        entries,
    };
    render_recovery_timeline(&output, use_json);
    log_cli_goal("CLI.RECOVERY.TIMELINE");
    Ok(())
}

fn build_recovery_timeline(
    messages: &[StoredMessage],
    target_identity: &PrincipalId,
) -> Result<Vec<RecoveryTimelineEntry>> {
    let request_schema = hex::encode(schema_recovery_request());
    let approval_schema = hex::encode(schema_recovery_approval());
    let execution_schema = hex::encode(schema_recovery_execution());
    let mut entries = Vec::new();

    for message in messages {
        let schema_hex = match message.schema.as_deref() {
            Some(value) => value,
            None => continue,
        };
        if schema_hex.eq_ignore_ascii_case(&request_schema) {
            let body = message.body.as_ref().ok_or_else(|| {
                ProtocolError::new(format!(
                    "stream {}#{} does not contain stored body for recovery request",
                    message.stream, message.seq
                ))
            })?;
            let payload: RecoveryRequest = serde_json::from_str(body).with_context(|| {
                format!(
                    "decoding recovery.request.v1 payload for {}#{}",
                    message.stream, message.seq
                )
            })?;
            if payload.target_identity != *target_identity {
                continue;
            }
            entries.push(RecoveryTimelineEntry {
                kind: RecoveryTimelineEntryKind::Request,
                stream_seq: message.seq,
                msg_id: hex::encode(compute_message_leaf_hash(message)?.as_bytes()),
                requested_new_identity: Some(hex::encode(
                    payload.requested_new_identity.as_bytes(),
                )),
                new_identity: None,
                approver_identity: None,
                decision: None,
            });
        } else if schema_hex.eq_ignore_ascii_case(&approval_schema) {
            let body = message.body.as_ref().ok_or_else(|| {
                ProtocolError::new(format!(
                    "stream {}#{} does not contain stored body for recovery approval",
                    message.stream, message.seq
                ))
            })?;
            let payload: RecoveryApproval = serde_json::from_str(body).with_context(|| {
                format!(
                    "decoding recovery.approval.v1 payload for {}#{}",
                    message.stream, message.seq
                )
            })?;
            if payload.target_identity != *target_identity {
                continue;
            }
            entries.push(RecoveryTimelineEntry {
                kind: RecoveryTimelineEntryKind::Approval,
                stream_seq: message.seq,
                msg_id: hex::encode(compute_message_leaf_hash(message)?.as_bytes()),
                requested_new_identity: Some(hex::encode(
                    payload.requested_new_identity.as_bytes(),
                )),
                new_identity: None,
                approver_identity: Some(hex::encode(payload.approver_identity.as_bytes())),
                decision: Some(payload.decision),
            });
        } else if schema_hex.eq_ignore_ascii_case(&execution_schema) {
            let body = message.body.as_ref().ok_or_else(|| {
                ProtocolError::new(format!(
                    "stream {}#{} does not contain stored body for recovery execution",
                    message.stream, message.seq
                ))
            })?;
            let payload: RecoveryExecution = serde_json::from_str(body).with_context(|| {
                format!(
                    "decoding recovery.execution.v1 payload for {}#{}",
                    message.stream, message.seq
                )
            })?;
            if payload.target_identity != *target_identity {
                continue;
            }
            entries.push(RecoveryTimelineEntry {
                kind: RecoveryTimelineEntryKind::Execution,
                stream_seq: message.seq,
                msg_id: hex::encode(compute_message_leaf_hash(message)?.as_bytes()),
                requested_new_identity: None,
                new_identity: Some(hex::encode(payload.new_identity.as_bytes())),
                approver_identity: None,
                decision: None,
            });
        }
    }

    Ok(entries)
}

#[derive(Debug, Clone, Serialize)]
struct RecoveryTimelineOutput {
    stream: String,
    target_identity: String,
    entries: Vec<RecoveryTimelineEntry>,
}

#[derive(Debug, Clone, Serialize)]
struct RecoveryTimelineEntry {
    kind: RecoveryTimelineEntryKind,
    stream_seq: u64,
    msg_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_new_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approver_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
enum RecoveryTimelineEntryKind {
    Request,
    Approval,
    Execution,
}

impl RecoveryTimelineEntryKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Approval => "approval",
            Self::Execution => "execution",
        }
    }
}

fn render_recovery_timeline(output: &RecoveryTimelineOutput, use_json: bool) {
    if use_json {
        match serde_json::to_string_pretty(output) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => match serde_json::to_string(output) {
                Ok(rendered) => println!("{rendered}"),
                Err(_) => println!("{{\"entries\":[]}}"),
            },
        }
        return;
    }

    println!("stream: {}", output.stream);
    println!("target_identity: {}", output.target_identity);
    if output.entries.is_empty() {
        println!("entries: (none)");
        return;
    }
    println!("entries:");
    for entry in &output.entries {
        println!("- type: {}", entry.kind.as_str());
        println!("  stream_seq: {}", entry.stream_seq);
        println!("  msg_id: {}", entry.msg_id);
        if let Some(ref requested) = entry.requested_new_identity {
            println!("  requested_new_identity: {}", requested);
        }
        if let Some(ref new_identity) = entry.new_identity {
            println!("  new_identity: {}", new_identity);
        }
        if let Some(ref approver) = entry.approver_identity {
            println!("  approver_identity: {}", approver);
        }
        if let Some(ref decision) = entry.decision {
            println!("  decision: {}", decision);
        }
    }
}

fn apply_balance_delta(
    balances: &mut BTreeMap<String, i128>,
    account: &AccountId,
    delta: i128,
    filter: Option<&AccountId>,
) -> Result<()> {
    if let Some(expected) = filter {
        if expected != account {
            return Ok(());
        }
    }

    let key = hex::encode(account.as_bytes());
    let entry = balances.entry(key.clone()).or_insert(0);
    *entry = entry
        .checked_add(delta)
        .ok_or_else(|| anyhow!("ledger balance overflow for account {}", key))?;
    Ok(())
}

async fn load_stream_messages(
    reference: HubReference,
    stream: &str,
    from_seq: u64,
) -> Result<(Vec<StoredMessage>, u64)> {
    match reference {
        HubReference::Local(data_dir) => {
            let stream_state = load_stream_state(&data_dir, stream).await?;
            let tip = stream_state.messages.last().map(|msg| msg.seq).unwrap_or(0);
            let messages = stream_state
                .messages
                .into_iter()
                .filter(|msg| msg.seq >= from_seq)
                .collect();
            Ok((messages, tip))
        }
        HubReference::Remote(client) => {
            let mut query: Vec<(&str, String)> = vec![("stream", stream.to_string())];
            if from_seq > 0 {
                query.push(("from", from_seq.to_string()));
            }
            let remote_messages: Vec<RemoteStoredMessage> = client
                .get_json("/stream", &query)
                .await
                .context("fetching stream messages")?;
            let tip = remote_messages
                .last()
                .map(|msg| msg.seq)
                .unwrap_or_else(|| from_seq.saturating_sub(1));
            let messages = remote_messages.into_iter().map(Into::into).collect();
            Ok((messages, tip))
        }
    }
}

async fn handle_operation_send(args: OperationSendArgs) -> Result<()> {
    let payload = build_generic_operation_payload(&args.schema_name, &args.body_json)?;
    submit_operation_payload(
        payload,
        OperationSubmissionOptions {
            hub: args.hub,
            client: args.client,
            stream: args.stream,
            cap: args.cap,
            expires_at: args.expires_at,
            parent: args.parent_id,
            use_json: json_output_enabled(args.json),
            context: "operation send",
            goal: "CLI.OP0.SEND",
        },
    )
    .await
}

async fn handle_operation_paid(args: OperationPaidArgs) -> Result<()> {
    let payload = build_paid_operation_payload(&args)?;
    submit_operation_payload(
        payload,
        OperationSubmissionOptions {
            hub: args.hub,
            client: args.client,
            stream: args.stream,
            cap: args.cap,
            expires_at: None,
            parent: None,
            use_json: json_output_enabled(args.json),
            context: "operation paid",
            goal: "CLI.OP0.PAID",
        },
    )
    .await
}

async fn handle_operation_access_grant(args: OperationAccessGrantArgs) -> Result<()> {
    let payload = build_access_grant_payload(&args)?;
    submit_operation_payload(
        payload,
        OperationSubmissionOptions {
            hub: args.hub,
            client: args.admin,
            stream: args.stream,
            cap: None,
            expires_at: None,
            parent: None,
            use_json: json_output_enabled(false),
            context: "operation access-grant",
            goal: "CLI.OP0.ACCESS_GRANT",
        },
    )
    .await
}

async fn handle_operation_access_revoke(args: OperationAccessRevokeArgs) -> Result<()> {
    let payload = build_access_revoke_payload(&args)?;
    submit_operation_payload(
        payload,
        OperationSubmissionOptions {
            hub: args.hub,
            client: args.admin,
            stream: args.stream,
            cap: None,
            expires_at: None,
            parent: None,
            use_json: json_output_enabled(false),
            context: "operation access-revoke",
            goal: "CLI.OP0.ACCESS_REVOKE",
        },
    )
    .await
}

async fn handle_operation_delegated(args: OperationDelegatedArgs) -> Result<()> {
    let payload = build_delegated_operation_payload(&args)?;
    submit_operation_payload(
        payload,
        OperationSubmissionOptions {
            hub: args.hub,
            client: args.client,
            stream: args.stream,
            cap: None,
            expires_at: None,
            parent: None,
            use_json: json_output_enabled(false),
            context: "operation delegated",
            goal: "CLI.OP0.DELEGATED",
        },
    )
    .await
}

async fn handle_operation_recovery_request(args: OperationRecoveryRequestArgs) -> Result<()> {
    let payload = build_recovery_request_payload(&args)?;
    submit_operation_payload(
        payload,
        OperationSubmissionOptions {
            hub: args.hub,
            client: args.client,
            stream: args.stream,
            cap: args.cap,
            expires_at: None,
            parent: None,
            use_json: json_output_enabled(args.json),
            context: "operation recovery-request",
            goal: "CLI.OP0.RECOVERY_REQUEST",
        },
    )
    .await
}

async fn handle_operation_recovery_approval(args: OperationRecoveryApprovalArgs) -> Result<()> {
    let payload = build_recovery_approval_payload(&args)?;
    submit_operation_payload(
        payload,
        OperationSubmissionOptions {
            hub: args.hub,
            client: args.client,
            stream: args.stream,
            cap: args.cap,
            expires_at: None,
            parent: None,
            use_json: json_output_enabled(args.json),
            context: "operation recovery-approval",
            goal: "CLI.OP0.RECOVERY_APPROVAL",
        },
    )
    .await
}

async fn handle_operation_recovery_execution(args: OperationRecoveryExecutionArgs) -> Result<()> {
    let payload = build_recovery_execution_payload(&args)?;
    submit_operation_payload(
        payload,
        OperationSubmissionOptions {
            hub: args.hub,
            client: args.client,
            stream: args.stream,
            cap: args.cap,
            expires_at: None,
            parent: None,
            use_json: json_output_enabled(args.json),
            context: "operation recovery-execution",
            goal: "CLI.OP0.RECOVERY_EXECUTION",
        },
    )
    .await
}

struct EncodedOperationPayload {
    schema_name: String,
    schema_id: [u8; 32],
    json_body: String,
    #[cfg_attr(not(test), allow(dead_code))]
    cbor_body: Vec<u8>,
}

impl EncodedOperationPayload {
    fn schema_hex(&self) -> String {
        hex::encode(self.schema_id)
    }
}

struct OperationSubmissionOptions {
    hub: HubLocatorArgs,
    client: PathBuf,
    stream: String,
    cap: Option<PathBuf>,
    expires_at: Option<u64>,
    parent: Option<String>,
    use_json: bool,
    context: &'static str,
    goal: &'static str,
}

struct OperationSubmissionResult {
    stream: String,
    seq: u64,
    receipt: StreamReceipt,
    operation_id: OperationId,
    schema_name: String,
    schema_hex: String,
}

async fn submit_operation_payload(
    payload: EncodedOperationPayload,
    options: OperationSubmissionOptions,
) -> Result<()> {
    let schema_hex = payload.schema_hex();
    let send_args = SendArgs {
        hub: options.hub,
        client: options.client,
        stream: options.stream.clone(),
        body: payload.json_body.clone(),
        schema: Some(schema_hex.clone()),
        expires_at: options.expires_at,
        cap: options.cap,
        parent: options.parent,
        attach: Vec::new(),
        no_store_body: false,
        pow_difficulty: None,
        pow_challenge: None,
        pow_nonce: None,
    };

    let reference = hub_reference_from_locator(&send_args.hub, options.context).await?;
    let outcome = send_message_with_reference(reference.clone(), send_args).await?;
    let submission =
        derive_operation_submission(reference, outcome, payload.schema_name, schema_hex).await?;
    render_operation_submission(&submission, options.use_json);
    log_cli_goal(options.goal);
    Ok(())
}

async fn derive_operation_submission(
    reference: HubReference,
    outcome: SendOutcome,
    schema_name: String,
    schema_hex: String,
) -> Result<OperationSubmissionResult> {
    let receipt = match (&reference, outcome.detail) {
        (HubReference::Local(_), SendOutcomeDetail::Local(detail)) => {
            let LocalSendDetail { receipt, .. } = *detail;
            receipt
        }
        (HubReference::Remote(client), SendOutcomeDetail::Remote(_)) => {
            fetch_remote_operation_receipt(client, &outcome.stream, outcome.seq).await?
        }
        (HubReference::Local(_), SendOutcomeDetail::Remote(_))
        | (HubReference::Remote(_), SendOutcomeDetail::Local(_)) => {
            bail_usage!("hub reference kind does not match send outcome")
        }
    };

    let operation_id = operation_id_from_receipt(&receipt)?;

    Ok(OperationSubmissionResult {
        stream: outcome.stream,
        seq: outcome.seq,
        receipt,
        operation_id,
        schema_name,
        schema_hex,
    })
}

fn render_operation_submission(result: &OperationSubmissionResult, use_json: bool) {
    if use_json {
        let output = json!({
            "ok": true,
            "stream": result.stream,
            "stream_seq": result.seq,
            "msg_id": result.receipt.leaf_hash,
            "operation_id": hex::encode(result.operation_id.as_bytes()),
            "schema_name": result.schema_name,
            "schema_id": result.schema_hex,
        });
        match serde_json::to_string_pretty(&output) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => println!("{output}"),
        }
        return;
    }

    println!("schema: {} ({})", result.schema_name, result.schema_hex);
    print_stream_receipt(&result.receipt);
    println!(
        "operation_id: {}",
        hex::encode(result.operation_id.as_bytes())
    );
}

async fn fetch_remote_operation_receipt(
    client: &HubHttpClient,
    stream: &str,
    seq: u64,
) -> Result<StreamReceipt> {
    let query = vec![
        ("stream", stream.to_string()),
        ("from", seq.to_string()),
        ("with_proof", "true".to_string()),
    ];
    let messages: Vec<RemoteStreamMessageWithProof> = client
        .get_json("/stream", &query)
        .await
        .context("fetching stream receipt")?;

    let entry = messages
        .into_iter()
        .find(|entry| entry.message.seq == seq)
        .ok_or_else(|| anyhow!("hub did not return receipt for {}#{}", stream, seq))?;

    let stored_message: StoredMessage = entry.message.into();
    let receipt = StreamReceipt::from(entry.receipt);
    let proof = entry
        .proof
        .clone()
        .try_into_mmr()
        .context("decoding stream proof")?;
    validate_stream_proof(&stored_message, &receipt, &proof)?;
    Ok(receipt)
}

fn operation_id_from_receipt(receipt: &StreamReceipt) -> Result<OperationId> {
    let leaf_bytes = hex::decode(&receipt.leaf_hash)
        .with_context(|| format!("decoding receipt leaf hash {}", receipt.leaf_hash))?;
    if leaf_bytes.len() != OPERATION_ID_LEN {
        bail_usage!(
            "receipt leaf hash must be {} bytes, found {}",
            OPERATION_ID_LEN,
            leaf_bytes.len()
        );
    }
    let mut msg_id = [0u8; OPERATION_ID_LEN];
    msg_id.copy_from_slice(&leaf_bytes);
    OperationId::derive(msg_id).map_err(|err| anyhow!("deriving operation_id: {err}"))
}

fn build_generic_operation_payload(
    schema_name: &str,
    body_json: &str,
) -> Result<EncodedOperationPayload> {
    let schema_id = resolve_operation_schema(schema_name)?;
    let json_value: JsonValue = serde_json::from_str(body_json)
        .map_err(|err| CliUsageError::new(format!("body-json must be valid JSON: {err}")))?;
    let cbor_value = json_value_to_cbor(&json_value)?;
    encode_operation_payload_from_values(schema_name.to_string(), schema_id, json_value, cbor_value)
}

fn build_paid_operation_payload(args: &OperationPaidArgs) -> Result<EncodedOperationPayload> {
    if args.operation_type.trim().is_empty() {
        bail_usage!("--op-type must not be empty");
    }
    let payer = parse_account_id_hex(&args.payer)?;
    let payee = parse_account_id_hex(&args.payee)?;
    let operation_args = parse_optional_json_to_cbor(args.operation_args.as_deref())?;
    let operation_reference = parse_optional_opaque_id(args.operation_reference.as_deref())?;
    let parent_operation_id = parse_optional_operation_id(args.parent_operation.as_deref())?;

    let payload = PaidOperation {
        operation_type: args.operation_type.clone(),
        operation_args,
        payer_account: payer,
        payee_account: payee,
        amount: args.amount,
        currency_code: Some(args.currency_code.clone()),
        operation_reference,
        parent_operation_id,
        ttl_seconds: args.ttl_seconds,
        metadata: None,
    };

    encode_struct_operation_payload("paid.operation.v1", schema_paid_operation(), &payload)
}

fn build_access_grant_payload(args: &OperationAccessGrantArgs) -> Result<EncodedOperationPayload> {
    let subject_identity = parse_principal_id_hex(&args.subject_identity)?;
    let allowed_stream_ids = parse_allowed_streams(args)?;
    let parent_operation_id = parse_optional_operation_id(args.parent_operation.as_deref())?;

    let payload = AccessGrant {
        subject_identity,
        subject_label: None,
        allowed_stream_ids,
        expiry_time: args.expiry_time,
        maximum_rate_per_second: args.max_rate_per_second,
        maximum_burst: args.max_burst,
        maximum_amount: args.max_amount,
        currency_code: args.currency_code.clone(),
        reason: args.reason.clone(),
        parent_operation_id,
    };

    encode_struct_operation_payload("access.grant.v1", schema_access_grant(), &payload)
}

fn build_access_revoke_payload(
    args: &OperationAccessRevokeArgs,
) -> Result<EncodedOperationPayload> {
    let subject_identity = parse_principal_id_hex(&args.subject_identity)?;
    let target_capability_reference =
        parse_optional_auth_ref(args.target_capability_reference.as_deref())?;
    let parent_operation_id = parse_optional_operation_id(args.parent_operation.as_deref())?;

    let payload = AccessRevoke {
        subject_identity,
        target_capability_reference,
        reason: args.reason.clone(),
        parent_operation_id,
    };

    encode_struct_operation_payload("access.revoke.v1", schema_access_revoke(), &payload)
}

fn build_delegated_operation_payload(
    args: &OperationDelegatedArgs,
) -> Result<EncodedOperationPayload> {
    if args.delegation_caps.is_empty() {
        bail_usage!("--delegation-cap must be provided at least once");
    }
    let principal_identity = parse_principal_id_hex(&args.principal)?;
    let agent_identity = parse_principal_id_hex(&args.agent)?;
    let delegation_chain = args
        .delegation_caps
        .iter()
        .map(|value| parse_auth_ref_hex(value))
        .collect::<Result<Vec<_>>>()?;
    let operation_schema = parse_schema_id_hex(&args.operation_schema_id)?;
    let operation_body = parse_json_string_to_cbor(&args.operation_body_json)?;
    let parent_operation_id = parse_optional_operation_id(args.parent_operation.as_deref())?;

    let payload = DelegatedExecution {
        principal_identity,
        agent_identity,
        delegation_chain,
        operation_schema,
        operation_body,
        parent_operation_id,
        metadata: None,
    };

    encode_struct_operation_payload(
        "delegated.execution.v1",
        schema_delegated_execution(),
        &payload,
    )
}

fn build_recovery_request_payload(
    args: &OperationRecoveryRequestArgs,
) -> Result<EncodedOperationPayload> {
    let target_identity = parse_principal_id_hex(&args.target_identity)?;
    let requested_new_identity = parse_principal_id_hex(&args.requested_new_identity)?;
    let metadata = parse_optional_json_value(args.metadata_json.as_deref())?;

    let payload = RecoveryRequest {
        target_identity,
        requested_new_identity,
        reason: args.reason.clone(),
        request_time: args.request_time,
        metadata,
    };

    encode_struct_operation_payload("recovery.request.v1", schema_recovery_request(), &payload)
}

fn build_recovery_approval_payload(
    args: &OperationRecoveryApprovalArgs,
) -> Result<EncodedOperationPayload> {
    if args.decision.trim().is_empty() {
        bail_usage!("--decision must not be empty");
    }
    let target_identity = parse_principal_id_hex(&args.target_identity)?;
    let requested_new_identity = parse_principal_id_hex(&args.requested_new_identity)?;
    let guardian_identity = parse_principal_id_hex(&args.guardian_identity)?;
    let policy_group_id = parse_optional_group_id_hex(args.policy_group_id.as_deref())?;
    let parent_operation_id = parse_optional_operation_id(args.parent_operation.as_deref())?;
    let metadata = parse_optional_json_value(args.metadata_json.as_deref())?;

    let payload = RecoveryApproval {
        target_identity,
        requested_new_identity,
        approver_identity: guardian_identity,
        policy_group_id,
        decision: args.decision.clone(),
        decision_time: args.decision_time,
        parent_operation_id,
        metadata,
    };

    encode_struct_operation_payload("recovery.approval.v1", schema_recovery_approval(), &payload)
}

fn build_recovery_execution_payload(
    args: &OperationRecoveryExecutionArgs,
) -> Result<EncodedOperationPayload> {
    let target_identity = parse_principal_id_hex(&args.target_identity)?;
    let new_identity = parse_principal_id_hex(&args.new_identity)?;
    let approval_references = parse_operation_id_list(&args.approval_references)?;
    let metadata = parse_optional_json_value(args.metadata_json.as_deref())?;

    let payload = RecoveryExecution {
        target_identity,
        new_identity,
        applied_time: args.applied_time,
        approval_references,
        metadata,
    };

    encode_struct_operation_payload(
        "recovery.execution.v1",
        schema_recovery_execution(),
        &payload,
    )
}

fn encode_struct_operation_payload<T>(
    schema_name: &str,
    schema_id: [u8; 32],
    payload: &T,
) -> Result<EncodedOperationPayload>
where
    T: Serialize,
{
    let json_body = serde_json::to_string(payload)
        .with_context(|| format!("encoding {schema_name} payload to JSON"))?;
    let mut cbor_body = Vec::new();
    ciborium::ser::into_writer(payload, &mut cbor_body)
        .map_err(|err| anyhow!("encoding {schema_name} payload to CBOR: {err}"))?;
    Ok(EncodedOperationPayload {
        schema_name: schema_name.to_string(),
        schema_id,
        json_body,
        cbor_body,
    })
}

fn encode_operation_payload_from_values(
    schema_name: String,
    schema_id: [u8; 32],
    json_value: JsonValue,
    cbor_value: CborValue,
) -> Result<EncodedOperationPayload> {
    let json_body = serde_json::to_string(&json_value)
        .with_context(|| format!("encoding {schema_name} body to JSON"))?;
    let mut cbor_body = Vec::new();
    ciborium::ser::into_writer(&cbor_value, &mut cbor_body)
        .map_err(|err| anyhow!("encoding {schema_name} body to CBOR: {err}"))?;
    Ok(EncodedOperationPayload {
        schema_name,
        schema_id,
        json_body,
        cbor_body,
    })
}

fn json_value_to_cbor(value: &JsonValue) -> Result<CborValue> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(value, &mut encoded)
        .context("encoding JSON value to CBOR for validation")?;
    let decoded = ciborium::de::from_reader(encoded.as_slice())
        .context("decoding intermediate CBOR value")?;
    Ok(decoded)
}

fn parse_optional_json_to_cbor(raw: Option<&str>) -> Result<CborValue> {
    match raw {
        Some(value) => parse_json_string_to_cbor(value),
        None => Ok(CborValue::Null),
    }
}

fn parse_optional_json_value(raw: Option<&str>) -> Result<Option<CborValue>> {
    match raw {
        Some(value) => {
            let parsed: JsonValue = serde_json::from_str(value).map_err(|err| {
                CliUsageError::new(format!("metadata-json must be valid JSON: {err}"))
            })?;
            let cbor_value = json_value_to_cbor(&parsed)?;
            Ok(Some(cbor_value))
        }
        None => Ok(None),
    }
}

fn parse_json_string_to_cbor(raw: &str) -> Result<CborValue> {
    let json_value: JsonValue = serde_json::from_str(raw)
        .map_err(|err| CliUsageError::new(format!("value must be valid JSON: {err}")))?;
    json_value_to_cbor(&json_value)
}

fn parse_account_id_hex(input: &str) -> Result<AccountId> {
    let bytes = parse_hex_key::<ACCOUNT_ID_LEN>(input)?;
    Ok(AccountId::from(bytes))
}

fn parse_principal_id_hex(input: &str) -> Result<PrincipalId> {
    let bytes = parse_hex_key::<{ HUB_ID_LEN }>(input)?;
    PrincipalId::from_slice(&bytes).map_err(|err| {
        anyhow!(CliUsageError::new(format!(
            "invalid principal id length: {err}"
        )))
    })
}

fn parse_group_id_hex(input: &str) -> Result<GroupId> {
    let bytes = parse_hex_key::<{ HUB_ID_LEN }>(input)?;
    GroupId::from_slice(&bytes).map_err(|err| {
        anyhow!(CliUsageError::new(format!(
            "invalid group id length: {err}"
        )))
    })
}

fn parse_optional_group_id_hex(input: Option<&str>) -> Result<Option<GroupId>> {
    input.map(parse_group_id_hex).transpose()
}

fn parse_auth_ref_hex(input: &str) -> Result<AuthRef> {
    let bytes = parse_hex_key::<{ SCHEMA_ID_LEN }>(input)?;
    AuthRef::from_slice(&bytes).map_err(|err| {
        anyhow!(CliUsageError::new(format!(
            "invalid auth_ref length: {err}"
        )))
    })
}

fn parse_opaque_id_hex(input: &str) -> Result<OpaqueId> {
    let bytes = parse_hex_key::<{ OPERATION_ID_LEN }>(input)?;
    OpaqueId::from_slice(&bytes).map_err(|err| {
        anyhow!(CliUsageError::new(format!(
            "invalid opaque id length: {err}"
        )))
    })
}

fn parse_operation_id_hex(input: &str) -> Result<OperationId> {
    let bytes = parse_hex_key::<{ OPERATION_ID_LEN }>(input)?;
    OperationId::from_slice(&bytes).map_err(|err| {
        anyhow!(CliUsageError::new(format!(
            "invalid operation id length: {err}"
        )))
    })
}

fn parse_operation_id_list(values: &[String]) -> Result<Vec<OperationId>> {
    if values.is_empty() {
        bail_usage!("--approval-ref must be provided at least once");
    }
    values
        .iter()
        .map(|value| parse_operation_id_hex(value))
        .collect()
}

fn parse_optional_operation_id(input: Option<&str>) -> Result<Option<OperationId>> {
    input.map(parse_operation_id_hex).transpose()
}

fn parse_optional_opaque_id(input: Option<&str>) -> Result<Option<OpaqueId>> {
    input.map(parse_opaque_id_hex).transpose()
}

fn parse_optional_auth_ref(input: Option<&str>) -> Result<Option<AuthRef>> {
    input.map(parse_auth_ref_hex).transpose()
}

fn parse_stream_id_hex(input: &str) -> Result<StreamId> {
    let bytes = parse_hex_key::<{ STREAM_ID_LEN }>(input)?;
    StreamId::from_slice(&bytes).map_err(|err| {
        anyhow!(CliUsageError::new(format!(
            "invalid stream id length: {err}"
        )))
    })
}

fn parse_allowed_streams(args: &OperationAccessGrantArgs) -> Result<Vec<StreamId>> {
    if args.allowed_streams.is_empty() {
        let derived = cap_stream_id_from_label(&args.stream)
            .with_context(|| format!("deriving stream identifier for {}", args.stream))?;
        return Ok(vec![derived]);
    }

    args.allowed_streams
        .iter()
        .map(|value| parse_stream_id_hex(value))
        .collect()
}

fn resolve_operation_schema(name: &str) -> Result<[u8; 32]> {
    let schema = match name {
        "paid.operation.v1" => schema_paid_operation(),
        "access.grant.v1" => schema_access_grant(),
        "access.revoke.v1" => schema_access_revoke(),
        "delegated.execution.v1" => schema_delegated_execution(),
        "agreement.definition.v1" => schema_agreement_definition(),
        "agreement.confirmation.v1" => schema_agreement_confirmation(),
        "data.publication.v1" => schema_data_publication(),
        "state.checkpoint.v1" => schema_state_checkpoint(),
        "recovery.request.v1" => schema_recovery_request(),
        "recovery.approval.v1" => schema_recovery_approval(),
        "recovery.execution.v1" => schema_recovery_execution(),
        "query.audit.v1" => schema_query_audit(),
        "federation.mirror.v1" => schema_federation_mirror(),
        other => {
            bail_usage!("unknown operation schema `{other}`")
        }
    };
    Ok(schema)
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
    match hub_reference_from_locator(&args.hub, "revoke publish").await? {
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
    match hub_reference_from_locator(&args.hub, "resync").await? {
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

async fn handle_snapshot_verify(args: SnapshotVerifyArgs) -> Result<()> {
    if args.upto_stream_seq == 0 {
        bail_usage!("--upto-stream-seq must be at least 1");
    }
    let state_class_filter = args.state_class.trim();
    if state_class_filter.is_empty() {
        bail_usage!("--state-class must not be empty");
    }

    let state_id = parse_opaque_id_hex(&args.state_id)?;
    let state_id_hex = hex::encode(state_id.as_bytes());
    let use_json = json_output_enabled(args.json);

    let reference = hub_reference_from_locator(&args.hub, "snapshot verify").await?;
    let (messages, stream_tip) = load_stream_messages(reference, &args.stream, 0).await?;
    if stream_tip < args.upto_stream_seq {
        bail_usage!(
            "stream {} only has seq {}, cannot verify upto {}",
            args.stream,
            stream_tip,
            args.upto_stream_seq
        );
    }

    let checkpoint_match = find_state_checkpoint(
        &messages,
        &state_id,
        args.upto_stream_seq,
        state_class_filter,
    )?;
    let (checkpoint_seq, checkpoint) = checkpoint_match.ok_or_else(|| {
        ProtocolError::new(format!(
            "no state.checkpoint.v1 found for state_id {} upto_stream_seq {}",
            state_id_hex, args.upto_stream_seq
        ))
    })?;
    let canonical_state_class = checkpoint.state_class.clone();

    let (serialized_state, state_json, wallet_state_summary) = match canonical_state_class.as_str()
    {
        "wallet.ledger" => {
            let account = AccountId::from_slice(state_id.as_bytes()).map_err(|err| {
                CliUsageError::new(format!(
                    "state-id must be a valid account id for wallet.ledger snapshots: {err}"
                ))
            })?;
            let summary = fold_wallet_ledger_snapshot(&messages, args.upto_stream_seq, &account)?;
            let json_value = serde_json::to_value(&summary)
                .context("serializing wallet ledger snapshot state")?;
            let serialized = summary.serialize_bytes()?;
            (serialized, Some(json_value), Some(summary))
        }
        other => {
            bail_usage!("unsupported state class `{other}`");
        }
    };

    let computed_state_hash = ht(
        &format!("veen/state-{}", canonical_state_class),
        &serialized_state,
    );
    let computed_state_hash_hex = hex::encode(computed_state_hash);
    let checkpoint_state_hash_hex = hex::encode(checkpoint.state_hash.as_bytes());

    let computed_mmr_root = compute_stream_prefix_mmr_root(&messages, args.upto_stream_seq)?;
    let computed_mmr_root_hex = hex::encode(computed_mmr_root.as_bytes());
    let checkpoint_mmr_root_hex = hex::encode(checkpoint.mmr_root.as_bytes());

    let mismatch_detail = if computed_mmr_root_hex != checkpoint_mmr_root_hex {
        Some(format!(
            "mmr_root mismatch (checkpoint={}, computed={})",
            checkpoint_mmr_root_hex, computed_mmr_root_hex
        ))
    } else if computed_state_hash_hex != checkpoint_state_hash_hex {
        Some(format!(
            "state_hash mismatch (checkpoint={}, computed={})",
            checkpoint_state_hash_hex, computed_state_hash_hex
        ))
    } else {
        None
    };

    let output = SnapshotVerifyOutput {
        stream: args.stream.clone(),
        state_class: canonical_state_class,
        state_id: state_id_hex,
        upto_stream_seq: args.upto_stream_seq,
        checkpoint_seq,
        consistent: mismatch_detail.is_none(),
        mismatch: mismatch_detail,
        checkpoint_state_hash: checkpoint_state_hash_hex,
        computed_state_hash: computed_state_hash_hex,
        checkpoint_mmr_root: checkpoint_mmr_root_hex,
        computed_mmr_root: computed_mmr_root_hex,
        state: state_json,
    };

    render_snapshot_verify(&output, wallet_state_summary.as_ref(), use_json)?;
    log_cli_goal("CLI.SNAPSHOT.VERIFY");
    Ok(())
}

#[derive(Serialize)]
struct SnapshotVerifyOutput {
    stream: String,
    state_class: String,
    state_id: String,
    upto_stream_seq: u64,
    checkpoint_seq: u64,
    consistent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mismatch: Option<String>,
    checkpoint_state_hash: String,
    computed_state_hash: String,
    checkpoint_mmr_root: String,
    computed_mmr_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<JsonValue>,
}

fn render_snapshot_verify(
    output: &SnapshotVerifyOutput,
    wallet_state: Option<&WalletLedgerSnapshotState>,
    use_json: bool,
) -> Result<()> {
    if use_json {
        match serde_json::to_string_pretty(output) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => match serde_json::to_string(output) {
                Ok(rendered) => println!("{rendered}"),
                Err(_) => println!("{{\"consistent\":false}}"),
            },
        }
        return Ok(());
    }

    println!("stream: {}", output.stream);
    println!("state_class: {}", output.state_class);
    println!("state_id: {}", output.state_id);
    println!("upto_stream_seq: {}", output.upto_stream_seq);
    println!("checkpoint_seq: {}", output.checkpoint_seq);
    println!("consistent: {}", output.consistent);
    if let Some(mismatch) = &output.mismatch {
        println!("mismatch: {mismatch}");
    }
    println!("checkpoint.state_hash: {}", output.checkpoint_state_hash);
    println!("computed.state_hash: {}", output.computed_state_hash);
    println!("checkpoint.mmr_root: {}", output.checkpoint_mmr_root);
    println!("computed.mmr_root: {}", output.computed_mmr_root);
    if let Some(state) = wallet_state {
        println!("wallet.account_id: {}", state.account_id);
        println!("wallet.balance: {}", state.balance);
    }
    Ok(())
}

fn find_state_checkpoint<'a, I>(
    messages: I,
    state_id: &OpaqueId,
    upto_stream_seq: u64,
    state_class: &str,
) -> Result<Option<(u64, StateCheckpoint)>>
where
    I: IntoIterator<Item = &'a StoredMessage>,
{
    let checkpoint_schema_hex = hex::encode(schema_state_checkpoint());
    let mut found: Option<(u64, StateCheckpoint)> = None;
    for message in messages {
        let Some(schema_hex) = message.schema.as_deref() else {
            continue;
        };
        if !schema_hex.eq_ignore_ascii_case(&checkpoint_schema_hex) {
            continue;
        }
        let body = message.body.as_ref().ok_or_else(|| {
            ProtocolError::new(format!(
                "stream {}#{} does not contain stored body for state checkpoint",
                message.stream, message.seq
            ))
        })?;
        let checkpoint: StateCheckpoint = serde_json::from_str(body).with_context(|| {
            format!(
                "decoding state.checkpoint.v1 payload for {}#{}",
                message.stream, message.seq
            )
        })?;
        if checkpoint.upto_stream_seq != upto_stream_seq {
            continue;
        }
        if checkpoint.state_id.as_bytes() != state_id.as_bytes() {
            continue;
        }
        if !checkpoint.state_class.eq_ignore_ascii_case(state_class) {
            continue;
        }
        found = Some((message.seq, checkpoint));
    }
    Ok(found)
}

#[derive(Debug, Clone, Serialize)]
struct WalletLedgerSnapshotState {
    account_id: String,
    balance: i128,
}

impl WalletLedgerSnapshotState {
    fn new(account: &AccountId, balance: i128) -> Self {
        Self {
            account_id: hex::encode(account.as_bytes()),
            balance,
        }
    }

    fn serialize_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("serializing wallet ledger snapshot state")
    }
}

fn fold_wallet_ledger_snapshot<'a, I>(
    messages: I,
    upto_stream_seq: u64,
    account: &AccountId,
) -> Result<WalletLedgerSnapshotState>
where
    I: IntoIterator<Item = &'a StoredMessage>,
{
    let schema_hex = hex::encode(schema_paid_operation());
    let mut balance: i128 = 0;
    let account_hex = hex::encode(account.as_bytes());
    for message in messages {
        if message.seq > upto_stream_seq {
            break;
        }
        let Some(current_schema) = message.schema.as_deref() else {
            continue;
        };
        if !current_schema.eq_ignore_ascii_case(&schema_hex) {
            continue;
        }
        let body = message.body.as_ref().ok_or_else(|| {
            ProtocolError::new(format!(
                "stream {}#{} does not contain stored body for paid operation",
                message.stream, message.seq
            ))
        })?;
        let payload: PaidOperation = serde_json::from_str(body).with_context(|| {
            format!(
                "decoding paid.operation.v1 payload for {}#{}",
                message.stream, message.seq
            )
        })?;
        let amount = payload.amount as i128;
        if payload.payer_account.as_bytes() == account.as_bytes() {
            balance = balance
                .checked_sub(amount)
                .ok_or_else(|| anyhow!("ledger balance underflow for account {}", account_hex))?;
        }
        if payload.payee_account.as_bytes() == account.as_bytes() {
            balance = balance
                .checked_add(amount)
                .ok_or_else(|| anyhow!("ledger balance overflow for account {}", account_hex))?;
        }
    }
    Ok(WalletLedgerSnapshotState::new(account, balance))
}

fn compute_stream_prefix_mmr_root<'a, I>(messages: I, upto_stream_seq: u64) -> Result<MmrRoot>
where
    I: IntoIterator<Item = &'a StoredMessage>,
{
    let mut mmr = Mmr::new();
    let mut last_seq = 0;
    let mut last_root: Option<MmrRoot> = None;
    for message in messages {
        if message.seq > upto_stream_seq {
            break;
        }
        let leaf = compute_message_leaf_hash(message)?;
        let (seq, root) = mmr.append(leaf);
        last_seq = seq;
        last_root = Some(root);
    }

    if last_seq == 0 {
        bail_protocol!(
            "no messages available to compute mmr_root for upto seq {}",
            upto_stream_seq
        );
    }
    if last_seq != upto_stream_seq {
        bail_protocol!(
            "stream data missing message {} required for snapshot (last folded seq {})",
            upto_stream_seq,
            last_seq
        );
    }

    if let Some(root) = last_root {
        Ok(root)
    } else {
        bail_protocol!(
            "missing mmr root after folding upto seq {}",
            upto_stream_seq
        );
    }
}

async fn handle_verify_state(args: VerifyStateArgs) -> Result<()> {
    let hub = hub_reference_from_locator(&args.hub, "verify-state").await?;
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
        pow_difficulty: args.pow_difficulty,
        pow_challenge: args.pow_challenge,
        pow_nonce: args.pow_nonce,
    };

    let result = handle_send(send_args).await;
    if result.is_ok() {
        log_cli_goal("CLI.RPC0.CALL");
    }
    result
}

async fn handle_crdt_lww_set(args: CrdtLwwSetArgs) -> Result<()> {
    let data_dir = hub_reference_from_locator(&args.hub, "crdt lww set")
        .await?
        .into_local()?;
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
    let data_dir = hub_reference_from_locator(&args.hub, "crdt lww get")
        .await?
        .into_local()?;
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
    let data_dir = hub_reference_from_locator(&args.hub, "crdt orset add")
        .await?
        .into_local()?;
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
    let data_dir = hub_reference_from_locator(&args.hub, "crdt orset remove")
        .await?
        .into_local()?;
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
    let data_dir = hub_reference_from_locator(&args.hub, "crdt orset list")
        .await?
        .into_local()?;
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
    let data_dir = hub_reference_from_locator(&args.hub, "crdt counter add")
        .await?
        .into_local()?;
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
    let data_dir = hub_reference_from_locator(&args.hub, "crdt counter get")
        .await?
        .into_local()?;
    ensure_client_label_exists(&args.client, &args.stream).await?;
    let state = load_counter_state(&data_dir, &args.stream).await?;
    println!("counter value={}", state.value);
    log_cli_goal("CLI.CRDT0.COUNTER_GET");
    Ok(())
}

async fn handle_anchor_publish(args: AnchorPublishArgs) -> Result<()> {
    match hub_reference_from_locator(&args.hub, "anchor publish").await? {
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

fn retention_value_to_json(value: RetentionValue) -> JsonValue {
    match value {
        RetentionValue::Indefinite => JsonValue::String("indefinite".to_string()),
        RetentionValue::Seconds(value) => JsonValue::Number(value.into()),
    }
}

async fn handle_retention_set(args: RetentionSetArgs) -> Result<()> {
    let retention_path = args.data_dir.join(STATE_DIR).join(RETENTION_CONFIG_FILE);
    let mut retention = if fs::try_exists(&retention_path)
        .await
        .with_context(|| format!("checking retention config {}", retention_path.display()))?
    {
        read_json_file(&retention_path).await?
    } else {
        JsonValue::Object(JsonMap::new())
    };

    let map = retention.as_object_mut().ok_or_else(|| {
        CliUsageError::new(format!(
            "existing retention config at {} is not a JSON object",
            retention_path.display()
        ))
    })?;

    if let Some(value) = args.receipts {
        map.insert("receipts".to_string(), retention_value_to_json(value));
    }
    if let Some(value) = args.payloads {
        map.insert("payloads".to_string(), retention_value_to_json(value));
    }
    if let Some(value) = args.checkpoints {
        map.insert("checkpoints".to_string(), retention_value_to_json(value));
    }

    if map.is_empty() {
        return Err(anyhow!(CliUsageError::new(
            "no retention values provided; nothing to update".to_string()
        )));
    }

    write_json_file(&retention_path, &retention).await?;
    println!(
        "updated retention configuration at {}",
        retention_path.display()
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&retention).context("formatting retention configuration")?
    );

    log_cli_goal("CLI.COMP0.RETENTION_SET");
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

#[derive(Clone, Copy)]
enum SelftestSuite {
    Core,
    Props,
    Fuzz,
    All,
    Federated,
    Kex1,
    Hardened,
    Meta,
    Recorder,
    Plus,
    PlusPlus,
}

impl SelftestSuite {
    fn name(self) -> &'static str {
        match self {
            SelftestSuite::Core => "core",
            SelftestSuite::Props => "props",
            SelftestSuite::Fuzz => "fuzz",
            SelftestSuite::All => "all",
            SelftestSuite::Federated => "federated",
            SelftestSuite::Kex1 => "kex1",
            SelftestSuite::Hardened => "hardened",
            SelftestSuite::Meta => "meta",
            SelftestSuite::Recorder => "recorder",
            SelftestSuite::Plus => "plus",
            SelftestSuite::PlusPlus => "plus-plus",
        }
    }
}

const SELFTEST_STUB_ENV: &str = "VEEN_SELFTEST_STUB";
const SELFTEST_STUB_FILE_ENV: &str = "VEEN_SELFTEST_STUB_FILE";

fn selftest_stub_enabled() -> bool {
    env::var_os(SELFTEST_STUB_ENV).is_some()
}

fn record_selftest_stub_marker(suite: SelftestSuite) -> Result<()> {
    if selftest_stub_enabled() {
        let name = suite.name();
        if let Some(path) = env::var_os(SELFTEST_STUB_FILE_ENV) {
            let mut file = StdOpenOptions::new()
                .create(true)
                .append(true)
                .open(PathBuf::from(path))
                .with_context(|| format!("opening selftest stub file for {name}"))?;
            writeln!(&mut file, "{name}").context("writing selftest stub marker")?;
        }
        println!("stubbed selftest suite: {name}");
    }
    Ok(())
}

fn emit_selftest_report(suite: SelftestSuite, report: &veen_selftest::SelftestReport) {
    println!();
    println!("self-test suite {} report:", suite.name());
    if report.is_empty() {
        println!("  (no self-test entries recorded)");
    } else {
        println!("{report}");
    }
}

async fn handle_env_init(args: EnvInitArgs) -> Result<()> {
    ensure_non_empty_field(&args.name, "name")?;
    ensure_non_empty_field(&args.cluster_context, "cluster-context")?;
    ensure_non_empty_field(&args.namespace, "namespace")?;
    if args.name.contains('/') || args.name.contains("\\") {
        bail_usage!("environment name must not contain path separators");
    }

    fs::create_dir_all(&args.root)
        .await
        .with_context(|| format!("creating {}", args.root.display()))?;
    let path = env_descriptor_path(&args.root, &args.name);
    ensure_absent(&path).await?;

    let descriptor = EnvDescriptor {
        version: ENV_DESCRIPTOR_VERSION,
        name: args.name,
        cluster_context: args.cluster_context,
        namespace: args.namespace,
        description: args.description,
        hubs: BTreeMap::new(),
        tenants: BTreeMap::new(),
    };
    write_env_descriptor(&path, &descriptor).await?;
    println!("wrote {}", path.display());
    Ok(())
}

async fn handle_env_add_hub(args: EnvAddHubArgs) -> Result<()> {
    ensure_non_empty_field(&args.hub_name, "hub-name")?;
    ensure_non_empty_field(&args.service_url, "service-url")?;
    let mut descriptor = read_env_descriptor(&args.env).await?;
    let profile_id = normalize_hex32_field(&args.profile_id, "profile-id")?;
    let realm_id = match args.realm {
        Some(ref value) => Some(normalize_hex32_field(value, "realm")?),
        None => None,
    };

    descriptor.hubs.insert(
        args.hub_name.clone(),
        EnvHubDescriptor {
            service_url: args.service_url.clone(),
            profile_id,
            realm_id,
        },
    );
    write_env_descriptor(&args.env, &descriptor).await?;
    println!("recorded hub `{}` in {}", args.hub_name, args.env.display());
    Ok(())
}

async fn handle_env_add_tenant(args: EnvAddTenantArgs) -> Result<()> {
    ensure_non_empty_field(&args.tenant_id, "tenant-id")?;
    ensure_non_empty_field(&args.stream_prefix, "stream-prefix")?;
    let mut descriptor = read_env_descriptor(&args.env).await?;
    let label_class = args
        .label_class
        .as_ref()
        .map(EnvTenantLabelClass::as_str)
        .unwrap_or("user")
        .to_string();

    descriptor.tenants.insert(
        args.tenant_id.clone(),
        EnvTenantDescriptor {
            stream_prefix: args.stream_prefix.clone(),
            label_class,
        },
    );
    write_env_descriptor(&args.env, &descriptor).await?;
    println!(
        "recorded tenant `{}` in {}",
        args.tenant_id,
        args.env.display()
    );
    Ok(())
}

async fn handle_env_show(args: EnvShowArgs) -> Result<()> {
    let descriptor = read_env_descriptor(&args.env).await?;
    if json_output_enabled(args.json) {
        let json = serde_json::to_string_pretty(&descriptor)
            .with_context(|| format!("serialising {}", args.env.display()))?;
        println!("{json}");
    } else {
        render_env_descriptor_summary(&descriptor);
    }
    Ok(())
}

async fn handle_audit_queries(args: AuditQueriesArgs) -> Result<()> {
    let reference = hub_reference_from_locator(&args.hub, "audit queries").await?;
    let use_json = json_output_enabled(args.json);
    let messages = fetch_stream_messages(&reference, &args.stream).await?;
    let mut rows = Vec::new();
    for message in messages {
        if !message_schema_matches(&message, schema_query_audit()) {
            continue;
        }
        let payload: QueryAuditLog = parse_message_payload(&message)?;
        if let Some(prefix) = &args.resource_prefix {
            if !payload.resource_identifier.starts_with(prefix) {
                continue;
            }
        }
        let request_time = payload.request_time.unwrap_or(message.sent_at);
        if let Some(since) = args.since {
            if request_time < since {
                continue;
            }
        }
        rows.push(AuditQueryRow {
            requester_identity: hex::encode(payload.requester_identity.as_ref()),
            resource_identifier: payload.resource_identifier,
            resource_class: payload.resource_class,
            purpose_code: payload.purpose_code,
            request_time,
        });
    }
    rows.sort_by_key(|row| row.request_time);
    render_audit_query_rows(&rows, use_json);
    log_cli_goal("CLI.AUDIT.QUERIES");
    Ok(())
}

async fn handle_audit_summary(args: AuditSummaryArgs) -> Result<()> {
    let reference = hub_reference_from_locator(&args.hub, "audit summary").await?;
    let use_json = json_output_enabled(args.json);
    let env_descriptor = match args.env {
        Some(path) => Some(read_env_descriptor(&path).await?),
        None => None,
    };
    let env_stream_classes = env_descriptor.as_ref().map(|descriptor| {
        descriptor
            .tenants
            .values()
            .map(|tenant| (tenant.stream_prefix.clone(), tenant.label_class.clone()))
            .collect::<BTreeMap<_, _>>()
    });
    let mut stream_inventory = gather_stream_inventory(&reference).await?;
    let mut stream_names: BTreeSet<String> = stream_inventory.keys().cloned().collect();
    if let Some(env_map) = &env_stream_classes {
        stream_names.extend(env_map.keys().cloned());
    }
    if stream_names.is_empty() {
        stream_names.extend(env_descriptor.iter().flat_map(|descriptor| {
            descriptor
                .tenants
                .values()
                .map(|tenant| tenant.stream_prefix.clone())
        }));
    }
    let mut summaries = Vec::new();
    let mut label_class_state = match &reference {
        HubReference::Remote(_) => LabelClassEndpointState::Unknown,
        _ => LabelClassEndpointState::Unsupported,
    };
    for stream in stream_names {
        let messages = fetch_stream_messages(&reference, &stream).await?;
        let mut schema_names = BTreeSet::new();
        let mut has_query_audit = false;
        let mut has_access_grant = false;
        let mut has_access_revoke = false;
        for message in &messages {
            if let Some(schema_id) = schema_id_from_message(message) {
                if let Some(name) = schema_name_from_id(schema_id) {
                    schema_names.insert(name.to_string());
                } else if let Some(hex) = &message.schema {
                    schema_names.insert(hex.clone());
                }
                if schema_id == schema_query_audit() {
                    has_query_audit = true;
                }
                if schema_id == schema_access_grant() {
                    has_access_grant = true;
                }
                if schema_id == schema_access_revoke() {
                    has_access_revoke = true;
                }
            }
        }
        let mut label_class = env_stream_classes
            .as_ref()
            .and_then(|map| map.get(&stream).cloned());
        let mut sensitivity = None;
        if let HubReference::Remote(client) = &reference {
            if !matches!(label_class_state, LabelClassEndpointState::Unsupported) {
                match fetch_stream_label_class(client, &stream).await {
                    Ok(Some(info)) => {
                        label_class_state = LabelClassEndpointState::Supported;
                        if let Some(class) = info.class {
                            label_class = Some(class);
                        }
                        sensitivity = info.sensitivity;
                    }
                    Ok(None) => {
                        label_class_state = LabelClassEndpointState::Supported;
                    }
                    Err(LabelClassFetchError::Unsupported) => {
                        label_class_state = LabelClassEndpointState::Unsupported;
                    }
                    Err(LabelClassFetchError::Other(err)) => return Err(err),
                }
            }
        }
        let audit_required =
            classification_is_sensitive(label_class.as_deref(), sensitivity.as_deref());
        summaries.push(AuditStreamSummaryRow {
            stream: stream.clone(),
            last_seq: stream_inventory.remove(&stream),
            label_class,
            sensitivity,
            schemas: schema_names.into_iter().collect(),
            has_query_audit,
            has_access_grant,
            has_access_revoke,
            audit_required,
            missing_required_audit: audit_required && !has_query_audit,
        });
    }
    summaries.sort_by(|a, b| a.stream.cmp(&b.stream));
    render_audit_summary(&summaries, use_json);
    log_cli_goal("CLI.AUDIT.SUMMARY");
    Ok(())
}

async fn handle_audit_enforce_check(args: AuditEnforceCheckArgs) -> Result<()> {
    if args.policy_files.is_empty() {
        bail_usage!("--policy-file must be provided at least once");
    }
    let reference = hub_reference_from_locator(&args.hub, "audit enforce-check").await?;
    let use_json = json_output_enabled(args.json);
    let mut documents = Vec::new();
    for path in &args.policy_files {
        let document: AuditPolicyDocument = read_json_file(path).await?;
        if document.version != 1 {
            bail_usage!(
                "unsupported policy version {} in {} (expected 1)",
                document.version,
                path.display()
            );
        }
        documents.push(document);
    }
    let mut rules = Vec::new();
    for document in documents {
        rules.extend(document.rules);
    }
    let stream_inventory = gather_stream_inventory(&reference).await?;
    let mut streams_to_scan: BTreeSet<String> = stream_inventory.keys().cloned().collect();
    for rule in &rules {
        if let AuditPolicyRule::RequireAudit { stream, .. } = rule {
            streams_to_scan.insert(stream.clone());
        }
    }
    let mut cache = StreamMessageCache::new(reference);
    let mut violations = Vec::new();
    let mut recovery_events = Vec::new();
    let needs_recovery = rules
        .iter()
        .any(|rule| matches!(rule, AuditPolicyRule::RequireRecoveryThreshold { .. }));
    if needs_recovery {
        recovery_events = collect_recovery_execution_events(&streams_to_scan, &mut cache).await?;
    }
    for rule in &rules {
        match rule {
            AuditPolicyRule::RequireAudit {
                stream,
                resource_class,
            } => {
                let messages = cache.messages(stream).await?;
                let mut found = false;
                for message in messages {
                    if !message_schema_matches(message, schema_query_audit()) {
                        continue;
                    }
                    let payload: QueryAuditLog = parse_message_payload(message)?;
                    if payload.resource_class == *resource_class {
                        found = true;
                        break;
                    }
                }
                if !found {
                    violations.push(format!(
                        "stream `{}` missing query.audit.v1 events for resource_class `{}`",
                        stream, resource_class
                    ));
                }
            }
            AuditPolicyRule::RequireRecoveryThreshold {
                target_identity_prefix,
                min_approvals,
            } => {
                let prefix = target_identity_prefix.to_ascii_lowercase();
                for event in &recovery_events {
                    if !event.target_identity_hex.starts_with(&prefix) {
                        continue;
                    }
                    let approvals = event.approval_count as u64;
                    if approvals < *min_approvals {
                        violations.push(format!(
                            "recovery.execution.v1 on stream `{}` seq {} has {approvals} approvals (expected >= {min_approvals})",
                            event.stream, event.seq
                        ));
                    }
                }
            }
        }
    }
    render_policy_check(&violations, use_json);
    if violations.is_empty() {
        log_cli_goal("CLI.AUDIT.ENFORCE");
        Ok(())
    } else {
        Err(anyhow::Error::new(AuditPolicyViolationError::new(
            violations,
        )))
    }
}

fn handle_selftest_stub(suite: SelftestSuite) -> Result<bool> {
    if selftest_stub_enabled() {
        record_selftest_stub_marker(suite)?;
        return Ok(true);
    }
    Ok(false)
}

#[derive(Debug, Clone)]
struct AuditQueryRow {
    requester_identity: String,
    resource_identifier: String,
    resource_class: String,
    purpose_code: Option<String>,
    request_time: u64,
}

#[derive(Debug, Clone)]
struct AuditStreamSummaryRow {
    stream: String,
    last_seq: Option<u64>,
    label_class: Option<String>,
    sensitivity: Option<String>,
    schemas: Vec<String>,
    has_query_audit: bool,
    has_access_grant: bool,
    has_access_revoke: bool,
    audit_required: bool,
    missing_required_audit: bool,
}

#[derive(Debug, Deserialize)]
struct AuditPolicyDocument {
    version: u64,
    rules: Vec<AuditPolicyRule>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum AuditPolicyRule {
    #[serde(rename = "require_audit")]
    RequireAudit {
        stream: String,
        resource_class: String,
    },
    #[serde(rename = "require_recovery_threshold")]
    RequireRecoveryThreshold {
        target_identity_prefix: String,
        min_approvals: u64,
    },
}

#[derive(Debug, Clone)]
struct LabelClassInfo {
    class: Option<String>,
    sensitivity: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LabelClassEndpointState {
    Unknown,
    Supported,
    Unsupported,
}

enum LabelClassFetchError {
    Unsupported,
    Other(anyhow::Error),
}

#[derive(Debug, Clone)]
struct RecoveryExecutionEvent {
    stream: String,
    seq: u64,
    target_identity_hex: String,
    approval_count: usize,
}

struct StreamMessageCache {
    reference: HubReference,
    cache: BTreeMap<String, Vec<StoredMessage>>,
}

impl StreamMessageCache {
    fn new(reference: HubReference) -> Self {
        Self {
            reference,
            cache: BTreeMap::new(),
        }
    }

    async fn messages(&mut self, stream: &str) -> Result<&[StoredMessage]> {
        if !self.cache.contains_key(stream) {
            let messages = fetch_stream_messages(&self.reference, stream).await?;
            self.cache.insert(stream.to_string(), messages);
        }
        Ok(self
            .cache
            .get(stream)
            .map(|messages| messages.as_slice())
            .expect("stream cache entry present"))
    }
}

fn render_audit_query_rows(rows: &[AuditQueryRow], use_json: bool) {
    if use_json {
        let payload: Vec<JsonValue> = rows
            .iter()
            .map(|row| {
                json!({
                    "requester_identity": row.requester_identity.clone(),
                    "resource_identifier": row.resource_identifier.clone(),
                    "resource_class": row.resource_class.clone(),
                    "purpose_code": row.purpose_code.clone(),
                    "request_time": row.request_time,
                })
            })
            .collect();
        let output = json!({ "ok": true, "rows": payload });
        println!("{}", pretty_json(output));
        return;
    }

    if rows.is_empty() {
        println!("no query audit records matched the provided filters");
        return;
    }

    println!("requester_identity\tresource_identifier\tresource_class\tpurpose_code\trequest_time");
    for row in rows {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            row.requester_identity,
            row.resource_identifier,
            row.resource_class,
            row.purpose_code
                .as_deref()
                .filter(|value| !value.is_empty())
                .unwrap_or("(none)"),
            row.request_time
        );
    }
}

fn render_audit_summary(rows: &[AuditStreamSummaryRow], use_json: bool) {
    if use_json {
        let payload: Vec<JsonValue> = rows
            .iter()
            .map(|row| {
                json!({
                    "stream": row.stream.clone(),
                    "last_seq": row.last_seq,
                    "label_class": row.label_class.clone(),
                    "sensitivity": row.sensitivity.clone(),
                    "schemas": row.schemas.clone(),
                    "has_query_audit": row.has_query_audit,
                    "has_access_grant": row.has_access_grant,
                    "has_access_revoke": row.has_access_revoke,
                    "audit_required": row.audit_required,
                    "missing_required_audit": row.missing_required_audit,
                })
            })
            .collect();
        let output = json!({ "ok": true, "streams": payload });
        println!("{}", pretty_json(output));
        return;
    }

    if rows.is_empty() {
        println!("no streams discovered for summary");
        return;
    }

    for row in rows {
        println!("stream: {}", row.stream);
        match row.last_seq {
            Some(seq) => println!("  last_seq: {seq}"),
            None => println!("  last_seq: (unknown)"),
        }
        match &row.label_class {
            Some(class) => println!("  label_class: {class}"),
            None => println!("  label_class: (unknown)"),
        }
        match &row.sensitivity {
            Some(value) => println!("  sensitivity: {value}"),
            None => println!("  sensitivity: (not set)"),
        }
        if row.schemas.is_empty() {
            println!("  schemas: (none)");
        } else {
            println!("  schemas: {}", row.schemas.join(", "));
        }
        println!("  query_audit_present: {}", row.has_query_audit);
        println!("  access_grant_present: {}", row.has_access_grant);
        println!("  access_revoke_present: {}", row.has_access_revoke);
        println!("  audit_required: {}", row.audit_required);
        println!("  missing_required_audit: {}", row.missing_required_audit);
        println!("---");
    }
}

fn render_policy_check(violations: &[String], use_json: bool) {
    if use_json {
        let output = json!({
            "ok": violations.is_empty(),
            "violations": violations,
        });
        println!("{}", pretty_json(output));
        return;
    }

    if violations.is_empty() {
        println!("no policy violations detected");
    } else {
        println!("policy violations detected:");
        for violation in violations {
            println!("- {violation}");
        }
    }
}

async fn fetch_stream_messages(
    reference: &HubReference,
    stream: &str,
) -> Result<Vec<StoredMessage>> {
    match reference {
        HubReference::Local(data_dir) => {
            let state = load_stream_state(data_dir, stream).await?;
            Ok(state.messages)
        }
        HubReference::Remote(client) => {
            let query = vec![("stream", stream.to_string())];
            let result: Result<Vec<RemoteStoredMessage>> = client.get_json("/stream", &query).await;
            match result {
                Ok(messages) => Ok(messages.into_iter().map(StoredMessage::from).collect()),
                Err(err) => {
                    if let Some(response_err) = err.downcast_ref::<HubResponseError>() {
                        if response_err.status == reqwest::StatusCode::NOT_FOUND {
                            return Ok(Vec::new());
                        }
                    }
                    Err(err)
                }
            }
        }
    }
}

async fn gather_stream_inventory(reference: &HubReference) -> Result<BTreeMap<String, u64>> {
    match reference {
        HubReference::Local(data_dir) => {
            let state = load_hub_state(data_dir).await?;
            Ok(state.last_stream_seq)
        }
        HubReference::Remote(client) => {
            let report: RemoteObservabilityReport = client.get_json("/metrics", &[]).await?;
            Ok(report.last_stream_seq)
        }
    }
}

fn schema_id_from_message(message: &StoredMessage) -> Option<[u8; 32]> {
    let schema_hex = message.schema.as_ref()?;
    let bytes = hex::decode(schema_hex).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Some(id)
}

fn message_schema_matches(message: &StoredMessage, schema_id: [u8; 32]) -> bool {
    schema_id_from_message(message)
        .map(|id| id == schema_id)
        .unwrap_or(false)
}

fn schema_name_from_id(schema_id: [u8; 32]) -> Option<&'static str> {
    if schema_id == schema_paid_operation() {
        Some("paid.operation.v1")
    } else if schema_id == schema_access_grant() {
        Some("access.grant.v1")
    } else if schema_id == schema_access_revoke() {
        Some("access.revoke.v1")
    } else if schema_id == schema_delegated_execution() {
        Some("delegated.execution.v1")
    } else if schema_id == schema_agreement_definition() {
        Some("agreement.definition.v1")
    } else if schema_id == schema_agreement_confirmation() {
        Some("agreement.confirmation.v1")
    } else if schema_id == schema_data_publication() {
        Some("data.publication.v1")
    } else if schema_id == schema_state_checkpoint() {
        Some("state.checkpoint.v1")
    } else if schema_id == schema_recovery_request() {
        Some("recovery.request.v1")
    } else if schema_id == schema_recovery_approval() {
        Some("recovery.approval.v1")
    } else if schema_id == schema_recovery_execution() {
        Some("recovery.execution.v1")
    } else if schema_id == schema_query_audit() {
        Some("query.audit.v1")
    } else if schema_id == schema_federation_mirror() {
        Some("federation.mirror.v1")
    } else {
        None
    }
}

fn parse_message_payload<T>(message: &StoredMessage) -> Result<T>
where
    T: DeserializeOwned,
{
    let body = message.body.as_ref().ok_or_else(|| {
        anyhow::Error::new(ProtocolError::new(format!(
            "message {}#{} does not retain its body",
            message.stream, message.seq
        )))
    })?;
    serde_json::from_str(body)
        .with_context(|| format!("decoding payload for {}#{}", message.stream, message.seq))
}

fn classification_is_sensitive(class: Option<&str>, sensitivity: Option<&str>) -> bool {
    class
        .map(|value| value.eq_ignore_ascii_case("sensitive"))
        .unwrap_or(false)
        || sensitivity
            .map(|value| value.eq_ignore_ascii_case("sensitive"))
            .unwrap_or(false)
}

async fn fetch_stream_label_class(
    client: &HubHttpClient,
    stream: &str,
) -> Result<Option<LabelClassInfo>, LabelClassFetchError> {
    let label_hex = derive_stream_label_hex(stream).map_err(LabelClassFetchError::Other)?;
    match fetch_label_class_descriptor(client, &label_hex).await {
        Ok(descriptor) => {
            if !descriptor.ok {
                return Ok(None);
            }
            Ok(Some(LabelClassInfo {
                class: descriptor.class,
                sensitivity: descriptor.sensitivity,
            }))
        }
        Err(err) => {
            if label_class_endpoint_missing(&err) {
                Err(LabelClassFetchError::Unsupported)
            } else {
                Err(LabelClassFetchError::Other(err))
            }
        }
    }
}

fn derive_stream_label_hex(stream: &str) -> Result<String> {
    let stream_id = cap_stream_id_from_label(stream)
        .with_context(|| format!("deriving stream identifier for {stream}"))?;
    let label = Label::derive([], stream_id, 0);
    Ok(hex::encode(label.as_bytes()))
}

fn label_class_endpoint_missing(err: &anyhow::Error) -> bool {
    if let Some(response) = err.downcast_ref::<HubResponseError>() {
        return response.status == reqwest::StatusCode::NOT_FOUND
            || response.status == reqwest::StatusCode::METHOD_NOT_ALLOWED;
    }
    false
}

async fn collect_recovery_execution_events(
    streams: &BTreeSet<String>,
    cache: &mut StreamMessageCache,
) -> Result<Vec<RecoveryExecutionEvent>> {
    let mut events = Vec::new();
    for stream in streams {
        let messages = cache.messages(stream).await?;
        for message in messages {
            if !message_schema_matches(message, schema_recovery_execution()) {
                continue;
            }
            let payload: RecoveryExecution = parse_message_payload(message)?;
            events.push(RecoveryExecutionEvent {
                stream: stream.clone(),
                seq: message.seq,
                target_identity_hex: hex::encode(payload.target_identity.as_ref()),
                approval_count: payload.approval_references.len(),
            });
        }
    }
    Ok(events)
}

async fn handle_selftest_core() -> Result<()> {
    if handle_selftest_stub(SelftestSuite::Core)? {
        return Ok(());
    }
    println!("running VEEN core self-tests...");
    let mut report = veen_selftest::SelftestReport::default();
    let result = {
        let mut reporter = veen_selftest::SelftestReporter::new(Some(&mut report));
        veen_selftest::run_core(&mut reporter).await
    };
    match result {
        Ok(()) => {
            emit_selftest_report(SelftestSuite::Core, &report);
            log_cli_goal("CLI.SELFTEST.CORE");
            Ok(())
        }
        Err(err) => {
            emit_selftest_report(SelftestSuite::Core, &report);
            Err(anyhow::Error::new(SelftestFailure::new(err)))
        }
    }
}

async fn handle_selftest_props() -> Result<()> {
    if handle_selftest_stub(SelftestSuite::Props)? {
        return Ok(());
    }
    println!("running VEEN property self-tests...");
    let mut report = veen_selftest::SelftestReport::default();
    let result = {
        let mut reporter = veen_selftest::SelftestReporter::new(Some(&mut report));
        veen_selftest::run_props(&mut reporter)
    };
    match result {
        Ok(()) => {
            emit_selftest_report(SelftestSuite::Props, &report);
            log_cli_goal("CLI.SELFTEST.PROPS");
            Ok(())
        }
        Err(err) => {
            emit_selftest_report(SelftestSuite::Props, &report);
            Err(anyhow::Error::new(SelftestFailure::new(err)))
        }
    }
}

async fn handle_selftest_fuzz() -> Result<()> {
    if handle_selftest_stub(SelftestSuite::Fuzz)? {
        return Ok(());
    }
    println!("running VEEN fuzz self-tests...");
    let mut report = veen_selftest::SelftestReport::default();
    let result = {
        let mut reporter = veen_selftest::SelftestReporter::new(Some(&mut report));
        veen_selftest::run_fuzz(&mut reporter)
    };
    match result {
        Ok(()) => {
            emit_selftest_report(SelftestSuite::Fuzz, &report);
            log_cli_goal("CLI.SELFTEST.FUZZ");
            Ok(())
        }
        Err(err) => {
            emit_selftest_report(SelftestSuite::Fuzz, &report);
            Err(anyhow::Error::new(SelftestFailure::new(err)))
        }
    }
}

async fn handle_selftest_all() -> Result<()> {
    if handle_selftest_stub(SelftestSuite::All)? {
        return Ok(());
    }
    println!("running full VEEN self-test suite...");
    let mut report = veen_selftest::SelftestReport::default();
    let result = {
        let mut reporter = veen_selftest::SelftestReporter::new(Some(&mut report));
        veen_selftest::run_all(&mut reporter).await
    };
    match result {
        Ok(()) => {
            emit_selftest_report(SelftestSuite::All, &report);
            log_cli_goal("CLI.SELFTEST.ALL");
            Ok(())
        }
        Err(err) => {
            emit_selftest_report(SelftestSuite::All, &report);
            Err(anyhow::Error::new(SelftestFailure::new(err)))
        }
    }
}

async fn handle_selftest_federated() -> Result<()> {
    if handle_selftest_stub(SelftestSuite::Federated)? {
        return Ok(());
    }
    println!("running VEEN federated self-tests...");
    let mut report = veen_selftest::SelftestReport::default();
    let result = {
        let mut reporter = veen_selftest::SelftestReporter::new(Some(&mut report));
        veen_selftest::run_federated(&mut reporter).await
    };
    match result {
        Ok(()) => {
            emit_selftest_report(SelftestSuite::Federated, &report);
            log_cli_goal("CLI.SELFTEST.FEDERATED");
            Ok(())
        }
        Err(err) => {
            emit_selftest_report(SelftestSuite::Federated, &report);
            Err(anyhow::Error::new(SelftestFailure::new(err)))
        }
    }
}

async fn handle_selftest_kex1() -> Result<()> {
    if handle_selftest_stub(SelftestSuite::Kex1)? {
        return Ok(());
    }
    println!("running VEEN KEX1+ self-tests...");
    let mut report = veen_selftest::SelftestReport::default();
    let result = {
        let mut reporter = veen_selftest::SelftestReporter::new(Some(&mut report));
        veen_selftest::run_kex1(&mut reporter).await
    };
    match result {
        Ok(()) => {
            emit_selftest_report(SelftestSuite::Kex1, &report);
            log_cli_goal("CLI.SELFTEST.KEX1");
            Ok(())
        }
        Err(err) => {
            emit_selftest_report(SelftestSuite::Kex1, &report);
            Err(anyhow::Error::new(SelftestFailure::new(err)))
        }
    }
}

async fn handle_selftest_hardened() -> Result<()> {
    if handle_selftest_stub(SelftestSuite::Hardened)? {
        return Ok(());
    }
    println!("running VEEN hardened self-tests...");
    let mut report = veen_selftest::SelftestReport::default();
    let result = {
        let mut reporter = veen_selftest::SelftestReporter::new(Some(&mut report));
        veen_selftest::run_hardened(&mut reporter).await
    };
    match result {
        Ok(()) => {
            emit_selftest_report(SelftestSuite::Hardened, &report);
            log_cli_goal("CLI.SELFTEST.HARDENED");
            Ok(())
        }
        Err(err) => {
            emit_selftest_report(SelftestSuite::Hardened, &report);
            Err(anyhow::Error::new(SelftestFailure::new(err)))
        }
    }
}

async fn handle_selftest_meta() -> Result<()> {
    if handle_selftest_stub(SelftestSuite::Meta)? {
        return Ok(());
    }
    println!("running VEEN meta self-tests...");
    let mut report = veen_selftest::SelftestReport::default();
    let result = {
        let mut reporter = veen_selftest::SelftestReporter::new(Some(&mut report));
        veen_selftest::run_meta(&mut reporter).await
    };
    match result {
        Ok(()) => {
            emit_selftest_report(SelftestSuite::Meta, &report);
            log_cli_goal("CLI.SELFTEST.META");
            Ok(())
        }
        Err(err) => {
            emit_selftest_report(SelftestSuite::Meta, &report);
            Err(anyhow::Error::new(SelftestFailure::new(err)))
        }
    }
}

async fn handle_selftest_recorder() -> Result<()> {
    if handle_selftest_stub(SelftestSuite::Recorder)? {
        return Ok(());
    }
    println!("running VEEN recorder self-tests...");
    let mut report = veen_selftest::SelftestReport::default();
    let result = {
        let mut reporter = veen_selftest::SelftestReporter::new(Some(&mut report));
        veen_selftest::run_recorder(&mut reporter).await
    };
    match result {
        Ok(()) => {
            emit_selftest_report(SelftestSuite::Recorder, &report);
            log_cli_goal("CLI.SELFTEST.RECORDER");
            Ok(())
        }
        Err(err) => {
            emit_selftest_report(SelftestSuite::Recorder, &report);
            Err(anyhow::Error::new(SelftestFailure::new(err)))
        }
    }
}

async fn handle_selftest_plus() -> Result<()> {
    record_selftest_stub_marker(SelftestSuite::Plus)?;
    println!("running VEEN plus self-tests...");
    let mut failed = Vec::new();

    if let Err(err) = handle_selftest_core().await {
        eprintln!("self-test suite core failed: {err:#}");
        failed.push(SelftestSuite::Core);
    }
    if let Err(err) = handle_selftest_props().await {
        eprintln!("self-test suite props failed: {err:#}");
        failed.push(SelftestSuite::Props);
    }
    if let Err(err) = handle_selftest_fuzz().await {
        eprintln!("self-test suite fuzz failed: {err:#}");
        failed.push(SelftestSuite::Fuzz);
    }
    if let Err(err) = handle_selftest_federated().await {
        eprintln!("self-test suite federated failed: {err:#}");
        failed.push(SelftestSuite::Federated);
    }
    if let Err(err) = handle_selftest_kex1().await {
        eprintln!("self-test suite kex1 failed: {err:#}");
        failed.push(SelftestSuite::Kex1);
    }
    if let Err(err) = handle_selftest_hardened().await {
        eprintln!("self-test suite hardened failed: {err:#}");
        failed.push(SelftestSuite::Hardened);
    }
    if let Err(err) = handle_selftest_meta().await {
        eprintln!("self-test suite meta failed: {err:#}");
        failed.push(SelftestSuite::Meta);
    }

    if failed.is_empty() {
        log_cli_goal("CLI.SELFTEST.PLUS");
        println!("VEEN self-test plus suites completed successfully");
        return Ok(());
    }

    let joined = failed
        .iter()
        .map(|suite| suite.name())
        .collect::<Vec<_>>()
        .join(", ");
    let err = anyhow!(format!("self-test suites failed: {joined}"));
    Err(anyhow::Error::new(SelftestFailure::new(err)))
}

async fn handle_selftest_plus_plus() -> Result<()> {
    record_selftest_stub_marker(SelftestSuite::PlusPlus)?;
    println!("running VEEN plus-plus self-tests...");

    handle_selftest_plus()
        .await
        .map_err(|err| anyhow::Error::new(SelftestFailure::new(err)))?;

    log_cli_goal("CLI.SELFTEST.PLUSPLUS");
    println!("VEEN self-test plus-plus suites completed successfully");
    Ok(())
}

async fn flush_hub_storage(data_dir: &Path) -> Result<()> {
    storage::flush_file_if_exists(&data_dir.join(RECEIPTS_FILE)).await?;
    storage::flush_file_if_exists(&data_dir.join(PAYLOADS_FILE)).await?;
    storage::flush_file_if_exists(&data_dir.join(CHECKPOINTS_FILE)).await?;
    storage::flush_file_if_exists(&data_dir.join(STATE_DIR).join(ANCHOR_LOG_FILE)).await?;
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

fn stream_index_path(data_dir: &Path, stream: &str) -> PathBuf {
    let name = stream_storage_name(stream);
    data_dir
        .join(STATE_DIR)
        .join(STREAMS_DIR)
        .join(format!("{name}.index"))
}

fn stream_bundle_path(data_dir: &Path, bundle: &str) -> PathBuf {
    let path = Path::new(bundle);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        data_dir.join(STATE_DIR).join(MESSAGES_DIR).join(path)
    }
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
    let json_path = stream_state_path(data_dir, stream);
    if fs::try_exists(&json_path)
        .await
        .with_context(|| format!("checking stream state {}", json_path.display()))?
    {
        return read_json_file(&json_path).await;
    }

    let index_path = stream_index_path(data_dir, stream);
    if fs::try_exists(&index_path)
        .await
        .with_context(|| format!("checking stream index {}", index_path.display()))?
    {
        let entries = stream_index::load_stream_index(&index_path)
            .await
            .with_context(|| format!("loading stream index from {}", index_path.display()))?;
        if entries.is_empty() {
            return Ok(HubStreamState::default());
        }

        let mut messages = Vec::with_capacity(entries.len());
        for entry in entries {
            let bundle_path = stream_bundle_path(data_dir, &entry.bundle);
            let message: StoredMessage = read_json_file(&bundle_path).await.with_context(|| {
                format!("decoding message bundle from {}", bundle_path.display())
            })?;
            messages.push(message);
        }
        return Ok(HubStreamState { messages });
    }

    Ok(HubStreamState::default())
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

struct ResolvedHubRef {
    reference: HubReference,
    profile_id: Option<String>,
}

impl ResolvedHubRef {
    fn into_reference(self) -> HubReference {
        self.reference
    }

    fn profile_id(&self) -> Option<&str> {
        self.profile_id.as_deref()
    }
}

async fn require_hub(locator: &HubLocatorArgs, context: &str) -> Result<ResolvedHubRef> {
    match resolve_optional_hub(locator).await? {
        Some(value) => Ok(value),
        None => bail_usage!(
            "{context} requires --hub URL or --env/--hub-name",
            context = context
        ),
    }
}

async fn resolve_optional_hub(locator: &HubLocatorArgs) -> Result<Option<ResolvedHubRef>> {
    if locator.hub.is_some() && (locator.env.is_some() || locator.hub_name.is_some()) {
        bail_usage!("--hub cannot be combined with --env or --hub-name");
    }

    if let Some(ref reference) = locator.hub {
        let hub = parse_hub_reference(reference)?;
        return Ok(Some(ResolvedHubRef {
            reference: hub,
            profile_id: None,
        }));
    }

    if locator.env.is_some() || locator.hub_name.is_some() {
        let env_path = locator
            .env
            .as_ref()
            .ok_or_else(|| CliUsageError::new("--env is required when using --hub-name".into()))?;
        let hub_name = locator
            .hub_name
            .as_deref()
            .ok_or_else(|| CliUsageError::new("--hub-name is required when using --env".into()))?;
        let descriptor = read_env_descriptor(env_path).await?;
        let hub_descriptor = descriptor.hubs.get(hub_name).ok_or_else(|| {
            CliUsageError::new(format!(
                "hub `{hub_name}` not found in {}",
                env_path.display()
            ))
        })?;
        let reference = parse_hub_reference(&hub_descriptor.service_url)?;
        return Ok(Some(ResolvedHubRef {
            reference,
            profile_id: Some(hub_descriptor.profile_id.clone()),
        }));
    }

    Ok(None)
}

async fn hub_reference_from_locator(
    locator: &HubLocatorArgs,
    context: &str,
) -> Result<HubReference> {
    let resolved = require_hub(locator, context).await?;
    if let Some(profile_id) = resolved.profile_id() {
        tracing::debug!(
            %profile_id,
            context = context,
            "resolved hub profile via env descriptor"
        );
    }
    Ok(resolved.into_reference())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;
    use ciborium::de::from_reader;
    use ciborium::ser::into_writer;
    use clap::Parser;
    use ed25519_dalek::{Signature, Verifier};
    use hyper::body::to_bytes;
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{
        Body, Method, Request as HyperRequest, Response as HyperResponse, Server, StatusCode,
    };
    use serde_json::{json, Value};
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::ffi::OsString;
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

    #[test]
    fn parse_label_map_entries_parses_pairs() -> anyhow::Result<()> {
        let entries = vec!["alpha=beta".to_string(), "foo = bar/baz".to_string()];
        let map = super::parse_label_map_entries(&entries)?;
        assert_eq!(map.get("alpha").cloned(), Some("beta".to_string()));
        assert_eq!(map.get("foo").cloned(), Some("bar/baz".to_string()));
        Ok(())
    }

    #[test]
    fn parse_label_map_entries_rejects_duplicates() {
        let entries = vec!["alpha=one".to_string(), "alpha=two".to_string()];
        let err = super::parse_label_map_entries(&entries).unwrap_err();
        assert!(err.to_string().contains("duplicate --label-map entry"));
    }

    #[test]
    fn args_request_json_output_detects_flag() {
        let args = vec![
            OsString::from("veen"),
            OsString::from("--json"),
            OsString::from("hub"),
        ];
        assert!(super::args_request_json_output(&args));

        let no_flag = vec![OsString::from("veen"), OsString::from("hub")];
        assert!(!super::args_request_json_output(&no_flag));
    }

    #[test]
    fn hub_tls_info_is_nested_under_hub_command() {
        let cli = Cli::parse_from(["veen", "hub", "tls-info", "--hub", "http://localhost:8080"]);

        match cli.command {
            Command::Hub(HubCommand::TlsInfo(args)) => {
                assert_eq!(args.hub.hub, Some("http://localhost:8080".to_string()));
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn hub_start_accepts_pow_difficulty() {
        let cli = Cli::parse_from([
            "veen",
            "hub",
            "start",
            "--listen",
            "127.0.0.1:8080",
            "--data-dir",
            "/tmp/veen",
            "--pow-difficulty",
            "6",
        ]);

        match cli.command {
            Command::Hub(HubCommand::Start(args)) => {
                assert_eq!(args.pow_difficulty, Some(6));
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn hub_start_rejects_zero_pow_difficulty() {
        let err = super::hub_start_overrides("profile", Some(0)).unwrap_err();
        assert!(err
            .to_string()
            .contains("pow-difficulty must be greater than zero"));
    }

    #[test]
    fn retention_value_parser_supports_seconds_and_indefinite() {
        assert_eq!(
            "600".parse::<RetentionValue>().unwrap(),
            RetentionValue::Seconds(600)
        );
        assert_eq!(
            "indefinite".parse::<RetentionValue>().unwrap(),
            RetentionValue::Indefinite
        );
        assert!("ten".parse::<RetentionValue>().is_err());
    }

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

    #[tokio::test]
    async fn env_descriptor_round_trip() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("alpha.env.json");
        let descriptor = EnvDescriptor {
            version: ENV_DESCRIPTOR_VERSION,
            name: "alpha".to_string(),
            cluster_context: "kind-test".to_string(),
            namespace: "veen".to_string(),
            description: Some("test".to_string()),
            hubs: BTreeMap::new(),
            tenants: BTreeMap::new(),
        };
        write_env_descriptor(&path, &descriptor).await?;
        let loaded = read_env_descriptor(&path).await?;
        assert_eq!(loaded.name, "alpha");
        assert_eq!(loaded.cluster_context, "kind-test");
        Ok(())
    }

    #[tokio::test]
    async fn env_descriptor_mutations_persist() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let root = dir.path().join("env");
        let init_args = EnvInitArgs {
            root: root.clone(),
            name: "demo".to_string(),
            cluster_context: "kind-demo".to_string(),
            namespace: "veen-demo".to_string(),
            description: None,
        };
        handle_env_init(init_args).await?;
        let env_path = root.join("demo.env.json");

        let add_hub = EnvAddHubArgs {
            env: env_path.clone(),
            hub_name: "primary".to_string(),
            service_url: "http://hub.demo".to_string(),
            profile_id: "a".repeat(64),
            realm: Some("b".repeat(64)),
        };
        handle_env_add_hub(add_hub).await?;

        let add_tenant = EnvAddTenantArgs {
            env: env_path.clone(),
            tenant_id: "tenant-a".to_string(),
            stream_prefix: "app".to_string(),
            label_class: Some(EnvTenantLabelClass::Wallet),
        };
        handle_env_add_tenant(add_tenant).await?;

        let descriptor = read_env_descriptor(&env_path).await?;
        let hub = descriptor.hubs.get("primary").expect("hub recorded");
        assert_eq!(hub.service_url, "http://hub.demo");
        assert_eq!(hub.profile_id, "a".repeat(64));
        let tenant = descriptor.tenants.get("tenant-a").expect("tenant recorded");
        assert_eq!(tenant.label_class, "wallet");
        assert_eq!(tenant.stream_prefix, "app");
        Ok(())
    }

    #[tokio::test]
    async fn env_descriptor_validation_detects_empty_namespace() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("broken.env.json");
        let invalid = json!({
            "version": ENV_DESCRIPTOR_VERSION,
            "name": "broken",
            "cluster_context": "ctx",
            "namespace": "",
            "hubs": {},
            "tenants": {}
        });
        tokio::fs::write(&path, serde_json::to_vec_pretty(&invalid)?).await?;
        let err = read_env_descriptor(&path)
            .await
            .expect_err("expected namespace validation failure");
        assert!(err.to_string().contains("namespace"));
        Ok(())
    }

    #[tokio::test]
    async fn retention_set_updates_requested_values() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let args = RetentionSetArgs {
            data_dir: dir.path().to_path_buf(),
            receipts: Some(RetentionValue::Seconds(3600)),
            payloads: Some(RetentionValue::Indefinite),
            checkpoints: None,
        };

        super::handle_retention_set(args).await?;

        let retention_path = dir.path().join(STATE_DIR).join(RETENTION_CONFIG_FILE);
        let stored: Value = read_json_file(&retention_path).await?;
        assert_eq!(stored.get("receipts"), Some(&json!(3600u64)));
        assert_eq!(stored.get("payloads"), Some(&json!("indefinite")));
        assert!(stored.get("checkpoints").is_none());
        Ok(())
    }

    #[test]
    fn kube_render_arguments_parse() {
        let cli = Cli::try_parse_from([
            "veen",
            "kube",
            "render",
            "--cluster-context",
            "kind-test",
            "--namespace",
            "veen",
            "--name",
            "alpha",
            "--image",
            "hub:latest",
            "--data-pvc",
            "alpha-pvc",
            "--replicas",
            "2",
        ])
        .expect("cli parse");
        match cli.command {
            Command::Kube(crate::kube::KubeCommand::Render(args)) => {
                assert_eq!(args.namespace.as_deref(), Some("veen"));
                assert_eq!(args.name, "alpha");
                assert_eq!(args.replicas, 2);
            }
            _ => panic!("expected kube render command"),
        }
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

    async fn spawn_submit_capture_server(
        response: RemoteSubmitResponse,
    ) -> anyhow::Result<(String, mpsc::Receiver<Vec<u8>>, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr: SocketAddr = listener.local_addr()?;
        let (tx, rx) = mpsc::channel(1);
        let response = Arc::new(response);
        let service = make_service_fn(move |_| {
            let tx = tx.clone();
            let response = Arc::clone(&response);
            async move {
                Ok::<_, Infallible>(service_fn(move |mut req: HyperRequest<Body>| {
                    let tx = tx.clone();
                    let response = Arc::clone(&response);
                    async move {
                        assert_eq!(req.method(), Method::POST);
                        assert_eq!(req.uri().path(), "/submit");
                        let body = to_bytes(req.body_mut()).await.unwrap().to_vec();
                        tx.send(body).await.unwrap();
                        let json = serde_json::to_vec(&*response).unwrap();
                        Ok::<_, Infallible>(
                            HyperResponse::builder()
                                .status(StatusCode::OK)
                                .body(Body::from(json))
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
    fn schema_show_text_output_matches_cli_goals() {
        let descriptor = RemoteSchemaDescriptorEntry {
            schema_id: "abcd".to_string(),
            name: "test.operation.v1".to_string(),
            version: "1".to_string(),
            doc_url: Some("https://schemas/test".to_string()),
            owner: Some("0123".to_string()),
            ts: 123,
            created_at: Some(100),
            updated_at: Some(120),
        };
        let usage = RemoteSchemaUsage {
            used_labels: vec!["core/example".to_string(), "core/audit".to_string()],
            used_count: Some(7),
            first_used_ts: Some(101),
            last_used_ts: Some(125),
        };

        let text = super::format_schema_descriptor_output(&descriptor, Some(&usage), false);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "schema_id: abcd");
        assert_eq!(lines[1], "name: test.operation.v1");
        assert_eq!(lines[2], "version: 1");
        assert_eq!(lines[3], "doc_url: https://schemas/test");
        assert_eq!(lines[4], "owner: 0123");
        assert_eq!(lines[5], "ts: 123");
        assert_eq!(lines[6], "created_at: 100");
        assert_eq!(lines[7], "updated_at: 120");
        assert_eq!(lines[8], "used_labels: [core/example,core/audit]");
        assert_eq!(lines[9], "used_count: 7");
        assert_eq!(lines[10], "first_used_ts: 101");
        assert_eq!(lines[11], "last_used_ts: 125");
    }

    #[test]
    fn schema_show_json_output_matches_cli_goals() {
        let descriptor = RemoteSchemaDescriptorEntry {
            schema_id: "a1b2".to_string(),
            name: "audit.record.v1".to_string(),
            version: "1".to_string(),
            doc_url: None,
            owner: None,
            ts: 42,
            created_at: None,
            updated_at: None,
        };
        let usage = RemoteSchemaUsage {
            used_labels: vec!["core/main".to_string()],
            used_count: Some(1),
            first_used_ts: Some(10),
            last_used_ts: Some(20),
        };

        let json = super::format_schema_descriptor_output(&descriptor, Some(&usage), true);
        let value: Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(value["schema_id"], "a1b2");
        assert_eq!(value["name"], "audit.record.v1");
        assert_eq!(value["doc_url"], Value::Null);
        assert_eq!(value["owner"], Value::Null);
        assert_eq!(value["usage"]["used_labels"], json!(["core/main"]));
        assert_eq!(value["usage"]["used_count"], 1);
        assert_eq!(value["usage"]["first_used_ts"], 10);
        assert_eq!(value["usage"]["last_used_ts"], 20);
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
            hub: HubLocatorArgs::from_url(hub_url.clone()),
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
            pow_nonce: None,
        })
        .await?;

        handle_stream(StreamArgs {
            hub: HubLocatorArgs::from_url(hub_url.clone()),
            client: client_dir.path().to_path_buf(),
            stream: "test".to_string(),
            from: 0,
            with_proof: false,
        })
        .await?;

        handle_resync(ResyncArgs {
            hub: HubLocatorArgs::from_url(hub_url),
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
    async fn send_remote_auto_solves_pow_cookie() -> anyhow::Result<()> {
        let client_dir = tempdir()?;
        handle_keygen(KeygenArgs {
            out: client_dir.path().to_path_buf(),
        })
        .await?;

        let response = RemoteSubmitResponse {
            stream: "pow".to_string(),
            seq: 1,
            mmr_root: "root".to_string(),
            stored_attachments: Vec::new(),
        };
        let (url, mut body_rx, server) = spawn_submit_capture_server(response).await?;

        let challenge_hex = "0abc".to_string();
        handle_send(SendArgs {
            hub: HubLocatorArgs::from_url(url.clone()),
            client: client_dir.path().to_path_buf(),
            stream: "pow".to_string(),
            body: json!({ "msg": "pow" }).to_string(),
            schema: None,
            expires_at: None,
            cap: None,
            parent: None,
            attach: Vec::new(),
            no_store_body: false,
            pow_difficulty: Some(4),
            pow_challenge: Some(challenge_hex.clone()),
            pow_nonce: None,
        })
        .await?;

        let body = body_rx.recv().await.expect("payload captured");
        server.abort();

        let request: RemoteSubmitRequest = serde_json::from_slice(&body)?;
        let cookie = request.pow_cookie.expect("pow cookie present");
        assert_eq!(cookie.difficulty, 4);
        let pow_cookie = cookie.into_pow_cookie();
        assert!(pow_cookie.meets_difficulty());
        assert_eq!(hex::encode(pow_cookie.challenge), challenge_hex);

        Ok(())
    }

    #[tokio::test]
    async fn send_remote_accepts_user_supplied_pow_cookie() -> anyhow::Result<()> {
        let client_dir = tempdir()?;
        handle_keygen(KeygenArgs {
            out: client_dir.path().to_path_buf(),
        })
        .await?;

        let response = RemoteSubmitResponse {
            stream: "pow".to_string(),
            seq: 7,
            mmr_root: "root".to_string(),
            stored_attachments: Vec::new(),
        };
        let (url, mut body_rx, server) = spawn_submit_capture_server(response).await?;

        let challenge_bytes = vec![0x55u8; 16];
        let challenge_hex = hex::encode(&challenge_bytes);
        let solved = super::solve_pow_cookie(challenge_bytes.clone(), 5)?;

        handle_send(SendArgs {
            hub: HubLocatorArgs::from_url(url.clone()),
            client: client_dir.path().to_path_buf(),
            stream: "pow".to_string(),
            body: json!({ "msg": "provided" }).to_string(),
            schema: None,
            expires_at: None,
            cap: None,
            parent: None,
            attach: Vec::new(),
            no_store_body: false,
            pow_difficulty: Some(solved.difficulty),
            pow_challenge: Some(challenge_hex.clone()),
            pow_nonce: Some(solved.nonce),
        })
        .await?;

        let body = body_rx.recv().await.expect("payload captured");
        server.abort();

        let request: RemoteSubmitRequest = serde_json::from_slice(&body)?;
        let cookie = request.pow_cookie.expect("pow cookie present");
        let pow_cookie = cookie.into_pow_cookie();
        assert_eq!(pow_cookie.difficulty, solved.difficulty);
        assert_eq!(pow_cookie.nonce, solved.nonce);
        assert_eq!(pow_cookie.challenge, challenge_bytes);

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
            hub: HubLocatorArgs::from_url(hub_url.clone()),
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
            pow_nonce: None,
        })
        .await?;

        handle_stream(StreamArgs {
            hub: HubLocatorArgs::from_url(hub_url.clone()),
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
            hub: HubLocatorArgs::from_url(hub_url.clone()),
        })
        .await?;
        assert_eq!(latest, checkpoint2);

        let range = handle_hub_checkpoint_range(HubCheckpointRangeArgs {
            hub: HubLocatorArgs::from_url(hub_url.clone()),
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
            hub: HubLocatorArgs::from_url(url.clone()),
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
            hub: HubLocatorArgs::from_url(url.clone()),
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
    async fn label_class_show_fetches_descriptor() -> anyhow::Result<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let expected_label = hex::encode([0x11u8; 32]);
        let expected_path = format!("/label-class/{expected_label}");
        let (path_tx, mut path_rx) = mpsc::channel(1);
        let response_label = expected_label.clone();
        let expected_path_for_server = expected_path.clone();
        let handle = tokio::spawn(async move {
            let service = make_service_fn(move |_| {
                let expected_path = expected_path_for_server.clone();
                let path_tx = path_tx.clone();
                let response_label = response_label.clone();
                async move {
                    Ok::<_, Infallible>(service_fn(move |req: HyperRequest<Body>| {
                        let expected_path = expected_path.clone();
                        let path_tx = path_tx.clone();
                        let response_label = response_label.clone();
                        async move {
                            if req.method() == Method::GET && req.uri().path() == expected_path {
                                path_tx.send(req.uri().path().to_string()).await.ok();
                                let body = serde_json::to_string(&json!({
                                    "ok": true,
                                    "label": response_label,
                                    "class": "user",
                                    "sensitivity": "medium",
                                    "retention_hint": 86_400u64,
                                    "pad_block_effective": 256u64,
                                    "retention_policy": "standard",
                                    "rate_policy": "rl0-default",
                                }))
                                .unwrap();
                                return Ok::<_, Infallible>(
                                    HyperResponse::builder()
                                        .status(StatusCode::OK)
                                        .body(Body::from(body))
                                        .unwrap(),
                                );
                            }
                            Ok::<_, Infallible>(
                                HyperResponse::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Body::empty())
                                    .unwrap(),
                            )
                        }
                    }))
                }
            });
            if let Err(err) = Server::from_tcp(listener)?.serve(service).await {
                eprintln!("label-class show test server error: {err}");
            }
            Ok::<_, anyhow::Error>(())
        });

        let url = format!("http://{addr}");
        handle_label_class_show(LabelClassShowArgs {
            hub: HubLocatorArgs::from_url(url),
            label: expected_label.clone(),
            json: true,
        })
        .await?;
        let requested_path = path_rx.recv().await.expect("path observed");
        assert_eq!(requested_path, expected_path);
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn label_class_list_fetches_entries() -> anyhow::Result<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let realm = hex::encode([0x22u8; 32]);
        let expected_query = format!("realm={realm}&class=user");
        let (query_tx, mut query_rx) = mpsc::channel(1);
        let expected_query_for_server = expected_query.clone();
        let handle = tokio::spawn(async move {
            let service = make_service_fn(move |_| {
                let expected_query = expected_query_for_server.clone();
                let query_tx = query_tx.clone();
                async move {
                    Ok::<_, Infallible>(service_fn(move |req: HyperRequest<Body>| {
                        let expected_query = expected_query.clone();
                        let query_tx = query_tx.clone();
                        async move {
                            if req.method() == Method::GET
                                && req.uri().path() == "/label-class"
                                && req.uri().query() == Some(expected_query.as_str())
                            {
                                query_tx
                                    .send(req.uri().query().unwrap().to_string())
                                    .await
                                    .ok();
                                let body = serde_json::to_string(&json!({
                                    "ok": true,
                                    "entries": [{
                                        "label": hex::encode([0x33u8; 32]),
                                        "class": "user",
                                        "sensitivity": "medium",
                                        "retention_hint": 86_400u64,
                                    }],
                                }))
                                .unwrap();
                                return Ok::<_, Infallible>(
                                    HyperResponse::builder()
                                        .status(StatusCode::OK)
                                        .body(Body::from(body))
                                        .unwrap(),
                                );
                            }
                            Ok::<_, Infallible>(
                                HyperResponse::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Body::empty())
                                    .unwrap(),
                            )
                        }
                    }))
                }
            });
            if let Err(err) = Server::from_tcp(listener)?.serve(service).await {
                eprintln!("label-class list test server error: {err}");
            }
            Ok::<_, anyhow::Error>(())
        });

        let url = format!("http://{addr}");
        handle_label_class_list(LabelClassListArgs {
            hub: HubLocatorArgs::from_url(url),
            realm: Some(realm.clone()),
            class: Some("user".to_string()),
            json: true,
        })
        .await?;
        let observed = query_rx.recv().await.expect("query observed");
        assert_eq!(observed, expected_query);
        handle.abort();
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
            hub: HubLocatorArgs::from_url(url.clone()),
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
            hub: HubLocatorArgs::from_url(url.clone()),
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

    #[test]
    fn snapshot_wallet_fold_computes_balance() -> anyhow::Result<()> {
        let account = AccountId::from_slice(&[0x33u8; ACCOUNT_ID_LEN])?;
        let peer = AccountId::from_slice(&[0x44u8; ACCOUNT_ID_LEN])?;
        let messages = vec![
            test_paid_message(1, &account, &peer, 50)?,
            test_paid_message(2, &peer, &account, 20)?,
        ];

        let summary = fold_wallet_ledger_snapshot(&messages, 2, &account)?;
        assert_eq!(summary.account_id, hex::encode(account.as_bytes()));
        assert_eq!(summary.balance, -30);

        let summary_one = fold_wallet_ledger_snapshot(&messages, 1, &account)?;
        assert_eq!(summary_one.balance, -50);
        Ok(())
    }

    #[test]
    fn snapshot_prefix_mmr_matches_manual_fold() -> anyhow::Result<()> {
        let mut messages = Vec::new();
        for seq in 1..=3 {
            messages.push(test_plain_message(seq));
        }

        let mut manual = Mmr::new();
        let mut expected = None;
        for message in &messages {
            let leaf = compute_message_leaf_hash(message)?;
            let (_, root) = manual.append(leaf);
            expected = Some(root);
        }

        let computed = compute_stream_prefix_mmr_root(&messages, 3)?;
        assert_eq!(
            computed.as_bytes(),
            expected.expect("manual root").as_bytes()
        );
        Ok(())
    }

    fn test_paid_message(
        seq: u64,
        payer: &AccountId,
        payee: &AccountId,
        amount: u64,
    ) -> anyhow::Result<StoredMessage> {
        let payload = PaidOperation {
            operation_type: "transfer".to_string(),
            operation_args: CborValue::Null,
            payer_account: *payer,
            payee_account: *payee,
            amount,
            currency_code: Some("USD".to_string()),
            operation_reference: None,
            parent_operation_id: None,
            ttl_seconds: None,
            metadata: None,
        };
        let body = serde_json::to_string(&payload)?;
        Ok(StoredMessage {
            stream: "wallet/demo".to_string(),
            seq,
            sent_at: 1_700_000_000 + seq,
            client_id: "client".to_string(),
            schema: Some(hex::encode(schema_paid_operation())),
            expires_at: None,
            parent: None,
            body: Some(body),
            body_digest: None,
            attachments: Vec::new(),
            auth_ref: None,
            idem: None,
        })
    }

    fn test_plain_message(seq: u64) -> StoredMessage {
        StoredMessage {
            stream: "wallet/demo".to_string(),
            seq,
            sent_at: 1_700_000_000 + seq,
            client_id: format!("client-{seq}"),
            schema: Some("test.schema".to_string()),
            expires_at: None,
            parent: None,
            body: Some(format!("{{\"seq\":{seq}}}")),
            body_digest: None,
            attachments: Vec::new(),
            auth_ref: None,
            idem: None,
        }
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
            hub: HubLocatorArgs::from_url(url.clone()),
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

    #[tokio::test]
    async fn schema_show_fetches_descriptor() -> anyhow::Result<()> {
        let schema_hex = hex::encode([0x42u8; SCHEMA_ID_LEN]);
        let response = RemoteSchemaRegistryEntry {
            ok: true,
            descriptor: Some(RemoteSchemaDescriptorEntry {
                schema_id: schema_hex.clone(),
                name: "test.operation.v1".to_string(),
                version: "1".to_string(),
                doc_url: Some("https://schemas/test".to_string()),
                owner: Some("abcd".to_string()),
                ts: 55,
                created_at: Some(50),
                updated_at: Some(55),
            }),
            usage: Some(RemoteSchemaUsage {
                used_labels: vec!["core/example".to_string()],
                used_count: Some(3),
                first_used_ts: Some(51),
                last_used_ts: Some(55),
            }),
        };
        let body_bytes = serde_json::to_vec(&response)?;
        let path = Box::leak(format!("/schema/{schema_hex}").into_boxed_str());
        let (url, server) = spawn_fixed_response_server(path, body_bytes).await?;
        let client = HubHttpClient::new(Url::parse(&url)?, build_http_client()?);
        let fetched = fetch_schema_registry_entry(&client, &schema_hex).await?;
        server.abort();
        assert_eq!(fetched, response);
        Ok(())
    }

    #[test]
    fn operation_schema_helper_matches_fixture() -> anyhow::Result<()> {
        let fixture_path = test_fixture_path("op_schema_ids.json");
        let data = std::fs::read(&fixture_path)?;
        let fixtures: BTreeMap<String, String> = serde_json::from_slice(&data)?;

        for (name, expected_hex) in fixtures {
            let derived = resolve_operation_schema(&name)?;
            assert_eq!(expected_hex, hex::encode(derived), "schema {name}");
        }

        Ok(())
    }

    #[test]
    fn paid_operation_payload_matches_fixture() -> anyhow::Result<()> {
        let args = sample_paid_operation_args();
        let payload = build_paid_operation_payload(&args)?;
        let fixture_path = test_fixture_path("op_paid_payload_hex.txt");
        let expected_hex = std::fs::read_to_string(&fixture_path)?.trim().to_string();
        let actual_hex = hex::encode(&payload.cbor_body);

        assert!(
            !expected_hex.is_empty(),
            "populate {} with paid operation fixture hex: {}",
            fixture_path.display(),
            actual_hex
        );
        assert_eq!(expected_hex, actual_hex, "paid operation payload changed");

        Ok(())
    }

    fn test_fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join(name)
    }

    fn sample_paid_operation_args() -> OperationPaidArgs {
        OperationPaidArgs {
            hub: HubLocatorArgs {
                hub: None,
                env: None,
                hub_name: None,
            },
            client: PathBuf::from("client.pem"),
            stream: "tenant/core".to_string(),
            operation_type: "ledger.transfer.v1".to_string(),
            payer: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string(),
            payee: "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100".to_string(),
            amount: 1_000_000,
            currency_code: "USD".to_string(),
            operation_args: Some(
                "{\"memo\":\"test payment\",\"tags\":[\"priority\",\"external\"]}".to_string(),
            ),
            ttl_seconds: Some(3_600),
            operation_reference: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
            parent_operation: Some(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            ),
            cap: None,
            json: false,
        }
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

    fn endpoint(&self) -> &Url {
        &self.base_url
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
        let response = Self::ensure_success(path, response).await?;
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
        let response = Self::ensure_success(path, response).await?;
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
        let response = Self::ensure_success(path, response).await?;
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
        Self::ensure_success(path, response).await?;
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
        Self::ensure_success(path, response).await?;
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
        let response = Self::ensure_success(path, response).await?;
        let bytes = response
            .bytes()
            .await
            .context("reading hub response body")?;
        let mut cursor = Cursor::new(bytes.as_ref());
        ciborium::de::from_reader(&mut cursor).context("decoding hub response body")
    }

    async fn ensure_success(path: &str, response: Response) -> Result<Response> {
        if response.status().is_success() {
            Ok(response)
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<failed to decode response>".to_string());
            Err(anyhow::Error::new(HubResponseError::new(
                path, status, body,
            )))
        }
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
    let mut parts = vec![format!("count={}", hist.count), format!("avg={avg:.2}")];
    if let Some(min) = hist.min {
        parts.push(format!("min={min:.2}"));
    }
    if let Some(max) = hist.max {
        parts.push(format!("max={max:.2}"));
    }
    if let Some(p95) = hist.p95 {
        parts.push(format!("p95={p95:.2}"));
    }
    if let Some(p99) = hist.p99 {
        parts.push(format!("p99={p99:.2}"));
    }
    parts.join(" ")
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

async fn write_env_descriptor(path: &Path, descriptor: &EnvDescriptor) -> Result<()> {
    descriptor.validate()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut rng = OsRng;
    let suffix = rng.next_u64();
    let tmp_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!(".{name}.tmp-{suffix:x}"))
        .unwrap_or_else(|| format!(".env.tmp-{suffix:x}"));
    let tmp_path = path.with_file_name(tmp_name);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp_path)
        .await
        .with_context(|| format!("creating {}", tmp_path.display()))?;
    let data = serde_json::to_vec_pretty(descriptor)
        .with_context(|| format!("serialising JSON for {}", path.display()))?;
    file.write_all(&data)
        .await
        .with_context(|| format!("writing {}", tmp_path.display()))?;
    file.flush().await?;
    file.sync_all().await?;
    drop(file);
    if let Err(err) = fs::rename(&tmp_path, path).await {
        let _ = fs::remove_file(&tmp_path).await;
        return Err(err).with_context(|| format!("replacing {}", path.display()));
    }
    Ok(())
}

pub(crate) async fn read_env_descriptor(path: &Path) -> Result<EnvDescriptor> {
    let descriptor: EnvDescriptor = read_json_file(path).await?;
    descriptor.validate()?;
    Ok(descriptor)
}

fn env_descriptor_path(root: &Path, name: &str) -> PathBuf {
    root.join(format!("{name}.env.json"))
}

fn ensure_non_empty_field(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail_usage!("{field} must not be empty", field = field);
    }
    Ok(())
}

fn normalize_hex32_field(value: &str, field: &str) -> Result<String> {
    let trimmed = value.trim().to_ascii_lowercase();
    if trimmed.len() != 64 {
        bail_usage!("{field} must be 64 hex characters", field = field);
    }
    if !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail_usage!(
            "{field} must contain only hexadecimal characters",
            field = field
        );
    }
    Ok(trimmed)
}

fn render_env_descriptor_summary(descriptor: &EnvDescriptor) {
    println!("name: {}", descriptor.name);
    println!("version: {}", descriptor.version);
    println!("cluster_context: {}", descriptor.cluster_context);
    println!("namespace: {}", descriptor.namespace);
    match descriptor
        .description
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        Some(value) => println!("description: {value}"),
        None => println!("description: (none)"),
    }
    if descriptor.hubs.is_empty() {
        println!("hubs: (none)");
    } else {
        println!("hubs:");
        for (name, hub) in descriptor.hubs.iter() {
            let realm = hub.realm_id.as_deref().unwrap_or("(none)");
            println!(
                "  {name}: url={} profile_id={} realm={realm}",
                hub.service_url, hub.profile_id
            );
        }
    }
    if descriptor.tenants.is_empty() {
        println!("tenants: (none)");
    } else {
        println!("tenants:");
        for (tenant, tenant_desc) in descriptor.tenants.iter() {
            println!(
                "  {tenant}: stream_prefix={} label_class={}",
                tenant_desc.stream_prefix, tenant_desc.label_class
            );
        }
    }
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
