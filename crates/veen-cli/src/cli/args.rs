use super::*;

macro_rules! bail_usage {
    ($($arg:tt)*) => {{
        return Err(anyhow::Error::new(CliUsageError::new(format!($($arg)*))));
    }};
}

#[derive(Subcommand)]
pub(crate) enum Command {
    /// Hub lifecycle and tooling commands (non-core endpoints).
    #[cfg(feature = "hub")]
    #[command(subcommand)]
    Hub(HubCommand),
    /// Show help for a command or subcommand.
    Help(HelpArgs),
    /// Generate a new VEEN client identity bundle.
    Keygen(KeygenArgs),
    /// Inspect or rotate client identity material.
    #[command(subcommand)]
    Id(IdCommand),
    /// Send a message to a stream.
    #[command(
        after_long_help = "Examples:\n  veen send --hub http://127.0.0.1:8080 --client ./client --stream demo/main --body 'hello'\n  veen send --env ./demo.env.json --hub-name primary --client ./client --stream tenant-a/chat --body '{\"op\":\"ping\"}'"
    )]
    Send(SendArgs),
    /// Authorize a capability token with the hub (non-core tooling endpoint).
    Authorize(CapAuthorizeArgs),
    /// Stream messages from the hub.
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
    #[command(subcommand, visible_alias = "op")]
    Operation(OperationCommand),
    /// Recovery procedure helpers.
    #[command(subcommand)]
    Recovery(RecoveryCommand),
    /// Revocation helpers.
    #[command(subcommand)]
    Revoke(RevokeCommand),
    /// Resynchronise durable state from the hub (non-core tooling endpoint).
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
    #[cfg(feature = "selftest")]
    #[command(subcommand)]
    Selftest(SelftestCommand),
    /// Environment descriptor helpers.
    #[command(subcommand)]
    Env(EnvCommand),
    /// Render Kubernetes manifests for VEEN profiles.
    #[cfg(feature = "kube")]
    #[command(subcommand)]
    Kube(KubeCommand),
    /// Audit and compliance helpers.
    #[command(subcommand)]
    Audit(AuditCommand),
}

#[derive(Debug, Args)]
pub(crate) struct HelpArgs {
    /// Command path to inspect (for example: `hub start`).
    #[arg(value_name = "COMMAND", num_args = 0.., trailing_var_arg = true)]
    pub(crate) command: Vec<String>,
}

#[derive(Subcommand)]
pub(crate) enum EnvCommand {
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
pub(crate) enum AuditCommand {
    /// Inspect query audit messages for a stream.
    Queries(AuditQueriesArgs),
    /// Summarise schemas and audit coverage for known streams.
    Summary(AuditSummaryArgs),
    /// Evaluate audit enforcement policy files.
    #[command(name = "enforce-check")]
    EnforceCheck(AuditEnforceCheckArgs),
}

#[derive(Subcommand)]
pub(crate) enum IdCommand {
    /// Show a client identity summary.
    Show(IdShowArgs),
    /// Rotate the client identifier key material.
    Rotate(IdRotateArgs),
    /// Inspect client identifier usage statistics.
    Usage(IdUsageArgs),
}

#[derive(Subcommand)]
pub(crate) enum AttachmentCommand {
    /// Verify an attachment against a stored message bundle.
    Verify(AttachmentVerifyArgs),
}

#[derive(Subcommand)]
pub(crate) enum RpcCommand {
    /// Invoke an RPC method through VEEN messaging flows.
    Call(RpcCallArgs),
}

#[derive(Subcommand)]
pub(crate) enum CrdtCommand {
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
pub(crate) enum FedCommand {
    /// Federation authority helpers.
    #[command(subcommand)]
    Authority(FedAuthorityCommand),
}

#[derive(Subcommand)]
pub(crate) enum FedAuthorityCommand {
    /// Publish an authority record for a stream.
    Publish(FedAuthorityPublishArgs),
    /// Show the active authority record for a stream.
    Show(FedAuthorityShowArgs),
}

#[derive(Subcommand)]
pub(crate) enum FederateCommand {
    /// Describe the work required to mirror a stream between hubs.
    #[command(name = "mirror-plan")]
    MirrorPlan(FederateMirrorPlanArgs),
    /// Execute a mirror plan by copying receipts into the target hub.
    #[command(name = "mirror-run")]
    MirrorRun(FederateMirrorRunArgs),
}

#[derive(Subcommand)]
pub(crate) enum LabelCommand {
    /// Inspect label authority information.
    Authority(LabelAuthorityArgs),
}

#[derive(Subcommand)]
pub(crate) enum LabelClassCommand {
    /// Publish a label classification record.
    Set(LabelClassSetArgs),
    /// Show the effective label classification for a label.
    Show(LabelClassShowArgs),
    /// List known label classifications.
    List(LabelClassListArgs),
}

#[derive(Subcommand)]
pub(crate) enum SchemaCommand {
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
pub(crate) enum WalletCommand {
    /// Emit a wallet transfer event.
    Transfer(WalletTransferArgs),
    /// Fold paid operations into account balances.
    Ledger(WalletLedgerArgs),
}

#[derive(Subcommand)]
pub(crate) enum AgreementCommand {
    /// Show agreement activity and party decisions.
    Status(AgreementStatusArgs),
}

#[derive(Subcommand)]
pub(crate) enum SnapshotCommand {
    /// Verify folded state against a state.checkpoint.v1 record.
    Verify(SnapshotVerifyArgs),
}

#[derive(Subcommand)]
pub(crate) enum OperationCommand {
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
pub(crate) enum RecoveryCommand {
    /// Show the recovery timeline for an identity.
    Timeline(RecoveryTimelineArgs),
}

#[derive(Subcommand)]
pub(crate) enum RevokeCommand {
    /// Publish a revocation record.
    Publish(RevokePublishArgs),
}

#[derive(Subcommand)]
pub(crate) enum PowCommand {
    /// Request a proof-of-work challenge from a hub (non-core tooling endpoint).
    Request(PowRequestArgs),
    /// Solve a proof-of-work challenge locally.
    Solve(PowSolveArgs),
}

#[derive(Subcommand)]
pub(crate) enum CrdtLwwCommand {
    /// Update a key within an LWW register.
    Set(CrdtLwwSetArgs),
    /// Fetch the current value from an LWW register.
    Get(CrdtLwwGetArgs),
}

#[derive(Subcommand)]
pub(crate) enum CrdtOrsetCommand {
    /// Add an element to an OR-set.
    Add(CrdtOrsetAddArgs),
    /// Remove an element from an OR-set.
    Remove(CrdtOrsetRemoveArgs),
    /// List the contents of an OR-set.
    List(CrdtOrsetListArgs),
}

#[derive(Subcommand)]
pub(crate) enum CrdtCounterCommand {
    /// Add a delta to a grow-only counter.
    Add(CrdtCounterAddArgs),
    /// Fetch the value of a grow-only counter.
    Get(CrdtCounterGetArgs),
}

#[derive(Subcommand)]
pub(crate) enum AnchorCommand {
    /// Request that the hub publishes an anchor for a stream.
    Publish(AnchorPublishArgs),
    /// Verify a checkpoint anchor reference.
    Verify(AnchorVerifyArgs),
}

#[derive(Subcommand)]
pub(crate) enum RetentionCommand {
    /// Show configured on-disk retention for a hub data directory.
    Show(RetentionShowArgs),
    /// Configure on-disk retention for a hub data directory.
    Set(RetentionSetArgs),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RetentionValue {
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

#[derive(Debug, Clone, Default, Args)]
pub(crate) struct HubLocatorArgs {
    /// Hub URL or local data directory path.
    #[arg(long, value_name = "URL|PATH", env = "VEEN_HUB")]
    pub(crate) hub: Option<String>,
    /// Environment descriptor file to resolve hub from.
    #[arg(long, value_name = "PATH", env = "VEEN_ENV", requires = "hub_name")]
    pub(crate) env: Option<PathBuf>,
    /// Hub name within the environment descriptor.
    #[arg(long = "hub-name", value_name = "NAME", requires = "env")]
    pub(crate) hub_name: Option<String>,
}

impl HubLocatorArgs {
    #[cfg(test)]
    pub(crate) fn from_url(url: String) -> Self {
        Self {
            hub: Some(url),
            env: None,
            hub_name: None,
        }
    }
}

#[derive(Args)]
pub(crate) struct KeygenArgs {
    /// Output path for the generated client identity bundle.
    #[arg(long)]
    pub(crate) out: PathBuf,
}

#[derive(Args)]
pub(crate) struct IdShowArgs {
    /// Path to the client identity bundle.
    #[arg(long)]
    pub(crate) client: PathBuf,
}

#[derive(Args)]
pub(crate) struct IdRotateArgs {
    /// Path to the client identity bundle.
    #[arg(long)]
    pub(crate) client: PathBuf,
}

#[derive(Args)]
pub(crate) struct IdUsageArgs {
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct SendArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    /// Path to the client identity bundle.
    #[arg(long)]
    pub(crate) client: PathBuf,
    /// Target stream name.
    #[arg(long)]
    pub(crate) stream: String,
    /// Message body (plain text or JSON).
    #[arg(long)]
    pub(crate) body: String,
    /// Schema identifier to tag the message with.
    #[arg(long, value_name = "HEX32")]
    pub(crate) schema: Option<String>,
    /// Message expiration as a UNIX timestamp.
    #[arg(long, value_name = "UNIX_TS")]
    pub(crate) expires_at: Option<u64>,
    /// Capability token file to attach for authorization.
    #[arg(long)]
    pub(crate) cap: Option<PathBuf>,
    /// Parent message reference (for threading).
    #[arg(long)]
    pub(crate) parent: Option<String>,
    /// Files to attach to the message.
    #[arg(long)]
    pub(crate) attach: Vec<PathBuf>,
    /// Skip persisting the message body locally.
    #[arg(long)]
    pub(crate) no_store_body: bool,
    /// Solve or supply a proof-of-work cookie requiring this difficulty (bits).
    #[arg(long, value_name = "BITS")]
    pub(crate) pow_difficulty: Option<u8>,
    /// Hex-encoded challenge to solve or re-use (requires --pow-difficulty).
    #[arg(long, value_name = "HEX", requires = "pow_difficulty")]
    pub(crate) pow_challenge: Option<String>,
    /// Pre-computed nonce for the supplied challenge (requires --pow-difficulty and --pow-challenge).
    #[arg(long, value_name = "NONCE", requires_all = ["pow_difficulty", "pow_challenge"])]
    pub(crate) pow_nonce: Option<u64>,
}

#[derive(Args)]
pub(crate) struct EnvInitArgs {
    #[arg(long)]
    pub(crate) root: PathBuf,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long, value_name = "CONTEXT")]
    pub(crate) cluster_context: String,
    #[arg(long)]
    pub(crate) namespace: String,
    #[arg(long)]
    pub(crate) description: Option<String>,
}

#[derive(Args)]
pub(crate) struct EnvAddHubArgs {
    #[arg(long)]
    pub(crate) env: PathBuf,
    #[arg(long = "hub-name")]
    pub(crate) hub_name: String,
    #[arg(long)]
    pub(crate) service_url: String,
    #[arg(long, value_name = "HEX32")]
    pub(crate) profile_id: String,
    #[arg(long, value_name = "HEX32")]
    pub(crate) realm: Option<String>,
}

#[derive(ValueEnum, Clone, Debug)]
pub(crate) enum EnvTenantLabelClass {
    User,
    Wallet,
    Log,
    Admin,
    Bulk,
}

impl EnvTenantLabelClass {
    pub(crate) fn as_str(&self) -> &'static str {
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
pub(crate) struct EnvAddTenantArgs {
    #[arg(long)]
    pub(crate) env: PathBuf,
    #[arg(long = "tenant-id")]
    pub(crate) tenant_id: String,
    #[arg(long = "stream-prefix")]
    pub(crate) stream_prefix: String,
    #[arg(long = "label-class", value_enum)]
    pub(crate) label_class: Option<EnvTenantLabelClass>,
}

#[derive(Args)]
pub(crate) struct EnvShowArgs {
    #[arg(long)]
    pub(crate) env: PathBuf,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct AuditQueriesArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long = "resource-prefix")]
    pub(crate) resource_prefix: Option<String>,
    #[arg(long, value_name = "UNIX_TIME")]
    pub(crate) since: Option<u64>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct AuditSummaryArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) env: Option<PathBuf>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct AuditEnforceCheckArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long = "policy-file")]
    pub(crate) policy_files: Vec<PathBuf>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct EnvDescriptor {
    pub(crate) version: u64,
    pub(crate) name: String,
    pub(crate) cluster_context: String,
    pub(crate) namespace: String,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) hubs: BTreeMap<String, EnvHubDescriptor>,
    #[serde(default)]
    pub(crate) tenants: BTreeMap<String, EnvTenantDescriptor>,
}

impl EnvDescriptor {
    pub(crate) fn validate(&self) -> Result<()> {
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
    pub(crate) service_url: String,
    pub(crate) profile_id: String,
    #[serde(default)]
    pub(crate) realm_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct EnvTenantDescriptor {
    pub(crate) stream_prefix: String,
    pub(crate) label_class: String,
}

#[derive(Args)]
pub(crate) struct StreamArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    /// Path to the client identity bundle.
    #[arg(long)]
    pub(crate) client: PathBuf,
    /// Stream name to read from.
    #[arg(long)]
    pub(crate) stream: String,
    /// Sequence number to start reading from (default: 0).
    #[arg(long, default_value_t = 0)]
    pub(crate) from: u64,
    /// Sequence number to stop reading at (inclusive).
    #[arg(long)]
    pub(crate) to: Option<u64>,
    /// Include Merkle inclusion proofs in the output.
    #[arg(long)]
    pub(crate) with_proof: bool,
}

#[derive(Args)]
pub(crate) struct AttachmentVerifyArgs {
    #[arg(long)]
    pub(crate) msg: PathBuf,
    #[arg(long)]
    pub(crate) file: PathBuf,
    #[arg(long)]
    pub(crate) index: u64,
}

#[derive(Args)]
pub(crate) struct FedAuthorityPublishArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) signer: PathBuf,
    #[arg(long)]
    pub(crate) realm: String,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long, value_enum, default_value_t = AuthorityPolicyValue::SinglePrimary)]
    pub(crate) policy: AuthorityPolicyValue,
    #[arg(long = "primary-hub")]
    pub(crate) primary_hub: String,
    #[arg(long = "replica-hub")]
    pub(crate) replica_hubs: Vec<String>,
    #[arg(long)]
    pub(crate) ttl: Option<u64>,
    #[arg(long)]
    pub(crate) ts: Option<u64>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub(crate) enum AuthorityPolicyValue {
    SinglePrimary,
    MultiPrimary,
}

#[derive(Args)]
pub(crate) struct FedAuthorityShowArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long, value_name = "HEX32")]
    pub(crate) realm: String,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args, Clone)]
pub(crate) struct FederateMirrorPlanArgs {
    #[arg(long, value_name = "URL")]
    pub(crate) source: String,
    #[arg(long, value_name = "URL")]
    pub(crate) target: String,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long, value_name = "SEQ")]
    pub(crate) from: Option<u64>,
    #[arg(long, value_name = "SEQ")]
    pub(crate) upto: Option<u64>,
    #[arg(long = "label-map", value_name = "SRC=TARGET")]
    pub(crate) label_map: Vec<String>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args, Clone)]
pub(crate) struct FederateMirrorRunArgs {
    #[command(flatten)]
    pub(crate) plan: FederateMirrorPlanArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) cap: Option<PathBuf>,
}

#[derive(Args)]
pub(crate) struct LabelAuthorityArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long, value_name = "HEX32")]
    pub(crate) label: String,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct LabelClassSetArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) signer: PathBuf,
    /// Explicit label identifier (hex-encoded).
    #[arg(
        long = "label",
        value_name = "HEX32",
        required_unless_present = "stream",
        conflicts_with = "stream"
    )]
    pub(crate) label_hex: Option<String>,
    /// Stream label used to derive the label identifier.
    #[arg(
        long,
        value_name = "STREAM",
        required_unless_present = "label_hex",
        conflicts_with = "label_hex"
    )]
    pub(crate) stream: Option<String>,
    #[arg(long)]
    pub(crate) class: String,
    #[arg(long)]
    pub(crate) sensitivity: Option<String>,
    #[arg(long = "retention-hint")]
    pub(crate) retention_hint: Option<u64>,
}

#[derive(Args)]
pub(crate) struct LabelClassShowArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    /// Hex-encoded label identifier.
    #[arg(
        long = "label",
        value_name = "HEX32",
        required_unless_present = "stream",
        conflicts_with = "stream"
    )]
    pub(crate) label_hex: Option<String>,
    /// Stream label used to derive the label identifier.
    #[arg(
        long,
        value_name = "STREAM",
        required_unless_present = "label_hex",
        conflicts_with = "label_hex"
    )]
    pub(crate) stream: Option<String>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct LabelClassListArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) class: Option<String>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct SchemaIdArgs {
    /// Schema name used for hashing.
    pub(crate) name: String,
}

#[derive(Args)]
pub(crate) struct SchemaRegisterArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) signer: PathBuf,
    #[arg(long = "schema-id")]
    pub(crate) schema_id: String,
    #[arg(long)]
    pub(crate) name: String,
    #[arg(long)]
    pub(crate) version: String,
    #[arg(long = "doc-url")]
    pub(crate) doc_url: Option<String>,
    #[arg(long)]
    pub(crate) owner: Option<String>,
    #[arg(long)]
    pub(crate) ts: Option<u64>,
}

#[derive(Args)]
pub(crate) struct SchemaShowArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long = "schema-id", value_name = "HEX32")]
    pub(crate) schema_id: String,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct SchemaListArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
}

#[derive(Args)]
pub(crate) struct WalletTransferArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) signer: PathBuf,
    #[arg(long = "wallet-id")]
    pub(crate) wallet_id: String,
    #[arg(long = "to-wallet-id")]
    pub(crate) to_wallet_id: String,
    #[arg(long)]
    pub(crate) amount: u64,
    #[arg(long)]
    pub(crate) ts: Option<u64>,
    #[arg(long = "transfer-id")]
    pub(crate) transfer_id: Option<String>,
    #[arg(long)]
    pub(crate) metadata: Option<String>,
}

#[derive(Args)]
pub(crate) struct WalletLedgerArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long = "since-stream-seq", default_value_t = 1)]
    pub(crate) since_stream_seq: u64,
    #[arg(long = "upto-stream-seq")]
    pub(crate) upto_stream_seq: Option<u64>,
    #[arg(long, value_name = "HEX32")]
    pub(crate) account: Option<String>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct AgreementStatusArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long = "agreement-id", value_name = "HEX32")]
    pub(crate) agreement_id: String,
    #[arg(long)]
    pub(crate) version: Option<u64>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct RecoveryTimelineArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long = "target-identity", value_name = "HEX32")]
    pub(crate) target_identity: String,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct SnapshotVerifyArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long = "state-id", value_name = "HEX32")]
    pub(crate) state_id: String,
    #[arg(long = "upto-stream-seq", value_name = "SEQ")]
    pub(crate) upto_stream_seq: u64,
    #[arg(long = "state-class", value_name = "CLASS_NAME")]
    pub(crate) state_class: String,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct OperationIdArgs {
    #[arg(long)]
    pub(crate) bundle: PathBuf,
}

#[derive(Args)]
pub(crate) struct OperationSendArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long = "schema-name")]
    pub(crate) schema_name: String,
    #[arg(long = "body-json")]
    pub(crate) body_json: String,
    #[arg(long)]
    pub(crate) cap: Option<PathBuf>,
    #[arg(long = "expires-at", value_name = "UNIX_TS")]
    pub(crate) expires_at: Option<u64>,
    #[arg(long = "parent-id", value_name = "HEX32")]
    pub(crate) parent_id: Option<String>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct OperationPaidArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long = "op-type")]
    pub(crate) operation_type: String,
    #[arg(long = "payer", value_name = "HEX32")]
    pub(crate) payer: String,
    #[arg(long = "payee", value_name = "HEX32")]
    pub(crate) payee: String,
    #[arg(long)]
    pub(crate) amount: u64,
    #[arg(long = "currency-code")]
    pub(crate) currency_code: String,
    #[arg(long = "op-args-json")]
    pub(crate) operation_args: Option<String>,
    #[arg(long = "ttl-seconds")]
    pub(crate) ttl_seconds: Option<u64>,
    #[arg(long = "op-ref", value_name = "HEX32")]
    pub(crate) operation_reference: Option<String>,
    #[arg(long = "parent-op", value_name = "HEX32")]
    pub(crate) parent_operation: Option<String>,
    #[arg(long)]
    pub(crate) cap: Option<PathBuf>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct OperationAccessGrantArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long = "admin")]
    pub(crate) admin: PathBuf,
    #[arg(long = "subject-identity", value_name = "HEX32")]
    pub(crate) subject_identity: String,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long = "expiry-time", value_name = "UNIX_TS")]
    pub(crate) expiry_time: u64,
    #[arg(long = "allowed-stream", value_name = "HEX32")]
    pub(crate) allowed_streams: Vec<String>,
    #[arg(long = "max-rate-per-second")]
    pub(crate) max_rate_per_second: Option<u64>,
    #[arg(long = "max-burst")]
    pub(crate) max_burst: Option<u64>,
    #[arg(long = "max-amount")]
    pub(crate) max_amount: Option<u64>,
    #[arg(long = "currency-code")]
    pub(crate) currency_code: Option<String>,
    #[arg(long = "reason")]
    pub(crate) reason: Option<String>,
    #[arg(long = "parent-op", value_name = "HEX32")]
    pub(crate) parent_operation: Option<String>,
}

#[derive(Args)]
pub(crate) struct OperationAccessRevokeArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long = "admin")]
    pub(crate) admin: PathBuf,
    #[arg(long = "subject-identity", value_name = "HEX32")]
    pub(crate) subject_identity: String,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long = "target-cap-ref", value_name = "HEX32")]
    pub(crate) target_capability_reference: Option<String>,
    #[arg(long = "reason")]
    pub(crate) reason: Option<String>,
    #[arg(long = "parent-op", value_name = "HEX32")]
    pub(crate) parent_operation: Option<String>,
}

#[derive(Args)]
pub(crate) struct OperationDelegatedArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long = "principal", value_name = "HEX32")]
    pub(crate) principal: String,
    #[arg(long = "agent", value_name = "HEX32")]
    pub(crate) agent: String,
    #[arg(
        long = "delegation-cap",
        value_name = "HEX32",
        value_delimiter = ',',
        num_args = 1..
    )]
    pub(crate) delegation_caps: Vec<String>,
    #[arg(long = "operation-schema-id", value_name = "HEX32")]
    pub(crate) operation_schema_id: String,
    #[arg(long = "operation-body-json")]
    pub(crate) operation_body_json: String,
    #[arg(long = "parent-op", value_name = "HEX32")]
    pub(crate) parent_operation: Option<String>,
}

#[derive(Args)]
pub(crate) struct OperationRecoveryRequestArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long = "target-identity", value_name = "HEX32")]
    pub(crate) target_identity: String,
    #[arg(long = "requested-new-identity", value_name = "HEX32")]
    pub(crate) requested_new_identity: String,
    #[arg(long)]
    pub(crate) reason: Option<String>,
    #[arg(long = "request-time", value_name = "UNIX_TS")]
    pub(crate) request_time: Option<u64>,
    #[arg(long = "metadata-json")]
    pub(crate) metadata_json: Option<String>,
    #[arg(long)]
    pub(crate) cap: Option<PathBuf>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct OperationRecoveryApprovalArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long = "target-identity", value_name = "HEX32")]
    pub(crate) target_identity: String,
    #[arg(long = "requested-new-identity", value_name = "HEX32")]
    pub(crate) requested_new_identity: String,
    #[arg(long = "guardian-identity", value_name = "HEX32")]
    pub(crate) guardian_identity: String,
    #[arg(long = "policy-group-id", value_name = "HEX32")]
    pub(crate) policy_group_id: Option<String>,
    #[arg(long)]
    pub(crate) decision: String,
    #[arg(long = "decision-time", value_name = "UNIX_TS")]
    pub(crate) decision_time: Option<u64>,
    #[arg(long = "parent-op", value_name = "HEX32")]
    pub(crate) parent_operation: Option<String>,
    #[arg(long = "metadata-json")]
    pub(crate) metadata_json: Option<String>,
    #[arg(long)]
    pub(crate) cap: Option<PathBuf>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct OperationRecoveryExecutionArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long = "target-identity", value_name = "HEX32")]
    pub(crate) target_identity: String,
    #[arg(long = "new-identity", value_name = "HEX32")]
    pub(crate) new_identity: String,
    #[arg(
        long = "approval-ref",
        value_name = "HEX32",
        value_delimiter = ',',
        num_args = 1..
    )]
    pub(crate) approval_references: Vec<String>,
    #[arg(long = "applied-time", value_name = "UNIX_TS")]
    pub(crate) applied_time: Option<u64>,
    #[arg(long = "metadata-json")]
    pub(crate) metadata_json: Option<String>,
    #[arg(long)]
    pub(crate) cap: Option<PathBuf>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub(crate) enum RevocationKindValue {
    #[clap(name = "client-id")]
    ClientId,
    #[clap(name = "auth-ref")]
    AuthRef,
    #[clap(name = "cap-token")]
    CapToken,
}

impl RevocationKindValue {
    pub(crate) fn as_str(&self) -> &'static str {
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
pub(crate) struct RevokePublishArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) signer: PathBuf,
    #[arg(long, value_enum)]
    pub(crate) kind: RevocationKindValue,
    #[arg(long)]
    pub(crate) target: String,
    #[arg(long)]
    pub(crate) reason: Option<String>,
    #[arg(long)]
    pub(crate) ttl: Option<u64>,
    #[arg(long)]
    pub(crate) ts: Option<u64>,
}

#[derive(Args)]
pub(crate) struct PowRequestArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long, value_name = "BITS")]
    pub(crate) difficulty: Option<u8>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct PowSolveArgs {
    #[arg(long, value_name = "HEX")]
    pub(crate) challenge: String,
    #[arg(long, value_name = "BITS")]
    pub(crate) difficulty: u8,
    #[arg(long)]
    pub(crate) max_iterations: Option<u64>,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct ResyncArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
}

#[derive(Args)]
pub(crate) struct VerifyStateArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
}

#[derive(Args)]
pub(crate) struct ExplainErrorArgs {
    #[arg(value_name = "CODE")]
    pub(crate) code: String,
}

#[derive(Args)]
pub(crate) struct RpcCallArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long)]
    pub(crate) method: String,
    #[arg(long)]
    pub(crate) args: String,
    #[arg(long, value_name = "MS")]
    pub(crate) timeout_ms: Option<u64>,
    #[arg(long)]
    pub(crate) idem: Option<u64>,
    /// Solve or supply a proof-of-work cookie requiring this difficulty (bits).
    #[arg(long, value_name = "BITS")]
    pub(crate) pow_difficulty: Option<u8>,
    /// Hex-encoded challenge to solve or re-use (requires --pow-difficulty).
    #[arg(long, value_name = "HEX", requires = "pow_difficulty")]
    pub(crate) pow_challenge: Option<String>,
    /// Pre-computed nonce for the supplied challenge (requires --pow-difficulty and --pow-challenge).
    #[arg(long, value_name = "NONCE", requires_all = ["pow_difficulty", "pow_challenge"])]
    pub(crate) pow_nonce: Option<u64>,
}

#[derive(Args)]
pub(crate) struct CrdtLwwSetArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long)]
    pub(crate) key: String,
    #[arg(long)]
    pub(crate) value: String,
    #[arg(long)]
    pub(crate) ts: Option<u64>,
}

#[derive(Args)]
pub(crate) struct CrdtLwwGetArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long)]
    pub(crate) key: String,
}

#[derive(Args)]
pub(crate) struct CrdtOrsetAddArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long)]
    pub(crate) elem: String,
}

#[derive(Args)]
pub(crate) struct CrdtOrsetRemoveArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long)]
    pub(crate) elem: String,
}

#[derive(Args)]
pub(crate) struct CrdtOrsetListArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
}

#[derive(Args)]
pub(crate) struct CrdtCounterAddArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long)]
    pub(crate) delta: u64,
}

#[derive(Args)]
pub(crate) struct CrdtCounterGetArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) client: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
}

#[derive(Args)]
pub(crate) struct AnchorPublishArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long)]
    pub(crate) epoch: Option<u64>,
    #[arg(long)]
    pub(crate) ts: Option<u64>,
    #[arg(long, value_name = "HEX")]
    pub(crate) nonce: Option<String>,
}

#[derive(Args)]
pub(crate) struct AnchorVerifyArgs {
    #[arg(long)]
    pub(crate) checkpoint: PathBuf,
}

#[derive(Args)]
pub(crate) struct RetentionShowArgs {
    #[arg(long, value_name = "DIR")]
    pub(crate) data_dir: PathBuf,
}

#[derive(Args, Clone, Debug)]
pub(crate) struct RetentionSetArgs {
    /// Hub data directory containing retention configuration.
    #[arg(long, value_name = "DIR")]
    pub(crate) data_dir: PathBuf,
    /// Retention window for receipts (seconds or "indefinite").
    #[arg(long, value_name = "SECONDS|indefinite")]
    pub(crate) receipts: Option<RetentionValue>,
    /// Retention window for payloads (seconds or "indefinite").
    #[arg(long, value_name = "SECONDS|indefinite")]
    pub(crate) payloads: Option<RetentionValue>,
    /// Retention window for checkpoints (seconds or "indefinite").
    #[arg(long, value_name = "SECONDS|indefinite")]
    pub(crate) checkpoints: Option<RetentionValue>,
}
