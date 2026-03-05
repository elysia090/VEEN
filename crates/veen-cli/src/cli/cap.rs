use super::*;

#[derive(Subcommand)]
pub(crate) enum CapCommand {
    /// Issue a capability token.
    Issue(CapIssueArgs),
    /// Authorize a capability token with the hub (non-core tooling endpoint).
    Authorize(CapAuthorizeArgs),
    /// Inspect hub view for a capability token (non-core tooling endpoint).
    Status(CapStatusArgs),
    /// Publish a revocation record via the capability surface.
    Revoke(RevokePublishArgs),
    /// Inspect revocation records.
    Revocations(CapRevocationsArgs),
}

#[derive(Args)]
pub(crate) struct CapIssueArgs {
    /// Issuer client identity directory.
    #[arg(long)]
    pub(crate) issuer: PathBuf,
    /// Subject client identity directory.
    #[arg(long)]
    pub(crate) subject: PathBuf,
    /// Stream name this capability applies to.
    #[arg(long)]
    pub(crate) stream: String,
    /// Capability time-to-live in seconds.
    #[arg(long)]
    pub(crate) ttl: u64,
    /// Optional rate limit as <ops>/<seconds> (for example: 10/1).
    #[arg(long)]
    pub(crate) rate: Option<String>,
    /// Output file path for the encoded capability token.
    #[arg(long)]
    pub(crate) out: PathBuf,
}

#[derive(Args)]
pub(crate) struct CapAuthorizeArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    /// Capability token file.
    #[arg(long)]
    pub(crate) cap: PathBuf,
}

#[derive(Args)]
pub(crate) struct CapStatusArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    /// Capability token file.
    #[arg(long)]
    pub(crate) cap: PathBuf,
    /// Emit machine-readable JSON output.
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct CapRevocationsArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    /// Filter by revocation kind.
    #[arg(long, value_enum)]
    pub(crate) kind: Option<RevocationKindValue>,
    /// Return entries with ts >= this Unix timestamp.
    #[arg(long)]
    pub(crate) since: Option<u64>,
    /// Return only currently-active revocations.
    #[arg(long)]
    pub(crate) active_only: bool,
    /// Maximum number of revocation rows to return.
    #[arg(long)]
    pub(crate) limit: Option<u64>,
    /// Emit machine-readable JSON output.
    #[arg(long)]
    pub(crate) json: bool,
}
