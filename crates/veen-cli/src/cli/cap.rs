use super::*;

#[derive(Subcommand)]
pub(crate) enum CapCommand {
    /// Issue a capability token.
    Issue(CapIssueArgs),
    /// Authorise a capability token with the hub (non-core tooling endpoint).
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
    #[arg(long)]
    pub(crate) issuer: PathBuf,
    #[arg(long)]
    pub(crate) subject: PathBuf,
    #[arg(long)]
    pub(crate) stream: String,
    #[arg(long)]
    pub(crate) ttl: u64,
    #[arg(long)]
    pub(crate) rate: Option<String>,
    #[arg(long)]
    pub(crate) out: PathBuf,
}

#[derive(Args)]
pub(crate) struct CapAuthorizeArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) cap: PathBuf,
}

#[derive(Args)]
pub(crate) struct CapStatusArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long)]
    pub(crate) cap: PathBuf,
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Args)]
pub(crate) struct CapRevocationsArgs {
    #[command(flatten)]
    pub(crate) hub: HubLocatorArgs,
    #[arg(long, value_enum)]
    pub(crate) kind: Option<RevocationKindValue>,
    #[arg(long)]
    pub(crate) since: Option<u64>,
    #[arg(long)]
    pub(crate) active_only: bool,
    #[arg(long)]
    pub(crate) limit: Option<u64>,
    #[arg(long)]
    pub(crate) json: bool,
}
