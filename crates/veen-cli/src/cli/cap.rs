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
pub(crate) struct CapAuthorizeArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    cap: PathBuf,
}

#[derive(Args)]
pub(crate) struct CapStatusArgs {
    #[command(flatten)]
    hub: HubLocatorArgs,
    #[arg(long)]
    cap: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
pub(crate) struct CapRevocationsArgs {
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
