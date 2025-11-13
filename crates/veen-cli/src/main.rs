use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tokio::fs;
use tracing_subscriber::EnvFilter;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const CLIENT_KEY_VERSION: u8 = 1;

#[derive(Parser)]
#[command(name = "veen-cli", version, about = "Client and admin tooling for VEEN", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new VEEN identity keypair.
    Keygen(KeygenArgs),
    /// Send an encrypted message to a stream.
    Send(SendArgs),
    /// Stream and decrypt messages from the hub.
    Stream(StreamArgs),
    /// Verify a receipt against the local ledger view.
    #[command(name = "verify-receipt")]
    VerifyReceipt(VerifyReceiptArgs),
    /// Send a message with an attachment payload.
    #[command(name = "send-with-attachment")]
    SendWithAttachment(SendWithAttachmentArgs),
    /// Verify an attachment against its commitment.
    #[command(name = "verify-attachment")]
    VerifyAttachment(VerifyAttachmentArgs),
    /// Capability management flows.
    #[command(subcommand)]
    Cap(CapCommands),
    /// Benchmark helpers.
    #[command(subcommand)]
    Bench(BenchCommands),
    /// Resynchronise durable state from the hub.
    Resync(ResyncArgs),
    /// Verify local state against the hub checkpoints.
    #[command(name = "verify-state")]
    VerifyState(VerifyStateArgs),
}

#[derive(Subcommand)]
enum CapCommands {
    /// Issue a capability token.
    Issue(CapIssueArgs),
    /// Authorise a capability token with the hub.
    Authorize(CapAuthorizeArgs),
}

#[derive(Subcommand)]
enum BenchCommands {
    /// Benchmark streaming send throughput.
    Send(BenchSendArgs),
}

#[derive(Args)]
struct KeygenArgs {
    #[arg(long)]
    out: PathBuf,
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
    #[arg(long, value_names = ["MSG", "RECEIPT"], num_args = 2)]
    dump_raw: Option<Vec<PathBuf>>,
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
}

#[derive(Args)]
struct VerifyReceiptArgs {
    #[arg(long)]
    receipt: PathBuf,
    #[arg(long)]
    stream: String,
}

#[derive(Args)]
struct SendWithAttachmentArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long)]
    file: PathBuf,
    #[arg(long, value_names = ["MSG", "RECEIPT"], num_args = 2)]
    dump_raw: Option<Vec<PathBuf>>,
}

#[derive(Args)]
struct VerifyAttachmentArgs {
    #[arg(long)]
    msg: PathBuf,
    #[arg(long)]
    file: PathBuf,
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
    rate: String,
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
struct BenchSendArgs {
    #[arg(long)]
    hub: String,
    #[arg(long)]
    client: PathBuf,
    #[arg(long)]
    stream: String,
    #[arg(long, default_value_t = 1)]
    count: u64,
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

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen(args) => handle_keygen(args).await,
        Commands::Send(args) => handle_send(args).await,
        Commands::Stream(args) => handle_stream(args).await,
        Commands::VerifyReceipt(args) => handle_verify_receipt(args).await,
        Commands::SendWithAttachment(args) => handle_send_with_attachment(args).await,
        Commands::VerifyAttachment(args) => handle_verify_attachment(args).await,
        Commands::Cap(cap) => match cap {
            CapCommands::Issue(args) => handle_cap_issue(args).await,
            CapCommands::Authorize(args) => handle_cap_authorize(args).await,
        },
        Commands::Bench(bench) => match bench {
            BenchCommands::Send(args) => handle_bench_send(args).await,
        },
        Commands::Resync(args) => handle_resync(args).await,
        Commands::VerifyState(args) => handle_verify_state(args).await,
    }
}

fn init_tracing() {
    let subscriber = tracing_subscriber::fmt().with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    );
    let _ = subscriber.try_init();
}

async fn handle_keygen(args: KeygenArgs) -> Result<()> {
    let private_path = args.out;
    let public_path = derive_public_path(&private_path);

    ensure_parent_dir(&private_path).await?;
    ensure_parent_dir(&public_path).await?;
    ensure_absent(&private_path).await?;
    ensure_absent(&public_path).await?;

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

    write_cbor_file(&private_path, &secret_bundle)
        .await
        .with_context(|| format!("writing private key material to {}", private_path.display()))?;
    restrict_private_permissions(&private_path).await?;
    write_cbor_file(&public_path, &public_bundle)
        .await
        .with_context(|| format!("writing public identity to {}", public_path.display()))?;

    tracing::info!(
        client_id = %hex::encode(client_id_bytes),
        private = %private_path.display(),
        public = %public_path.display(),
        "generated VEEN client identity",
    );

    Ok(())
}

async fn handle_send(_args: SendArgs) -> Result<()> {
    not_implemented("send")
}

async fn handle_stream(_args: StreamArgs) -> Result<()> {
    not_implemented("stream")
}

async fn handle_verify_receipt(_args: VerifyReceiptArgs) -> Result<()> {
    not_implemented("verify-receipt")
}

async fn handle_send_with_attachment(_args: SendWithAttachmentArgs) -> Result<()> {
    not_implemented("send-with-attachment")
}

async fn handle_verify_attachment(_args: VerifyAttachmentArgs) -> Result<()> {
    not_implemented("verify-attachment")
}

async fn handle_cap_issue(_args: CapIssueArgs) -> Result<()> {
    not_implemented("cap issue")
}

async fn handle_cap_authorize(_args: CapAuthorizeArgs) -> Result<()> {
    not_implemented("cap authorize")
}

async fn handle_bench_send(_args: BenchSendArgs) -> Result<()> {
    not_implemented("bench send")
}

async fn handle_resync(_args: ResyncArgs) -> Result<()> {
    not_implemented("resync")
}

async fn handle_verify_state(_args: VerifyStateArgs) -> Result<()> {
    not_implemented("verify-state")
}

fn not_implemented(command: &str) -> Result<()> {
    let placeholder_stream = veen_core::StreamId::new([0u8; 32]);
    tracing::debug!(command = command, placeholder_stream = %placeholder_stream, "invoked VEEN CLI scaffold");
    bail!(
        "`veen-cli {command}` is a scaffold. Implement the end-to-end workflow described in doc/GOALS.txt to make this command functional."
    );
}

async fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating directory {}", parent.display()))?;
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

fn derive_public_path(private_path: &Path) -> PathBuf {
    let mut stem = OsString::from(private_path.as_os_str());
    stem.push(".pub");
    PathBuf::from(stem)
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
