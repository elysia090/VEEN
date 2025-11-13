use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

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

async fn handle_keygen(_args: KeygenArgs) -> Result<()> {
    not_implemented("keygen")
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
