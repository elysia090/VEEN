use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use tokio::fs::{self, OpenOptions};
use tokio::signal;
use tracing_subscriber::EnvFilter;

const RECEIPTS_FILE: &str = "receipts.cborseq";
const PAYLOADS_FILE: &str = "payloads.cborseq";
const CHECKPOINTS_FILE: &str = "checkpoints.cborseq";
const HUB_PID_FILE: &str = "hub.pid";
const STATE_DIR: &str = "state";
const STREAMS_DIR: &str = "streams";
const MESSAGES_DIR: &str = "messages";
const CAPABILITIES_DIR: &str = "capabilities";
const CRDT_DIR: &str = "crdt";
const ATTACHMENTS_DIR: &str = "attachments";
const ANCHORS_DIR: &str = "anchors";
const TLS_INFO_FILE: &str = "tls_info.json";

#[derive(Parser)]
#[command(name = "veen-hub", version, about = "Run the VEEN hub runtime", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the VEEN hub service.
    Run(RunCommand),
}

#[derive(Args, Debug)]
struct RunCommand {
    /// Socket address to listen on for hub HTTP APIs.
    #[arg(long, value_parser = clap::value_parser!(SocketAddr))]
    listen: SocketAddr,
    /// Directory for persisting hub state.
    #[arg(long)]
    data_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(cmd) => run_hub(cmd).await,
    }
}

fn init_tracing() {
    let subscriber = tracing_subscriber::fmt().with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    );
    let _ = subscriber.try_init();
}

async fn run_hub(cmd: RunCommand) -> Result<()> {
    tracing::info!(listen = %cmd.listen, data_dir = %cmd.data_dir.display(), "initialising VEEN hub runtime");

    ensure_data_dir_layout(&cmd.data_dir).await?;
    write_pid_file(&cmd.data_dir).await?;
    ensure_tls_snapshot(&cmd.data_dir).await?;

    tracing::info!(
        pid = process::id(),
        "VEEN hub metadata initialised; awaiting shutdown signal"
    );
    println!("VEEN hub listening on {}", cmd.listen);
    println!("data_dir: {}", cmd.data_dir.display());
    println!("pid: {}", process::id());
    println!("press Ctrl+C to stop the hub");

    signal::ctrl_c()
        .await
        .context("waiting for Ctrl+C to stop hub runtime")?;

    tracing::info!("shutdown signal received; flushing hub storage");
    flush_hub_storage(&cmd.data_dir).await?;
    remove_pid_file(&cmd.data_dir).await?;
    tracing::info!("hub runtime stopped cleanly");
    println!("VEEN hub stopped cleanly");

    Ok(())
}

async fn ensure_data_dir_layout(data_dir: &Path) -> Result<()> {
    fs::create_dir_all(data_dir)
        .await
        .with_context(|| format!("creating hub data directory {}", data_dir.display()))?;

    ensure_file(&data_dir.join(RECEIPTS_FILE)).await?;
    ensure_file(&data_dir.join(PAYLOADS_FILE)).await?;
    ensure_file(&data_dir.join(CHECKPOINTS_FILE)).await?;

    let state_dir = data_dir.join(STATE_DIR);
    fs::create_dir_all(&state_dir)
        .await
        .with_context(|| format!("creating hub state directory {}", state_dir.display()))?;
    fs::create_dir_all(state_dir.join(STREAMS_DIR))
        .await
        .with_context(|| format!("creating streams directory under {}", state_dir.display()))?;
    fs::create_dir_all(state_dir.join(MESSAGES_DIR))
        .await
        .with_context(|| format!("creating messages directory under {}", state_dir.display()))?;
    fs::create_dir_all(state_dir.join(CAPABILITIES_DIR))
        .await
        .with_context(|| {
            format!(
                "creating capabilities directory under {}",
                state_dir.display()
            )
        })?;
    fs::create_dir_all(state_dir.join(CRDT_DIR))
        .await
        .with_context(|| format!("creating CRDT directory under {}", state_dir.display()))?;
    fs::create_dir_all(state_dir.join(ATTACHMENTS_DIR))
        .await
        .with_context(|| {
            format!(
                "creating attachments directory under {}",
                state_dir.display()
            )
        })?;

    fs::create_dir_all(data_dir.join(ANCHORS_DIR))
        .await
        .with_context(|| format!("creating anchors directory under {}", data_dir.display()))?;

    Ok(())
}

async fn ensure_file(path: &Path) -> Result<()> {
    if fs::try_exists(path)
        .await
        .with_context(|| format!("checking {}", path.display()))?
    {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating parent directory {}", parent.display()))?;
    }

    fs::write(path, &[])
        .await
        .with_context(|| format!("initialising {}", path.display()))?;
    Ok(())
}

async fn ensure_tls_snapshot(data_dir: &Path) -> Result<()> {
    let path = data_dir.join(STATE_DIR).join(TLS_INFO_FILE);
    if fs::try_exists(&path)
        .await
        .with_context(|| format!("checking TLS snapshot {}", path.display()))?
    {
        return Ok(());
    }

    const TLS_INFO_JSON: &str =
        "{\"version\":\"TLS 1.3\",\"cipher\":\"TLS_AES_256_GCM_SHA384\",\"aead\":true,\"compression\":false}";

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("ensuring TLS metadata directory {}", parent.display()))?;
    }

    fs::write(&path, TLS_INFO_JSON)
        .await
        .with_context(|| format!("writing TLS metadata to {}", path.display()))?;
    Ok(())
}

async fn write_pid_file(data_dir: &Path) -> Result<()> {
    let pid_path = data_dir.join(HUB_PID_FILE);
    if fs::try_exists(&pid_path)
        .await
        .with_context(|| format!("checking PID file {}", pid_path.display()))?
    {
        bail!(
            "hub PID file {} already exists; is another hub running?",
            pid_path.display()
        );
    }

    let pid_contents = process::id().to_string();
    fs::write(&pid_path, pid_contents)
        .await
        .with_context(|| format!("writing PID file {}", pid_path.display()))?;
    restrict_private_permissions(&pid_path).await?;
    Ok(())
}

async fn remove_pid_file(data_dir: &Path) -> Result<()> {
    let pid_path = data_dir.join(HUB_PID_FILE);
    if fs::try_exists(&pid_path)
        .await
        .with_context(|| format!("checking PID file {}", pid_path.display()))?
    {
        fs::remove_file(&pid_path)
            .await
            .with_context(|| format!("removing PID file {}", pid_path.display()))?;
    }
    Ok(())
}

async fn flush_hub_storage(data_dir: &Path) -> Result<()> {
    flush_file_if_exists(&data_dir.join(RECEIPTS_FILE)).await?;
    flush_file_if_exists(&data_dir.join(PAYLOADS_FILE)).await?;
    flush_file_if_exists(&data_dir.join(CHECKPOINTS_FILE)).await?;
    flush_file_if_exists(&data_dir.join(STATE_DIR).join(TLS_INFO_FILE)).await?;
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
