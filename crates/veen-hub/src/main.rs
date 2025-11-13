use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

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
    tracing::info!(listen = %cmd.listen, data_dir = ?cmd.data_dir, "initialising VEEN hub scaffold");
    tracing::debug!(
        expected_hub_id_len = veen_core::HUB_ID_LEN,
        "hub identifiers are derived from veen-core primitives"
    );

    bail!("`veen-hub run` is currently a scaffold. Implement the hub state machine, capability enforcement, and overlay surfaces as described in doc/GOALS.txt before using this in production.");
}
