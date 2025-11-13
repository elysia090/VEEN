use std::time::Duration;

use anyhow::Result;
use clap::{ArgAction, Args, Parser, Subcommand};
use reqwest::Url;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use veen_bridge::{run_bridge, BridgeConfig, EndpointConfig};

#[derive(Parser)]
#[command(name = "veen-bridge", version, about = "Federation bridge for VEEN hubs", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the federation bridge between a primary hub and a replica.
    Run(RunCommand),
}

#[derive(Args, Debug)]
struct RunCommand {
    /// Base URL for the primary hub.
    #[arg(long, value_parser = clap::value_parser!(Url))]
    from: Url,
    /// Optional bearer token for the primary hub.
    #[arg(long)]
    from_token: Option<String>,
    /// Base URL for the replica hub.
    #[arg(long, value_parser = clap::value_parser!(Url))]
    to: Url,
    /// Optional bearer token for the replica hub.
    #[arg(long)]
    to_token: Option<String>,
    /// Poll interval in milliseconds between stream checks.
    #[arg(long, default_value_t = 250)]
    poll_interval_ms: u64,
    /// Streams to replicate. If omitted the bridge will follow all streams reported by the primary hub.
    #[arg(long = "stream", action = ArgAction::Append)]
    streams: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(cmd) => run(cmd).await?,
    }

    Ok(())
}

async fn run(cmd: RunCommand) -> Result<()> {
    let config = BridgeConfig {
        primary: EndpointConfig::new(cmd.from, cmd.from_token),
        replica: EndpointConfig::new(cmd.to, cmd.to_token),
        poll_interval: Duration::from_millis(cmd.poll_interval_ms.max(50)),
        initial_streams: cmd.streams,
    };

    let shutdown = CancellationToken::new();
    let ctrl_c = shutdown.clone();

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            ctrl_c.cancel();
        }
    });

    run_bridge(config, shutdown).await
}

fn init_tracing() {
    let subscriber = tracing_subscriber::fmt().with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    );
    let _ = subscriber.try_init();
}
