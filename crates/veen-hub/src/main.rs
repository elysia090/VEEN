use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use tokio::signal;
use tracing_subscriber::EnvFilter;

use veen_hub::config::{HubRole, HubRuntimeConfig};
use veen_hub::runtime::HubRuntime;

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
    /// Optional path to a configuration file describing the runtime overlays.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Role to run the hub as.
    #[arg(long, value_enum, default_value_t = HubRoleArg::Primary)]
    role: HubRoleArg,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum HubRoleArg {
    Primary,
    Replica,
}

impl From<HubRoleArg> for HubRole {
    fn from(value: HubRoleArg) -> Self {
        match value {
            HubRoleArg::Primary => HubRole::Primary,
            HubRoleArg::Replica => HubRole::Replica,
        }
    }
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
    let runtime_config =
        HubRuntimeConfig::from_sources(cmd.listen, cmd.data_dir, cmd.config, cmd.role.into())
            .await?;
    tracing::info!(
        listen = %runtime_config.listen,
        data_dir = %runtime_config.data_dir.display(),
        "initialising VEEN hub runtime"
    );

    let runtime = HubRuntime::start(runtime_config).await?;
    println!("VEEN hub listening on {}", runtime.listen_addr());
    println!("data_dir: {}", runtime.data_dir().display());
    println!("press Ctrl+C to stop the hub");

    signal::ctrl_c().await?;

    tracing::info!("shutdown signal received; flushing hub storage");
    runtime.shutdown().await?;
    tracing::info!("hub runtime stopped cleanly");
    println!("VEEN hub stopped cleanly");

    Ok(())
}
