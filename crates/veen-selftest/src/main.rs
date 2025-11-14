use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "veen-selftest", version, about = "Integration harness for VEEN", long_about = None)]
struct Cli {
    #[command(subcommand)]
    suite: Suite,
}

#[derive(Subcommand)]
enum Suite {
    /// Execute the core protocol acceptance tests.
    Core,
    /// Execute property-style checks and overlay scenarios.
    Props,
    /// Execute fuzz-style robustness checks.
    Fuzz,
    /// Execute all suites.
    All,
    /// Execute overlay integration scenarios.
    Overlays(OverlaysArgs),
}

#[derive(Args)]
struct OverlaysArgs {
    /// Limit execution to a specific overlay subset.
    #[arg(long)]
    subset: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.suite {
        Suite::Core => veen_selftest::run_core().await,
        Suite::Props => veen_selftest::run_props(),
        Suite::Fuzz => veen_selftest::run_fuzz(),
        Suite::All => veen_selftest::run_all().await,
        Suite::Overlays(args) => veen_selftest::run_overlays(args.subset.as_deref()).await,
    }?;

    Ok(())
}

fn init_tracing() {
    let subscriber = tracing_subscriber::fmt().with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    );
    let _ = subscriber.try_init();
}
