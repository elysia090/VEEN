use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
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
    /// Execute overlay scenarios layered on top of the core protocol.
    Overlays,
    /// Execute all suites.
    All,
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.suite {
        Suite::Core => run_core().await,
        Suite::Overlays => run_overlays().await,
        Suite::All => run_all().await,
    }
}

fn init_tracing() {
    let subscriber = tracing_subscriber::fmt().with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    );
    let _ = subscriber.try_init();
}

async fn run_core() -> Result<()> {
    not_implemented("core")
}

async fn run_overlays() -> Result<()> {
    not_implemented("overlays")
}

async fn run_all() -> Result<()> {
    not_implemented("all")
}

fn not_implemented(suite: &str) -> Result<()> {
    let placeholder_mmr = veen_core::wire::Mmr::new();
    tracing::debug!(
        suite = suite,
        placeholder_seq = placeholder_mmr.seq(),
        "invoked VEEN self-test scaffold"
    );
    bail!(
        "`veen-selftest {suite}` is a scaffold. Implement the orchestrated scenarios from doc/GOALS.txt to make this suite meaningful."
    );
}
