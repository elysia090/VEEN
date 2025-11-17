use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use veen_selftest::{SelftestReport, SelftestReporter};

#[derive(Parser)]
#[command(name = "veen-selftest", version, about = "Integration harness for VEEN", long_about = None)]
struct Cli {
    /// Emit a human-readable summary of the executed invariants.
    #[arg(long, conflicts_with = "json")]
    summary: bool,
    /// Emit a JSON report describing the executed invariants.
    #[arg(long, conflicts_with = "summary")]
    json: bool,
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
    /// Execute federated overlay acceptance scenarios.
    Federated,
    /// Execute lifecycle and revocation (KEX1+) scenarios.
    Kex1,
    /// Execute hardened-profile (SH1+) scenarios.
    Hardened,
    /// Execute META0+/label overlay scenarios.
    Meta,
    /// Execute the aggregated v0.0.1+ suite.
    Plus,
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

    let mut report = if cli.summary || cli.json {
        Some(SelftestReport::default())
    } else {
        None
    };
    let mut reporter = SelftestReporter::new(report.as_mut());

    let result = match cli.suite {
        Suite::Core => veen_selftest::run_core(&mut reporter).await,
        Suite::Props => veen_selftest::run_props(&mut reporter),
        Suite::Fuzz => veen_selftest::run_fuzz(&mut reporter),
        Suite::All => veen_selftest::run_all(&mut reporter).await,
        Suite::Federated => veen_selftest::run_federated(&mut reporter).await,
        Suite::Kex1 => veen_selftest::run_kex1(&mut reporter).await,
        Suite::Hardened => veen_selftest::run_hardened(&mut reporter).await,
        Suite::Meta => veen_selftest::run_meta(&mut reporter).await,
        Suite::Plus => veen_selftest::run_plus(&mut reporter).await,
        Suite::Overlays(args) => {
            veen_selftest::run_overlays(args.subset.as_deref(), &mut reporter).await
        }
    };

    if result.is_ok() {
        if cli.summary {
            if let Some(report) = &report {
                println!("{report}");
            }
        } else if cli.json {
            if let Some(report) = &report {
                let json = serde_json::to_string_pretty(report)?;
                println!("{json}");
            }
        }
    }

    result?;

    Ok(())
}

fn init_tracing() {
    let subscriber = tracing_subscriber::fmt().with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
    );
    let _ = subscriber.try_init();
}
