use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use veen_selftest::{PerfConfig, PerfMode, SelftestReport, SelftestReporter};

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
    /// Execute recorder and checkpoint scenarios.
    Recorder,
    /// Execute overlay integration scenarios.
    Overlays(OverlaysArgs),
    /// Execute the performance harness against a disposable hub.
    Perf(PerfArgs),
}

#[derive(Args)]
struct OverlaysArgs {
    /// Limit execution to a specific overlay subset.
    #[arg(long)]
    subset: Option<String>,
}

#[derive(Args)]
struct PerfArgs {
    /// Number of submit requests to issue during the run.
    #[arg(long, default_value_t = 256)]
    requests: usize,
    /// Maximum number of concurrent in-flight submissions.
    #[arg(long, default_value_t = 32)]
    concurrency: usize,
    /// Transport mode used to reach the hub.
    #[arg(long, value_enum, default_value_t = PerfModeArg::InProcess)]
    mode: PerfModeArg,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
enum PerfModeArg {
    InProcess,
    Http,
}

impl From<PerfModeArg> for PerfMode {
    fn from(value: PerfModeArg) -> Self {
        match value {
            PerfModeArg::InProcess => PerfMode::InProcess,
            PerfModeArg::Http => PerfMode::Http,
        }
    }
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
        Suite::Recorder => veen_selftest::run_recorder(&mut reporter).await,
        Suite::Overlays(args) => {
            veen_selftest::run_overlays(args.subset.as_deref(), &mut reporter).await
        }
        Suite::Perf(args) => {
            let config = PerfConfig {
                requests: args.requests,
                concurrency: args.concurrency,
                mode: args.mode.into(),
            };
            veen_selftest::run_perf(config, &mut reporter)
                .await
                .map(|_| ())
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
