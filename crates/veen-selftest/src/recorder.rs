use anyhow::{Context, Result};

use crate::process_harness::IntegrationHarness;
use crate::{SelftestGoalReport, SelftestReporter};

pub async fn run_recorder(reporter: &mut SelftestReporter<'_>) -> Result<()> {
    let mut harness = IntegrationHarness::new()
        .await
        .context("initialising recorder harness")?;

    let (capture, recovery) = harness
        .run_recorder_suite()
        .await
        .context("running recorder end-to-end scenario")?;

    reporter.record(SelftestGoalReport {
        goal: "SELFTEST.RECORDER.CAPTURE".into(),
        environment: vec![format!("stream={}", capture.stream)],
        invariants: vec![
            "recorder streams accept CLI and HTTP events".into(),
            "recorder events include subject, principal, type, and time fields".into(),
            "checkpoint log root matches stream MMR root".into(),
            "inclusion proofs validate against checkpoint".into(),
        ],
        evidence: vec![
            format!("mmr_root={}", capture.mmr_root),
            format!("checkpoint_root={}", capture.checkpoint_root),
            format!("events={}", capture.total_events),
            format!("sampled_seqs={:?}", capture.sampled_seqs),
            format!("checkpoint_log={}", capture.checkpoint_path.display()),
        ],
        perf: None,
    });

    reporter.record(SelftestGoalReport {
        goal: "SELFTEST.RECORDER.RECOVERY".into(),
        environment: vec![format!("stream={}", recovery.stream)],
        invariants: vec![
            "hub restarts cleanly after checkpoint kill".into(),
            "replay window derived from checkpoint upto_seq".into(),
            "post-restart proofs validate against checkpoint root".into(),
        ],
        evidence: vec![
            format!("checkpoint_root={}", recovery.checkpoint_root),
            format!("replay_from_seq={}", recovery.replay_from_seq),
            format!("validated_seqs={:?}", recovery.validated_seqs),
        ],
        perf: None,
    });

    Ok(())
}
