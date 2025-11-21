use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use veen_core::query::{
    EvidenceMode, EvidencePolicy, QueryDescriptor, QueryError, QueryFilter, ResultContext,
    ResultDigest,
};

use crate::process_harness::{HubRole, IntegrationHarness};
use crate::{SelftestGoalReport, SelftestReporter};

const QUERY_STREAM: &str = "record/query/requests";

pub async fn run_query_overlays(reporter: &mut SelftestReporter<'_>) -> Result<()> {
    let mut harness = IntegrationHarness::new()
        .await
        .context("initialising query harness")?;

    let digest = validate_canonical_hashes(&mut harness)
        .await
        .context("computing canonical digests")?;
    let validation = exercise_descriptor_validation(&mut harness)
        .await
        .context("exercising validation")?;

    reporter.record(SelftestGoalReport {
        goal: "SELFTEST.QUERY.digest".into(),
        environment: vec!["subset=query".into(), format!("stream={QUERY_STREAM}")],
        invariants: vec![
            "result digests reflect canonical row hashing".into(),
            "evidence summaries honour policy mode and identifiers".into(),
            "canonical hashes are stable across policy variants".into(),
        ],
        evidence: vec![
            format!("none_rows_hash={}", digest.none_rows_hash),
            format!("spot_rows_hash={}", digest.spot_rows_hash),
            format!("full_rows_hash={}", digest.full_rows_hash),
            format!("none_evidence_hash={}", digest.none_evidence_hash),
            format!("spot_evidence_hash={}", digest.spot_evidence_hash),
            format!("full_evidence_hash={}", digest.full_evidence_hash),
            format!("mmr_root={}", digest.mmr_root),
            format!("sampled_seqs={:?}", digest.sampled_seqs),
        ],
        perf: None,
    });

    reporter.record(SelftestGoalReport {
        goal: "SELFTEST.QUERY.validation".into(),
        environment: vec!["subset=query".into(), format!("stream={QUERY_STREAM}")],
        invariants: vec![
            "empty scopes are rejected with validation errors".into(),
            "spot evidence requires a non-zero sample rate".into(),
            "time window end must not precede start".into(),
        ],
        evidence: vec![
            format!("empty_scope_status={}", validation.empty_scope_status),
            format!("zero_sample_status={}", validation.zero_sample_status),
            format!("invalid_window_status={}", validation.invalid_window_status),
            format!("empty_scope_error={}", validation.empty_scope_error),
            format!("zero_sample_error={}", validation.zero_sample_error),
            format!("invalid_window_error={}", validation.invalid_window_error),
        ],
        perf: None,
    });

    Ok(())
}

struct DigestEvidence {
    none_rows_hash: String,
    spot_rows_hash: String,
    full_rows_hash: String,
    none_evidence_hash: String,
    spot_evidence_hash: String,
    full_evidence_hash: String,
    mmr_root: String,
    sampled_seqs: Vec<u64>,
}

async fn validate_canonical_hashes(harness: &mut IntegrationHarness) -> Result<DigestEvidence> {
    let hub = harness
        .spawn_hub("query-hub", HubRole::Primary, &[])
        .await
        .context("spawning query hub")?;
    harness
        .wait_for_health(hub.listen_addr())
        .await
        .context("waiting for query hub health")?;

    let hub_url = format!("http://{}", hub.listen_addr());
    let client_dir = harness.base_dir().join("query-client");
    tokio::fs::create_dir_all(&client_dir)
        .await
        .context("creating query client dir")?;
    harness
        .run_cli_success(
            vec![
                "keygen".into(),
                "--out".into(),
                client_dir.as_os_str().to_os_string(),
            ],
            "creating query client identity",
        )
        .await?;

    let mut sent_rows = Vec::new();
    for (idx, body) in [
        json!({"subject_id": "alice", "event_time": "2025-01-01T00:00:00Z", "action": "login"}),
        json!({"subject_id": "bob", "event_time": "2025-01-02T12:00:00Z", "action": "logout"}),
        json!({"subject_id": "carol", "event_time": "2025-01-03T08:30:00Z", "action": "login"}),
    ]
    .into_iter()
    .enumerate()
    {
        let label = format!("query-{idx}");
        let body_text = serde_json::to_string(&body)
            .with_context(|| format!("serialising query event {label}"))?;
        harness
            .send_test_message(&hub_url, &client_dir, QUERY_STREAM, &body_text)
            .await
            .with_context(|| format!("sending query event {label}"))?;
        sent_rows.push(body);
    }

    let messages = harness
        .fetch_stream_with_proofs(&hub_url, QUERY_STREAM)
        .await
        .context("fetching query stream with proofs")?;
    if messages.is_empty() {
        bail!("query harness emitted no messages for {QUERY_STREAM}");
    }

    let rows: Vec<Value> = messages
        .iter()
        .map(|entry| {
            serde_json::from_str(
                &entry
                    .message
                    .body
                    .as_deref()
                    .ok_or_else(|| anyhow!("missing body for query message"))?,
            )
            .context("decoding query row body")
        })
        .collect::<Result<_>>()?;

    let mmr_root = messages
        .first()
        .map(|entry| entry.receipt.mmr_root.clone())
        .unwrap_or_default();

    let baseline_descriptor = QueryDescriptor {
        query_id: Some("q-selftest".into()),
        version: Some(1),
        scope: vec![QUERY_STREAM.into()],
        filter: QueryFilter::default(),
        projection: vec!["subject_id".into(), "event_time".into(), "action".into()],
        aggregate: None,
        evidence: EvidencePolicy::default(),
        meta: None,
    };

    let normalized = baseline_descriptor
        .clone()
        .normalize()
        .context("normalising baseline descriptor")?;

    let sample_rate = 0.5;
    let sampled_receipts: Vec<_> = messages.iter().step_by(2).collect();
    let sampled_seqs: Vec<u64> = sampled_receipts
        .iter()
        .map(|entry| entry.message.seq)
        .collect();

    let summary_none = json!({
        "mode": "none",
        "verified": [json!({"mmr_root": mmr_root})],
    });
    let none_digest = build_digest(
        &rows,
        EvidencePolicy::default(),
        &summary_none,
        &normalized.query_id,
        None,
    )?;

    let summary_spot = json!({
        "mode": "spot",
        "query_id": none_digest.query_id,
        "result_id": "spot-selftest",
        "sample_rate": sample_rate,
        "verified": [json!({
            "mmr_root": mmr_root,
            "receipts": sampled_receipts
                .iter()
                .map(|entry| json!({
                    "seq": entry.message.seq,
                    "mmr_root": entry.receipt.mmr_root,
                    "leaf_hash": entry.receipt.leaf_hash,
                }))
                .collect::<Vec<_>>(),
        })],
    });
    let spot_digest = build_digest(
        &rows,
        EvidencePolicy {
            mode: EvidenceMode::Spot,
            sample_rate: Some(sample_rate),
        },
        &summary_spot,
        &normalized.query_id,
        Some("spot-selftest"),
    )?;

    let summary_full = json!({
        "mode": "full",
        "query_id": none_digest.query_id,
        "result_id": "full-selftest",
        "verified": [json!({
            "mmr_root": mmr_root,
            "receipts": messages
                .iter()
                .map(|entry| json!({
                    "seq": entry.message.seq,
                    "mmr_root": entry.receipt.mmr_root,
                    "leaf_hash": entry.receipt.leaf_hash,
                }))
                .collect::<Vec<_>>(),
        })],
    });
    let full_digest = build_digest(
        &rows,
        EvidencePolicy {
            mode: EvidenceMode::Full,
            sample_rate: None,
        },
        &summary_full,
        &normalized.query_id,
        Some("full-selftest"),
    )?;

    let expected_rows_hash = canonical_hash(&Value::Array(rows.clone()))?;
    assert_eq!(none_digest.rows_hash, expected_rows_hash);
    assert_eq!(spot_digest.rows_hash, expected_rows_hash);
    assert_eq!(full_digest.rows_hash, expected_rows_hash);

    let none_evidence_hash = canonical_hash(&summary_none)?;
    let spot_evidence_hash = canonical_hash(&summary_spot)?;
    let full_evidence_hash = canonical_hash(&summary_full)?;
    assert_eq!(none_digest.evidence_hash, none_evidence_hash);
    assert_eq!(spot_digest.evidence_hash, spot_evidence_hash);
    assert_eq!(full_digest.evidence_hash, full_evidence_hash);

    Ok(DigestEvidence {
        none_rows_hash: none_digest.rows_hash,
        spot_rows_hash: spot_digest.rows_hash,
        full_rows_hash: full_digest.rows_hash,
        none_evidence_hash,
        spot_evidence_hash,
        full_evidence_hash,
        mmr_root,
        sampled_seqs,
    })
}

async fn exercise_descriptor_validation(
    harness: &mut IntegrationHarness,
) -> Result<ValidationEvidence> {
    let hub = harness
        .spawn_hub("query-validation", HubRole::Primary, &[])
        .await
        .context("spawning validation hub")?;
    harness
        .wait_for_health(hub.listen_addr())
        .await
        .context("waiting for validation hub health")?;

    let hub_url = format!("http://{}", hub.listen_addr());

    let empty_scope_descriptor = QueryDescriptor {
        query_id: Some("q-invalid".into()),
        version: Some(1),
        scope: vec![],
        filter: QueryFilter::default(),
        projection: vec!["subject_id".into()],
        aggregate: None,
        evidence: EvidencePolicy::default(),
        meta: None,
    };

    let zero_sample_descriptor = QueryDescriptor {
        query_id: Some("q-invalid".into()),
        version: Some(1),
        scope: vec![QUERY_STREAM.into()],
        filter: QueryFilter::default(),
        projection: vec!["subject_id".into()],
        aggregate: None,
        evidence: EvidencePolicy {
            mode: EvidenceMode::Spot,
            sample_rate: Some(0.0),
        },
        meta: None,
    };

    let invalid_window_descriptor = QueryDescriptor {
        query_id: Some("q-invalid".into()),
        version: Some(1),
        scope: vec![QUERY_STREAM.into()],
        filter: QueryFilter {
            subject_id: None,
            event_type: None,
            time: veen_core::query::TimeFilter {
                from: Some("2025-01-02T00:00:00Z".into()),
                to: Some("2025-01-01T00:00:00Z".into()),
            },
        },
        projection: vec!["subject_id".into()],
        aggregate: None,
        evidence: EvidencePolicy::default(),
        meta: None,
    };

    let validation_cases = vec![
        (empty_scope_descriptor, QueryError::EmptyScope),
        (zero_sample_descriptor, QueryError::InvalidSampleRate(0.0)),
        (invalid_window_descriptor, QueryError::InvalidTimeWindow),
    ];

    let mut error_summaries = BTreeMap::new();
    for (descriptor, expected) in validation_cases {
        let error = descriptor
            .clone()
            .normalize()
            .expect_err("descriptor should fail normalization");
        if error != expected {
            bail!(
                "unexpected error {:?} for descriptor {:?}; expected {:?}",
                error,
                descriptor,
                expected
            );
        }

        let response = harness
            .http_client()
            .post(format!("{hub_url}/query"))
            .json(&descriptor)
            .send()
            .await
            .context("posting invalid descriptor to hub")?;

        error_summaries.insert(
            expected.to_string(),
            format!("{} {}", response.status(), error),
        );
    }

    Ok(ValidationEvidence {
        empty_scope_status: error_summaries
            .get(&QueryError::EmptyScope.to_string())
            .cloned()
            .unwrap_or_else(|| "404 NotFound".into()),
        zero_sample_status: error_summaries
            .get(&QueryError::InvalidSampleRate(0.0).to_string())
            .cloned()
            .unwrap_or_else(|| "404 NotFound".into()),
        invalid_window_status: error_summaries
            .get(&QueryError::InvalidTimeWindow.to_string())
            .cloned()
            .unwrap_or_else(|| "404 NotFound".into()),
        empty_scope_error: QueryError::EmptyScope.to_string(),
        zero_sample_error: QueryError::InvalidSampleRate(0.0).to_string(),
        invalid_window_error: QueryError::InvalidTimeWindow.to_string(),
    })
}

struct ValidationEvidence {
    empty_scope_status: String,
    zero_sample_status: String,
    invalid_window_status: String,
    empty_scope_error: String,
    zero_sample_error: String,
    invalid_window_error: String,
}

fn build_digest(
    rows: &[Value],
    evidence: EvidencePolicy,
    summary: &Value,
    query_id: &str,
    explicit_result_id: Option<&str>,
) -> Result<ResultDigest> {
    ResultDigest::from_rows_and_evidence(
        query_id,
        explicit_result_id.map(str::to_string),
        rows,
        evidence.clone(),
        summary,
        ResultContext::new("2025-03-25T10:30:00Z", "hub-selftest", None),
        || format!("{:?}-result", evidence.mode),
    )
    .map_err(Into::into)
}

fn canonical_hash(value: &Value) -> Result<String> {
    let canonical = canonicalize_value(value);
    let bytes = serde_json::to_vec(&canonical)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

            let mut sorted = serde_json::Map::new();
            for (key, value) in entries {
                sorted.insert(key.clone(), canonicalize_value(value));
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_value).collect()),
        _ => value.clone(),
    }
}
