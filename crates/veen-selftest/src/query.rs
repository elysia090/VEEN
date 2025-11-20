use anyhow::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use veen_core::query::{
    EvidenceMode, EvidencePolicy, QueryDescriptor, QueryError, QueryFilter, ResultContext,
    ResultDigest,
};

use crate::{SelftestGoalReport, SelftestReporter};

pub async fn run_query_overlays(reporter: &mut SelftestReporter<'_>) -> Result<()> {
    let digest = validate_canonical_hashes()?;
    let validation = exercise_descriptor_validation()?;

    reporter.record(SelftestGoalReport {
        goal: "SELFTEST.QUERY.digest".into(),
        environment: vec!["subset=query".into()],
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
        ],
        perf: None,
    });

    reporter.record(SelftestGoalReport {
        goal: "SELFTEST.QUERY.validation".into(),
        environment: vec!["subset=query".into()],
        invariants: vec![
            "empty scopes are rejected with validation errors".into(),
            "spot evidence requires a non-zero sample rate".into(),
            "time window end must not precede start".into(),
        ],
        evidence: vec![
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
}

fn validate_canonical_hashes() -> Result<DigestEvidence> {
    let rows = vec![
        json!({"subject_id": "alice", "event_time": "2025-01-01T00:00:00Z", "action": "login"}),
        json!({"subject_id": "bob", "event_time": "2025-01-02T12:00:00Z", "action": "logout"}),
    ];

    let mmr_root = format!("{:x}", Sha256::digest(b"selftest-mmr-root"));
    let base_summary = json!({
        "mode": "none",
        "verified": [json!({"mmr_root": mmr_root})],
    });

    let none_policy = EvidencePolicy::default();
    let none_digest = ResultDigest::from_rows_and_evidence(
        "q-fixed",
        Some("r-none".into()),
        &rows,
        none_policy.clone(),
        &base_summary,
        ResultContext::new("2025-03-25T10:30:00Z", "hub-selftest", None),
        || "r-none".to_string(),
    )?;

    let spot_policy = EvidencePolicy {
        mode: EvidenceMode::Spot,
        sample_rate: Some(0.25),
    };
    let spot_summary = json!({
        "mode": "spot",
        "query_id": none_digest.query_id,
        "result_id": "r-spot",
        "sample_rate": 0.25,
        "verified": [json!({"mmr_root": mmr_root})],
    });
    let spot_digest = ResultDigest::from_rows_and_evidence(
        "q-fixed",
        Some("r-spot".into()),
        &rows,
        spot_policy.clone(),
        &spot_summary,
        ResultContext::new("2025-03-25T10:30:00Z", "hub-selftest", None),
        || "r-spot".to_string(),
    )?;

    let full_policy = EvidencePolicy {
        mode: EvidenceMode::Full,
        sample_rate: None,
    };
    let full_summary = json!({
        "mode": "full",
        "query_id": none_digest.query_id,
        "result_id": "r-full",
        "verified": [json!({"mmr_root": mmr_root})],
    });
    let full_digest = ResultDigest::from_rows_and_evidence(
        "q-fixed",
        Some("r-full".into()),
        &rows,
        full_policy.clone(),
        &full_summary,
        ResultContext::new("2025-03-25T10:30:00Z", "hub-selftest", None),
        || "r-full".to_string(),
    )?;

    let expected_rows_hash = canonical_hash(&Value::Array(rows.clone()))?;
    assert_eq!(none_digest.rows_hash, expected_rows_hash);
    assert_eq!(spot_digest.rows_hash, expected_rows_hash);
    assert_eq!(full_digest.rows_hash, expected_rows_hash);

    let none_evidence_hash = canonical_hash(&base_summary)?;
    let spot_evidence_hash = canonical_hash(&spot_summary)?;
    let full_evidence_hash = canonical_hash(&full_summary)?;
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
    })
}

fn exercise_descriptor_validation() -> Result<ValidationEvidence> {
    let empty_scope_error = QueryDescriptor {
        query_id: Some("q-invalid".into()),
        version: Some(1),
        scope: vec![],
        filter: QueryFilter::default(),
        projection: vec!["subject_id".into()],
        aggregate: None,
        evidence: EvidencePolicy::default(),
        meta: None,
    }
    .normalize()
    .unwrap_err();

    let zero_sample_error = QueryDescriptor {
        query_id: Some("q-invalid".into()),
        version: Some(1),
        scope: vec!["record/query/requests".into()],
        filter: QueryFilter::default(),
        projection: vec!["subject_id".into()],
        aggregate: None,
        evidence: EvidencePolicy {
            mode: EvidenceMode::Spot,
            sample_rate: Some(0.0),
        },
        meta: None,
    }
    .normalize()
    .unwrap_err();

    let invalid_window_error = QueryDescriptor {
        query_id: Some("q-invalid".into()),
        version: Some(1),
        scope: vec!["record/query/requests".into()],
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
    }
    .normalize()
    .unwrap_err();

    assert_eq!(empty_scope_error, QueryError::EmptyScope);
    assert_eq!(zero_sample_error, QueryError::InvalidSampleRate(0.0));
    assert_eq!(invalid_window_error, QueryError::InvalidTimeWindow);

    Ok(ValidationEvidence {
        empty_scope_error: empty_scope_error.to_string(),
        zero_sample_error: zero_sample_error.to_string(),
        invalid_window_error: invalid_window_error.to_string(),
    })
}

struct ValidationEvidence {
    empty_scope_error: String,
    zero_sample_error: String,
    invalid_window_error: String,
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
