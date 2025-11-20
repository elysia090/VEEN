use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Recorder stream that accepts normalized query descriptors.
pub const QUERY_REQUEST_STREAM: &str = "record/query/requests";

/// Recorder stream that records query result digests.
pub const QUERY_RESULT_STREAM: &str = "record/query/results";

/// Evidence modes supported by the Query API specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceMode {
    None,
    Spot,
    Full,
}

/// Evidence policy attached to a query descriptor or result digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidencePolicy {
    pub mode: EvidenceMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_rate: Option<f64>,
}

impl Default for EvidencePolicy {
    fn default() -> Self {
        Self {
            mode: EvidenceMode::None,
            sample_rate: None,
        }
    }
}

impl EvidencePolicy {
    fn normalize(&mut self) -> Result<(), QueryError> {
        match self.mode {
            EvidenceMode::None => {
                if self.sample_rate.is_some() {
                    return Err(QueryError::UnexpectedSampleRate);
                }
                self.sample_rate = None;
            }
            EvidenceMode::Spot => {
                let sample = self.sample_rate.ok_or(QueryError::MissingSampleRate)?;
                if !(sample.is_sign_positive() && sample <= 1.0) {
                    return Err(QueryError::InvalidSampleRate(sample));
                }
            }
            EvidenceMode::Full => {
                if self.sample_rate.is_some() {
                    return Err(QueryError::UnexpectedSampleRate);
                }
                self.sample_rate = None;
            }
        }
        Ok(())
    }
}

/// Time window filter applied to queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TimeFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

/// Event filter applied to queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct QueryFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "TimeFilter::is_default")]
    pub time: TimeFilter,
}

impl TimeFilter {
    fn validate(&self) -> Result<(), QueryError> {
        let start = self.from.as_deref().map(validate_timestamp).transpose()?;
        let end = self.to.as_deref().map(validate_timestamp).transpose()?;

        if let (Some(start), Some(end)) = (start, end) {
            if start > end {
                return Err(QueryError::InvalidTimeWindow);
            }
        }

        Ok(())
    }

    fn is_default(&self) -> bool {
        self.from.is_none() && self.to.is_none()
    }
}

impl QueryFilter {
    fn validate(&self) -> Result<(), QueryError> {
        if let Some(event_types) = &self.event_type {
            if event_types.is_empty() {
                return Err(QueryError::InvalidEventTypes);
            }
            if event_types.iter().any(|value| value.trim().is_empty()) {
                return Err(QueryError::InvalidEventTypes);
            }
        }
        self.time.validate()
    }
}

/// Aggregate block attached to a query descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Aggregate {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub group_by: Vec<String>,
    pub metrics: Vec<String>,
}

impl Aggregate {
    fn validate(&self) -> Result<(), QueryError> {
        if self.metrics.is_empty() {
            return Err(QueryError::MissingMetrics);
        }
        Ok(())
    }
}

/// Query descriptor submitted by a client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryDescriptor {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u8>,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default)]
    pub filter: QueryFilter,
    #[serde(default)]
    pub projection: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate: Option<Aggregate>,
    #[serde(default)]
    pub evidence: EvidencePolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<JsonMap<String, Value>>,
}

impl QueryDescriptor {
    /// Normalizes and validates the descriptor according to the specification.
    ///
    /// * Fills a missing `version` with `1`.
    /// * Generates a `query_id` when absent using the provided generator.
    /// * Validates required fields and evidence constraints.
    pub fn normalize_with<F>(
        self,
        mut query_id_gen: F,
    ) -> Result<NormalizedQueryDescriptor, QueryError>
    where
        F: FnMut() -> String,
    {
        let version = self.version.unwrap_or(1);
        if version != 1 {
            return Err(QueryError::UnsupportedVersion(version.into()));
        }

        if self.scope.is_empty() {
            return Err(QueryError::EmptyScope);
        }

        if self.projection.is_empty() {
            return Err(QueryError::EmptyProjection);
        }

        let mut evidence = self.evidence;
        evidence.normalize()?;

        self.filter.validate()?;

        if let Some(aggregate) = &self.aggregate {
            aggregate.validate()?;
        }

        let query_id = self
            .query_id
            .unwrap_or_else(|| query_id_gen())
            .trim()
            .to_string();

        if query_id.is_empty() {
            return Err(QueryError::MissingQueryId);
        }

        Ok(NormalizedQueryDescriptor {
            query_id,
            version,
            scope: self.scope,
            filter: self.filter,
            projection: self.projection,
            aggregate: self.aggregate,
            evidence,
            meta: self.meta,
        })
    }

    /// Convenience wrapper that uses a random query identifier.
    pub fn normalize(self) -> Result<NormalizedQueryDescriptor, QueryError> {
        self.normalize_with(generate_query_id)
    }
}

/// Query descriptor after validation and normalization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedQueryDescriptor {
    pub query_id: String,
    pub version: u8,
    pub scope: Vec<String>,
    pub filter: QueryFilter,
    pub projection: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate: Option<Aggregate>,
    pub evidence: EvidencePolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<JsonMap<String, Value>>,
}

/// Result digest committed alongside query results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResultDigest {
    pub query_id: String,
    pub result_id: String,
    pub version: u8,
    pub row_count: usize,
    pub evidence_policy: EvidencePolicy,
    pub rows_hash: String,
    pub evidence_hash: String,
    pub executed_at: String,
    pub hub_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
}

impl ResultDigest {
    /// Builds a digest for the provided result set and evidence summary.
    pub fn from_rows_and_evidence<G>(
        query_id: impl Into<String>,
        result_id: Option<String>,
        rows: &[Value],
        mut evidence_policy: EvidencePolicy,
        evidence_summary: &Value,
        executed_at: impl Into<String>,
        hub_id: impl Into<String>,
        profile_id: Option<String>,
        mut result_id_gen: G,
    ) -> Result<Self, QueryError>
    where
        G: FnMut() -> String,
    {
        evidence_policy.normalize()?;

        let executed_at = executed_at.into();
        validate_timestamp(&executed_at)?;

        let result_id = result_id
            .unwrap_or_else(|| result_id_gen())
            .trim()
            .to_string();
        if result_id.is_empty() {
            return Err(QueryError::MissingResultId);
        }

        let rows_hash = hash_rows(rows)?;
        let evidence_hash = hash_evidence_summary(evidence_summary)?;

        Ok(Self {
            query_id: query_id.into(),
            result_id,
            version: 1,
            row_count: rows.len(),
            evidence_policy,
            rows_hash,
            evidence_hash,
            executed_at,
            hub_id: hub_id.into(),
            profile_id,
        })
    }

    /// Convenience wrapper that generates a random result identifier.
    pub fn from_rows(
        query_id: impl Into<String>,
        rows: &[Value],
        evidence_policy: EvidencePolicy,
        evidence_summary: &Value,
        executed_at: impl Into<String>,
        hub_id: impl Into<String>,
        profile_id: Option<String>,
    ) -> Result<Self, QueryError> {
        Self::from_rows_and_evidence(
            query_id,
            None,
            rows,
            evidence_policy,
            evidence_summary,
            executed_at,
            hub_id,
            profile_id,
            generate_result_id,
        )
    }
}

/// Errors raised when normalizing or hashing queries and results.
#[derive(Debug, Error, PartialEq)]
pub enum QueryError {
    #[error("scope must contain at least one stream")]
    EmptyScope,
    #[error("projection must contain at least one field")]
    EmptyProjection,
    #[error("query_id must be provided or generated")]
    MissingQueryId,
    #[error("result_id must be provided or generated")]
    MissingResultId,
    #[error("evidence.sample_rate is required for spot mode")]
    MissingSampleRate,
    #[error("evidence.sample_rate must be in (0, 1], got {0}")]
    InvalidSampleRate(f64),
    #[error("evidence.sample_rate must be omitted for this mode")]
    UnexpectedSampleRate,
    #[error("event_type filters must not be empty")]
    InvalidEventTypes,
    #[error("aggregate metrics must not be empty")]
    MissingMetrics,
    #[error("timestamps must follow RFC3339 UTC (example 2025-11-19T03:20:00Z)")]
    InvalidTimestamp,
    #[error("time.from must not be after time.to")]
    InvalidTimeWindow,
    #[error("unsupported query descriptor version {0}")]
    UnsupportedVersion(u64),
    #[error("failed to produce canonical JSON for hashing: {0}")]
    CanonicalJson(String),
}

fn generate_query_id() -> String {
    generate_hex_id("q-")
}

fn generate_result_id() -> String {
    generate_hex_id("r-")
}

fn generate_hex_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).unwrap_or_default();
    let mut encoded = String::with_capacity(prefix.len() + bytes.len() * 2);
    let _ = encoded.write_str(prefix);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn validate_timestamp(raw: &str) -> Result<OffsetDateTime, QueryError> {
    let timestamp =
        OffsetDateTime::parse(raw, &Rfc3339).map_err(|_| QueryError::InvalidTimestamp)?;
    if timestamp.offset() != time::UtcOffset::UTC {
        return Err(QueryError::InvalidTimestamp);
    }
    Ok(timestamp)
}

fn hash_rows(rows: &[Value]) -> Result<String, QueryError> {
    let canonical_rows = Value::Array(rows.iter().map(canonicalize_value).collect());
    hash_json_value(&canonical_rows)
}

fn hash_evidence_summary(summary: &Value) -> Result<String, QueryError> {
    hash_json_value(&canonicalize_value(summary))
}

fn hash_json_value(value: &Value) -> Result<String, QueryError> {
    let bytes =
        serde_json::to_vec(value).map_err(|err| QueryError::CanonicalJson(err.to_string()))?;
    let digest = Sha256::digest(bytes);
    Ok(hex::encode(digest))
}

fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));

            let mut sorted = JsonMap::new();
            for (key, value) in entries {
                sorted.insert(key.clone(), canonicalize_value(value));
            }

            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_value).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_descriptor_with_defaults() {
        let descriptor = QueryDescriptor {
            query_id: None,
            version: None,
            scope: vec!["record/app/http".into()],
            filter: QueryFilter::default(),
            projection: vec!["subject_id".into(), "event_time".into()],
            aggregate: None,
            evidence: EvidencePolicy::default(),
            meta: None,
        };

        let normalized = descriptor
            .normalize_with(|| "q-fixed".to_string())
            .expect("normalize");

        assert_eq!(normalized.query_id, "q-fixed");
        assert_eq!(normalized.version, 1);
        assert_eq!(normalized.scope, vec!["record/app/http".to_string()]);
        assert_eq!(normalized.projection.len(), 2);
    }

    #[test]
    fn rejects_invalid_evidence_policy() {
        let descriptor = QueryDescriptor {
            query_id: Some("q-1".into()),
            version: Some(1),
            scope: vec!["record/app/http".into()],
            filter: QueryFilter::default(),
            projection: vec!["subject_id".into()],
            aggregate: None,
            evidence: EvidencePolicy {
                mode: EvidenceMode::Spot,
                sample_rate: None,
            },
            meta: None,
        };

        let error = descriptor.normalize().expect_err("should fail");
        assert_eq!(error, QueryError::MissingSampleRate);
    }

    #[test]
    fn validates_time_window_and_ordering() {
        let filter = QueryFilter {
            subject_id: None,
            event_type: None,
            time: TimeFilter {
                from: Some("2025-11-19T03:20:00Z".into()),
                to: Some("2025-11-18T03:20:00Z".into()),
            },
        };

        let descriptor = QueryDescriptor {
            query_id: Some("q-1".into()),
            version: Some(1),
            scope: vec!["record/app/http".into()],
            filter,
            projection: vec!["subject_id".into()],
            aggregate: None,
            evidence: EvidencePolicy::default(),
            meta: None,
        };

        let error = descriptor.normalize().expect_err("should fail");
        assert_eq!(error, QueryError::InvalidTimeWindow);
    }

    #[test]
    fn canonical_hash_ignores_field_order() {
        let row_a = serde_json::json!({
            "subject_id": "user:1",
            "event_time": "2025-11-18T12:00:00Z",
            "origin": "api",
        });
        let row_b = serde_json::json!({
            "origin": "api",
            "event_time": "2025-11-18T12:00:00Z",
            "subject_id": "user:1",
        });

        let hash_a = hash_rows(&[row_a]).expect("hash a");
        let hash_b = hash_rows(&[row_b]).expect("hash b");

        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn builds_result_digest() {
        let rows = vec![serde_json::json!({
            "subject_id": "user:123",
            "event_time": "2025-11-18T12:34:56Z",
        })];
        let evidence_policy = EvidencePolicy {
            mode: EvidenceMode::None,
            sample_rate: None,
        };
        let summary = serde_json::json!({ "mode": "none" });

        let digest = ResultDigest::from_rows_and_evidence(
            "q-1",
            Some("r-1".into()),
            &rows,
            evidence_policy,
            &summary,
            "2025-11-19T03:20:00Z",
            "hub-1",
            Some("profile-1".into()),
            || "r-1".into(),
        )
        .expect("digest");

        assert_eq!(digest.row_count, 1);
        assert_eq!(digest.result_id, "r-1");
        assert_eq!(digest.query_id, "q-1");
        assert_eq!(digest.version, 1);
    }
}
