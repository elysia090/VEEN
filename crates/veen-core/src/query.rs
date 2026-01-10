use std::fmt::Write as _;
use std::io::{self, Write as _};

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
                if !(sample > 0.0 && sample <= 1.0) {
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
    fn normalize(&mut self) -> Result<(), QueryError> {
        let (from_value, from_ts) = normalize_timestamp(self.from.as_deref())?;
        let (to_value, to_ts) = normalize_timestamp(self.to.as_deref())?;

        self.from = from_value;
        self.to = to_value;

        if let (Some(start), Some(end)) = (from_ts, to_ts) {
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
    fn normalize(mut self) -> Result<Self, QueryError> {
        if let Some(subject_id) = &self.subject_id {
            self.subject_id = Some(normalize_non_empty(
                subject_id,
                QueryError::InvalidSubjectId,
            )?);
        }

        if let Some(event_types) = self.event_type {
            self.event_type = Some(normalize_required_list(
                event_types,
                QueryError::InvalidEventTypes,
                QueryError::InvalidEventTypes,
            )?);
        }

        if let Some(from) = self.time.from.as_ref() {
            if from.trim().is_empty() {
                return Err(QueryError::InvalidTimestamp);
            }
        }

        self.time.normalize()?;

        Ok(self)
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
    fn normalize(mut self) -> Result<Self, QueryError> {
        self.group_by =
            normalize_optional_list(self.group_by, QueryError::InvalidAggregateGroupBy)?;
        self.metrics = normalize_required_list(
            self.metrics,
            QueryError::MissingMetrics,
            QueryError::InvalidAggregateMetrics,
        )?;

        Ok(self)
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

fn normalize_list_in_place(
    values: &mut Vec<String>,
    invalid_error: QueryError,
) -> Result<(), QueryError> {
    for value in values.iter_mut() {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(invalid_error);
        }
        if trimmed.len() != value.len() {
            *value = trimmed.to_string();
        }
    }

    Ok(())
}

fn normalize_optional_list(
    mut values: Vec<String>,
    invalid_error: QueryError,
) -> Result<Vec<String>, QueryError> {
    normalize_list_in_place(&mut values, invalid_error)?;
    Ok(values)
}

fn normalize_required_list(
    mut values: Vec<String>,
    empty_error: QueryError,
    invalid_error: QueryError,
) -> Result<Vec<String>, QueryError> {
    if values.is_empty() {
        return Err(empty_error);
    }

    normalize_list_in_place(&mut values, invalid_error)?;
    Ok(values)
}

fn normalize_non_empty(value: &str, error: QueryError) -> Result<String, QueryError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(error)
    } else {
        Ok(trimmed.to_string())
    }
}

impl QueryDescriptor {
    /// Normalizes and validates the descriptor according to the specification.
    ///
    /// * Fills a missing `version` with `1`.
    /// * Generates a `query_id` when absent using the provided generator.
    /// * Validates required fields and evidence constraints.
    pub fn normalize_with<F>(self, query_id_gen: F) -> Result<NormalizedQueryDescriptor, QueryError>
    where
        F: FnMut() -> String,
    {
        let version = self.version.unwrap_or(1);
        if version != 1 {
            return Err(QueryError::UnsupportedVersion(version.into()));
        }

        let scope =
            normalize_required_list(self.scope, QueryError::EmptyScope, QueryError::InvalidScope)?;
        let projection = normalize_required_list(
            self.projection,
            QueryError::EmptyProjection,
            QueryError::InvalidProjection,
        )?;

        let mut evidence = self.evidence;
        evidence.normalize()?;

        let filter = self.filter.normalize()?;

        let aggregate = match self.aggregate {
            Some(aggregate) => Some(aggregate.normalize()?),
            None => None,
        };

        let query_id = normalize_non_empty(
            &self.query_id.unwrap_or_else(query_id_gen),
            QueryError::MissingQueryId,
        )?;

        Ok(NormalizedQueryDescriptor {
            query_id,
            version,
            scope,
            filter,
            projection,
            aggregate,
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

impl NormalizedQueryDescriptor {
    /// Serializes the normalized descriptor using canonical JSON ordering.
    pub fn to_canonical_json(&self) -> Result<String, QueryError> {
        let value =
            serde_json::to_value(self).map_err(|err| QueryError::CanonicalJson(err.to_string()))?;
        let canonical = canonicalize_value(&value);
        serde_json::to_string(&canonical).map_err(|err| QueryError::CanonicalJson(err.to_string()))
    }
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

/// Context needed to build a result digest.
pub struct ResultContext {
    pub executed_at: String,
    pub hub_id: String,
    pub profile_id: Option<String>,
}

impl ResultContext {
    pub fn new(
        executed_at: impl Into<String>,
        hub_id: impl Into<String>,
        profile_id: Option<String>,
    ) -> Self {
        Self {
            executed_at: executed_at.into(),
            hub_id: hub_id.into(),
            profile_id,
        }
    }
}

impl ResultDigest {
    /// Builds a digest for the provided result set and evidence summary.
    pub fn from_rows_and_evidence<G>(
        query_id: impl Into<String>,
        result_id: Option<String>,
        rows: &[Value],
        mut evidence_policy: EvidencePolicy,
        evidence_summary: &Value,
        context: ResultContext,
        mut result_id_gen: G,
    ) -> Result<Self, QueryError>
    where
        G: FnMut() -> String,
    {
        evidence_policy.normalize()?;

        let query_id = normalize_non_empty(&query_id.into(), QueryError::InvalidQueryId)?;

        let executed_at = context.executed_at;
        validate_timestamp(&executed_at)?;

        let result_id = normalize_non_empty(
            &result_id.unwrap_or_else(&mut result_id_gen),
            QueryError::MissingResultId,
        )?;

        validate_rows(rows)?;
        validate_evidence_summary(evidence_summary, &evidence_policy, &query_id, &result_id)?;

        let hub_id = normalize_non_empty(&context.hub_id, QueryError::InvalidHubId)?;

        let profile_id = context
            .profile_id
            .map(|value| normalize_non_empty(&value, QueryError::InvalidProfileId))
            .transpose()?;

        let rows_hash = hash_rows(rows)?;
        let evidence_hash = hash_evidence_summary(evidence_summary)?;

        Ok(Self {
            query_id,
            result_id,
            version: 1,
            row_count: rows.len(),
            evidence_policy,
            rows_hash,
            evidence_hash,
            executed_at,
            hub_id,
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
            ResultContext::new(executed_at, hub_id, profile_id),
            generate_result_id,
        )
    }

    /// Serializes the digest using canonical JSON ordering.
    pub fn to_canonical_json(&self) -> Result<String, QueryError> {
        let value =
            serde_json::to_value(self).map_err(|err| QueryError::CanonicalJson(err.to_string()))?;
        let canonical = canonicalize_value(&value);
        serde_json::to_string(&canonical).map_err(|err| QueryError::CanonicalJson(err.to_string()))
    }
}

/// Errors raised when normalizing or hashing queries and results.
#[derive(Debug, Error, PartialEq)]
pub enum QueryError {
    #[error("scope must contain at least one stream")]
    EmptyScope,
    #[error("projection must contain at least one field")]
    EmptyProjection,
    #[error("scope entries must be non-empty strings")]
    InvalidScope,
    #[error("projection fields must be non-empty strings")]
    InvalidProjection,
    #[error("subject_id must be non-empty when provided")]
    InvalidSubjectId,
    #[error("query_id must be provided or generated")]
    MissingQueryId,
    #[error("query_id must be a non-empty string")]
    InvalidQueryId,
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
    #[error("aggregate metrics must be non-empty strings")]
    InvalidAggregateMetrics,
    #[error("aggregate group_by entries must be non-empty strings")]
    InvalidAggregateGroupBy,
    #[error("timestamps must follow RFC3339 UTC (example 2025-11-19T03:20:00Z)")]
    InvalidTimestamp,
    #[error("time.from must not be after time.to")]
    InvalidTimeWindow,
    #[error("unsupported query descriptor version {0}")]
    UnsupportedVersion(u64),
    #[error("failed to produce canonical JSON for hashing: {0}")]
    CanonicalJson(String),
    #[error("result rows must be JSON objects")]
    InvalidResultRow,
    #[error("hub_id must be a non-empty string")]
    InvalidHubId,
    #[error("profile_id must be non-empty when provided")]
    InvalidProfileId,
    #[error("evidence summary must be a JSON object with a mode matching the evidence policy")]
    InvalidEvidenceSummary,
    #[error("evidence summary mode must match evidence policy")]
    EvidenceModeMismatch,
    #[error("evidence summary identifiers must match query_id and result_id")]
    EvidenceIdentifierMismatch,
    #[error("evidence summary sample_rate must match evidence policy")]
    EvidenceSampleRateMismatch,
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

fn normalize_timestamp(
    raw: Option<&str>,
) -> Result<(Option<String>, Option<OffsetDateTime>), QueryError> {
    match raw {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(QueryError::InvalidTimestamp);
            }

            let parsed = validate_timestamp(trimmed)?;
            let formatted = parsed
                .format(&Rfc3339)
                .map_err(|_| QueryError::InvalidTimestamp)?;

            Ok((Some(formatted), Some(parsed)))
        }
        None => Ok((None, None)),
    }
}

fn hash_rows(rows: &[Value]) -> Result<String, QueryError> {
    let canonical_rows = Value::Array(rows.iter().map(canonicalize_value).collect());
    hash_json_value(&canonical_rows)
}

fn hash_evidence_summary(summary: &Value) -> Result<String, QueryError> {
    hash_json_value(&canonicalize_value(summary))
}

fn hash_json_value(value: &Value) -> Result<String, QueryError> {
    let mut hasher = Sha256::new();
    let mut writer = HashWriter::new(&mut hasher);
    serde_json::to_writer(&mut writer, value)
        .map_err(|err| QueryError::CanonicalJson(err.to_string()))?;
    Ok(hex::encode(hasher.finalize()))
}

fn validate_rows(rows: &[Value]) -> Result<(), QueryError> {
    if rows.iter().all(|row| matches!(row, Value::Object(_))) {
        Ok(())
    } else {
        Err(QueryError::InvalidResultRow)
    }
}

fn validate_evidence_summary(
    summary: &Value,
    policy: &EvidencePolicy,
    query_id: &str,
    result_id: &str,
) -> Result<(), QueryError> {
    let summary_obj = summary
        .as_object()
        .ok_or(QueryError::InvalidEvidenceSummary)?;

    let mode = summary_obj
        .get("mode")
        .and_then(Value::as_str)
        .ok_or(QueryError::InvalidEvidenceSummary)?;

    let expected_mode = match policy.mode {
        EvidenceMode::None => "none",
        EvidenceMode::Spot => "spot",
        EvidenceMode::Full => "full",
    };

    if mode != expected_mode {
        return Err(QueryError::EvidenceModeMismatch);
    }

    match policy.mode {
        EvidenceMode::None => {
            if summary_obj.contains_key("sample_rate") {
                return Err(QueryError::UnexpectedSampleRate);
            }
            validate_summary_identifiers(summary_obj, query_id, result_id, false)?;
            validate_verified_entries(summary_obj.get("verified"))?;
        }
        EvidenceMode::Spot => {
            let expected = policy.sample_rate.ok_or(QueryError::MissingSampleRate)?;
            let sample_rate = summary_obj
                .get("sample_rate")
                .and_then(Value::as_f64)
                .ok_or(QueryError::MissingSampleRate)?;

            if (sample_rate - expected).abs() > f64::EPSILON {
                return Err(QueryError::EvidenceSampleRateMismatch);
            }

            validate_summary_identifiers(summary_obj, query_id, result_id, true)?;

            let verified = summary_obj
                .get("verified")
                .ok_or(QueryError::InvalidEvidenceSummary)?;
            validate_verified_entries(Some(verified))?;
        }
        EvidenceMode::Full => {
            if summary_obj.contains_key("sample_rate") {
                return Err(QueryError::UnexpectedSampleRate);
            }

            validate_summary_identifiers(summary_obj, query_id, result_id, true)?;

            let verified = summary_obj
                .get("verified")
                .ok_or(QueryError::InvalidEvidenceSummary)?;
            validate_verified_entries(Some(verified))?;
        }
    }

    Ok(())
}

fn validate_summary_identifiers(
    summary_obj: &JsonMap<String, Value>,
    query_id: &str,
    result_id: &str,
    required: bool,
) -> Result<(), QueryError> {
    let summary_query_id = summary_obj.get("query_id").and_then(Value::as_str);
    let summary_result_id = summary_obj.get("result_id").and_then(Value::as_str);

    if required {
        let summary_query_id = summary_query_id.ok_or(QueryError::InvalidEvidenceSummary)?;
        let summary_result_id = summary_result_id.ok_or(QueryError::InvalidEvidenceSummary)?;
        if summary_query_id.trim() != query_id || summary_result_id.trim() != result_id {
            return Err(QueryError::EvidenceIdentifierMismatch);
        }
        return Ok(());
    }

    if let Some(value) = summary_query_id {
        if value.trim() != query_id {
            return Err(QueryError::EvidenceIdentifierMismatch);
        }
    }

    if let Some(value) = summary_result_id {
        if value.trim() != result_id {
            return Err(QueryError::EvidenceIdentifierMismatch);
        }
    }

    Ok(())
}

fn validate_verified_entries(value: Option<&Value>) -> Result<(), QueryError> {
    match value {
        None => Ok(()),
        Some(verified) => {
            let entries = verified
                .as_array()
                .ok_or(QueryError::InvalidEvidenceSummary)?;

            if entries.iter().any(|entry| !entry.is_object()) {
                return Err(QueryError::InvalidEvidenceSummary);
            }

            Ok(())
        }
    }
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

struct HashWriter<'a, D> {
    hasher: &'a mut D,
}

impl<'a, D> HashWriter<'a, D> {
    fn new(hasher: &'a mut D) -> Self {
        Self { hasher }
    }
}

impl<D> io::Write for HashWriter<'_, D>
where
    D: Digest,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.hasher.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
    fn rejects_zero_sample_rate() {
        let descriptor = QueryDescriptor {
            query_id: Some("q-1".into()),
            version: Some(1),
            scope: vec!["record/app/http".into()],
            filter: QueryFilter::default(),
            projection: vec!["subject_id".into()],
            aggregate: None,
            evidence: EvidencePolicy {
                mode: EvidenceMode::Spot,
                sample_rate: Some(0.0),
            },
            meta: None,
        };

        let error = descriptor.normalize().expect_err("should fail");
        assert_eq!(error, QueryError::InvalidSampleRate(0.0));
    }

    #[test]
    fn rejects_blank_scope_entries() {
        let descriptor = QueryDescriptor {
            query_id: None,
            version: None,
            scope: vec!["   ".into()],
            filter: QueryFilter::default(),
            projection: vec!["subject_id".into()],
            aggregate: None,
            evidence: EvidencePolicy::default(),
            meta: None,
        };

        let error = descriptor.normalize().expect_err("should fail");
        assert_eq!(error, QueryError::InvalidScope);
    }

    #[test]
    fn rejects_blank_projection_entries() {
        let descriptor = QueryDescriptor {
            query_id: None,
            version: None,
            scope: vec!["record/app/http".into()],
            filter: QueryFilter::default(),
            projection: vec!["".into()],
            aggregate: None,
            evidence: EvidencePolicy::default(),
            meta: None,
        };

        let error = descriptor.normalize().expect_err("should fail");
        assert_eq!(error, QueryError::InvalidProjection);
    }

    #[test]
    fn rejects_blank_aggregate_fields() {
        let aggregate = Aggregate {
            group_by: vec!["".into()],
            metrics: vec!["   ".into()],
        };

        let descriptor = QueryDescriptor {
            query_id: Some("q-1".into()),
            version: Some(1),
            scope: vec!["record/app/http".into()],
            filter: QueryFilter::default(),
            projection: vec!["subject_id".into()],
            aggregate: Some(aggregate),
            evidence: EvidencePolicy::default(),
            meta: None,
        };

        let error = descriptor.normalize().expect_err("should fail");
        assert_eq!(error, QueryError::InvalidAggregateGroupBy);
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
    fn normalizes_time_filter_to_canonical_rfc3339() {
        let descriptor = QueryDescriptor {
            query_id: Some("q-1".into()),
            version: Some(1),
            scope: vec!["record/app/http".into()],
            filter: QueryFilter {
                subject_id: None,
                event_type: None,
                time: TimeFilter {
                    from: Some(" 2025-11-18T12:00:00Z ".into()),
                    to: Some("2025-11-19T01:00:00Z".into()),
                },
            },
            projection: vec!["subject_id".into()],
            aggregate: None,
            evidence: EvidencePolicy::default(),
            meta: None,
        };

        let normalized = descriptor.normalize().expect("normalize");

        assert_eq!(
            normalized.filter.time.from.as_deref(),
            Some("2025-11-18T12:00:00Z")
        );
        assert_eq!(
            normalized.filter.time.to.as_deref(),
            Some("2025-11-19T01:00:00Z")
        );
    }

    #[test]
    fn rejects_non_utc_timestamps_in_time_filter() {
        let descriptor = QueryDescriptor {
            query_id: Some("q-1".into()),
            version: Some(1),
            scope: vec!["record/app/http".into()],
            filter: QueryFilter {
                subject_id: None,
                event_type: None,
                time: TimeFilter {
                    from: Some("2025-11-18T12:00:00+02:00".into()),
                    to: None,
                },
            },
            projection: vec!["subject_id".into()],
            aggregate: None,
            evidence: EvidencePolicy::default(),
            meta: None,
        };

        let error = descriptor.normalize().expect_err("should fail");

        assert_eq!(error, QueryError::InvalidTimestamp);
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
    fn descriptor_to_canonical_json_sorts_keys() {
        let descriptor = NormalizedQueryDescriptor {
            query_id: "q-1".into(),
            version: 1,
            scope: vec!["record/app/http".into()],
            filter: QueryFilter::default(),
            projection: vec!["subject_id".into(), "event_time".into()],
            aggregate: None,
            evidence: EvidencePolicy::default(),
            meta: Some(JsonMap::from_iter([
                ("z_key".into(), Value::from(9)),
                ("a_key".into(), Value::from("first")),
            ])),
        };

        let encoded = descriptor.to_canonical_json().expect("canonical json");
        assert_eq!(
            encoded,
            "{\"evidence\":{\"mode\":\"none\"},\"filter\":{},\"meta\":{\"a_key\":\"first\",\"z_key\":9},\"projection\":[\"subject_id\",\"event_time\"],\"query_id\":\"q-1\",\"scope\":[\"record/app/http\"],\"version\":1}"
        );
    }

    #[test]
    fn digest_to_canonical_json_sorts_keys() {
        let digest = ResultDigest {
            query_id: "q-1".into(),
            result_id: "r-1".into(),
            version: 1,
            row_count: 2,
            evidence_policy: EvidencePolicy::default(),
            rows_hash: "aa".into(),
            evidence_hash: "bb".into(),
            executed_at: "2025-11-19T03:20:00Z".into(),
            hub_id: "hub-1".into(),
            profile_id: Some("profile-1".into()),
        };

        let encoded = digest.to_canonical_json().expect("canonical json");
        assert_eq!(
            encoded,
            "{\"evidence_hash\":\"bb\",\"evidence_policy\":{\"mode\":\"none\"},\"executed_at\":\"2025-11-19T03:20:00Z\",\"hub_id\":\"hub-1\",\"profile_id\":\"profile-1\",\"query_id\":\"q-1\",\"result_id\":\"r-1\",\"row_count\":2,\"rows_hash\":\"aa\",\"version\":1}"
        );
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
            ResultContext::new("2025-11-19T03:20:00Z", "hub-1", Some("profile-1".into())),
            || "r-1".into(),
        )
        .expect("digest");

        assert_eq!(digest.row_count, 1);
        assert_eq!(digest.result_id, "r-1");
        assert_eq!(digest.query_id, "q-1");
        assert_eq!(digest.version, 1);
    }

    #[test]
    fn rejects_non_object_rows() {
        let rows = vec![serde_json::json!("not-an-object")];
        let evidence_policy = EvidencePolicy::default();
        let summary = serde_json::json!({ "mode": "none" });

        let error = ResultDigest::from_rows_and_evidence(
            "q-1",
            Some("r-1".into()),
            &rows,
            evidence_policy,
            &summary,
            ResultContext::new("2025-11-19T03:20:00Z", "hub-1", None),
            || "r-1".into(),
        )
        .expect_err("should fail");

        assert_eq!(error, QueryError::InvalidResultRow);
    }

    #[test]
    fn rejects_blank_hub_and_profile_ids() {
        let rows = vec![serde_json::json!({ "subject_id": "user:123" })];
        let evidence_policy = EvidencePolicy::default();
        let summary = serde_json::json!({ "mode": "none" });

        let error = ResultDigest::from_rows_and_evidence(
            "q-1",
            Some("r-1".into()),
            &rows,
            evidence_policy.clone(),
            &summary,
            ResultContext::new("2025-11-19T03:20:00Z", "   ", None),
            || "r-1".into(),
        )
        .expect_err("should fail");

        assert_eq!(error, QueryError::InvalidHubId);

        let error = ResultDigest::from_rows_and_evidence(
            "q-1",
            Some("r-1".into()),
            &rows,
            evidence_policy,
            &summary,
            ResultContext::new("2025-11-19T03:20:00Z", "hub-1", Some("   ".into())),
            || "r-1".into(),
        )
        .expect_err("should fail");

        assert_eq!(error, QueryError::InvalidProfileId);
    }

    #[test]
    fn rejects_blank_query_id_in_digest() {
        let rows = vec![serde_json::json!({ "subject_id": "user:123" })];
        let summary = serde_json::json!({ "mode": "none" });

        let error = ResultDigest::from_rows_and_evidence(
            "   ",
            Some("r-1".into()),
            &rows,
            EvidencePolicy::default(),
            &summary,
            ResultContext::new("2025-11-19T03:20:00Z", "hub-1", None),
            || "r-1".into(),
        )
        .expect_err("should fail");

        assert_eq!(error, QueryError::InvalidQueryId);
    }

    #[test]
    fn validates_evidence_summary_mode_and_identifiers() {
        let rows = vec![serde_json::json!({ "subject_id": "user:123" })];
        let evidence_policy = EvidencePolicy {
            mode: EvidenceMode::Spot,
            sample_rate: Some(0.5),
        };

        let wrong_mode = serde_json::json!({
            "mode": "full",
            "sample_rate": 0.5,
            "query_id": "q-1",
            "result_id": "r-1",
        });

        let error = ResultDigest::from_rows_and_evidence(
            "q-1",
            Some("r-1".into()),
            &rows,
            evidence_policy.clone(),
            &wrong_mode,
            ResultContext::new("2025-11-19T03:20:00Z", "hub-1", None),
            || "r-1".into(),
        )
        .expect_err("should fail");

        assert_eq!(error, QueryError::EvidenceModeMismatch);

        let mismatched_ids = serde_json::json!({
            "mode": "spot",
            "sample_rate": 0.5,
            "query_id": "other",
            "result_id": "r-1",
        });

        let error = ResultDigest::from_rows_and_evidence(
            "q-1",
            Some("r-1".into()),
            &rows,
            evidence_policy.clone(),
            &mismatched_ids,
            ResultContext::new("2025-11-19T03:20:00Z", "hub-1", None),
            || "r-1".into(),
        )
        .expect_err("should fail");

        assert_eq!(error, QueryError::EvidenceIdentifierMismatch);

        let mismatched_sample_rate = serde_json::json!({
            "mode": "spot",
            "sample_rate": 0.7,
            "query_id": "q-1",
            "result_id": "r-1",
        });

        let error = ResultDigest::from_rows_and_evidence(
            "q-1",
            Some("r-1".into()),
            &rows,
            evidence_policy,
            &mismatched_sample_rate,
            ResultContext::new("2025-11-19T03:20:00Z", "hub-1", None),
            || "r-1".into(),
        )
        .expect_err("should fail");

        assert_eq!(error, QueryError::EvidenceSampleRateMismatch);
    }

    #[test]
    fn rejects_incomplete_evidence_summary_for_strict_modes() {
        let rows = vec![serde_json::json!({ "subject_id": "user:123" })];
        let spot_policy = EvidencePolicy {
            mode: EvidenceMode::Spot,
            sample_rate: Some(0.5),
        };

        let error = ResultDigest::from_rows_and_evidence(
            "q-1",
            Some("r-1".into()),
            &rows,
            spot_policy.clone(),
            &serde_json::json!({
                "mode": "spot",
                "sample_rate": 0.5,
                "verified": [],
            }),
            ResultContext::new("2025-11-19T03:20:00Z", "hub-1", None),
            || "ignored".into(),
        )
        .expect_err("should fail when IDs are missing");

        assert_eq!(error, QueryError::InvalidEvidenceSummary);

        let error = ResultDigest::from_rows_and_evidence(
            "q-1",
            Some("r-1".into()),
            &rows,
            spot_policy,
            &serde_json::json!({
                "mode": "spot",
                "sample_rate": 0.5,
                "query_id": "q-1",
                "result_id": "r-1",
            }),
            ResultContext::new("2025-11-19T03:20:00Z", "hub-1", None),
            || "ignored".into(),
        )
        .expect_err("should fail when verified is missing");

        assert_eq!(error, QueryError::InvalidEvidenceSummary);

        let error = ResultDigest::from_rows_and_evidence(
            "q-1",
            Some("r-1".into()),
            &rows,
            EvidencePolicy {
                mode: EvidenceMode::Full,
                sample_rate: None,
            },
            &serde_json::json!({
                "mode": "full",
                "query_id": "q-1",
                "result_id": "r-1",
            }),
            ResultContext::new("2025-11-19T03:20:00Z", "hub-1", None),
            || "ignored".into(),
        )
        .expect_err("should fail when verified is missing for full mode");

        assert_eq!(error, QueryError::InvalidEvidenceSummary);
    }
}
