use std::collections::hash_map::Entry;
use std::collections::HashMap;

use ciborium::value::Value;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{h, realm::RealmId};

use super::{ContextId, OrgId};

/// Returns the schema identifier for `id.external.v1` as defined in the
/// identity specification.
#[must_use]
pub fn schema_external_link() -> [u8; 32] {
    h(b"id.external.v1")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalLinkRecordDe {
    realm_id: RealmId,
    #[serde(default)]
    ctx_id: Option<ContextId>,
    #[serde(default)]
    org_id: Option<OrgId>,
    provider: String,
    external_sub: String,
    #[serde(default)]
    attributes: Option<Value>,
    ts: u64,
}

/// External identity linkage as defined in section 10.2 of the identity
/// specification.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalLinkRecord {
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctx_id: Option<ContextId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<OrgId>,
    pub provider: String,
    pub external_sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Value>,
    pub ts: u64,
}

impl ExternalLinkRecord {
    /// Returns `true` if the record references at least one local identifier.
    #[must_use]
    pub fn has_subject(&self) -> bool {
        self.ctx_id.is_some() || self.org_id.is_some()
    }
}

impl<'de> Deserialize<'de> for ExternalLinkRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let record = ExternalLinkRecordDe::deserialize(deserializer)?;
        if record.ctx_id.is_none() && record.org_id.is_none() {
            return Err(DeError::custom(
                "external link must reference ctx_id or org_id",
            ));
        }

        if let Some(ref value) = record.attributes {
            if !matches!(value, Value::Map(_)) {
                return Err(DeError::custom("attributes must be a CBOR map"));
            }
        }

        Ok(Self {
            realm_id: record.realm_id,
            ctx_id: record.ctx_id,
            org_id: record.org_id,
            provider: record.provider,
            external_sub: record.external_sub,
            attributes: record.attributes,
            ts: record.ts,
        })
    }
}

#[derive(Debug, Clone)]
struct ExternalEntry {
    record: ExternalLinkRecord,
    stream_seq: u64,
}

/// Index of external identity linkages applying the LWW semantics described in
/// the specification.
#[derive(Debug, Clone, Default)]
pub struct ExternalLinkDirectory {
    providers: HashMap<String, HashMap<String, ExternalEntry>>,
}

impl ExternalLinkDirectory {
    /// Creates an empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Removes all stored linkages.
    pub fn clear(&mut self) {
        self.providers.clear();
    }

    /// Returns the number of stored linkages.
    #[must_use]
    pub fn len(&self) -> usize {
        self.providers.values().map(HashMap::len).sum()
    }

    /// Returns `true` if the directory is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.values().all(HashMap::is_empty)
    }

    /// Inserts a record, applying the `(ts, stream_seq)` precedence rule.
    pub fn upsert(&mut self, record: ExternalLinkRecord, stream_seq: u64) {
        let provider_key = record.provider.clone();
        let subject_key = record.external_sub.clone();
        let provider_map = self.providers.entry(provider_key).or_default();

        match provider_map.entry(subject_key) {
            Entry::Vacant(slot) => {
                slot.insert(ExternalEntry { record, stream_seq });
            }
            Entry::Occupied(mut slot) => {
                let replace =
                    (record.ts, stream_seq) >= (slot.get().record.ts, slot.get().stream_seq);
                if replace {
                    slot.insert(ExternalEntry { record, stream_seq });
                }
            }
        }
    }

    /// Returns the record for the given provider and external subject.
    #[must_use]
    pub fn get(&self, provider: &str, external_sub: &str) -> Option<&ExternalLinkRecord> {
        self.providers
            .get(provider)
            .and_then(|subjects| subjects.get(external_sub))
            .map(|entry| &entry.record)
    }

    /// Returns an iterator over stored linkages.
    pub fn records(&self) -> impl Iterator<Item = &ExternalLinkRecord> {
        self.providers
            .values()
            .flat_map(|subjects| subjects.values().map(|entry| &entry.record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_matches_expected_digest() {
        assert_eq!(
            schema_external_link(),
            [
                0xbe, 0xa8, 0x94, 0xa1, 0x9e, 0x52, 0x2b, 0xc3, 0x18, 0xdc, 0xce, 0xb3, 0x4a, 0xc9,
                0xb1, 0x34, 0x27, 0x8d, 0xf5, 0x99, 0xed, 0x87, 0xbf, 0xd4, 0x52, 0xf7, 0xd9, 0xc2,
                0xed, 0x51, 0xb9, 0xe1,
            ]
        );
    }

    #[test]
    fn record_requires_subject() {
        let realm = RealmId::derive("realm");
        let value = Value::Map(vec![
            (
                Value::Text("realm_id".into()),
                Value::Bytes(realm.as_ref().to_vec()),
            ),
            (Value::Text("provider".into()), Value::Text("github".into())),
            (
                Value::Text("external_sub".into()),
                Value::Text("alice".into()),
            ),
            (Value::Text("ts".into()), Value::Integer(0u8.into())),
        ]);

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&value, &mut buf).expect("serialize value");
        let result: Result<ExternalLinkRecord, _> = ciborium::de::from_reader(buf.as_slice());
        assert!(result.is_err(), "missing ctx_id/org_id must error");
    }

    #[test]
    fn attributes_must_be_map() {
        let realm = RealmId::derive("realm");
        let ctx = ContextId::new([0x11; 32]);
        let value = Value::Map(vec![
            (
                Value::Text("realm_id".into()),
                Value::Bytes(realm.as_ref().to_vec()),
            ),
            (
                Value::Text("ctx_id".into()),
                Value::Bytes(ctx.as_ref().to_vec()),
            ),
            (Value::Text("provider".into()), Value::Text("google".into())),
            (
                Value::Text("external_sub".into()),
                Value::Text("alice".into()),
            ),
            (Value::Text("attributes".into()), Value::Array(Vec::new())),
            (Value::Text("ts".into()), Value::Integer(1u8.into())),
        ]);

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&value, &mut buf).expect("serialize value");
        let result: Result<ExternalLinkRecord, _> = ciborium::de::from_reader(buf.as_slice());
        assert!(result.is_err(), "attributes must be map");
    }

    #[test]
    fn directory_applies_lww_semantics() {
        let realm = RealmId::derive("realm");
        let ctx_a = ContextId::new([0x21; 32]);
        let ctx_b = ContextId::new([0x22; 32]);
        let mut dir = ExternalLinkDirectory::new();

        let record_a = ExternalLinkRecord {
            realm_id: realm,
            ctx_id: Some(ctx_a),
            org_id: None,
            provider: "github".into(),
            external_sub: "alice".into(),
            attributes: None,
            ts: 100,
        };
        let record_b = ExternalLinkRecord {
            realm_id: realm,
            ctx_id: Some(ctx_b),
            org_id: None,
            provider: "github".into(),
            external_sub: "alice".into(),
            attributes: None,
            ts: 101,
        };

        dir.upsert(record_a.clone(), 4);
        dir.upsert(record_b.clone(), 1);

        let resolved = dir.get("github", "alice").expect("link");
        assert_eq!(resolved.ctx_id, Some(ctx_b));

        // Lower timestamp loses even with higher stream sequence.
        dir.upsert(record_a.clone(), 10);
        let resolved = dir.get("github", "alice").expect("link");
        assert_eq!(resolved.ctx_id, Some(ctx_b));

        // Equal timestamp uses stream sequence as tie breaker.
        let mut record_c = record_b.clone();
        record_c.ts = 101;
        dir.upsert(record_c.clone(), 8);
        let resolved = dir.get("github", "alice").expect("link");
        assert_eq!(resolved.ctx_id, record_c.ctx_id);

        assert_eq!(dir.len(), 1);
    }
}
