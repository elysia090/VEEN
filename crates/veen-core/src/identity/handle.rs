use std::collections::hash_map::Entry;
use std::collections::HashMap;

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{h, realm::RealmId};

use super::{ContextId, OrgId};

/// Returns the schema identifier for `id.handlemap.v1` as defined in the
/// identity specification.
#[must_use]
pub fn schema_handle_map() -> [u8; 32] {
    h(b"id.handlemap.v1")
}

/// Target entity referenced by a handle mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandleTarget {
    /// Handle resolves to a context identifier.
    Context(ContextId),
    /// Handle resolves to an organisation identifier.
    Org(OrgId),
}

impl HandleTarget {
    /// Returns the [`HandleTargetType`] corresponding to the target.
    #[must_use]
    pub const fn target_type(&self) -> HandleTargetType {
        match self {
            Self::Context(_) => HandleTargetType::Ctx,
            Self::Org(_) => HandleTargetType::Org,
        }
    }

    /// Returns the target as a context identifier if applicable.
    #[must_use]
    pub const fn context_id(self) -> Option<ContextId> {
        match self {
            Self::Context(id) => Some(id),
            Self::Org(_) => None,
        }
    }

    /// Returns the target as an organisation identifier if applicable.
    #[must_use]
    pub const fn org_id(self) -> Option<OrgId> {
        match self {
            Self::Context(_) => None,
            Self::Org(id) => Some(id),
        }
    }

    #[must_use]
    fn id_bytes(&self) -> &[u8; super::ID_LEN] {
        match self {
            Self::Context(id) => id.as_bytes(),
            Self::Org(id) => id.as_bytes(),
        }
    }
}

impl From<ContextId> for HandleTarget {
    fn from(value: ContextId) -> Self {
        Self::Context(value)
    }
}

impl From<OrgId> for HandleTarget {
    fn from(value: OrgId) -> Self {
        Self::Org(value)
    }
}

/// Identifier describing the kind of entity referenced by a handle mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HandleTargetType {
    /// Handle resolves to a context identifier.
    Ctx,
    /// Handle resolves to an organisation identifier.
    Org,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct HandleRecordSer<'a> {
    realm_id: &'a RealmId,
    handle: &'a str,
    target_type: HandleTargetType,
    #[serde(with = "serde_bytes")]
    target_id: &'a [u8],
    ts: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HandleRecordDe {
    realm_id: RealmId,
    handle: String,
    target_type: HandleTargetType,
    #[serde(with = "serde_bytes")]
    target_id: Vec<u8>,
    ts: u64,
}

/// Handle mapping record as defined in section 10.1 of the identity
/// specification. Mappings form an LWW-register keyed by
/// `(realm_id, handle)` where precedence is determined by `(ts, stream_seq)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleRecord {
    pub realm_id: RealmId,
    pub handle: String,
    pub target: HandleTarget,
    pub ts: u64,
}

impl HandleRecord {
    /// Creates a new handle record for the provided parameters.
    #[must_use]
    pub fn new(
        realm_id: RealmId,
        handle: impl Into<String>,
        target: HandleTarget,
        ts: u64,
    ) -> Self {
        Self {
            realm_id,
            handle: handle.into(),
            target,
            ts,
        }
    }

    /// Returns the [`HandleTargetType`] stored in this record.
    #[must_use]
    pub const fn target_type(&self) -> HandleTargetType {
        self.target.target_type()
    }
}

impl Serialize for HandleRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: &[u8] = self.target.id_bytes();
        let view = HandleRecordSer {
            realm_id: &self.realm_id,
            handle: &self.handle,
            target_type: self.target_type(),
            target_id: bytes,
            ts: self.ts,
        };
        view.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HandleRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let record = HandleRecordDe::deserialize(deserializer)?;
        let target = match record.target_type {
            HandleTargetType::Ctx => ContextId::from_slice(&record.target_id)
                .map(HandleTarget::Context)
                .map_err(DeError::custom)?,
            HandleTargetType::Org => OrgId::from_slice(&record.target_id)
                .map(HandleTarget::Org)
                .map_err(DeError::custom)?,
        };

        Ok(Self {
            realm_id: record.realm_id,
            handle: record.handle,
            target,
            ts: record.ts,
        })
    }
}

#[derive(Debug, Clone)]
struct HandleEntry {
    record: HandleRecord,
    stream_seq: u64,
}

/// Materialised view over handle mappings grouped by realm.
#[derive(Debug, Clone, Default)]
pub struct HandleNamespace {
    realms: HashMap<RealmId, HashMap<String, HandleEntry>>,
}

impl HandleNamespace {
    /// Creates an empty handle namespace view.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Removes all stored mappings.
    pub fn clear(&mut self) {
        self.realms.clear();
    }

    /// Returns the number of stored mappings across all realms.
    #[must_use]
    pub fn len(&self) -> usize {
        self.realms.values().map(HashMap::len).sum()
    }

    /// Returns `true` if no mappings are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.realms.values().all(HashMap::is_empty)
    }

    /// Inserts or updates a handle mapping using the LWW rule from the
    /// specification. Records with a smaller `(ts, stream_seq)` pair are
    /// ignored.
    pub fn upsert(&mut self, record: HandleRecord, stream_seq: u64) {
        let realm_id = record.realm_id;
        let handle_key = record.handle.clone();
        let entry_map = self.realms.entry(realm_id).or_default();

        match entry_map.entry(handle_key) {
            Entry::Vacant(slot) => {
                slot.insert(HandleEntry { record, stream_seq });
            }
            Entry::Occupied(mut slot) => {
                let replace =
                    (record.ts, stream_seq) >= (slot.get().record.ts, slot.get().stream_seq);
                if replace {
                    slot.insert(HandleEntry { record, stream_seq });
                }
            }
        }
    }

    /// Resolves a handle for the specified realm.
    #[must_use]
    pub fn resolve(&self, realm_id: RealmId, handle: &str) -> Option<&HandleRecord> {
        self.realms
            .get(&realm_id)
            .and_then(|handles| handles.get(handle))
            .map(|entry| &entry.record)
    }

    /// Returns an iterator over the stored handle records.
    pub fn records(&self) -> impl Iterator<Item = &HandleRecord> {
        self.realms
            .values()
            .flat_map(|handles| handles.values().map(|entry| &entry.record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realm::RealmId;

    #[test]
    fn schema_matches_expected_digest() {
        assert_eq!(
            schema_handle_map(),
            [
                0x74, 0x54, 0xd5, 0x11, 0xff, 0x99, 0x15, 0x78, 0xe2, 0x9b, 0x35, 0x4a, 0x41, 0xc8,
                0xb9, 0x27, 0x7c, 0x83, 0xa8, 0xfb, 0x69, 0x2b, 0x4e, 0x71, 0x86, 0xeb, 0xe4, 0xb3,
                0x3b, 0x6e, 0x9c, 0x88,
            ]
        );
    }

    #[test]
    fn handle_record_round_trip() {
        let realm = RealmId::derive("example");
        let ctx = ContextId::new([0x11; 32]);
        let record = HandleRecord::new(realm, "@alice", HandleTarget::Context(ctx), 42);

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&record, &mut buf).expect("serialize");
        let decoded: HandleRecord = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(decoded, record);
    }

    #[test]
    fn namespace_applies_lww_semantics() {
        let realm = RealmId::derive("realm");
        let ctx_old = ContextId::new([0xAA; 32]);
        let ctx_new = ContextId::new([0xBB; 32]);
        let mut ns = HandleNamespace::new();

        ns.upsert(
            HandleRecord::new(realm, "user", HandleTarget::Context(ctx_old), 10),
            5,
        );
        ns.upsert(
            HandleRecord::new(realm, "user", HandleTarget::Context(ctx_new), 11),
            3,
        );

        let resolved = ns.resolve(realm, "user").expect("mapping");
        assert_eq!(resolved.target.context_id(), Some(ctx_new));

        // Lower timestamp should not replace even with higher stream sequence.
        ns.upsert(
            HandleRecord::new(realm, "user", HandleTarget::Context(ctx_old), 9),
            100,
        );
        let resolved = ns.resolve(realm, "user").expect("mapping");
        assert_eq!(resolved.target.context_id(), Some(ctx_new));

        // Equal timestamp prefers the greater stream sequence.
        ns.upsert(
            HandleRecord::new(realm, "user", HandleTarget::Context(ctx_old), 11),
            7,
        );
        let resolved = ns.resolve(realm, "user").expect("mapping");
        assert_eq!(resolved.target.context_id(), Some(ctx_old));
    }

    #[test]
    fn namespace_tracks_multiple_realms() {
        let realm_a = RealmId::derive("a");
        let realm_b = RealmId::derive("b");
        let ctx_a = ContextId::new([0x01; 32]);
        let ctx_b = ContextId::new([0x02; 32]);
        let mut ns = HandleNamespace::new();

        ns.upsert(HandleRecord::new(realm_a, "user", ctx_a.into(), 1), 1);
        ns.upsert(HandleRecord::new(realm_b, "user", ctx_b.into(), 1), 1);

        assert_eq!(ns.len(), 2);
        assert_eq!(
            ns.resolve(realm_a, "user").unwrap().target.context_id(),
            Some(ctx_a)
        );
        assert_eq!(
            ns.resolve(realm_b, "user").unwrap().target.context_id(),
            Some(ctx_b)
        );
    }
}
