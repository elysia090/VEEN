use std::{
    collections::{hash_map::Entry, HashMap},
    convert::TryFrom,
    fmt,
};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{h, LengthError};

/// Length in bytes of schema identifiers and owner keys.
pub const SCHEMA_ID_LEN: usize = 32;

/// Returns the schema identifier for `veen.meta.schema.v1`.
#[must_use]
pub fn schema_meta_schema() -> [u8; 32] {
    h(b"veen.meta.schema.v1")
}

/// Strongly typed wrapper for schema identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaId([u8; SCHEMA_ID_LEN]);

impl SchemaId {
    /// Creates a new [`SchemaId`] from the provided byte array.
    #[must_use]
    pub const fn new(bytes: [u8; SCHEMA_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SCHEMA_ID_LEN] {
        &self.0
    }

    /// Attempts to construct a [`SchemaId`] from an arbitrary slice enforcing the
    /// exact length from the specification.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != SCHEMA_ID_LEN {
            return Err(LengthError::new(SCHEMA_ID_LEN, bytes.len()));
        }
        let mut out = [0u8; SCHEMA_ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }
}

impl From<[u8; SCHEMA_ID_LEN]> for SchemaId {
    fn from(value: [u8; SCHEMA_ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; SCHEMA_ID_LEN]> for SchemaId {
    fn from(value: &[u8; SCHEMA_ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for SchemaId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for SchemaId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for SchemaId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for SchemaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for SchemaId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct SchemaIdVisitor;

impl<'de> Visitor<'de> for SchemaIdVisitor {
    type Value = SchemaId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte schema identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        SchemaId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for SchemaId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(SchemaIdVisitor)
    }
}

/// Wrapper for optional owner public keys carried by schema descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaOwner([u8; SCHEMA_ID_LEN]);

impl SchemaOwner {
    /// Creates a new [`SchemaOwner`] from the provided byte array.
    #[must_use]
    pub const fn new(bytes: [u8; SCHEMA_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SCHEMA_ID_LEN] {
        &self.0
    }

    /// Attempts to construct a [`SchemaOwner`] from an arbitrary slice, enforcing the
    /// fixed length in the specification.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != SCHEMA_ID_LEN {
            return Err(LengthError::new(SCHEMA_ID_LEN, bytes.len()));
        }
        let mut out = [0u8; SCHEMA_ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }
}

impl From<[u8; SCHEMA_ID_LEN]> for SchemaOwner {
    fn from(value: [u8; SCHEMA_ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; SCHEMA_ID_LEN]> for SchemaOwner {
    fn from(value: &[u8; SCHEMA_ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for SchemaOwner {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for SchemaOwner {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for SchemaOwner {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for SchemaOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for SchemaOwner {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct SchemaOwnerVisitor;

impl<'de> Visitor<'de> for SchemaOwnerVisitor {
    type Value = SchemaOwner;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte schema owner key")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        SchemaOwner::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for SchemaOwner {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(SchemaOwnerVisitor)
    }
}

/// Schema descriptor carried on `stream_schema_meta` as defined by META0+.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaDescriptor {
    pub schema_id: SchemaId,
    pub name: String,
    pub version: String,
    pub doc_url: Option<String>,
    pub owner: Option<SchemaOwner>,
    pub ts: u64,
}

#[derive(Debug, Clone)]
struct RegistryEntry {
    descriptor: SchemaDescriptor,
    stream_seq: u64,
}

/// In-memory registry mapping schema identifiers to their latest descriptors as
/// recommended by META0+.
#[derive(Debug, Clone, Default)]
pub struct SchemaRegistry {
    entries: HashMap<SchemaId, RegistryEntry>,
}

impl SchemaRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Removes all stored descriptors.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the number of tracked schema descriptors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the registry does not contain any descriptors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Inserts or updates a schema descriptor using `(ts, stream_seq)`
    /// last-writer-wins precedence.
    pub fn upsert(&mut self, descriptor: SchemaDescriptor, stream_seq: u64) {
        let key = descriptor.schema_id;
        match self.entries.entry(key) {
            Entry::Vacant(slot) => {
                slot.insert(RegistryEntry {
                    descriptor,
                    stream_seq,
                });
            }
            Entry::Occupied(mut slot) => {
                let replace =
                    (descriptor.ts, stream_seq) >= (slot.get().descriptor.ts, slot.get().stream_seq);
                if replace {
                    slot.insert(RegistryEntry {
                        descriptor,
                        stream_seq,
                    });
                }
            }
        }
    }

    /// Returns the descriptor for the provided schema identifier, if present.
    #[must_use]
    pub fn get(&self, schema_id: &SchemaId) -> Option<&SchemaDescriptor> {
        self.entries
            .get(schema_id)
            .map(|entry| &entry.descriptor)
    }

    /// Returns an iterator over stored schema descriptors.
    pub fn descriptors(&self) -> impl Iterator<Item = &SchemaDescriptor> {
        self.entries.values().map(|entry| &entry.descriptor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_matches_expected_digest() {
        assert_eq!(
            schema_meta_schema(),
            [
                0x7c, 0x54, 0x39, 0xfa, 0xf0, 0x99, 0xaf, 0x62, 0xd3, 0x54, 0xaf, 0x26, 0x5f, 0x5a,
                0xf7, 0x2b, 0x80, 0x0c, 0xfb, 0xdc, 0xec, 0xc6, 0x17, 0x50, 0x46, 0x0d, 0x64, 0x1a,
                0x1a, 0x8a, 0x81, 0x41,
            ]
        );
    }

    #[test]
    fn schema_id_from_slice_enforces_length() {
        let bytes = [0xAA; SCHEMA_ID_LEN];
        let id = SchemaId::from_slice(&bytes).expect("schema id");
        assert_eq!(id.as_bytes(), &bytes);

        let err = SchemaId::from_slice(&bytes[..SCHEMA_ID_LEN - 1]).expect_err("length error");
        assert_eq!(err.expected(), SCHEMA_ID_LEN);
        assert_eq!(err.actual(), SCHEMA_ID_LEN - 1);
    }

    #[test]
    fn schema_owner_from_slice_enforces_length() {
        let bytes = [0x55; SCHEMA_ID_LEN];
        let owner = SchemaOwner::from_slice(&bytes).expect("schema owner");
        assert_eq!(owner.as_bytes(), &bytes);

        let err = SchemaOwner::from_slice(&bytes[..SCHEMA_ID_LEN - 1]).expect_err("length error");
        assert_eq!(err.expected(), SCHEMA_ID_LEN);
        assert_eq!(err.actual(), SCHEMA_ID_LEN - 1);
    }

    #[test]
    fn schema_descriptor_round_trip() {
        let descriptor = SchemaDescriptor {
            schema_id: SchemaId::new([0x01; SCHEMA_ID_LEN]),
            name: "wallet.transfer".into(),
            version: "v1".into(),
            doc_url: Some("https://example.com/schema".into()),
            owner: Some(SchemaOwner::new([0x02; SCHEMA_ID_LEN])),
            ts: 1_700_000_000,
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&descriptor, &mut buf).expect("serialize");
        let decoded: SchemaDescriptor = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(decoded, descriptor);
    }

    #[test]
    fn registry_tracks_latest_descriptor() {
        let mut registry = SchemaRegistry::new();
        assert!(registry.is_empty());

        let schema_id = SchemaId::new([0xAA; SCHEMA_ID_LEN]);
        let base = SchemaDescriptor {
            schema_id,
            name: "wallet.transfer".into(),
            version: "v1".into(),
            doc_url: None,
            owner: None,
            ts: 10,
        };
        registry.upsert(base.clone(), 1);

        let newer = SchemaDescriptor {
            ts: 11,
            doc_url: Some("https://example.com/wallet-transfer".into()),
            ..base.clone()
        };
        registry.upsert(newer.clone(), 2);

        let entry = registry.get(&schema_id).expect("descriptor present");
        assert_eq!(entry, &newer);
        assert_eq!(registry.len(), 1);

        let older = SchemaDescriptor {
            ts: 9,
            version: "v0".into(),
            ..base
        };
        registry.upsert(older, 3);
        let entry = registry.get(&schema_id).expect("descriptor retained");
        assert_eq!(entry, &newer, "older record must not replace newer");

        let listed: Vec<_> = registry.descriptors().collect();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], entry);
    }

    #[test]
    fn registry_uses_stream_seq_for_tiebreaker() {
        let mut registry = SchemaRegistry::new();
        let schema_id = SchemaId::new([0xBB; SCHEMA_ID_LEN]);

        let first = SchemaDescriptor {
            schema_id,
            name: "rpc".into(),
            version: "v1".into(),
            doc_url: None,
            owner: None,
            ts: 20,
        };
        registry.upsert(first.clone(), 5);

        let second = SchemaDescriptor { version: "v1.1".into(), ..first.clone() };
        registry.upsert(second.clone(), 4);
        assert_eq!(registry.get(&schema_id), Some(&first));

        registry.upsert(second.clone(), 6);
        assert_eq!(registry.get(&schema_id), Some(&second));

        registry.clear();
        assert!(registry.is_empty());
    }
}
