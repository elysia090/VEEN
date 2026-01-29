use std::{convert::TryFrom, fmt};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ht, label::StreamId, LengthError};

/// Length in bytes of a VEEN realm identifier.
pub const REALM_ID_LEN: usize = 32;

/// Opaque newtype describing a deployment-defined realm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RealmId([u8; REALM_ID_LEN]);

impl RealmId {
    /// Derives the realm identifier from a human readable name as defined in
    /// the identity specification, i.e. `realm_id = Ht("id/realm",
    /// ascii(realm_name))`.
    #[must_use]
    pub fn derive(realm_name: impl AsRef<str>) -> Self {
        Self::from(ht("id/realm", realm_name.as_ref().as_bytes()))
    }

    /// Creates a new [`RealmId`] from the provided byte array.
    #[must_use]
    pub const fn new(bytes: [u8; REALM_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; REALM_ID_LEN] {
        &self.0
    }

    /// Attempts to construct a [`RealmId`] from an arbitrary slice, enforcing
    /// the fixed length defined in the specification.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != REALM_ID_LEN {
            return Err(LengthError::new(REALM_ID_LEN, bytes.len()));
        }
        let mut out = [0u8; REALM_ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    /// Returns the administrative stream used for publishing authority
    /// records, i.e. `stream_fed_admin = Ht("veen/admin", realm_id)`.
    #[must_use]
    pub fn stream_fed_admin(&self) -> StreamId {
        StreamId::from(ht("veen/admin", self.as_ref()))
    }

    /// Returns the revocation stream for this realm, i.e.
    /// `stream_revocation = Ht("veen/revocation", realm_id)`.
    #[must_use]
    pub fn stream_revocation(&self) -> StreamId {
        StreamId::from(ht("veen/revocation", self.as_ref()))
    }

    /// Returns the label classification stream for this realm, i.e.
    /// `stream_label_class = Ht("veen/label-class", realm_id)`.
    #[must_use]
    pub fn stream_label_class(&self) -> StreamId {
        StreamId::from(ht("veen/label-class", self.as_ref()))
    }

    /// Returns the schema metadata stream for this realm, i.e.
    /// `stream_schema_meta = Ht("veen/meta-schema", realm_id)`.
    #[must_use]
    pub fn stream_schema_meta(&self) -> StreamId {
        StreamId::from(ht("veen/meta-schema", self.as_ref()))
    }
}

impl From<[u8; REALM_ID_LEN]> for RealmId {
    fn from(value: [u8; REALM_ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; REALM_ID_LEN]> for RealmId {
    fn from(value: &[u8; REALM_ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for RealmId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for RealmId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for RealmId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

crate::impl_hex_fmt!(RealmId);

impl Serialize for RealmId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct RealmIdVisitor;

impl<'de> Visitor<'de> for RealmIdVisitor {
    type Value = RealmId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a {REALM_ID_LEN}-byte VEEN realm identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        RealmId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for RealmId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(RealmIdVisitor)
    }
}

crate::impl_fixed_hex_from_str!(RealmId, REALM_ID_LEN);

#[cfg(test)]
mod tests;
