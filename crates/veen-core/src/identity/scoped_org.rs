use std::{convert::TryFrom, fmt};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ht, realm::RealmId, LengthError};

use super::{org::OrgId, ID_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopedOrgId([u8; ID_LEN]);

impl ScopedOrgId {
    #[must_use]
    pub const fn new(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != ID_LEN {
            return Err(LengthError::new(ID_LEN, bytes.len()));
        }
        let mut out = [0u8; ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    #[must_use]
    pub fn derive(org_id: OrgId, realm_id: RealmId) -> Self {
        let mut data = Vec::with_capacity(ID_LEN * 2);
        data.extend_from_slice(org_id.as_ref());
        data.extend_from_slice(realm_id.as_ref());
        Self::from(ht("id/org/realm", &data))
    }
}

impl From<[u8; ID_LEN]> for ScopedOrgId {
    fn from(value: [u8; ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; ID_LEN]> for ScopedOrgId {
    fn from(value: &[u8; ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for ScopedOrgId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for ScopedOrgId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for ScopedOrgId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for ScopedOrgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for ScopedOrgId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct ScopedOrgIdVisitor;

impl<'de> Visitor<'de> for ScopedOrgIdVisitor {
    type Value = ScopedOrgId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN scoped-organization identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        ScopedOrgId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for ScopedOrgId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ScopedOrgIdVisitor)
    }
}
