use std::{convert::TryFrom, fmt};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ht, LengthError};

use super::{ensure_ed25519_public_key_len, ID_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrincipalId([u8; ID_LEN]);

impl PrincipalId {
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

    pub fn derive(principal_pk: impl AsRef<[u8]>) -> Result<Self, LengthError> {
        let principal_pk = principal_pk.as_ref();
        ensure_ed25519_public_key_len(principal_pk)?;
        Ok(Self::from(ht("id/principal", principal_pk)))
    }
}

impl From<[u8; ID_LEN]> for PrincipalId {
    fn from(value: [u8; ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; ID_LEN]> for PrincipalId {
    fn from(value: &[u8; ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for PrincipalId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for PrincipalId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for PrincipalId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for PrincipalId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct PrincipalIdVisitor;

impl<'de> Visitor<'de> for PrincipalIdVisitor {
    type Value = PrincipalId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN principal identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        PrincipalId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for PrincipalId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PrincipalIdVisitor)
    }
}
