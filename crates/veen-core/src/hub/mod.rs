use std::{convert::TryFrom, fmt};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ht, LengthError};

/// Length in bytes of the derived hub identifier.
pub const HUB_ID_LEN: usize = 32;

/// Opaque newtype describing the `hub_id = Ht("veen/hub-id", hub_pk)`
/// derivation from the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HubId([u8; HUB_ID_LEN]);

impl HubId {
    /// Creates a [`HubId`] from the provided byte array.
    #[must_use]
    pub const fn new(bytes: [u8; HUB_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical hub identifier derived from the Ed25519 public
    /// key as defined in the specification.
    pub fn derive(public_key: impl AsRef<[u8]>) -> Result<Self, LengthError> {
        let public_key = public_key.as_ref();
        if public_key.len() != HUB_ID_LEN {
            return Err(LengthError::new(HUB_ID_LEN, public_key.len()));
        }
        Ok(Self(ht("veen/hub-id", public_key)))
    }

    /// Borrows the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HUB_ID_LEN] {
        &self.0
    }

    /// Attempts to construct a [`HubId`] from an arbitrary slice, enforcing
    /// the exact length required by the specification.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != HUB_ID_LEN {
            return Err(LengthError::new(HUB_ID_LEN, bytes.len()));
        }
        let mut out = [0u8; HUB_ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }
}

impl From<[u8; HUB_ID_LEN]> for HubId {
    fn from(value: [u8; HUB_ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; HUB_ID_LEN]> for HubId {
    fn from(value: &[u8; HUB_ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for HubId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for HubId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for HubId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for HubId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for HubId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct HubIdVisitor;

impl<'de> Visitor<'de> for HubIdVisitor {
    type Value = HubId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a {HUB_ID_LEN}-byte VEEN hub identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        HubId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for HubId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(HubIdVisitor)
    }
}

crate::hexutil::impl_fixed_hex_from_str!(HubId, HUB_ID_LEN);

#[cfg(test)]
mod tests;
