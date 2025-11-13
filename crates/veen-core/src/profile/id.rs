use std::fmt;

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Opaque newtype describing the profile identifier computed from a
/// [`Profile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileId(pub [u8; 32]);

impl AsRef<[u8]> for ProfileId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for ProfileId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

struct ProfileIdVisitor;

impl<'de> Visitor<'de> for ProfileIdVisitor {
    type Value = ProfileId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN profile identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        if v.len() != 32 {
            return Err(E::invalid_length(v.len(), &self));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(v);
        Ok(ProfileId(bytes))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for ProfileId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ProfileIdVisitor)
    }
}
