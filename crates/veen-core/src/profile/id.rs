use std::{convert::TryFrom, fmt};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::LengthError;

/// Opaque newtype describing the profile identifier computed from a
/// [`Profile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileId(pub [u8; 32]);

impl ProfileId {
    /// Attempts to construct a [`ProfileId`] from an arbitrary byte slice,
    /// enforcing the fixed size defined in the specification.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != 32 {
            return Err(LengthError::new(32, bytes.len()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }
}

impl From<[u8; 32]> for ProfileId {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<&[u8; 32]> for ProfileId {
    fn from(value: &[u8; 32]) -> Self {
        Self(*value)
    }
}

impl AsRef<[u8]> for ProfileId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for ProfileId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for ProfileId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

crate::hexutil::impl_hex_fmt!(ProfileId);

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
        ProfileId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
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

crate::hexutil::impl_fixed_hex_from_str!(ProfileId, 32);

#[cfg(test)]
mod tests {
    use super::ProfileId;
    use std::str::FromStr;

    #[test]
    fn profile_id_try_from_vec_enforces_length() {
        let bytes = vec![0x11; 32];
        let id = ProfileId::try_from(bytes.clone()).expect("valid profile id");
        assert_eq!(id.as_ref(), bytes.as_slice());

        let err = ProfileId::try_from(vec![0x22; 31]).expect_err("length error");
        assert_eq!(err.expected(), 32);
        assert_eq!(err.actual(), 31);
    }

    #[test]
    fn profile_id_hex_formatting_matches_display() {
        let id = ProfileId([0xde; 32]);
        assert_eq!(format!("{id}"), "de".repeat(32));
        assert_eq!(format!("{id:x}"), "de".repeat(32));
        assert_eq!(format!("{id:X}"), "DE".repeat(32));
    }

    #[test]
    fn profile_id_from_str_rejects_invalid_length() {
        let err = ProfileId::from_str("abcd").expect_err("length error");
        assert_eq!(err.expected(), Some(64));
        assert_eq!(err.actual(), Some(4));
    }
}
