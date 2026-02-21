use std::{convert::TryFrom, fmt};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use veen_core::{ht, LengthError};

use super::{ensure_ed25519_public_key_len, ID_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrgId([u8; ID_LEN]);

impl OrgId {
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

    pub fn derive(org_pk: impl AsRef<[u8]>) -> Result<Self, LengthError> {
        let org_pk = org_pk.as_ref();
        ensure_ed25519_public_key_len(org_pk)?;
        Ok(Self::from(ht("id/org", org_pk)))
    }
}

impl From<[u8; ID_LEN]> for OrgId {
    fn from(value: [u8; ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; ID_LEN]> for OrgId {
    fn from(value: &[u8; ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for OrgId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for OrgId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for OrgId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

veen_core::impl_hex_fmt!(OrgId);

impl Serialize for OrgId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct OrgIdVisitor;

impl<'de> Visitor<'de> for OrgIdVisitor {
    type Value = OrgId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN organization identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        OrgId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for OrgId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(OrgIdVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    fn sample_pk() -> [u8; 32] {
        [0x11; 32]
    }

    #[test]
    fn new_and_as_bytes() {
        let bytes = [0x11; ID_LEN];
        let id = OrgId::new(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn from_slice_success() {
        let bytes = [0x22; ID_LEN];
        let id = OrgId::from_slice(&bytes).expect("from_slice should succeed");
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn from_slice_error_on_wrong_length() {
        let err = OrgId::from_slice(&[0u8; ID_LEN - 1]).expect_err("should fail");
        assert_eq!(err.expected(), ID_LEN);
        assert_eq!(err.actual(), ID_LEN - 1);
    }

    #[test]
    fn from_fixed_array() {
        let bytes = [0x33; ID_LEN];
        let id = OrgId::from(bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn from_fixed_array_ref() {
        let bytes = [0x44; ID_LEN];
        let id = OrgId::from(&bytes);
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn try_from_slice_success() {
        let bytes = [0x55; ID_LEN];
        let id = OrgId::try_from(bytes.as_slice()).expect("try_from slice");
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn try_from_slice_error() {
        let err = OrgId::try_from([0u8; 1].as_slice()).expect_err("should fail");
        assert_eq!(err.expected(), ID_LEN);
    }

    #[test]
    fn try_from_vec_success() {
        let bytes = [0x66; ID_LEN];
        let id = OrgId::try_from(bytes.to_vec()).expect("try_from vec");
        assert_eq!(id.as_bytes(), &bytes);
    }

    #[test]
    fn try_from_vec_error() {
        let err = OrgId::try_from(vec![0u8; 1]).expect_err("should fail");
        assert_eq!(err.expected(), ID_LEN);
    }

    #[test]
    fn as_ref_returns_bytes() {
        let bytes = [0x77; ID_LEN];
        let id = OrgId::new(bytes);
        assert_eq!(id.as_ref(), &bytes);
    }

    #[test]
    fn display_is_hex() {
        let bytes = [0xBB; ID_LEN];
        let id = OrgId::new(bytes);
        assert_eq!(id.to_string(), hex::encode(bytes));
    }

    #[test]
    fn derive_success() {
        let pk = sample_pk();
        let id = OrgId::derive(pk).expect("derive should succeed");
        assert_eq!(id.as_bytes(), &veen_core::ht("id/org", &pk));
    }

    #[test]
    fn derive_error_on_wrong_key_length() {
        let short_pk = [0u8; 16];
        let err = OrgId::derive(short_pk).expect_err("should fail");
        assert_eq!(err.expected(), super::super::ED25519_PUBLIC_KEY_LEN);
    }

    #[test]
    fn serde_cbor_roundtrip() {
        let pk = sample_pk();
        let id = OrgId::derive(pk).expect("derive");

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&id, &mut buf).expect("serialize");
        let decoded: OrgId = ciborium::de::from_reader(buf.as_slice()).expect("deserialize");
        assert_eq!(decoded, id);
    }

    #[test]
    fn serde_cbor_invalid_length_error() {
        let short: &[u8] = &[0u8; ID_LEN - 1];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&serde_bytes::Bytes::new(short), &mut buf).expect("serialize");
        let result: Result<OrgId, _> = ciborium::de::from_reader(buf.as_slice());
        assert!(result.is_err(), "should reject wrong-length bytes");
    }

    #[test]
    fn equality_and_hash() {
        use std::collections::HashSet;
        let bytes = [0xCC; ID_LEN];
        let a = OrgId::new(bytes);
        let b = OrgId::new(bytes);
        assert_eq!(a, b);
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn clone_and_copy() {
        let id = OrgId::new([0xDD; ID_LEN]);
        let cloned = id;
        assert_eq!(id, cloned);
    }
}
