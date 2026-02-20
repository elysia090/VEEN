use std::{convert::TryFrom, fmt};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use veen_core::{ht, realm::RealmId, LengthError};

use super::{ensure_ed25519_public_key_len, ID_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContextId([u8; ID_LEN]);

impl ContextId {
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

    pub fn derive(principal_pk: impl AsRef<[u8]>, realm_id: RealmId) -> Result<Self, LengthError> {
        let principal_pk = principal_pk.as_ref();
        ensure_ed25519_public_key_len(principal_pk)?;
        let mut data = Vec::with_capacity(super::ED25519_PUBLIC_KEY_LEN + ID_LEN);
        data.extend_from_slice(principal_pk);
        data.extend_from_slice(realm_id.as_ref());
        Ok(Self::from(ht("id/ctx", &data)))
    }
}

impl From<[u8; ID_LEN]> for ContextId {
    fn from(value: [u8; ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; ID_LEN]> for ContextId {
    fn from(value: &[u8; ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for ContextId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for ContextId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for ContextId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

veen_core::impl_hex_fmt!(ContextId);

impl Serialize for ContextId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct ContextIdVisitor;

impl<'de> Visitor<'de> for ContextIdVisitor {
    type Value = ContextId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN context identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        ContextId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for ContextId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ContextIdVisitor)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::convert::TryFrom;

    const ID_LEN: usize = super::ID_LEN;

    fn sample_bytes() -> [u8; ID_LEN] {
        let mut out = [0u8; ID_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = i as u8;
        }
        out
    }

    fn sample_key() -> [u8; super::super::ED25519_PUBLIC_KEY_LEN] {
        let mut out = [0u8; super::super::ED25519_PUBLIC_KEY_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (0xA0_u8).wrapping_add(i as u8);
        }
        out
    }

    // --- Construction ---

    #[test]
    fn new_preserves_bytes() {
        let bytes = sample_bytes();
        let id = ContextId::new(bytes);
        assert_eq!(*id.as_bytes(), bytes);
    }

    #[test]
    fn from_array_constructs_correctly() {
        let bytes = sample_bytes();
        let id = ContextId::from(bytes);
        assert_eq!(*id.as_bytes(), bytes);
    }

    #[test]
    fn from_ref_array_constructs_correctly() {
        let bytes = sample_bytes();
        let id = ContextId::from(&bytes);
        assert_eq!(*id.as_bytes(), bytes);
    }

    #[test]
    fn from_slice_accepts_correct_length() {
        let bytes = sample_bytes();
        let id = ContextId::from_slice(&bytes).unwrap();
        assert_eq!(*id.as_bytes(), bytes);
    }

    #[test]
    fn from_slice_rejects_short_input() {
        let err = ContextId::from_slice(&[0u8; 31]).unwrap_err();
        assert_eq!(err.expected(), ID_LEN);
        assert_eq!(err.actual(), 31);
    }

    #[test]
    fn from_slice_rejects_long_input() {
        let err = ContextId::from_slice(&[0u8; 33]).unwrap_err();
        assert_eq!(err.expected(), ID_LEN);
        assert_eq!(err.actual(), 33);
    }

    #[test]
    fn from_slice_rejects_empty_input() {
        let err = ContextId::from_slice(&[]).unwrap_err();
        assert_eq!(err.expected(), ID_LEN);
        assert_eq!(err.actual(), 0);
    }

    // --- TryFrom ---

    #[test]
    fn try_from_slice_works() {
        let bytes = sample_bytes();
        let id = ContextId::try_from(bytes.as_slice()).unwrap();
        assert_eq!(*id.as_bytes(), bytes);
    }

    #[test]
    fn try_from_slice_rejects_wrong_length() {
        let short: &[u8] = &[1, 2, 3];
        assert!(ContextId::try_from(short).is_err());
    }

    #[test]
    fn try_from_vec_works() {
        let bytes = sample_bytes();
        let id = ContextId::try_from(bytes.to_vec()).unwrap();
        assert_eq!(*id.as_bytes(), bytes);
    }

    #[test]
    fn try_from_vec_rejects_wrong_length() {
        assert!(ContextId::try_from(vec![0u8; 10]).is_err());
    }

    // --- AsRef ---

    #[test]
    fn as_ref_returns_slice() {
        let bytes = sample_bytes();
        let id = ContextId::new(bytes);
        let slice: &[u8] = id.as_ref();
        assert_eq!(slice, &bytes);
    }

    // --- Derive ---

    #[test]
    fn derive_produces_deterministic_result() {
        let pk = sample_key();
        let realm = RealmId::from(ht("id/realm", b"test-realm"));
        let id1 = ContextId::derive(pk, realm).unwrap();
        let id2 = ContextId::derive(pk, realm).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn derive_different_keys_produce_different_ids() {
        let pk1 = sample_key();
        let mut pk2 = sample_key();
        pk2[0] ^= 0xFF;
        let realm = RealmId::from(ht("id/realm", b"test-realm"));
        let id1 = ContextId::derive(pk1, realm).unwrap();
        let id2 = ContextId::derive(pk2, realm).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn derive_different_realms_produce_different_ids() {
        let pk = sample_key();
        let realm1 = RealmId::from(ht("id/realm", b"realm-a"));
        let realm2 = RealmId::from(ht("id/realm", b"realm-b"));
        let id1 = ContextId::derive(pk, realm1).unwrap();
        let id2 = ContextId::derive(pk, realm2).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn derive_rejects_wrong_key_length() {
        let short_key = [0u8; 16];
        let realm = RealmId::from(ht("id/realm", b"test"));
        assert!(ContextId::derive(short_key, realm).is_err());
    }

    #[test]
    fn derive_matches_manual_ht_computation() {
        let pk = sample_key();
        let realm = RealmId::from(ht("id/realm", b"my-app"));
        let id = ContextId::derive(pk, realm).unwrap();
        let mut data = Vec::new();
        data.extend_from_slice(&pk);
        data.extend_from_slice(realm.as_ref());
        assert_eq!(*id.as_bytes(), ht("id/ctx", &data));
    }

    // --- Clone, Copy, PartialEq, Eq, Hash ---

    #[test]
    fn clone_and_copy_produce_equal_values() {
        let id = ContextId::new(sample_bytes());
        let cloned = id;
        let copied = id;
        assert_eq!(id, cloned);
        assert_eq!(id, copied);
    }

    #[test]
    fn hash_is_consistent_for_equal_values() {
        let id1 = ContextId::new(sample_bytes());
        let id2 = ContextId::new(sample_bytes());
        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    #[test]
    fn different_ids_are_not_equal() {
        let id1 = ContextId::new([0u8; ID_LEN]);
        let id2 = ContextId::new([1u8; ID_LEN]);
        assert_ne!(id1, id2);
    }

    // --- Display / LowerHex / UpperHex ---

    #[test]
    fn display_outputs_lowercase_hex() {
        let mut bytes = [0u8; ID_LEN];
        bytes[0] = 0xAB;
        bytes[31] = 0xCD;
        let id = ContextId::new(bytes);
        let s = format!("{id}");
        assert_eq!(s.len(), 64);
        assert!(s.starts_with("ab"));
        assert!(s.ends_with("cd"));
    }

    #[test]
    fn lower_hex_format() {
        let id = ContextId::new([0xFF; ID_LEN]);
        let s = format!("{id:x}");
        assert_eq!(s, "ff".repeat(32));
    }

    #[test]
    fn upper_hex_format() {
        let id = ContextId::new([0xFF; ID_LEN]);
        let s = format!("{id:X}");
        assert_eq!(s, "FF".repeat(32));
    }

    #[test]
    fn display_zero_bytes() {
        let id = ContextId::new([0u8; ID_LEN]);
        assert_eq!(format!("{id}"), "00".repeat(32));
    }

    // --- Debug ---

    #[test]
    fn debug_format_contains_type_name() {
        let id = ContextId::new([0u8; ID_LEN]);
        let dbg = format!("{id:?}");
        assert!(dbg.contains("ContextId"));
    }

    // --- Serde round-trip with ciborium (CBOR) ---

    #[test]
    fn cbor_round_trip() {
        let id = ContextId::new(sample_bytes());
        let mut buf = Vec::new();
        ciborium::into_writer(&id, &mut buf).unwrap();
        let decoded: ContextId = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn cbor_round_trip_all_zeros() {
        let id = ContextId::new([0u8; ID_LEN]);
        let mut buf = Vec::new();
        ciborium::into_writer(&id, &mut buf).unwrap();
        let decoded: ContextId = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn cbor_round_trip_all_ones() {
        let id = ContextId::new([0xFF; ID_LEN]);
        let mut buf = Vec::new();
        ciborium::into_writer(&id, &mut buf).unwrap();
        let decoded: ContextId = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn cbor_deserialize_wrong_length_fails() {
        // Serialize a shorter byte string manually
        let short_bytes: &[u8] = &[1, 2, 3];
        let mut buf = Vec::new();
        ciborium::into_writer(&ciborium::Value::Bytes(short_bytes.to_vec()), &mut buf).unwrap();
        let result: Result<ContextId, _> = ciborium::from_reader(buf.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn visitor_byte_buf_accepts_exact_length() {
        use serde::de::value::Error as DeValueError;
        use serde::de::Visitor;

        let id = ContextIdVisitor
            .visit_byte_buf::<DeValueError>(sample_bytes().to_vec())
            .unwrap();
        assert_eq!(id, ContextId::new(sample_bytes()));
    }
}
