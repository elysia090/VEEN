use std::{convert::TryFrom, fmt};

use ciborium::ser::into_writer;
use hex::encode;
use serde::de::{Error as DeError, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{ht, LengthError};

/// Error returned when encoding a [`Profile`] fails.
#[derive(Debug, Error)]
pub enum ProfileError {
    /// Serialisation or IO failure during CBOR encoding.
    #[error("failed to encode profile to CBOR: {0}")]
    Encoding(String),
}

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

crate::impl_hex_fmt!(ProfileId);

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

crate::impl_fixed_hex_from_str!(ProfileId, 32);

/// The canonical VEEN cryptographic profile definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub aead: &'static str,
    pub kdf: &'static str,
    pub sig: &'static str,
    pub dh: &'static str,
    pub hpke_suite: &'static str,
    pub epoch_sec: u64,
    pub pad_block: u64,
    pub mmr_hash: &'static str,
}

impl Serialize for Profile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(8))?;
        map.serialize_entry(&1u64, &self.aead)?;
        map.serialize_entry(&2u64, &self.kdf)?;
        map.serialize_entry(&3u64, &self.sig)?;
        map.serialize_entry(&4u64, &self.dh)?;
        map.serialize_entry(&5u64, &self.hpke_suite)?;
        map.serialize_entry(&6u64, &self.epoch_sec)?;
        map.serialize_entry(&7u64, &self.pad_block)?;
        map.serialize_entry(&8u64, &self.mmr_hash)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for Profile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProfileVisitor;

        fn require_value<E>(label: &'static str, value: Option<String>) -> Result<String, E>
        where
            E: DeError,
        {
            value.ok_or_else(|| DeError::missing_field(label))
        }

        fn resolve_allowed<E>(
            field: &'static str,
            value: String,
            allowed: &'static str,
        ) -> Result<&'static str, E>
        where
            E: DeError,
        {
            if value == allowed {
                Ok(allowed)
            } else {
                Err(DeError::custom(format!(
                    "unsupported {field} value {value}"
                )))
            }
        }

        impl<'de> Visitor<'de> for ProfileVisitor {
            type Value = Profile;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a VEEN profile map with integer keys 1..=8")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut aead: Option<String> = None;
                let mut kdf: Option<String> = None;
                let mut sig: Option<String> = None;
                let mut dh: Option<String> = None;
                let mut hpke_suite: Option<String> = None;
                let mut epoch_sec: Option<u64> = None;
                let mut pad_block: Option<u64> = None;
                let mut mmr_hash: Option<String> = None;

                while let Some(key) = map.next_key::<u64>()? {
                    match key {
                        1 => {
                            if aead.replace(map.next_value()?).is_some() {
                                return Err(DeError::custom("duplicate profile key 1"));
                            }
                        }
                        2 => {
                            if kdf.replace(map.next_value()?).is_some() {
                                return Err(DeError::custom("duplicate profile key 2"));
                            }
                        }
                        3 => {
                            if sig.replace(map.next_value()?).is_some() {
                                return Err(DeError::custom("duplicate profile key 3"));
                            }
                        }
                        4 => {
                            if dh.replace(map.next_value()?).is_some() {
                                return Err(DeError::custom("duplicate profile key 4"));
                            }
                        }
                        5 => {
                            if hpke_suite.replace(map.next_value()?).is_some() {
                                return Err(DeError::custom("duplicate profile key 5"));
                            }
                        }
                        6 => {
                            if epoch_sec.replace(map.next_value()?).is_some() {
                                return Err(DeError::custom("duplicate profile key 6"));
                            }
                        }
                        7 => {
                            if pad_block.replace(map.next_value()?).is_some() {
                                return Err(DeError::custom("duplicate profile key 7"));
                            }
                        }
                        8 => {
                            if mmr_hash.replace(map.next_value()?).is_some() {
                                return Err(DeError::custom("duplicate profile key 8"));
                            }
                        }
                        _ => {
                            return Err(DeError::custom(format!("unknown profile key {key}")));
                        }
                    }
                }

                let aead = resolve_allowed(
                    "aead",
                    require_value("1 (aead)", aead)?,
                    "xchacha20poly1305",
                )?;
                let kdf = resolve_allowed("kdf", require_value("2 (kdf)", kdf)?, "hkdf-sha256")?;
                let sig = resolve_allowed("sig", require_value("3 (sig)", sig)?, "ed25519")?;
                let dh = resolve_allowed("dh", require_value("4 (dh)", dh)?, "x25519")?;
                let hpke_suite = resolve_allowed(
                    "hpke_suite",
                    require_value("5 (hpke_suite)", hpke_suite)?,
                    "X25519-HKDF-SHA256-CHACHA20POLY1305",
                )?;
                let epoch_sec = epoch_sec.ok_or_else(|| DeError::missing_field("6 (epoch_sec)"))?;
                let pad_block = pad_block.ok_or_else(|| DeError::missing_field("7 (pad_block)"))?;
                let mmr_hash = resolve_allowed(
                    "mmr_hash",
                    require_value("8 (mmr_hash)", mmr_hash)?,
                    "sha256",
                )?;

                Ok(Profile {
                    aead,
                    kdf,
                    sig,
                    dh,
                    hpke_suite,
                    epoch_sec,
                    pad_block,
                    mmr_hash,
                })
            }
        }

        deserializer.deserialize_map(ProfileVisitor)
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            aead: "xchacha20poly1305",
            kdf: "hkdf-sha256",
            sig: "ed25519",
            dh: "x25519",
            hpke_suite: "X25519-HKDF-SHA256-CHACHA20POLY1305",
            epoch_sec: 60,
            pad_block: 256,
            mmr_hash: "sha256",
        }
    }
}

impl Profile {
    /// Returns the canonical identifier for the profile as described in the
    /// specification, i.e. `profile_id = Ht("veen/profile", CBOR(profile))`.
    pub fn id(&self) -> Result<ProfileId, ProfileError> {
        let mut buf = Vec::new();
        into_writer(self, &mut buf).map_err(|err| ProfileError::Encoding(err.to_string()))?;
        Ok(ProfileId(ht("veen/profile", &buf)))
    }

    /// Formats the profile identifier as lowercase hexadecimal.
    pub fn id_hex(&self) -> Result<String, ProfileError> {
        let id = self.id()?;
        Ok(encode(id.0))
    }
}

#[cfg(test)]
mod tests {
    use ciborium::{de::from_reader, ser::into_writer, value::Value};
    use hex::ToHex;
    use std::{convert::TryFrom, str::FromStr};

    use super::{Profile, ProfileId};

    #[test]
    fn default_profile_matches_snapshot() {
        let profile = Profile::default();
        let id = profile.id().expect("profile id");
        let as_hex = id.encode_hex::<String>();
        assert_eq!(
            as_hex,
            "1db91032b4bf4cd8b9f56a782b299458e6f782d3a1276f04c50c7b02651038ca"
        );
    }

    #[test]
    fn profile_id_round_trips_via_string() {
        let profile = Profile::default();
        let id = profile.id().expect("profile id");
        let encoded = id.encode_hex::<String>();
        let parsed = encoded.parse::<ProfileId>().expect("parse profile id");
        assert_eq!(parsed, id);
        assert_eq!(parsed.to_string(), encoded);
    }

    #[test]
    fn profile_id_serializes_as_cbor_bstr() {
        let profile = Profile::default();
        let id = profile.id().expect("profile id");
        let mut buf = Vec::new();
        into_writer(&id, &mut buf).expect("serialize profile id");
        assert_eq!(buf[0], 0x58);
        assert_eq!(buf[1], 32);
        assert_eq!(&buf[2..], id.as_ref());

        let decoded: ProfileId = from_reader(buf.as_slice()).expect("deserialize profile id");
        assert_eq!(decoded, id);

        let mut invalid = vec![0x58, 0x21];
        invalid.extend([0u8; 33]);
        let result: Result<ProfileId, _> = from_reader(invalid.as_slice());
        assert!(result.is_err(), "expected profile id length enforcement");
    }

    #[test]
    fn profile_id_from_slice_enforces_length() {
        let valid = [0x55; 32];
        let id = ProfileId::from_slice(&valid).expect("valid profile id");
        assert_eq!(id.as_ref(), &valid);

        let err = ProfileId::from_slice(&valid[..31]).expect_err("length error");
        assert_eq!(err.expected(), 32);
        assert_eq!(err.actual(), 31);
    }

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

    #[test]
    fn profile_id_from_and_as_ref() {
        let bytes = [0xAB; 32];
        let id = ProfileId::from(bytes);
        assert_eq!(id.as_ref(), &bytes[..]);
        let id2 = ProfileId::from(&bytes);
        assert_eq!(id2.as_ref(), &bytes[..]);
    }

    #[test]
    fn profile_id_try_from_slice() {
        let bytes = [0x55; 32];
        let id = ProfileId::try_from(bytes.as_slice()).expect("ok");
        assert_eq!(id.as_ref(), &bytes[..]);
        let err = ProfileId::try_from([0u8; 5].as_slice()).expect_err("too short");
        assert_eq!(err.expected(), 32);
    }

    #[test]
    fn profile_id_try_from_vec() {
        let bytes = vec![0x77u8; 32];
        let id = ProfileId::try_from(bytes.clone()).expect("ok");
        assert_eq!(id.as_ref(), bytes.as_slice());
    }

    #[test]
    fn profile_id_hex() {
        let profile = Profile::default();
        let hex = profile.id_hex().expect("id_hex");
        assert_eq!(
            hex,
            "1db91032b4bf4cd8b9f56a782b299458e6f782d3a1276f04c50c7b02651038ca"
        );
    }

    fn int(n: u64) -> Value {
        Value::Integer(n.into())
    }

    /// Helper that builds a complete valid CBOR map for Profile.
    fn valid_profile_map() -> Value {
        Value::Map(vec![
            (int(1), Value::Text("xchacha20poly1305".to_string())),
            (int(2), Value::Text("hkdf-sha256".to_string())),
            (int(3), Value::Text("ed25519".to_string())),
            (int(4), Value::Text("x25519".to_string())),
            (
                int(5),
                Value::Text("X25519-HKDF-SHA256-CHACHA20POLY1305".to_string()),
            ),
            (int(6), int(60)),
            (int(7), int(256)),
            (int(8), Value::Text("sha256".to_string())),
        ])
    }

    #[test]
    fn profile_serde_roundtrip() {
        let profile = Profile::default();
        let mut buf = Vec::new();
        into_writer(&profile, &mut buf).expect("serialize profile");
        let decoded: Profile = from_reader(buf.as_slice()).expect("deserialize profile");
        assert_eq!(decoded, profile);
    }

    #[test]
    fn profile_deserialize_missing_field() {
        // Map with only key 1 (aead) – all others missing.
        let partial = Value::Map(vec![(int(1), Value::Text("xchacha20poly1305".to_string()))]);
        let mut buf = Vec::new();
        into_writer(&partial, &mut buf).expect("serialize");
        let result: Result<Profile, _> = from_reader(buf.as_slice());
        assert!(result.is_err(), "must fail when fields are missing");
    }

    #[test]
    fn profile_deserialize_unsupported_aead() {
        let mut map = valid_profile_map();
        // Replace key 1 with unsupported aead value.
        if let Value::Map(ref mut entries) = map {
            entries[0].1 = Value::Text("aes-gcm".to_string());
        }
        let mut buf = Vec::new();
        into_writer(&map, &mut buf).expect("serialize");
        let result: Result<Profile, _> = from_reader(buf.as_slice());
        assert!(result.is_err(), "must fail for unsupported aead");
    }

    #[test]
    fn profile_deserialize_unsupported_kdf() {
        let mut map = valid_profile_map();
        if let Value::Map(ref mut entries) = map {
            entries[1].1 = Value::Text("argon2".to_string());
        }
        let mut buf = Vec::new();
        into_writer(&map, &mut buf).expect("serialize");
        let result: Result<Profile, _> = from_reader(buf.as_slice());
        assert!(result.is_err(), "must fail for unsupported kdf");
    }

    #[test]
    fn profile_deserialize_unsupported_sig() {
        let mut map = valid_profile_map();
        if let Value::Map(ref mut entries) = map {
            entries[2].1 = Value::Text("ecdsa-p256".to_string());
        }
        let mut buf = Vec::new();
        into_writer(&map, &mut buf).expect("serialize");
        let result: Result<Profile, _> = from_reader(buf.as_slice());
        assert!(result.is_err(), "must fail for unsupported sig");
    }

    #[test]
    fn profile_deserialize_unsupported_dh() {
        let mut map = valid_profile_map();
        if let Value::Map(ref mut entries) = map {
            entries[3].1 = Value::Text("ecdh-p256".to_string());
        }
        let mut buf = Vec::new();
        into_writer(&map, &mut buf).expect("serialize");
        let result: Result<Profile, _> = from_reader(buf.as_slice());
        assert!(result.is_err(), "must fail for unsupported dh");
    }

    #[test]
    fn profile_deserialize_unsupported_hpke() {
        let mut map = valid_profile_map();
        if let Value::Map(ref mut entries) = map {
            entries[4].1 = Value::Text("bad-suite".to_string());
        }
        let mut buf = Vec::new();
        into_writer(&map, &mut buf).expect("serialize");
        let result: Result<Profile, _> = from_reader(buf.as_slice());
        assert!(result.is_err(), "must fail for unsupported hpke_suite");
    }

    #[test]
    fn profile_deserialize_unsupported_mmr_hash() {
        let mut map = valid_profile_map();
        if let Value::Map(ref mut entries) = map {
            entries[7].1 = Value::Text("blake3".to_string());
        }
        let mut buf = Vec::new();
        into_writer(&map, &mut buf).expect("serialize");
        let result: Result<Profile, _> = from_reader(buf.as_slice());
        assert!(result.is_err(), "must fail for unsupported mmr_hash");
    }

    #[test]
    fn profile_deserialize_unknown_key() {
        let with_unknown = Value::Map(vec![(int(99), Value::Text("unknown".to_string()))]);
        let mut buf = Vec::new();
        into_writer(&with_unknown, &mut buf).expect("serialize");
        let result: Result<Profile, _> = from_reader(buf.as_slice());
        assert!(result.is_err(), "must fail for unknown key 99");
    }

    #[test]
    fn profile_deserialize_duplicate_key() {
        // Two entries with key 1.
        let dup = Value::Map(vec![
            (int(1), Value::Text("xchacha20poly1305".to_string())),
            (int(1), Value::Text("xchacha20poly1305".to_string())),
        ]);
        let mut buf = Vec::new();
        into_writer(&dup, &mut buf).expect("serialize");
        let result: Result<Profile, _> = from_reader(buf.as_slice());
        assert!(result.is_err(), "must fail for duplicate key");
    }
}
