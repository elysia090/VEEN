use ciborium::ser::into_writer;
use hex::encode;
use serde::de::{Error as DeError, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

mod error;
mod id;

pub use self::error::ProfileError;
pub use self::id::ProfileId;

use crate::ht;

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
    use ciborium::{de::from_reader, ser::into_writer};
    use hex::ToHex;

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
}
