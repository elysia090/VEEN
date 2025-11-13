use ciborium::ser::into_writer;
use hex::encode;
use serde::{Deserialize, Serialize};

mod error;
mod id;

pub use self::error::ProfileError;
pub use self::id::ProfileId;

use crate::ht;

/// The canonical VEEN cryptographic profile definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub aead: &'static str,
    pub kdf: &'static str,
    pub sig: &'static str,
    pub dh: &'static str,
    #[serde(rename = "hpke_suite")]
    pub hpke_suite: &'static str,
    pub epoch_sec: u64,
    pub pad_block: u64,
    pub mmr_hash: &'static str,
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
            pad_block: 0,
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
            "f5a9c1afdd0a8771f8d599ff8ba8146f407455ae6abf451a3e99363577a12d20"
        );
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
}
