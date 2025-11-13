use std::fmt::{self, Write as _};

use ciborium::ser::into_writer;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ht;

/// The canonical VEEN cryptographic profile definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Error returned when encoding a [`Profile`] fails.
#[derive(Debug, Error)]
pub enum ProfileError {
    /// Serialisation or IO failure during CBOR encoding.
    #[error("failed to encode profile to CBOR: {0}")]
    Encoding(String),
}

/// Opaque newtype describing the profile identifier computed from a
/// [`Profile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        let mut out = String::with_capacity(64);
        for byte in id.0 {
            write!(&mut out, "{byte:02x}").expect("write to string");
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use hex::ToHex;

    use super::Profile;

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
}
