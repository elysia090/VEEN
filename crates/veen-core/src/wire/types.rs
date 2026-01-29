use std::{convert::TryFrom, fmt};

use ed25519_dalek::{
    ed25519::signature::Verifier, Signature as DalekSignature,
    SignatureError as DalekSignatureError, VerifyingKey,
};
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{hash::h, label::Label, profile::ProfileId, LengthError};

use super::derivation::{hash_tagged, TAG_ATT_NONCE, TAG_LEAF, TAG_MMR_NODE, TAG_MMR_ROOT};
use crate::hash::ht_parts;

macro_rules! fixed_bytes_type {
    ($(#[$meta:meta])* $vis:vis struct $name:ident($len:expr); expecting: $expecting:expr;) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        $vis struct $name([u8; $len]);

        impl $name {
            #[must_use]
            pub const fn new(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
                if bytes.len() != $len {
                    return Err(LengthError::new($len, bytes.len()));
                }
                let mut out = [0u8; $len];
                out.copy_from_slice(bytes);
                Ok(Self::new(out))
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(value: [u8; $len]) -> Self {
                Self::new(value)
            }
        }

        impl From<&[u8; $len]> for $name {
            fn from(value: &[u8; $len]) -> Self {
                Self::new(*value)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = LengthError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                Self::from_slice(value)
            }
        }

        impl TryFrom<Vec<u8>> for $name {
            type Error = LengthError;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                Self::from_slice(&value)
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        crate::impl_hex_fmt!($name);

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(self.as_ref())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct VisitorImpl;

                impl<'de> Visitor<'de> for VisitorImpl {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str($expecting)
                    }

                    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                    where
                        E: DeError,
                    {
                        $name::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
                    }

                    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                    where
                        E: DeError,
                    {
                        self.visit_bytes(&v)
                    }
                }

                deserializer.deserialize_bytes(VisitorImpl)
            }
        }

        crate::impl_fixed_hex_from_str!($name, $len);
    };
}

/// Length in bytes of Ed25519-based identifiers and hashes used in VEEN wire objects.
pub const HASH_LEN: usize = 32;
/// Length in bytes of Ed25519 signatures used by VEEN wire objects.
pub const SIGNATURE_LEN: usize = 64;
/// Length in bytes of AEAD nonces derived from the specification hashes.
pub const AEAD_NONCE_LEN: usize = 24;

#[must_use]
pub(crate) fn truncate_nonce(digest: [u8; 32]) -> [u8; AEAD_NONCE_LEN] {
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce.copy_from_slice(&digest[..AEAD_NONCE_LEN]);
    nonce
}

fixed_bytes_type!(
    /// Raw Ed25519 public key carried as `client_id` on the wire.
    pub struct ClientId(HASH_LEN);
    expecting: "a 32-byte VEEN client identifier";
);

fixed_bytes_type!(
    /// Admission reference carried on the wire to bind to a capability token.
    pub struct AuthRef(HASH_LEN);
    expecting: "a 32-byte VEEN auth_ref value";
);

fixed_bytes_type!(
    /// Canonical SHA-256 hash of the ciphertext payload.
    pub struct CtHash(HASH_LEN);
    expecting: "a 32-byte VEEN ciphertext hash";
);

impl CtHash {
    /// Computes the canonical ciphertext hash `H(ciphertext)`.
    #[must_use]
    pub fn compute(ciphertext: &[u8]) -> Self {
        Self(h(ciphertext))
    }
}

fixed_bytes_type!(
    /// Leaf hash committed into the MMR for each message.
    pub struct LeafHash(HASH_LEN);
    expecting: "a 32-byte VEEN leaf hash";
);

impl LeafHash {
    /// Computes the canonical leaf hash derivation used by the specification.
    #[must_use]
    pub fn derive(
        label: &Label,
        profile_id: &ProfileId,
        ct_hash: &CtHash,
        client_id: &ClientId,
        client_seq: u64,
    ) -> Self {
        let mut data = [0u8; 136];
        let mut offset = 0;
        data[offset..offset + 32].copy_from_slice(label.as_ref());
        offset += 32;
        data[offset..offset + 32].copy_from_slice(profile_id.as_ref());
        offset += 32;
        data[offset..offset + 32].copy_from_slice(ct_hash.as_ref());
        offset += 32;
        data[offset..offset + 32].copy_from_slice(client_id.as_ref());
        offset += 32;
        data[offset..offset + 8].copy_from_slice(&client_seq.to_be_bytes());
        Self(hash_tagged(TAG_LEAF, &data))
    }

    /// Computes the attachment nonce `Trunc_24(Ht("veen/att-nonce", msg_id || u64be(i)))`.
    #[must_use]
    pub fn attachment_nonce(&self, index: u64) -> [u8; AEAD_NONCE_LEN] {
        let mut data = [0u8; 40];
        data[..HASH_LEN].copy_from_slice(self.as_ref());
        data[HASH_LEN..].copy_from_slice(&index.to_be_bytes());
        truncate_nonce(hash_tagged(TAG_ATT_NONCE, &data))
    }
}

fixed_bytes_type!(
    /// Intermediate MMR node or peak hash.
    pub struct MmrNode(HASH_LEN);
    expecting: "a 32-byte VEEN MMR node hash";
);

impl MmrNode {
    #[must_use]
    pub fn combine(left: &Self, right: &Self) -> Self {
        let mut data = [0u8; HASH_LEN * 2];
        data[..HASH_LEN].copy_from_slice(left.as_ref());
        data[HASH_LEN..].copy_from_slice(right.as_ref());
        Self(hash_tagged(TAG_MMR_NODE, &data))
    }
}

impl From<LeafHash> for MmrNode {
    fn from(value: LeafHash) -> Self {
        Self::new(*value.as_bytes())
    }
}

fixed_bytes_type!(
    /// Merkle Mountain Range root committed by hubs.
    pub struct MmrRoot(HASH_LEN);
    expecting: "a 32-byte VEEN MMR root";
);

impl MmrRoot {
    /// Computes an MMR root by folding the provided peaks using the
    /// `Ht("veen/mmr-root", …)` derivation from the specification.
    #[must_use]
    pub fn from_peaks(peaks: &[MmrNode]) -> Option<Self> {
        if peaks.is_empty() {
            return None;
        }

        if peaks.len() == 1 {
            return Some(Self::from(peaks[0]));
        }

        let root = ht_parts(TAG_MMR_ROOT, peaks.iter().map(|peak| peak.as_ref()));
        Some(Self(root))
    }

    /// Computes an MMR root using the provided scratch buffer for API compatibility.
    #[must_use]
    pub fn from_peaks_with_scratch(peaks: &[MmrNode], _scratch: &mut Vec<u8>) -> Option<Self> {
        if peaks.is_empty() {
            return None;
        }

        if peaks.len() == 1 {
            return Some(Self::from(peaks[0]));
        }

        let root = ht_parts(TAG_MMR_ROOT, peaks.iter().map(|peak| peak.as_ref()));
        Some(Self(root))
    }

    /// Computes an MMR root from a leading peak and trailing peaks without
    /// allocating an intermediate buffer.
    #[must_use]
    pub fn from_peak_and_suffix(peak: &MmrNode, suffix: &[MmrNode]) -> Self {
        if suffix.is_empty() {
            return Self::from(*peak);
        }

        let root = ht_parts(
            TAG_MMR_ROOT,
            std::iter::once(peak.as_ref()).chain(suffix.iter().map(|node| node.as_ref())),
        );
        Self(root)
    }
}

impl From<MmrNode> for MmrRoot {
    fn from(value: MmrNode) -> Self {
        Self::new(*value.as_bytes())
    }
}

/// Errors returned when verifying Ed25519 signatures embedded in VEEN wire
/// objects.
#[derive(Debug, Error)]
pub enum SignatureVerifyError {
    /// Provided public key bytes were not a valid Ed25519 key.
    #[error("invalid Ed25519 public key: {0}")]
    InvalidPublicKey(#[source] DalekSignatureError),
    /// Provided signature bytes were not a valid Ed25519 signature.
    #[error("invalid Ed25519 signature encoding: {0}")]
    InvalidSignatureEncoding(#[source] DalekSignatureError),
    /// Signature verification failed for the supplied message and key.
    #[error("signature verification failed: {0}")]
    VerificationFailed(#[source] DalekSignatureError),
}

fixed_bytes_type!(
    /// Canonical Ed25519 signature stored in `MSG.sig`, `RECEIPT.hub_sig`, and checkpoints.
    pub struct Signature64(SIGNATURE_LEN);
    expecting: "a 64-byte VEEN Ed25519 signature";
);

impl Signature64 {
    /// Verifies the signature against the provided Ed25519 public key and
    /// message bytes.
    pub fn verify(
        &self,
        public_key: &[u8; HASH_LEN],
        message: &[u8],
    ) -> Result<(), SignatureVerifyError> {
        let verifying_key =
            VerifyingKey::from_bytes(public_key).map_err(SignatureVerifyError::InvalidPublicKey)?;
        let signature = DalekSignature::try_from(self.as_bytes() as &[u8])
            .map_err(SignatureVerifyError::InvalidSignatureEncoding)?;
        verifying_key
            .verify(message, &signature)
            .map_err(SignatureVerifyError::VerificationFailed)
    }
}

impl From<LeafHash> for MmrRoot {
    fn from(value: LeafHash) -> Self {
        Self::new(*value.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::Digest;

    use super::{
        hash_tagged, truncate_nonce, AuthRef, ClientId, CtHash, LeafHash, MmrNode, MmrRoot,
        Signature64, HASH_LEN, SIGNATURE_LEN, TAG_ATT_NONCE, TAG_MMR_ROOT,
    };

    #[test]
    fn identifiers_round_trip_via_strings() {
        let client_hex = hex::encode([0x01; HASH_LEN]);
        let auth_hex = hex::encode([0x02; HASH_LEN]);
        let ct_hex = hex::encode([0x03; HASH_LEN]);
        let leaf_hex = hex::encode([0x04; HASH_LEN]);
        let node_hex = hex::encode([0x05; HASH_LEN]);
        let root_hex = hex::encode([0x06; HASH_LEN]);
        let sig_hex = hex::encode([0x07; SIGNATURE_LEN]);

        let client = client_hex.parse::<ClientId>().expect("client id");
        let auth = auth_hex.parse::<AuthRef>().expect("auth ref");
        let ct = ct_hex.parse::<CtHash>().expect("ct hash");
        let leaf = leaf_hex.parse::<LeafHash>().expect("leaf hash");
        let node = node_hex.parse::<MmrNode>().expect("mmr node");
        let root = root_hex.parse::<MmrRoot>().expect("mmr root");
        let sig = sig_hex.parse::<Signature64>().expect("signature");

        assert_eq!(client.to_string(), client_hex);
        assert_eq!(auth.to_string(), auth_hex);
        assert_eq!(ct.to_string(), ct_hex);
        assert_eq!(leaf.to_string(), leaf_hex);
        assert_eq!(node.to_string(), node_hex);
        assert_eq!(root.to_string(), root_hex);
        assert_eq!(sig.to_string(), sig_hex);
    }

    #[test]
    fn fixed_length_round_trips() {
        let client = ClientId::new([0x11; HASH_LEN]);
        let auth = AuthRef::new([0x22; HASH_LEN]);
        let ct = CtHash::new([0x33; HASH_LEN]);
        let leaf = LeafHash::new([0x44; HASH_LEN]);
        let node = MmrNode::new([0x55; HASH_LEN]);
        let root = MmrRoot::new([0x66; HASH_LEN]);
        let sig = Signature64::new([0x77; SIGNATURE_LEN]);

        assert_eq!(client.as_bytes(), &[0x11; HASH_LEN]);
        assert_eq!(auth.as_bytes(), &[0x22; HASH_LEN]);
        assert_eq!(ct.as_bytes(), &[0x33; HASH_LEN]);
        assert_eq!(leaf.as_bytes(), &[0x44; HASH_LEN]);
        assert_eq!(node.as_bytes(), &[0x55; HASH_LEN]);
        assert_eq!(root.as_bytes(), &[0x66; HASH_LEN]);
        assert_eq!(sig.as_bytes(), &[0x77; SIGNATURE_LEN]);

        let client_err = ClientId::from_slice(&client.as_bytes()[..HASH_LEN - 1]).err();
        assert!(client_err.is_some(), "invalid client length should error");

        let auth_err = AuthRef::from_slice(&auth.as_bytes()[..HASH_LEN - 1]).err();
        assert!(auth_err.is_some(), "invalid auth_ref length should error");

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&client, &mut buf).expect("serialize");
        let decoded: ClientId = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(decoded, client);
    }

    #[test]
    fn ct_hash_matches_sha256() {
        let ciphertext = b"ciphertext-test";
        let ct = CtHash::compute(ciphertext);
        let direct = sha2::Sha256::digest(ciphertext);
        assert_eq!(ct.as_ref(), direct.as_slice());
    }

    #[test]
    fn mmr_root_from_peaks_handles_multiple() {
        let peak1 = MmrNode::new([0xAA; HASH_LEN]);
        let peak2 = MmrNode::new([0xBB; HASH_LEN]);
        let peaks = vec![peak1, peak2];
        let root = MmrRoot::from_peaks(&peaks).expect("root");

        let mut data = Vec::new();
        data.extend_from_slice(peak1.as_ref());
        data.extend_from_slice(peak2.as_ref());
        let expected = hash_tagged(TAG_MMR_ROOT, &data);
        assert_eq!(root.as_bytes(), &expected);
    }

    #[test]
    fn signature_from_slice_enforces_length() {
        let sig = Signature64::new([0x99; SIGNATURE_LEN]);
        let ok = Signature64::from_slice(sig.as_ref()).expect("sig");
        assert_eq!(ok, sig);

        let err = Signature64::from_slice(&sig.as_ref()[..SIGNATURE_LEN - 1]).expect_err("err");
        assert_eq!(err.expected(), SIGNATURE_LEN);
    }

    #[test]
    fn signature_verify_accepts_valid_signature() {
        let signing_key = SigningKey::from_bytes(&[0x11; 32]);
        let message = b"verify-me";
        let signature = signing_key.sign(message);
        let sig = Signature64::from(signature.to_bytes());

        assert!(sig
            .verify(signing_key.verifying_key().as_bytes(), message)
            .is_ok());
    }

    #[test]
    fn signature_verify_rejects_modified_message() {
        let signing_key = SigningKey::from_bytes(&[0x22; 32]);
        let message = b"message";
        let signature = signing_key.sign(message);
        let sig = Signature64::from(signature.to_bytes());

        let result = sig.verify(signing_key.verifying_key().as_bytes(), b"tampered");
        assert!(matches!(
            result,
            Err(super::SignatureVerifyError::VerificationFailed(_))
        ));
    }

    #[test]
    fn attachment_nonce_matches_spec_formula() {
        let leaf = LeafHash::new([0xAB; HASH_LEN]);
        let index = 3u64;
        let nonce = leaf.attachment_nonce(index);

        let mut data = Vec::new();
        data.extend_from_slice(leaf.as_ref());
        data.extend_from_slice(&index.to_be_bytes());
        let expected = truncate_nonce(hash_tagged(TAG_ATT_NONCE, &data));
        assert_eq!(nonce, expected);
    }
}
