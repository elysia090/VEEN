use std::fmt;

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    hash::h,
    meta::SchemaId,
    wire::{
        derivation::{hash_tagged, TAG_ATT_NODE, TAG_ATT_ROOT},
        types::{AuthRef, LeafHash, HASH_LEN},
    },
    LengthError,
};

/// Canonical payload header carried inside encrypted VEEN messages as defined
/// in section 6 of spec-1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadHeader {
    pub schema: SchemaId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<LeafHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub att_root: Option<AttachmentRoot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_ref: Option<AuthRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// Identifier of an attachment ciphertext (coid) derived as `H(ciphertext)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttachmentId([u8; HASH_LEN]);

impl AttachmentId {
    /// Creates a new attachment identifier from the provided bytes.
    #[must_use]
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Attempts to construct an [`AttachmentId`] from an arbitrary slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != HASH_LEN {
            return Err(LengthError::new(HASH_LEN, bytes.len()));
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    /// Computes the attachment identifier `coid = H(ciphertext)` for the
    /// provided ciphertext bytes.
    #[must_use]
    pub fn from_ciphertext(ciphertext: impl AsRef<[u8]>) -> Self {
        Self(h(ciphertext.as_ref()))
    }
}

impl From<[u8; HASH_LEN]> for AttachmentId {
    fn from(value: [u8; HASH_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; HASH_LEN]> for AttachmentId {
    fn from(value: &[u8; HASH_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for AttachmentId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for AttachmentId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for AttachmentId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

crate::hexutil::impl_hex_fmt!(AttachmentId);

impl Serialize for AttachmentId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct AttachmentIdVisitor;

impl<'de> Visitor<'de> for AttachmentIdVisitor {
    type Value = AttachmentId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN attachment identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        AttachmentId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for AttachmentId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(AttachmentIdVisitor)
    }
}

crate::hexutil::impl_fixed_hex_from_str!(AttachmentId, HASH_LEN);

/// Canonical attachment Merkle root committed in `payload_hdr.att_root`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttachmentRoot([u8; HASH_LEN]);

impl AttachmentRoot {
    /// Creates a new [`AttachmentRoot`] from the provided bytes.
    #[must_use]
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the root bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Attempts to construct an [`AttachmentRoot`] from an arbitrary slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != HASH_LEN {
            return Err(LengthError::new(HASH_LEN, bytes.len()));
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    /// Computes the attachment root for the provided attachment identifiers
    /// using the Merkle construction defined in spec-1 section 10.
    #[must_use]
    pub fn from_ids<I>(ids: I) -> Option<Self>
    where
        I: IntoIterator<Item = AttachmentId>,
    {
        let mut peaks = Vec::new();
        let mut seq = 0u64;

        for id in ids {
            seq = seq.checked_add(1)?;
            let mut carry = AttachmentNode::from(id);
            let mut index = seq;

            while index & 1 == 0 {
                let left = peaks.pop()?;
                carry = AttachmentNode::combine(&left, &carry);
                index >>= 1;
            }

            peaks.push(carry);
        }

        Self::from_peaks(&peaks)
    }

    /// Convenience helper to compute the attachment root directly from the
    /// ciphertext bytes.
    #[must_use]
    pub fn from_ciphertexts<'a, I>(ciphertexts: I) -> Option<Self>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let ids = ciphertexts.into_iter().map(AttachmentId::from_ciphertext);
        Self::from_ids(ids)
    }

    fn from_peaks(peaks: &[AttachmentNode]) -> Option<Self> {
        match peaks.len() {
            0 => None,
            1 => Some(Self::new(*peaks[0].as_bytes())),
            _ => {
                let mut data = Vec::with_capacity(peaks.len() * HASH_LEN);
                for peak in peaks {
                    data.extend_from_slice(peak.as_ref());
                }
                Some(Self(hash_tagged(TAG_ATT_ROOT, &data)))
            }
        }
    }
}

impl From<AttachmentId> for AttachmentRoot {
    fn from(value: AttachmentId) -> Self {
        Self::new(*value.as_bytes())
    }
}

impl From<[u8; HASH_LEN]> for AttachmentRoot {
    fn from(value: [u8; HASH_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; HASH_LEN]> for AttachmentRoot {
    fn from(value: &[u8; HASH_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for AttachmentRoot {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for AttachmentRoot {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for AttachmentRoot {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

crate::hexutil::impl_hex_fmt!(AttachmentRoot);

impl Serialize for AttachmentRoot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct AttachmentRootVisitor;

impl<'de> Visitor<'de> for AttachmentRootVisitor {
    type Value = AttachmentRoot;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN attachment root")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        AttachmentRoot::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for AttachmentRoot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(AttachmentRootVisitor)
    }
}

crate::hexutil::impl_fixed_hex_from_str!(AttachmentRoot, HASH_LEN);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AttachmentNode([u8; HASH_LEN]);

impl AttachmentNode {
    #[must_use]
    fn from(id: AttachmentId) -> Self {
        Self(*id.as_bytes())
    }

    #[must_use]
    fn combine(left: &Self, right: &Self) -> Self {
        let mut data = [0u8; HASH_LEN * 2];
        data[..HASH_LEN].copy_from_slice(left.as_ref());
        data[HASH_LEN..].copy_from_slice(right.as_ref());
        Self(hash_tagged(TAG_ATT_NODE, &data))
    }

    #[must_use]
    const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl AsRef<[u8]> for AttachmentNode {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use hex::FromHex;

    use super::*;

    #[test]
    fn attachment_identifiers_round_trip_via_strings() {
        let id_bytes = [0x11; HASH_LEN];
        let root_bytes = [0x22; HASH_LEN];

        let id_hex = hex::encode(id_bytes);
        let root_hex = hex::encode(root_bytes);

        let parsed_id = id_hex.parse::<AttachmentId>().expect("parse attachment id");
        let parsed_root = root_hex
            .parse::<AttachmentRoot>()
            .expect("parse attachment root");

        assert_eq!(parsed_id.as_bytes(), &id_bytes);
        assert_eq!(parsed_id.to_string(), id_hex);
        assert_eq!(parsed_root.as_bytes(), &root_bytes);
        assert_eq!(parsed_root.to_string(), root_hex);
    }

    #[test]
    fn payload_header_round_trip() {
        let schema = SchemaId::from_slice(
            &<[u8; 32]>::from_hex(
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            )
            .unwrap(),
        )
        .unwrap();
        let parent = LeafHash::from_slice(
            &<[u8; 32]>::from_hex(
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            )
            .unwrap(),
        )
        .unwrap();
        let att_root =
            AttachmentRoot::from_ciphertexts([b"cipher-1".as_ref(), b"cipher-2".as_ref()])
                .expect("attachment root");
        let cap_ref = AuthRef::from_slice(
            &<[u8; 32]>::from_hex(
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            )
            .unwrap(),
        )
        .unwrap();

        let header = PayloadHeader {
            schema,
            parent_id: Some(parent),
            att_root: Some(att_root),
            cap_ref: Some(cap_ref),
            expires_at: Some(1_700_000_000),
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&header, &mut buf).expect("serialize payload header");
        let decoded: PayloadHeader =
            ciborium::de::from_reader(buf.as_slice()).expect("deserialize payload header");
        assert_eq!(decoded, header);
    }

    #[test]
    fn attachment_id_from_ciphertext_matches_sha256() {
        let id = AttachmentId::from_ciphertext(b"attachment-cipher");
        let expected = h(b"attachment-cipher");
        assert_eq!(id.as_bytes(), &expected);
    }

    #[test]
    fn attachment_root_none_for_empty_input() {
        assert!(AttachmentRoot::from_ids(std::iter::empty()).is_none());
        let empty_ciphertexts: [&[u8]; 0] = [];
        assert!(AttachmentRoot::from_ciphertexts(empty_ciphertexts).is_none());
    }

    #[test]
    fn attachment_root_matches_manual_derivation() {
        let c1 = b"ciphertext-1";
        let c2 = b"ciphertext-2";
        let c3 = b"ciphertext-3";

        let coid1 = AttachmentId::from_ciphertext(c1);
        let coid2 = AttachmentId::from_ciphertext(c2);
        let coid3 = AttachmentId::from_ciphertext(c3);

        let mut peaks = Vec::new();
        for (seq, id) in [coid1, coid2, coid3].into_iter().enumerate() {
            let mut carry = AttachmentNode::from(id);
            let mut index = seq + 1;
            while index & 1 == 0 {
                let left = peaks.pop().unwrap();
                carry = AttachmentNode::combine(&left, &carry);
                index >>= 1;
            }
            peaks.push(carry);
        }
        let expected = AttachmentRoot::from_peaks(&peaks).expect("expected root");

        let computed = AttachmentRoot::from_ciphertexts([c1.as_ref(), c2.as_ref(), c3.as_ref()])
            .expect("computed root");
        assert_eq!(computed, expected);
    }
}
