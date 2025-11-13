use std::{convert::TryFrom, fmt};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{hash::h, label::Label, profile::ProfileId, LengthError};

/// Length in bytes of Ed25519-based identifiers and hashes used in VEEN wire objects.
pub const HASH_LEN: usize = 32;
/// Length in bytes of Ed25519 signatures used by VEEN wire objects.
pub const SIGNATURE_LEN: usize = 64;
/// Length in bytes of AEAD nonces derived from the specification hashes.
pub const AEAD_NONCE_LEN: usize = 24;

/// Raw Ed25519 public key carried as `client_id` on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientId([u8; HASH_LEN]);

impl ClientId {
    #[must_use]
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != HASH_LEN {
            return Err(LengthError::new(HASH_LEN, bytes.len()));
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }
}

impl From<[u8; HASH_LEN]> for ClientId {
    fn from(value: [u8; HASH_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; HASH_LEN]> for ClientId {
    fn from(value: &[u8; HASH_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for ClientId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for ClientId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for ClientId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for ClientId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct ClientIdVisitor;

impl<'de> Visitor<'de> for ClientIdVisitor {
    type Value = ClientId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN client identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        ClientId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for ClientId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ClientIdVisitor)
    }
}

/// Admission reference carried on the wire to bind to a capability token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthRef([u8; HASH_LEN]);

impl AuthRef {
    #[must_use]
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != HASH_LEN {
            return Err(LengthError::new(HASH_LEN, bytes.len()));
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }
}

impl From<[u8; HASH_LEN]> for AuthRef {
    fn from(value: [u8; HASH_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; HASH_LEN]> for AuthRef {
    fn from(value: &[u8; HASH_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for AuthRef {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for AuthRef {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for AuthRef {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for AuthRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for AuthRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct AuthRefVisitor;

impl<'de> Visitor<'de> for AuthRefVisitor {
    type Value = AuthRef;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN auth_ref value")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        AuthRef::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for AuthRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(AuthRefVisitor)
    }
}

/// Canonical SHA-256 hash of the ciphertext payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CtHash([u8; HASH_LEN]);

impl CtHash {
    #[must_use]
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != HASH_LEN {
            return Err(LengthError::new(HASH_LEN, bytes.len()));
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    /// Computes the canonical ciphertext hash `H(ciphertext)`.
    #[must_use]
    pub fn compute(ciphertext: &[u8]) -> Self {
        Self(h(ciphertext))
    }
}

impl From<[u8; HASH_LEN]> for CtHash {
    fn from(value: [u8; HASH_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; HASH_LEN]> for CtHash {
    fn from(value: &[u8; HASH_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for CtHash {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for CtHash {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for CtHash {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for CtHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for CtHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct CtHashVisitor;

impl<'de> Visitor<'de> for CtHashVisitor {
    type Value = CtHash;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN ciphertext hash")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        CtHash::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for CtHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(CtHashVisitor)
    }
}

/// Leaf hash committed into the MMR for each message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LeafHash([u8; HASH_LEN]);

impl LeafHash {
    #[must_use]
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != HASH_LEN {
            return Err(LengthError::new(HASH_LEN, bytes.len()));
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    /// Computes the canonical leaf hash derivation used by the specification.
    #[must_use]
    pub fn derive(
        label: &Label,
        profile_id: &ProfileId,
        ct_hash: &CtHash,
        client_id: &ClientId,
        client_seq: u64,
    ) -> Self {
        let mut data =
            Vec::with_capacity(label.as_ref().len() + profile_id.as_ref().len() + 8 + 64);
        data.extend_from_slice(label.as_ref());
        data.extend_from_slice(profile_id.as_ref());
        data.extend_from_slice(ct_hash.as_ref());
        data.extend_from_slice(client_id.as_ref());
        data.extend_from_slice(&client_seq.to_be_bytes());
        Self(crate::hash::ht("veen/leaf", &data))
    }

    /// Computes the attachment nonce `Trunc_24(Ht("veen/att-nonce", msg_id || u64be(i)))`.
    #[must_use]
    pub fn attachment_nonce(&self, index: u64) -> [u8; AEAD_NONCE_LEN] {
        let mut data = Vec::with_capacity(self.as_ref().len() + std::mem::size_of::<u64>());
        data.extend_from_slice(self.as_ref());
        data.extend_from_slice(&index.to_be_bytes());
        let digest = crate::hash::ht("veen/att-nonce", &data);

        let mut nonce = [0u8; AEAD_NONCE_LEN];
        nonce.copy_from_slice(&digest[..AEAD_NONCE_LEN]);
        nonce
    }
}

impl From<[u8; HASH_LEN]> for LeafHash {
    fn from(value: [u8; HASH_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; HASH_LEN]> for LeafHash {
    fn from(value: &[u8; HASH_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for LeafHash {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for LeafHash {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for LeafHash {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for LeafHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for LeafHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct LeafHashVisitor;

impl<'de> Visitor<'de> for LeafHashVisitor {
    type Value = LeafHash;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN leaf hash")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        LeafHash::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for LeafHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(LeafHashVisitor)
    }
}

/// Intermediate MMR node or peak hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MmrNode([u8; HASH_LEN]);

impl MmrNode {
    #[must_use]
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != HASH_LEN {
            return Err(LengthError::new(HASH_LEN, bytes.len()));
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    #[must_use]
    pub fn combine(left: &Self, right: &Self) -> Self {
        let mut data = [0u8; HASH_LEN * 2];
        data[..HASH_LEN].copy_from_slice(left.as_ref());
        data[HASH_LEN..].copy_from_slice(right.as_ref());
        Self(crate::hash::ht("veen/mmr-node", &data))
    }
}

impl From<[u8; HASH_LEN]> for MmrNode {
    fn from(value: [u8; HASH_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; HASH_LEN]> for MmrNode {
    fn from(value: &[u8; HASH_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for MmrNode {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for MmrNode {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for MmrNode {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for MmrNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for MmrNode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct MmrNodeVisitor;

impl<'de> Visitor<'de> for MmrNodeVisitor {
    type Value = MmrNode;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN MMR node hash")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        MmrNode::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for MmrNode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(MmrNodeVisitor)
    }
}

impl From<LeafHash> for MmrNode {
    fn from(value: LeafHash) -> Self {
        Self::new(*value.as_bytes())
    }
}

/// Merkle Mountain Range root committed by hubs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MmrRoot([u8; HASH_LEN]);

impl MmrRoot {
    #[must_use]
    pub const fn new(bytes: [u8; HASH_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != HASH_LEN {
            return Err(LengthError::new(HASH_LEN, bytes.len()));
        }
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

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

        let mut data = Vec::with_capacity(peaks.len() * HASH_LEN);
        for peak in peaks {
            data.extend_from_slice(peak.as_ref());
        }
        Some(Self(crate::hash::ht("veen/mmr-root", &data)))
    }
}

impl From<[u8; HASH_LEN]> for MmrRoot {
    fn from(value: [u8; HASH_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; HASH_LEN]> for MmrRoot {
    fn from(value: &[u8; HASH_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for MmrRoot {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for MmrRoot {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for MmrRoot {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for MmrRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for MmrRoot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct MmrRootVisitor;

impl<'de> Visitor<'de> for MmrRootVisitor {
    type Value = MmrRoot;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN MMR root")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        MmrRoot::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for MmrRoot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(MmrRootVisitor)
    }
}

impl From<MmrNode> for MmrRoot {
    fn from(value: MmrNode) -> Self {
        Self::new(*value.as_bytes())
    }
}

/// Canonical Ed25519 signature stored in `MSG.sig`, `RECEIPT.hub_sig`, and checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature64([u8; SIGNATURE_LEN]);

impl Signature64 {
    #[must_use]
    pub const fn new(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != SIGNATURE_LEN {
            return Err(LengthError::new(SIGNATURE_LEN, bytes.len()));
        }
        let mut out = [0u8; SIGNATURE_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }
}

impl From<[u8; SIGNATURE_LEN]> for Signature64 {
    fn from(value: [u8; SIGNATURE_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; SIGNATURE_LEN]> for Signature64 {
    fn from(value: &[u8; SIGNATURE_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for Signature64 {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for Signature64 {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for Signature64 {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for Signature64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for Signature64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct SignatureVisitor;

impl<'de> Visitor<'de> for SignatureVisitor {
    type Value = Signature64;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 64-byte VEEN Ed25519 signature")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Signature64::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for Signature64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(SignatureVisitor)
    }
}

impl From<LeafHash> for MmrRoot {
    fn from(value: LeafHash) -> Self {
        Self::new(*value.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use sha2::Digest;

    use super::{
        AuthRef, ClientId, CtHash, LeafHash, MmrNode, MmrRoot, Signature64, AEAD_NONCE_LEN,
        HASH_LEN, SIGNATURE_LEN,
    };

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
        let expected = crate::hash::ht("veen/mmr-root", &data);
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
    fn attachment_nonce_matches_spec_formula() {
        let leaf = LeafHash::new([0xAB; HASH_LEN]);
        let index = 3u64;
        let nonce = leaf.attachment_nonce(index);

        let mut data = Vec::new();
        data.extend_from_slice(leaf.as_ref());
        data.extend_from_slice(&index.to_be_bytes());
        let digest = crate::hash::ht("veen/att-nonce", &data);

        let mut expected = [0u8; AEAD_NONCE_LEN];
        expected.copy_from_slice(&digest[..AEAD_NONCE_LEN]);
        assert_eq!(nonce, expected);
    }
}
