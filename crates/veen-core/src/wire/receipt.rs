use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{
    label::Label,
    wire::{
        cbor::{seq_next_required, seq_no_trailing, serialize_fixed_seq},
        types::{LeafHash, MmrRoot, Signature64, SignatureVerifyError, HASH_LEN},
        CborError,
    },
};

use super::{derivation::TAG_SIG, signing::WireSignable};

/// Wire format version for `RECEIPT` objects.
pub const RECEIPT_VERSION: u64 = 1;

/// VEEN RECEIPT object as defined in section 4.3 of spec-1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub ver: u64,
    pub label: Label,
    pub stream_seq: u64,
    pub leaf_hash: LeafHash,
    pub mmr_root: MmrRoot,
    pub hub_ts: u64,
    pub hub_sig: Signature64,
}

/// Errors produced when validating hub signatures on RECEIPT objects.
#[derive(Debug, Error)]
pub enum ReceiptVerifyError {
    /// Failed to serialize the signable view using deterministic CBOR.
    #[error("failed to compute signing digest: {0}")]
    Signing(#[from] CborError),
    /// Signature verification failure (invalid key, encoding, or mismatch).
    #[error(transparent)]
    Signature(#[from] SignatureVerifyError),
}

#[derive(Debug)]
pub(crate) struct ReceiptSignable<'a> {
    ver: u64,
    label: &'a Label,
    stream_seq: u64,
    leaf_hash: &'a LeafHash,
    mmr_root: &'a MmrRoot,
    hub_ts: u64,
}

impl<'a> From<&'a Receipt> for ReceiptSignable<'a> {
    fn from(value: &'a Receipt) -> Self {
        Self {
            ver: value.ver,
            label: &value.label,
            stream_seq: value.stream_seq,
            leaf_hash: &value.leaf_hash,
            mmr_root: &value.mmr_root,
            hub_ts: value.hub_ts,
        }
    }
}

impl Serialize for Receipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_fixed_seq(serializer, 7, |seq| {
            seq.serialize_element(&self.ver)?;
            seq.serialize_element(&self.label)?;
            seq.serialize_element(&self.stream_seq)?;
            seq.serialize_element(&self.leaf_hash)?;
            seq.serialize_element(&self.mmr_root)?;
            seq.serialize_element(&self.hub_ts)?;
            seq.serialize_element(&self.hub_sig)?;
            Ok(())
        })
    }
}

impl Serialize for ReceiptSignable<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_fixed_seq(serializer, 6, |seq| {
            seq.serialize_element(&self.ver)?;
            seq.serialize_element(&self.label)?;
            seq.serialize_element(&self.stream_seq)?;
            seq.serialize_element(&self.leaf_hash)?;
            seq.serialize_element(&self.mmr_root)?;
            seq.serialize_element(&self.hub_ts)?;
            Ok(())
        })
    }
}

struct ReceiptVisitor;

impl<'de> Visitor<'de> for ReceiptVisitor {
    type Value = Receipt;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VEEN RECEIPT array with 7 elements")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let expecting = "VEEN RECEIPT array with 7 elements";
        let ver = seq_next_required(&mut seq, 0, expecting)?;
        let label = seq_next_required(&mut seq, 1, expecting)?;
        let stream_seq = seq_next_required(&mut seq, 2, expecting)?;
        let leaf_hash = seq_next_required(&mut seq, 3, expecting)?;
        let mmr_root = seq_next_required(&mut seq, 4, expecting)?;
        let hub_ts = seq_next_required(&mut seq, 5, expecting)?;
        let hub_sig = seq_next_required(&mut seq, 6, expecting)?;
        seq_no_trailing(&mut seq, 7, expecting)?;

        Ok(Receipt {
            ver,
            label,
            stream_seq,
            leaf_hash,
            mmr_root,
            hub_ts,
            hub_sig,
        })
    }
}

impl<'de> Deserialize<'de> for Receipt {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(ReceiptVisitor)
    }
}

impl WireSignable for Receipt {
    type Signable<'a> = ReceiptSignable<'a>;

    fn signable(&self) -> Self::Signable<'_> {
        ReceiptSignable::from(self)
    }
}

impl Receipt {
    /// Returns `true` if the receipt declares the canonical wire version.
    #[must_use]
    pub fn has_valid_version(&self) -> bool {
        self.ver == RECEIPT_VERSION
    }

    /// Serializes the receipt without the hub signature using deterministic CBOR.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CborError> {
        WireSignable::signing_bytes(self)
    }

    /// Computes the `Ht("veen/sig", …)` digest required by spec-1 for hub signatures.
    pub fn signing_tagged_hash(&self) -> Result<[u8; 32], CborError> {
        WireSignable::signing_tagged_hash(self, TAG_SIG)
    }

    /// Verifies `hub_sig` using the provided hub Ed25519 public key bytes.
    pub fn verify_signature(
        &self,
        hub_public_key: &[u8; HASH_LEN],
    ) -> Result<(), ReceiptVerifyError> {
        let digest = self.signing_tagged_hash()?;
        self.hub_sig
            .verify(hub_public_key, digest.as_ref())
            .map_err(ReceiptVerifyError::from)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::wire::derivation::{hash_tagged, TAG_SIG};

    #[test]
    fn receipt_version_matches_spec() {
        let receipt = Receipt {
            ver: RECEIPT_VERSION,
            label: Label::from_slice(&[0x11; 32]).unwrap(),
            stream_seq: 9,
            leaf_hash: LeafHash::new([0x22; 32]),
            mmr_root: MmrRoot::new([0x33; 32]),
            hub_ts: 1_700_000_000,
            hub_sig: Signature64::new([0x44; 64]),
        };
        assert!(receipt.has_valid_version());
    }

    #[test]
    fn signing_tagged_hash_matches_manual_encoding() {
        let receipt = Receipt {
            ver: RECEIPT_VERSION,
            label: Label::from_slice(&[0x21; 32]).unwrap(),
            stream_seq: 5,
            leaf_hash: LeafHash::new([0x22; 32]),
            mmr_root: MmrRoot::new([0x23; 32]),
            hub_ts: 1_700_000_999,
            hub_sig: Signature64::new([0x24; 64]),
        };

        let view = ReceiptSignable::from(&receipt);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&view, &mut buf).unwrap();
        let expected = hash_tagged(TAG_SIG, &buf);

        let computed = receipt.signing_tagged_hash().unwrap();
        assert_eq!(computed.as_slice(), expected);
    }

    #[test]
    fn verify_signature_accepts_valid_signature() {
        let signing_key = SigningKey::from_bytes(&[0x77; 32]);
        let hub_pk = signing_key.verifying_key();

        let mut receipt = Receipt {
            ver: RECEIPT_VERSION,
            label: Label::from_slice(&[0x11; 32]).unwrap(),
            stream_seq: 12,
            leaf_hash: LeafHash::new([0x22; 32]),
            mmr_root: MmrRoot::new([0x33; 32]),
            hub_ts: 1_700_000_000,
            hub_sig: Signature64::new([0u8; 64]),
        };

        let digest = receipt.signing_tagged_hash().unwrap();
        let signature = signing_key.sign(digest.as_ref());
        receipt.hub_sig = Signature64::from(signature.to_bytes());

        assert!(receipt.verify_signature(hub_pk.as_bytes()).is_ok());
    }

    #[test]
    fn verify_signature_rejects_modified_signature() {
        let signing_key = SigningKey::from_bytes(&[0x88; 32]);
        let hub_pk = signing_key.verifying_key();

        let mut receipt = Receipt {
            ver: RECEIPT_VERSION,
            label: Label::from_slice(&[0x21; 32]).unwrap(),
            stream_seq: 2,
            leaf_hash: LeafHash::new([0x22; 32]),
            mmr_root: MmrRoot::new([0x23; 32]),
            hub_ts: 1_700_001_000,
            hub_sig: Signature64::new([0u8; 64]),
        };

        let digest = receipt.signing_tagged_hash().unwrap();
        let signature = signing_key.sign(digest.as_ref());
        let mut bytes = signature.to_bytes();
        bytes[1] ^= 0xAA;
        receipt.hub_sig = Signature64::from(bytes);

        assert!(matches!(
            receipt.verify_signature(hub_pk.as_bytes()),
            Err(ReceiptVerifyError::Signature(
                SignatureVerifyError::VerificationFailed(_)
            ))
        ));
    }

    #[test]
    fn receipt_serializes_as_cbor_array() {
        let receipt = Receipt {
            ver: RECEIPT_VERSION,
            label: Label::from_slice(&[0x41; 32]).unwrap(),
            stream_seq: 7,
            leaf_hash: LeafHash::new([0x42; 32]),
            mmr_root: MmrRoot::new([0x43; 32]),
            hub_ts: 1_700_000_123,
            hub_sig: Signature64::new([0x44; 64]),
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&receipt, &mut buf).unwrap();
        let value: ciborium::value::Value = ciborium::de::from_reader(buf.as_slice()).unwrap();

        let array = match value {
            ciborium::value::Value::Array(entries) => entries,
            _ => panic!("expected array"),
        };

        assert_eq!(array.len(), 7);
    }
}
