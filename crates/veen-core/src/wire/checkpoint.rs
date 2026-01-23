use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{
    label::Label,
    wire::{
        cbor::{seq_next_required, seq_no_trailing, serialize_fixed_seq},
        types::{MmrRoot, Signature64, SignatureVerifyError, HASH_LEN},
        CborError,
    },
};

use super::{derivation::TAG_SIG, signing::WireSignable};

/// Wire format version for `CHECKPOINT` objects.
pub const CHECKPOINT_VERSION: u64 = 1;

/// VEEN CHECKPOINT object as defined in section 4.4 of spec-1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub ver: u64,
    pub label_prev: Label,
    pub label_curr: Label,
    pub upto_seq: u64,
    pub mmr_root: MmrRoot,
    pub epoch: u64,
    pub hub_sig: Signature64,
    pub witness_sigs: Option<Vec<Signature64>>,
}

/// Errors returned when validating signatures on CHECKPOINT objects.
#[derive(Debug, Error)]
pub enum CheckpointVerifyError {
    /// Failed to serialize the signable view using deterministic CBOR.
    #[error("failed to compute signing digest: {0}")]
    Signing(#[from] CborError),
    /// Signature verification failure (invalid key, encoding, or mismatch).
    #[error(transparent)]
    Signature(#[from] SignatureVerifyError),
}

#[derive(Debug)]
pub(crate) struct CheckpointSignable<'a> {
    ver: u64,
    label_prev: &'a Label,
    label_curr: &'a Label,
    upto_seq: u64,
    mmr_root: &'a MmrRoot,
    epoch: u64,
    witness_sigs: Option<&'a [Signature64]>,
}

impl<'a> From<&'a Checkpoint> for CheckpointSignable<'a> {
    fn from(value: &'a Checkpoint) -> Self {
        Self {
            ver: value.ver,
            label_prev: &value.label_prev,
            label_curr: &value.label_curr,
            upto_seq: value.upto_seq,
            mmr_root: &value.mmr_root,
            epoch: value.epoch,
            witness_sigs: value.witness_sigs.as_deref(),
        }
    }
}

impl Serialize for Checkpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let len = if self.witness_sigs.is_some() { 8 } else { 7 };
        serialize_fixed_seq(serializer, len, |seq| {
            seq.serialize_element(&self.ver)?;
            seq.serialize_element(&self.label_prev)?;
            seq.serialize_element(&self.label_curr)?;
            seq.serialize_element(&self.upto_seq)?;
            seq.serialize_element(&self.mmr_root)?;
            seq.serialize_element(&self.epoch)?;
            seq.serialize_element(&self.hub_sig)?;
            if let Some(witness_sigs) = &self.witness_sigs {
                seq.serialize_element(witness_sigs)?;
            }
            Ok(())
        })
    }
}

impl Serialize for CheckpointSignable<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let len = if self.witness_sigs.is_some() { 7 } else { 6 };
        serialize_fixed_seq(serializer, len, |seq| {
            seq.serialize_element(&self.ver)?;
            seq.serialize_element(&self.label_prev)?;
            seq.serialize_element(&self.label_curr)?;
            seq.serialize_element(&self.upto_seq)?;
            seq.serialize_element(&self.mmr_root)?;
            seq.serialize_element(&self.epoch)?;
            if let Some(witness_sigs) = &self.witness_sigs {
                seq.serialize_element(witness_sigs)?;
            }
            Ok(())
        })
    }
}

struct CheckpointVisitor;

impl<'de> Visitor<'de> for CheckpointVisitor {
    type Value = Checkpoint;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VEEN CHECKPOINT array with 7 or 8 elements")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let expecting = "VEEN CHECKPOINT array with 7 or 8 elements";
        let ver = seq_next_required(&mut seq, 0, expecting)?;
        let label_prev = seq_next_required(&mut seq, 1, expecting)?;
        let label_curr = seq_next_required(&mut seq, 2, expecting)?;
        let upto_seq = seq_next_required(&mut seq, 3, expecting)?;
        let mmr_root = seq_next_required(&mut seq, 4, expecting)?;
        let epoch = seq_next_required(&mut seq, 5, expecting)?;
        let hub_sig = seq_next_required(&mut seq, 6, expecting)?;
        let witness_sigs: Option<Vec<Signature64>> = seq.next_element()?;
        seq_no_trailing(&mut seq, 8, expecting)?;

        Ok(Checkpoint {
            ver,
            label_prev,
            label_curr,
            upto_seq,
            mmr_root,
            epoch,
            hub_sig,
            witness_sigs,
        })
    }
}

impl<'de> Deserialize<'de> for Checkpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(CheckpointVisitor)
    }
}

impl WireSignable for Checkpoint {
    type Signable<'a> = CheckpointSignable<'a>;

    fn signable(&self) -> Self::Signable<'_> {
        CheckpointSignable::from(self)
    }
}

impl Checkpoint {
    /// Returns `true` if the checkpoint declares the canonical wire version.
    #[must_use]
    pub fn has_valid_version(&self) -> bool {
        self.ver == CHECKPOINT_VERSION
    }

    /// Serializes the checkpoint without the hub signature field.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CborError> {
        WireSignable::signing_bytes(self)
    }

    /// Computes the canonical `Ht("veen/sig", …)` digest for checkpoint signatures.
    pub fn signing_tagged_hash(&self) -> Result<[u8; 32], CborError> {
        WireSignable::signing_tagged_hash(self, TAG_SIG)
    }

    /// Verifies `hub_sig` using the provided hub Ed25519 public key bytes.
    pub fn verify_signature(
        &self,
        hub_public_key: &[u8; HASH_LEN],
    ) -> Result<(), CheckpointVerifyError> {
        let digest = self.signing_tagged_hash()?;
        self.hub_sig
            .verify(hub_public_key, digest.as_ref())
            .map_err(CheckpointVerifyError::from)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::wire::derivation::{hash_tagged, TAG_SIG};

    #[test]
    fn checkpoint_version_matches_spec() {
        let checkpoint = Checkpoint {
            ver: CHECKPOINT_VERSION,
            label_prev: Label::from_slice(&[0x11; 32]).unwrap(),
            label_curr: Label::from_slice(&[0x22; 32]).unwrap(),
            upto_seq: 128,
            mmr_root: MmrRoot::new([0x33; 32]),
            epoch: 99,
            hub_sig: Signature64::new([0x44; 64]),
            witness_sigs: Some(vec![Signature64::new([0x55; 64])]),
        };
        assert!(checkpoint.has_valid_version());
    }

    #[test]
    fn signing_tagged_hash_matches_manual_encoding() {
        let checkpoint = Checkpoint {
            ver: CHECKPOINT_VERSION,
            label_prev: Label::from_slice(&[0x31; 32]).unwrap(),
            label_curr: Label::from_slice(&[0x32; 32]).unwrap(),
            upto_seq: 42,
            mmr_root: MmrRoot::new([0x33; 32]),
            epoch: 77,
            hub_sig: Signature64::new([0x34; 64]),
            witness_sigs: Some(vec![Signature64::new([0x35; 64])]),
        };

        let view = CheckpointSignable::from(&checkpoint);
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&view, &mut buf).unwrap();
        let expected = hash_tagged(TAG_SIG, &buf);

        let computed = checkpoint.signing_tagged_hash().unwrap();
        assert_eq!(computed.as_slice(), expected);
    }

    #[test]
    fn verify_signature_accepts_valid_signature() {
        let signing_key = SigningKey::from_bytes(&[0x55; 32]);
        let hub_pk = signing_key.verifying_key();

        let mut checkpoint = Checkpoint {
            ver: CHECKPOINT_VERSION,
            label_prev: Label::from_slice(&[0x11; 32]).unwrap(),
            label_curr: Label::from_slice(&[0x22; 32]).unwrap(),
            upto_seq: 42,
            mmr_root: MmrRoot::new([0x33; 32]),
            epoch: 77,
            hub_sig: Signature64::new([0u8; 64]),
            witness_sigs: None,
        };

        let digest = checkpoint.signing_tagged_hash().unwrap();
        let signature = signing_key.sign(digest.as_ref());
        checkpoint.hub_sig = Signature64::from(signature.to_bytes());

        assert!(checkpoint.verify_signature(hub_pk.as_bytes()).is_ok());
    }

    #[test]
    fn verify_signature_rejects_modified_signature() {
        let signing_key = SigningKey::from_bytes(&[0x66; 32]);
        let hub_pk = signing_key.verifying_key();

        let mut checkpoint = Checkpoint {
            ver: CHECKPOINT_VERSION,
            label_prev: Label::from_slice(&[0x31; 32]).unwrap(),
            label_curr: Label::from_slice(&[0x32; 32]).unwrap(),
            upto_seq: 99,
            mmr_root: MmrRoot::new([0x33; 32]),
            epoch: 11,
            hub_sig: Signature64::new([0u8; 64]),
            witness_sigs: None,
        };

        let digest = checkpoint.signing_tagged_hash().unwrap();
        let signature = signing_key.sign(digest.as_ref());
        let mut bytes = signature.to_bytes();
        bytes[2] ^= 0x01;
        checkpoint.hub_sig = Signature64::from(bytes);

        assert!(matches!(
            checkpoint.verify_signature(hub_pk.as_bytes()),
            Err(CheckpointVerifyError::Signature(
                SignatureVerifyError::VerificationFailed(_)
            ))
        ));
    }

    #[test]
    fn checkpoint_serializes_as_cbor_array_without_witnesses() {
        let checkpoint = Checkpoint {
            ver: CHECKPOINT_VERSION,
            label_prev: Label::from_slice(&[0x51; 32]).unwrap(),
            label_curr: Label::from_slice(&[0x52; 32]).unwrap(),
            upto_seq: 5,
            mmr_root: MmrRoot::new([0x53; 32]),
            epoch: 12,
            hub_sig: Signature64::new([0x54; 64]),
            witness_sigs: None,
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&checkpoint, &mut buf).unwrap();
        let value: ciborium::value::Value = ciborium::de::from_reader(buf.as_slice()).unwrap();

        let array = match value {
            ciborium::value::Value::Array(entries) => entries,
            _ => panic!("expected array"),
        };

        assert_eq!(array.len(), 7);
    }

    #[test]
    fn checkpoint_serializes_as_cbor_array_with_witnesses() {
        let checkpoint = Checkpoint {
            ver: CHECKPOINT_VERSION,
            label_prev: Label::from_slice(&[0x61; 32]).unwrap(),
            label_curr: Label::from_slice(&[0x62; 32]).unwrap(),
            upto_seq: 9,
            mmr_root: MmrRoot::new([0x63; 32]),
            epoch: 21,
            hub_sig: Signature64::new([0x64; 64]),
            witness_sigs: Some(vec![Signature64::new([0x65; 64])]),
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&checkpoint, &mut buf).unwrap();
        let value: ciborium::value::Value = ciborium::de::from_reader(buf.as_slice()).unwrap();

        let array = match value {
            ciborium::value::Value::Array(entries) => entries,
            _ => panic!("expected array"),
        };

        assert_eq!(array.len(), 8);
    }
}
