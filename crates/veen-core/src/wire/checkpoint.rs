use std::io;

use serde::{Deserialize, Serialize};

use crate::{
    hash::ht,
    label::Label,
    wire::types::{MmrRoot, Signature64},
};

/// Wire format version for `CHECKPOINT` objects.
pub const CHECKPOINT_VERSION: u64 = 1;

/// VEEN CHECKPOINT object as defined in section 5 of spec-1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub ver: u64,
    pub label_prev: Label,
    pub label_curr: Label,
    pub upto_seq: u64,
    pub mmr_root: MmrRoot,
    pub epoch: u64,
    pub hub_sig: Signature64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_sigs: Option<Vec<Signature64>>,
}

type CborError = ciborium::ser::Error<io::Error>;

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointSignable<'a> {
    ver: u64,
    label_prev: &'a Label,
    label_curr: &'a Label,
    upto_seq: u64,
    mmr_root: &'a MmrRoot,
    epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
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

impl Checkpoint {
    /// Returns `true` if the checkpoint declares the canonical wire version.
    #[must_use]
    pub fn has_valid_version(&self) -> bool {
        self.ver == CHECKPOINT_VERSION
    }

    /// Serializes the checkpoint without the hub signature field.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, CborError> {
        let mut buf = Vec::new();
        let view = CheckpointSignable::from(self);
        ciborium::ser::into_writer(&view, &mut buf)?;
        Ok(buf)
    }

    /// Computes the canonical `Ht("veen/sig", …)` digest for checkpoint signatures.
    pub fn signing_tagged_hash(&self) -> Result<[u8; 32], CborError> {
        let bytes = self.signing_bytes()?;
        Ok(ht("veen/sig", &bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::ht;

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
        let expected = ht("veen/sig", &buf);

        let computed = checkpoint.signing_tagged_hash().unwrap();
        assert_eq!(computed.as_slice(), expected);
    }
}
