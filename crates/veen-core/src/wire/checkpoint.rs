use serde::{Deserialize, Serialize};

use crate::{
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

impl Checkpoint {
    /// Returns `true` if the checkpoint declares the canonical wire version.
    #[must_use]
    pub fn has_valid_version(&self) -> bool {
        self.ver == CHECKPOINT_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
