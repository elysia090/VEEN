use serde::{Deserialize, Serialize};

use crate::{
    label::Label,
    wire::types::{LeafHash, MmrRoot, Signature64},
};

/// Wire format version for `RECEIPT` objects.
pub const RECEIPT_VERSION: u64 = 1;

/// VEEN RECEIPT object as defined in section 5 of spec-1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub ver: u64,
    pub label: Label,
    pub stream_seq: u64,
    pub leaf_hash: LeafHash,
    pub mmr_root: MmrRoot,
    pub hub_ts: u64,
    pub hub_sig: Signature64,
}

impl Receipt {
    /// Returns `true` if the receipt declares the canonical wire version.
    #[must_use]
    pub fn has_valid_version(&self) -> bool {
        self.ver == RECEIPT_VERSION
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
