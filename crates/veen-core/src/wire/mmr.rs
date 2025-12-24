use crate::wire::proof::{Direction, MmrPathNode, MmrProof, PROOF_VERSION};
use crate::wire::types::{LeafHash, MmrNode, MmrRoot};

/// Maintains the per-label Merkle Mountain Range state as described in spec-1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mmr {
    seq: u64,
    peaks: Vec<MmrNode>,
}

impl Mmr {
    /// Creates an empty MMR state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of leaves that have been appended.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Returns the current peaks ordered by increasing tree size.
    #[must_use]
    pub fn peaks(&self) -> &[MmrNode] {
        &self.peaks
    }

    /// Appends a new leaf hash and returns the updated `(stream_seq, mmr_root)` pair.
    pub fn append(&mut self, leaf: LeafHash) -> (u64, MmrRoot) {
        let (seq, root, _) = self.append_leaf(leaf, false);
        (seq, root)
    }

    /// Appends a new leaf hash and returns the updated `(stream_seq, mmr_root, proof)` tuple.
    pub fn append_with_proof(&mut self, leaf: LeafHash) -> (u64, MmrRoot, MmrProof) {
        let (seq, root, proof) = self.append_leaf(leaf, true);
        (seq, root, proof.expect("proof requested"))
    }

    /// Computes the current MMR root if any leaves have been appended.
    #[must_use]
    pub fn root(&self) -> Option<MmrRoot> {
        MmrRoot::from_peaks(&self.peaks)
    }

    fn append_leaf(
        &mut self,
        leaf: LeafHash,
        with_proof: bool,
    ) -> (u64, MmrRoot, Option<MmrProof>) {
        self.seq = self.seq.checked_add(1).expect("stream_seq overflow");
        let mut carry = MmrNode::from(leaf);
        let mut seq = self.seq;
        let mut path = with_proof.then(Vec::new);

        while seq & 1 == 0 {
            let left = self.peaks.pop().expect("folding requires an existing peak");
            if let Some(path) = path.as_mut() {
                path.push(MmrPathNode {
                    dir: Direction::Left,
                    sib: left,
                });
            }
            carry = MmrNode::combine(&left, &carry);
            seq >>= 1;
        }

        let peaks_after = path.as_ref().map(|_| self.peaks.clone());
        self.peaks.push(carry);
        let root = MmrRoot::from_peaks(&self.peaks).expect("peaks must be non-empty");

        let proof = path.map(|path| MmrProof {
            ver: PROOF_VERSION,
            leaf_hash: leaf,
            path,
            peaks_after: peaks_after.unwrap_or_default(),
        });

        (self.seq, root, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(value: u8) -> LeafHash {
        LeafHash::new([value; 32])
    }

    #[test]
    fn empty_mmr_has_no_root() {
        let mmr = Mmr::new();
        assert_eq!(mmr.seq(), 0);
        assert!(mmr.root().is_none());
    }

    #[test]
    fn append_follows_spec_fold_order() {
        let mut mmr = Mmr::new();

        let leaf1 = leaf(0x11);
        let (seq1, root1) = mmr.append(leaf1);
        assert_eq!(seq1, 1);
        assert_eq!(root1.as_bytes(), leaf1.as_bytes());
        assert_eq!(mmr.peaks().len(), 1);

        let leaf2 = leaf(0x22);
        let (seq2, root2) = mmr.append(leaf2);
        let expected_fold = MmrNode::combine(&MmrNode::from(leaf1), &MmrNode::from(leaf2));
        assert_eq!(seq2, 2);
        assert_eq!(root2.as_bytes(), expected_fold.as_ref());
        assert_eq!(mmr.peaks(), &[expected_fold]);

        let leaf3 = leaf(0x33);
        let (seq3, root3) = mmr.append(leaf3);
        assert_eq!(seq3, 3);
        let expected_root = MmrRoot::from_peaks(&[expected_fold, MmrNode::from(leaf3)]).unwrap();
        assert_eq!(root3, expected_root);
        assert_eq!(mmr.peaks(), &[expected_fold, MmrNode::from(leaf3)]);
    }

    #[test]
    fn append_with_proof_verifies() {
        let mut mmr = Mmr::new();

        for value in 1..=5u8 {
            let leaf = leaf(value);
            let (seq, root, proof) = mmr.append_with_proof(leaf);
            assert_eq!(seq as u8, value);
            assert!(proof.verify(&root), "proof must verify for seq {seq}");
            assert_eq!(proof.leaf_hash, leaf);
        }
    }
}
