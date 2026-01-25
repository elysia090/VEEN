use crate::wire::proof::{Direction, MmrPathNode, MmrProof, PROOF_VERSION};
use crate::wire::types::{LeafHash, MmrNode, MmrRoot};

/// Maintains the per-label Merkle Mountain Range state as described in spec-1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mmr {
    seq: u64,
    peaks_by_height: Vec<Option<MmrNode>>,
    peaks_scratch: Vec<MmrNode>,
    root_scratch: Vec<u8>,
}

impl Mmr {
    const MAX_HEIGHT: usize = 64;

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

    /// Returns the current peaks ordered by increasing height.
    #[must_use]
    pub fn peaks(&self) -> Vec<MmrNode> {
        self.collect_peaks()
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
        let peaks = self.collect_peaks();
        MmrRoot::from_peaks(&peaks)
    }

    fn append_leaf(
        &mut self,
        leaf: LeafHash,
        with_proof: bool,
    ) -> (u64, MmrRoot, Option<MmrProof>) {
        self.seq = self.seq.checked_add(1).expect("stream_seq overflow");
        let mut carry = MmrNode::from(leaf);
        let mut height = 0usize;
        let mut path = with_proof.then(Vec::new);

        while height < Self::MAX_HEIGHT {
            let left = match self.peaks_by_height.get_mut(height) {
                Some(slot) => slot.take(),
                None => None,
            };
            let Some(left) = left else { break };
            if let Some(path) = path.as_mut() {
                path.push(MmrPathNode {
                    dir: Direction::Left,
                    sib: left,
                });
            }
            carry = MmrNode::combine(&left, &carry);
            height = height.saturating_add(1);
        }

        if height >= Self::MAX_HEIGHT {
            panic!("mmr height overflow");
        }

        self.peaks_by_height[height] = Some(carry);
        self.peaks_scratch.clear();
        let mut peak_index = None;
        for (idx, peak) in self.peaks_by_height.iter().enumerate() {
            if let Some(peak) = peak {
                if idx == height {
                    peak_index = Some(self.peaks_scratch.len());
                }
                self.peaks_scratch.push(*peak);
            }
        }
        let peak_index = peak_index.expect("new peak must be recorded");
        let root = MmrRoot::from_peaks_with_scratch(&self.peaks_scratch, &mut self.root_scratch)
            .expect("peaks must be non-empty");

        let proof = path.map(|path| MmrProof {
            ver: PROOF_VERSION,
            leaf_hash: leaf,
            path,
            peaks_after: self.peaks_scratch[peak_index.saturating_add(1)..].to_vec(),
        });

        (self.seq, root, proof)
    }

    fn collect_peaks(&self) -> Vec<MmrNode> {
        self.peaks_by_height
            .iter()
            .filter_map(|peak| *peak)
            .collect()
    }
}

impl Default for Mmr {
    fn default() -> Self {
        Self {
            seq: 0,
            peaks_by_height: vec![None; Self::MAX_HEIGHT],
            peaks_scratch: Vec::with_capacity(Self::MAX_HEIGHT),
            root_scratch: Vec::with_capacity(Self::MAX_HEIGHT * 32),
        }
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
        assert_eq!(mmr.peaks(), vec![expected_fold]);

        let leaf3 = leaf(0x33);
        let (seq3, root3) = mmr.append(leaf3);
        assert_eq!(seq3, 3);
        let expected_root = MmrRoot::from_peaks(&[MmrNode::from(leaf3), expected_fold]).unwrap();
        assert_eq!(root3, expected_root);
        assert_eq!(mmr.peaks(), vec![MmrNode::from(leaf3), expected_fold]);
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
