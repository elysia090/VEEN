use crate::wire::proof::{Direction, MmrPathNode, MmrProof, PROOF_VERSION};
use crate::wire::types::{LeafHash, MmrNode, MmrRoot};
use thiserror::Error;

const MAX_HEIGHT: usize = 64;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MmrError {
    #[error("stream sequence overflow")]
    StreamSeqOverflow,
    #[error("mmr height overflow at height {height}")]
    HeightOverflow { height: usize },
    #[error("peak bitmap inconsistent at height {height}")]
    PeakBitmapInconsistent { height: usize },
}

/// Maintains the per-label Merkle Mountain Range state as described in spec-1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mmr {
    seq: u64,
    peaks_by_height: [Option<MmrNode>; MAX_HEIGHT],
    peak_bitmap: u64,
    peaks_scratch: Vec<MmrNode>,
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

    /// Returns the current peaks ordered by increasing height.
    #[must_use]
    pub fn peaks(&self) -> Vec<MmrNode> {
        self.collect_peaks()
    }

    /// Appends a new leaf hash and returns the updated `(stream_seq, mmr_root)` pair.
    pub fn append(&mut self, leaf: LeafHash) -> Result<(u64, MmrRoot), MmrError> {
        let outcome = self.append_leaf(leaf, false)?;
        let (seq, root, _) = outcome.into_parts();
        Ok((seq, root))
    }

    /// Appends a new leaf hash and returns the updated `(stream_seq, mmr_root, proof)` tuple.
    pub fn append_with_proof(
        &mut self,
        leaf: LeafHash,
    ) -> Result<(u64, MmrRoot, MmrProof), MmrError> {
        let outcome = self.append_leaf(leaf, true)?;
        let height = outcome.height;
        let (seq, root, proof) = outcome.into_parts();
        let proof = proof.ok_or(MmrError::PeakBitmapInconsistent { height })?;
        Ok((seq, root, proof))
    }

    /// Computes the current MMR root if any leaves have been appended.
    #[must_use]
    pub fn root(&self) -> Option<MmrRoot> {
        let peaks = self.collect_peaks();
        MmrRoot::from_peaks(&peaks)
    }

    fn append_leaf(&mut self, leaf: LeafHash, with_proof: bool) -> Result<AppendOutcome, MmrError> {
        self.seq = self.seq.checked_add(1).ok_or(MmrError::StreamSeqOverflow)?;
        let mut carry = MmrNode::from(leaf);
        let mut height = 0usize;
        let mut path = with_proof.then(|| Vec::with_capacity(MAX_HEIGHT));

        while height < MAX_HEIGHT {
            if self.peak_bitmap & (1u64 << height) == 0 {
                break;
            }
            let left = self.peaks_by_height[height]
                .take()
                .ok_or(MmrError::PeakBitmapInconsistent { height })?;
            self.peak_bitmap &= !(1u64 << height);
            if let Some(path) = path.as_mut() {
                path.push(MmrPathNode {
                    dir: Direction::Left,
                    sib: left,
                });
            }
            carry = MmrNode::combine(&left, &carry);
            height = height.saturating_add(1);
        }

        if height >= MAX_HEIGHT {
            return Err(MmrError::HeightOverflow { height });
        }

        self.peaks_by_height[height] = Some(carry);
        self.peak_bitmap |= 1u64 << height;
        self.peaks_scratch.clear();
        let mut peak_index = None;
        let mut bitmap = self.peak_bitmap;
        while bitmap != 0 {
            let idx = bitmap.trailing_zeros() as usize;
            bitmap &= !(1u64 << idx);
            let peak = self.peaks_by_height[idx]
                .ok_or(MmrError::PeakBitmapInconsistent { height: idx })?;
            if idx == height {
                peak_index = Some(self.peaks_scratch.len());
            }
            self.peaks_scratch.push(peak);
        }
        let peak_index = peak_index.ok_or(MmrError::PeakBitmapInconsistent { height })?;
        let root = MmrRoot::from_peaks(&self.peaks_scratch)
            .ok_or(MmrError::PeakBitmapInconsistent { height })?;

        let proof = path.map(|path| MmrProof {
            ver: PROOF_VERSION,
            leaf_hash: leaf,
            path,
            peaks_after: {
                let start = peak_index.saturating_add(1);
                let suffix = &self.peaks_scratch[start..];
                let mut out = Vec::with_capacity(suffix.len());
                out.extend_from_slice(suffix);
                out
            },
        });

        Ok(AppendOutcome {
            seq: self.seq,
            root,
            proof,
            height,
        })
    }

    fn collect_peaks(&self) -> Vec<MmrNode> {
        let mut peaks = Vec::with_capacity(self.peaks_by_height.len());
        let mut bitmap = self.peak_bitmap;
        while bitmap != 0 {
            let idx = bitmap.trailing_zeros() as usize;
            bitmap &= !(1u64 << idx);
            peaks.push(self.peaks_by_height[idx].expect("peak bitmap out of sync"));
        }
        peaks
    }
}

struct AppendOutcome {
    seq: u64,
    root: MmrRoot,
    proof: Option<MmrProof>,
    height: usize,
}

impl AppendOutcome {
    fn into_parts(self) -> (u64, MmrRoot, Option<MmrProof>) {
        (self.seq, self.root, self.proof)
    }
}

impl Default for Mmr {
    fn default() -> Self {
        Self {
            seq: 0,
            peaks_by_height: [None; MAX_HEIGHT],
            peak_bitmap: 0,
            peaks_scratch: Vec::with_capacity(MAX_HEIGHT),
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
        let (seq1, root1) = mmr.append(leaf1).expect("append leaf1");
        assert_eq!(seq1, 1);
        assert_eq!(root1.as_bytes(), leaf1.as_bytes());
        assert_eq!(mmr.peaks().len(), 1);

        let leaf2 = leaf(0x22);
        let (seq2, root2) = mmr.append(leaf2).expect("append leaf2");
        let expected_fold = MmrNode::combine(&MmrNode::from(leaf1), &MmrNode::from(leaf2));
        assert_eq!(seq2, 2);
        assert_eq!(root2.as_bytes(), expected_fold.as_ref());
        assert_eq!(mmr.peaks(), vec![expected_fold]);

        let leaf3 = leaf(0x33);
        let (seq3, root3) = mmr.append(leaf3).expect("append leaf3");
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
            let (seq, root, proof) = mmr.append_with_proof(leaf).expect("append with proof");
            assert_eq!(seq as u8, value);
            assert!(proof.verify(&root), "proof must verify for seq {seq}");
            assert_eq!(proof.leaf_hash, leaf);
        }
    }
}
