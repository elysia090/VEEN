use std::fmt;

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::wire::types::{LeafHash, MmrNode, MmrRoot};

/// Wire format version for `mmr_proof` objects.
pub const PROOF_VERSION: u64 = 1;

/// Direction of a sibling node in an MMR authentication path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Sibling hash is on the left; current node is the right child.
    Left,
    /// Sibling hash is on the right; current node is the left child.
    Right,
}

impl Direction {
    #[must_use]
    fn as_u8(self) -> u8 {
        match self {
            Self::Left => 0,
            Self::Right => 1,
        }
    }
}

impl Serialize for Direction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.as_u8())
    }
}

struct DirectionVisitor;

impl<'de> Visitor<'de> for DirectionVisitor {
    type Value = Direction;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("0 or 1 for MMR direction")
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        match v {
            0 => Ok(Direction::Left),
            1 => Ok(Direction::Right),
            _ => Err(E::invalid_value(serde::de::Unexpected::Unsigned(v), &self)),
        }
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        if v < 0 {
            return Err(E::invalid_value(serde::de::Unexpected::Signed(v), &self));
        }
        self.visit_u64(v as u64)
    }
}

impl<'de> Deserialize<'de> for Direction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_u64(DirectionVisitor)
    }
}

/// Single step in an MMR authentication path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MmrPathNode {
    pub dir: Direction,
    pub sib: MmrNode,
}

impl MmrPathNode {
    #[must_use]
    fn fold(&self, acc: &MmrNode) -> MmrNode {
        match self.dir {
            Direction::Left => MmrNode::combine(&self.sib, acc),
            Direction::Right => MmrNode::combine(acc, &self.sib),
        }
    }
}

/// Inclusion proof for the VEEN MMR structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MmrProof {
    pub ver: u64,
    pub leaf_hash: LeafHash,
    pub path: Vec<MmrPathNode>,
    /// Peaks that precede the target tree in the MMR fold order.
    pub peaks_after: Vec<MmrNode>,
}

impl MmrProof {
    /// Returns `true` if the proof declares the canonical wire version.
    #[must_use]
    pub fn has_valid_version(&self) -> bool {
        self.ver == PROOF_VERSION
    }

    /// Verifies the proof against the provided MMR root.
    #[must_use]
    pub fn verify(&self, expected_root: &MmrRoot) -> bool {
        if !self.has_valid_version() {
            return false;
        }

        let mut acc = MmrNode::from(self.leaf_hash);
        for step in &self.path {
            acc = step.fold(&acc);
        }

        let mut peaks = Vec::with_capacity(1 + self.peaks_after.len());
        peaks.extend_from_slice(&self.peaks_after);
        peaks.push(acc);

        match MmrRoot::from_peaks(&peaks) {
            Some(root) => root == *expected_root,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(value: u8) -> MmrNode {
        MmrNode::new([value; 32])
    }

    #[test]
    fn direction_serializes_as_expected() {
        let left = Direction::Left;
        let right = Direction::Right;

        let mut left_buf = Vec::new();
        ciborium::ser::into_writer(&left, &mut left_buf).unwrap();
        let mut right_buf = Vec::new();
        ciborium::ser::into_writer(&right, &mut right_buf).unwrap();

        assert_eq!(left_buf, vec![0x00]);
        assert_eq!(right_buf, vec![0x01]);

        let decoded_left: Direction = ciborium::de::from_reader(left_buf.as_slice()).unwrap();
        let decoded_right: Direction = ciborium::de::from_reader(right_buf.as_slice()).unwrap();
        assert_eq!(decoded_left, Direction::Left);
        assert_eq!(decoded_right, Direction::Right);
    }

    #[test]
    fn proof_verification_matches_manual_root() {
        let leaf = LeafHash::new([0x11; 32]);
        let sibling = node(0x22);
        let combined = MmrNode::combine(&MmrNode::from(leaf), &sibling);
        let root = MmrRoot::from(combined);

        let proof = MmrProof {
            ver: PROOF_VERSION,
            leaf_hash: leaf,
            path: vec![MmrPathNode {
                dir: Direction::Right,
                sib: sibling,
            }],
            peaks_after: Vec::new(),
        };

        assert!(proof.verify(&root));
    }

    #[test]
    fn proof_rejects_wrong_root() {
        let leaf = LeafHash::new([0x33; 32]);
        let sibling = node(0x44);

        let proof = MmrProof {
            ver: PROOF_VERSION,
            leaf_hash: leaf,
            path: vec![MmrPathNode {
                dir: Direction::Left,
                sib: sibling,
            }],
            peaks_after: Vec::new(),
        };

        let other_root = MmrRoot::new([0x55; 32]);
        assert!(!proof.verify(&other_root));
    }
}
