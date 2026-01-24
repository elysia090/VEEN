use std::fmt;

use serde::de::{Error as DeError, MapAccess, Visitor};
use serde::ser::SerializeMap;
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmrProof {
    pub ver: u64,
    pub leaf_hash: LeafHash,
    pub path: Vec<MmrPathNode>,
    /// Peaks that follow the target tree in increasing height order.
    pub peaks_after: Vec<MmrNode>,
}

impl Serialize for MmrPathNode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry(&1u64, &self.dir)?;
        map.serialize_entry(&2u64, &self.sib)?;
        map.end()
    }
}

struct MmrPathNodeVisitor;

impl<'de> Visitor<'de> for MmrPathNodeVisitor {
    type Value = MmrPathNode;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("mmr path node map with integer keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut dir: Option<Direction> = None;
        let mut sib: Option<MmrNode> = None;

        while let Some(key) = map.next_key::<u64>()? {
            match key {
                1 => {
                    if dir.is_some() {
                        return Err(DeError::duplicate_field("dir"));
                    }
                    dir = Some(map.next_value()?);
                }
                2 => {
                    if sib.is_some() {
                        return Err(DeError::duplicate_field("sib"));
                    }
                    sib = Some(map.next_value()?);
                }
                _ => {
                    return Err(DeError::custom(format!("unknown path node key: {key}")));
                }
            }
        }

        let dir = dir.ok_or_else(|| DeError::missing_field("dir"))?;
        let sib = sib.ok_or_else(|| DeError::missing_field("sib"))?;
        Ok(MmrPathNode { dir, sib })
    }
}

impl<'de> Deserialize<'de> for MmrPathNode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(MmrPathNodeVisitor)
    }
}

impl Serialize for MmrProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(4))?;
        map.serialize_entry(&1u64, &self.ver)?;
        map.serialize_entry(&2u64, &self.leaf_hash)?;
        map.serialize_entry(&3u64, &self.path)?;
        map.serialize_entry(&4u64, &self.peaks_after)?;
        map.end()
    }
}

struct MmrProofVisitor;

impl<'de> Visitor<'de> for MmrProofVisitor {
    type Value = MmrProof;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("mmr proof map with integer keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut ver: Option<u64> = None;
        let mut leaf_hash: Option<LeafHash> = None;
        let mut path: Option<Vec<MmrPathNode>> = None;
        let mut peaks_after: Option<Vec<MmrNode>> = None;

        while let Some(key) = map.next_key::<u64>()? {
            match key {
                1 => {
                    if ver.is_some() {
                        return Err(DeError::duplicate_field("ver"));
                    }
                    ver = Some(map.next_value()?);
                }
                2 => {
                    if leaf_hash.is_some() {
                        return Err(DeError::duplicate_field("leaf_hash"));
                    }
                    leaf_hash = Some(map.next_value()?);
                }
                3 => {
                    if path.is_some() {
                        return Err(DeError::duplicate_field("path"));
                    }
                    path = Some(map.next_value()?);
                }
                4 => {
                    if peaks_after.is_some() {
                        return Err(DeError::duplicate_field("peaks_after"));
                    }
                    peaks_after = Some(map.next_value()?);
                }
                _ => {
                    return Err(DeError::custom(format!("unknown mmr proof key: {key}")));
                }
            }
        }

        let ver = ver.ok_or_else(|| DeError::missing_field("ver"))?;
        let leaf_hash = leaf_hash.ok_or_else(|| DeError::missing_field("leaf_hash"))?;
        let path = path.ok_or_else(|| DeError::missing_field("path"))?;
        let peaks_after = peaks_after.ok_or_else(|| DeError::missing_field("peaks_after"))?;

        Ok(MmrProof {
            ver,
            leaf_hash,
            path,
            peaks_after,
        })
    }
}

impl<'de> Deserialize<'de> for MmrProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(MmrProofVisitor)
    }
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
        peaks.push(acc);
        peaks.extend_from_slice(&self.peaks_after);

        match MmrRoot::from_peaks(&peaks) {
            Some(root) => root == *expected_root,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

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

    #[test]
    fn proof_serializes_as_integer_keyed_map() {
        let proof = MmrProof {
            ver: PROOF_VERSION,
            leaf_hash: LeafHash::new([0x01; 32]),
            path: vec![MmrPathNode {
                dir: Direction::Left,
                sib: MmrNode::new([0x02; 32]),
            }],
            peaks_after: vec![MmrNode::new([0x03; 32])],
        };

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&proof, &mut buf).unwrap();
        let value: Value = ciborium::de::from_reader(buf.as_slice()).unwrap();

        let map = match value {
            Value::Map(entries) => entries,
            _ => panic!("expected map"),
        };

        let keys: Vec<u64> = map
            .iter()
            .map(|(key, _)| match key {
                Value::Integer(value) => (*value).try_into().unwrap(),
                _ => panic!("expected integer key"),
            })
            .collect();

        assert_eq!(keys, vec![1, 2, 3, 4]);
    }
}
