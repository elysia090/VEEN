use std::{collections::HashMap, convert::TryFrom, fmt};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{h, LengthError};

/// Length in bytes of a revocation target value.
pub const REVOCATION_TARGET_LEN: usize = 32;

/// Returns the schema identifier for `veen.revocation.v1`.
#[must_use]
pub fn schema_revocation() -> [u8; 32] {
    h(b"veen.revocation.v1")
}

/// Canonical hash used when revoking capability tokens.
#[must_use]
pub fn cap_token_hash(cbor_cap_token: &[u8]) -> [u8; 32] {
    h(cbor_cap_token)
}

/// Identifier for a revocation target as defined in KEX1+.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RevocationTarget([u8; REVOCATION_TARGET_LEN]);

impl RevocationTarget {
    /// Creates a new [`RevocationTarget`] from a byte array.
    #[must_use]
    pub const fn new(bytes: [u8; REVOCATION_TARGET_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; REVOCATION_TARGET_LEN] {
        &self.0
    }

    /// Attempts to construct a target from an arbitrary slice enforcing the exact
    /// length defined by the specification.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != REVOCATION_TARGET_LEN {
            return Err(LengthError::new(REVOCATION_TARGET_LEN, bytes.len()));
        }
        let mut out = [0u8; REVOCATION_TARGET_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }
}

impl From<[u8; REVOCATION_TARGET_LEN]> for RevocationTarget {
    fn from(value: [u8; REVOCATION_TARGET_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; REVOCATION_TARGET_LEN]> for RevocationTarget {
    fn from(value: &[u8; REVOCATION_TARGET_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for RevocationTarget {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for RevocationTarget {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for RevocationTarget {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for RevocationTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for RevocationTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct RevocationTargetVisitor;

impl<'de> Visitor<'de> for RevocationTargetVisitor {
    type Value = RevocationTarget;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte revocation target")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        RevocationTarget::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for RevocationTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(RevocationTargetVisitor)
    }
}

/// Revocation kind values as defined by the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RevocationKind {
    /// Revocation of a `client_id`.
    ClientId,
    /// Revocation of an `auth_ref`.
    AuthRef,
    /// Revocation of a capability token hash.
    CapToken,
}

/// Revocation record derived from stream updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRecord {
    pub kind: RevocationKind,
    pub target: RevocationTarget,
    pub reason: Option<String>,
    pub ts: u64,
    pub ttl: Option<u64>,
}

impl RevocationRecord {
    /// Returns `true` if the revocation applies at the provided Unix timestamp.
    #[must_use]
    pub fn is_active_at(&self, time: u64) -> bool {
        if time < self.ts {
            return false;
        }
        match self.ttl {
            Some(ttl) => match self.ts.checked_add(ttl) {
                Some(expiry) => time < expiry,
                None => true,
            },
            None => true,
        }
    }

    /// Returns the exclusive expiry timestamp if the record has a bounded lifetime.
    #[must_use]
    pub fn expires_at(&self) -> Option<u64> {
        self.ttl.and_then(|ttl| self.ts.checked_add(ttl))
    }
}

type RevocationKey = (RevocationKind, RevocationTarget);

/// In-memory materialization of revocation records keyed by `(kind, target)`.
#[derive(Debug, Clone, Default)]
pub struct RevocationView {
    records: HashMap<RevocationKey, Vec<RevocationRecord>>,
}

impl RevocationView {
    /// Creates an empty view.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Removes all tracked revocations.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// Returns the number of distinct `(kind, target)` entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if the view has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Inserts a revocation record into the view.
    pub fn insert(&mut self, record: RevocationRecord) {
        let key = (record.kind, record.target);
        self.records.entry(key).or_default().push(record);
    }

    /// Extends the view with multiple revocation records.
    pub fn extend<I>(&mut self, records: I)
    where
        I: IntoIterator<Item = RevocationRecord>,
    {
        for record in records {
            self.insert(record);
        }
    }

    /// Removes revocation records that have expired by `time`.
    pub fn purge_expired(&mut self, time: u64) {
        self.records.retain(|_, entries| {
            entries.retain(|record| record.is_active_at(time) || record.ts > time);
            !entries.is_empty()
        });
    }

    fn active_record_at(
        &self,
        kind: RevocationKind,
        target: RevocationTarget,
        time: u64,
    ) -> Option<&RevocationRecord> {
        self.records.get(&(kind, target)).and_then(|records| {
            records
                .iter()
                .filter(|record| record.is_active_at(time))
                .max_by_key(|record| record.ts)
        })
    }

    /// Returns `true` if the specified `(kind, target)` is revoked at `time`.
    #[must_use]
    pub fn is_revoked(&self, kind: RevocationKind, target: RevocationTarget, time: u64) -> bool {
        self.active_record_at(kind, target, time).is_some()
    }

    /// Returns the active revocation record if present at `time`.
    #[must_use]
    pub fn revoked_record(
        &self,
        kind: RevocationKind,
        target: RevocationTarget,
        time: u64,
    ) -> Option<&RevocationRecord> {
        self.active_record_at(kind, target, time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_matches_expected_digest() {
        assert_eq!(
            schema_revocation(),
            [
                0x19, 0x92, 0x70, 0xcc, 0xcd, 0x72, 0xd7, 0xd8, 0xb6, 0xb6, 0x90, 0x5c, 0x45, 0x7a,
                0x79, 0xaa, 0x27, 0x50, 0xe0, 0xc1, 0x63, 0x1e, 0xfd, 0x07, 0xe0, 0x95, 0x46, 0x6e,
                0x5e, 0xfa, 0x39, 0x99,
            ]
        );
    }

    #[test]
    fn cap_token_hash_matches_sha256() {
        let data = [0xAB; 42];
        let hash = cap_token_hash(&data);
        assert_eq!(hash, h(&data));
    }

    #[test]
    fn revocation_target_from_slice_enforces_length() {
        let bytes = [0x11; REVOCATION_TARGET_LEN];
        let target = RevocationTarget::from_slice(&bytes).expect("target");
        assert_eq!(target.as_bytes(), &bytes);

        let err = RevocationTarget::from_slice(&bytes[..REVOCATION_TARGET_LEN - 1])
            .expect_err("length error");
        assert_eq!(err.expected(), REVOCATION_TARGET_LEN);
        assert_eq!(err.actual(), REVOCATION_TARGET_LEN - 1);
    }

    #[test]
    fn revocation_record_activity_window() {
        let record = RevocationRecord {
            kind: RevocationKind::AuthRef,
            target: RevocationTarget::new([0x22; REVOCATION_TARGET_LEN]),
            reason: Some("compromised".into()),
            ts: 10_000,
            ttl: Some(300),
        };

        assert!(!record.is_active_at(9_999));
        assert!(record.is_active_at(10_000));
        assert!(record.is_active_at(10_299));
        assert!(!record.is_active_at(10_300));
        assert_eq!(record.expires_at(), Some(10_300));
    }

    #[test]
    fn revocation_record_unbounded_window() {
        let record = RevocationRecord {
            kind: RevocationKind::ClientId,
            target: RevocationTarget::new([0x33; REVOCATION_TARGET_LEN]),
            reason: None,
            ts: u64::MAX - 5,
            ttl: None,
        };

        assert!(record.is_active_at(u64::MAX - 5));
        assert!(record.is_active_at(u64::MAX));
        assert_eq!(record.expires_at(), None);
    }

    #[test]
    fn view_tracks_active_revocations() {
        let target = RevocationTarget::new([0x44; REVOCATION_TARGET_LEN]);
        let record = RevocationRecord {
            kind: RevocationKind::AuthRef,
            target,
            reason: None,
            ts: 5_000,
            ttl: Some(100),
        };

        let mut view = RevocationView::new();
        view.insert(record);

        assert!(view.is_revoked(RevocationKind::AuthRef, target, 5_050));
        assert!(!view.is_revoked(RevocationKind::AuthRef, target, 5_200));
    }

    #[test]
    fn view_purges_expired_records() {
        let target = RevocationTarget::new([0x55; REVOCATION_TARGET_LEN]);
        let mut view = RevocationView::new();
        view.insert(RevocationRecord {
            kind: RevocationKind::ClientId,
            target,
            reason: None,
            ts: 1_000,
            ttl: Some(50),
        });
        view.insert(RevocationRecord {
            kind: RevocationKind::ClientId,
            target,
            reason: None,
            ts: 1_200,
            ttl: Some(400),
        });

        view.purge_expired(1_300);

        assert_eq!(view.len(), 1);
        assert!(view.is_revoked(RevocationKind::ClientId, target, 1_225));
        assert!(!view.is_revoked(RevocationKind::ClientId, target, 1_650));
    }

    #[test]
    fn view_retains_future_records() {
        let target = RevocationTarget::new([0x66; REVOCATION_TARGET_LEN]);
        let mut view = RevocationView::new();
        view.insert(RevocationRecord {
            kind: RevocationKind::CapToken,
            target,
            reason: None,
            ts: 10_000,
            ttl: Some(100),
        });

        view.purge_expired(9_900);

        assert_eq!(view.len(), 1);
        assert!(!view.is_revoked(RevocationKind::CapToken, target, 9_950));
        assert!(view.is_revoked(RevocationKind::CapToken, target, 10_050));
    }
}
