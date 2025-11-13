use serde::{Deserialize, Serialize};

use crate::{h, hub::HubId, label::StreamId, realm::RealmId};

/// Returns the schema identifier for `veen.fed.authority.v1`.
#[must_use]
pub fn schema_fed_authority() -> [u8; 32] {
    h(b"veen.fed.authority.v1")
}

/// Policy describing how authority for a stream is delegated within a federation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityPolicy {
    /// Single primary hub is authoritative; replicas are read-only.
    SinglePrimary,
    /// Multiple hubs are permitted to accept writes for the stream.
    MultiPrimary,
}

/// Federated authority record as defined by FED1 in the specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRecord {
    pub realm_id: RealmId,
    pub stream_id: StreamId,
    pub primary_hub: HubId,
    pub replica_hubs: Vec<HubId>,
    pub policy: AuthorityPolicy,
    pub ts: u64,
    pub ttl: u64,
}

impl AuthorityRecord {
    /// Returns `true` if the authority record is active at the provided Unix timestamp.
    #[must_use]
    pub fn is_active_at(&self, time: u64) -> bool {
        if time < self.ts {
            return false;
        }
        match self.ts.checked_add(self.ttl) {
            Some(expiry) => time < expiry,
            None => true,
        }
    }

    /// Returns the exclusive expiry timestamp if the record has a bounded lifetime.
    #[must_use]
    pub fn expires_at(&self) -> Option<u64> {
        self.ts.checked_add(self.ttl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_matches_expected_digest() {
        assert_eq!(
            schema_fed_authority(),
            [
                0x90, 0xbe, 0x86, 0xc2, 0xcb, 0xef, 0x28, 0x46, 0x73, 0x87, 0xb4, 0xc2, 0x2a, 0x6b,
                0x11, 0x85, 0xde, 0x7a, 0x2f, 0x57, 0x02, 0x8c, 0xb4, 0xf1, 0x25, 0xef, 0x01, 0xd4,
                0x1c, 0x63, 0x2c, 0x29,
            ]
        );
    }

    #[test]
    fn authority_record_activity_window() {
        let realm = RealmId::derive("example");
        let stream = realm.stream_fed_admin();
        let primary = HubId::new([0x11; 32]);
        let replicas = vec![HubId::new([0x22; 32])];
        let record = AuthorityRecord {
            realm_id: realm,
            stream_id: stream,
            primary_hub: primary,
            replica_hubs: replicas,
            policy: AuthorityPolicy::SinglePrimary,
            ts: 1_000,
            ttl: 600,
        };

        assert!(!record.is_active_at(999));
        assert!(record.is_active_at(1_000));
        assert!(record.is_active_at(1_599));
        assert!(!record.is_active_at(1_600));
        assert_eq!(record.expires_at(), Some(1_600));
    }

    #[test]
    fn authority_record_handles_overflow() {
        let record = AuthorityRecord {
            realm_id: RealmId::derive("overflow"),
            stream_id: StreamId::new([0; 32]),
            primary_hub: HubId::new([0; 32]),
            replica_hubs: Vec::new(),
            policy: AuthorityPolicy::MultiPrimary,
            ts: u64::MAX - 10,
            ttl: 100,
        };

        assert!(record.is_active_at(u64::MAX));
        assert_eq!(record.expires_at(), None);
    }
}
