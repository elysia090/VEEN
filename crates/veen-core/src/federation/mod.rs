use std::{cmp::Ordering, collections::HashMap};

use serde::{Deserialize, Serialize};

use crate::{
    h,
    hub::HubId,
    label::{Label, StreamId},
    realm::RealmId,
};

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

fn record_precedence(a: &AuthorityRecord, b: &AuthorityRecord) -> Ordering {
    a.ts.cmp(&b.ts)
        .then_with(|| a.primary_hub.as_bytes().cmp(b.primary_hub.as_bytes()))
}

type AuthorityKey = (RealmId, StreamId);

/// In-memory materialization of FED1 authority records keyed by
/// `(realm_id, stream_id)` as described in spec-2 section 2.4.
#[derive(Debug, Clone, Default)]
pub struct AuthorityView {
    records: HashMap<AuthorityKey, Vec<AuthorityRecord>>,
}

impl AuthorityView {
    /// Creates an empty view.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears all stored authority records.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// Returns the number of tracked `(realm_id, stream_id)` entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if the view contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Inserts an authority record into the view. Multiple records for the same
    /// key are retained so that active selection can apply the precedence rule
    /// from spec-2 section 2.2.
    pub fn insert(&mut self, record: AuthorityRecord) {
        let key = (record.realm_id, record.stream_id);
        self.records.entry(key).or_default().push(record);
    }

    /// Extends the view with a sequence of authority records.
    pub fn extend<I>(&mut self, records: I)
    where
        I: IntoIterator<Item = AuthorityRecord>,
    {
        for record in records {
            self.insert(record);
        }
    }

    /// Removes records that have definitively expired as of `time`. Records
    /// with a future activation timestamp are preserved.
    pub fn purge_expired(&mut self, time: u64) {
        self.records.retain(|_, entries| {
            entries.retain(|record| record.is_active_at(time) || record.ts > time);
            !entries.is_empty()
        });
    }

    /// Returns the highest precedence active record for `(realm_id, stream_id)`
    /// at the provided Unix timestamp.
    #[must_use]
    pub fn active_record_at(
        &self,
        realm_id: RealmId,
        stream_id: StreamId,
        time: u64,
    ) -> Option<&AuthorityRecord> {
        self.records
            .get(&(realm_id, stream_id))
            .and_then(|records| {
                records
                    .iter()
                    .filter(|record| record.is_active_at(time))
                    .min_by(|a, b| record_precedence(*a, *b))
            })
    }

    /// Computes the [`LabelAuthority`] for a stream with an optional realm.
    #[must_use]
    pub fn label_authority(
        &self,
        stream_id: StreamId,
        realm_id: Option<RealmId>,
        time: u64,
    ) -> LabelAuthority {
        match realm_id.and_then(|realm| self.active_record_at(realm, stream_id, time)) {
            Some(record) => LabelAuthority {
                realm_id,
                stream_id,
                primary_hub: Some(record.primary_hub),
                replica_hubs: record.replica_hubs.clone(),
                policy: LabelPolicy::from(record.policy),
            },
            None => LabelAuthority {
                realm_id,
                stream_id,
                primary_hub: None,
                replica_hubs: Vec::new(),
                policy: LabelPolicy::Unspecified,
            },
        }
    }

    /// Computes the [`LabelAuthority`] for a label using deployment-defined
    /// mapping functions.
    #[must_use]
    pub fn label_authority_for_label<F, G>(
        &self,
        label: &Label,
        stream_id_for_label: F,
        realm_id_for_label: G,
        time: u64,
    ) -> LabelAuthority
    where
        F: Fn(&Label) -> StreamId,
        G: Fn(&Label) -> Option<RealmId>,
    {
        let stream_id = stream_id_for_label(label);
        let realm_id = realm_id_for_label(label);
        self.label_authority(stream_id, realm_id, time)
    }
}

/// Policy classification returned by [`LabelAuthority`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelPolicy {
    /// The label is governed by a single primary hub.
    SinglePrimary,
    /// Multiple hubs are allowed to accept writes for the label.
    MultiPrimary,
    /// No explicit authority information is available.
    Unspecified,
}

impl From<AuthorityPolicy> for LabelPolicy {
    fn from(value: AuthorityPolicy) -> Self {
        match value {
            AuthorityPolicy::SinglePrimary => LabelPolicy::SinglePrimary,
            AuthorityPolicy::MultiPrimary => LabelPolicy::MultiPrimary,
        }
    }
}

/// Derived view for a specific label in AUTH1 section 3.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelAuthority {
    pub realm_id: Option<RealmId>,
    pub stream_id: StreamId,
    pub primary_hub: Option<HubId>,
    pub replica_hubs: Vec<HubId>,
    pub policy: LabelPolicy,
}

impl LabelAuthority {
    /// Returns `true` if the provided hub is permitted to accept messages under
    /// this label according to AUTH1 section 3.3.
    #[must_use]
    pub fn allows_hub(&self, hub_id: HubId) -> bool {
        match self.policy {
            LabelPolicy::SinglePrimary => self.primary_hub == Some(hub_id),
            LabelPolicy::MultiPrimary => {
                self.primary_hub == Some(hub_id)
                    || self
                        .replica_hubs
                        .iter()
                        .copied()
                        .any(|replica| replica == hub_id)
            }
            LabelPolicy::Unspecified => true,
        }
    }

    /// Returns `true` if the label has no explicit authority information.
    #[must_use]
    pub fn is_unspecified(&self) -> bool {
        matches!(self.policy, LabelPolicy::Unspecified)
    }

    /// Returns `true` if the label enforces single-primary semantics.
    #[must_use]
    pub fn is_single_primary(&self) -> bool {
        matches!(self.policy, LabelPolicy::SinglePrimary)
    }

    /// Returns `true` if the label is configured for multi-primary operation.
    #[must_use]
    pub fn is_multi_primary(&self) -> bool {
        matches!(self.policy, LabelPolicy::MultiPrimary)
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

    #[test]
    fn authority_view_selects_highest_precedence_active_record() {
        let realm = RealmId::derive("realm");
        let stream = realm.stream_fed_admin();
        let primary_a = HubId::new([0x11; 32]);
        let primary_b = HubId::new([0x22; 32]);
        let mut view = AuthorityView::new();

        view.insert(AuthorityRecord {
            realm_id: realm,
            stream_id: stream,
            primary_hub: primary_b,
            replica_hubs: Vec::new(),
            policy: AuthorityPolicy::SinglePrimary,
            ts: 2_000,
            ttl: 1_000,
        });
        view.insert(AuthorityRecord {
            realm_id: realm,
            stream_id: stream,
            primary_hub: primary_a,
            replica_hubs: Vec::new(),
            policy: AuthorityPolicy::MultiPrimary,
            ts: 1_500,
            ttl: 1_000,
        });

        let active = view
            .active_record_at(realm, stream, 2_100)
            .expect("active record");
        assert_eq!(active.primary_hub, primary_a);
        assert_eq!(active.policy, AuthorityPolicy::MultiPrimary);
    }

    #[test]
    fn authority_view_applies_primary_tie_breaker() {
        let realm = RealmId::derive("realm-tie");
        let stream = realm.stream_fed_admin();
        let mut view = AuthorityView::new();

        view.insert(AuthorityRecord {
            realm_id: realm,
            stream_id: stream,
            primary_hub: HubId::new([0x55; 32]),
            replica_hubs: Vec::new(),
            policy: AuthorityPolicy::SinglePrimary,
            ts: 4_000,
            ttl: 1_000,
        });
        view.insert(AuthorityRecord {
            realm_id: realm,
            stream_id: stream,
            primary_hub: HubId::new([0x11; 32]),
            replica_hubs: Vec::new(),
            policy: AuthorityPolicy::SinglePrimary,
            ts: 4_000,
            ttl: 1_000,
        });

        let active = view
            .active_record_at(realm, stream, 4_100)
            .expect("active record");
        assert_eq!(active.primary_hub, HubId::new([0x11; 32]));
    }

    #[test]
    fn label_authority_defaults_to_unspecified() {
        let stream = StreamId::new([0xAA; 32]);
        let label = Label::derive([], stream, 0);
        let view = AuthorityView::new();

        let authority = view.label_authority_for_label(&label, |_label| stream, |_label| None, 1);

        assert!(authority.is_unspecified());
        assert_eq!(authority.primary_hub, None);
        assert!(authority.replica_hubs.is_empty());
    }

    #[test]
    fn label_authority_resolves_single_primary() {
        let realm = RealmId::derive("realm-authority");
        let stream = realm.stream_fed_admin();
        let label = Label::derive([], stream, 0);
        let mut view = AuthorityView::new();
        let primary = HubId::new([0x33; 32]);

        view.insert(AuthorityRecord {
            realm_id: realm,
            stream_id: stream,
            primary_hub: primary,
            replica_hubs: vec![HubId::new([0x44; 32])],
            policy: AuthorityPolicy::SinglePrimary,
            ts: 100,
            ttl: 600,
        });

        let authority =
            view.label_authority_for_label(&label, |_label| stream, |_label| Some(realm), 200);

        assert!(authority.is_single_primary());
        assert_eq!(authority.primary_hub, Some(primary));
        assert_eq!(authority.replica_hubs.len(), 1);
        assert!(authority.allows_hub(primary));
        assert!(!authority.allows_hub(HubId::new([0x44; 32])));
    }

    #[test]
    fn label_authority_allows_listed_multi_primary_hubs() {
        let realm = RealmId::derive("realm-multi");
        let stream = realm.stream_fed_admin();
        let label = Label::derive([], stream, 0);
        let mut view = AuthorityView::new();
        let primary = HubId::new([0x10; 32]);
        let replica = HubId::new([0x20; 32]);

        view.insert(AuthorityRecord {
            realm_id: realm,
            stream_id: stream,
            primary_hub: primary,
            replica_hubs: vec![replica],
            policy: AuthorityPolicy::MultiPrimary,
            ts: 1_000,
            ttl: 1_000,
        });

        let authority =
            view.label_authority_for_label(&label, |_label| stream, |_label| Some(realm), 1_200);

        assert!(authority.is_multi_primary());
        assert!(authority.allows_hub(primary));
        assert!(authority.allows_hub(replica));
        assert!(!authority.allows_hub(HubId::new([0x30; 32])));
    }

    #[test]
    fn purge_expired_removes_old_records() {
        let realm = RealmId::derive("realm-prune");
        let stream = realm.stream_fed_admin();
        let mut view = AuthorityView::new();

        view.insert(AuthorityRecord {
            realm_id: realm,
            stream_id: stream,
            primary_hub: HubId::new([0x55; 32]),
            replica_hubs: Vec::new(),
            policy: AuthorityPolicy::SinglePrimary,
            ts: 10,
            ttl: 5,
        });
        view.insert(AuthorityRecord {
            realm_id: realm,
            stream_id: stream,
            primary_hub: HubId::new([0x66; 32]),
            replica_hubs: Vec::new(),
            policy: AuthorityPolicy::SinglePrimary,
            ts: 100,
            ttl: 5,
        });

        view.purge_expired(20);
        assert_eq!(view.len(), 1);
        let active = view.active_record_at(realm, stream, 104).expect("active");
        assert_eq!(active.primary_hub, HubId::new([0x66; 32]));
    }
}
