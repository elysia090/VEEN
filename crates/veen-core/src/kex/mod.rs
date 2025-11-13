use std::collections::HashMap;

use thiserror::Error;

use crate::{label::Label, wire::types::ClientId};

/// Configuration describing the KEX1+ client usage bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientUsageConfig {
    /// Maximum lifetime in seconds for a `client_id` before rotation is required.
    pub max_client_id_lifetime_sec: u64,
    /// Maximum number of messages a `client_id` may send per label.
    pub max_msgs_per_label: u64,
}

impl ClientUsageConfig {
    /// Creates a new [`ClientUsageConfig`].
    #[must_use]
    pub const fn new(max_client_id_lifetime_sec: u64, max_msgs_per_label: u64) -> Self {
        Self {
            max_client_id_lifetime_sec,
            max_msgs_per_label,
        }
    }
}

/// Tracks the locally generated client usage required by KEX1+.
#[derive(Debug, Clone)]
pub struct ClientUsage {
    created_at: u64,
    sent_msgs_per_label: HashMap<Label, u64>,
}

impl ClientUsage {
    /// Creates a new usage tracker anchored at the provided creation timestamp.
    #[must_use]
    pub fn new(created_at: u64) -> Self {
        Self {
            created_at,
            sent_msgs_per_label: HashMap::new(),
        }
    }

    /// Returns the timestamp at which the current `client_id` was created.
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Returns the number of messages sent for the given label.
    #[must_use]
    pub fn sent_for_label(&self, label: &Label) -> u64 {
        self.sent_msgs_per_label.get(label).copied().unwrap_or(0)
    }

    /// Increments the message counter for `label`, returning the updated value.
    pub fn record_message(&mut self, label: Label) -> Result<u64, ClientUsageError> {
        let counter = self.sent_msgs_per_label.entry(label).or_insert(0);
        *counter = counter
            .checked_add(1)
            .ok_or(ClientUsageError::MessageCountOverflow { label })?;
        Ok(*counter)
    }

    /// Returns `true` if the client lifetime bound has been met or exceeded.
    #[must_use]
    pub fn lifetime_exceeded(&self, now: u64, config: ClientUsageConfig) -> bool {
        now
            .checked_sub(self.created_at)
            .is_some_and(|elapsed| elapsed >= config.max_client_id_lifetime_sec)
    }

    /// Returns `true` if any per-label counter has met or exceeded the bound.
    #[must_use]
    pub fn message_limit_exceeded(&self, config: ClientUsageConfig) -> bool {
        self.sent_msgs_per_label
            .values()
            .any(|&count| count >= config.max_msgs_per_label)
    }

    /// Returns `true` if rotation should occur due to lifetime or message count.
    #[must_use]
    pub fn should_rotate(&self, now: u64, config: ClientUsageConfig) -> bool {
        self.lifetime_exceeded(now, config) || self.message_limit_exceeded(config)
    }
}

/// Errors returned when recording client usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClientUsageError {
    /// The per-label message counter overflowed.
    #[error("message count overflow for label {label}")]
    MessageCountOverflow { label: Label },
}

#[derive(Debug, Clone)]
struct ObservedClient {
    first_seen: u64,
    counts: HashMap<Label, u64>,
}

impl ObservedClient {
    fn new(first_seen: u64) -> Self {
        Self {
            first_seen,
            counts: HashMap::new(),
        }
    }
}

/// Result describing whether KEX1+ bounds were exceeded for an observed client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservationDecision {
    lifetime_exceeded: bool,
    message_count_exceeded: bool,
}

impl ObservationDecision {
    /// Returns `true` if the lifetime bound has been exceeded.
    #[must_use]
    pub const fn lifetime_exceeded(self) -> bool {
        self.lifetime_exceeded
    }

    /// Returns `true` if the per-label message bound has been exceeded.
    #[must_use]
    pub const fn message_count_exceeded(self) -> bool {
        self.message_count_exceeded
    }

    /// Returns `true` if any bound violation occurred.
    #[must_use]
    pub const fn is_violation(self) -> bool {
        self.lifetime_exceeded || self.message_count_exceeded
    }
}

/// Errors returned when observing remote client usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ObservationError {
    /// The per-label message counter overflowed.
    #[error("message count overflow for client {client_id} on label {label}")]
    MessageCountOverflow { client_id: ClientId, label: Label },
}

/// Tracks remote client usage as recommended for hubs implementing KEX1+.
#[derive(Debug, Clone)]
pub struct ClientObservationIndex {
    config: ClientUsageConfig,
    clients: HashMap<ClientId, ObservedClient>,
}

impl ClientObservationIndex {
    /// Creates a new observation index using the provided bounds.
    #[must_use]
    pub fn new(config: ClientUsageConfig) -> Self {
        Self {
            config,
            clients: HashMap::new(),
        }
    }

    /// Removes all tracked client observations.
    pub fn clear(&mut self) {
        self.clients.clear();
    }

    /// Returns the number of tracked clients.
    #[must_use]
    pub fn len(&self) -> usize {
        self.clients.len()
    }

    /// Returns `true` if no clients are currently tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// Observes a message from `client_id` for `label` at time `now` and
    /// evaluates it against the configured bounds.
    pub fn observe(
        &mut self,
        client_id: ClientId,
        label: Label,
        now: u64,
    ) -> Result<ObservationDecision, ObservationError> {
        let entry = self
            .clients
            .entry(client_id)
            .or_insert_with(|| ObservedClient::new(now));

        let count = entry.counts.entry(label).or_insert(0);
        *count = count
            .checked_add(1)
            .ok_or(ObservationError::MessageCountOverflow { client_id, label })?;

        let lifetime_exceeded = now
            .checked_sub(entry.first_seen)
            .is_some_and(|elapsed| elapsed >= self.config.max_client_id_lifetime_sec);

        let message_count_exceeded = *count >= self.config.max_msgs_per_label;

        Ok(ObservationDecision {
            lifetime_exceeded,
            message_count_exceeded,
        })
    }
}

/// Returns the exclusive expiry timestamp for a capability token if it fits in `u64`.
#[must_use]
pub fn cap_token_expiry(issued_at: u64, ttl: u64) -> Option<u64> {
    issued_at.checked_add(ttl)
}

/// Returns `true` if a capability token with `issued_at` and `ttl` is valid at `now`.
#[must_use]
pub fn cap_token_is_valid(now: u64, issued_at: u64, ttl: u64) -> bool {
    if now < issued_at {
        return false;
    }

    match cap_token_expiry(issued_at, ttl) {
        Some(expiry) => now < expiry,
        None => true,
    }
}

/// Returns `true` if a capability token with optional `ttl` is valid at `now`.
#[must_use]
pub fn cap_token_is_valid_opt(now: u64, issued_at: u64, ttl: Option<u64>) -> bool {
    if now < issued_at {
        return false;
    }

    match ttl {
        Some(ttl) => cap_token_is_valid(now, issued_at, ttl),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(byte: u8) -> Label {
        Label::from([byte; 32])
    }

    #[test]
    fn client_usage_rotation_by_lifetime() {
        let config = ClientUsageConfig::new(3_600, 10);
        let usage = ClientUsage::new(1_000);
        assert!(!usage.lifetime_exceeded(4_500, config));
        assert!(usage.lifetime_exceeded(4_600, config));
    }

    #[test]
    fn client_usage_rotation_by_count() {
        let config = ClientUsageConfig::new(3_600, 3);
        let mut usage = ClientUsage::new(1_000);
        let lbl = label(0x11);
        usage.record_message(lbl).unwrap();
        assert!(!usage.message_limit_exceeded(config));
        usage.record_message(lbl).unwrap();
        assert!(!usage.message_limit_exceeded(config));
        usage.record_message(lbl).unwrap();
        assert!(usage.message_limit_exceeded(config));
        assert!(usage.should_rotate(1_100, config));
    }

    #[test]
    fn client_usage_overflow_is_error() {
        let mut usage = ClientUsage::new(1_000);
        let lbl = label(0x22);
        usage.sent_msgs_per_label.insert(lbl, u64::MAX);
        let err = usage.record_message(lbl).expect_err("overflow");
        match err {
            ClientUsageError::MessageCountOverflow { label: overflowed } => {
                assert_eq!(overflowed, lbl);
            }
        }
    }

    #[test]
    fn observation_detects_message_bound() {
        let config = ClientUsageConfig::new(10, 2);
        let mut index = ClientObservationIndex::new(config);
        let client = ClientId::new([0xAA; 32]);
        let lbl = label(0x33);

        let first = index.observe(client, lbl, 100).unwrap();
        assert!(!first.is_violation());

        let second = index.observe(client, lbl, 101).unwrap();
        assert!(second.message_count_exceeded());
        assert!(second.is_violation());
    }

    #[test]
    fn observation_detects_lifetime_bound() {
        let config = ClientUsageConfig::new(10, 5);
        let mut index = ClientObservationIndex::new(config);
        let client = ClientId::new([0xBB; 32]);
        let lbl = label(0x44);

        index.observe(client, lbl, 1_000).unwrap();
        let before_boundary = index.observe(client, lbl, 1_009).unwrap();
        assert!(!before_boundary.lifetime_exceeded());
        assert!(!before_boundary.is_violation());

        let at_boundary = index.observe(client, lbl, 1_010).unwrap();
        assert!(at_boundary.lifetime_exceeded());
        assert!(at_boundary.is_violation());

        let after_boundary = index.observe(client, lbl, 1_011).unwrap();
        assert!(after_boundary.lifetime_exceeded());
        assert!(after_boundary.is_violation());
    }

    #[test]
    fn observation_overflow_is_error() {
        let config = ClientUsageConfig::new(10, u64::MAX);
        let mut index = ClientObservationIndex::new(config);
        let client = ClientId::new([0xCC; 32]);
        let lbl = label(0x55);

        index.observe(client, lbl, 5).unwrap();
        if let Some(entry) = index.clients.get_mut(&client) {
            entry.counts.insert(lbl, u64::MAX);
        }

        let err = index.observe(client, lbl, 6).expect_err("overflow");
        match err {
            ObservationError::MessageCountOverflow { client_id, label } => {
                assert_eq!(client_id, client);
                assert_eq!(label, lbl);
            }
        }
    }

    #[test]
    fn cap_token_expiry_and_validation() {
        let issued_at = 1_000;
        let ttl = 600;
        let expiry = cap_token_expiry(issued_at, ttl).expect("expiry");
        assert_eq!(expiry, 1_600);
        assert!(!cap_token_is_valid(999, issued_at, ttl));
        assert!(!cap_token_is_valid(1_600, issued_at, ttl));
        assert!(!cap_token_is_valid(1_601, issued_at, ttl));
    }

    #[test]
    fn cap_token_validation_handles_overflow() {
        let issued_at = u64::MAX - 10;
        let ttl = 20;
        assert!(cap_token_expiry(issued_at, ttl).is_none());
        assert!(cap_token_is_valid(u64::MAX, issued_at, ttl));
    }

    #[test]
    fn cap_token_optional_ttl() {
        assert!(cap_token_is_valid_opt(1_000, 500, None));
        assert!(!cap_token_is_valid_opt(499, 500, None));
        assert!(!cap_token_is_valid_opt(2_000, 500, Some(1_000)));
    }
}
