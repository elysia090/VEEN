use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ht;

/// Length in bytes of a VEEN stream identifier.
pub const STREAM_ID_LEN: usize = 32;

/// Strongly typed wrapper around the 32-byte stream identifier used when
/// deriving labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StreamId([u8; STREAM_ID_LEN]);

impl StreamId {
    /// Creates a stream identifier from the provided 32-byte array.
    #[must_use]
    pub const fn new(bytes: [u8; STREAM_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; STREAM_ID_LEN] {
        &self.0
    }
}

impl From<[u8; STREAM_ID_LEN]> for StreamId {
    fn from(value: [u8; STREAM_ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; STREAM_ID_LEN]> for StreamId {
    fn from(value: &[u8; STREAM_ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl AsRef<[u8]> for StreamId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Result of the `label = Ht("veen/label", routing_key || stream_id ||
/// u64be(epoch))` derivation described in the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Label([u8; 32]);

impl Label {
    /// Computes the canonical label for a given routing key, stream identifier,
    /// and epoch.
    #[must_use]
    pub fn derive(routing_key: impl AsRef<[u8]>, stream_id: StreamId, epoch: u64) -> Self {
        let routing_key = routing_key.as_ref();
        let mut data = Vec::with_capacity(routing_key.len() + STREAM_ID_LEN + 8);
        data.extend_from_slice(routing_key);
        data.extend_from_slice(stream_id.as_ref());
        data.extend_from_slice(&epoch.to_be_bytes());
        Self(ht("veen/label", &data))
    }

    /// Borrows the label bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Label {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<&[u8; 32]> for Label {
    fn from(value: &[u8; 32]) -> Self {
        Self(*value)
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
