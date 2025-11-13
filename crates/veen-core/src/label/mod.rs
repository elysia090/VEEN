use std::fmt;

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ht;

/// Length in bytes of a VEEN stream identifier.
pub const STREAM_ID_LEN: usize = 32;

/// Strongly typed wrapper around the 32-byte stream identifier used when
/// deriving labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

impl Serialize for StreamId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct StreamIdVisitor;

impl<'de> Visitor<'de> for StreamIdVisitor {
    type Value = StreamId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a {STREAM_ID_LEN}-byte VEEN stream identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        if v.len() != STREAM_ID_LEN {
            return Err(E::invalid_length(v.len(), &self));
        }
        let mut bytes = [0u8; STREAM_ID_LEN];
        bytes.copy_from_slice(v);
        Ok(StreamId::new(bytes))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for StreamId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(StreamIdVisitor)
    }
}

/// Result of the `label = Ht("veen/label", routing_key || stream_id ||
/// u64be(epoch))` derivation described in the specification.
pub const LABEL_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Label([u8; LABEL_LEN]);

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
    pub const fn as_bytes(&self) -> &[u8; LABEL_LEN] {
        &self.0
    }
}

impl From<[u8; LABEL_LEN]> for Label {
    fn from(value: [u8; LABEL_LEN]) -> Self {
        Self(value)
    }
}

impl From<&[u8; LABEL_LEN]> for Label {
    fn from(value: &[u8; LABEL_LEN]) -> Self {
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

impl Serialize for Label {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct LabelVisitor;

impl<'de> Visitor<'de> for LabelVisitor {
    type Value = Label;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a {LABEL_LEN}-byte VEEN label")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        if v.len() != LABEL_LEN {
            return Err(E::invalid_length(v.len(), &self));
        }
        let mut bytes = [0u8; LABEL_LEN];
        bytes.copy_from_slice(v);
        Ok(Label(bytes))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for Label {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(LabelVisitor)
    }
}

#[cfg(test)]
mod tests;
