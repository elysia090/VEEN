use std::{convert::TryFrom, fmt};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ht, LengthError};

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

    /// Attempts to construct a [`StreamId`] from an arbitrary byte slice,
    /// enforcing the exact length required by the specification.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != STREAM_ID_LEN {
            return Err(LengthError::new(STREAM_ID_LEN, bytes.len()));
        }
        let mut out = [0u8; STREAM_ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
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

impl TryFrom<&[u8]> for StreamId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for StreamId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for StreamId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

crate::impl_hex_fmt!(StreamId);

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
        StreamId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
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

crate::impl_fixed_hex_from_str!(StreamId, STREAM_ID_LEN);

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

    /// Attempts to construct a [`Label`] from an arbitrary byte slice,
    /// enforcing the exact length defined by the specification.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != LABEL_LEN {
            return Err(LengthError::new(LABEL_LEN, bytes.len()));
        }
        let mut out = [0u8; LABEL_LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
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

impl TryFrom<&[u8]> for Label {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for Label {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

crate::impl_hex_fmt!(Label);

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
        Label::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
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

crate::impl_fixed_hex_from_str!(Label, LABEL_LEN);

#[cfg(test)]
mod tests;
