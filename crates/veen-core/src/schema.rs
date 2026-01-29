use std::{convert::TryFrom, fmt};

use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::LengthError;

/// Length in bytes of schema identifiers and owner keys.
pub const SCHEMA_ID_LEN: usize = 32;

fn copy_schema_bytes(bytes: &[u8]) -> Result<[u8; SCHEMA_ID_LEN], LengthError> {
    if bytes.len() != SCHEMA_ID_LEN {
        return Err(LengthError::new(SCHEMA_ID_LEN, bytes.len()));
    }

    let mut out = [0u8; SCHEMA_ID_LEN];
    out.copy_from_slice(bytes);
    Ok(out)
}

macro_rules! impl_schema_value {
    ($ty:ident, $visitor:ident, $expecting:literal) => {
        impl $ty {
            #[doc = concat!(
                "Attempts to construct a [`",
                stringify!($ty),
                "`] from an arbitrary slice enforcing the exact length from the specification."
            )]
            pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
                copy_schema_bytes(bytes).map(Self::new)
            }
        }

        impl From<[u8; SCHEMA_ID_LEN]> for $ty {
            fn from(value: [u8; SCHEMA_ID_LEN]) -> Self {
                Self::new(value)
            }
        }

        impl From<&[u8; SCHEMA_ID_LEN]> for $ty {
            fn from(value: &[u8; SCHEMA_ID_LEN]) -> Self {
                Self::new(*value)
            }
        }

        impl TryFrom<&[u8]> for $ty {
            type Error = LengthError;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                Self::from_slice(value)
            }
        }

        impl TryFrom<Vec<u8>> for $ty {
            type Error = LengthError;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                Self::from_slice(&value)
            }
        }

        impl AsRef<[u8]> for $ty {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        impl Serialize for $ty {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(self.as_ref())
            }
        }

        struct $visitor;

        impl<'de> Visitor<'de> for $visitor {
            type Value = $ty;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str($expecting)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                $ty::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
            }

            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                self.visit_bytes(&v)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut buf = Vec::with_capacity(SCHEMA_ID_LEN);
                while let Some(byte) = seq.next_element::<u8>()? {
                    buf.push(byte);
                }
                $ty::try_from(buf).map_err(|err| A::Error::invalid_length(err.actual(), &self))
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_bytes($visitor)
            }
        }
    };
}

/// Strongly typed wrapper for schema identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaId([u8; SCHEMA_ID_LEN]);

impl SchemaId {
    /// Creates a new [`SchemaId`] from the provided byte array.
    #[must_use]
    pub const fn new(bytes: [u8; SCHEMA_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SCHEMA_ID_LEN] {
        &self.0
    }
}

crate::impl_hex_fmt!(SchemaId);

crate::impl_fixed_hex_from_str!(SchemaId, SCHEMA_ID_LEN);

/// Wrapper for optional owner public keys carried by schema descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SchemaOwner([u8; SCHEMA_ID_LEN]);

impl SchemaOwner {
    /// Creates a new [`SchemaOwner`] from the provided byte array.
    #[must_use]
    pub const fn new(bytes: [u8; SCHEMA_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SCHEMA_ID_LEN] {
        &self.0
    }
}

crate::impl_hex_fmt!(SchemaOwner);

crate::impl_fixed_hex_from_str!(SchemaOwner, SCHEMA_ID_LEN);

impl_schema_value!(SchemaId, SchemaIdVisitor, "a 32-byte schema identifier");

impl_schema_value!(
    SchemaOwner,
    SchemaOwnerVisitor,
    "a 32-byte schema owner key"
);
