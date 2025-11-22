use std::io;

use serde::Serialize;

use crate::hash::ht;

pub type CborError = ciborium::ser::Error<io::Error>;

pub(crate) fn serialize_signable<T: Serialize>(value: &T) -> Result<Vec<u8>, CborError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)?;
    Ok(buf)
}

pub(crate) fn tagged_hash<T: Serialize>(tag: &str, value: &T) -> Result<[u8; 32], CborError> {
    let bytes = serialize_signable(value)?;
    Ok(ht(tag, &bytes))
}
