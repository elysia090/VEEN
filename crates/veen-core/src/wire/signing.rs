use std::io;

use serde::Serialize;

use super::derivation::hash_tagged;

pub type CborError = ciborium::ser::Error<io::Error>;

pub(crate) trait WireSignable {
    type Signable<'a>: Serialize
    where
        Self: 'a;

    fn signable(&self) -> Self::Signable<'_>;

    fn signing_bytes(&self) -> Result<Vec<u8>, CborError> {
        serialize_signable(&self.signable())
    }

    fn signing_tagged_hash(&self, tag: &str) -> Result<[u8; 32], CborError> {
        tagged_hash(tag, &self.signable())
    }
}

pub(crate) fn serialize_signable<T: Serialize>(value: &T) -> Result<Vec<u8>, CborError> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)?;
    Ok(buf)
}

pub(crate) fn tagged_hash<T: Serialize>(tag: &str, value: &T) -> Result<[u8; 32], CborError> {
    let bytes = serialize_signable(value)?;
    Ok(hash_tagged(tag, &bytes))
}
