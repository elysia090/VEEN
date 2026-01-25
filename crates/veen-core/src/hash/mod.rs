use sha2::{Digest, Sha256};

/// Computes the plain SHA-256 digest `H(x)` used throughout the overlay
/// specifications for schema identifiers.
#[must_use]
pub fn h(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

/// Computes the domain separated hash `Ht(tag, data)` defined in the VEEN
/// specification.
///
/// The hash is SHA-256 over the ASCII tag, followed by a zero byte, followed by
/// the binary payload.
#[must_use]
pub fn ht(tag: &str, data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update([0u8]);
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

/// Computes the domain separated hash `Ht(tag, parts...)` without allocating a
/// contiguous buffer for the concatenated payload.
#[must_use]
pub fn ht_parts<'a, I>(tag: &str, parts: I) -> [u8; 32]
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let mut hasher = Sha256::new();
    hasher.update(tag.as_bytes());
    hasher.update([0u8]);
    for part in parts {
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

#[cfg(test)]
mod tests;
