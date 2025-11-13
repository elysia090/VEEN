use sha2::{Digest, Sha256};

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
    digest
        .as_slice()
        .try_into()
        .expect("digest should be 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::ht;

    #[test]
    fn ht_matches_known_vector() {
        let digest = ht("veen/profile", b"hello world");
        let expected = [
            0x01, 0xa5, 0x69, 0xeb, 0xb6, 0x9d, 0xdd, 0x4d, 0x66, 0xe6, 0x48, 0xa0, 0xfb, 0xe6,
            0x24, 0x7a, 0x36, 0xb2, 0x7f, 0x1d, 0x08, 0xe1, 0x8d, 0x08, 0xff, 0x7b, 0x3b, 0xac,
            0x14, 0x86, 0x94, 0x83,
        ];
        assert_eq!(digest, expected);
    }
}
