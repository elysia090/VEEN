use serde::{Deserialize, Serialize};

use crate::ht;

/// Returns the schema identifier for `veen.pow.cookie.v1`.
#[must_use]
pub fn schema_pow_cookie() -> [u8; 32] {
    crate::h(b"veen.pow.cookie.v1")
}

/// Proof-of-work cookie used as an optional admission prefilter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowCookie {
    pub challenge: Vec<u8>,
    pub nonce: u64,
    pub difficulty: u8,
}

impl PowCookie {
    /// Computes the domain-separated hash `Ht("veen/pow", challenge || u64be(nonce))`.
    #[must_use]
    pub fn value(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(self.challenge.len() + std::mem::size_of::<u64>());
        data.extend_from_slice(&self.challenge);
        data.extend_from_slice(&self.nonce.to_be_bytes());
        ht("veen/pow", &data)
    }

    /// Returns `true` if the cookie satisfies its advertised difficulty.
    #[must_use]
    pub fn meets_difficulty(&self) -> bool {
        satisfies_difficulty(&self.value(), self.difficulty)
    }
}

fn satisfies_difficulty(value: &[u8; 32], difficulty: u8) -> bool {
    if difficulty == 0 {
        return true;
    }

    let full_bytes = (difficulty / 8) as usize;
    let remaining_bits = difficulty % 8;

    if value.iter().take(full_bytes).any(|&byte| byte != 0) {
        return false;
    }

    if remaining_bits == 0 {
        return true;
    }

    if full_bytes >= value.len() {
        return false;
    }

    let mask = 0xFFu8 << (8 - remaining_bits);
    value[full_bytes] & mask == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_matches_expected_digest() {
        assert_eq!(
            schema_pow_cookie(),
            [
                0xc5, 0xd6, 0xfb, 0x71, 0x09, 0xe8, 0x73, 0x96, 0x88, 0x2d, 0x0d, 0x89, 0x1f, 0x3e,
                0xb6, 0xa8, 0x2c, 0x31, 0x97, 0x39, 0x13, 0xd8, 0xf8, 0x89, 0xe2, 0x33, 0xfc, 0xbb,
                0xeb, 0xd3, 0xda, 0xc7,
            ]
        );
    }

    #[test]
    fn meets_difficulty_checks_leading_zero_bits() {
        let challenge = b"spec-pow-test".to_vec();
        let cookie = PowCookie {
            challenge: challenge.clone(),
            nonce: 951,
            difficulty: 12,
        };
        assert!(cookie.meets_difficulty());

        let mut failing = cookie.clone();
        failing.nonce += 1;
        assert!(!failing.meets_difficulty());
    }

    #[test]
    fn zero_difficulty_always_valid() {
        let cookie = PowCookie {
            challenge: vec![0xAA; 8],
            nonce: 0,
            difficulty: 0,
        };
        assert!(cookie.meets_difficulty());
    }
}
