use std::convert::TryFrom;

use thiserror::Error;

/// Length in bytes of the HPKE encapsulated key prefix.
pub const HPKE_ENC_LEN: usize = 32;

/// Length in bytes of the ciphertext length prefix (two u32 lengths).
pub const CIPHERTEXT_LEN_PREFIX: usize = 8;

/// Parsed view of a VEEN ciphertext envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CiphertextEnvelope<'a> {
    pub enc: [u8; HPKE_ENC_LEN],
    pub hdr_len: u32,
    pub body_len: u32,
    pub hpke_ct_hdr: &'a [u8],
    pub aead_ct_body: &'a [u8],
    pub padding: &'a [u8],
}

/// Errors returned when parsing ciphertext envelopes.
#[derive(Debug, Error)]
pub enum CiphertextParseError {
    #[error("ciphertext is too short: expected at least {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },
    #[error("ciphertext length {length} exceeds limit {limit}")]
    CiphertextTooLarge { length: usize, limit: usize },
    #[error("ciphertext length overflow while computing envelope bounds")]
    LengthOverflow,
    #[error("payload header length {hdr_len} exceeds limit {limit}")]
    HeaderTooLarge { hdr_len: usize, limit: usize },
    #[error("payload body length {body_len} exceeds limit {limit}")]
    BodyTooLarge { body_len: usize, limit: usize },
    #[error("ciphertext contains non-zero padding byte at offset {offset}")]
    NonZeroPadding { offset: usize },
    #[error("ciphertext length is not aligned to pad_block {pad_block}")]
    PadBlockMismatch { pad_block: u64, length: usize },
}

impl<'a> CiphertextEnvelope<'a> {
    /// Parses a ciphertext envelope from raw bytes, enforcing the spec-required
    /// padding checks (rejecting non-zero padding bytes).
    pub fn parse(ciphertext: &'a [u8]) -> Result<Self, CiphertextParseError> {
        let base_len = HPKE_ENC_LEN + CIPHERTEXT_LEN_PREFIX;
        if ciphertext.len() < base_len {
            return Err(CiphertextParseError::Truncated {
                expected: base_len,
                actual: ciphertext.len(),
            });
        }

        let mut enc = [0u8; HPKE_ENC_LEN];
        enc.copy_from_slice(&ciphertext[..HPKE_ENC_LEN]);

        let hdr_len_bytes = &ciphertext[HPKE_ENC_LEN..HPKE_ENC_LEN + 4];
        let body_len_bytes = &ciphertext[HPKE_ENC_LEN + 4..HPKE_ENC_LEN + 8];
        let hdr_len =
            u32::from_be_bytes(<[u8; 4]>::try_from(hdr_len_bytes).expect("slice length validated"));
        let body_len = u32::from_be_bytes(
            <[u8; 4]>::try_from(body_len_bytes).expect("slice length validated"),
        );

        let hdr_len_usize =
            usize::try_from(hdr_len).map_err(|_| CiphertextParseError::LengthOverflow)?;
        let body_len_usize =
            usize::try_from(body_len).map_err(|_| CiphertextParseError::LengthOverflow)?;

        let hdr_start = base_len;
        let hdr_end = hdr_start
            .checked_add(hdr_len_usize)
            .ok_or(CiphertextParseError::LengthOverflow)?;
        let body_end = hdr_end
            .checked_add(body_len_usize)
            .ok_or(CiphertextParseError::LengthOverflow)?;

        if ciphertext.len() < body_end {
            return Err(CiphertextParseError::Truncated {
                expected: body_end,
                actual: ciphertext.len(),
            });
        }

        let hpke_ct_hdr = &ciphertext[hdr_start..hdr_end];
        let aead_ct_body = &ciphertext[hdr_end..body_end];
        let padding = &ciphertext[body_end..];

        if let Some((idx, _)) = padding.iter().enumerate().find(|(_, byte)| **byte != 0) {
            return Err(CiphertextParseError::NonZeroPadding {
                offset: body_end + idx,
            });
        }

        Ok(Self {
            enc,
            hdr_len,
            body_len,
            hpke_ct_hdr,
            aead_ct_body,
            padding,
        })
    }

    /// Parses a ciphertext envelope and enforces an additional pad block length
    /// check (useful when `pad_block` is configured in the profile).
    pub fn parse_with_pad_block(
        ciphertext: &'a [u8],
        pad_block: u64,
    ) -> Result<Self, CiphertextParseError> {
        let envelope = Self::parse(ciphertext)?;
        if pad_block > 0 {
            let pad_block_usize =
                usize::try_from(pad_block).map_err(|_| CiphertextParseError::LengthOverflow)?;
            if pad_block_usize == 0 || !ciphertext.len().is_multiple_of(pad_block_usize) {
                return Err(CiphertextParseError::PadBlockMismatch {
                    pad_block,
                    length: ciphertext.len(),
                });
            }
        }
        Ok(envelope)
    }

    /// Parses a ciphertext envelope and enforces spec-defined size limits
    /// before any decryption occurs.
    pub fn parse_with_limits(
        ciphertext: &'a [u8],
        pad_block: u64,
        max_msg_bytes: usize,
        max_hdr_bytes: usize,
        max_body_bytes: usize,
    ) -> Result<Self, CiphertextParseError> {
        if ciphertext.len() > max_msg_bytes {
            return Err(CiphertextParseError::CiphertextTooLarge {
                length: ciphertext.len(),
                limit: max_msg_bytes,
            });
        }

        let envelope = Self::parse(ciphertext)?;
        if usize::try_from(envelope.hdr_len).map_err(|_| CiphertextParseError::LengthOverflow)?
            > max_hdr_bytes
        {
            return Err(CiphertextParseError::HeaderTooLarge {
                hdr_len: envelope.hdr_len as usize,
                limit: max_hdr_bytes,
            });
        }
        if usize::try_from(envelope.body_len).map_err(|_| CiphertextParseError::LengthOverflow)?
            > max_body_bytes
        {
            return Err(CiphertextParseError::BodyTooLarge {
                body_len: envelope.body_len as usize,
                limit: max_body_bytes,
            });
        }

        if pad_block > 0 {
            let pad_block_usize =
                usize::try_from(pad_block).map_err(|_| CiphertextParseError::LengthOverflow)?;
            if pad_block_usize == 0 || !ciphertext.len().is_multiple_of(pad_block_usize) {
                return Err(CiphertextParseError::PadBlockMismatch {
                    pad_block,
                    length: ciphertext.len(),
                });
            }
        }

        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ciphertext(hdr: &[u8], body: &[u8], padding: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xAA; HPKE_ENC_LEN]);
        out.extend_from_slice(&(hdr.len() as u32).to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(hdr);
        out.extend_from_slice(body);
        out.extend_from_slice(padding);
        out
    }

    #[test]
    fn parses_ciphertext_without_padding() {
        let hdr = [0x01, 0x02];
        let body = [0x03, 0x04, 0x05];
        let ciphertext = build_ciphertext(&hdr, &body, &[]);

        let envelope = CiphertextEnvelope::parse(&ciphertext).expect("parse");
        assert_eq!(envelope.hdr_len, hdr.len() as u32);
        assert_eq!(envelope.body_len, body.len() as u32);
        assert_eq!(envelope.hpke_ct_hdr, hdr);
        assert_eq!(envelope.aead_ct_body, body);
        assert!(envelope.padding.is_empty());
    }

    #[test]
    fn parses_ciphertext_with_zero_padding() {
        let hdr = [0x0A];
        let body = [0x0B];
        let padding = [0u8; 3];
        let ciphertext = build_ciphertext(&hdr, &body, &padding);

        let envelope = CiphertextEnvelope::parse(&ciphertext).expect("parse");
        assert_eq!(envelope.padding, padding);
    }

    #[test]
    fn rejects_ciphertext_with_non_zero_padding() {
        let hdr = [0x0C];
        let body = [0x0D];
        let padding = [0u8, 1u8, 0u8];
        let ciphertext = build_ciphertext(&hdr, &body, &padding);

        let err = CiphertextEnvelope::parse(&ciphertext).expect_err("expected padding error");
        assert!(matches!(err, CiphertextParseError::NonZeroPadding { .. }));
    }

    #[test]
    fn rejects_truncated_ciphertext() {
        let mut ciphertext = vec![0xAA; HPKE_ENC_LEN + CIPHERTEXT_LEN_PREFIX];
        ciphertext.extend_from_slice(&[0x00; 2]);
        let err = CiphertextEnvelope::parse(&ciphertext).expect_err("expected truncation");
        assert!(matches!(err, CiphertextParseError::Truncated { .. }));
    }

    #[test]
    fn enforces_pad_block_multiple() {
        let hdr = [0x11];
        let body = [0x22];
        let ciphertext = build_ciphertext(&hdr, &body, &[0u8; 1]);

        let err =
            CiphertextEnvelope::parse_with_pad_block(&ciphertext, 4).expect_err("pad mismatch");
        assert!(matches!(err, CiphertextParseError::PadBlockMismatch { .. }));
    }

    #[test]
    fn rejects_ciphertext_exceeding_limits() {
        let hdr = [0x11, 0x12];
        let body = [0x22, 0x23, 0x24];
        let ciphertext = build_ciphertext(&hdr, &body, &[0u8; 1]);

        let err = CiphertextEnvelope::parse_with_limits(&ciphertext, 0, 8, 16, 16)
            .expect_err("expected max msg size error");
        assert!(matches!(
            err,
            CiphertextParseError::CiphertextTooLarge { .. }
        ));

        let err = CiphertextEnvelope::parse_with_limits(&ciphertext, 0, ciphertext.len(), 1, 16)
            .expect_err("expected max header size error");
        assert!(matches!(err, CiphertextParseError::HeaderTooLarge { .. }));

        let err = CiphertextEnvelope::parse_with_limits(&ciphertext, 0, ciphertext.len(), 16, 1)
            .expect_err("expected max body size error");
        assert!(matches!(err, CiphertextParseError::BodyTooLarge { .. }));
    }
}
