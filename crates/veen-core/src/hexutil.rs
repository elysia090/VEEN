use std::error::Error;
use std::fmt;

use hex::FromHexError;

/// Error raised when parsing a fixed-length hexadecimal string into bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseHexError {
    /// The input did not contain the expected number of hexadecimal characters.
    InvalidLength { expected: usize, actual: usize },
    /// The input contained a non-hexadecimal character.
    InvalidCharacter { index: usize, character: char },
}

impl fmt::Display for ParseHexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "expected {expected} hex characters, found {actual}")
            }
            Self::InvalidCharacter { index, character } => {
                write!(f, "invalid hex character '{character}' at index {index}")
            }
        }
    }
}

impl Error for ParseHexError {}

/// Decodes a fixed-length hexadecimal string into a byte array of size `N`.
///
/// Returns a [`ParseHexError`] when the string is the wrong length or contains
/// non-hexadecimal characters.
pub(crate) fn decode_hex_array<const N: usize>(input: &str) -> Result<[u8; N], ParseHexError> {
    let expected = N * 2;
    if input.len() != expected {
        return Err(ParseHexError::InvalidLength {
            expected,
            actual: input.len(),
        });
    }

    let mut buf = [0u8; N];
    hex::decode_to_slice(input, &mut buf).map_err(|err| match err {
        FromHexError::InvalidHexCharacter { c, index } => ParseHexError::InvalidCharacter {
            index,
            character: c,
        },
        FromHexError::OddLength | FromHexError::InvalidStringLength => {
            ParseHexError::InvalidLength {
                expected,
                actual: input.len(),
            }
        }
    })?;

    Ok(buf)
}

macro_rules! impl_hex_fmt {
    ($name:ty) => {
        impl ::core::fmt::LowerHex for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                for byte in self.as_ref() {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl ::core::fmt::UpperHex for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                for byte in self.as_ref() {
                    write!(f, "{byte:02X}")?;
                }
                Ok(())
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::LowerHex::fmt(self, f)
            }
        }
    };
}

macro_rules! impl_fixed_hex_from_str {
    ($name:ty, $len:expr) => {
        impl ::core::str::FromStr for $name {
            type Err = $crate::hexutil::ParseHexError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $crate::hexutil::decode_hex_array::<$len>(s).map(Self::from)
            }
        }
    };
}

pub(crate) use {impl_fixed_hex_from_str, impl_hex_fmt};

#[cfg(test)]
mod tests {
    use super::{decode_hex_array, ParseHexError};
    use std::str::FromStr;

    #[test]
    fn decode_hex_array_rejects_invalid_length() {
        let err = decode_hex_array::<32>("0011").expect_err("length error");
        assert!(matches!(
            err,
            ParseHexError::InvalidLength {
                expected: 64,
                actual: 4
            }
        ));
    }

    #[test]
    fn decode_hex_array_rejects_invalid_character() {
        let err = decode_hex_array::<2>("zzzz").expect_err("invalid character");
        assert!(matches!(
            err,
            ParseHexError::InvalidCharacter {
                index: 0,
                character: 'z'
            }
        ));
    }

    #[test]
    fn decode_hex_array_reports_invalid_character_index() {
        let err = decode_hex_array::<2>("0g00").expect_err("invalid character");
        assert!(matches!(
            err,
            ParseHexError::InvalidCharacter {
                index: 1,
                character: 'g'
            }
        ));
    }

    #[test]
    fn decode_hex_array_decodes_lower_and_uppercase() {
        let lower = decode_hex_array::<2>("0a0b").expect("lowercase hex");
        assert_eq!(lower, [0x0a, 0x0b]);

        let upper = decode_hex_array::<2>("0A0B").expect("uppercase hex");
        assert_eq!(upper, [0x0a, 0x0b]);
    }

    #[test]
    fn decode_hex_array_handles_zero_length_arrays() {
        let value = decode_hex_array::<0>("").expect("zero length hex");
        assert!(value.is_empty());
    }

    #[test]
    fn decode_hex_array_rejects_too_long_input() {
        let err = decode_hex_array::<1>("abcd").expect_err("too long");
        assert!(matches!(
            err,
            ParseHexError::InvalidLength {
                expected: 2,
                actual: 4
            }
        ));
    }

    #[test]
    fn impl_hex_fmt_supports_lower_and_upper_hex() {
        #[derive(Clone, Copy)]
        struct Dummy([u8; 2]);

        impl AsRef<[u8]> for Dummy {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        crate::hexutil::impl_hex_fmt!(Dummy);

        let value = Dummy([0xde, 0xad]);
        assert_eq!(format!("{value}"), "dead");
        assert_eq!(format!("{value:x}"), "dead");
        assert_eq!(format!("{value:X}"), "DEAD");
    }

    #[test]
    fn parse_hex_error_formats_messages() {
        let err = ParseHexError::InvalidLength {
            expected: 8,
            actual: 6,
        };
        assert_eq!(
            err.to_string(),
            "expected 8 hex characters, found 6"
        );

        let err = ParseHexError::InvalidCharacter {
            index: 3,
            character: 'x',
        };
        assert_eq!(err.to_string(), "invalid hex character 'x' at index 3");
    }

    #[test]
    fn impl_fixed_hex_from_str_parses_newtype() {
        #[derive(Debug, PartialEq)]
        struct Token([u8; 2]);

        impl From<[u8; 2]> for Token {
            fn from(value: [u8; 2]) -> Self {
                Self(value)
            }
        }

        crate::hexutil::impl_fixed_hex_from_str!(Token, 2);

        let value = Token::from_str("0a0b").expect("parse token");
        assert_eq!(value, Token([0x0a, 0x0b]));

        let err = Token::from_str("0a0").expect_err("length error");
        assert_eq!(
            err,
            ParseHexError::InvalidLength {
                expected: 4,
                actual: 3
            }
        );
    }

    #[test]
    fn impl_fixed_hex_from_str_surfaces_invalid_character() {
        #[derive(Debug, PartialEq)]
        struct Token([u8; 1]);

        impl From<[u8; 1]> for Token {
            fn from(value: [u8; 1]) -> Self {
                Self(value)
            }
        }

        crate::hexutil::impl_fixed_hex_from_str!(Token, 1);

        let err = Token::from_str("0g").expect_err("invalid character");
        assert_eq!(
            err,
            ParseHexError::InvalidCharacter {
                index: 1,
                character: 'g'
            }
        );
    }
}
