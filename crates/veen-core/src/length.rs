use std::error::Error;
use std::fmt;

/// Error indicating that a value did not match the expected byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LengthError {
    expected: usize,
    actual: usize,
}

impl LengthError {
    /// Creates a new [`LengthError`] with the expected and actual lengths.
    #[must_use]
    pub const fn new(expected: usize, actual: usize) -> Self {
        Self { expected, actual }
    }

    /// Returns the expected length in bytes.
    #[must_use]
    pub const fn expected(&self) -> usize {
        self.expected
    }

    /// Returns the actual length that was provided.
    #[must_use]
    pub const fn actual(&self) -> usize {
        self.actual
    }
}

impl fmt::Display for LengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "expected {expected} bytes, found {actual}",
            expected = self.expected,
            actual = self.actual
        )
    }
}

impl Error for LengthError {}
