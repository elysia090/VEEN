use thiserror::Error;

/// Error returned when encoding a [`Profile`] fails.
#[derive(Debug, Error)]
pub enum ProfileError {
    /// Serialisation or IO failure during CBOR encoding.
    #[error("failed to encode profile to CBOR: {0}")]
    Encoding(String),
}
