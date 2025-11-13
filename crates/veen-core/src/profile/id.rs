use std::fmt;

use serde::{Deserialize, Serialize};

/// Opaque newtype describing the profile identifier computed from a
/// [`Profile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileId(pub [u8; 32]);

impl AsRef<[u8]> for ProfileId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
