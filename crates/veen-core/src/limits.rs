//! Default protocol limits defined by the VEEN v0.0.1 specification.
//!
//! Section 14 of `doc/spec.md` establishes conservative upper bounds that
//! implementations must enforce when processing client traffic.  These values
//! keep hub resource usage predictable while remaining configurable by higher
//! level components when a deployment explicitly chooses different limits.

/// Maximum total size of a serialized VEEN message in bytes.
pub const MAX_MSG_BYTES: usize = 1_048_576;

/// Maximum size of the unencrypted payload body in bytes.
pub const MAX_BODY_BYTES: usize = 1_048_320;

/// Maximum size of the encrypted payload header in bytes.
pub const MAX_HDR_BYTES: usize = 16_384;

/// Maximum number of nodes allowed in an inclusion proof path.
pub const MAX_PROOF_LEN: usize = 64;

/// Maximum number of signatures permitted in a capability token chain.
pub const MAX_CAP_CHAIN: usize = 8;

/// Maximum number of attachments that may accompany a single message.
pub const MAX_ATTACHMENTS_PER_MSG: usize = 1_024;

/// Maximum size of a single attachment in bytes.
pub const MAX_ATTACHMENT_BYTES: usize = MAX_BODY_BYTES;
