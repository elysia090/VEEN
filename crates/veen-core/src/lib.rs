//! Core primitives and helpers for the Verifiable End-to-End Network (VEEN).
//!
//! The crate focuses on providing strongly typed helpers around the immutable
//! wire-format specification documented in `doc/spec.md`. The intent is to
//! make it straightforward to experiment with protocol implementations while
//! enforcing consistent hashing and encoding behaviour across binaries.

pub mod capability;
mod hash;
pub mod hexutil;
pub mod hub;
pub mod kex;
pub mod label;
mod length;
pub mod limits;
pub mod profile;
pub mod realm;
pub mod schema;
pub mod wire;

pub use crate::capability::{
    from_cbor as cap_token_from_cbor, stream_id_from_label as cap_stream_id_from_label, CapToken,
    CapTokenAllow, CapTokenEncodeError, CapTokenIssueError, CapTokenRate, CapTokenVerifyError,
    StreamIdParseError, CAP_TOKEN_VERSION,
};
pub use crate::hash::{h, ht};
pub use crate::hexutil::ParseHexError;
pub use crate::hub::{HubId, HUB_ID_LEN};
pub use crate::kex::{
    cap_token_expiry, cap_token_is_valid, cap_token_is_valid_opt, ClientObservationIndex,
    ClientUsage, ClientUsageConfig, ClientUsageError, ObservationDecision, ObservationError,
};
pub use crate::label::{Label, StreamId};
pub use crate::length::LengthError;
pub use crate::limits::{
    MAX_ATTACHMENTS_PER_MSG, MAX_ATTACHMENT_BYTES, MAX_BODY_BYTES, MAX_CAP_CHAIN, MAX_HDR_BYTES,
    MAX_MSG_BYTES, MAX_PROOF_LEN,
};
pub use crate::profile::{Profile, ProfileId};
pub use crate::realm::{RealmId, REALM_ID_LEN};
pub use crate::schema::{SchemaId, SchemaOwner, SCHEMA_ID_LEN};
pub use crate::wire::{
    AttachmentId, AttachmentRoot, AuthRef, Checkpoint, CheckpointVerifyError, CiphertextEnvelope,
    CiphertextParseError, ClientId, CtHash, Direction, LeafHash, Mmr, MmrNode, MmrPathNode,
    MmrProof, MmrRoot, Msg, MsgVerifyError, PayloadHeader, Receipt, ReceiptVerifyError,
    Signature64, SignatureVerifyError, AEAD_NONCE_LEN, CIPHERTEXT_LEN_PREFIX, HPKE_ENC_LEN,
};
