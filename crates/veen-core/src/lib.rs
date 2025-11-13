//! Core primitives and helpers for the Verifiable End-to-End Network (VEEN).
//!
//! The crate focuses on providing strongly typed helpers around the immutable
//! wire-format specification documented in `doc/spec-1.txt` and the
//! operational overlays captured in `doc/spec-2.txt`. The intent is to
//! make it straightforward to experiment with protocol implementations while
//! enforcing consistent hashing and encoding behaviour across binaries.

pub mod federation;
mod hash;
pub mod hub;
pub mod identity;
pub mod kex;
pub mod label;
pub mod label_class;
mod length;
pub mod meta;
pub mod pow;
pub mod profile;
pub mod realm;
pub mod revocation;
pub mod wallet;
pub mod wire;

pub use crate::federation::{
    schema_fed_authority, AuthorityPolicy, AuthorityRecord, AuthorityView, LabelAuthority,
    LabelPolicy,
};
pub use crate::hash::{h, ht};
pub use crate::hub::{HubId, HUB_ID_LEN};
pub use crate::identity::{
    schema_external_link, schema_handle_map, stream_id_ctx, stream_id_handle_ns, stream_id_org,
    stream_id_principal, ContextId, DeviceId, ExternalLinkDirectory, ExternalLinkRecord, GroupId,
    HandleNamespace, HandleRecord, HandleTarget, HandleTargetType, OrgId, PrincipalId, ScopedOrgId,
};
pub use crate::kex::{
    cap_token_expiry, cap_token_is_valid, cap_token_is_valid_opt, ClientObservationIndex,
    ClientUsage, ClientUsageConfig, ClientUsageError, ObservationDecision, ObservationError,
};
pub use crate::label::{Label, StreamId};
pub use crate::label_class::{schema_label_class, LabelClassRecord};
pub use crate::length::LengthError;
pub use crate::meta::{schema_meta_schema, SchemaDescriptor, SchemaId, SchemaOwner, SCHEMA_ID_LEN};
pub use crate::pow::{schema_pow_cookie, PowCookie};
pub use crate::profile::{Profile, ProfileId};
pub use crate::realm::{RealmId, REALM_ID_LEN};
pub use crate::revocation::{
    cap_token_hash, schema_revocation, RevocationKind, RevocationRecord, RevocationTarget,
    REVOCATION_TARGET_LEN,
};
pub use crate::wallet::{
    approval_hash, needs_daily_limit_reset, schema_wallet_adjust, schema_wallet_close,
    schema_wallet_deposit, schema_wallet_freeze, schema_wallet_limit, schema_wallet_open,
    schema_wallet_transfer, schema_wallet_unfreeze, schema_wallet_withdraw, stream_id_wallet,
    TransferId, WalletAdjustEvent, WalletBridgeIndex, WalletCloseEvent, WalletDepositEvent,
    WalletError, WalletEvent, WalletEventDecodeError, WalletFoldError, WalletFreezeEvent, WalletId,
    WalletLimitEvent, WalletOpenEvent, WalletState, WalletTransferEvent, WalletUnfreezeEvent,
    WalletWithdrawEvent, TRANSFER_ID_LEN, WALLET_ID_LEN,
};
pub use crate::wire::{
    AttachmentId, AttachmentRoot, AuthRef, Checkpoint, CheckpointVerifyError, ClientId, CtHash,
    Direction, LeafHash, Mmr, MmrNode, MmrPathNode, MmrProof, MmrRoot, Msg, MsgVerifyError,
    PayloadHeader, Receipt, ReceiptVerifyError, Signature64, SignatureVerifyError, AEAD_NONCE_LEN,
};
