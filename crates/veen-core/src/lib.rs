//! Core primitives and helpers for the Verifiable End-to-End Network (VEEN).
//!
//! The crate focuses on providing strongly typed helpers around the immutable
//! wire-format specification documented in `doc/spec.md`. The intent is to
//! make it straightforward to experiment with protocol implementations while
//! enforcing consistent hashing and encoding behaviour across binaries.

pub mod capability;
pub mod federation;
mod hash;
mod hexutil;
pub mod hub;
pub mod identity;
pub mod kex;
pub mod label;
pub mod label_class;
mod length;
pub mod limits;
pub mod meta;
pub mod operation;
pub mod pow;
pub mod profile;
pub mod query;
pub mod realm;
pub mod revocation;
pub mod wallet;
pub mod wire;

pub use crate::capability::{
    from_cbor as cap_token_from_cbor, stream_id_from_label as cap_stream_id_from_label, CapToken,
    CapTokenAllow, CapTokenEncodeError, CapTokenIssueError, CapTokenRate, CapTokenVerifyError,
    StreamIdParseError, CAP_TOKEN_VERSION,
};
pub use crate::federation::{
    schema_fed_authority, AuthorityPolicy, AuthorityRecord, AuthorityView, LabelAuthority,
    LabelPolicy,
};
pub use crate::hash::{h, ht};
pub use crate::hexutil::ParseHexError;
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
pub use crate::limits::{
    MAX_ATTACHMENTS_PER_MSG, MAX_BODY_BYTES, MAX_CAP_CHAIN, MAX_HDR_BYTES, MAX_MSG_BYTES,
    MAX_PROOF_LEN,
};
pub use crate::meta::{schema_meta_schema, SchemaDescriptor, SchemaId, SchemaOwner, SCHEMA_ID_LEN};
pub use crate::operation::{
    schema_access_grant, schema_access_revoke, schema_agreement_confirmation,
    schema_agreement_definition, schema_data_publication, schema_delegated_execution,
    schema_federation_mirror, schema_paid_operation, schema_query_audit, schema_recovery_approval,
    schema_recovery_execution, schema_recovery_request, schema_state_checkpoint, AccessGrant,
    AccessRevoke, AccountId, AgreementConfirmation, AgreementDefinition, DataPublication,
    DelegatedExecution, FederationMirror, OpaqueId, OperationDecodeError, OperationId,
    OperationIndex, OperationPayload, PaidOperation, QueryAuditLog, RecoveryApproval,
    RecoveryExecution, RecoveryRequest, StateCheckpoint, ACCOUNT_ID_LEN, OPAQUE_ID_LEN,
    OPERATION_ID_LEN,
};
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
