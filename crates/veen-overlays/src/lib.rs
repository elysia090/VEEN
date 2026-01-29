//! Overlay schemas and deterministic fold helpers for VEEN.
//!
//! This crate hosts higher-level overlay types (identity, wallet, operations,
//! revocation, queries, etc.) that are layered on top of the core protocol
//! primitives provided by `veen-core`.

pub mod federation;
pub mod identity;
pub mod label_class;
pub mod meta;
pub mod operation;
pub mod pow;
pub mod query;
pub mod revocation;
pub mod wallet;

pub use crate::federation::{
    schema_fed_authority, AuthorityPolicy, AuthorityRecord, AuthorityView, LabelAuthority,
    LabelPolicy,
};
pub use crate::identity::{
    schema_external_link, schema_handle_map, stream_id_ctx, stream_id_handle_ns, stream_id_org,
    stream_id_principal, ContextId, DeviceId, ExternalLinkDirectory, ExternalLinkRecord, GroupId,
    HandleNamespace, HandleRecord, HandleTarget, HandleTargetType, OrgId, PrincipalId, ScopedOrgId,
};
pub use crate::label_class::{schema_label_class, LabelClassRecord};
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
pub use crate::query::*;
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
