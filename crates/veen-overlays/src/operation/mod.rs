use std::{collections::HashMap, convert::TryFrom, fmt, io::Cursor};

use ciborium::{de::from_reader, value::Value};
use serde::de::{DeserializeOwned, Error as DeError, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{
    identity::{GroupId, PrincipalId},
    meta::SchemaId,
};
use veen_core::{
    h, ht,
    label::{Label, StreamId},
    wire::{
        types::{AuthRef, LeafHash, MmrRoot},
        AttachmentRoot,
    },
    LengthError,
};

/// Length in bytes of a VEEN operation identifier.
pub const OPERATION_ID_LEN: usize = 32;
/// Length in bytes of an account identifier.
pub const ACCOUNT_ID_LEN: usize = 32;
/// Length in bytes of opaque identifiers reused across operation overlays.
pub const OPAQUE_ID_LEN: usize = 32;

fn ensure_len(bytes: &[u8], expected: usize) -> Result<(), LengthError> {
    if bytes.len() != expected {
        Err(LengthError::new(expected, bytes.len()))
    } else {
        Ok(())
    }
}

/// Identifier derived from the message leaf hash for referencing operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OperationId([u8; OPERATION_ID_LEN]);

impl OperationId {
    #[must_use]
    pub const fn new(bytes: [u8; OPERATION_ID_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; OPERATION_ID_LEN] {
        &self.0
    }

    /// Attempts to construct an [`OperationId`] from an arbitrary byte slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        ensure_len(bytes, OPERATION_ID_LEN)?;
        let mut out = [0u8; OPERATION_ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    /// Derives the canonical operation identifier from the provided message identifier.
    pub fn derive(msg_id: impl AsRef<[u8]>) -> Result<Self, LengthError> {
        let msg_id = msg_id.as_ref();
        ensure_len(msg_id, OPERATION_ID_LEN)?;
        Ok(Self(ht("veen/operation-id", msg_id)))
    }

    /// Derives the canonical operation identifier from a committed [`LeafHash`].
    #[must_use]
    pub fn from_leaf_hash(leaf_hash: &LeafHash) -> Self {
        Self(ht("veen/operation-id", leaf_hash.as_ref()))
    }
}

impl From<[u8; OPERATION_ID_LEN]> for OperationId {
    fn from(value: [u8; OPERATION_ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; OPERATION_ID_LEN]> for OperationId {
    fn from(value: &[u8; OPERATION_ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for OperationId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for OperationId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for OperationId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

veen_core::impl_hex_fmt!(OperationId);

impl Serialize for OperationId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct OperationIdVisitor;

impl<'de> Visitor<'de> for OperationIdVisitor {
    type Value = OperationId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN operation identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        OperationId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut buf = Vec::with_capacity(OPERATION_ID_LEN);
        while let Some(byte) = seq.next_element::<u8>()? {
            buf.push(byte);
        }
        OperationId::try_from(buf).map_err(|err| A::Error::invalid_length(err.actual(), &self))
    }
}

impl<'de> Deserialize<'de> for OperationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(OperationIdVisitor)
    }
}

/// Identifier for logical accounts referenced by paid operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountId([u8; ACCOUNT_ID_LEN]);

impl AccountId {
    #[must_use]
    pub const fn new(bytes: [u8; ACCOUNT_ID_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ACCOUNT_ID_LEN] {
        &self.0
    }

    /// Attempts to construct an [`AccountId`] from an arbitrary byte slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        ensure_len(bytes, ACCOUNT_ID_LEN)?;
        let mut out = [0u8; ACCOUNT_ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }
}

impl From<[u8; ACCOUNT_ID_LEN]> for AccountId {
    fn from(value: [u8; ACCOUNT_ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; ACCOUNT_ID_LEN]> for AccountId {
    fn from(value: &[u8; ACCOUNT_ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for AccountId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for AccountId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for AccountId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

veen_core::impl_hex_fmt!(AccountId);

impl Serialize for AccountId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct AccountIdVisitor;

impl<'de> Visitor<'de> for AccountIdVisitor {
    type Value = AccountId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte account identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        AccountId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut buf = Vec::with_capacity(ACCOUNT_ID_LEN);
        while let Some(byte) = seq.next_element::<u8>()? {
            buf.push(byte);
        }
        AccountId::try_from(buf).map_err(|err| A::Error::invalid_length(err.actual(), &self))
    }
}

impl<'de> Deserialize<'de> for AccountId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(AccountIdVisitor)
    }
}

/// Generic 32-byte identifier reused for hashes and references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpaqueId([u8; OPAQUE_ID_LEN]);

impl OpaqueId {
    #[must_use]
    pub const fn new(bytes: [u8; OPAQUE_ID_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; OPAQUE_ID_LEN] {
        &self.0
    }

    /// Attempts to construct an [`OpaqueId`] from an arbitrary byte slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        ensure_len(bytes, OPAQUE_ID_LEN)?;
        let mut out = [0u8; OPAQUE_ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }
}

impl From<[u8; OPAQUE_ID_LEN]> for OpaqueId {
    fn from(value: [u8; OPAQUE_ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; OPAQUE_ID_LEN]> for OpaqueId {
    fn from(value: &[u8; OPAQUE_ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for OpaqueId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for OpaqueId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for OpaqueId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

veen_core::impl_hex_fmt!(OpaqueId);

impl Serialize for OpaqueId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct OpaqueIdVisitor;

impl<'de> Visitor<'de> for OpaqueIdVisitor {
    type Value = OpaqueId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte opaque identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        OpaqueId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut buf = Vec::with_capacity(OPAQUE_ID_LEN);
        while let Some(byte) = seq.next_element::<u8>()? {
            buf.push(byte);
        }
        OpaqueId::try_from(buf).map_err(|err| A::Error::invalid_length(err.actual(), &self))
    }
}

impl<'de> Deserialize<'de> for OpaqueId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(OpaqueIdVisitor)
    }
}

/// Paid operation payload as defined in the Paid Operation profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaidOperation {
    pub operation_type: String,
    pub operation_args: Value,
    pub payer_account: AccountId,
    pub payee_account: AccountId,
    pub amount: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_reference: Option<OpaqueId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_operation_id: Option<OperationId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Access grant payload as defined by the Access Grant profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessGrant {
    pub subject_identity: PrincipalId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_label: Option<String>,
    pub allowed_stream_ids: Vec<StreamId>,
    pub expiry_time: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_rate_per_second: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_burst: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_operation_id: Option<OperationId>,
}

/// Access revoke payload as defined by the Access Grant profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessRevoke {
    pub subject_identity: PrincipalId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_capability_reference: Option<AuthRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_operation_id: Option<OperationId>,
}

/// Delegated execution payload as defined in the Delegated Execution profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedExecution {
    pub principal_identity: PrincipalId,
    pub agent_identity: PrincipalId,
    pub delegation_chain: Vec<AuthRef>,
    pub operation_schema: SchemaId,
    pub operation_body: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_operation_id: Option<OperationId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

impl DelegatedExecution {
    fn validate(&self) -> Result<(), OperationDecodeError> {
        if self.delegation_chain.is_empty() {
            return Err(OperationDecodeError::InvalidDelegationChain);
        }
        Ok(())
    }
}

/// Agreement definition payload as defined in the Multi Party Agreement profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgreementDefinition {
    pub agreement_id: OpaqueId,
    pub version: u64,
    pub terms_hash: OpaqueId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_attachment_root: Option<AttachmentRoot>,
    pub parties: Vec<PrincipalId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Agreement confirmation payload as defined in the Multi Party Agreement profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgreementConfirmation {
    pub agreement_id: OpaqueId,
    pub version: u64,
    pub party_identity: PrincipalId,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_operation_id: Option<OperationId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Data publication payload as defined in the Data Publication profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataPublication {
    pub publication_id: OpaqueId,
    pub publisher_identity: PrincipalId,
    pub content_root: OpaqueId,
    pub content_class: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// State checkpoint payload as defined in the State Snapshot profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateCheckpoint {
    pub state_id: OpaqueId,
    pub upto_stream_seq: u64,
    pub mmr_root: MmrRoot,
    pub state_hash: OpaqueId,
    pub state_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Recovery request payload as defined in the Recovery Procedure profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRequest {
    pub target_identity: PrincipalId,
    pub requested_new_identity: PrincipalId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Recovery approval payload as defined in the Recovery Procedure profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryApproval {
    pub target_identity: PrincipalId,
    pub requested_new_identity: PrincipalId,
    pub approver_identity: PrincipalId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_group_id: Option<GroupId>,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_operation_id: Option<OperationId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Recovery execution payload as defined in the Recovery Procedure profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryExecution {
    pub target_identity: PrincipalId,
    pub new_identity: PrincipalId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_time: Option<u64>,
    pub approval_references: Vec<OperationId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

impl RecoveryExecution {
    fn validate(&self) -> Result<(), OperationDecodeError> {
        if self.approval_references.is_empty() {
            return Err(OperationDecodeError::MissingApprovalReferences);
        }
        Ok(())
    }
}

/// Query audit payload as defined in the Query Audit Log profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryAuditLog {
    pub requester_identity: PrincipalId,
    pub resource_identifier: String,
    pub resource_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_parameters: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<OpaqueId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Federation mirror payload as defined in the Federation Synchronization profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationMirror {
    pub source_hub_identifier: String,
    pub source_label: Label,
    pub source_stream_seq: u64,
    pub source_leaf_hash: LeafHash,
    pub source_receipt_root: MmrRoot,
    pub target_label: Label,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirror_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

fn decode_body<T>(body: &[u8]) -> Result<T, OperationDecodeError>
where
    T: DeserializeOwned,
{
    from_reader(Cursor::new(body)).map_err(|source| OperationDecodeError::Decode { source })
}

/// Errors returned when decoding or validating operation payloads.
#[derive(Debug, Error)]
pub enum OperationDecodeError {
    /// The provided schema identifier is not recognised.
    #[error("unknown operation schema {schema:?}")]
    UnknownSchema { schema: [u8; 32] },
    /// Deserialization of the CBOR payload failed.
    #[error("failed to decode operation payload: {source}")]
    Decode {
        #[from]
        source: ciborium::de::Error<std::io::Error>,
    },
    /// Delegated execution payloads must contain at least one capability reference.
    #[error("delegation chain must not be empty")]
    InvalidDelegationChain,
    /// Recovery execution payloads must reference at least one approval.
    #[error("recovery execution must reference at least one approval")]
    MissingApprovalReferences,
}

/// Enumeration over all operation payloads supported by this module.
#[derive(Debug, Clone, PartialEq)]
pub enum OperationPayload {
    PaidOperation(PaidOperation),
    AccessGrant(AccessGrant),
    AccessRevoke(AccessRevoke),
    DelegatedExecution(DelegatedExecution),
    AgreementDefinition(AgreementDefinition),
    AgreementConfirmation(AgreementConfirmation),
    DataPublication(DataPublication),
    StateCheckpoint(StateCheckpoint),
    RecoveryRequest(RecoveryRequest),
    RecoveryApproval(RecoveryApproval),
    RecoveryExecution(RecoveryExecution),
    QueryAuditLog(QueryAuditLog),
    FederationMirror(FederationMirror),
}

impl OperationPayload {
    /// Attempts to decode an operation payload from the provided schema identifier and CBOR body.
    pub fn from_schema_and_body(
        schema: [u8; 32],
        body: &[u8],
    ) -> Result<Self, OperationDecodeError> {
        let payload = if schema == schema_paid_operation() {
            Self::PaidOperation(decode_body(body)?)
        } else if schema == schema_access_grant() {
            Self::AccessGrant(decode_body(body)?)
        } else if schema == schema_access_revoke() {
            Self::AccessRevoke(decode_body(body)?)
        } else if schema == schema_delegated_execution() {
            let payload: DelegatedExecution = decode_body(body)?;
            payload.validate()?;
            Self::DelegatedExecution(payload)
        } else if schema == schema_agreement_definition() {
            Self::AgreementDefinition(decode_body(body)?)
        } else if schema == schema_agreement_confirmation() {
            Self::AgreementConfirmation(decode_body(body)?)
        } else if schema == schema_data_publication() {
            Self::DataPublication(decode_body(body)?)
        } else if schema == schema_state_checkpoint() {
            Self::StateCheckpoint(decode_body(body)?)
        } else if schema == schema_recovery_request() {
            Self::RecoveryRequest(decode_body(body)?)
        } else if schema == schema_recovery_approval() {
            Self::RecoveryApproval(decode_body(body)?)
        } else if schema == schema_recovery_execution() {
            let payload: RecoveryExecution = decode_body(body)?;
            payload.validate()?;
            Self::RecoveryExecution(payload)
        } else if schema == schema_query_audit() {
            Self::QueryAuditLog(decode_body(body)?)
        } else if schema == schema_federation_mirror() {
            Self::FederationMirror(decode_body(body)?)
        } else {
            return Err(OperationDecodeError::UnknownSchema { schema });
        };
        Ok(payload)
    }

    /// Returns the schema identifier corresponding to this payload.
    #[must_use]
    pub fn schema_id(&self) -> [u8; 32] {
        match self {
            Self::PaidOperation(_) => schema_paid_operation(),
            Self::AccessGrant(_) => schema_access_grant(),
            Self::AccessRevoke(_) => schema_access_revoke(),
            Self::DelegatedExecution(_) => schema_delegated_execution(),
            Self::AgreementDefinition(_) => schema_agreement_definition(),
            Self::AgreementConfirmation(_) => schema_agreement_confirmation(),
            Self::DataPublication(_) => schema_data_publication(),
            Self::StateCheckpoint(_) => schema_state_checkpoint(),
            Self::RecoveryRequest(_) => schema_recovery_request(),
            Self::RecoveryApproval(_) => schema_recovery_approval(),
            Self::RecoveryExecution(_) => schema_recovery_execution(),
            Self::QueryAuditLog(_) => schema_query_audit(),
            Self::FederationMirror(_) => schema_federation_mirror(),
        }
    }
}

/// Returns the schema identifier for `paid.operation.v1`.
#[must_use]
pub fn schema_paid_operation() -> [u8; 32] {
    h(b"veen/schema:paid.operation.v1")
}

/// Returns the schema identifier for `access.grant.v1`.
#[must_use]
pub fn schema_access_grant() -> [u8; 32] {
    h(b"veen/schema:access.grant.v1")
}

/// Returns the schema identifier for `access.revoke.v1`.
#[must_use]
pub fn schema_access_revoke() -> [u8; 32] {
    h(b"veen/schema:access.revoke.v1")
}

/// Returns the schema identifier for `delegated.execution.v1`.
#[must_use]
pub fn schema_delegated_execution() -> [u8; 32] {
    h(b"veen/schema:delegated.execution.v1")
}

/// Returns the schema identifier for `agreement.definition.v1`.
#[must_use]
pub fn schema_agreement_definition() -> [u8; 32] {
    h(b"veen/schema:agreement.definition.v1")
}

/// Returns the schema identifier for `agreement.confirmation.v1`.
#[must_use]
pub fn schema_agreement_confirmation() -> [u8; 32] {
    h(b"veen/schema:agreement.confirmation.v1")
}

/// Returns the schema identifier for `data.publication.v1`.
#[must_use]
pub fn schema_data_publication() -> [u8; 32] {
    h(b"veen/schema:data.publication.v1")
}

/// Returns the schema identifier for `state.checkpoint.v1`.
#[must_use]
pub fn schema_state_checkpoint() -> [u8; 32] {
    h(b"veen/schema:state.checkpoint.v1")
}

/// Returns the schema identifier for `recovery.request.v1`.
#[must_use]
pub fn schema_recovery_request() -> [u8; 32] {
    h(b"veen/schema:recovery.request.v1")
}

/// Returns the schema identifier for `recovery.approval.v1`.
#[must_use]
pub fn schema_recovery_approval() -> [u8; 32] {
    h(b"veen/schema:recovery.approval.v1")
}

/// Returns the schema identifier for `recovery.execution.v1`.
#[must_use]
pub fn schema_recovery_execution() -> [u8; 32] {
    h(b"veen/schema:recovery.execution.v1")
}

/// Returns the schema identifier for `query.audit.v1`.
#[must_use]
pub fn schema_query_audit() -> [u8; 32] {
    h(b"veen/schema:query.audit.v1")
}

/// Returns the schema identifier for `federation.mirror.v1`.
#[must_use]
pub fn schema_federation_mirror() -> [u8; 32] {
    h(b"veen/schema:federation.mirror.v1")
}

/// Helper index that groups operation identifiers by schema for quick lookups.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OperationIndex {
    inner: HashMap<[u8; 32], Vec<OperationId>>,
}

impl OperationIndex {
    /// Inserts a new mapping between the schema identifier and the provided operation id.
    pub fn insert(&mut self, schema: [u8; 32], operation_id: OperationId) {
        self.inner.entry(schema).or_default().push(operation_id);
    }

    /// Returns the list of operation identifiers observed for the provided schema, if any.
    #[must_use]
    pub fn get(&self, schema: [u8; 32]) -> Option<&[OperationId]> {
        self.inner.get(&schema).map(|ids| ids.as_slice())
    }

    /// Returns whether the index already tracks the provided operation id under the schema.
    #[must_use]
    pub fn contains(&self, schema: [u8; 32], operation_id: &OperationId) -> bool {
        self.inner
            .get(&schema)
            .is_some_and(|ids| ids.contains(operation_id))
    }

    /// Clears all tracked entries.
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::ser::into_writer;

    fn sample_bytes(prefix: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = prefix.wrapping_add(index as u8);
        }
        out
    }

    #[test]
    fn schema_constants_match_expected_values() {
        assert_eq!(
            schema_paid_operation(),
            [
                0xe7, 0xca, 0x17, 0xe7, 0xda, 0x0f, 0x55, 0x39, 0xe0, 0x2f, 0xb8, 0x9a, 0x23, 0x4c,
                0x58, 0xe8, 0x80, 0x8d, 0x84, 0xe8, 0x32, 0xa9, 0x7e, 0x7c, 0x70, 0xd9, 0x5f, 0xa4,
                0x37, 0x64, 0x69, 0xa5,
            ]
        );
        assert_eq!(
            schema_access_grant(),
            [
                0xd0, 0x69, 0xa2, 0xba, 0xa0, 0x97, 0x83, 0x7d, 0xf1, 0xe6, 0xfc, 0x27, 0xf0, 0x7a,
                0x43, 0xac, 0x9b, 0x9e, 0xd6, 0x71, 0x7a, 0xc7, 0x1f, 0x2d, 0xd7, 0x2f, 0x97, 0x76,
                0x85, 0xd7, 0xc8, 0xc0,
            ]
        );
        assert_eq!(
            schema_access_revoke(),
            [
                0xc2, 0xe4, 0x25, 0x3b, 0x2e, 0xd2, 0x52, 0x12, 0xb0, 0xc4, 0xe6, 0xfb, 0x19, 0x20,
                0x83, 0xb6, 0x59, 0x75, 0x62, 0xf8, 0x63, 0x65, 0x02, 0x94, 0x0f, 0x1e, 0x2e, 0x85,
                0xca, 0xe5, 0xc3, 0x80,
            ]
        );
        assert_eq!(
            schema_delegated_execution(),
            [
                0x69, 0xce, 0xb5, 0x04, 0x0a, 0x2b, 0x77, 0xe7, 0xd6, 0x74, 0xc5, 0xd2, 0x67, 0xf5,
                0x9c, 0x5c, 0x4a, 0xc6, 0xd5, 0xe4, 0x78, 0x3e, 0xc1, 0x13, 0x5b, 0x3b, 0xab, 0xf9,
                0x21, 0xe3, 0x83, 0x56,
            ]
        );
        assert_eq!(
            schema_agreement_definition(),
            [
                0x43, 0x67, 0x77, 0x81, 0xec, 0x86, 0x6a, 0xe7, 0xef, 0x69, 0x6f, 0xb7, 0x60, 0x27,
                0xcb, 0x74, 0xf7, 0x8a, 0x65, 0x1a, 0xc7, 0x5e, 0x04, 0xc7, 0xbc, 0x0a, 0x25, 0x5c,
                0x45, 0x68, 0xe8, 0x5d,
            ]
        );
        assert_eq!(
            schema_agreement_confirmation(),
            [
                0x21, 0xb3, 0xcc, 0xcd, 0x9b, 0x21, 0x34, 0x37, 0xd2, 0x0e, 0x57, 0x0f, 0xe9, 0x9a,
                0x0c, 0x80, 0x9a, 0x54, 0x82, 0x2e, 0x3c, 0x0c, 0x13, 0x67, 0xf8, 0x2a, 0x0b, 0x06,
                0x30, 0x88, 0x03, 0xd2,
            ]
        );
        assert_eq!(
            schema_data_publication(),
            [
                0x4a, 0x73, 0xc0, 0x4f, 0xac, 0xf1, 0x5c, 0xe3, 0x95, 0x99, 0x2a, 0xc5, 0xff, 0x5e,
                0xd6, 0x8f, 0x5a, 0x1c, 0xe4, 0xed, 0xb4, 0xe4, 0x91, 0x36, 0x46, 0x78, 0x0d, 0x3e,
                0x7c, 0x01, 0x37, 0x5b,
            ]
        );
        assert_eq!(
            schema_state_checkpoint(),
            [
                0x38, 0xd5, 0x4b, 0x9a, 0x59, 0x9a, 0x8b, 0x6f, 0xbd, 0x43, 0x3b, 0x71, 0x5f, 0xb2,
                0x39, 0x99, 0xbb, 0x37, 0xb1, 0x2a, 0x0f, 0x1b, 0x62, 0xa8, 0xe7, 0x50, 0x5e, 0x58,
                0xcd, 0x46, 0x27, 0x88,
            ]
        );
        assert_eq!(
            schema_recovery_request(),
            [
                0x69, 0x79, 0x9a, 0xc3, 0xb7, 0x69, 0x4c, 0xce, 0x78, 0xa0, 0x89, 0xb5, 0x0c, 0x6f,
                0xc4, 0x73, 0x93, 0x70, 0x61, 0xe0, 0x8b, 0x4e, 0x6c, 0x2e, 0xb8, 0x57, 0x14, 0x3b,
                0xcb, 0xe7, 0xc6, 0xbf,
            ]
        );
        assert_eq!(
            schema_recovery_approval(),
            [
                0xb7, 0xc2, 0x1b, 0xd0, 0xea, 0x5c, 0x61, 0x5f, 0x49, 0x0c, 0xf3, 0x69, 0xa2, 0x6c,
                0x4f, 0x7f, 0x75, 0x45, 0xdc, 0xf2, 0x69, 0x2e, 0x04, 0x82, 0x46, 0x26, 0xc2, 0x6a,
                0xe7, 0x4c, 0x15, 0xf7,
            ]
        );
        assert_eq!(
            schema_recovery_execution(),
            [
                0xa8, 0xac, 0x82, 0x16, 0xad, 0x40, 0x37, 0xeb, 0x8f, 0x8d, 0x23, 0xb9, 0xdf, 0x04,
                0x7c, 0xcd, 0x9e, 0x63, 0x70, 0x20, 0x49, 0x39, 0xda, 0xf0, 0x1e, 0xc2, 0x8b, 0x49,
                0x07, 0xbd, 0xe2, 0xf3,
            ]
        );
        assert_eq!(
            schema_query_audit(),
            [
                0x9a, 0xcf, 0xbd, 0xd7, 0x72, 0xc4, 0xfa, 0xe6, 0x74, 0x34, 0x62, 0x2b, 0xb7, 0x86,
                0xf0, 0x71, 0xfd, 0x8f, 0x38, 0x5f, 0x94, 0x35, 0xb0, 0x08, 0x35, 0xb5, 0xc9, 0xf7,
                0x91, 0xf7, 0xe6, 0xae,
            ]
        );
        assert_eq!(
            schema_federation_mirror(),
            [
                0x99, 0x50, 0x00, 0xe2, 0x5e, 0xe8, 0xac, 0x0c, 0x3d, 0xce, 0x00, 0x4c, 0x97, 0x4f,
                0x6f, 0xac, 0x3b, 0x0e, 0x23, 0xb9, 0x16, 0x18, 0x4f, 0xe4, 0x27, 0x9a, 0x93, 0x56,
                0x8e, 0x12, 0x3b, 0x9b,
            ]
        );
    }

    #[test]
    fn operation_id_derivation_matches_spec() {
        let leaf_hash = LeafHash::from(sample_bytes(0x10));
        let derived = OperationId::from_leaf_hash(&leaf_hash);
        let expected = OperationId::from(ht("veen/operation-id", leaf_hash.as_ref()));
        assert_eq!(derived, expected);
    }

    #[test]
    fn delegation_chain_validation() {
        let payload = DelegatedExecution {
            principal_identity: PrincipalId::from(sample_bytes(0x01)),
            agent_identity: PrincipalId::from(sample_bytes(0x02)),
            delegation_chain: Vec::new(),
            operation_schema: SchemaId::from(sample_bytes(0x03)),
            operation_body: Value::Null,
            parent_operation_id: None,
            metadata: None,
        };
        assert!(matches!(
            payload.validate(),
            Err(OperationDecodeError::InvalidDelegationChain)
        ));
    }

    #[test]
    fn recovery_execution_validation() {
        let payload = RecoveryExecution {
            target_identity: PrincipalId::from(sample_bytes(0x01)),
            new_identity: PrincipalId::from(sample_bytes(0x02)),
            applied_time: None,
            approval_references: Vec::new(),
            metadata: None,
        };
        assert!(matches!(
            payload.validate(),
            Err(OperationDecodeError::MissingApprovalReferences)
        ));
    }

    #[test]
    fn operation_payload_round_trip() {
        let payload = PaidOperation {
            operation_type: "translate".into(),
            operation_args: Value::Map(vec![]),
            payer_account: AccountId::from(sample_bytes(0x11)),
            payee_account: AccountId::from(sample_bytes(0x22)),
            amount: 100,
            currency_code: Some("USD".into()),
            operation_reference: Some(OpaqueId::from(sample_bytes(0x33))),
            parent_operation_id: Some(OperationId::from(sample_bytes(0x44))),
            ttl_seconds: Some(60),
            metadata: None,
        };
        let mut encoded = Vec::new();
        into_writer(&payload, &mut encoded).expect("encode paid operation");

        let decoded = OperationPayload::from_schema_and_body(schema_paid_operation(), &encoded)
            .expect("decode operation");
        assert_eq!(decoded, OperationPayload::PaidOperation(payload));
    }

    #[test]
    fn index_tracks_operations_by_schema() {
        let mut index = OperationIndex::default();
        let schema = schema_paid_operation();
        let op_a = OperationId::from(sample_bytes(0x55));
        let op_b = OperationId::from(sample_bytes(0x66));

        assert!(!index.contains(schema, &op_a));
        index.insert(schema, op_a);
        index.insert(schema, op_b);

        let entries = index.get(schema).expect("entries");
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&op_a));
        assert!(index.contains(schema, &op_b));

        index.clear();
        assert!(index.get(schema).is_none());
    }

    #[test]
    fn operation_payload_rejects_unknown_schema() {
        let payload = PaidOperation {
            operation_type: "translate".into(),
            operation_args: Value::Null,
            payer_account: AccountId::from(sample_bytes(0x10)),
            payee_account: AccountId::from(sample_bytes(0x20)),
            amount: 1,
            currency_code: None,
            operation_reference: None,
            parent_operation_id: None,
            ttl_seconds: None,
            metadata: None,
        };
        let mut encoded = Vec::new();
        into_writer(&payload, &mut encoded).expect("encode");

        let err = OperationPayload::from_schema_and_body([0u8; 32], &encoded)
            .expect_err("unknown schema");
        assert!(matches!(err, OperationDecodeError::UnknownSchema { .. }));
    }

    #[test]
    fn id_type_constructors_and_conversions() {
        use std::convert::TryFrom;

        // OperationId
        let bytes = sample_bytes(0x01);
        let op = OperationId::new(bytes);
        assert_eq!(op.as_bytes(), &bytes);
        assert_eq!(op.as_ref(), &bytes[..]);

        let op2 = OperationId::from(bytes);
        assert_eq!(op2, op);
        let op3 = OperationId::from(&bytes);
        assert_eq!(op3, op);

        let op4 = OperationId::try_from(bytes.as_slice()).expect("try_from slice");
        assert_eq!(op4, op);
        let err = OperationId::try_from([0u8; 1].as_slice()).expect_err("too short");
        assert_eq!(err.expected(), OPERATION_ID_LEN);

        let op5 = OperationId::try_from(bytes.to_vec()).expect("try_from vec");
        assert_eq!(op5, op);
        let err2 = OperationId::try_from(vec![0u8; 1]).expect_err("too short");
        assert_eq!(err2.expected(), OPERATION_ID_LEN);

        let display = op.to_string();
        assert_eq!(display, hex::encode(bytes));

        // AccountId
        let abytes = sample_bytes(0x02);
        let acc = AccountId::new(abytes);
        assert_eq!(acc.as_bytes(), &abytes);
        assert_eq!(acc.as_ref(), &abytes[..]);
        let acc2 = AccountId::from(abytes);
        assert_eq!(acc2, acc);
        let acc3 = AccountId::from(&abytes);
        assert_eq!(acc3, acc);
        let acc4 = AccountId::try_from(abytes.as_slice()).expect("try_from slice");
        assert_eq!(acc4, acc);
        let acc_err = AccountId::try_from([0u8; 1].as_slice()).expect_err("too short");
        assert_eq!(acc_err.expected(), ACCOUNT_ID_LEN);
        let acc5 = AccountId::try_from(abytes.to_vec()).expect("try_from vec");
        assert_eq!(acc5, acc);

        // OpaqueId
        let obytes = sample_bytes(0x03);
        let oid = OpaqueId::new(obytes);
        assert_eq!(oid.as_bytes(), &obytes);
        assert_eq!(oid.as_ref(), &obytes[..]);
        let oid2 = OpaqueId::from(obytes);
        assert_eq!(oid2, oid);
        let oid3 = OpaqueId::from(&obytes);
        assert_eq!(oid3, oid);
        let oid4 = OpaqueId::try_from(obytes.as_slice()).expect("try_from slice");
        assert_eq!(oid4, oid);
        let oid_err = OpaqueId::try_from([0u8; 1].as_slice()).expect_err("too short");
        assert_eq!(oid_err.expected(), OPAQUE_ID_LEN);
        let oid5 = OpaqueId::try_from(obytes.to_vec()).expect("try_from vec");
        assert_eq!(oid5, oid);
    }

    #[test]
    fn id_type_serde_roundtrip() {
        let op = OperationId::new(sample_bytes(0xAA));
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&op, &mut buf).expect("serialize");
        let decoded: OperationId = ciborium::de::from_reader(buf.as_slice()).expect("deserialize");
        assert_eq!(decoded, op);

        let acc = AccountId::new(sample_bytes(0xBB));
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&acc, &mut buf).expect("serialize");
        let decoded: AccountId = ciborium::de::from_reader(buf.as_slice()).expect("deserialize");
        assert_eq!(decoded, acc);

        let oid = OpaqueId::new(sample_bytes(0xCC));
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&oid, &mut buf).expect("serialize");
        let decoded: OpaqueId = ciborium::de::from_reader(buf.as_slice()).expect("deserialize");
        assert_eq!(decoded, oid);
    }

    #[test]
    fn id_type_serde_invalid_length() {
        let short: &[u8] = &[0u8; OPERATION_ID_LEN - 1];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&serde_bytes::Bytes::new(short), &mut buf).expect("serialize");
        let result: Result<OperationId, _> = ciborium::de::from_reader(buf.as_slice());
        assert!(result.is_err());

        let short2: &[u8] = &[0u8; ACCOUNT_ID_LEN - 1];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&serde_bytes::Bytes::new(short2), &mut buf).expect("serialize");
        let result2: Result<AccountId, _> = ciborium::de::from_reader(buf.as_slice());
        assert!(result2.is_err());
    }

    #[test]
    fn operation_payload_all_schemas() {
        fn encode_and_decode<T: serde::Serialize>(value: T, schema: [u8; 32]) -> OperationPayload {
            let mut encoded = Vec::new();
            into_writer(&value, &mut encoded).expect("encode");
            OperationPayload::from_schema_and_body(schema, &encoded).expect("decode")
        }

        let principal = PrincipalId::from(sample_bytes(0x01));
        let stream_id = StreamId::from(sample_bytes(0x02));

        // AccessGrant
        let grant = AccessGrant {
            subject_identity: principal,
            subject_label: None,
            allowed_stream_ids: vec![stream_id],
            expiry_time: 9999,
            maximum_rate_per_second: None,
            maximum_burst: None,
            maximum_amount: None,
            currency_code: None,
            reason: None,
            parent_operation_id: None,
        };
        let payload = encode_and_decode(grant.clone(), schema_access_grant());
        assert_eq!(payload, OperationPayload::AccessGrant(grant));
        assert_eq!(payload.schema_id(), schema_access_grant());

        // AccessRevoke
        let revoke = AccessRevoke {
            subject_identity: principal,
            target_capability_reference: None,
            reason: None,
            parent_operation_id: None,
        };
        let payload = encode_and_decode(revoke.clone(), schema_access_revoke());
        assert_eq!(payload, OperationPayload::AccessRevoke(revoke));
        assert_eq!(payload.schema_id(), schema_access_revoke());

        // DelegatedExecution (with non-empty chain)
        let delg = DelegatedExecution {
            principal_identity: principal,
            agent_identity: PrincipalId::from(sample_bytes(0x10)),
            delegation_chain: vec![veen_core::wire::types::AuthRef::new(sample_bytes(0x20))],
            operation_schema: SchemaId::from(sample_bytes(0x30)),
            operation_body: ciborium::value::Value::Null,
            parent_operation_id: None,
            metadata: None,
        };
        let payload = encode_and_decode(delg.clone(), schema_delegated_execution());
        assert_eq!(payload, OperationPayload::DelegatedExecution(delg));
        assert_eq!(payload.schema_id(), schema_delegated_execution());

        // AgreementDefinition
        let agree_def = AgreementDefinition {
            agreement_id: OpaqueId::new(sample_bytes(0x40)),
            version: 1,
            terms_hash: OpaqueId::new(sample_bytes(0x41)),
            terms_attachment_root: None,
            parties: vec![principal],
            effective_time: None,
            expiry_time: None,
            metadata: None,
        };
        let payload = encode_and_decode(agree_def.clone(), schema_agreement_definition());
        assert_eq!(payload, OperationPayload::AgreementDefinition(agree_def));
        assert_eq!(payload.schema_id(), schema_agreement_definition());

        // AgreementConfirmation
        let agree_conf = AgreementConfirmation {
            agreement_id: OpaqueId::new(sample_bytes(0x50)),
            version: 1,
            party_identity: principal,
            decision: "accepted".to_string(),
            decision_time: Some(100),
            parent_operation_id: None,
            metadata: None,
        };
        let payload = encode_and_decode(agree_conf.clone(), schema_agreement_confirmation());
        assert_eq!(payload, OperationPayload::AgreementConfirmation(agree_conf));
        assert_eq!(payload.schema_id(), schema_agreement_confirmation());

        // DataPublication
        let data_pub = DataPublication {
            publication_id: OpaqueId::new(sample_bytes(0x60)),
            publisher_identity: principal,
            content_root: OpaqueId::new(sample_bytes(0x61)),
            content_class: "text/plain".to_string(),
            version: "1.0".to_string(),
            labels: vec![],
            source_uri: None,
            metadata: None,
        };
        let payload = encode_and_decode(data_pub.clone(), schema_data_publication());
        assert_eq!(payload, OperationPayload::DataPublication(data_pub));
        assert_eq!(payload.schema_id(), schema_data_publication());

        // StateCheckpoint
        let state_cp = StateCheckpoint {
            state_id: OpaqueId::new(sample_bytes(0x70)),
            upto_stream_seq: 42,
            mmr_root: MmrRoot::new(sample_bytes(0x71)),
            state_hash: OpaqueId::new(sample_bytes(0x72)),
            state_class: "snapshot".to_string(),
            metadata: None,
        };
        let payload = encode_and_decode(state_cp.clone(), schema_state_checkpoint());
        assert_eq!(payload, OperationPayload::StateCheckpoint(state_cp));
        assert_eq!(payload.schema_id(), schema_state_checkpoint());

        // RecoveryRequest
        let rec_req = RecoveryRequest {
            target_identity: principal,
            requested_new_identity: PrincipalId::from(sample_bytes(0x80)),
            reason: None,
            request_time: None,
            metadata: None,
        };
        let payload = encode_and_decode(rec_req.clone(), schema_recovery_request());
        assert_eq!(payload, OperationPayload::RecoveryRequest(rec_req));
        assert_eq!(payload.schema_id(), schema_recovery_request());

        // RecoveryApproval
        let rec_appr = RecoveryApproval {
            target_identity: principal,
            requested_new_identity: PrincipalId::from(sample_bytes(0x90)),
            approver_identity: PrincipalId::from(sample_bytes(0x91)),
            policy_group_id: None,
            decision: "approved".to_string(),
            decision_time: None,
            parent_operation_id: None,
            metadata: None,
        };
        let payload = encode_and_decode(rec_appr.clone(), schema_recovery_approval());
        assert_eq!(payload, OperationPayload::RecoveryApproval(rec_appr));
        assert_eq!(payload.schema_id(), schema_recovery_approval());

        // RecoveryExecution (with non-empty references)
        let rec_exec = RecoveryExecution {
            target_identity: principal,
            new_identity: PrincipalId::from(sample_bytes(0xA0)),
            applied_time: None,
            approval_references: vec![OperationId::new(sample_bytes(0xA1))],
            metadata: None,
        };
        let payload = encode_and_decode(rec_exec.clone(), schema_recovery_execution());
        assert_eq!(payload, OperationPayload::RecoveryExecution(rec_exec));
        assert_eq!(payload.schema_id(), schema_recovery_execution());

        // QueryAuditLog
        let query_audit = QueryAuditLog {
            requester_identity: principal,
            resource_identifier: "res-1".to_string(),
            resource_class: "class-a".to_string(),
            query_parameters: None,
            purpose_code: None,
            result_digest: None,
            request_time: None,
            metadata: None,
        };
        let payload = encode_and_decode(query_audit.clone(), schema_query_audit());
        assert_eq!(payload, OperationPayload::QueryAuditLog(query_audit));
        assert_eq!(payload.schema_id(), schema_query_audit());

        // FederationMirror
        let fed_mirror = FederationMirror {
            source_hub_identifier: "hub.example.com".to_string(),
            source_label: Label::from(sample_bytes(0xB0)),
            source_stream_seq: 42,
            source_leaf_hash: LeafHash::from(sample_bytes(0xB1)),
            source_receipt_root: MmrRoot::new(sample_bytes(0xB2)),
            target_label: Label::from(sample_bytes(0xB3)),
            mirror_time: None,
            metadata: None,
        };
        let payload = encode_and_decode(fed_mirror.clone(), schema_federation_mirror());
        assert_eq!(payload, OperationPayload::FederationMirror(fed_mirror));
        assert_eq!(payload.schema_id(), schema_federation_mirror());

        // PaidOperation schema_id
        let paid = PaidOperation {
            operation_type: "op".into(),
            operation_args: ciborium::value::Value::Null,
            payer_account: AccountId::new(sample_bytes(0xC0)),
            payee_account: AccountId::new(sample_bytes(0xC1)),
            amount: 1,
            currency_code: None,
            operation_reference: None,
            parent_operation_id: None,
            ttl_seconds: None,
            metadata: None,
        };
        let paid_payload = OperationPayload::PaidOperation(paid);
        assert_eq!(paid_payload.schema_id(), schema_paid_operation());
    }

    #[test]
    fn operation_id_from_slice_error() {
        let err = OperationId::from_slice(&[0u8; OPERATION_ID_LEN - 1]).expect_err("too short");
        assert_eq!(err.expected(), OPERATION_ID_LEN);
    }
}
