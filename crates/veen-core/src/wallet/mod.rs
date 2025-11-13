use std::{collections::HashSet, convert::TryFrom, fmt, io::Cursor};

use ciborium::{de::from_reader, value::Value};
use serde::de::{DeserializeOwned, Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::ByteBuf;
use thiserror::Error;

use crate::{
    hash::{h, ht},
    identity::ContextId,
    label::StreamId,
    realm::RealmId,
    wire::types::LeafHash,
    LengthError,
};

/// Length in bytes of a VEEN wallet identifier.
pub const WALLET_ID_LEN: usize = 32;

/// Length in bytes of a VEEN wallet transfer identifier.
pub const TRANSFER_ID_LEN: usize = 32;

/// Opaque newtype describing the wallet identifier derived from
/// `(realm_id, ctx_id, currency_code)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WalletId([u8; WALLET_ID_LEN]);

impl WalletId {
    /// Creates a wallet identifier from the provided byte array.
    #[must_use]
    pub const fn new(bytes: [u8; WALLET_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; WALLET_ID_LEN] {
        &self.0
    }

    /// Attempts to construct a [`WalletId`] from a byte slice, enforcing the
    /// specification-mandated length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != WALLET_ID_LEN {
            return Err(LengthError::new(WALLET_ID_LEN, bytes.len()));
        }
        let mut out = [0u8; WALLET_ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    /// Derives the canonical wallet identifier from a realm, context identity,
    /// and ASCII currency code as defined in the wallet specification.
    pub fn derive(
        realm_id: RealmId,
        ctx_id: ContextId,
        currency_code: impl AsRef<str>,
    ) -> Result<Self, WalletError> {
        let currency_code = currency_code.as_ref();
        if let Some((index, byte)) = currency_code
            .as_bytes()
            .iter()
            .enumerate()
            .find(|(_, byte)| !byte.is_ascii())
        {
            return Err(WalletError::NonAsciiCurrency { index, byte: *byte });
        }

        let mut data = Vec::with_capacity(
            RealmId::as_bytes(&realm_id).len()
                + ContextId::as_bytes(&ctx_id).len()
                + currency_code.len(),
        );
        data.extend_from_slice(realm_id.as_ref());
        data.extend_from_slice(ctx_id.as_ref());
        data.extend_from_slice(currency_code.as_bytes());

        Ok(Self::from(ht("wallet/id", &data)))
    }
}

/// Opaque newtype describing the globally unique transfer identifier derived
/// from the source message identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransferId([u8; TRANSFER_ID_LEN]);

impl TransferId {
    /// Creates a transfer identifier from the provided byte array.
    #[must_use]
    pub const fn new(bytes: [u8; TRANSFER_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the underlying identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TRANSFER_ID_LEN] {
        &self.0
    }

    /// Attempts to construct a [`TransferId`] from a byte slice, enforcing the
    /// specification-mandated length.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != TRANSFER_ID_LEN {
            return Err(LengthError::new(TRANSFER_ID_LEN, bytes.len()));
        }
        let mut out = [0u8; TRANSFER_ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    /// Derives the canonical transfer identifier from the VEEN message
    /// identifier, i.e. `transfer_id = Ht("wallet/xfer", msg_id)`.
    pub fn derive(msg_id: impl AsRef<[u8]>) -> Result<Self, LengthError> {
        let msg_id = msg_id.as_ref();
        if msg_id.len() != TRANSFER_ID_LEN {
            return Err(LengthError::new(TRANSFER_ID_LEN, msg_id.len()));
        }
        Ok(Self::from(ht("wallet/xfer", msg_id)))
    }
}

impl From<[u8; TRANSFER_ID_LEN]> for TransferId {
    fn from(value: [u8; TRANSFER_ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; TRANSFER_ID_LEN]> for TransferId {
    fn from(value: &[u8; TRANSFER_ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for TransferId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for TransferId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for TransferId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for TransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for TransferId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct TransferIdVisitor;

impl<'de> Visitor<'de> for TransferIdVisitor {
    type Value = TransferId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN wallet transfer identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        TransferId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for TransferId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(TransferIdVisitor)
    }
}

impl From<[u8; WALLET_ID_LEN]> for WalletId {
    fn from(value: [u8; WALLET_ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; WALLET_ID_LEN]> for WalletId {
    fn from(value: &[u8; WALLET_ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for WalletId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for WalletId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for WalletId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for WalletId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for WalletId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct WalletIdVisitor;

impl<'de> Visitor<'de> for WalletIdVisitor {
    type Value = WalletId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN wallet identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        WalletId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for WalletId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(WalletIdVisitor)
    }
}

/// Error returned when wallet-specific derivations violate the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WalletError {
    /// The provided currency code contained non-ASCII data.
    #[error("currency code must be ASCII, found non-ASCII byte {byte:#04x} at index {index}")]
    NonAsciiCurrency { index: usize, byte: u8 },
}

/// Wallet opening event body as defined by `wallet.open.v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletOpenEvent {
    pub wallet_id: WalletId,
    pub realm_id: RealmId,
    pub ctx_id: ContextId,
    pub currency: String,
    pub created_at: u64,
}

/// Wallet closing event body as defined by `wallet.close.v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletCloseEvent {
    pub wallet_id: WalletId,
    pub ts: u64,
}

/// Deposit event body as defined by `wallet.deposit.v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletDepositEvent {
    pub wallet_id: WalletId,
    pub amount: u64,
    pub ts: u64,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<ByteBuf>,
}

/// Withdraw event body as defined by `wallet.withdraw.v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletWithdrawEvent {
    pub wallet_id: WalletId,
    pub amount: u64,
    pub ts: u64,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<ByteBuf>,
}

/// Transfer event body as defined by `wallet.transfer.v1`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WalletTransferEvent {
    pub wallet_id: WalletId,
    pub to_wallet_id: WalletId,
    pub amount: u64,
    pub ts: u64,
    pub transfer_id: TransferId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletTransferEventDe {
    wallet_id: WalletId,
    to_wallet_id: WalletId,
    amount: u64,
    ts: u64,
    transfer_id: TransferId,
    #[serde(default)]
    metadata: Option<Value>,
}

impl<'de> Deserialize<'de> for WalletTransferEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = WalletTransferEventDe::deserialize(deserializer)?;
        if let Some(ref metadata) = value.metadata {
            if !matches!(metadata, Value::Map(_)) {
                return Err(DeError::custom("metadata must be a CBOR map"));
            }
        }
        Ok(Self {
            wallet_id: value.wallet_id,
            to_wallet_id: value.to_wallet_id,
            amount: value.amount,
            ts: value.ts,
            transfer_id: value.transfer_id,
            metadata: value.metadata,
        })
    }
}

/// Adjustment event body as defined by `wallet.adjust.v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletAdjustEvent {
    pub wallet_id: WalletId,
    pub delta: i128,
    pub ts: u64,
    pub reason: String,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<ByteBuf>,
}

/// Limit configuration event body as defined by `wallet.limit.v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletLimitEvent {
    pub wallet_id: WalletId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daily_limit: Option<u64>,
    pub ts: u64,
}

/// Freeze event body as defined by `wallet.freeze.v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletFreezeEvent {
    pub wallet_id: WalletId,
    pub ts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Unfreeze event body as defined by `wallet.unfreeze.v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletUnfreezeEvent {
    pub wallet_id: WalletId,
    pub ts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn decode_event<T>(body: &[u8]) -> Result<T, WalletEventDecodeError>
where
    T: DeserializeOwned,
{
    from_reader(Cursor::new(body)).map_err(|source| WalletEventDecodeError::Decode { source })
}

/// Errors returned when decoding WAL events from CBOR bodies.
#[derive(Debug, Error)]
pub enum WalletEventDecodeError {
    /// The provided schema identifier does not correspond to a known WAL event.
    #[error("unknown wallet schema {schema:?}")]
    UnknownSchema { schema: [u8; 32] },
    /// Deserialization of the CBOR event body failed.
    #[error("failed to decode wallet event: {source}")]
    Decode {
        #[from]
        source: ciborium::de::Error<std::io::Error>,
    },
}

/// Enumeration over the WAL event types supported by this module.
#[derive(Debug, Clone, PartialEq)]
pub enum WalletEvent {
    Open(WalletOpenEvent),
    Close(WalletCloseEvent),
    Deposit(WalletDepositEvent),
    Withdraw(WalletWithdrawEvent),
    Transfer(WalletTransferEvent),
    Adjust(WalletAdjustEvent),
    Limit(WalletLimitEvent),
    Freeze(WalletFreezeEvent),
    Unfreeze(WalletUnfreezeEvent),
}

impl WalletEvent {
    /// Attempts to decode a WAL event from the provided schema identifier and CBOR body.
    pub fn from_schema_and_body(
        schema: [u8; 32],
        body: &[u8],
    ) -> Result<Self, WalletEventDecodeError> {
        if schema == schema_wallet_open() {
            Ok(Self::Open(decode_event(body)?))
        } else if schema == schema_wallet_close() {
            Ok(Self::Close(decode_event(body)?))
        } else if schema == schema_wallet_deposit() {
            Ok(Self::Deposit(decode_event(body)?))
        } else if schema == schema_wallet_withdraw() {
            Ok(Self::Withdraw(decode_event(body)?))
        } else if schema == schema_wallet_transfer() {
            Ok(Self::Transfer(decode_event(body)?))
        } else if schema == schema_wallet_adjust() {
            Ok(Self::Adjust(decode_event(body)?))
        } else if schema == schema_wallet_limit() {
            Ok(Self::Limit(decode_event(body)?))
        } else if schema == schema_wallet_freeze() {
            Ok(Self::Freeze(decode_event(body)?))
        } else if schema == schema_wallet_unfreeze() {
            Ok(Self::Unfreeze(decode_event(body)?))
        } else {
            Err(WalletEventDecodeError::UnknownSchema { schema })
        }
    }

    /// Returns the schema identifier associated with this event variant.
    #[must_use]
    pub fn schema_id(&self) -> [u8; 32] {
        match self {
            Self::Open(_) => schema_wallet_open(),
            Self::Close(_) => schema_wallet_close(),
            Self::Deposit(_) => schema_wallet_deposit(),
            Self::Withdraw(_) => schema_wallet_withdraw(),
            Self::Transfer(_) => schema_wallet_transfer(),
            Self::Adjust(_) => schema_wallet_adjust(),
            Self::Limit(_) => schema_wallet_limit(),
            Self::Freeze(_) => schema_wallet_freeze(),
            Self::Unfreeze(_) => schema_wallet_unfreeze(),
        }
    }

    /// Applies the event to a [`WalletState`] using the folding rules defined by the specification.
    pub fn apply_to(&self, state: &mut WalletState) -> Result<(), WalletFoldError> {
        match self {
            Self::Open(event) => state.apply_open(event),
            Self::Close(event) => state.apply_close(event),
            Self::Deposit(event) => state.apply_deposit(event),
            Self::Withdraw(event) => state.apply_withdraw(event),
            Self::Transfer(event) => state.apply_transfer(event),
            Self::Adjust(event) => state.apply_adjust(event),
            Self::Limit(event) => state.apply_limit(event),
            Self::Freeze(event) => state.apply_freeze(event),
            Self::Unfreeze(event) => state.apply_unfreeze(event),
        }
    }
}

/// Errors returned when applying WAL events to a [`WalletState`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WalletFoldError {
    /// The wallet identifier derived from the event fields does not match the provided value.
    #[error("wallet identifier mismatch (expected {expected}, found {actual})")]
    WalletIdMismatch {
        expected: WalletId,
        actual: WalletId,
    },
    /// The currency code was not valid ASCII.
    #[error("currency code must be ASCII, found non-ASCII byte {byte:#04x} at index {index}")]
    NonAsciiCurrency { index: usize, byte: u8 },
    /// The wallet has not been opened yet.
    #[error("wallet has not been opened")]
    WalletNotOpen,
    /// The wallet has been closed and cannot accept mutations.
    #[error("wallet is closed")]
    WalletClosed,
    /// The wallet is frozen and cannot accept outgoing debits.
    #[error("wallet is frozen")]
    WalletFrozen,
    /// The wallet does not have an identifier associated with it yet.
    #[error("wallet identifier is unknown; process wallet.open.v1 first")]
    WalletIdUnknown,
    /// The event does not reference this wallet.
    #[error(
        "transfer does not involve wallet {wallet_id}; found source {event_wallet_id} and destination {to_wallet_id}"
    )]
    TransferNotApplicable {
        wallet_id: WalletId,
        event_wallet_id: WalletId,
        to_wallet_id: WalletId,
    },
    /// The debit amount exceeds the available balance.
    #[error("insufficient balance for debit: have {balance}, need {amount}")]
    InsufficientFunds { balance: u64, amount: u64 },
    /// Adding the provided amount would overflow the balance counter.
    #[error("balance overflow")]
    BalanceOverflow,
    /// Subtracting the provided amount would underflow the balance counter.
    #[error("balance underflow")]
    BalanceUnderflow,
    /// The pending daily spend counter would overflow.
    #[error("pending daily spent overflow")]
    DailySpentOverflow,
    /// The debit would exceed the configured daily limit.
    #[error("daily limit exceeded: limit {limit}, attempted {attempted}")]
    DailyLimitExceeded { limit: u64, attempted: u64 },
    /// The adjustment would result in a negative balance.
    #[error("adjustment would result in a negative balance")]
    NegativeBalance,
}

impl From<WalletError> for WalletFoldError {
    fn from(value: WalletError) -> Self {
        match value {
            WalletError::NonAsciiCurrency { index, byte } => Self::NonAsciiCurrency { index, byte },
        }
    }
}

/// Tracks bridged WAL events to provide parent-based deduplication as recommended by WALBR0.
#[derive(Debug, Clone, Default)]
pub struct WalletBridgeIndex {
    seen_parent_ids: HashSet<LeafHash>,
}

impl WalletBridgeIndex {
    /// Creates an empty bridge index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Removes all tracked parent identifiers.
    pub fn clear(&mut self) {
        self.seen_parent_ids.clear();
    }

    /// Returns the number of tracked parent identifiers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen_parent_ids.len()
    }

    /// Returns `true` if no parent identifiers have been observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen_parent_ids.is_empty()
    }

    /// Returns `true` if the provided parent identifier has already been observed.
    #[must_use]
    pub fn has_seen(&self, parent_id: &LeafHash) -> bool {
        self.seen_parent_ids.contains(parent_id)
    }

    /// Records the provided parent identifier and returns `true` if the caller should
    /// process the associated event.
    ///
    /// When `parent_id` is `None`, the caller should treat the event as locally
    /// originated and always process it.
    pub fn observe(&mut self, parent_id: Option<LeafHash>) -> bool {
        match parent_id {
            Some(id) => self.seen_parent_ids.insert(id),
            None => true,
        }
    }

    /// Removes a previously recorded parent identifier. Returns `true` when the
    /// identifier was present in the index.
    pub fn remove(&mut self, parent_id: &LeafHash) -> bool {
        self.seen_parent_ids.remove(parent_id)
    }
}

/// Canonical helper implementing the day-based reset check described in the specification.
#[must_use]
pub fn needs_daily_limit_reset(last_reset_ts: u64, now: u64) -> bool {
    if last_reset_ts == 0 {
        return true;
    }
    last_reset_ts / 86_400 != now / 86_400
}

/// Materialized wallet state derived by folding WAL events.
#[derive(Debug, Clone, Default)]
pub struct WalletState {
    wallet_id: Option<WalletId>,
    exists: bool,
    closed: bool,
    balance: u64,
    frozen: bool,
    daily_limit: Option<u64>,
    pending_daily_spent: u64,
    last_limit_reset_ts: u64,
    seen_debit_transfers: HashSet<TransferId>,
    seen_credit_transfers: HashSet<TransferId>,
}

impl WalletState {
    /// Applies an event while performing WALBR0 parent-based deduplication when
    /// a bridge index is provided.
    ///
    /// Returns `true` when the event mutated state and `false` if it was skipped
    /// because the associated `parent_id` had already been observed.
    pub fn apply_with_bridge(
        &mut self,
        event: &WalletEvent,
        parent_id: Option<LeafHash>,
        bridge_index: Option<&mut WalletBridgeIndex>,
    ) -> Result<bool, WalletFoldError> {
        match bridge_index {
            Some(index) => {
                if let Some(parent) = parent_id {
                    if !index.observe(Some(parent)) {
                        return Ok(false);
                    }

                    if let Err(error) = event.apply_to(self) {
                        index.remove(&parent);
                        return Err(error);
                    }

                    Ok(true)
                } else {
                    event.apply_to(self)?;
                    Ok(true)
                }
            }
            None => {
                event.apply_to(self)?;
                Ok(true)
            }
        }
    }

    /// Creates an empty wallet state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the wallet identifier if one has been set.
    #[must_use]
    pub fn wallet_id(&self) -> Option<WalletId> {
        self.wallet_id
    }

    /// Returns whether the wallet currently exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.exists
    }

    /// Returns whether the wallet has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Returns the current wallet balance.
    #[must_use]
    pub fn balance(&self) -> u64 {
        self.balance
    }

    /// Returns whether the wallet is currently frozen.
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// Returns the configured daily limit, if any.
    #[must_use]
    pub fn daily_limit(&self) -> Option<u64> {
        self.daily_limit
    }

    /// Returns the amount spent in the current daily window.
    #[must_use]
    pub fn pending_daily_spent(&self) -> u64 {
        self.pending_daily_spent
    }

    /// Returns the timestamp that anchors the current daily limit window.
    #[must_use]
    pub fn last_limit_reset_ts(&self) -> u64 {
        self.last_limit_reset_ts
    }

    /// Applies a wallet opening event.
    pub fn apply_open(&mut self, event: &WalletOpenEvent) -> Result<(), WalletFoldError> {
        let expected = WalletId::derive(event.realm_id, event.ctx_id, &event.currency)?;
        if expected != event.wallet_id {
            return Err(WalletFoldError::WalletIdMismatch {
                expected,
                actual: event.wallet_id,
            });
        }

        if let Some(current) = self.wallet_id {
            if current != event.wallet_id {
                return Err(WalletFoldError::WalletIdMismatch {
                    expected: current,
                    actual: event.wallet_id,
                });
            }
        } else {
            self.wallet_id = Some(event.wallet_id);
        }

        self.exists = true;
        self.closed = false;
        self.balance = 0;
        self.frozen = false;
        self.daily_limit = None;
        self.pending_daily_spent = 0;
        self.last_limit_reset_ts = event.created_at;
        self.seen_debit_transfers.clear();
        self.seen_credit_transfers.clear();

        Ok(())
    }

    /// Applies a wallet closing event.
    pub fn apply_close(&mut self, event: &WalletCloseEvent) -> Result<(), WalletFoldError> {
        if !self.exists {
            return Ok(());
        }

        self.expect_wallet(event.wallet_id)?;
        self.closed = true;
        Ok(())
    }

    /// Applies a deposit event.
    pub fn apply_deposit(&mut self, event: &WalletDepositEvent) -> Result<(), WalletFoldError> {
        self.expect_wallet(event.wallet_id)?;
        self.ensure_open()?;
        self.balance = self
            .balance
            .checked_add(event.amount)
            .ok_or(WalletFoldError::BalanceOverflow)?;
        Ok(())
    }

    /// Applies a withdrawal event.
    pub fn apply_withdraw(&mut self, event: &WalletWithdrawEvent) -> Result<(), WalletFoldError> {
        self.expect_wallet(event.wallet_id)?;
        self.debit(event.amount, event.ts)
    }

    /// Applies a transfer event, handling both source debits and destination credits.
    pub fn apply_transfer(&mut self, event: &WalletTransferEvent) -> Result<(), WalletFoldError> {
        let wallet_id = self.wallet_id.ok_or(WalletFoldError::WalletIdUnknown)?;

        if event.wallet_id == wallet_id && event.to_wallet_id == wallet_id {
            if self.seen_debit_transfers.contains(&event.transfer_id)
                && self.seen_credit_transfers.contains(&event.transfer_id)
            {
                return Ok(());
            }
            self.ensure_active()?;
            self.seen_debit_transfers.insert(event.transfer_id);
            self.seen_credit_transfers.insert(event.transfer_id);
            return Ok(());
        }

        if event.wallet_id == wallet_id {
            if self.seen_debit_transfers.contains(&event.transfer_id) {
                return Ok(());
            }
            self.debit(event.amount, event.ts)?;
            self.seen_debit_transfers.insert(event.transfer_id);
            return Ok(());
        }

        if event.to_wallet_id == wallet_id {
            if self.seen_credit_transfers.contains(&event.transfer_id) {
                return Ok(());
            }
            self.ensure_open()?;
            self.balance = self
                .balance
                .checked_add(event.amount)
                .ok_or(WalletFoldError::BalanceOverflow)?;
            self.seen_credit_transfers.insert(event.transfer_id);
            return Ok(());
        }

        Err(WalletFoldError::TransferNotApplicable {
            wallet_id,
            event_wallet_id: event.wallet_id,
            to_wallet_id: event.to_wallet_id,
        })
    }

    /// Applies an adjustment event.
    pub fn apply_adjust(&mut self, event: &WalletAdjustEvent) -> Result<(), WalletFoldError> {
        self.expect_wallet(event.wallet_id)?;
        self.ensure_open()?;

        let current = i128::from(self.balance);
        let new_balance = current + event.delta;
        if new_balance < 0 {
            return Err(WalletFoldError::NegativeBalance);
        }
        let new_balance =
            u64::try_from(new_balance).map_err(|_| WalletFoldError::BalanceOverflow)?;
        self.balance = new_balance;
        Ok(())
    }

    /// Applies a limit configuration event.
    pub fn apply_limit(&mut self, event: &WalletLimitEvent) -> Result<(), WalletFoldError> {
        self.expect_wallet(event.wallet_id)?;
        self.ensure_open()?;

        self.daily_limit = event.daily_limit;
        match self.daily_limit {
            Some(_) => {
                if self.last_limit_reset_ts == 0
                    || needs_daily_limit_reset(self.last_limit_reset_ts, event.ts)
                {
                    self.pending_daily_spent = 0;
                    self.last_limit_reset_ts = event.ts;
                }
            }
            None => {
                self.pending_daily_spent = 0;
                self.last_limit_reset_ts = 0;
            }
        }

        Ok(())
    }

    /// Applies a freeze event.
    pub fn apply_freeze(&mut self, event: &WalletFreezeEvent) -> Result<(), WalletFoldError> {
        if !self.exists {
            return Err(WalletFoldError::WalletNotOpen);
        }
        self.expect_wallet(event.wallet_id)?;
        self.frozen = true;
        Ok(())
    }

    /// Applies an unfreeze event.
    pub fn apply_unfreeze(&mut self, event: &WalletUnfreezeEvent) -> Result<(), WalletFoldError> {
        if !self.exists {
            return Err(WalletFoldError::WalletNotOpen);
        }
        self.expect_wallet(event.wallet_id)?;
        self.frozen = false;
        Ok(())
    }

    fn expect_wallet(&self, wallet_id: WalletId) -> Result<(), WalletFoldError> {
        if !self.exists {
            return Err(WalletFoldError::WalletNotOpen);
        }
        if let Some(current) = self.wallet_id {
            if current != wallet_id {
                return Err(WalletFoldError::WalletIdMismatch {
                    expected: current,
                    actual: wallet_id,
                });
            }
        } else {
            return Err(WalletFoldError::WalletIdUnknown);
        }
        Ok(())
    }

    fn ensure_open(&self) -> Result<(), WalletFoldError> {
        if !self.exists {
            return Err(WalletFoldError::WalletNotOpen);
        }
        if self.closed {
            return Err(WalletFoldError::WalletClosed);
        }
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), WalletFoldError> {
        self.ensure_open()?;
        if self.frozen {
            return Err(WalletFoldError::WalletFrozen);
        }
        Ok(())
    }

    fn debit(&mut self, amount: u64, ts: u64) -> Result<(), WalletFoldError> {
        self.ensure_active()?;

        let pending_update = self.evaluate_daily_limit(amount, ts)?;

        if self.balance < amount {
            return Err(WalletFoldError::InsufficientFunds {
                balance: self.balance,
                amount,
            });
        }

        self.balance = self
            .balance
            .checked_sub(amount)
            .ok_or(WalletFoldError::BalanceUnderflow)?;

        if let Some((new_pending, reset)) = pending_update {
            if reset || self.last_limit_reset_ts == 0 {
                self.pending_daily_spent = 0;
                self.last_limit_reset_ts = ts;
            }
            self.pending_daily_spent = new_pending;
        }

        Ok(())
    }

    fn evaluate_daily_limit(
        &self,
        amount: u64,
        ts: u64,
    ) -> Result<Option<(u64, bool)>, WalletFoldError> {
        if let Some(limit) = self.daily_limit {
            let mut pending = self.pending_daily_spent;
            let mut reset = false;
            if needs_daily_limit_reset(self.last_limit_reset_ts, ts) {
                pending = 0;
                reset = true;
            }
            let new_pending = pending
                .checked_add(amount)
                .ok_or(WalletFoldError::DailySpentOverflow)?;
            if new_pending > limit {
                return Err(WalletFoldError::DailyLimitExceeded {
                    limit,
                    attempted: new_pending,
                });
            }
            Ok(Some((new_pending, reset)))
        } else {
            Ok(None)
        }
    }
}

/// Returns the canonical wallet stream identifier,
/// `stream_id_wallet = Ht("wallet/stream", wallet_id)`.
#[must_use]
pub fn stream_id_wallet(wallet_id: WalletId) -> StreamId {
    StreamId::from(ht("wallet/stream", wallet_id.as_ref()))
}

/// Computes the canonical approval hash used for multisignature policies,
/// `approval_hash = Ht("wallet/approval", wallet_id || to_wallet_id ||
/// u64be(amount) || u64be(ts) || transfer_id)`.
#[must_use]
pub fn approval_hash(
    wallet_id: WalletId,
    to_wallet_id: WalletId,
    amount: u64,
    ts: u64,
    transfer_id: TransferId,
) -> [u8; 32] {
    let mut data =
        Vec::with_capacity(WALLET_ID_LEN * 2 + std::mem::size_of::<u64>() * 2 + TRANSFER_ID_LEN);
    data.extend_from_slice(wallet_id.as_ref());
    data.extend_from_slice(to_wallet_id.as_ref());
    data.extend_from_slice(&amount.to_be_bytes());
    data.extend_from_slice(&ts.to_be_bytes());
    data.extend_from_slice(transfer_id.as_ref());
    ht("wallet/approval", &data)
}

/// Returns the schema identifier for `wallet.open.v1`.
#[must_use]
pub fn schema_wallet_open() -> [u8; 32] {
    h(b"wallet.open.v1")
}

/// Returns the schema identifier for `wallet.close.v1`.
#[must_use]
pub fn schema_wallet_close() -> [u8; 32] {
    h(b"wallet.close.v1")
}

/// Returns the schema identifier for `wallet.deposit.v1`.
#[must_use]
pub fn schema_wallet_deposit() -> [u8; 32] {
    h(b"wallet.deposit.v1")
}

/// Returns the schema identifier for `wallet.withdraw.v1`.
#[must_use]
pub fn schema_wallet_withdraw() -> [u8; 32] {
    h(b"wallet.withdraw.v1")
}

/// Returns the schema identifier for `wallet.transfer.v1`.
#[must_use]
pub fn schema_wallet_transfer() -> [u8; 32] {
    h(b"wallet.transfer.v1")
}

/// Returns the schema identifier for `wallet.adjust.v1`.
#[must_use]
pub fn schema_wallet_adjust() -> [u8; 32] {
    h(b"wallet.adjust.v1")
}

/// Returns the schema identifier for `wallet.limit.v1`.
#[must_use]
pub fn schema_wallet_limit() -> [u8; 32] {
    h(b"wallet.limit.v1")
}

/// Returns the schema identifier for `wallet.freeze.v1`.
#[must_use]
pub fn schema_wallet_freeze() -> [u8; 32] {
    h(b"wallet.freeze.v1")
}

/// Returns the schema identifier for `wallet.unfreeze.v1`.
#[must_use]
pub fn schema_wallet_unfreeze() -> [u8; 32] {
    h(b"wallet.unfreeze.v1")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::wire::types::LeafHash;

    fn sample_key(prefix: u8) -> [u8; WALLET_ID_LEN] {
        let mut out = [0u8; WALLET_ID_LEN];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = prefix.wrapping_add(index as u8);
        }
        out
    }

    #[test]
    fn wallet_bridge_index_tracks_parent_ids() {
        let parent_a = LeafHash::new([0x11; 32]);
        let parent_b = LeafHash::new([0x22; 32]);

        let mut index = WalletBridgeIndex::new();
        assert!(index.observe(Some(parent_a)));
        assert!(
            !index.observe(Some(parent_a)),
            "duplicate parent should be ignored"
        );
        assert!(index.observe(Some(parent_b)));
        assert_eq!(index.len(), 2);
        assert!(index.has_seen(&parent_a));
        assert!(
            index.observe(None),
            "locally originated events always apply"
        );
        assert_eq!(index.len(), 2, "local events do not mutate state");

        index.clear();
        assert!(index.is_empty());
    }

    #[test]
    fn wallet_state_skips_duplicate_bridged_events() {
        let (mut state, wallet_id, _, _, created_at) =
            open_wallet_state("realm-bridge", 0x21, "USD");
        let deposit = WalletDepositEvent {
            wallet_id,
            amount: 100,
            ts: created_at + 10,
            reference: None,
        };
        let event = WalletEvent::Deposit(deposit);
        let parent_id = LeafHash::new([0xAB; 32]);
        let mut index = WalletBridgeIndex::new();

        let applied = state
            .apply_with_bridge(&event, Some(parent_id), Some(&mut index))
            .expect("apply deposit");
        assert!(applied);
        assert_eq!(state.balance(), 100);

        let applied = state
            .apply_with_bridge(&event, Some(parent_id), Some(&mut index))
            .expect("dedupe");
        assert!(!applied, "duplicate bridged event should be ignored");
        assert_eq!(state.balance(), 100);
        assert!(index.has_seen(&parent_id));
    }

    #[test]
    fn wallet_state_bridge_index_not_marked_on_error() {
        let (mut state, wallet_id, _, _, created_at) =
            open_wallet_state("realm-bridge-error", 0x22, "USD");
        let wrong_wallet = WalletId::new([0x44; WALLET_ID_LEN]);
        let bad_event = WalletEvent::Deposit(WalletDepositEvent {
            wallet_id: wrong_wallet,
            amount: 50,
            ts: created_at + 5,
            reference: None,
        });
        let parent_id = LeafHash::new([0xCD; 32]);
        let mut index = WalletBridgeIndex::new();

        let err = state
            .apply_with_bridge(&bad_event, Some(parent_id), Some(&mut index))
            .expect_err("wallet id mismatch");
        assert!(matches!(err, WalletFoldError::WalletIdMismatch { .. }));
        assert!(!index.has_seen(&parent_id));

        let good_event = WalletEvent::Deposit(WalletDepositEvent {
            wallet_id,
            amount: 50,
            ts: created_at + 6,
            reference: None,
        });
        let applied = state
            .apply_with_bridge(&good_event, Some(parent_id), Some(&mut index))
            .expect("apply after fix");
        assert!(applied);
        assert_eq!(state.balance(), 50);
        assert!(index.has_seen(&parent_id));
    }

    #[test]
    fn wallet_state_local_events_ignore_bridge_index() {
        let (mut state, wallet_id, _, _, created_at) =
            open_wallet_state("realm-local", 0x23, "USD");
        let deposit_event = WalletEvent::Deposit(WalletDepositEvent {
            wallet_id,
            amount: 75,
            ts: created_at + 3,
            reference: None,
        });
        let mut index = WalletBridgeIndex::new();

        let applied = state
            .apply_with_bridge(&deposit_event, None, Some(&mut index))
            .expect("local deposit");
        assert!(applied);
        assert_eq!(state.balance(), 75);
        assert_eq!(index.len(), 0, "local events must not mutate index");
    }

    fn open_wallet_state(
        realm_name: &str,
        key_prefix: u8,
        currency: &str,
    ) -> (WalletState, WalletId, RealmId, ContextId, u64) {
        let realm = RealmId::derive(realm_name);
        let principal_pk = sample_key(key_prefix);
        let ctx = ContextId::derive(principal_pk, realm).expect("ctx id");
        let wallet_id = WalletId::derive(realm, ctx, currency).expect("wallet id");
        let created_at = 1_700_000_000u64 + key_prefix as u64;
        let open_event = WalletOpenEvent {
            wallet_id,
            realm_id: realm,
            ctx_id: ctx,
            currency: currency.to_string(),
            created_at,
        };
        let mut state = WalletState::new();
        state.apply_open(&open_event).expect("apply open");
        (state, wallet_id, realm, ctx, created_at)
    }

    #[test]
    fn wallet_id_matches_spec_formula() {
        let realm = RealmId::derive("example-realm");
        let principal_pk = sample_key(0x11);
        let ctx = ContextId::derive(principal_pk, realm).expect("ctx id");
        let wallet = WalletId::derive(realm, ctx, "USD").expect("wallet id");

        let mut data = Vec::new();
        data.extend_from_slice(realm.as_ref());
        data.extend_from_slice(ctx.as_ref());
        data.extend_from_slice(b"USD");

        assert_eq!(wallet.as_bytes(), &ht("wallet/id", &data));
    }

    #[test]
    fn wallet_id_from_slice_enforces_length() {
        let bytes = [0xAA; WALLET_ID_LEN];
        let wallet = WalletId::from_slice(&bytes).expect("wallet id");
        assert_eq!(wallet.as_bytes(), &bytes);

        let err = WalletId::from_slice(&bytes[..WALLET_ID_LEN - 1]).expect_err("length error");
        assert_eq!(err.expected(), WALLET_ID_LEN);
        assert_eq!(err.actual(), WALLET_ID_LEN - 1);
    }

    #[test]
    fn stream_id_wallet_matches_spec_formula() {
        let realm = RealmId::derive("realm-x");
        let ctx = ContextId::new([0x22; WALLET_ID_LEN]);
        let wallet = WalletId::derive(realm, ctx, "JPY").expect("wallet id");
        let stream = stream_id_wallet(wallet);
        assert_eq!(stream.as_bytes(), &ht("wallet/stream", wallet.as_ref()));
    }

    #[test]
    fn wallet_currency_code_must_be_ascii() {
        let realm = RealmId::derive("realm-y");
        let ctx = ContextId::new([0x33; WALLET_ID_LEN]);
        let err = WalletId::derive(realm, ctx, "円JPY").expect_err("non-ascii");
        match err {
            WalletError::NonAsciiCurrency { index, .. } => assert_eq!(index, 0),
        }
    }

    #[test]
    fn transfer_id_matches_spec_formula() {
        let msg_id = [0x44; TRANSFER_ID_LEN];
        let transfer = TransferId::derive(msg_id).expect("transfer id");
        assert_eq!(transfer.as_bytes(), &ht("wallet/xfer", &msg_id));
    }

    #[test]
    fn transfer_id_from_slice_enforces_length() {
        let bytes = [0x77; TRANSFER_ID_LEN];
        let transfer = TransferId::from_slice(&bytes).expect("transfer id");
        assert_eq!(transfer.as_bytes(), &bytes);

        let err = TransferId::from_slice(&bytes[..TRANSFER_ID_LEN - 1]).expect_err("length error");
        assert_eq!(err.expected(), TRANSFER_ID_LEN);
        assert_eq!(err.actual(), TRANSFER_ID_LEN - 1);
    }

    #[test]
    fn approval_hash_matches_spec_formula() {
        let wallet_a = WalletId::new([0x01; WALLET_ID_LEN]);
        let wallet_b = WalletId::new([0x02; WALLET_ID_LEN]);
        let transfer = TransferId::derive([0xAB; TRANSFER_ID_LEN]).expect("transfer id");
        let amount = 1_000u64;
        let ts = 1_696_000_000u64;

        let hash = approval_hash(wallet_a, wallet_b, amount, ts, transfer);

        let mut data = Vec::new();
        data.extend_from_slice(wallet_a.as_ref());
        data.extend_from_slice(wallet_b.as_ref());
        data.extend_from_slice(&amount.to_be_bytes());
        data.extend_from_slice(&ts.to_be_bytes());
        data.extend_from_slice(transfer.as_ref());

        assert_eq!(hash, ht("wallet/approval", &data));
    }

    #[test]
    fn daily_limit_reset_follows_day_boundary() {
        let base = 1_700_000_000u64;
        assert!(needs_daily_limit_reset(0, base));
        assert!(!needs_daily_limit_reset(base, base + 3_600));
        assert!(needs_daily_limit_reset(base, base + 86_400));
    }

    #[test]
    fn wallet_state_open_initializes_fields() {
        let (state, wallet_id, _, _, created_at) =
            open_wallet_state("realm-open-init", 0x20, "USD");
        assert_eq!(state.wallet_id(), Some(wallet_id));
        assert!(state.exists());
        assert!(!state.is_closed());
        assert_eq!(state.balance(), 0);
        assert!(!state.is_frozen());
        assert_eq!(state.daily_limit(), None);
        assert_eq!(state.pending_daily_spent(), 0);
        assert_eq!(state.last_limit_reset_ts(), created_at);
    }

    #[test]
    fn wallet_state_open_rejects_mismatched_wallet_id() {
        let realm = RealmId::derive("realm-open-mismatch");
        let principal_pk = sample_key(0x30);
        let ctx = ContextId::derive(principal_pk, realm).expect("ctx id");
        let open = WalletOpenEvent {
            wallet_id: WalletId::new([0xAA; WALLET_ID_LEN]),
            realm_id: realm,
            ctx_id: ctx,
            currency: "USD".to_string(),
            created_at: 1_700_000_123,
        };
        let mut state = WalletState::new();
        let err = state.apply_open(&open).expect_err("wallet mismatch");
        assert!(matches!(err, WalletFoldError::WalletIdMismatch { .. }));
    }

    #[test]
    fn wallet_state_withdraw_enforces_balance_and_limit() {
        let (mut state, wallet_id, _, _, created_at) =
            open_wallet_state("realm-withdraw", 0x40, "EUR");
        state
            .apply_deposit(&WalletDepositEvent {
                wallet_id,
                amount: 500,
                ts: created_at + 1,
                reference: None,
            })
            .unwrap();
        state
            .apply_limit(&WalletLimitEvent {
                wallet_id,
                daily_limit: Some(200),
                ts: created_at + 2,
            })
            .unwrap();
        state
            .apply_withdraw(&WalletWithdrawEvent {
                wallet_id,
                amount: 150,
                ts: created_at + 10,
                reference: None,
            })
            .unwrap();
        assert_eq!(state.balance(), 350);
        assert_eq!(state.pending_daily_spent(), 150);

        let err = state
            .apply_withdraw(&WalletWithdrawEvent {
                wallet_id,
                amount: 100,
                ts: created_at + 20,
                reference: None,
            })
            .expect_err("daily limit exceeded");
        assert!(matches!(err, WalletFoldError::DailyLimitExceeded { .. }));
        assert_eq!(state.balance(), 350);
        assert_eq!(state.pending_daily_spent(), 150);

        state
            .apply_withdraw(&WalletWithdrawEvent {
                wallet_id,
                amount: 100,
                ts: created_at + 86_400 + 5,
                reference: None,
            })
            .unwrap();
        assert_eq!(state.balance(), 250);
        assert_eq!(state.pending_daily_spent(), 100);
        assert_eq!(state.last_limit_reset_ts(), created_at + 86_400 + 5);
    }

    #[test]
    fn wallet_state_transfer_updates_source_and_destination() {
        let (mut source, source_wallet, realm, _, created_at) =
            open_wallet_state("realm-transfer", 0x50, "USD");
        source
            .apply_deposit(&WalletDepositEvent {
                wallet_id: source_wallet,
                amount: 300,
                ts: created_at + 1,
                reference: None,
            })
            .unwrap();
        source
            .apply_limit(&WalletLimitEvent {
                wallet_id: source_wallet,
                daily_limit: Some(500),
                ts: created_at + 2,
            })
            .unwrap();

        let dest_principal = sample_key(0x60);
        let dest_ctx = ContextId::derive(dest_principal, realm).expect("dest ctx");
        let dest_wallet = WalletId::derive(realm, dest_ctx, "USD").expect("dest wallet");
        let dest_open = WalletOpenEvent {
            wallet_id: dest_wallet,
            realm_id: realm,
            ctx_id: dest_ctx,
            currency: "USD".into(),
            created_at: created_at + 3,
        };
        let mut dest = WalletState::new();
        dest.apply_open(&dest_open).unwrap();

        let transfer_id = TransferId::derive([0x12; TRANSFER_ID_LEN]).expect("transfer id");
        let transfer = WalletTransferEvent {
            wallet_id: source_wallet,
            to_wallet_id: dest_wallet,
            amount: 120,
            ts: created_at + 4,
            transfer_id,
            metadata: None,
        };

        source.apply_transfer(&transfer).unwrap();
        assert_eq!(source.balance(), 180);
        assert_eq!(source.pending_daily_spent(), 120);

        dest.apply_transfer(&transfer).unwrap();
        assert_eq!(dest.balance(), 120);

        source.apply_transfer(&transfer).unwrap();
        dest.apply_transfer(&transfer).unwrap();
        assert_eq!(source.balance(), 180);
        assert_eq!(dest.balance(), 120);
    }

    #[test]
    fn wallet_state_self_transfer_is_noop_and_idempotent() {
        let (mut state, wallet_id, _, _, created_at) =
            open_wallet_state("realm-self-transfer", 0x51, "USD");
        state
            .apply_deposit(&WalletDepositEvent {
                wallet_id,
                amount: 200,
                ts: created_at + 1,
                reference: None,
            })
            .unwrap();

        let transfer_id = TransferId::derive([0x34; TRANSFER_ID_LEN]).expect("transfer id");
        let transfer = WalletTransferEvent {
            wallet_id,
            to_wallet_id: wallet_id,
            amount: 150,
            ts: created_at + 2,
            transfer_id,
            metadata: None,
        };

        state.apply_transfer(&transfer).unwrap();
        assert_eq!(state.balance(), 200);
        assert_eq!(state.pending_daily_spent(), 0);

        state.apply_transfer(&transfer).unwrap();
        assert_eq!(state.balance(), 200);
        assert_eq!(state.pending_daily_spent(), 0);
    }

    #[test]
    fn wallet_state_adjust_respects_non_negative_balance() {
        let (mut state, wallet_id, _, _, created_at) =
            open_wallet_state("realm-adjust", 0x70, "USD");
        state
            .apply_deposit(&WalletDepositEvent {
                wallet_id,
                amount: 100,
                ts: created_at + 1,
                reference: None,
            })
            .unwrap();
        state
            .apply_adjust(&WalletAdjustEvent {
                wallet_id,
                delta: 25,
                ts: created_at + 2,
                reason: "bonus".into(),
                reference: None,
            })
            .unwrap();
        assert_eq!(state.balance(), 125);

        let err = state
            .apply_adjust(&WalletAdjustEvent {
                wallet_id,
                delta: -200,
                ts: created_at + 3,
                reason: "reversal".into(),
                reference: None,
            })
            .expect_err("negative balance");
        assert!(matches!(err, WalletFoldError::NegativeBalance));
        assert_eq!(state.balance(), 125);
    }

    #[test]
    fn wallet_state_freeze_blocks_outgoing_debits() {
        let (mut state, wallet_id, _, _, created_at) =
            open_wallet_state("realm-freeze", 0x80, "USD");
        state
            .apply_deposit(&WalletDepositEvent {
                wallet_id,
                amount: 80,
                ts: created_at + 1,
                reference: None,
            })
            .unwrap();
        state
            .apply_freeze(&WalletFreezeEvent {
                wallet_id,
                ts: created_at + 2,
                reason: Some("investigation".into()),
            })
            .unwrap();

        let err = state
            .apply_withdraw(&WalletWithdrawEvent {
                wallet_id,
                amount: 10,
                ts: created_at + 3,
                reference: None,
            })
            .expect_err("wallet frozen");
        assert!(matches!(err, WalletFoldError::WalletFrozen));
        assert_eq!(state.balance(), 80);

        state
            .apply_unfreeze(&WalletUnfreezeEvent {
                wallet_id,
                ts: created_at + 4,
                reason: None,
            })
            .unwrap();
        state
            .apply_withdraw(&WalletWithdrawEvent {
                wallet_id,
                amount: 10,
                ts: created_at + 5,
                reference: None,
            })
            .unwrap();
        assert_eq!(state.balance(), 70);
    }

    #[test]
    fn wallet_state_close_prevents_mutations() {
        let (mut state, wallet_id, _, _, created_at) =
            open_wallet_state("realm-close", 0x90, "USD");
        state
            .apply_close(&WalletCloseEvent {
                wallet_id,
                ts: created_at + 1,
            })
            .unwrap();
        assert!(state.is_closed());

        let err = state
            .apply_deposit(&WalletDepositEvent {
                wallet_id,
                amount: 10,
                ts: created_at + 2,
                reference: None,
            })
            .expect_err("wallet closed");
        assert!(matches!(err, WalletFoldError::WalletClosed));
    }

    #[test]
    fn wallet_state_reopen_resets_state() {
        let (mut state, wallet_id, realm_id, ctx_id, created_at) =
            open_wallet_state("realm-reopen", 0x91, "USD");

        state
            .apply_deposit(&WalletDepositEvent {
                wallet_id,
                amount: 200,
                ts: created_at + 1,
                reference: None,
            })
            .unwrap();
        state
            .apply_limit(&WalletLimitEvent {
                wallet_id,
                daily_limit: Some(150),
                ts: created_at + 2,
            })
            .unwrap();
        state
            .apply_withdraw(&WalletWithdrawEvent {
                wallet_id,
                amount: 50,
                ts: created_at + 3,
                reference: None,
            })
            .unwrap();
        state
            .apply_freeze(&WalletFreezeEvent {
                wallet_id,
                ts: created_at + 4,
                reason: Some("review".into()),
            })
            .unwrap();
        state
            .apply_close(&WalletCloseEvent {
                wallet_id,
                ts: created_at + 5,
            })
            .unwrap();

        let err = state
            .apply_deposit(&WalletDepositEvent {
                wallet_id,
                amount: 10,
                ts: created_at + 6,
                reference: None,
            })
            .expect_err("wallet closed");
        assert!(matches!(err, WalletFoldError::WalletClosed));

        let reopen_at = created_at + 10;
        let reopen = WalletOpenEvent {
            wallet_id,
            realm_id,
            ctx_id,
            currency: "USD".into(),
            created_at: reopen_at,
        };
        state.apply_open(&reopen).unwrap();

        assert!(state.exists());
        assert!(!state.is_closed());
        assert_eq!(state.balance(), 0);
        assert!(!state.is_frozen());
        assert_eq!(state.daily_limit(), None);
        assert_eq!(state.pending_daily_spent(), 0);
        assert_eq!(state.last_limit_reset_ts(), reopen_at);

        state
            .apply_deposit(&WalletDepositEvent {
                wallet_id,
                amount: 25,
                ts: reopen_at + 1,
                reference: None,
            })
            .unwrap();
        assert_eq!(state.balance(), 25);
    }

    #[test]
    fn transfer_metadata_requires_map() {
        use ciborium::value::Value;
        use ciborium::{de::from_reader, ser::into_writer};

        let transfer_id = TransferId::new([0xAA; TRANSFER_ID_LEN]);
        let wallet_id = WalletId::new([0xBB; WALLET_ID_LEN]);
        let to_wallet_id = WalletId::new([0xCC; WALLET_ID_LEN]);
        let value = Value::Map(vec![
            (
                Value::Text("wallet_id".into()),
                Value::Bytes(wallet_id.as_ref().to_vec()),
            ),
            (
                Value::Text("to_wallet_id".into()),
                Value::Bytes(to_wallet_id.as_ref().to_vec()),
            ),
            (Value::Text("amount".into()), Value::Integer(5u8.into())),
            (Value::Text("ts".into()), Value::Integer(1u8.into())),
            (
                Value::Text("transfer_id".into()),
                Value::Bytes(transfer_id.as_ref().to_vec()),
            ),
            (Value::Text("metadata".into()), Value::Array(vec![])),
        ]);
        let mut buf = Vec::new();
        into_writer(&value, &mut buf).expect("serialize");
        let result: Result<WalletTransferEvent, _> = from_reader(buf.as_slice());
        assert!(result.is_err(), "metadata must be map");
    }

    #[test]
    fn wallet_event_decodes_and_applies() {
        use ciborium::ser::into_writer;

        let realm = RealmId::derive("realm-wallet-event");
        let principal_pk = sample_key(0xA0);
        let ctx = ContextId::derive(principal_pk, realm).expect("ctx id");
        let wallet_id = WalletId::derive(realm, ctx, "USD").expect("wallet id");
        let created_at = 1_700_100_000u64;

        let open = WalletOpenEvent {
            wallet_id,
            realm_id: realm,
            ctx_id: ctx,
            currency: "USD".into(),
            created_at,
        };
        let mut buf = Vec::new();
        into_writer(&open, &mut buf).expect("encode open");

        let event =
            WalletEvent::from_schema_and_body(schema_wallet_open(), &buf).expect("decode open");
        assert!(matches!(event, WalletEvent::Open(_)));

        let mut state = WalletState::new();
        event.apply_to(&mut state).expect("apply open");
        assert!(state.exists());

        let deposit = WalletDepositEvent {
            wallet_id,
            amount: 250,
            ts: created_at + 1,
            reference: None,
        };
        buf.clear();
        into_writer(&deposit, &mut buf).expect("encode deposit");

        let event = WalletEvent::from_schema_and_body(schema_wallet_deposit(), &buf)
            .expect("decode deposit");
        assert!(matches!(event, WalletEvent::Deposit(_)));
        event.apply_to(&mut state).expect("apply deposit");
        assert_eq!(state.balance(), 250);

        let withdraw = WalletWithdrawEvent {
            wallet_id,
            amount: 100,
            ts: created_at + 2,
            reference: None,
        };
        buf.clear();
        into_writer(&withdraw, &mut buf).expect("encode withdraw");

        let event = WalletEvent::from_schema_and_body(schema_wallet_withdraw(), &buf)
            .expect("decode withdraw");
        assert!(matches!(event, WalletEvent::Withdraw(_)));
        event.apply_to(&mut state).expect("apply withdraw");
        assert_eq!(state.balance(), 150);
    }

    #[test]
    fn wallet_event_unknown_schema_rejected() {
        let err = WalletEvent::from_schema_and_body([0xAA; 32], &[]) // invalid schema
            .expect_err("unknown schema");
        assert!(matches!(err, WalletEventDecodeError::UnknownSchema { .. }));
    }

    #[test]
    fn schema_identifiers_match_known_vectors() {
        assert_eq!(
            schema_wallet_open(),
            [
                0xf1, 0xb3, 0x7e, 0x20, 0x7e, 0x51, 0xe7, 0x8a, 0x9f, 0x83, 0xb0, 0x76, 0xad, 0x5d,
                0x14, 0xed, 0xf9, 0xb8, 0x11, 0xa9, 0x80, 0x5d, 0x2d, 0xc4, 0x03, 0xe2, 0x08, 0x2f,
                0x9c, 0x92, 0x4a, 0xea,
            ]
        );
        assert_eq!(
            schema_wallet_close(),
            [
                0x5d, 0x13, 0x56, 0xa5, 0x49, 0x38, 0x44, 0xfe, 0xbc, 0xda, 0x7e, 0xfe, 0x7e, 0xf8,
                0x37, 0xfc, 0x22, 0x06, 0x29, 0xb6, 0x1d, 0xd9, 0x9e, 0x7c, 0x68, 0x94, 0x94, 0x0a,
                0x57, 0xb6, 0x12, 0x12,
            ]
        );
        assert_eq!(
            schema_wallet_deposit(),
            [
                0xed, 0x05, 0x51, 0x13, 0x92, 0x7b, 0x80, 0x0b, 0xe6, 0xce, 0x91, 0xf7, 0x1a, 0x5f,
                0xa9, 0x39, 0xcf, 0xd5, 0x5e, 0x01, 0x42, 0xe3, 0x7b, 0xff, 0x20, 0x5e, 0x12, 0xfa,
                0xdd, 0xe2, 0x02, 0x0e,
            ]
        );
        assert_eq!(
            schema_wallet_withdraw(),
            [
                0x9d, 0x29, 0xf9, 0xcf, 0x92, 0x6c, 0x26, 0x8b, 0xe8, 0xfd, 0x5b, 0x5c, 0xbd, 0x0d,
                0xdb, 0xb5, 0x8d, 0x44, 0x33, 0x14, 0x2f, 0x38, 0x67, 0x4c, 0xd9, 0xf5, 0x06, 0xde,
                0xcc, 0x6c, 0x12, 0x5e,
            ]
        );
        assert_eq!(
            schema_wallet_transfer(),
            [
                0x53, 0x50, 0xcf, 0x85, 0xe6, 0xe0, 0x43, 0x8e, 0xd3, 0x4d, 0xb2, 0x26, 0x94, 0xc3,
                0xf1, 0x42, 0x90, 0x37, 0x19, 0x13, 0x5a, 0xed, 0x65, 0x9f, 0x24, 0x01, 0xfc, 0xba,
                0xff, 0x98, 0x39, 0x11,
            ]
        );
        assert_eq!(
            schema_wallet_adjust(),
            [
                0xdf, 0x4a, 0xf9, 0x96, 0x17, 0x9e, 0x4a, 0x2f, 0x97, 0x23, 0xf7, 0xdb, 0xdd, 0x8c,
                0x62, 0xff, 0x0a, 0x88, 0x31, 0xfc, 0x6e, 0x38, 0x65, 0xf5, 0x50, 0xb8, 0xb2, 0x5a,
                0xdf, 0xcf, 0x3e, 0xa0,
            ]
        );
        assert_eq!(
            schema_wallet_limit(),
            [
                0x61, 0x75, 0x83, 0x74, 0xa8, 0x47, 0x4b, 0x41, 0x54, 0xf3, 0x01, 0x60, 0x3c, 0x35,
                0x19, 0xd7, 0xcb, 0xd8, 0xeb, 0x1f, 0x76, 0x0a, 0xed, 0x05, 0xdd, 0xdf, 0x57, 0xb6,
                0x13, 0x3c, 0x39, 0x79,
            ]
        );
        assert_eq!(
            schema_wallet_freeze(),
            [
                0x25, 0x91, 0x4e, 0x04, 0xbf, 0xb5, 0x42, 0x0b, 0x60, 0xc5, 0x2a, 0x1f, 0xcd, 0x59,
                0x75, 0x01, 0xde, 0xaf, 0xa7, 0x71, 0xb8, 0xce, 0x84, 0xac, 0xa0, 0x81, 0xe3, 0xfd,
                0x29, 0x05, 0x1d, 0x36,
            ]
        );
        assert_eq!(
            schema_wallet_unfreeze(),
            [
                0x75, 0x6d, 0x26, 0xe8, 0x11, 0x7e, 0xfc, 0x33, 0x27, 0x58, 0x40, 0x92, 0xd7, 0x3c,
                0x34, 0xd4, 0x41, 0xea, 0x1a, 0x0e, 0xe8, 0xc5, 0x3b, 0x05, 0x66, 0xab, 0xb0, 0x06,
                0x11, 0x02, 0x73, 0x12,
            ]
        );
    }
}
