use std::{convert::TryFrom, fmt};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{
    hash::{h, ht},
    identity::ContextId,
    label::StreamId,
    realm::RealmId,
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

    fn sample_key(prefix: u8) -> [u8; WALLET_ID_LEN] {
        let mut out = [0u8; WALLET_ID_LEN];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = prefix.wrapping_add(index as u8);
        }
        out
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
