use std::{convert::TryFrom, fmt};

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ht, label::StreamId, realm::RealmId, LengthError};

const ID_LEN: usize = 32;
const ED25519_PUBLIC_KEY_LEN: usize = 32;

fn ensure_ed25519_public_key_len(bytes: &[u8]) -> Result<(), LengthError> {
    if bytes.len() != ED25519_PUBLIC_KEY_LEN {
        Err(LengthError::new(ED25519_PUBLIC_KEY_LEN, bytes.len()))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrincipalId([u8; ID_LEN]);

impl PrincipalId {
    #[must_use]
    pub const fn new(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != ID_LEN {
            return Err(LengthError::new(ID_LEN, bytes.len()));
        }
        let mut out = [0u8; ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    pub fn derive(principal_pk: impl AsRef<[u8]>) -> Result<Self, LengthError> {
        let principal_pk = principal_pk.as_ref();
        ensure_ed25519_public_key_len(principal_pk)?;
        Ok(Self::from(ht("id/principal", principal_pk)))
    }
}

impl From<[u8; ID_LEN]> for PrincipalId {
    fn from(value: [u8; ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; ID_LEN]> for PrincipalId {
    fn from(value: &[u8; ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for PrincipalId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for PrincipalId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for PrincipalId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for PrincipalId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct PrincipalIdVisitor;

impl<'de> Visitor<'de> for PrincipalIdVisitor {
    type Value = PrincipalId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN principal identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        PrincipalId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for PrincipalId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PrincipalIdVisitor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContextId([u8; ID_LEN]);

impl ContextId {
    #[must_use]
    pub const fn new(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != ID_LEN {
            return Err(LengthError::new(ID_LEN, bytes.len()));
        }
        let mut out = [0u8; ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    pub fn derive(principal_pk: impl AsRef<[u8]>, realm_id: RealmId) -> Result<Self, LengthError> {
        let principal_pk = principal_pk.as_ref();
        ensure_ed25519_public_key_len(principal_pk)?;
        let mut data = Vec::with_capacity(ED25519_PUBLIC_KEY_LEN + ID_LEN);
        data.extend_from_slice(principal_pk);
        data.extend_from_slice(realm_id.as_ref());
        Ok(Self::from(ht("id/ctx", &data)))
    }
}

impl From<[u8; ID_LEN]> for ContextId {
    fn from(value: [u8; ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; ID_LEN]> for ContextId {
    fn from(value: &[u8; ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for ContextId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for ContextId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for ContextId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for ContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for ContextId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct ContextIdVisitor;

impl<'de> Visitor<'de> for ContextIdVisitor {
    type Value = ContextId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN context identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        ContextId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for ContextId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ContextIdVisitor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId([u8; ID_LEN]);

impl DeviceId {
    #[must_use]
    pub const fn new(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != ID_LEN {
            return Err(LengthError::new(ID_LEN, bytes.len()));
        }
        let mut out = [0u8; ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    pub fn derive(device_pk: impl AsRef<[u8]>) -> Result<Self, LengthError> {
        let device_pk = device_pk.as_ref();
        ensure_ed25519_public_key_len(device_pk)?;
        Ok(Self::from(ht("id/device", device_pk)))
    }
}

impl From<[u8; ID_LEN]> for DeviceId {
    fn from(value: [u8; ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; ID_LEN]> for DeviceId {
    fn from(value: &[u8; ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for DeviceId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for DeviceId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for DeviceId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for DeviceId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct DeviceIdVisitor;

impl<'de> Visitor<'de> for DeviceIdVisitor {
    type Value = DeviceId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN device identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        DeviceId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(DeviceIdVisitor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrgId([u8; ID_LEN]);

impl OrgId {
    #[must_use]
    pub const fn new(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != ID_LEN {
            return Err(LengthError::new(ID_LEN, bytes.len()));
        }
        let mut out = [0u8; ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    pub fn derive(org_pk: impl AsRef<[u8]>) -> Result<Self, LengthError> {
        let org_pk = org_pk.as_ref();
        ensure_ed25519_public_key_len(org_pk)?;
        Ok(Self::from(ht("id/org", org_pk)))
    }
}

impl From<[u8; ID_LEN]> for OrgId {
    fn from(value: [u8; ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; ID_LEN]> for OrgId {
    fn from(value: &[u8; ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for OrgId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for OrgId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for OrgId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for OrgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for OrgId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct OrgIdVisitor;

impl<'de> Visitor<'de> for OrgIdVisitor {
    type Value = OrgId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN organization identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        OrgId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for OrgId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(OrgIdVisitor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopedOrgId([u8; ID_LEN]);

impl ScopedOrgId {
    #[must_use]
    pub const fn new(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != ID_LEN {
            return Err(LengthError::new(ID_LEN, bytes.len()));
        }
        let mut out = [0u8; ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    #[must_use]
    pub fn derive(org_id: OrgId, realm_id: RealmId) -> Self {
        let mut data = Vec::with_capacity(ID_LEN * 2);
        data.extend_from_slice(org_id.as_ref());
        data.extend_from_slice(realm_id.as_ref());
        Self::from(ht("id/org/realm", &data))
    }
}

impl From<[u8; ID_LEN]> for ScopedOrgId {
    fn from(value: [u8; ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; ID_LEN]> for ScopedOrgId {
    fn from(value: &[u8; ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for ScopedOrgId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for ScopedOrgId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for ScopedOrgId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for ScopedOrgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for ScopedOrgId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct ScopedOrgIdVisitor;

impl<'de> Visitor<'de> for ScopedOrgIdVisitor {
    type Value = ScopedOrgId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN scoped-organization identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        ScopedOrgId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for ScopedOrgId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ScopedOrgIdVisitor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId([u8; ID_LEN]);

impl GroupId {
    #[must_use]
    pub const fn new(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, LengthError> {
        if bytes.len() != ID_LEN {
            return Err(LengthError::new(ID_LEN, bytes.len()));
        }
        let mut out = [0u8; ID_LEN];
        out.copy_from_slice(bytes);
        Ok(Self::new(out))
    }

    #[must_use]
    pub fn derive(org_id: OrgId, group_local_name: impl AsRef<str>) -> Self {
        let name = group_local_name.as_ref();
        let mut data = Vec::with_capacity(ID_LEN + name.len());
        data.extend_from_slice(org_id.as_ref());
        data.extend_from_slice(name.as_bytes());
        Self::from(ht("id/group", &data))
    }
}

impl From<[u8; ID_LEN]> for GroupId {
    fn from(value: [u8; ID_LEN]) -> Self {
        Self::new(value)
    }
}

impl From<&[u8; ID_LEN]> for GroupId {
    fn from(value: &[u8; ID_LEN]) -> Self {
        Self::new(*value)
    }
}

impl TryFrom<&[u8]> for GroupId {
    type Error = LengthError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

impl TryFrom<Vec<u8>> for GroupId {
    type Error = LengthError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_slice(&value)
    }
}

impl AsRef<[u8]> for GroupId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for GroupId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

struct GroupIdVisitor;

impl<'de> Visitor<'de> for GroupIdVisitor {
    type Value = GroupId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte VEEN group identifier")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        GroupId::from_slice(v).map_err(|err| E::invalid_length(err.actual(), &self))
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_bytes(&v)
    }
}

impl<'de> Deserialize<'de> for GroupId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(GroupIdVisitor)
    }
}

pub fn stream_id_principal(principal_pk: impl AsRef<[u8]>) -> Result<StreamId, LengthError> {
    let principal_pk = principal_pk.as_ref();
    ensure_ed25519_public_key_len(principal_pk)?;
    Ok(StreamId::from(ht("id/stream/principal", principal_pk)))
}

#[must_use]
pub fn stream_id_ctx(ctx_id: ContextId, realm_id: RealmId) -> StreamId {
    let mut data = Vec::with_capacity(ID_LEN * 2);
    data.extend_from_slice(ctx_id.as_ref());
    data.extend_from_slice(realm_id.as_ref());
    StreamId::from(ht("id/stream/ctx", &data))
}

#[must_use]
pub fn stream_id_org(org_id: OrgId) -> StreamId {
    StreamId::from(ht("id/stream/org", org_id.as_ref()))
}

#[must_use]
pub fn stream_id_handle_ns(realm_id: RealmId) -> StreamId {
    StreamId::from(ht("id/stream/handle", realm_id.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key(prefix: u8) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        let mut out = [0u8; ED25519_PUBLIC_KEY_LEN];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = prefix.wrapping_add(index as u8);
        }
        out
    }

    #[test]
    fn principal_id_matches_spec_formula() {
        let pk = sample_key(0x10);
        let principal_id = PrincipalId::derive(pk).expect("principal id");
        assert_eq!(principal_id.as_bytes(), &ht("id/principal", &pk));
    }

    #[test]
    fn context_id_matches_spec_formula() {
        let pk = sample_key(0x20);
        let realm = RealmId::from(ht("id/realm", b"example-app"));
        let ctx = ContextId::derive(pk, realm).expect("ctx id");

        let mut data = Vec::new();
        data.extend_from_slice(&pk);
        data.extend_from_slice(realm.as_ref());
        assert_eq!(ctx.as_bytes(), &ht("id/ctx", &data));
    }

    #[test]
    fn device_id_matches_spec_formula() {
        let pk = sample_key(0x30);
        let device = DeviceId::derive(pk).expect("device id");
        assert_eq!(device.as_bytes(), &ht("id/device", &pk));
    }

    #[test]
    fn org_and_scoped_org_ids_match_spec_formula() {
        let org_pk = sample_key(0x40);
        let org = OrgId::derive(org_pk).expect("org id");
        assert_eq!(org.as_bytes(), &ht("id/org", &org_pk));

        let realm = RealmId::from(ht("id/realm", b"tenant-123"));
        let scoped = ScopedOrgId::derive(org, realm);
        let mut data = Vec::new();
        data.extend_from_slice(org.as_ref());
        data.extend_from_slice(realm.as_ref());
        assert_eq!(scoped.as_bytes(), &ht("id/org/realm", &data));
    }

    #[test]
    fn group_id_matches_spec_formula() {
        let org_pk = sample_key(0x50);
        let org = OrgId::derive(org_pk).expect("org id");
        let group = GroupId::derive(org, "ops");

        let mut data = Vec::new();
        data.extend_from_slice(org.as_ref());
        data.extend_from_slice(b"ops");
        assert_eq!(group.as_bytes(), &ht("id/group", &data));
    }

    #[test]
    fn stream_ids_match_spec_formula() {
        let pk = sample_key(0x60);
        let principal_stream = stream_id_principal(pk).expect("principal stream");
        assert_eq!(principal_stream.as_bytes(), &ht("id/stream/principal", &pk));

        let realm = RealmId::from(ht("id/realm", b"default"));
        let ctx = ContextId::derive(pk, realm).expect("ctx id");
        let ctx_stream = stream_id_ctx(ctx, realm);
        let mut ctx_data = Vec::new();
        ctx_data.extend_from_slice(ctx.as_ref());
        ctx_data.extend_from_slice(realm.as_ref());
        assert_eq!(ctx_stream.as_bytes(), &ht("id/stream/ctx", &ctx_data));

        let org = OrgId::derive(pk).expect("org id");
        let org_stream = stream_id_org(org);
        assert_eq!(org_stream.as_bytes(), &ht("id/stream/org", org.as_ref()));

        let handle_stream = stream_id_handle_ns(realm);
        assert_eq!(
            handle_stream.as_bytes(),
            &ht("id/stream/handle", realm.as_ref())
        );
    }

    #[test]
    fn enforcing_public_key_length() {
        let pk = [0u8; ED25519_PUBLIC_KEY_LEN - 1];
        let err = PrincipalId::derive(pk);
        assert!(err.is_err(), "expected length error for short key");
        let err = DeviceId::derive(pk);
        assert!(err.is_err(), "expected length error for short device key");
    }
}
