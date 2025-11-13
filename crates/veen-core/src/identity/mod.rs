use crate::{label::StreamId, realm::RealmId, LengthError};

mod context;
mod device;
mod group;
mod org;
mod principal;
mod scoped_org;

pub use context::ContextId;
pub use device::DeviceId;
pub use group::GroupId;
pub use org::OrgId;
pub use principal::PrincipalId;
pub use scoped_org::ScopedOrgId;

const ID_LEN: usize = 32;
const ED25519_PUBLIC_KEY_LEN: usize = 32;

fn ensure_ed25519_public_key_len(bytes: &[u8]) -> Result<(), LengthError> {
    if bytes.len() != ED25519_PUBLIC_KEY_LEN {
        Err(LengthError::new(ED25519_PUBLIC_KEY_LEN, bytes.len()))
    } else {
        Ok(())
    }
}

pub fn stream_id_principal(principal_pk: impl AsRef<[u8]>) -> Result<StreamId, LengthError> {
    let principal_pk = principal_pk.as_ref();
    ensure_ed25519_public_key_len(principal_pk)?;
    Ok(StreamId::from(crate::ht(
        "id/stream/principal",
        principal_pk,
    )))
}

#[must_use]
pub fn stream_id_ctx(ctx_id: ContextId, realm_id: RealmId) -> StreamId {
    let mut data = Vec::with_capacity(ID_LEN * 2);
    data.extend_from_slice(ctx_id.as_ref());
    data.extend_from_slice(realm_id.as_ref());
    StreamId::from(crate::ht("id/stream/ctx", &data))
}

#[must_use]
pub fn stream_id_org(org_id: OrgId) -> StreamId {
    StreamId::from(crate::ht("id/stream/org", org_id.as_ref()))
}

#[must_use]
pub fn stream_id_handle_ns(realm_id: RealmId) -> StreamId {
    StreamId::from(crate::ht("id/stream/handle", realm_id.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key(prefix: u8) -> [u8; super::ED25519_PUBLIC_KEY_LEN] {
        let mut out = [0u8; super::ED25519_PUBLIC_KEY_LEN];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = prefix.wrapping_add(index as u8);
        }
        out
    }

    #[test]
    fn principal_id_matches_spec_formula() {
        let pk = sample_key(0x10);
        let principal_id = PrincipalId::derive(pk).expect("principal id");
        assert_eq!(principal_id.as_bytes(), &crate::ht("id/principal", &pk));
    }

    #[test]
    fn context_id_matches_spec_formula() {
        let pk = sample_key(0x20);
        let realm = RealmId::from(crate::ht("id/realm", b"example-app"));
        let ctx = ContextId::derive(pk, realm).expect("ctx id");

        let mut data = Vec::new();
        data.extend_from_slice(&pk);
        data.extend_from_slice(realm.as_ref());
        assert_eq!(ctx.as_bytes(), &crate::ht("id/ctx", &data));
    }

    #[test]
    fn device_id_matches_spec_formula() {
        let pk = sample_key(0x30);
        let device = DeviceId::derive(pk).expect("device id");
        assert_eq!(device.as_bytes(), &crate::ht("id/device", &pk));
    }

    #[test]
    fn org_and_scoped_org_ids_match_spec_formula() {
        let org_pk = sample_key(0x40);
        let org = OrgId::derive(org_pk).expect("org id");
        assert_eq!(org.as_bytes(), &crate::ht("id/org", &org_pk));

        let realm = RealmId::from(crate::ht("id/realm", b"tenant-123"));
        let scoped = ScopedOrgId::derive(org, realm);
        let mut data = Vec::new();
        data.extend_from_slice(org.as_ref());
        data.extend_from_slice(realm.as_ref());
        assert_eq!(scoped.as_bytes(), &crate::ht("id/org/realm", &data));
    }

    #[test]
    fn group_id_matches_spec_formula() {
        let org_pk = sample_key(0x50);
        let org = OrgId::derive(org_pk).expect("org id");
        let group = GroupId::derive(org, "ops");

        let mut data = Vec::new();
        data.extend_from_slice(org.as_ref());
        data.extend_from_slice(b"ops");
        assert_eq!(group.as_bytes(), &crate::ht("id/group", &data));
    }

    #[test]
    fn stream_ids_match_spec_formula() {
        let pk = sample_key(0x60);
        let principal_stream = stream_id_principal(pk).expect("principal stream");
        assert_eq!(
            principal_stream.as_bytes(),
            &crate::ht("id/stream/principal", &pk)
        );

        let realm = RealmId::from(crate::ht("id/realm", b"default"));
        let ctx = ContextId::derive(pk, realm).expect("ctx id");
        let ctx_stream = stream_id_ctx(ctx, realm);
        let mut ctx_data = Vec::new();
        ctx_data.extend_from_slice(ctx.as_ref());
        ctx_data.extend_from_slice(realm.as_ref());
        assert_eq!(
            ctx_stream.as_bytes(),
            &crate::ht("id/stream/ctx", &ctx_data)
        );

        let org = OrgId::derive(pk).expect("org id");
        let org_stream = stream_id_org(org);
        assert_eq!(
            org_stream.as_bytes(),
            &crate::ht("id/stream/org", org.as_ref())
        );

        let handle_stream = stream_id_handle_ns(realm);
        assert_eq!(
            handle_stream.as_bytes(),
            &crate::ht("id/stream/handle", realm.as_ref())
        );
    }

    #[test]
    fn enforcing_public_key_length() {
        let pk = [0u8; super::ED25519_PUBLIC_KEY_LEN - 1];
        let err = PrincipalId::derive(pk);
        assert!(err.is_err(), "expected length error for short key");
        let err = DeviceId::derive(pk);
        assert!(err.is_err(), "expected length error for short device key");
    }
}
