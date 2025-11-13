//! Core primitives and helpers for the Verifiable End-to-End Network (VEEN).
//!
//! The crate focuses on providing strongly typed helpers around the immutable
//! wire-format specification documented in `doc/spec.txt`.  The intent is to
//! make it straightforward to experiment with protocol implementations while
//! enforcing consistent hashing and encoding behaviour across binaries.

mod hash;
pub mod hub;
pub mod identity;
pub mod label;
mod length;
pub mod profile;
pub mod realm;

pub use crate::hash::ht;
pub use crate::hub::{HubId, HUB_ID_LEN};
pub use crate::identity::{
    stream_id_ctx, stream_id_handle_ns, stream_id_org, stream_id_principal, ContextId, DeviceId,
    GroupId, OrgId, PrincipalId, ScopedOrgId,
};
pub use crate::label::{Label, StreamId};
pub use crate::length::LengthError;
pub use crate::profile::{Profile, ProfileId};
pub use crate::realm::{RealmId, REALM_ID_LEN};
