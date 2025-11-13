//! Core primitives and helpers for the Verifiable End-to-End Network (VEEN).
//!
//! The crate focuses on providing strongly typed helpers around the immutable
//! wire-format specification documented in `doc/spec.txt`.  The intent is to
//! make it straightforward to experiment with protocol implementations while
//! enforcing consistent hashing and encoding behaviour across binaries.

mod hash;
pub mod label;
pub mod profile;

pub use crate::hash::ht;
pub use crate::label::{Label, StreamId};
pub use crate::profile::{Profile, ProfileId};
