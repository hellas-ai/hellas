//! Shared cryptographic identities and transport-independent service authority.
//! Hosts own authentication, persistence and effects; this crate owns their rules.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod authority;
mod digest;
pub mod hex;
pub mod signature;
pub mod tags;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use digest::{Digest, hash_tuple};
pub use signature::{
    ProducerId, ProducerSigningKey, PublicKey, Signature, SignatureError, SignatureKind,
};
