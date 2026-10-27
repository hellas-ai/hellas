//! Durable paid-work orchestration for Hellas endpoints.
//!
//! Canonical paid-work and grant records live in [`model`]; generated RPC
//! interfaces and signed-transcript codecs remain in [`hellas_rpc`].
//! This crate owns the endpoint workflow, durable journals, recovery, and
//! settlement drivers used by both clients and providers.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

#[cfg(test)]
extern crate self as hellas_channel;

#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod test_support;

pub mod content;
pub mod endpoint_lock;
pub mod job;
pub mod model;
pub mod work;
pub mod work_close;
pub mod work_handshake;
pub mod work_open;
pub mod work_store;
