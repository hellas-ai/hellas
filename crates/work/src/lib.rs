//! Durable paid-work orchestration for Hellas endpoints.
//!
//! Canonical records and generated RPC interfaces remain in [`hellas_rpc`].
//! This crate owns the endpoint workflow, durable journals, recovery, and
//! settlement drivers used by both clients and providers.

pub mod grant_service;
pub mod work;
pub mod work_close;
pub mod work_handshake;
pub mod work_open;
pub mod work_store;
