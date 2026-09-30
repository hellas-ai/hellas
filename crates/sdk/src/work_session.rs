//! Funding selects the durable session implementation at compile time.
use hellas_work::work_store::channel::funding::Funding;
pub use hellas_work::work_store::channel::funding::PaymentFunding;
use std::ops::{Deref, DerefMut};

pub trait SessionFunding: Funding {
    type Session;
}

/// One serial client channel. The funding type fixes its clock, journal,
/// authentication and obligations; no runtime enum can mix paid and grant state.
pub struct WorkSession<F: SessionFunding> {
    inner: F::Session,
}
impl<F: SessionFunding> Deref for WorkSession<F> {
    type Target = F::Session;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl<F: SessionFunding> DerefMut for WorkSession<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
#[cfg(feature = "paid-client")]
impl SessionFunding for PaymentFunding {
    type Session = crate::paid_client::PaymentSession;
}
#[cfg(feature = "paid-client")]
impl WorkSession<PaymentFunding> {
    pub async fn open(
        options: crate::paid_client::PaidWorkOptions,
        endpoint: iroh::Endpoint,
        signer: hellas_kernel::Secp256k1Signer,
    ) -> Result<Self, crate::paid_client::PaidClientError> {
        Ok(Self {
            inner: crate::paid_client::PaymentSession::open(options, endpoint, signer).await?,
        })
    }
}
