//! One verified input and its funding-bound execution admission.
use super::BackendFault;
use super::admission::{AdmittedWork, CapacityDomain, WorkAdmission, WorkPermit};
use crate::content::InvocationContent;
use hellas_rpc::Retention;
use hellas_rpc::protocol::invocation::{Limits, PreparedInvocation};

pub struct Admitted<I = PreparedInvocation, A = WorkAdmission> {
    input: I,
    limits: Limits,
    domain: CapacityDomain,
    content: InvocationContent,
    admission: A,
}

impl<I, A: std::fmt::Debug> std::fmt::Debug for Admitted<I, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Admitted")
            .field("limits", &self.limits)
            .field("domain", &self.domain)
            .field("retention", &self.retention())
            .field("admission", &self.admission)
            .finish()
    }
}

impl<I> Admitted<I> {
    /// The endpoint has checked the input and policy before creating this ticket.
    /// Retention includes the funding model's memory-only restriction.
    pub fn new(
        input: I,
        limits: Limits,
        domain: CapacityDomain,
        content: InvocationContent,
        admission: WorkAdmission,
    ) -> Self {
        Self {
            input,
            limits,
            domain,
            content,
            admission,
        }
    }

    pub async fn reserve(
        self,
        payment: impl core::future::Future<Output = Result<WorkPermit, BackendFault>>,
    ) -> Result<Admitted<I, AdmittedWork>, BackendFault> {
        let admission = self.admission.reserve(self.domain, payment).await?;
        Ok(Admitted {
            input: self.input,
            limits: self.limits,
            domain: self.domain,
            content: self.content,
            admission,
        })
    }
}

impl<I, A> Admitted<I, A> {
    pub const fn invocation(&self) -> &I {
        &self.input
    }
    pub const fn limits(&self) -> &Limits {
        &self.limits
    }
    pub const fn capacity_domain(&self) -> CapacityDomain {
        self.domain
    }
    pub const fn retention(&self) -> Retention {
        self.content.retention()
    }
    pub const fn content(&self) -> &InvocationContent {
        &self.content
    }
    pub fn into_parts_and_admission(self) -> (I, Limits, InvocationContent, A) {
        (self.input, self.limits, self.content, self.admission)
    }
}
