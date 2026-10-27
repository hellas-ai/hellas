//! Routes authenticated Work requests to the configured funding authority.
use hellas_rpc::pb::work::Refusable;

use crate::paid_provider::{MountedWork, MountedWorkService};
use hellas_rpc::call::{WithTrailer, with_trailer as wt};
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, AdmitCertificateRequest, AdmitCertificateResponse,
    DeliverResultRequest, DeliverResultResponse, ExchangeSetupRequest, ExchangeSetupResponse,
    FundingKind, GetStandingRequest, GetStandingResponse, WorkRefusalCode, WorkRefused, WorkRoute,
};
use hellas_rpc::services::work::WorkHandler;
use hellas_rpc::services::work_setup::WorkSetupHandler;
use hellas_wire::{TransportContext, WireCode, WireStatus};
use hellas_work::grant_service::{GrantService, GrantWork};
use std::sync::Arc;
use tokio::sync::Semaphore;
mod admission;
mod connection;
use connection::ConnectionWork;
pub use connection::WorkConnection;
pub(crate) use connection::connect_work;

/// Hosts select available fundings before serving. Each connection then proves
/// and retains exactly one funding mode before ordinary Work RPC is exposed.
#[derive(Clone)]
pub struct WorkRouter {
    grants: Option<GrantService>,
    payment: Option<MountedWork>,
    slots: Arc<Semaphore>,
    pending: Arc<Semaphore>,
    public: Arc<Semaphore>,
    unverified: admission::UnverifiedAdmission,
}
impl WorkRouter {
    pub fn grants(grants: GrantService) -> Self {
        Self::new(Some(grants), None)
    }
    pub fn payment(payment: MountedWork) -> Self {
        Self::new(None, Some(payment))
    }
    pub fn both(payment: MountedWork, grants: GrantService) -> Self {
        Self::new(Some(grants), Some(payment))
    }
    fn new(grants: Option<GrantService>, payment: Option<MountedWork>) -> Self {
        let public_slots = if grants.is_some() { 64 } else { 128 };
        Self {
            grants,
            payment,
            slots: Arc::new(Semaphore::new(128)),
            pending: Arc::new(Semaphore::new(16)),
            // Public payment-mode selection proves no application identity.
            // It cannot consume the capacity reserved for authenticated grants.
            public: Arc::new(Semaphore::new(public_slots)),
            unverified: Default::default(),
        }
    }
    pub fn grant_service(&self) -> Option<&GrantService> {
        self.grants.as_ref()
    }
}

enum Handler<'a> {
    Grants(&'a GrantWork),
    Payment(MountedWorkService),
    Unavailable,
}

#[derive(Clone, Copy, Debug)]
pub struct UnmountedWork;

pub(crate) fn not_ready() -> WorkRefused {
    WorkRefused {
        grant: None,
        code: WorkRefusalCode::NotReady as i32,
        reason: "work state is not mounted".to_string(),
    }
}

impl WorkSetupHandler for UnmountedWork {
    async fn request_offer(
        &self,
        _request: hellas_rpc::pb::work::RequestOfferRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<hellas_rpc::pb::work::RequestOfferResponse>> + Send, WireStatus>
    {
        Ok(hellas_rpc::pb::work::RequestOfferResponse {
            outcome: Some(
                hellas_rpc::pb::work::request_offer_response::Outcome::Refused(
                    hellas_rpc::pb::work::OfferRefused {
                        code: hellas_rpc::pb::work::OfferRefusalCode::NoPolicy as i32,
                        required: 0,
                    },
                ),
            ),
        })
    }

    async fn exchange_setup(
        &self,
        _request: ExchangeSetupRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<ExchangeSetupResponse>> + Send, WireStatus> {
        Ok(ExchangeSetupResponse::refused(not_ready()))
    }
}

impl WorkHandler for UnmountedWork {
    async fn get_standing(
        &self,
        _request: GetStandingRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<GetStandingResponse>> + Send, WireStatus> {
        Ok(GetStandingResponse::refused(not_ready()))
    }

    async fn accept_work(
        &self,
        _request: AcceptWorkRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AcceptWorkResponse>> + Send, WireStatus> {
        Ok(AcceptWorkResponse::refused(not_ready()))
    }

    async fn upload_content(
        &self,
        _request: hellas_rpc::pb::work::UploadContentRequest,
        _context: TransportContext,
    ) -> Result<
        impl Into<WithTrailer<hellas_rpc::pb::work::UploadContentResponse>> + Send,
        WireStatus,
    > {
        Err::<hellas_rpc::pb::work::UploadContentResponse, _>(WireStatus::new(
            WireCode::Unavailable,
            "work channel is not mounted",
        ))
    }
    async fn deliver_result(
        &self,
        _request: DeliverResultRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<DeliverResultResponse>> + Send, WireStatus> {
        Ok(DeliverResultResponse::refused(not_ready()))
    }

    async fn stream_result(
        &self,
        _request: DeliverResultRequest,
        _context: TransportContext,
    ) -> Result<hellas_work::work::PaidResultStream, WireStatus> {
        Err(WireStatus::new(
            hellas_wire::WireCode::Unavailable,
            "work authority is not mounted",
        ))
    }

    async fn admit_certificate(
        &self,
        _request: AdmitCertificateRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AdmitCertificateResponse>> + Send, WireStatus> {
        Ok(AdmitCertificateResponse::refused(not_ready()))
    }
}

impl WorkHandler for ConnectionWork {
    async fn get_standing(
        &self,
        request: GetStandingRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<GetStandingResponse>> + Send, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Handler::Grants(service) => wt(service.get_standing(request, context)).await,
            Handler::Payment(service) => wt(service.get_standing(request, context)).await,
            Handler::Unavailable => wt(UnmountedWork.get_standing(request, context)).await,
        }
    }
    async fn accept_work(
        &self,
        request: AcceptWorkRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AcceptWorkResponse>> + Send, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Handler::Grants(service) => wt(service.accept_work(request, context)).await,
            Handler::Payment(service) => wt(service.accept_work(request, context)).await,
            Handler::Unavailable => wt(UnmountedWork.accept_work(request, context)).await,
        }
    }
    async fn upload_content(
        &self,
        request: hellas_rpc::pb::work::UploadContentRequest,
        context: TransportContext,
    ) -> Result<
        impl Into<WithTrailer<hellas_rpc::pb::work::UploadContentResponse>> + Send,
        WireStatus,
    > {
        match self.handler(&context, request.route.as_ref())? {
            Handler::Grants(service) => wt(service.upload_content(request, context)).await,
            Handler::Payment(service) => wt(service.upload_content(request, context)).await,
            Handler::Unavailable => wt(UnmountedWork.upload_content(request, context)).await,
        }
    }
    async fn deliver_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<DeliverResultResponse>> + Send, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Handler::Grants(service) => wt(service.deliver_result(request, context)).await,
            Handler::Payment(service) => wt(service.deliver_result(request, context)).await,
            Handler::Unavailable => wt(UnmountedWork.deliver_result(request, context)).await,
        }
    }
    async fn admit_certificate(
        &self,
        request: AdmitCertificateRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AdmitCertificateResponse>> + Send, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Handler::Grants(service) => wt(service.admit_certificate(request, context)).await,
            Handler::Payment(service) => wt(service.admit_certificate(request, context)).await,
            Handler::Unavailable => wt(UnmountedWork.admit_certificate(request, context)).await,
        }
    }
    async fn stream_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<hellas_work::work::PaidResultStream, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Handler::Grants(service) => service.stream_result(request, context).await,
            Handler::Payment(service) => service.stream_result(request, context).await,
            Handler::Unavailable => UnmountedWork.stream_result(request, context).await,
        }
    }
}
