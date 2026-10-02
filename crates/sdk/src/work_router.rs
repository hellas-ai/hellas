//! Routes authenticated Work requests to the configured funding authority.
#[cfg(feature = "paid-provider")]
use crate::paid_provider::{MountedWork, MountedWorkService};
use hellas_rpc::call::WithTrailer;
use hellas_rpc::pb::work::{
    AcceptWorkRequest, AcceptWorkResponse, AdmitCertificateRequest, AdmitCertificateResponse,
    DeliverResultRequest, DeliverResultResponse, ExchangeSetupRequest, ExchangeSetupResponse,
    FundingKind, GetStandingRequest, GetStandingResponse, WorkRefusalCode, WorkRefused, WorkRoute,
    accept_work_response, admit_certificate_response, deliver_result_response,
    exchange_setup_response, get_standing_response,
};
use hellas_rpc::services::work::WorkHandler;
use hellas_rpc::services::work_setup::WorkSetupHandler;
use hellas_wire::{TransportContext, WireCode, WireStatus};
use hellas_work::grant_service::GrantService;

/// Funding is fixed before serving. Grant authority owns a provider-wide journal;
/// payment channels are mounted by their finalized-chain observer.
#[derive(Clone)]
pub enum WorkRouter {
    Grants(GrantService),
    #[cfg(feature = "paid-provider")]
    Payment(MountedWork),
    #[cfg(feature = "paid-provider")]
    Both {
        payment: MountedWork,
        grants: GrantService,
    },
}

enum Handler<'a> {
    Grants(&'a GrantService),
    #[cfg(feature = "paid-provider")]
    Payment(MountedWorkService),
    Unavailable,
}

impl WorkRouter {
    /// The grant authority selected at construction, if this router serves grants.
    pub fn grant_service(&self) -> Option<&GrantService> {
        match self {
            Self::Grants(grants) => Some(grants),
            #[cfg(feature = "paid-provider")]
            Self::Both { grants, .. } => Some(grants),
            #[cfg(feature = "paid-provider")]
            Self::Payment(_) => None,
        }
    }

    fn handler<'a>(
        &'a self,
        context: &TransportContext,
        route: Option<&WorkRoute>,
    ) -> Result<Handler<'a>, WireStatus> {
        let route = route
            .ok_or_else(|| WireStatus::new(WireCode::InvalidArgument, "missing work route"))?;
        match FundingKind::try_from(route.funding_kind) {
            Ok(FundingKind::Grant) => Ok(match self {
                Self::Grants(grants) => Handler::Grants(grants),
                #[cfg(feature = "paid-provider")]
                Self::Both { grants, .. } => Handler::Grants(grants),
                #[cfg(feature = "paid-provider")]
                Self::Payment(_) => Handler::Unavailable,
            }),
            Ok(FundingKind::Payment) => {
                #[cfg(feature = "paid-provider")]
                if let Self::Payment(payment) | Self::Both { payment, .. } = self {
                    return Ok(match payment.handler(context, Some(route))? {
                        Some(service) => Handler::Payment(service),
                        None => Handler::Unavailable,
                    });
                }
                #[cfg(not(feature = "paid-provider"))]
                let _ = context;
                Ok(Handler::Unavailable)
            }
            _ => Err(WireStatus::new(
                WireCode::InvalidArgument,
                "invalid funding kind",
            )),
        }
    }
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
    async fn exchange_setup(
        &self,
        _request: ExchangeSetupRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<ExchangeSetupResponse>> + Send, WireStatus> {
        Ok(ExchangeSetupResponse {
            outcome: Some(exchange_setup_response::Outcome::Refused(not_ready())),
        })
    }
}

impl WorkHandler for UnmountedWork {
    async fn get_standing(
        &self,
        _request: GetStandingRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<GetStandingResponse>> + Send, WireStatus> {
        Ok(GetStandingResponse {
            outcome: Some(get_standing_response::Outcome::Refused(not_ready())),
        })
    }

    async fn accept_work(
        &self,
        _request: AcceptWorkRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AcceptWorkResponse>> + Send, WireStatus> {
        Ok(AcceptWorkResponse {
            outcome: Some(accept_work_response::Outcome::Refused(not_ready())),
        })
    }

    async fn deliver_result(
        &self,
        _request: DeliverResultRequest,
        _context: TransportContext,
    ) -> Result<impl Into<WithTrailer<DeliverResultResponse>> + Send, WireStatus> {
        Ok(DeliverResultResponse {
            outcome: Some(deliver_result_response::Outcome::Refused(not_ready())),
        })
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
        Ok(AdmitCertificateResponse {
            outcome: Some(admit_certificate_response::Outcome::Refused(not_ready())),
        })
    }
}

impl WorkHandler for WorkRouter {
    async fn get_standing(
        &self,
        request: GetStandingRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<GetStandingResponse>> + Send, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Handler::Grants(service) => Ok(Into::<WithTrailer<GetStandingResponse>>::into(
                service.get_standing(request, context).await?,
            )),
            #[cfg(feature = "paid-provider")]
            Handler::Payment(service) => Ok(Into::<WithTrailer<GetStandingResponse>>::into(
                service.get_standing(request, context).await?,
            )),
            Handler::Unavailable => Ok(Into::<WithTrailer<GetStandingResponse>>::into(
                UnmountedWork.get_standing(request, context).await?,
            )),
        }
    }
    async fn accept_work(
        &self,
        request: AcceptWorkRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AcceptWorkResponse>> + Send, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Handler::Grants(service) => Ok(Into::<WithTrailer<AcceptWorkResponse>>::into(
                service.accept_work(request, context).await?,
            )),
            #[cfg(feature = "paid-provider")]
            Handler::Payment(service) => Ok(Into::<WithTrailer<AcceptWorkResponse>>::into(
                service.accept_work(request, context).await?,
            )),
            Handler::Unavailable => Ok(Into::<WithTrailer<AcceptWorkResponse>>::into(
                UnmountedWork.accept_work(request, context).await?,
            )),
        }
    }
    async fn deliver_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<DeliverResultResponse>> + Send, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Handler::Grants(service) => Ok(Into::<WithTrailer<DeliverResultResponse>>::into(
                service.deliver_result(request, context).await?,
            )),
            #[cfg(feature = "paid-provider")]
            Handler::Payment(service) => Ok(Into::<WithTrailer<DeliverResultResponse>>::into(
                service.deliver_result(request, context).await?,
            )),
            Handler::Unavailable => Ok(Into::<WithTrailer<DeliverResultResponse>>::into(
                UnmountedWork.deliver_result(request, context).await?,
            )),
        }
    }
    async fn admit_certificate(
        &self,
        request: AdmitCertificateRequest,
        context: TransportContext,
    ) -> Result<impl Into<WithTrailer<AdmitCertificateResponse>> + Send, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Handler::Grants(service) => Ok(Into::<WithTrailer<AdmitCertificateResponse>>::into(
                service.admit_certificate(request, context).await?,
            )),
            #[cfg(feature = "paid-provider")]
            Handler::Payment(service) => Ok(Into::<WithTrailer<AdmitCertificateResponse>>::into(
                service.admit_certificate(request, context).await?,
            )),
            Handler::Unavailable => Ok(Into::<WithTrailer<AdmitCertificateResponse>>::into(
                UnmountedWork.admit_certificate(request, context).await?,
            )),
        }
    }
    async fn stream_result(
        &self,
        request: DeliverResultRequest,
        context: TransportContext,
    ) -> Result<hellas_work::work::PaidResultStream, WireStatus> {
        match self.handler(&context, request.route.as_ref())? {
            Handler::Grants(service) => service.stream_result(request, context).await,
            #[cfg(feature = "paid-provider")]
            Handler::Payment(service) => service.stream_result(request, context).await,
            Handler::Unavailable => UnmountedWork.stream_result(request, context).await,
        }
    }
}
