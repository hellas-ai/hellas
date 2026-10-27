use crate::pb::work::*;

/// Work's unary responses retain the same structured refusal and recovery fields.
pub trait Refusable {
    fn refused(refusal: WorkRefused) -> Self;
}

impl Refusable for ExchangeSetupResponse {
    fn refused(refusal: WorkRefused) -> Self {
        Self {
            outcome: Some(exchange_setup_response::Outcome::Refused(refusal)),
        }
    }
}
impl Refusable for GetStandingResponse {
    fn refused(refusal: WorkRefused) -> Self {
        Self {
            outcome: Some(get_standing_response::Outcome::Refused(refusal)),
        }
    }
}
impl Refusable for AcceptWorkResponse {
    fn refused(refusal: WorkRefused) -> Self {
        Self {
            outcome: Some(accept_work_response::Outcome::Refused(refusal)),
        }
    }
}
impl Refusable for AdmitCertificateResponse {
    fn refused(refusal: WorkRefused) -> Self {
        Self {
            outcome: Some(admit_certificate_response::Outcome::Refused(refusal)),
        }
    }
}
