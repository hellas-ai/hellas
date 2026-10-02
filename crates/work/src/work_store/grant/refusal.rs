//! Structured grant refusals. Diagnostics never select client recovery policy.
use super::{GrantStoreError, ledger::LedgerError};
use crate::work_store::ChannelStateError;
use hellas_rpc::pb::work::{GrantRefusal, GrantRefusalCode, WorkRefusalCode, WorkRefused};
use hellas_rpc::protocol::work_grant::{records::GrantError, resource::TemplateError};

pub fn refused(code: GrantRefusalCode) -> WorkRefused {
    let outer = match code {
        GrantRefusalCode::Expired => WorkRefusalCode::Expired,
        GrantRefusalCode::Paused
        | GrantRefusalCode::Revoked
        | GrantRefusalCode::StaleRevision
        | GrantRefusalCode::StaleGeneration
        | GrantRefusalCode::Budget
        | GrantRefusalCode::Concurrency
        | GrantRefusalCode::StateCapacity
        | GrantRefusalCode::QueueCapacity
        | GrantRefusalCode::Quarantined
        | GrantRefusalCode::OutputUnavailable
        | GrantRefusalCode::Released
        | GrantRefusalCode::Indeterminate => WorkRefusalCode::Declined,
        GrantRefusalCode::StorageUnavailable => WorkRefusalCode::Unavailable,
        _ => WorkRefusalCode::Invalid,
    };
    WorkRefused {
        code: outer as i32,
        reason: code.as_str_name().into(),
        grant: Some(GrantRefusal {
            code: code as i32,
            current_revision: 0,
            terminal: None,
        }),
    }
}
impl From<&GrantStoreError> for WorkRefused {
    fn from(error: &GrantStoreError) -> Self {
        use GrantRefusalCode as C;
        let code = match error {
            GrantStoreError::Journal(_)
            | GrantStoreError::WriterPoisoned
            | GrantStoreError::Completion(_)
            | GrantStoreError::Task(_) => C::StorageUnavailable,
            GrantStoreError::Grant(error) => match error {
                GrantError::Unauthorized | GrantError::Signature | GrantError::Audience => {
                    C::Unauthorized
                }
                GrantError::Expired => C::Expired,
                GrantError::Paused => C::Paused,
                GrantError::Revoked => C::Revoked,
                GrantError::Revision(_) => C::StaleRevision,
                GrantError::OutOfScope | GrantError::AccountBacked => C::OutOfScope,
                GrantError::StateCapacity => C::StateCapacity,
                GrantError::Generation => C::StaleGeneration,
                GrantError::Quarantined => C::Quarantined,
                GrantError::Malformed
                | GrantError::UnsupportedKey
                | GrantError::UnsupportedRoot
                | GrantError::Limits => C::Malformed,
            },
            GrantStoreError::Ledger(error) => match error {
                LedgerError::OverBudget { .. } => C::Budget,
                LedgerError::Concurrent(_) => C::Concurrency,
                _ => C::Malformed,
            },
            GrantStoreError::Resource(error) => match error {
                TemplateError::Origin => C::Origin,
                TemplateError::PathMethod => C::PathMethod,
                TemplateError::Tls => C::Tls,
                TemplateError::Credential => C::Credential,
                TemplateError::Headers => C::Headers,
                TemplateError::GenerationCap => C::GenerationCap,
                TemplateError::StreamUsage => C::StreamUsage,
                TemplateError::ResponseCap => C::ResponseCap,
                TemplateError::Malformed => C::Malformed,
            },
            GrantStoreError::Channel(
                ChannelStateError::AcceptanceLate { .. } | ChannelStateError::DispatchLate { .. },
            ) => C::Expired,
            GrantStoreError::Channel(ChannelStateError::Indeterminate) => C::Indeterminate,
            GrantStoreError::Channel(_)
            | GrantStoreError::Input(_)
            | GrantStoreError::Malformed => C::Malformed,
        };
        let mut refusal = refused(code);
        if let GrantStoreError::Grant(GrantError::Revision(revision)) = error {
            refusal
                .grant
                .as_mut()
                .expect("grant refusal")
                .current_revision = revision.0;
        }
        refusal
    }
}
