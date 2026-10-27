//! Structured grant refusals. Diagnostics never select client recovery policy.
use super::{NodeStoreError, ledger::LedgerError};
use crate::model::grant::{records::GrantError, resource::TemplateError};
use crate::work_store::ChannelStateError;
use hellas_rpc::pb::work::{GrantRefusal, GrantRefusalCode, WorkRefusalCode, WorkRefused};

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
impl From<NodeStoreError> for WorkRefused {
    fn from(error: NodeStoreError) -> Self {
        Self::from(&error)
    }
}

impl From<&NodeStoreError> for WorkRefused {
    fn from(error: &NodeStoreError) -> Self {
        use GrantRefusalCode as C;
        let code = match error {
            NodeStoreError::Io(_)
            | NodeStoreError::Uninitialized
            | NodeStoreError::Journal(_)
            | NodeStoreError::ClockJump
            | NodeStoreError::WriterPoisoned
            | NodeStoreError::Completion(_)
            | NodeStoreError::Task(_) => C::StorageUnavailable,
            NodeStoreError::Authority(error) => match error {
                hellas_auth::authority::AuthorityError::Denied
                | hellas_auth::authority::AuthorityError::StepUp
                | hellas_auth::authority::AuthorityError::Credential
                | hellas_auth::authority::AuthorityError::Audience
                | hellas_auth::authority::AuthorityError::Missing => C::Unauthorized,
                hellas_auth::authority::AuthorityError::Revoked => C::Revoked,
                hellas_auth::authority::AuthorityError::Expired => C::Expired,
                hellas_auth::authority::AuthorityError::Revision => C::StaleRevision,
                hellas_auth::authority::AuthorityError::Capacity => C::StateCapacity,
                _ => C::Malformed,
            },
            NodeStoreError::AlreadyInitialized
            | NodeStoreError::MissingProvider
            | NodeStoreError::MissingMachine
            | NodeStoreError::ProviderBound => C::Malformed,
            NodeStoreError::Grant(error) => match error {
                GrantError::Unauthorized | GrantError::Signature | GrantError::Audience => {
                    C::Unauthorized
                }
                GrantError::Expired => C::Expired,
                GrantError::Paused => C::Paused,
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
            NodeStoreError::Ledger(error) => match error {
                LedgerError::OverBudget { .. } => C::Budget,
                LedgerError::Concurrent(_) => C::Concurrency,
                LedgerError::Revision => C::StaleRevision,
                LedgerError::Capacity => C::StateCapacity,
                _ => C::Malformed,
            },
            NodeStoreError::Resource(error) => match error {
                TemplateError::Model | TemplateError::Settings => C::OutOfScope,
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
            NodeStoreError::Channel(
                ChannelStateError::AcceptanceLate { .. } | ChannelStateError::DispatchLate { .. },
            ) => C::Expired,
            NodeStoreError::Channel(ChannelStateError::Indeterminate) => C::Indeterminate,
            NodeStoreError::Channel(_) | NodeStoreError::Input(_) | NodeStoreError::Malformed => {
                C::Malformed
            }
        };
        WorkRefused {
            grant: Some(GrantRefusal {
                code: code as i32,
                current_revision: match error {
                    NodeStoreError::Grant(GrantError::Revision(revision)) => revision.0,
                    _ => 0,
                },
                terminal: None,
            }),
            ..refused(code)
        }
    }
}
