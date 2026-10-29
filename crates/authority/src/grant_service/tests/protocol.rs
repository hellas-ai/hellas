use futures::StreamExt;
use hellas_auth::Digest;
use hellas_auth::authority::{GrantId, Revision, UnixMillis};

mod cache;
mod delivery;
mod expiry;
mod recovery;
mod refusals;
mod refused_uploads;
mod revocation;
mod rpc_stream;
mod sponsorship;
mod usage;

use crate::test_support::*;
use hellas_authority::{grant_service::GrantService, work_store::grant::*};
use hellas_channel::test_support::transport;
use hellas_rpc::{pb::work::*, *};
use hellas_wire::{
    AuthLevel, Dispatcher, PeerIdentity, StreamTransport, TransportContext, mux::MuxTransport,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Notify;
use {
    crate::model::grant::budget::*, crate::model::grant::standing::*, crate::model::grant::*,
    hellas_channel::model::work::*,
};

use hellas_channel::test_support::backend::{Backend, Reply};
fn context() -> TransportContext {
    TransportContext {
        peer: Some(PeerIdentity([1; 32])),
        auth_level: AuthLevel::Vouched,
        open_exporter: Some([7; 32]),
        ..Default::default()
    }
}
fn request(store: &NodeStore, nonce: u64) -> AcceptWorkRequest {
    let (a, signature, input) = proposal(store, nonce);
    AcceptWorkRequest {
        route: Some(WorkRoute::grant(a.channel_id.0)),
        authorization: a.encode(),
        client_signature: signature.bytes().to_vec(),
        prepared_input: input.canonical_bytes().unwrap(),
    }
}
fn accepted_id(response: AcceptWorkResponse) -> Digest {
    let accepted = match response.outcome {
        Some(accept_work_response::Outcome::Accepted(accepted)) => accepted,
        other => panic!("expected accepted work, got {other:?}"),
    };
    Digest::from_bytes(accepted.work_id.try_into().unwrap())
}
fn refusal(response: AcceptWorkResponse) -> GrantRefusalCode {
    let refused = match response.outcome {
        Some(accept_work_response::Outcome::Refused(refused)) => refused,
        other => panic!("expected a work refusal, got {other:?}"),
    };
    GrantRefusalCode::try_from(refused.grant.unwrap().code).unwrap()
}
async fn service(
    store: NodeStore,
    backend: Backend,
    secret: &hellas_auth::authority::CredentialSecret,
) -> (
    GrantService,
    super::GrantWork,
    hellas_auth::authority::CredentialSecret,
) {
    let service = GrantService::new(
        store,
        Arc::new(principal(2).1),
        backend,
        vec![],
        Arc::new(|| UnixMillis(1_000)),
    )
    .unwrap();
    let (work, credential) =
        common_node::execution(&service, secret, &principal(1).1, GrantId([1; 16])).await;
    (service, work, credential)
}

/// Observe durable state without notifying the service or sampling its clock.
async fn snapshot(service: &GrantService) -> State {
    service.node().writer().await.unwrap().state().clone()
}

/// Grant revisions are authority-wide, so read the execution grant's current one.
async fn execution_revision(service: &GrantService) -> Revision {
    snapshot(service)
        .await
        .authority()
        .grant(common_node::EXECUTION_AUTHORIZATION)
        .unwrap()
        .revision()
}

async fn set_execution_expiry(
    service: &GrantService,
    secret: &hellas_auth::authority::CredentialSecret,
    expires: UnixMillis,
) {
    let node = service.node();
    let admin = crate::test_support::session(&node, secret).await;
    service
        .administer(async |store, now| {
            let id = common_node::EXECUTION_AUTHORIZATION;
            let grant = store.state().authority().grant(id).unwrap();
            let expected = grant.revision();
            let mut spec = grant.spec().clone();
            spec.expires = expires;
            store
                .administer_authority(
                    &admin,
                    hellas_auth::authority::AdministrationCommand::Grant(
                        hellas_auth::authority::GrantCommand::Revise {
                            authorization: GrantId([0; 16]),
                            id,
                            expected,
                            spec,
                        },
                    ),
                    now,
                )
                .await
        })
        .await
        .unwrap();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessTarget {
    Credential,
    Grant,
}

async fn revoke_access(
    service: &GrantService,
    administrator: &hellas_auth::authority::CredentialSecret,
    credential: &hellas_auth::authority::CredentialSecret,
    target: AccessTarget,
) {
    let node = service.node();
    let admin = crate::test_support::session(&node, administrator).await;
    match target {
        AccessTarget::Credential => {
            node.revoke_credential(&admin, GrantId([0; 16]), credential.id(), Revision(1))
                .await
                .unwrap();
        }
        AccessTarget::Grant => {
            service
                .administer(async |store, now| {
                    let id = common_node::EXECUTION_AUTHORIZATION;
                    let expected = store.state().authority().grant(id).unwrap().revision();
                    store
                        .administer_authority(
                            &admin,
                            hellas_auth::authority::AdministrationCommand::Grant(
                                hellas_auth::authority::GrantCommand::Revoke {
                                    authorization: GrantId([0; 16]),
                                    id,
                                    expected,
                                },
                            ),
                            now,
                        )
                        .await
                })
                .await
                .unwrap();
        }
    }
}

mod compute_usage;
