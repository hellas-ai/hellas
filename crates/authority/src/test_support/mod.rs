use crate::work_store::grant::NodeStore;
use hellas_auth::authority::{GrantId, PrincipalId, Revision, UnixMillis};
use hellas_auth::{Digest, ProducerSigningKey, Signature};
use hellas_rpc::*;
use std::num::NonZeroU64;
use {
    crate::model::grant::budget::*,
    crate::model::grant::records::*,
    crate::model::grant::*,
    hellas_rpc::protocol::invocation::{
        Admission, InvocationPolicy, Limits, PreparedInvocation,
        fetch::{FetchAdmission, FetchLimits, FetchRoutePolicy},
    },
};
tokio::task_local! {
    /// Pause this task's bootstrap after staging is durable, before publication.
    /// The first notification announces the pause; the second releases it.
    pub static BOOTSTRAP_COMMIT_PAUSE: (
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    );
}

pub(crate) async fn pause_bootstrap_commit() {
    if let Ok((entered, release)) = BOOTSTRAP_COMMIT_PAUSE.try_with(Clone::clone) {
        entered.notify_one();
        release.notified().await;
    }
}

pub fn budget() -> BudgetNode {
    BudgetNode::Subject {
        pool: common_node::POOL,
        subject: principal(1).0,
    }
}
/// Authenticate a credential with a daily session by its bound node key.
pub fn signed_caller(
    authority: &hellas_auth::authority::AuthorityState,
    secret: &hellas_auth::authority::CredentialSecret,
    node_key: &ProducerSigningKey,
    now: UnixMillis,
) -> hellas_auth::authority::AuthenticatedCaller {
    let binding = hellas_auth::Digest::hash(b"test session");
    let pending = authority.begin_authentication(binding, now).unwrap();
    let proof = pending
        .challenge()
        .sign_daily(authority.authority(), binding, secret.id(), node_key)
        .unwrap();
    pending
        .complete(authority, binding, secret, &proof, now)
        .unwrap()
        .into_caller()
}
/// Authenticate a credential with a passkey session by its subject.
pub fn passkey_caller(
    authority: &hellas_auth::authority::AuthorityState,
    secret: &hellas_auth::authority::CredentialSecret,
    now: UnixMillis,
) -> hellas_auth::authority::AuthenticatedCaller {
    try_passkey_caller(authority, secret, now).unwrap()
}
pub fn try_passkey_caller(
    authority: &hellas_auth::authority::AuthorityState,
    secret: &hellas_auth::authority::CredentialSecret,
    now: UnixMillis,
) -> Result<hellas_auth::authority::AuthenticatedCaller, hellas_auth::authority::AuthorityError> {
    let subject = authority
        .credential(secret.id())
        .ok_or(hellas_auth::authority::AuthorityError::Credential)?
        .scope()
        .subject;
    let binding = hellas_auth::Digest::hash(b"test session");
    let pending = authority.begin_authentication(binding, now)?;
    let digest = pending
        .challenge()
        .proof_digest(authority.authority(), binding, secret.id())?;
    let proof = hellas_auth::authority::SessionProof::Passkey(
        hellas_auth::test_support::assertion(&passkey_of(subject), digest),
    );
    Ok(pending
        .complete(authority, binding, secret, &proof, now)?
        .into_caller())
}
/// A passkey session for `secret` through the checked node API, as its subject.
pub async fn session(
    node: &crate::node::NodeCoordinator,
    secret: &hellas_auth::authority::CredentialSecret,
) -> hellas_auth::authority::AuthenticatedCaller {
    try_session(node, secret).await.unwrap()
}
pub async fn try_session(
    node: &crate::node::NodeCoordinator,
    secret: &hellas_auth::authority::CredentialSecret,
) -> Result<hellas_auth::authority::AuthenticatedCaller, crate::work_store::grant::NodeStoreError> {
    let subject = node
        .writer()
        .await?
        .state()
        .authority()
        .credential(secret.id())
        .ok_or(hellas_auth::authority::AuthorityError::Credential)?
        .scope()
        .subject;
    node.authenticate_session(
        secret,
        crate::node::SessionKey::Passkey(&passkey_of(subject)),
    )
    .await
}
pub fn policy() -> GrantPolicy {
    let route = FetchRoutePolicy::sealed_route("openai", "responses").unwrap();
    GrantPolicy {
        resource: hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test resource")),
        account: hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test account")),
        revision: hellas_auth::authority::Revision(1),
        name: "responses".into(),
        invocation_policy: InvocationPolicy {
            admissions: vec![Admission::Fetch {
                admission: FetchAdmission {
                    contract: test_responses_contract(),
                    route,
                    limits: FetchLimits {
                        max_request_body_bytes: 4096,
                        max_output_events: 64,
                        max_spool_bytes: 65_536,
                        max_encoded_result_frame: 262_144,
                        max_encoded_prepared_input: 1_048_576,
                    },
                },
            }],
            limits: Limits {
                max_upload_bytes: 1_048_576,
                max_output_bytes: 1_048_576,
                max_steps: 128,
                execution_timeout_ms: 10_000,
            },
        },
        https: None,
        pricing: crate::model::grant::pricing::Pricing {
            revision: hellas_auth::authority::Revision(1),
            rates: None,
        },
        responses: Some(crate::model::grant::responses::ResponsesResource {
            model: "fixture".into(),
            max_output_tokens: 8,
            settings: Default::default(),
        }),
    }
}
pub fn definition(id: GrantId, client: PrincipalId) -> GrantDef {
    GrantDef {
        id,
        revision: Revision(1),
        policies: vec![policy()],
        budget: BudgetNode::Subject {
            pool: common_node::POOL,
            subject: client,
        },
        max_job_millis: NonZeroU64::new(10000).unwrap(),
        enabled: true,
        allow_account_backed: true,
    }
}

pub fn chat_resource(origin: &str, max_output_tokens: u64) -> resource::HttpsResource {
    resource::HttpsResource {
        origin: origin.into(),
        paths: vec!["/v1/chat/completions".into()],
        methods: vec!["POST".into()],
        credential: None,
        tls: hellas_rpc::http_fetch::HttpTls {
            roots: hellas_rpc::http_fetch::HttpTrustRoots::WebPki,
            spki_sha256: vec![],
        },
        accounting: resource::AccountingProfile::OpenaiChat,
        max_output_tokens,
        max_response_bytes: 4096,
        model_policy: None,
    }
}

pub fn use_https(policy: &mut GrantPolicy, resource: resource::HttpsResource) {
    for admission in &mut policy.invocation_policy.admissions {
        if let Admission::Fetch { admission } = admission {
            admission.contract = hellas_rpc::FetchContract::http().unwrap();
        }
    }
    policy.responses = None;
    policy.https = Some(resource);
}
pub const JOURNAL_AUTHORIZATION: hellas_auth::authority::GrantId = GrantId([237; 16]);
pub async fn setup(
    path: &std::path::Path,
) -> (NodeStore, hellas_auth::authority::AuthenticatedCaller) {
    let (mut store, secret) = setup_with_credential(path).await;
    let application = execution_caller(&mut store, &secret, GrantId([0; 16])).await;
    (store, application)
}
pub async fn execution_caller(
    store: &mut NodeStore,
    secret: &hellas_auth::authority::CredentialSecret,
    root: GrantId,
) -> hellas_auth::authority::AuthenticatedCaller {
    let credential = execution_credential(store, secret, root).await;
    let now = store.state().now();
    signed_caller(store.state().authority(), &credential, &principal(1).1, now)
}
/// Issue principal 1's execution grant and app credential.
pub async fn execution_credential(
    store: &mut NodeStore,
    secret: &hellas_auth::authority::CredentialSecret,
    root: GrantId,
) -> hellas_auth::authority::CredentialSecret {
    use hellas_auth::authority as auth;
    let now = store.state().now();
    let administrator = passkey_caller(store.state().authority(), secret, now);
    let mut scope = store
        .state()
        .authority()
        .grant(root)
        .unwrap()
        .spec()
        .clone();
    scope.subject = principal(1).0;
    scope.permissions = [auth::Permission {
        operation: auth::OperationId::new(crate::grant_service::WORK_EXECUTE).unwrap(),
        resource: crate::grant_service::allowance_resource(scope.authority, GrantId([1; 16])),
    }]
    .into();
    scope.issuance = None;
    scope.delegation_depth = 1;
    let [secret] = credentials::issue(
        credentials::Issuer::Store(store, now),
        &administrator,
        root,
        Some(JOURNAL_AUTHORIZATION),
        scope,
    )
    .await;
    secret
}
pub async fn setup_with_credential(
    path: &std::path::Path,
) -> (NodeStore, hellas_auth::authority::CredentialSecret) {
    let (store, secret) = common_node::bootstrap_node_with_credential(
        path,
        network(),
        Some(hellas_channel::test_support::software_enrollment(
            2, [2; 32],
        )),
        UnixMillis(1000),
    )
    .await
    .unwrap();
    let requests = |amount| {
        vec![Limit {
            meter: Meter::Requests,
            window: Window::Total,
            amount,
        }]
    };
    let store = common_node::provision(
        path,
        store,
        &secret,
        principal(2).1,
        (4, requests(4)),
        definition(GrantId([1; 16]), principal(1).0),
        (requests(3), 2),
    )
    .await;
    (store, secret)
}
pub fn proposal(
    store: &NodeStore,
    nonce: u64,
) -> (GrantJobAuthorizationV1, Signature, PreparedInvocation) {
    proposal_for(store, GrantId([1; 16]), nonce, principal(1).1)
}
pub fn proposal_for(
    store: &NodeStore,
    id: GrantId,
    nonce: u64,
    key: ProducerSigningKey,
) -> (GrantJobAuthorizationV1, Signature, PreparedInvocation) {
    let def = store.state().grant(id).unwrap();
    let client = channel_client(subject_of(&key));
    let channel = store.state().channel_id(id, client).unwrap();
    let environment = if def.policies[0].https.is_some() {
        hellas_rpc::FetchContract::http().unwrap()
    } else {
        test_responses_contract()
    };
    let body = if let Some(resource) = &def.policies[0].https {
        serde_json::to_vec(&hellas_rpc::http_fetch::HttpFetchRequest {
            url: format!("{}{}", resource.origin, resource.paths[0]),
            method: "POST".into(),
            headers: vec![],
            body_base64: "eyJtYXhfdG9rZW5zIjo4fQ==".into(),
            tls: resource.tls.clone(),
            credential: resource.credential.clone(),
            max_response_bytes: resource.max_response_bytes,
        })
        .unwrap()
    } else {
        br#"{"model":"fixture","input":"never-journal-this-body","max_output_tokens":8}"#.to_vec()
    };
    let events = hellas_rpc::fetch::build_input_events_with_retention(
        "openai",
        "responses",
        &body,
        environment.manifest_id(),
        Assurance::ProducerSigned,
        &key,
        Retention::Ephemeral,
    )
    .unwrap();
    let input = hellas_rpc::protocol::invocation::fetch::prepare(
        &events,
        &environment,
        hellas_auth::PublicKey::Secp256k1(
            grant_producer(store.state().provider().unwrap())
                .unwrap()
                .to_bytes(),
        ),
        def.policies[0].invocation_policy.canonical_bytes().unwrap(),
        [nonce as u8; 32],
    )
    .unwrap();
    let a = GrantJobAuthorizationV1 {
        channel_id: channel,
        generation: store.state().generation(id).unwrap(),
        grant_id: id,
        grant_revision: def.revision,
        resource_id: def.policies[0].resource,
        resource_revision: def.policies[0].revision,
        pricing_revision: def.policies[0].pricing.revision,
        work_policy_digest: hellas_channel::job::policy_digest(
            network(),
            channel.0,
            &def.policies[0].invocation_policy,
        )
        .unwrap(),
        input_content: hellas_rpc::ContentRef::for_bytes(&input.canonical_bytes().unwrap()),
        prepared_input_digest: hellas_channel::job::bound_prepared_input_digest(
            network(),
            channel.0,
            &input,
        )
        .unwrap(),
        proposal_nonce: nonce,
        acceptance_deadline_ms: UnixMillis(2_000),
        request_commitment: input.request.commitment().unwrap(),
        environment_commitment: environment.manifest_id(),
        terminal_deadline_ms: UnixMillis(4_000),
        delivery_deadline_ms: UnixMillis(5_000),
    };
    (
        a,
        key.sign_digest(grant_work_id(network(), &a)).unwrap(),
        input,
    )
}

pub mod common_node;

pub mod credentials;

pub async fn accept_grant(
    work: &crate::grant_service::GrantWork,
    request: &hellas_rpc::pb::work::AcceptWorkRequest,
    signer: &ProducerSigningKey,
) -> hellas_rpc::pb::work::AcceptWorkResponse {
    let exporter = [7; 32];
    let (wire, chunks) = grant_upload_requests(request, signer, network(), exporter);
    for chunk in chunks {
        if let Some(refusal) = upload_failure(
            work.upload(
                &chunk,
                &hellas_wire::TransportContext {
                    open_exporter: Some(exporter),
                    ..Default::default()
                },
            )
            .await,
        ) {
            return refusal;
        }
    }
    work.accept(&wire).await
}

/// Raw store operations used by accounting tests; preserve the caller and simulated time.
pub async fn accept(
    store: &mut NodeStore,
    caller: &hellas_auth::authority::AuthenticatedCaller,
    request: (GrantJobAuthorizationV1, Signature, &PreparedInvocation),
    now: u64,
) -> Result<Signature, crate::work_store::grant::NodeStoreError> {
    store
        .accept(
            (caller, JOURNAL_AUTHORIZATION),
            request.0,
            request.1,
            request.2,
            &principal(2).1,
            UnixMillis(now),
        )
        .await
}
pub async fn dispatch(
    store: &mut NodeStore,
    caller: &hellas_auth::authority::AuthenticatedCaller,
    job: (ChannelId, Digest),
    now: u64,
) -> Result<(), crate::work_store::grant::NodeStoreError> {
    store
        .dispatch(
            (caller, JOURNAL_AUTHORIZATION),
            job.0,
            job.1,
            UnixMillis(now),
        )
        .await
}
pub async fn finish(
    store: &mut NodeStore,
    job: (ChannelId, Digest),
    outcome: crate::work_store::grant::GrantOutcome,
    usage: Usage,
    now: u64,
) -> Result<(), crate::work_store::grant::NodeStoreError> {
    store
        .finish(job.0, job.1, outcome, None, usage, UnixMillis(now))
        .await
}
pub fn used(store: &NodeStore, node: BudgetNode, meter: Meter) -> u64 {
    store
        .state()
        .ledger()
        .node(node)
        .unwrap()
        .counter(meter, Window::Total)
        .used
}
pub async fn reopen(
    path: &std::path::Path,
    now: u64,
) -> Result<NodeStore, crate::work_store::grant::NodeStoreError> {
    NodeStore::open(
        path,
        network(),
        Some(hellas_channel::test_support::software_enrollment(
            2, [2; 32],
        )),
        UnixMillis(now),
    )
    .await
}

pub use hellas_auth::{
    assert_err,
    test_support::{Actor, Rights, actors},
};
pub mod ids {
    pub use hellas_auth::test_support::ids::*;
    pub const ALLOWANCE: hellas_auth::authority::GrantId =
        hellas_auth::authority::GrantId([100; 16]);
    pub const LAPTOP_ALLOWANCE: hellas_auth::authority::GrantId =
        hellas_auth::authority::GrantId([101; 16]);
    pub const NEW_ALLOWANCE: hellas_auth::authority::GrantId =
        hellas_auth::authority::GrantId([102; 16]);
}
mod node;
pub use node::{
    Allowance, Capacity, Node, Proposal, TestClock, TestNode, TestService, WAIT, authority,
    provider_enrollment, within,
};

pub mod compute;

pub use hellas_channel::test_support::{
    all_files, backend, channel, channel_client, device, enrollment, grant_upload_requests, holder,
    network, node_key, passkey, passkey_of, principal, software_enrollment, subject_of,
    test_responses_contract, transport, upload_failure,
};

/// Hold the node writer to exercise cancellation and deadlines under contention.
pub async fn hold_writer(node: &crate::node::NodeCoordinator) -> impl Drop + '_ {
    node.writer().await.unwrap()
}
