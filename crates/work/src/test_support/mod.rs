use crate::model::work::PrivateRecord as _;
use crate::model::{
    fetch::*,
    grant::{budget::*, records::*, *},
    profile::*,
};
use crate::work_store::grant::NodeStore;
use hellas_auth::authority::{GrantId, PrincipalId, Revision, UnixMillis};
use hellas_auth::{Digest, ProducerSigningKey, PublicKey, Signature};
use hellas_kernel::NetworkId;
use hellas_rpc::*;
use std::num::NonZeroU64;
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
pub fn network() -> NetworkId {
    NetworkId::new("grants-fixture").unwrap()
}
/// A fixture principal and the node key of its device. The passkey seed is
/// disjoint from the node key seed, which also serves provider producer keys.
pub fn principal(seed: u8) -> (PrincipalId, ProducerSigningKey) {
    let principal =
        PrincipalId::from_public_key(PublicKey::P256(passkey(seed).party_key().to_bytes()))
            .unwrap();
    (
        principal,
        ProducerSigningKey::from_secret_bytes([seed; 32]).unwrap(),
    )
}
/// The node key of `principal(seed)`'s device.
pub fn node_key(seed: u8) -> hellas_auth::authority::NodeKey {
    hellas_auth::authority::NodeKey::from_public_key(principal(seed).1.public_key()).unwrap()
}
pub fn passkey(seed: u8) -> hellas_kernel::SoftPasskey {
    hellas_kernel::SoftPasskey::from_secret_scalar([0x80 | seed; 32]).unwrap()
}
/// Disjoint from the actors' node key seeds (0x61..=0x69).
const SEEDS: std::ops::RangeInclusive<u8> = 1..=0x5f;
const ACTORS: [hellas_auth::test_support::Actor; 9] = {
    use hellas_auth::test_support::actors::*;
    [
        ROOT,
        OPERATOR,
        FRIEND,
        AGENT,
        PROVIDER,
        STRANGER,
        RECOVERY_OWNER,
        SUCCESSOR,
        ATTACKER,
    ]
};
/// The passkey of a fixture subject: an auth actor or a `principal(seed)`.
pub fn passkey_of(subject: PrincipalId) -> hellas_kernel::SoftPasskey {
    ACTORS
        .into_iter()
        .find(|actor| actor.principal() == subject)
        .map(|actor| actor.passkey())
        .or_else(|| SEEDS.map(passkey).find(|p| principal_of(p) == subject))
        .expect("subject is a fixture principal")
}
/// The node key of a fixture subject's device.
pub fn device(subject: PrincipalId) -> ProducerSigningKey {
    ACTORS
        .into_iter()
        .find(|actor| actor.principal() == subject)
        .map(|actor| actor.node_key())
        .or_else(|| SEEDS.map(principal).find(|p| p.0 == subject).map(|p| p.1))
        .expect("subject is a fixture principal")
}
/// The fixture subject whose device holds `key`.
pub fn subject_of(key: &ProducerSigningKey) -> PrincipalId {
    ACTORS
        .into_iter()
        .find(|actor| actor.node_key().public_key() == key.public_key())
        .map(|actor| actor.principal())
        .or_else(|| {
            SEEDS
                .map(principal)
                .find(|p| p.1.public_key() == key.public_key())
                .map(|p| p.0)
        })
        .expect("key is a fixture device")
}
/// The channel a fixture subject's own device opens.
pub fn channel_client(subject: PrincipalId) -> ChannelClient {
    ChannelClient {
        principal: subject,
        node: hellas_auth::authority::NodeKey::from_public_key(device(subject).public_key())
            .unwrap(),
    }
}
/// Credentials in fixtures are held by their subject's own device.
pub fn holder(subject: PrincipalId) -> hellas_auth::authority::CredentialHolder {
    hellas_auth::authority::CredentialHolder::Node(
        hellas_auth::authority::NodeKey::from_public_key(device(subject).public_key()).unwrap(),
    )
}
fn principal_of(passkey: &hellas_kernel::SoftPasskey) -> PrincipalId {
    PrincipalId::from_public_key(PublicKey::P256(passkey.party_key().to_bytes())).unwrap()
}

/// A provider's self-attested enrollment whose node key is `[seed; 32]`, the
/// node key of `principal(seed)`'s device. Its software root has its own key.
pub fn software_enrollment(seed: u8, transport: [u8; 32]) -> ProviderEnrollmentBundle {
    let root = ProducerSigningKey::from_secret_bytes([0xc0 | seed; 32]).unwrap();
    let key = ProducerSigningKey::from_secret_bytes([seed; 32]).unwrap();
    enrollment(&root, &key, transport, [seed; 32])
}

/// Keep root, producer, transport and installation identities independent in fixtures.
pub fn enrollment(
    root: &ProducerSigningKey,
    producer: &ProducerSigningKey,
    transport: [u8; 32],
    nonce: [u8; 32],
) -> ProviderEnrollmentBundle {
    let statement = ProviderGenesisStatement {
        root_kind: RootKind::Software,
        root_public_key: root.public_key(),
        producer_public_key: producer.public_key(),
        transport_public_key: PublicKey::Ed25519(transport),
        platform_credential: PlatformCredential::Absent,
        installation_nonce: nonce,
    };
    let proof = root
        .sign_digest(Digest::hash(&statement.canonical_bytes()))
        .unwrap();
    ProviderEnrollmentBundle {
        genesis: SignedProviderGenesis {
            statement,
            root_proof: RootProof::Software(proof),
        },
        platform: PlatformEnrollment::Absent,
    }
}
pub fn policy() -> GrantPolicy {
    let route = FetchRoutePolicy::sealed_route("openai", "responses").unwrap();
    GrantPolicy {
        resource: hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test resource")),
        account: hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test account")),
        revision: hellas_auth::authority::Revision(1),
        name: "responses".into(),
        work: WorkPolicy::Fetch {
            contract: test_responses_contract(),
            policy: FetchPolicyV2 {
                allowed_environment: test_responses_contract().manifest_id(),
                route_commitment: fetch_route_commitment(&route.canonical_body_bytes()).unwrap(),
                max_request_body_bytes: 4096,
                max_output_events: 64,
                max_output_bytes: 1_048_576,
                max_spool_bytes: 65_536,
                max_encoded_result_frame: 262_144,
                max_encoded_prepared_input: 1_048_576,
                max_upload_bytes: 1_048_576,
            },
            route,
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
    }
}

pub fn use_https(policy: &mut GrantPolicy, resource: resource::HttpsResource) {
    if let WorkPolicy::Fetch {
        policy, contract, ..
    } = &mut policy.work
    {
        *contract = hellas_rpc::FetchContract::http().unwrap();
        policy.allowed_environment = contract.manifest_id();
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
        Some(crate::test_support::software_enrollment(2, [2; 32])),
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
) -> (GrantJobAuthorizationV1, Signature, PreparedWorkInput) {
    proposal_for(store, GrantId([1; 16]), nonce, principal(1).1)
}
pub fn proposal_for(
    store: &NodeStore,
    id: GrantId,
    nonce: u64,
    key: ProducerSigningKey,
) -> (GrantJobAuthorizationV1, Signature, PreparedWorkInput) {
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
    let input: PreparedWorkInput = PreparedPaidFetchInputV1::new(&events, &environment)
        .unwrap()
        .into();
    let a = GrantJobAuthorizationV1 {
        channel_id: channel,
        generation: store.state().generation(id).unwrap(),
        grant_id: id,
        grant_revision: def.revision,
        resource_id: def.policies[0].resource,
        resource_revision: def.policies[0].revision,
        pricing_revision: def.policies[0].pricing.revision,
        work_policy_digest: def.policies[0].work.digest(network(), channel.0),
        input_content: hellas_rpc::ContentRef::for_bytes(&input.encode().unwrap()),
        prepared_input_digest: input.bound_digest(network(), channel.0).unwrap(),
        proposal_nonce: nonce,
        acceptance_deadline_ms: UnixMillis(2_000),
        request_commitment: RequestCommitment::from_digest(
            input.input_commitment().unwrap().digest(),
        ),
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

/// Every file under `root`, so a privacy scan also reads a database's
/// `-wal` and `-shm` companions.
pub fn all_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            paths.extend(all_files(&path));
        } else {
            paths.push(path);
        }
    }
    paths
}

pub fn test_responses_contract() -> hellas_rpc::FetchContract {
    hellas_rpc::FetchContract::new(
        "openai-responses-0.0.2",
        hellas_rpc::FetchSchema::StatelessResponsesV1,
        "openai-responses-driver-0.0.1",
        hellas_rpc::FetchEgress::FixedHttps("https://api.openai.com/v1/responses".into()),
    )
    .unwrap()
}

pub mod backend;
pub mod credentials;
pub mod transport;

/// Turns a fixture's locally held input body into signed upload RPCs and a
/// reference-only acceptance. Provider handlers never receive the body inline.
pub fn grant_upload_requests(
    request: &hellas_rpc::pb::work::AcceptWorkRequest,
    signer: &ProducerSigningKey,
    network: NetworkId,
    exporter: [u8; 32],
) -> (
    hellas_rpc::pb::work::AcceptWorkRequest,
    Vec<hellas_rpc::pb::work::UploadContentRequest>,
) {
    use hellas_rpc::protocol::content_upload::{
        CONTENT_CHUNK_BYTES, chunk_digest, encode_reference,
    };
    let mut wire = request.clone();
    let Ok(a) = GrantJobAuthorizationV1::decode(&request.authorization) else {
        return (wire, Vec::new());
    };
    if request.prepared_input.is_empty() {
        return (wire, Vec::new());
    }
    let reference = ContentRef::new(
        ContentId::hash(&request.prepared_input),
        request.prepared_input.len() as u64,
    );
    wire.prepared_input = encode_reference(reference);
    let work = grant_work_id(network, &a);
    let chunks = request
        .prepared_input
        .chunks(CONTENT_CHUNK_BYTES)
        .enumerate()
        .map(|(index, chunk)| {
            let offset = (index * CONTENT_CHUNK_BYTES) as u64;
            let signature = signer
                .sign_digest(chunk_digest(
                    a.channel_id.0,
                    work,
                    reference,
                    offset,
                    chunk,
                    &exporter,
                ))
                .unwrap();
            hellas_rpc::pb::work::UploadContentRequest {
                route: wire.route.clone(),
                authorization: wire.authorization.clone(),
                client_signature: wire.client_signature.clone(),
                content_id: reference.id().as_bytes().to_vec(),
                total_bytes: reference.bytes(),
                offset,
                chunk: chunk.to_vec(),
                chunk_signature: signature.bytes().to_vec(),
            }
        })
        .collect();
    (wire, chunks)
}

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
    request: (GrantJobAuthorizationV1, Signature, &PreparedWorkInput),
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
        Some(crate::test_support::software_enrollment(2, [2; 32])),
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

pub mod evaluate;

pub mod paid;

pub fn upload_failure(
    response: Result<hellas_rpc::pb::work::UploadContentResponse, hellas_wire::WireStatus>,
) -> Option<hellas_rpc::pb::work::AcceptWorkResponse> {
    use hellas_rpc::pb::work::{
        AcceptWorkResponse, WorkRefusalCode, WorkRefused, accept_work_response,
    };
    let refusal = match response {
        Ok(response) => response.refused?,
        Err(error) => WorkRefused {
            code: WorkRefusalCode::Unavailable as i32,
            reason: error.to_string(),
            grant: None,
        },
    };
    Some(AcceptWorkResponse {
        outcome: Some(accept_work_response::Outcome::Refused(refusal)),
    })
}
