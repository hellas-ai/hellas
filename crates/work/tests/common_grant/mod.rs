use hellas_kernel::NetworkId;
use hellas_rpc::{
    protocol::{
        work_fetch::*,
        work_grant::{budget::*, records::*, *},
        work_profile::*,
    },
    *,
};
use hellas_work::work_store::grant::GrantStore;
use std::num::{NonZeroU16, NonZeroU64};
pub fn network() -> NetworkId {
    NetworkId::new("grants-fixture").unwrap()
}
pub fn principal(seed: u8) -> (Principal, ProducerSigningKey) {
    let key = ProducerSigningKey::from_secret_bytes([seed; 32]).unwrap();
    let statement = ProviderGenesisStatement {
        root_kind: RootKind::Software,
        root_public_key: key.public_key(),
        producer_public_key: key.public_key(),
        transport_public_key: PublicKey::Ed25519([seed; 32]),
        platform_credential: PlatformCredential::Absent,
        installation_nonce: [seed; 32],
    };
    let proof = key
        .sign_digest(Digest::hash(&statement.canonical_bytes()))
        .unwrap();
    (
        Principal::verify(ProviderEnrollmentBundle {
            genesis: SignedProviderGenesis {
                statement,
                root_proof: RootProof::Software(proof),
            },
            platform: PlatformEnrollment::Absent,
        })
        .unwrap(),
        key,
    )
}
pub fn policy() -> GrantPolicy {
    let route = FetchRoutePolicy::sealed_route("openai", "responses").unwrap();
    GrantPolicy {
        name: "responses".into(),
        work: WorkPolicy::Fetch {
            policy: FetchPolicyV2 {
                allowed_environment: FetchEnvironment::OpenAiResponses.manifest_id(),
                route_commitment: fetch_route_commitment(&route.canonical_body_bytes()).unwrap(),
                max_request_body_bytes: 4096,
                max_output_events: 64,
                max_output_bytes: 1_048_576,
                max_spool_bytes: 65_536,
                max_encoded_result_frame: 262_144,
                max_encoded_prepared_input: 1_048_576,
            },
            route,
        },
        https: None,
    }
}
pub fn definition(id: GrantId, client: Principal) -> GrantDef {
    GrantDef {
        id,
        revision: Revision(1),
        kind: GrantKind::Principal(client),
        policies: vec![policy()],
        limits: vec![Limit {
            meter: Meter::Requests,
            window: Window::Total,
            amount: 3,
        }],
        max_job_millis: NonZeroU64::new(10000).unwrap(),
        max_in_flight: NonZeroU16::new(2).unwrap(),
        expires: None,
        state: GrantState::Active,
        allow_account_backed: true,
    }
}
pub fn setup(path: &std::path::Path) -> GrantStore {
    let mut store = GrantStore::open(
        path,
        network(),
        principal(2).0.bundle().clone(),
        UnixMillis(1_000),
    )
    .unwrap();
    store
        .configure_machine(
            vec![Limit {
                meter: Meter::Requests,
                window: Window::Total,
                amount: 4,
            }],
            4,
            UnixMillis(1_000),
        )
        .unwrap();
    store
        .define(
            definition(GrantId([1; 16]), principal(1).0),
            UnixMillis(1_000),
        )
        .unwrap();
    store
}
pub fn proposal(
    store: &GrantStore,
    nonce: u64,
) -> (GrantJobAuthorizationV1, Signature, PreparedWorkInput) {
    let id = GrantId([1; 16]);
    let def = store.state().grant(id).unwrap();
    let channel = store.state().channel_id(id).unwrap();
    let key = principal(1).1;
    let environment = if def.policies[0].https.is_some() {
        FetchEnvironment::Http
    } else {
        FetchEnvironment::OpenAiResponses
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
        b"{\"secret\":\"never-journal-this-body\"}".to_vec()
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
    let input: PreparedWorkInput = PreparedPaidFetchInputV1::new(&events, &environment.manifest())
        .unwrap()
        .into();
    let a = GrantJobAuthorizationV1 {
        channel_id: channel,
        grant_id: id,
        grant_revision: def.revision,
        catalogue_revision: Revision(0),
        work_policy_digest: def.policies[0].work.digest(network(), channel.0),
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
