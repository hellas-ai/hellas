#![cfg(feature = "work")]
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_kernel::NetworkId;
use hellas_rpc::{
    protocol::{
        work_fetch::*,
        work_grant::{records::*, resource::*, *},
        work_profile::WorkPolicy,
    },
    *,
};
use std::num::{NonZeroU16, NonZeroU64};
fn principal(n: u8) -> (Principal, ProducerSigningKey) {
    let key = ProducerSigningKey::from_secret_bytes([n; 32]).unwrap();
    let statement = ProviderGenesisStatement {
        root_kind: RootKind::Software,
        root_public_key: key.public_key(),
        producer_public_key: key.public_key(),
        transport_public_key: PublicKey::Ed25519([n; 32]),
        platform_credential: PlatformCredential::Absent,
        installation_nonce: [n; 32],
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
fn resource() -> HttpsResource {
    HttpsResource {
        origin: "https://glm.lan:8443".into(),
        paths: vec!["/v1/chat/completions".into()],
        methods: vec!["POST".into()],
        credential: Some("glm".into()),
        tls: http_fetch::HttpTls {
            roots: http_fetch::HttpTrustRoots::Certificates {
                der_base64: vec![STANDARD.encode(b"fixture DER")],
            },
            spki_sha256: vec![],
        },
        accounting: AccountingProfile::OpenaiChat,
        max_output_tokens: 16,
        max_response_bytes: 4096,
    }
}
fn request(body: serde_json::Value) -> http_fetch::HttpFetchRequest {
    let r = resource();
    http_fetch::HttpFetchRequest {
        url: format!("{}{}", r.origin, r.paths[0]),
        method: "POST".into(),
        headers: vec![],
        body_base64: STANDARD.encode(serde_json::to_vec(&body).unwrap()),
        tls: r.tls,
        credential: r.credential,
        max_response_bytes: r.max_response_bytes,
    }
}
#[test]
fn signed_template_is_exact_and_only_client_repairs_generation() {
    let r = resource();
    r.validate().unwrap();
    let mut req = request(serde_json::json!({"stream":true,"messages":[]}));
    assert_eq!(r.matches(&req), Err(TemplateError::GenerationCap));
    assert_eq!(r.prepare(&mut req), Ok(16));
    assert_eq!(r.matches(&req), Ok(16));
    let body: serde_json::Value = serde_json::from_slice(&req.body().unwrap()).unwrap();
    assert_eq!(body["stream_options"]["include_usage"], true);
    for (field, expected) in [
        (0, TemplateError::Origin),
        (1, TemplateError::PathMethod),
        (2, TemplateError::Tls),
        (3, TemplateError::Credential),
    ] {
        let mut altered = req.clone();
        match field {
            0 => altered.url = "https://elsewhere.lan/v1/chat/completions".into(),
            1 => altered.method = "GET".into(),
            2 => altered.tls.roots = http_fetch::HttpTrustRoots::WebPki,
            _ => altered.credential = None,
        };
        assert_eq!(r.matches(&altered), Err(expected));
    }
    for body in [
        serde_json::json!({"max_tokens":17}),
        serde_json::json!({"max_tokens":4,"n":2}),
        serde_json::json!({"max_tokens":4,"max_completion_tokens":8}),
        serde_json::json!({"stream":true,"stream_options":null}),
    ] {
        let mut req = request(body);
        let before = req.clone();
        assert!(r.prepare(&mut req).is_err());
        assert_eq!(req, before);
    }
}
#[test]
fn enrollment_proof_and_private_offer_audience_are_not_advisory() {
    let (provider, key) = principal(1);
    let (client, _) = principal(2);
    let (stranger, _) = principal(3);
    let mut bad = client.bundle().clone();
    bad.genesis.statement.transport_public_key = PublicKey::Ed25519([9; 32]);
    assert!(matches!(Principal::verify(bad), Err(GrantError::Signature)));
    let network = NetworkId::new("grant-fixture").unwrap();
    let route = FetchRoutePolicy::sealed_route("http", "request").unwrap();
    let policy = GrantPolicy {
        name: "glm".into(),
        work: WorkPolicy::Fetch {
            policy: FetchPolicyV2 {
                allowed_environment: FetchEnvironment::Http.manifest_id(),
                route_commitment: fetch_route_commitment(&route.canonical_body_bytes()).unwrap(),
                max_request_body_bytes: 4096,
                max_output_events: 64,
                max_output_bytes: 65536,
                max_spool_bytes: 131072,
                max_encoded_result_frame: 131072,
                max_encoded_prepared_input: 65536,
            },
            route,
        },
        https: Some(resource()),
    };
    let grant = GrantDef {
        id: GrantId([7; 16]),
        revision: Revision(1),
        kind: GrantKind::Principal(client.clone()),
        policies: vec![policy],
        limits: vec![],
        weight: NonZeroU16::new(1).unwrap(),
        max_job_millis: NonZeroU64::new(10000).unwrap(),
        max_in_flight: NonZeroU16::new(2).unwrap(),
        expires: None,
        state: GrantState::Active,
        allow_account_backed: true,
    };
    let offer = Offer {
        network,
        provider: provider.bundle().clone(),
        grant,
        generation: 0,
        sequence: 1,
        valid_until: UnixMillis(2000),
        addresses: vec![],
    };
    let signed = SignedOffer::sign(offer, &key).unwrap();
    let bytes = signed.encode().unwrap();
    assert_eq!(
        SignedOffer::decode(&bytes, client.id(), UnixMillis(1000)).unwrap(),
        signed
    );
    assert_eq!(
        SignedOffer::decode(&bytes, stranger.id(), UnixMillis(1000)),
        Err(GrantError::Audience)
    );
    assert_eq!(
        SignedOffer::decode(&bytes, client.id(), UnixMillis(2000)),
        Err(GrantError::Expired)
    );
    let owner = owner_grant_id(network, provider.bundle().content_id(), client.id());
    assert_eq!(
        owner,
        owner_grant_id(network, provider.bundle().content_id(), client.id())
    );
    assert_ne!(
        owner,
        owner_grant_id(network, client.bundle().content_id(), provider.id())
    );
    assert_ne!(
        owner,
        owner_grant_id(
            NetworkId::new("different").unwrap(),
            provider.bundle().content_id(),
            client.id()
        )
    );
}

#[test]
fn duplicate_request_fields_cannot_bypass_a_token_cap() {
    let resource = resource();
    for body in [
        r#"{"max_tokens":1000000,"max_tokens":4}"#,
        r#"{"max_tokens":4,"stream":true,"stream_options":{"include_usage":false,"include_usage":true}}"#,
    ] {
        let mut signed = request(serde_json::json!({}));
        signed.body_base64 = STANDARD.encode(body);
        assert_eq!(resource.matches(&signed), Err(TemplateError::Malformed));
        let original = signed.clone();
        assert_eq!(resource.prepare(&mut signed), Err(TemplateError::Malformed));
        assert_eq!(signed, original);
    }
}

#[test]
fn grant_principals_explicitly_refuse_unsupported_roots_and_keys() {
    let valid = principal(1).0;
    let mut unsupported = valid.bundle().clone();
    unsupported.genesis.statement.root_kind = RootKind::SecureEnclave;
    assert!(matches!(
        Principal::verify(unsupported),
        Err(GrantError::UnsupportedRoot)
    ));
    let mut unsupported = valid.bundle().clone();
    unsupported.genesis.root_proof = RootProof::AppleAppAttest(vec![]);
    assert!(matches!(
        Principal::verify(unsupported),
        Err(GrantError::UnsupportedRoot)
    ));
    for producer in [true, false] {
        let mut unsupported = valid.bundle().clone();
        if producer {
            unsupported.genesis.statement.producer_public_key = PublicKey::Ed25519([1; 32]);
        } else {
            unsupported.genesis.statement.transport_public_key =
                valid.bundle().genesis.statement.producer_public_key;
        }
        assert!(matches!(
            Principal::verify(unsupported),
            Err(GrantError::UnsupportedKey)
        ));
    }
}
