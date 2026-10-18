use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_auth::authority::{GrantId, Revision, UnixMillis};
use hellas_auth::{Digest, PublicKey};
use hellas_kernel::NetworkId;
use hellas_rpc::*;
use hellas_work::model::grant::records::{
    decode_contact, grant_producer, grant_transport, principal_id, verify_contact,
};
use hellas_work::model::{
    fetch::*,
    grant::{records::*, resource::*, *},
    profile::WorkPolicy,
};
use hellas_work::test_support::{principal, software_enrollment};
use std::num::NonZeroU64;
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
fn contact_proof_offer_signature_and_actor_channel_binding_are_not_advisory() {
    let key = principal(1).1;
    let provider = software_enrollment(1, [1; 32]);
    let client_key = principal(2).1;
    let client = software_enrollment(2, [2; 32]);
    let (stranger, _) = principal(3);
    let mut bad = client.clone();
    bad.genesis.statement.transport_public_key = PublicKey::Ed25519([9; 32]);
    assert!(matches!(verify_contact(&bad), Err(GrantError::Signature)));
    let network = NetworkId::new("grant-fixture").unwrap();
    let route = FetchRoutePolicy::sealed_route("http", "request").unwrap();
    let policy = GrantPolicy {
        resource: hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test resource")),
        account: hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test account")),
        revision: hellas_auth::authority::Revision(1),
        name: "glm".into(),
        work: WorkPolicy::Fetch {
            contract: hellas_rpc::FetchContract::http().unwrap(),
            policy: FetchPolicyV2 {
                allowed_environment: hellas_rpc::FetchContract::http().unwrap().manifest_id(),
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
        pricing: hellas_work::model::grant::pricing::Pricing {
            revision: hellas_auth::authority::Revision(1),
            rates: None,
        },
        responses: None,
    };
    let grant = GrantDef {
        id: GrantId([7; 16]),
        revision: Revision(1),
        policies: vec![policy],
        budget: budget::BudgetNode::Subject {
            pool: budget::PoolId([1; 16]),
            subject: principal_id(&client).unwrap(),
        },
        max_job_millis: NonZeroU64::new(10000).unwrap(),
        enabled: true,
        allow_account_backed: true,
    };
    let offer = Offer {
        network,
        provider: provider.clone(),
        grant,
        generation: 0,
        sequence: 1,
        valid_until: UnixMillis(2000),
        addresses: vec![],
    };
    let signed = SignedOffer::sign(offer, &key).unwrap();
    let mut empty = signed.offer().clone();
    empty.grant.policies.clear();
    assert_eq!(SignedOffer::sign(empty, &key), Err(GrantError::Limits));
    let bytes = signed.encode().unwrap();
    let mut other_device = client.clone();
    other_device.genesis.statement.transport_public_key = PublicKey::Ed25519([42; 32]);
    other_device.genesis.statement.installation_nonce = [43; 32];
    other_device.genesis.root_proof = RootProof::Software(
        client_key
            .sign_digest(Digest::hash(
                &other_device.genesis.statement.canonical_bytes(),
            ))
            .unwrap(),
    );
    verify_contact(&other_device).unwrap();
    assert_ne!(other_device.content_id(), client.content_id());
    assert_ne!(
        grant_transport(&other_device).unwrap(),
        grant_transport(&client).unwrap()
    );
    assert_eq!(
        principal_id(&other_device).unwrap(),
        principal_id(&client).unwrap()
    );
    assert_eq!(
        grant_producer(&other_device).unwrap(),
        grant_producer(&client).unwrap()
    );
    assert_eq!(
        principal_id(&other_device).unwrap(),
        hellas_auth::authority::PrincipalId::from_public_key(client_key.public_key()).unwrap()
    );
    assert_eq!(
        principal_id(&decode_contact(&other_device.canonical_bytes()).unwrap()).unwrap(),
        principal_id(&client).unwrap()
    );
    assert_eq!(
        SignedOffer::decode(&bytes, UnixMillis(1000)).unwrap(),
        signed
    );
    assert_eq!(
        signed.offer().channel(principal_id(&client).unwrap()),
        grant_channel_id(
            network,
            provider.content_id(),
            GrantId([7; 16]),
            principal_id(&other_device).unwrap(),
            0
        )
    );

    let locator = standing::StandingLocator {
        provider: provider.content_id(),
        grant: GrantId([7; 16]),
        client: principal_id(&client).unwrap(),
        generation: 9,
    };
    let encoded = locator.encode();
    assert_eq!(
        standing::StandingLocator::decode(&encoded).unwrap(),
        locator
    );
    assert!(standing::StandingLocator::decode(&encoded[..88]).is_err());
    let mut invalid = encoded.to_vec();
    invalid.push(0);
    assert!(standing::StandingLocator::decode(&invalid).is_err());
    let mut invalid = encoded;
    invalid[48..81].fill(0);
    assert_eq!(
        standing::StandingLocator::decode(&invalid),
        Err(GrantError::UnsupportedKey)
    );
    assert_eq!(
        SignedOffer::decode(&bytes, UnixMillis(1000)).unwrap(),
        signed
    );
    assert_ne!(
        signed.offer().channel(stranger),
        signed.offer().channel(principal_id(&client).unwrap())
    );
    assert_eq!(
        SignedOffer::decode(&bytes, UnixMillis(2000)),
        Err(GrantError::Expired)
    );
    let owner = owner_grant_id(
        network,
        provider.content_id(),
        principal_id(&client).unwrap(),
    );
    assert_eq!(
        owner,
        owner_grant_id(
            network,
            provider.content_id(),
            principal_id(&other_device).unwrap()
        )
    );
    assert_ne!(
        owner,
        owner_grant_id(
            network,
            client.content_id(),
            principal_id(&provider).unwrap()
        )
    );
    assert_ne!(
        owner,
        owner_grant_id(
            NetworkId::new("different").unwrap(),
            provider.content_id(),
            principal_id(&client).unwrap()
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
fn contacts_explicitly_refuse_unsupported_roots_and_keys() {
    let valid = software_enrollment(1, [1; 32]);
    let mut unsupported = valid.clone();
    unsupported.genesis.statement.root_kind = RootKind::SecureEnclave;
    assert!(matches!(
        verify_contact(&unsupported),
        Err(GrantError::UnsupportedRoot)
    ));
    let mut unsupported = valid.clone();
    unsupported.genesis.root_proof = RootProof::AppleAppAttest(vec![]);
    assert!(matches!(
        verify_contact(&unsupported),
        Err(GrantError::UnsupportedRoot)
    ));
    for producer in [true, false] {
        let mut unsupported = valid.clone();
        if producer {
            unsupported.genesis.statement.producer_public_key = PublicKey::Ed25519([1; 32]);
        } else {
            unsupported.genesis.statement.transport_public_key =
                valid.genesis.statement.producer_public_key;
        }
        assert!(matches!(
            verify_contact(&unsupported),
            Err(GrantError::UnsupportedKey)
        ));
    }
}
