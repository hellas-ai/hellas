use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_auth::PublicKey;
use hellas_auth::authority::{GrantId, Revision, UnixMillis};
use hellas_authority::model::grant::records::verify_software_enrollment;
use hellas_channel::test_support::{channel_client, principal, software_enrollment};
use hellas_kernel::NetworkId;
use hellas_rpc::*;
use std::num::NonZeroU64;
use {
    hellas_authority::model::grant::records::*, hellas_authority::model::grant::resource::*,
    hellas_authority::model::grant::*, hellas_rpc::protocol::invocation::InvocationPolicy,
    hellas_rpc::protocol::invocation::fetch::*,
};
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
    let (client_principal, _) = principal(2);
    let client = software_enrollment(2, [2; 32]);
    let (stranger, _) = principal(3);
    let mut bad = client.clone();
    bad.genesis.statement.transport_public_key = PublicKey::Ed25519([9; 32]);
    assert!(matches!(
        verify_software_enrollment(&bad),
        Err(GrantError::Signature)
    ));
    let network = NetworkId::new("grant-fixture").unwrap();
    let route = FetchRoutePolicy::sealed_route("http", "request").unwrap();
    let policy = GrantPolicy {
        resource: hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test resource")),
        account: hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test account")),
        revision: hellas_auth::authority::Revision(1),
        name: "glm".into(),
        invocation_policy: InvocationPolicy {
            admissions: vec![hellas_rpc::protocol::invocation::Admission::Fetch {
                admission: FetchAdmission {
                    contract: hellas_rpc::FetchContract::http().unwrap(),
                    route,
                    limits: FetchLimits {
                        max_request_body_bytes: 4096,
                        max_output_events: 64,
                        max_spool_bytes: 131072,
                        max_encoded_result_frame: 131072,
                        max_encoded_prepared_input: 65536,
                    },
                },
            }],
            limits: hellas_rpc::protocol::invocation::Limits {
                max_upload_bytes: 65536,
                max_output_bytes: 65536,
                max_steps: 128,
                execution_timeout_ms: 10_000,
            },
        },
        https: Some(resource()),
        pricing: hellas_authority::model::grant::pricing::Pricing {
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
            subject: client_principal,
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
    assert_eq!(
        SignedOffer::decode(&bytes, UnixMillis(1000)).unwrap(),
        signed
    );
    let client_channel = channel_client(client_principal);
    assert_eq!(
        signed.offer().channel(client_channel),
        grant_channel_id(
            network,
            provider.content_id(),
            GrantId([7; 16]),
            client_channel,
            0
        )
    );

    let locator = standing::StandingLocator {
        provider: provider.content_id(),
        grant: GrantId([7; 16]),
        client: client_channel,
        generation: 9,
    };
    let encoded = locator.encode();
    // The principal and the node key travel with their curve tags.
    assert_eq!(encoded.len(), 124);
    assert_eq!(encoded[48], hellas_auth::SignatureKind::P256.to_byte());
    assert_eq!(encoded[49..82], client_principal.as_bytes()[..]);
    assert_eq!(encoded[82], hellas_auth::SignatureKind::Secp256k1.to_byte());
    assert_eq!(encoded[83..116], client_channel.node.as_bytes()[..]);
    assert_eq!(encoded[116..], 9u64.to_be_bytes());
    assert_eq!(
        standing::StandingLocator::decode(&encoded).unwrap(),
        locator
    );
    assert!(standing::StandingLocator::decode(&encoded[..123]).is_err());
    let mut invalid = encoded.to_vec();
    invalid.push(0);
    assert!(standing::StandingLocator::decode(&invalid).is_err());
    let mut invalid = encoded;
    invalid[48] = hellas_auth::SignatureKind::Secp256k1.to_byte();
    assert_eq!(
        standing::StandingLocator::decode(&invalid),
        Err(GrantError::UnsupportedKey)
    );
    let mut invalid = encoded;
    invalid[49..82].fill(0);
    assert_eq!(
        standing::StandingLocator::decode(&invalid),
        Err(GrantError::UnsupportedKey)
    );
    let mut invalid = encoded;
    invalid[82] = hellas_auth::SignatureKind::P256.to_byte();
    assert_eq!(
        standing::StandingLocator::decode(&invalid),
        Err(GrantError::UnsupportedKey)
    );
    let mut invalid = encoded;
    invalid[83..116].fill(0);
    assert_eq!(
        standing::StandingLocator::decode(&invalid),
        Err(GrantError::UnsupportedKey)
    );
    assert_eq!(
        SignedOffer::decode(&bytes, UnixMillis(1000)).unwrap(),
        signed
    );
    assert_ne!(
        signed.offer().channel(channel_client(stranger)),
        signed.offer().channel(client_channel)
    );
    // The same principal on another device opens another channel.
    assert_ne!(
        signed.offer().channel(ChannelClient {
            principal: client_principal,
            node: hellas_auth::authority::NodeKey::from_public_key(principal(4).1.public_key())
                .unwrap(),
        }),
        signed.offer().channel(client_channel)
    );
    assert_eq!(
        SignedOffer::decode(&bytes, UnixMillis(2000)),
        Err(GrantError::Expired)
    );
    let owner = owner_grant_id(network, provider.content_id(), client_principal);
    assert_ne!(
        owner,
        owner_grant_id(network, client.content_id(), principal(1).0)
    );
    assert_ne!(
        owner,
        owner_grant_id(
            NetworkId::new("different").unwrap(),
            provider.content_id(),
            client_principal
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
        verify_software_enrollment(&unsupported),
        Err(GrantError::UnsupportedRoot)
    ));
    let mut unsupported = valid.clone();
    unsupported.genesis.root_proof = RootProof::AppleAppAttest(vec![]);
    assert!(matches!(
        verify_software_enrollment(&unsupported),
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
            verify_software_enrollment(&unsupported),
            Err(GrantError::UnsupportedKey)
        ));
    }
}
