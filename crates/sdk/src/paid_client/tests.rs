use super::*;
use hellas_rpc::pb::execute::{OpenRequest, OpenResponse, open_response};
use hellas_rpc::{
    Assurance, Digest, PlatformCredential, PlatformEnrollment, ProducerSigningKey,
    ProviderEnrollmentBundle, ProviderGenesisStatement, PublicKey, RootKind, RootProof,
    SignedProviderGenesis,
};
use hellas_wire::{MethodMarker, StreamTransport, WireStatus};

fn enrollment(peer: EndpointId) -> (ProviderEnrollmentBundle, ProducerSigningKey) {
    let root = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
    let producer = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
    let statement = ProviderGenesisStatement {
        root_kind: RootKind::Software,
        root_public_key: root.public_key(),
        producer_public_key: producer.public_key(),
        transport_public_key: PublicKey::Ed25519(*peer.as_bytes()),
        platform_credential: PlatformCredential::Absent,
        installation_nonce: [3; 32],
    };
    let proof = root
        .sign_digest(Digest::hash(&statement.canonical_bytes()))
        .unwrap();
    (
        ProviderEnrollmentBundle {
            genesis: SignedProviderGenesis {
                statement,
                root_proof: RootProof::Software(proof),
            },
            platform: PlatformEnrollment::Absent,
        },
        producer,
    )
}

async fn serve_open<M>(
    transport: &IrohTransport,
    bundle: ProviderEnrollmentBundle,
    producer: ProducerSigningKey,
) where
    M: MethodMarker<Request = OpenRequest, Response = OpenResponse>,
{
    let inbound = transport.accept().await.unwrap().unwrap();
    // A paid request must never be the first RPC on a trusted connection.
    assert_eq!(inbound.method_id, M::METHOD_ID);
    hellas_rpc::call::dispatch_unary_with_context::<IrohTransport, M, _, _, _>(
        inbound,
        move |request, context| async move {
            let nonce: [u8; 32] = request.nonce.try_into().unwrap();
            let binding = hellas_rpc::open_proof_binding(
                &context.open_exporter.unwrap(),
                &nonce,
                &producer.public_key(),
                bundle.content_id(),
                M::Service::ALPN.as_bytes(),
            );
            Ok::<_, WireStatus>(OpenResponse {
                provider_genesis: bundle.canonical_bytes(),
                proof: Some(open_response::Proof::ProducerSignature(
                    hellas_rpc::run_ticket::signature_to_pb(
                        &producer.sign_digest(binding).unwrap(),
                    ),
                )),
            })
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn both_paid_connections_open_before_disclosure_and_refuse_wrong_assurance_or_party() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let server = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[4; 32]))
            .alpns(vec![
                hellas_rpc::services::work::Work::ALPN.as_bytes().to_vec(),
                hellas_rpc::services::work_setup::WorkSetup::ALPN
                    .as_bytes()
                    .to_vec(),
            ])
            .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let (bundle, key) = enrollment(server.id());
        let trust = hellas_client::ProviderTrustAnchor {
            expected_genesis: bundle.content_id(),
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        };
        let addresses = server.bound_sockets();
        let serving = server.clone();
        let (done, completed) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = Vec::new();
            for _ in 0..4 {
                let connection = serving.accept().await.unwrap().await.unwrap();
                let setup = connection.alpn()
                    == hellas_rpc::services::work_setup::WorkSetup::ALPN.as_bytes();
                let transport = IrohTransport::new(connection);
                if setup {
                    serve_open::<hellas_rpc::services::work_setup::Open>(
                        &transport,
                        bundle.clone(),
                        key.clone(),
                    )
                    .await;
                } else {
                    serve_open::<hellas_rpc::services::work::Open>(
                        &transport,
                        bundle.clone(),
                        key.clone(),
                    )
                    .await;
                }
                connections.push(transport);
            }
            let _ = completed.await;
        });
        let mut dialer = ProviderDialer::new(
            server.id(),
            addresses,
            bind_paid_endpoint(SecretKey::from_bytes(&[5; 32]))
                .await
                .unwrap(),
            Some(trust),
        );
        dialer.setup().await.expect("setup authenticates");
        dialer.work().await.expect("work authenticates");
        *dialer.producer.lock().unwrap() = Some(
            ProducerSigningKey::from_secret_bytes([6; 32])
                .unwrap()
                .public_key(),
        );
        let error = dialer
            .work()
            .await
            .err()
            .expect("different payment party is refused");
        assert!(
            error
                .to_string()
                .contains("differs from the payment channel")
        );
        *dialer.producer.lock().unwrap() = None;
        dialer.trust.as_mut().unwrap().required_assurance = Assurance::AppleAppAttest;
        let error = dialer
            .setup()
            .await
            .err()
            .expect("software proof cannot satisfy App Attest");
        assert!(error.to_string().contains("Secure Enclave provider root"));
        done.send(()).unwrap();
        task.await.unwrap();
        dialer.endpoint.close().await;
        server.close().await;
    })
    .await
    .unwrap();
}

#[test]
fn recovery_skips_only_permanent_delivery_refusals() {
    use hellas_client::work::CollectResultError;
    use hellas_work::work::{DeliverError, WorkRefusal};

    for (refusal, permanent) in [
        (WorkRefusal::Declined, true),
        (WorkRefusal::Expired, true),
        (WorkRefusal::NotReady, false),
        (WorkRefusal::Unavailable, false),
    ] {
        let delivery = || DeliverError::Refused {
            refusal,
            reason: "provider diagnostic".to_owned(),
        };
        assert_eq!(permanently_refused_delivery(&delivery().into()), permanent);
        assert_eq!(
            permanently_refused_delivery(&CollectResultError::Deliver(delivery()).into()),
            permanent,
        );
    }
    assert!(!permanently_refused_delivery(
        &DeliverError::Malformed("result").into()
    ));
    assert!(!permanently_refused_delivery(&anyhow::anyhow!(
        "connection lost"
    )));
}

fn fetch_request(
    assurance: Assurance,
    retention: hellas_rpc::Retention,
) -> (ProviderChannelPolicy, PreparedPaidWorkInput, PublicKey) {
    use hellas_rpc::protocol::work::PaidChannelPolicyV1;
    use hellas_rpc::protocol::work_fetch::{
        FetchRoutePolicy, PaidFetchPolicyV1, PreparedPaidFetchInputV1, fetch_route_commitment,
    };
    let environment = hellas_rpc::FetchEnvironment::OpenAiResponses;
    let caller = ProducerSigningKey::from_secret_bytes([7; 32]).unwrap();
    let events = hellas_rpc::fetch::build_input_events_with_retention(
        "openai",
        "responses",
        br#"{"input":"private request"}"#,
        environment.manifest_id(),
        assurance,
        &caller,
        retention,
    )
    .unwrap();
    let prepared = PreparedPaidFetchInputV1::new(&events, &environment.manifest())
        .unwrap()
        .into();
    let route = FetchRoutePolicy::sealed_route("openai", "responses").unwrap();
    let policy = ProviderChannelPolicy {
        network: hellas_kernel::NetworkId::new("paid-client-test").unwrap(),
        policy_salt: [8; 32],
        channel_policy: PaidChannelPolicyV1 {
            compute_credit_limit: 40,
            delivery_credit_limit: 40,
        },
        execution_policy: PaidWorkPolicy::Fetch {
            policy: PaidFetchPolicyV1 {
                allowed_environment: environment.manifest_id(),
                route_commitment: fetch_route_commitment(&route.canonical_body_bytes()).unwrap(),
                max_request_body_bytes: 4096,
                max_output_events: 64,
                max_output_bytes: 16384,
                max_spool_bytes: 65536,
                max_encoded_result_frame: 65536,
                max_encoded_prepared_input: 65536,
                dispatch_margin_blocks: 4,
                delivery_margin_blocks: 2,
                oracle_grace_blocks: 6,
                fixed_price: 10,
            },
            route,
        },
        expected_payment_values: hellas_kernel::EdgeValues::new(
            1000,
            200,
            hellas_kernel::Fees::ZERO,
        ),
        min_omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
    };
    (policy, prepared, caller.public_key())
}

#[test]
fn fetch_preflight_requires_matching_trust_caller_and_ephemeral_retention() {
    use hellas_rpc::Retention;
    let (policy, prepared, caller) = fetch_request(Assurance::AppleAppAttest, Retention::Ephemeral);
    let error = check_request(&policy, &prepared, None, caller).unwrap_err();
    assert!(error.to_string().contains("trust anchor before disclosure"));
    let mut trust = hellas_client::ProviderTrustAnchor {
        expected_genesis: hellas_rpc::ContentId::from_bytes([8; 32]),
        required_assurance: Assurance::ProducerSigned,
        apple_app_attest: None,
    };
    assert!(
        check_request(&policy, &prepared, Some(&trust), caller)
            .unwrap_err()
            .to_string()
            .contains("assurance differs")
    );
    trust.required_assurance = Assurance::AppleAppAttest;
    // Preflight checks the anchor selection; the live Open validates its proof.
    check_request(&policy, &prepared, Some(&trust), caller).unwrap();
    let other = ProducerSigningKey::from_secret_bytes([9; 32])
        .unwrap()
        .public_key();
    assert!(
        check_request(&policy, &prepared, Some(&trust), other)
            .unwrap_err()
            .to_string()
            .contains("caller does not match")
    );
    let (policy, prepared, caller) = fetch_request(Assurance::ProducerSigned, Retention::Ephemeral);
    check_request(&policy, &prepared, None, caller).unwrap();
    assert_eq!(prepared.assurance().unwrap(), Assurance::ProducerSigned);
    let (policy, retained, caller) = fetch_request(Assurance::ProducerSigned, Retention::Retain);
    assert!(
        check_request(&policy, &retained, None, caller)
            .unwrap_err()
            .to_string()
            .contains("ephemeral retention")
    );
}
