use super::*;
use crate::test_support::enrollment;
#[cfg(feature = "paid-provider")]
mod offer;
mod recovery;
use hellas_rpc::pb::execute::{OpenRequest, OpenResponse, open_response};
use hellas_rpc::{Assurance, ProducerSigningKey, ProviderEnrollmentBundle, PublicKey};
use hellas_wire::{MethodMarker, StreamTransport, WireStatus};

#[tokio::test]
async fn insufficient_collateral_is_rejected_before_network_or_journal_creation() {
    let (policy, _, _) = fetch_request(Assurance::ProducerSigned, hellas_rpc::Retention::Ephemeral);
    let root = tempfile::tempdir().unwrap();
    let journal_root = root.path().join("journal");
    let endpoint = Endpoint::builder(presets::Minimal)
        .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let args = PaidWorkOptions {
        config: WorkConfig {
            payment_policy: payment_policy(),
            chain: crate::work_config::ChainCrossCheck {
                network: policy.network,
                genesis_payload_digest: [0; 32].into(),
                threshold_identity: Vec::new(),
            },
            // No chain is needed to reject these terms.
            validators: Vec::new(),
            journal_root: root.path().join("provider"),
            routes: Default::default(),
            policy_salt: policy.policy_salt,
            channel_policy: policy.channel_policy,
            work_policy: policy.work_policy,
            poll: Duration::from_millis(200),
            max_observation_age: Duration::from_secs(5),
            expected_payment_values: hellas_kernel::EdgeValues::new(
                1000,
                0,
                hellas_kernel::Fees::ZERO,
            ),
            min_omit_response_blocks: policy.min_omit_response_blocks,
        },
        journal_root: journal_root.clone(),
        provider: endpoint.id(),
        provider_addrs: Vec::new(),
        provider_trust: crate::test_support::provider_trust(endpoint.id()),
        bond: EdgeId::from_bytes([0; 32]),
        payment_funding: Funding::new(
            hellas_kernel::List::empty(hellas_kernel::CoinId::from_bytes([0; 32])),
            hellas_kernel::List::empty(hellas_kernel::CoinId::from_bytes([0; 32])),
        ),
        omission_bond: 51,
        acceptance_blocks: 300,
        terminal_blocks: 3000,
        payment_blocks: 600,
        timeout: Duration::from_secs(30),
    };
    let result = PaidWorkSession::open(
        args,
        endpoint.clone(),
        Secp256k1Signer::from_secret_scalar([1; 32]).unwrap(),
    )
    .await;
    assert!(matches!(
        result,
        Err(PaidClientError::WorkSetup(
            hellas_rpc::protocol::work_setup::WorkSetupError::Undercollateralised {
                bond: 51,
                capacity: 949,
            }
        ))
    ));
    assert!(!journal_root.exists());
    endpoint.close().await;
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
                    hellas_rpc::signature_wire::signature_to_pb(
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
            trust,
        );
        let setup = dialer.setup().await.expect("setup authenticates");
        let work = dialer.work().await.expect("work authenticates");
        for _ in 0..3 {
            assert_eq!(
                setup.open_exporter().unwrap(),
                dialer.setup().await.unwrap().open_exporter().unwrap()
            );
            assert_eq!(
                work.open_exporter().unwrap(),
                dialer.work().await.unwrap().open_exporter().unwrap()
            );
        }
        work.connection().close(0u32.into(), b"test reconnect");
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
                .contains("differs from the pinned producer")
        );
        *dialer.producer.lock().unwrap() = None;
        setup.connection().close(0u32.into(), b"test reconnect");
        dialer.trust.required_assurance = Assurance::AppleAppAttest;
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
    assert!(!permanently_refused_delivery(&PaidClientError::Timeout {
        stage: "connection"
    }));
}

fn fetch_request(
    assurance: Assurance,
    retention: hellas_rpc::Retention,
) -> (ProviderChannelPolicy, PreparedWorkInput, PublicKey) {
    use hellas_rpc::protocol::work::PaidChannelPolicyV1;
    use hellas_rpc::protocol::work_fetch::{
        FetchPolicyV2, FetchRoutePolicy, PreparedPaidFetchInputV1, fetch_route_commitment,
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
        payment_policy: payment_policy(),
        network: hellas_kernel::NetworkId::new("paid-client-test").unwrap(),
        policy_salt: [8; 32],
        channel_policy: PaidChannelPolicyV1 {
            compute_credit_limit: 40,
            delivery_credit_limit: 40,
        },
        work_policy: WorkPolicy::Fetch {
            policy: FetchPolicyV2 {
                allowed_environment: environment.manifest_id(),
                route_commitment: fetch_route_commitment(&route.canonical_body_bytes()).unwrap(),
                max_request_body_bytes: 4096,
                max_output_events: 64,
                max_output_bytes: 16384,
                max_spool_bytes: 65536,
                max_encoded_result_frame: 65536,
                max_encoded_prepared_input: 65536,
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
    let mut trust = hellas_client::ProviderTrustAnchor {
        expected_genesis: hellas_rpc::ContentId::from_bytes([8; 32]),
        required_assurance: Assurance::ProducerSigned,
        apple_app_attest: None,
    };
    assert!(
        check_request(&policy, &prepared, &trust, caller)
            .unwrap_err()
            .to_string()
            .contains("assurance differs")
    );
    trust.required_assurance = Assurance::AppleAppAttest;
    // Preflight checks the anchor selection; the live Open validates its proof.
    check_request(&policy, &prepared, &trust, caller).unwrap();
    let other = ProducerSigningKey::from_secret_bytes([9; 32])
        .unwrap()
        .public_key();
    assert!(
        check_request(&policy, &prepared, &trust, other)
            .unwrap_err()
            .to_string()
            .contains("Fetch caller")
    );
    let (policy, prepared, caller) = fetch_request(Assurance::ProducerSigned, Retention::Ephemeral);
    trust.required_assurance = Assurance::ProducerSigned;
    check_request(&policy, &prepared, &trust, caller).unwrap();
    assert_eq!(prepared.assurance().unwrap(), Assurance::ProducerSigned);
    let (policy, retained, caller) = fetch_request(Assurance::ProducerSigned, Retention::Retain);
    assert!(
        check_request(&policy, &retained, &trust, caller)
            .unwrap_err()
            .to_string()
            .contains("ephemeral")
    );
}

fn payment_policy() -> hellas_rpc::protocol::work::JobPaymentPolicyV2 {
    hellas_rpc::protocol::work::JobPaymentPolicyV2 {
        fixed_price: 10,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
    }
}
