use super::*;
use crate::test_support::enrollment;
mod offer;
mod recovery;
use hellas_auth::{ProducerSigningKey, PublicKey};
use hellas_rpc::pb::execute::{OpenRequest, OpenResponse, open_response};
use hellas_rpc::{Assurance, ProviderEnrollmentBundle};
use hellas_wire::{MethodMarker, StreamTransport, WireStatus};

#[tokio::test]
async fn paid_image_burst_is_verified_and_delivered() {
    use crate::gateway_work::{GatewayEvent as _, Requester};
    use hellas_channel::test_support::channel as fixture;
    use hellas_gateway::{ComputeEvent, WorkEvent, WorkGatewayError};
    use hellas_rpc::protocol::invocation::{
        Artifact,
        compute::{OutputKind, RunMetadata},
        output::{self, InvocationOutput, Outcome},
    };
    let mut policy = fixture::work_policy();
    policy.limits.max_output_bytes = 4 << 20;
    let mut plan = fixture::plan();
    plan.outputs[0].kind = OutputKind::Buffer { max_bytes: 3 << 20 };
    let mut prepared = fixture::bundle(1);
    prepared.input.parameters = hellas_rpc::JsonBytes(plan.canonical_bytes().unwrap());
    prepared.request.input = prepared.input.content_id().unwrap();
    prepared.application_policy = hellas_rpc::JsonBytes(policy.canonical_bytes().unwrap());
    let key = fixture::provider_producer();
    let caller = PublicKey::Secp256k1(fixture::client().party_key().to_bytes());
    // A 512x512 RGB F32 image; 255 maximizes CBOR integer-array expansion.
    let expected = InvocationOutput {
        outcome: Outcome::Succeeded,
        artifacts: vec![Artifact::new(
            "answer",
            "catena.bytes.v1",
            vec![255; 512 * 512 * 3 * 4],
        )],
        metadata: hellas_rpc::JsonBytes(
            hellas_rpc::canonical_dag_cbor(&RunMetadata {
                steps: 0,
                stop: None,
            })
            .unwrap(),
        ),
    };
    let events = expected
        .sign(&prepared.request, &key, output::MAX_CHUNK_BYTES)
        .unwrap();
    let transcript = hellas_channel::model::work::encode_transcript(&events).unwrap();
    assert!(transcript.len() > hellas_channel::work_store::journal::MAX_RECORD_BYTES);
    let verified =
        verify_transcript(&prepared, &policy, &caller, &key.public_key(), &transcript).unwrap();
    assert_eq!(verified.output, expected);

    let limit = policy.admit(&prepared, &caller).unwrap().max_spool_bytes as usize;
    let oversized = vec![0; limit + 1];
    let error =
        verify_transcript(&prepared, &policy, &caller, &key.public_key(), &oversized).unwrap_err();
    assert!(error.to_string().contains("over the authorized limit"));
    assert!(
        verify_transcript(
            &prepared,
            &policy,
            &caller,
            &ProducerSigningKey::from_secret_bytes([3; 32])
                .unwrap()
                .public_key(),
            &transcript,
        )
        .is_err()
    );
    let accepted = hellas_rpc::provenance::ExecutionProvenance {
        commitment_id: [23; 32],
        provider: key.public_key(),
    };
    let (requester, mut response) = Requester::<ComputeEvent, WorkGatewayError>::new();
    // A retained result can arrive in one burst before the consumer polls.
    requester.accepted()(accepted.clone());
    let progress = requester.progress();
    for envelope in &events[..events.len() - 1] {
        progress(envelope.clone()).unwrap();
    }
    requester.emit(Ok(WorkEvent::Transcript(transcript.clone())));
    requester.emit(Ok(WorkEvent::Output(
        ComputeEvent::completed(&verified.output, &key.public_key()).unwrap(),
    )));
    drop(progress);
    drop(requester);
    assert!(
        matches!(response.next().await.unwrap().unwrap(), WorkEvent::Accepted(actual) if actual == accepted)
    );
    let mut pixels = Vec::new();
    for _ in &events[..events.len() - 1] {
        let WorkEvent::Output(ComputeEvent::Output(chunk)) =
            response.next().await.unwrap().unwrap()
        else {
            panic!("expected image prefix");
        };
        assert_eq!(chunk.name, "answer");
        assert_eq!(chunk.format, "catena.bytes.v1");
        assert_eq!(chunk.offset, pixels.len() as u64);
        pixels.extend_from_slice(chunk.bytes.as_bytes());
    }
    assert_eq!(pixels, expected.artifacts[0].bytes.as_bytes());
    assert!(
        matches!(response.next().await.unwrap().unwrap(), WorkEvent::Transcript(actual) if actual == transcript)
    );
    assert!(
        matches!(response.next().await.unwrap().unwrap(), WorkEvent::Output(ComputeEvent::Done { output: actual, provider }) if actual == expected && provider == key.public_key())
    );
    assert!(response.next().await.is_none());
}

#[test]
fn insufficient_quoted_collateral_is_rejected_before_a_bond_request_or_journal() {
    let (mut policy, _, _) = fetch_request(Assurance::ProducerSigned);
    policy.expected_payment_values =
        hellas_kernel::EdgeValues::new(1000, 0, hellas_kernel::Fees::ZERO);
    let fixture = crate::test_support::PaidFixture::new();
    let root = tempfile::tempdir().unwrap();
    let journal_root = root.path().join("journal");
    let mut config = fixture.config.clone();
    config.chain.network = policy.network;
    let args = PaidWorkOptions {
        config,
        journal_root: journal_root.clone(),
        provider: crate::test_support::address(SecretKey::generate().public()),
        provider_addrs: vec![],
        assurance: Assurance::ProducerSigned,
        apple_trust: None,
        expected_price: policy.payment_policy.fixed_price,
        acceptance_blocks: 300,
        terminal_blocks: 3000,
        payment_blocks: 600,
        timeout: Some(Duration::from_secs(30)),
    };
    assert!(matches!(
        super::offer::check_policy(&args, &policy, 51),
        Err(PaidClientError::WorkSetup(
            hellas_channel::model::setup::WorkSetupError::Undercollateralised {
                bond: 51,
                capacity: 949
            }
        ))
    ));
    assert!(!journal_root.exists());
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
    if M::Service::ALPN == hellas_rpc::services::work::Work::ALPN {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let Ok((mut send, mut recv)) = transport.connection().accept_bi().await else {
            return;
        };
        assert_eq!(recv.read_u8().await.unwrap(), 1);
        assert_eq!(recv.read(&mut [0]).await.unwrap(), None);
        send.write_all(&[1]).await.unwrap();
        send.shutdown().await.unwrap();
    }
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
    use hellas_channel::work::{DeliverError, WorkRefusal};
    use hellas_client::work::CollectResultError;

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

fn fetch_events(
    assurance: Assurance,
    retention: hellas_rpc::Retention,
) -> Vec<hellas_rpc::InputEventEnvelope> {
    hellas_rpc::fetch::build_input_events_with_retention(
        "openai",
        "responses",
        br#"{"input":"private request"}"#,
        test_responses_contract().manifest_id(),
        assurance,
        &ProducerSigningKey::from_secret_bytes([7; 32]).unwrap(),
        retention,
    )
    .unwrap()
}

fn fetch_request(assurance: Assurance) -> (ProviderChannelPolicy, PreparedInvocation, PublicKey) {
    use hellas_channel::model::work::PaidChannelPolicyV1;
    let invocation_policy = crate::test_support::work_policy();
    let prepared = hellas_rpc::protocol::invocation::fetch::prepare(
        &fetch_events(assurance, hellas_rpc::Retention::Ephemeral),
        &test_responses_contract(),
        ProducerSigningKey::from_secret_bytes([2; 32])
            .unwrap()
            .public_key(),
        invocation_policy.canonical_bytes().unwrap(),
        [1; 32],
    )
    .unwrap();
    let policy = ProviderChannelPolicy {
        payment_policy: payment_policy(),
        network: hellas_kernel::NetworkId::new("paid-client-test").unwrap(),
        policy_salt: [8; 32],
        channel_policy: PaidChannelPolicyV1 {
            compute_credit_limit: 40,
            delivery_credit_limit: 40,
        },
        invocation_policy,
        expected_payment_values: hellas_kernel::EdgeValues::new(
            1000,
            200,
            hellas_kernel::Fees::ZERO,
        ),
        min_omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
    };
    let caller = ProducerSigningKey::from_secret_bytes([7; 32])
        .unwrap()
        .public_key();
    (policy, prepared, caller)
}

#[test]
fn fetch_preflight_requires_matching_trust_caller_and_ephemeral_retention() {
    use hellas_rpc::Retention;
    let (policy, prepared, caller) = fetch_request(Assurance::AppleAppAttest);
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
            .contains("differs from its invocation")
    );
    let (policy, prepared, caller) = fetch_request(Assurance::ProducerSigned);
    trust.required_assurance = Assurance::ProducerSigned;
    check_request(&policy, &prepared, &trust, caller).unwrap();
    assert_eq!(prepared.request.assurance, Assurance::ProducerSigned);
    assert!(
        hellas_rpc::protocol::invocation::fetch::prepare(
            &fetch_events(Assurance::ProducerSigned, Retention::Retain),
            &test_responses_contract(),
            caller,
            policy.invocation_policy.canonical_bytes().unwrap(),
            [1; 32],
        )
        .unwrap_err()
        .to_string()
        .contains("ephemeral")
    );
}

fn payment_policy() -> hellas_channel::model::work::JobPaymentPolicyV2 {
    hellas_channel::model::work::JobPaymentPolicyV2 {
        fixed_price: 10,
        dispatch_margin_blocks: 4,
        delivery_margin_blocks: 2,
        oracle_grace_blocks: 6,
    }
}

use hellas_channel::test_support::test_responses_contract;

#[tokio::test]
async fn client_checks_live_owner_and_own_payout_before_countersigning() {
    use crate::test_support::{PaidFixture, signer};
    use hellas_auth::test_support::actors::{FRIEND, ROOT};
    use hellas_channel::model::bundle::WorkChannelSetupBundleV2;
    use hellas_channel::work_store::SetupScan;
    use hellas_kernel::{Auth, Key, Parties, PartyAuth, PartyKeys, Terms, Tx};

    let root = tempfile::tempdir().unwrap();
    let peer = SecretKey::from_bytes(&[71; 32]).public();
    let authority =
        crate::test_support::authority(&root.path().join("authority"), enrollment(peer).0).await;
    let fixture = PaidFixture::new();
    let client = signer(1);
    let provider = signer(2);
    for (name, owner, delegate, refusal) in [
        (
            "foreign-owner",
            FRIEND.principal(),
            Some(client.party_key()),
            Some("client coin owner"),
        ),
        (
            "provider-selected-lock",
            ROOT.principal(),
            None,
            Some("client payout delegation"),
        ),
        (
            "own-owner",
            ROOT.principal(),
            Some(client.party_key()),
            None,
        ),
    ] {
        let mut bond_terms = fixture.proposal.bond_terms().clone();
        bond_terms.parties = Parties::new(
            PartyKeys::sole(provider.party_key()),
            PartyKeys::new(
                Key::from_bytes(*owner.as_bytes()),
                client.party_key(),
                delegate,
            ),
        );
        let funding = fixture.proposal.bond_funding().clone();
        let hash = Tx::open_hash(
            fixture.config.chain.network,
            &funding,
            &Terms::work_stake_bond(bond_terms.clone()),
        );
        let proposal = WorkChannelSetupBundleV2::propose_bond(
            fixture.config.chain.network,
            funding.clone(),
            bond_terms,
            PartyAuth::owner(Auth::native(provider.sign(hash))),
        )
        .unwrap();
        let store = SetupStore::open(
            &root.path().join(name),
            fixture.config.chain.network,
            proposal.bond_edge(),
            Role::Client,
            &Secp256k1Verifier::new(),
        )
        .await
        .unwrap();
        let policy = fixture.policy.clone();
        let mut setup = SetupEndpoint::new(
            store,
            client.clone(),
            PaymentAdmission::Proposes(Box::new(policy.clone())),
        );
        setup.import(&proposal.encode()).await.unwrap();
        setup
            .arm_scan(SetupScan {
                height: 0,
                payload: [0; 32],
            })
            .await
            .unwrap();
        let terms = payment_terms(&fixture.config, &policy, &proposal, 601);
        let payment_funding = Funding::new(
            hellas_kernel::List::take(
                [hellas_kernel::CoinId::from_bytes([91; 32]); hellas_kernel::MAX_PARTY_INPUTS],
                1,
            ),
            hellas_kernel::List::empty(hellas_kernel::CoinId::from_bytes([0; 32])),
        );
        let result = propose_client_payment(
            &mut setup,
            authority.owner().await.unwrap(),
            &client,
            payment_funding,
            terms,
        )
        .await;
        if let Some(reason) = refusal {
            assert!(
                matches!(result, Err(PaidClientError::InputMismatch(actual)) if actual == reason)
            );
            assert_eq!(setup.state().revision(), Some(1));
            assert_eq!(setup.state().bundle().unwrap(), &proposal);
        } else {
            result.unwrap();
            assert_eq!(setup.state().revision(), Some(2));
        }
    }
}
