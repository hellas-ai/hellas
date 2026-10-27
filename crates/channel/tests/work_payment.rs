//! Paying for one checked job: the amount each endpoint derives for
//! itself, what is on the disk before either of them speaks, and what a
//! certificate the ledger cannot explain does.
//!
//! One call, over a real multiplexed transport, so the request is
//! framed, routed by method id, decoded and answered rather than handed
//! to a function. Every crash is a real one: the endpoints are dropped
//! and their stores reopened over their own files.
//!
//! What is not re-proved here. The transition rules themselves belong to
//! the journal and are pinned in `work_store_channel.rs` — that a
//! payment past its deadline is refused, that a paid job is not paid for
//! again after a restart. The record arithmetic belongs to
//! `paid_work_vectors.rs`. These tests are about the two endpoints and
//! the wire between them.

use hellas_work::test_support::transport::transport_pair;
use support::temp;

use hellas_auth::Digest;
use hellas_kernel::{
    Decode as _, EarnedCertificate, EdgeId, Encode as _, Secp256k1Signer, TermsHash,
};
use hellas_rpc::pb::work::{
    AdmitCertificateRequest, AdmitCertificateResponse, WorkPaid, WorkRefusalCode,
    admit_certificate_response::Outcome as AdmitOutcome,
};
use hellas_rpc::services::work::WorkClientImpl;
use hellas_work::model::work::{
    PaymentBindingV1, PrivateRecord as _, payment_binding_digest, signing_hash,
};
use hellas_work::test_support::channel::{
    CURSOR, PRICE, client, deadlines, payload_at, provider, store_at,
};
use hellas_work::work::{
    ClientEndpoint, PaymentError, ProviderEndpoint, RunError, WorkRefusal, WorkService,
    admit_payment,
};
use hellas_work::work_close::FinalizedWork;
use hellas_work::work_store::{JobPhase, JobState, Role};

mod support;

use hellas_work::test_support::channel::{accept, checked_job, ready, serve_work as serve, stop};

// ── Driving the call ──────────────────────────────────────────────────

/// One `AdmitCertificate` over a live transport: signed, journaled,
/// sent, and acknowledged.
async fn pay_over_wire(
    service: &WorkService,
    client: &mut ClientEndpoint,
    id: Digest,
) -> Result<u64, PaymentError> {
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let outcome = admit_payment(&WorkClientImpl::new(transport), client, id).await;
    stop(serving).await;
    outcome
}

/// The provider's answer to one payment, whatever it is.
async fn admit_response(
    service: &WorkService,
    request: AdmitCertificateRequest,
) -> AdmitCertificateResponse {
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let response = WorkClientImpl::new(transport)
        .admit_certificate(request)
        .await;
    stop(serving).await;
    match response {
        Ok(response) => response,
        Err(status) => panic!("the call completes: {status}"),
    }
}

fn refusal_of(response: &AdmitCertificateResponse) -> WorkRefusalCode {
    match &response.outcome {
        Some(AdmitOutcome::Refused(refused)) => match WorkRefusalCode::try_from(refused.code) {
            Ok(code) => code,
            Err(error) => panic!("the refusal code is one of the six: {error}"),
        },
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn signature_over(signer: &Secp256k1Signer, hash: hellas_kernel::PayloadHash) -> Vec<u8> {
    signer.sign(hash).as_bytes().to_vec()
}

fn certificate_bytes(certificate: &EarnedCertificate) -> Vec<u8> {
    let mut buf = vec![0_u8; certificate.encoded_size()];
    let written = certificate.write_to(&mut buf);
    buf.truncate(written);
    buf
}

// ── One job, paid for ─────────────────────────────────────────────────

/// One checked answer becomes one certificate, and both endpoints end
/// at the same number.
///
/// The record counts at the end are what say nothing was written twice:
/// the call was made a second time, and the journals a process that saw
/// none of it reopens are the same length as before.
#[tokio::test]
async fn one_certificate_pays_for_one_job() {
    let mut fixture = checked_job().await;
    let id = fixture.id;

    let credited = match pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(credited) => credited,
        Err(error) => panic!("the checked job is paid: {error}"),
    };
    assert_eq!(credited, PRICE);

    let state = fixture.client.state();
    assert!(state.jobs().next().is_none(), "the payment closes the job");
    assert_eq!(state.ledger().credited_cumulative(), PRICE);
    let Some(payment) = state.last_payment() else {
        panic!("the payment is retained for re-sending");
    };
    assert_eq!(payment.work_id, id);
    assert_eq!(payment.certificate.earned_cumulative(), PRICE);
    assert_eq!(
        payment.binding.work_id, id,
        "the binding names the job it paid for",
    );
    assert_eq!(
        payment.binding.certificate_digest,
        payment
            .certificate
            .digest(fixture.ready.channel().network()),
        "and the certificate it paid with",
    );

    {
        let state = fixture
            .service
            .with_state(|state| state.clone())
            .await
            .expect("the endpoint is reachable");
        assert!(state.jobs().next().is_none());
        assert_eq!(state.ledger().credited_cumulative(), PRICE);
        assert_eq!(state.max_executable_certificate(), PRICE);
        assert!(
            state.terminals().next().is_some(),
            "the admitted certificate is this channel's one terminal",
        );
    }

    // The acknowledgement lost to a crash: the same bytes again, and
    // the same answer.
    match pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(again) => assert_eq!(again, PRICE),
        Err(error) => panic!("a re-sent payment is acknowledged: {error}"),
    }

    // The retained payment answers for the job it paid for and no
    // other: a channel with a payment on its disk has not thereby paid
    // for everything.
    let elsewhere = fixture.client.pay(Digest::from_bytes([0xaa; 32])).await;
    assert!(
        matches!(elsewhere, Err(PaymentError::NoSuchJob)),
        "another job's payment is not this one's: {elsewhere:?}",
    );

    drop(fixture.client);
    drop(fixture.service);
    let client_store = store_at(
        fixture.client_root.path(),
        &fixture.ready,
        Role::Client,
        CURSOR,
    )
    .await;
    let provider_store = store_at(
        fixture.provider_root.path(),
        &fixture.ready,
        Role::Provider,
        CURSOR,
    )
    .await;
    // Retiring a job checkpoints its accounting and removes its payload frames.
    for (store, role) in [(&client_store, "client"), (&provider_store, "provider")] {
        assert_eq!(
            store.len(),
            0,
            "the {role} journal retired the paid job's records"
        );
        let state = store.state();
        assert!(state.jobs().next().is_none(), "the {role} job is closed");
        assert_eq!(state.ledger().credited_cumulative(), PRICE);
        assert_eq!(state.max_executable_certificate(), PRICE);
    }
    assert_eq!(
        client_store.state().last_payment().map(|p| p.work_id),
        Some(id)
    );
}

// ── What the provider will be paid ────────────────────────────────────

/// A provider credits the payment its own ledger arrives at, and no
/// other.
///
/// Each request below moves exactly one field of the honest payment and
/// is re-signed by the client, so what refuses it is the arithmetic and
/// not the signature — and the last two move no field and change only
/// the signer, so both signature rules are shown to be there too.
///
/// Nothing is banked on any of them. A certificate whose binding this
/// ledger cannot explain is not money that was earned and mis-labelled;
/// both halves of an honest payment come out of one derivation.
#[tokio::test]
async fn the_provider_prices_the_payment_itself() {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    let channel = fixture.ready.channel().clone();
    let honest = match fixture.client.pay(id).await {
        Ok(request) => request,
        Err(error) => panic!("the client signs its payment: {error}"),
    };
    let Ok(binding) = PaymentBindingV1::decode(&honest.binding) else {
        panic!("the client's own binding decodes");
    };
    let Ok(certificate) = EarnedCertificate::decode(&honest.certificate) else {
        panic!("the client's own certificate decodes");
    };
    let certificate = certificate.0;

    let elsewhere = Digest::from_bytes([0x5e; 32]);
    let bindings = [
        (
            "work_id",
            PaymentBindingV1 {
                work_id: elsewhere,
                ..binding
            },
        ),
        (
            "result_digest",
            PaymentBindingV1 {
                result_digest: elsewhere,
                ..binding
            },
        ),
        (
            "certificate_digest",
            PaymentBindingV1 {
                certificate_digest: hellas_kernel::PayloadHash::from_bytes([0x5e; 32]),
                ..binding
            },
        ),
    ];
    for (field, mutated) in bindings {
        assert_ne!(mutated, binding, "{field} is the one thing varied");
        let request = AdmitCertificateRequest {
            binding: mutated.encode(),
            binding_signature: signature_over(
                &client(),
                signing_hash(payment_binding_digest(&channel, &mutated)),
            ),
            ..honest.clone()
        };
        let response = admit_response(&fixture.service, request).await;
        assert_eq!(
            refusal_of(&response),
            WorkRefusalCode::Invalid,
            "a binding whose {field} this provider did not arrive at",
        );
        assert_nothing_credited(&fixture.service, field).await;
    }

    // The certificate's own three fields, each re-signed so the refusal
    // is the ledger's rather than a signature's.
    let other_edge = EdgeId::from_bytes([0x77; EdgeId::LENGTH]);
    let other_terms = TermsHash::from_bytes([0x88; 32]);
    let certificates = [
        (
            "earned_cumulative",
            EarnedCertificate::new(
                channel.payment_edge(),
                channel.payment_terms_hash(),
                PRICE + 1,
            ),
        ),
        (
            "payment_edge",
            EarnedCertificate::new(other_edge, channel.payment_terms_hash(), PRICE),
        ),
        (
            "payment_terms_hash",
            EarnedCertificate::new(channel.payment_edge(), other_terms, PRICE),
        ),
    ];
    for (field, mutated) in certificates {
        assert_ne!(mutated, certificate, "{field} is the one thing varied");
        // The binding is left alone, so the check in front of the
        // certificate passes and the certificate's own field is what
        // refuses each case.
        let request = AdmitCertificateRequest {
            certificate: certificate_bytes(&mutated),
            certificate_signature: signature_over(&client(), mutated.digest(channel.network())),
            ..honest.clone()
        };
        let response = admit_response(&fixture.service, request).await;
        assert_eq!(
            refusal_of(&response),
            WorkRefusalCode::Invalid,
            "a certificate whose {field} this provider did not arrive at",
        );
        assert_nothing_credited(&fixture.service, field).await;
    }

    // The honest bytes, signed by the wrong party — once for each
    // signature the record carries.
    for (slot, request) in [
        (
            "binding",
            AdmitCertificateRequest {
                binding_signature: signature_over(
                    &provider(),
                    signing_hash(payment_binding_digest(&channel, &binding)),
                ),
                ..honest.clone()
            },
        ),
        (
            "certificate",
            AdmitCertificateRequest {
                certificate_signature: signature_over(
                    &provider(),
                    certificate.digest(channel.network()),
                ),
                ..honest.clone()
            },
        ),
    ] {
        let response = admit_response(&fixture.service, request).await;
        assert_eq!(
            refusal_of(&response),
            WorkRefusalCode::Invalid,
            "a {slot} the client did not sign",
        );
        assert_nothing_credited(&fixture.service, slot).await;
    }

    // The control: the client's own bytes, credited.
    let response = admit_response(&fixture.service, honest).await;
    assert!(
        matches!(response.outcome, Some(AdmitOutcome::Paid(_))),
        "the client's own payment is credited: {response:?}",
    );
}

/// Asserts that a refused payment moved no money at all.
async fn assert_nothing_credited(service: &WorkService, what: &str) {
    let state = service
        .with_state(|state| state.clone())
        .await
        .expect("the endpoint is reachable");
    assert_eq!(
        state.ledger().credited_cumulative(),
        0,
        "{what} credits nothing",
    );
    assert_eq!(
        state.max_executable_certificate(),
        0,
        "{what} is not banked either",
    );
    assert_eq!(
        state.jobs().next().map(JobState::phase),
        Some(JobPhase::Delivered),
        "{what} leaves the job unpaid",
    );
}

/// An acknowledgement is only this payment's if it names this
/// payment's amount.
///
/// The number is the one thing varied: the same durable certificate,
/// and three answers about what it bought.
#[tokio::test]
async fn an_acknowledgement_must_name_the_amount_that_was_signed() {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    match pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(credited) => assert_eq!(credited, PRICE),
        Err(error) => panic!("the checked job is paid: {error}"),
    }

    for credited_cumulative in [PRICE - 1, PRICE, PRICE + 1] {
        let response = AdmitCertificateResponse {
            outcome: Some(AdmitOutcome::Paid(WorkPaid {
                credited_cumulative,
            })),
        };
        let read = fixture.client.acknowledged(id, &response);
        if credited_cumulative == PRICE {
            assert_eq!(read.ok(), Some(PRICE), "the amount that was signed");
            continue;
        }
        let Err(PaymentError::Acknowledged { signed, credited }) = read else {
            panic!("an acknowledgement of {credited_cumulative}: {read:?}");
        };
        assert_eq!(signed, PRICE);
        assert_eq!(credited, credited_cumulative);
    }
}

/// A job with no result yet has nothing to pay for: the client signs
/// nothing, and the provider credits nothing.
///
/// The control is `one_certificate_pays_for_one_job`: the same call, on
/// the same channel, once a result has been computed and delivered.
#[tokio::test]
async fn an_uncomputed_job_is_not_paid_for() {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let id = accept(&mut [&mut client_store, &mut provider_store]).await;
    let Ok(mut endpoint) = ClientEndpoint::new(ready.clone(), client_store, client()) else {
        panic!("the client endpoint binds");
    };
    let Ok(provider_endpoint) = ProviderEndpoint::new(ready.clone(), provider_store, provider())
    else {
        panic!("the provider endpoint binds");
    };
    let service = WorkService::new(provider_endpoint);

    let paid = endpoint.pay(id).await;
    let Err(PaymentError::NotPayable { phase }) = paid else {
        panic!("an accepted job with no result: {paid:?}");
    };
    assert_eq!(phase, JobPhase::Accepted);
    assert!(
        endpoint.state().last_payment().is_none(),
        "and nothing was signed",
    );

    // And a well-formed, correctly signed payment for that same job is
    // refused by the provider, whose journal has no result to price
    // either.
    let channel = ready.channel();
    let certificate =
        EarnedCertificate::new(channel.payment_edge(), channel.payment_terms_hash(), PRICE);
    let binding = PaymentBindingV1 {
        work_id: id,
        result_digest: Digest::from_bytes([0x22; 32]),
        certificate_digest: certificate.digest(channel.network()),
    };
    let response = admit_response(
        &service,
        AdmitCertificateRequest {
            route: Some(hellas_rpc::pb::work::WorkRoute::payment(channel.id())),
            certificate: certificate_bytes(&certificate),
            binding: binding.encode(),
            binding_signature: signature_over(
                &client(),
                signing_hash(payment_binding_digest(channel, &binding)),
            ),
            certificate_signature: signature_over(&client(), certificate.digest(channel.network())),
        },
    )
    .await;
    assert_eq!(refusal_of(&response), WorkRefusalCode::Declined);
    let state = service
        .with_state(|state| state.clone())
        .await
        .expect("the endpoint is reachable");
    assert_eq!(state.ledger().credited_cumulative(), 0);
    assert_eq!(state.max_executable_certificate(), 0);
    assert_eq!(
        state.jobs().next().map(JobState::phase),
        Some(JobPhase::Accepted),
        "and nothing moved",
    );
}

/// A payment is exactly the bytes the service defines, and no other
/// spelling of them.
///
/// Each request below is the honest one with one field mis-encoded, and
/// none of the three reaches a rule about money: nothing is credited,
/// and nothing is banked either.
#[tokio::test]
async fn a_payment_is_exactly_the_bytes_the_service_defines() {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    let honest = match fixture.client.pay(id).await {
        Ok(request) => request,
        Err(error) => panic!("the client signs its payment: {error}"),
    };

    let mut trailing = honest.certificate.clone();
    trailing.push(0);
    let mut truncated = honest.binding.clone();
    truncated.pop();
    let mut short = honest.binding_signature.clone();
    short.pop();
    let mutations = [
        (
            "a trailing byte on the certificate",
            AdmitCertificateRequest {
                certificate: trailing,
                ..honest.clone()
            },
        ),
        (
            "a truncated binding",
            AdmitCertificateRequest {
                binding: truncated,
                ..honest.clone()
            },
        ),
        (
            "a 63-byte binding signature",
            AdmitCertificateRequest {
                binding_signature: short,
                ..honest.clone()
            },
        ),
    ];
    for (what, request) in mutations {
        let response = admit_response(&fixture.service, request).await;
        assert_eq!(refusal_of(&response), WorkRefusalCode::Invalid, "{what}");
        assert_nothing_credited(&fixture.service, what).await;
    }

    // The control: the same request, whole.
    let response = admit_response(&fixture.service, honest).await;
    assert!(
        matches!(response.outcome, Some(AdmitOutcome::Paid(_))),
        "the whole request is paid: {response:?}",
    );
}

// ── Payment against default ───────────────────────────────────────────

/// A defaulted job and a paid job are the same job, and exactly one of
/// the two terminals is written.
///
/// Both orders, over the one file that decides them. Expiring first: the
/// provider's watcher reaches finalized blocks past the height this
/// client signed to pay by, and the job rests at a permanent expired
/// terminal — the provider bears whatever it spent, there being no
/// client charge to move. A payment then is refused *and not banked*,
/// because the one job is already over. Paying first: the payment rests
/// the job at a certified terminal, and there is nothing left to expire.
#[tokio::test]
async fn a_defaulted_job_is_not_paid_for_as_well() {
    let mut fixture = checked_job().await;
    let id = fixture.id;
    {
        let provider = &fixture.service;
        // The default is the watcher's, reached the only way it can
        // be: finalized blocks past the height this client signed to
        // pay by. No local call can ask for it.
        let Ok(mut driver) = provider.drive() else {
            panic!("this channel's cursor driver is free");
        };
        let mut next = provider
            .with_state(|state| state.cursor().0)
            .await
            .expect("the endpoint is reachable")
            .saturating_add(1);
        while next <= deadlines().payment + 1 {
            if let Err(error) = driver
                .observe_finalized(&FinalizedWork {
                    height: next,
                    parent: payload_at(next.saturating_sub(1)),
                    payload: payload_at(next),
                    txs: Vec::new(),
                })
                .await
            {
                panic!("the fixture block applies: {error}");
            }
            next += 1;
        }
        drop(driver);
        let (open_job, expired) = provider
            .with_state(|state| {
                (
                    state.jobs().next().is_some(),
                    matches!(
                        state.terminals().next().map(|t| &t.outcome),
                        Some(hellas_work::work_store::TerminalOutcome::Expired { .. })
                    ),
                )
            })
            .await
            .expect("the endpoint is reachable");
        assert!(!open_job, "the expired job is closed");
        assert!(expired, "and rests at an expired terminal");
    }

    let paid = pay_over_wire(&fixture.service, &mut fixture.client, id).await;
    let Err(PaymentError::Refused { refusal, .. }) = paid else {
        panic!("a defaulted job takes no payment: {paid:?}");
    };
    assert_eq!(refusal, WorkRefusal::Conflict);
    {
        let state = fixture
            .service
            .with_state(|state| state.clone())
            .await
            .expect("the endpoint is reachable");
        assert_eq!(state.ledger().credited_cumulative(), 0);
        assert_eq!(
            state.max_executable_certificate(),
            0,
            "a job already expired is not banked as well",
        );
    }
    assert_eq!(
        fixture.client.state().ledger().credited_cumulative(),
        PRICE,
        "the client holds a payment no provider will take",
    );

    // The other order.
    let mut fixture = checked_job().await;
    let id = fixture.id;
    match pay_over_wire(&fixture.service, &mut fixture.client, id).await {
        Ok(credited) => assert_eq!(credited, PRICE),
        Err(error) => panic!("the checked job is paid: {error}"),
    }
    let provider = &fixture.service;
    let ended = provider.end_run(id).await;
    assert!(
        matches!(ended, Err(RunError::NoSuchJob)),
        "a paid job is closed: {ended:?}",
    );
    assert_eq!(
        provider
            .with_state(|state| state.ledger().credited_cumulative())
            .await
            .expect("the endpoint is reachable"),
        PRICE,
    );
}

#[tokio::test]
async fn stale_observation_blocks_new_money_but_preserves_retransmission() {
    use hellas_work::work::{ClientChannel as _, ClientService, EndpointError};
    let fixture = checked_job().await;
    let mut client = ClientService::new(fixture.client);
    let id = fixture.id;
    assert!(matches!(
        client.client().await.unwrap().pay(id).await,
        Err(PaymentError::Endpoint(EndpointError::ObservationStale))
    ));
    assert_eq!(
        client
            .with_state(|state| state.ledger().credited_cumulative())
            .await
            .unwrap(),
        0
    );
    client
        .observer()
        .observe_ready(
            fixture.ready.clone(),
            hellas_work::work::ObservationTime::now(),
            std::time::Duration::from_secs(30),
        )
        .await
        .unwrap();
    let request = client.client().await.unwrap().pay(id).await.unwrap();
    client.observer().suspend().await.unwrap();
    assert_eq!(
        client.client().await.unwrap().pay(id).await.unwrap(),
        request
    );

    fixture.service.require_observer().await.unwrap();
    let refused = admit_response(&fixture.service, request.clone()).await;
    assert_eq!(refusal_of(&refused), WorkRefusalCode::NotReady);
    assert_nothing_credited(&fixture.service, "observer has not initialized").await;
    fixture
        .service
        .observe_ready(
            fixture.ready,
            hellas_work::work::ObservationTime::now(),
            std::time::Duration::from_secs(30),
        )
        .await
        .unwrap();
    let accepted = admit_response(&fixture.service, request.clone()).await;
    assert!(matches!(accepted.outcome, Some(AdmitOutcome::Paid(_))));
    fixture.service.suspend().await.unwrap();
    assert_eq!(admit_response(&fixture.service, request).await, accepted);
    assert_eq!(
        fixture
            .service
            .with_state(|state| state.ledger().credited_cumulative())
            .await
            .unwrap(),
        PRICE
    );
}

#[tokio::test]
async fn client_close_recovery_does_not_require_new_work_readiness() {
    let mut fixture = checked_job().await;
    fixture.client.pay(fixture.id).await.unwrap();
    let start = fixture.client.prepare_close().await.unwrap();
    drop(fixture.client);
    let recovered_store = store_at(
        fixture.client_root.path(),
        &fixture.ready,
        Role::Client,
        CURSOR,
    )
    .await;
    let mut recovered = ClientEndpoint::recover(recovered_store, client()).unwrap();
    assert!(recovered.state().is_closing());
    assert_eq!(recovered.prepare_close().await.unwrap(), start);
    assert_eq!(recovered.state().max_executable_certificate(), PRICE);
}

#[tokio::test]
async fn observed_close_and_payment_have_one_journal_order() {
    use hellas_work::work::{ClientChannel as _, ClientService, ObservationTime};
    use hellas_work::work_close::close_start;
    for payment_first in [false, true] {
        let fixture = checked_job().await;
        let mut client = ClientService::new(fixture.client);
        let observer = client.observer();
        observer
            .observe_ready(
                fixture.ready.clone(),
                ObservationTime::now(),
                std::time::Duration::from_secs(30),
            )
            .await
            .unwrap();
        let start = close_start(
            fixture.ready.channel(),
            hellas_kernel::Party::Maker,
            CURSOR,
            None,
            &self::client(),
        )
        .unwrap();
        let block = FinalizedWork {
            height: CURSOR + 1,
            parent: payload_at(CURSOR),
            payload: payload_at(CURSOR + 1),
            txs: vec![hellas_kernel::Tx::move_action(
                hellas_kernel::Move::StartPaymentClose(start),
            )],
        };
        if payment_first {
            let request = client
                .client()
                .await
                .unwrap()
                .pay(fixture.id)
                .await
                .unwrap();
            let credited = admit_response(&fixture.service, request).await;
            assert!(matches!(credited.outcome, Some(AdmitOutcome::Paid(_))));
        }
        observer
            .drive()
            .unwrap()
            .observe_finalized(&block)
            .await
            .unwrap();
        fixture
            .service
            .drive()
            .unwrap()
            .observe_finalized(&block)
            .await
            .unwrap();
        assert!(
            observer
                .with_state(|state| state.is_closing())
                .await
                .unwrap()
        );
        let retried = client.client().await.unwrap().pay(fixture.id).await;
        if payment_first {
            // Retrying the durable certificate is allowed after close observation.
            let response = admit_response(&fixture.service, retried.unwrap()).await;
            assert!(matches!(response.outcome, Some(AdmitOutcome::Paid(_))));
        } else {
            assert!(matches!(retried, Err(PaymentError::NoSuchJob)));
        }
        let expected = if payment_first { PRICE } else { 0 };
        assert_eq!(
            client
                .with_state(|state| state.max_executable_certificate())
                .await
                .unwrap(),
            expected
        );
        assert_eq!(
            fixture
                .service
                .with_state(|state| state.max_executable_certificate())
                .await
                .unwrap(),
            expected
        );
    }
}
