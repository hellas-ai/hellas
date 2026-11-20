use super::*;
use hellas_auth::authority::*;
use hellas_authority::authenticator::Authenticator as _;
use hellas_authority::model::grant::budget::BudgetNode;
use hellas_authority::test_support::{compute::Compute, credentials, ids};
use hellas_channel::test_support::actors::{FRIEND, PROVIDER, ROOT};
use hellas_store::content::{LocalStore, MemoryStore, Reservations, Scope};

#[tokio::test]
async fn a_home_contact_receives_access_and_executes_a_compute_job() {
    let directory = tempfile::tempdir().unwrap();
    let location = StoreLocation::for_test(directory.path());
    let chain = hellas_chain::genesis::ChainProfile::known(hellas_chain::genesis::Chain::Devnet);
    let home = Home::open(&location, &chain).unwrap();
    let principal = home.principal().unwrap();
    let holder = NodeKey::from_public_key(home.producer().public_key()).unwrap();
    let assertion = home
        .owner()
        .unwrap()
        .assert(ContactCard::digest(principal, "embedder"))
        .await
        .unwrap();
    let contact = crate::contact::Contact {
        card: ContactCard::new(principal, "embedder".into(), assertion).unwrap(),
        holder,
    };
    let contact = crate::contact::Contact::decode(&contact.encode().unwrap()).unwrap();
    let mut allowance = Compute.allowance(ids::ALLOWANCE, FRIEND);
    if let BudgetNode::Subject { subject, .. } = &mut allowance.definition.budget {
        *subject = contact.card.principal();
    }
    let host = crate::test_support::Host::builder()
        .with_allowance(allowance)
        .build()
        .await;
    let remote = host.remote().await;
    let node = host.world.service.node();
    let admin = host.world.administrator(ROOT).await;
    let authorization = GrantId([210; 16]);
    let scope = GrantSpec {
        authority: admin.authority(),
        subject: contact.card.principal(),
        permissions: [Permission {
            operation: OperationId::new(hellas_authority::grant_service::WORK_EXECUTE).unwrap(),
            resource: hellas_authority::grant_service::allowance_resource(
                admin.authority(),
                host.allowance.id,
            ),
        }]
        .into(),
        not_before: host.world.clock.now(),
        expires: UnixMillis(u64::MAX),
        delegation_depth: 0,
        issuance: None,
    };
    let [] = credentials::issue(
        credentials::Issuer::Node(&node),
        &admin,
        ids::ROOT_GRANT,
        Some(authorization),
        scope.clone(),
    )
    .await;
    let (_, credential) = credentials::issue_one(
        &node,
        &admin,
        ids::ROOT_GRANT,
        scope,
        CredentialHolder::Node(contact.holder),
    )
    .await
    .unwrap();
    let offer = hellas_authority::model::grant::records::SignedOffer::sign(
        host.options(remote.addresses()).target.offer().clone(),
        &PROVIDER.node_key(),
    )
    .unwrap();
    let file = directory.path().join("shared.access");
    crate::access_bundle::AccessBundle {
        offers: vec![offer],
        authority: admin.authority(),
        authorization,
        subject: principal,
        holder,
        credential,
        expires: UnixMillis(u64::MAX),
        label: None,
    }
    .save(&file)
    .unwrap();
    let target = home
        .target(TargetSpec::Access {
            file,
            provider: None,
            trust: None,
            resource: None,
            assurance: Assurance::ProducerSigned,
        })
        .await
        .unwrap();
    let environment = hellas_channel::test_support::channel::environment();
    let content = LocalStore::Memory(MemoryStore::new(Reservations::ram(
        hellas_channel::content::DEFAULT_MAX_STAGING_BYTES,
    )));
    hellas_channel::content::upload_object(&content, &environment.canonical_bytes().unwrap())
        .await
        .unwrap();
    let job = Job::from_input(
        0,
        crate::job::JobInput::Compute {
            evaluator: hellas_channel::test_support::channel::evaluator(),
            environment,
            plan: hellas_channel::test_support::channel::plan(),
            inputs: vec![],
            content: (content, Scope::Owner).into(),
        },
    )
    .unwrap();
    let run = || {
        target.executor(&job, None).unwrap().run(
            &job,
            home.producer(),
            None,
            crate::execution::stop_on(std::future::pending()),
            Default::default(),
            Box::new(|_| Ok(())),
        )
    };
    let first = run().await.unwrap();
    assert_eq!(first.output.artifacts[0].bytes.as_bytes(), &[0]);
    let replay = run().await.unwrap();
    assert_eq!(first.transcript, replay.transcript);
    assert_eq!(
        host.backend.calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    home.close().await;
    remote.shutdown().await;
    host.world.service.shutdown().await.unwrap();
    host.content.close().await;
    let reopened = Home::open(&location, &chain).unwrap();
    assert_eq!(reopened.principal().unwrap(), principal);
    assert_eq!(
        reopened.producer().public_key(),
        home.producer().public_key()
    );
    assert_eq!(reopened.client_root(), home.client_root());
    reopened.close().await;
}
