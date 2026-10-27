use super::*;

#[tokio::test]
async fn signed_model_and_settings_limits_reject_before_client_signing_and_provider_reservation() {
    use crate::model::fetch::PreparedPaidFetchInputV1;
    use crate::model::grant::resource::TemplateError;
    use hellas_work::work_store::grant::{GrantChannelState, GrantClientStore};
    let directory = tempfile::tempdir().unwrap();
    let (mut store, application) = setup(&directory.path().join("provider")).await;
    let now = UnixMillis(1000);
    let offer = standing(&mut store).await.offer;
    let (template, _, valid_input) = proposal(&store, 1);
    let original = store.state().clone();
    let mut client = GrantClientStore::open(
        &directory.path().join("client"),
        network(),
        crate::test_support::software_enrollment(2, [2; 32]),
        GrantChannelState {
            id: template.channel_id,
            grant: template.grant_id,
            generation: 0,
            client: crate::test_support::channel_client(principal(1).0),
        },
        now,
    )
    .await
    .unwrap();
    for revision in [Revision(0), Revision(2)] {
        let mut wrong_price = template;
        wrong_price.pricing_revision = revision;
        assert_err!(
            client
                .propose(&offer, wrong_price, &valid_input, &principal(1).1, now)
                .await,
            NodeStoreError::Grant(GrantError::OutOfScope)
        );
        assert_eq!(client.next_nonce().unwrap(), 1);
        assert!(client.book().pending_proposal().is_none());
        let signature = principal(1)
            .1
            .sign_digest(grant_work_id(network(), &wrong_price))
            .unwrap();
        assert_err!(accept(
                &mut store,
                &application,
                (wrong_price, signature, &valid_input),
                now.0
            )
            .await, NodeStoreError::Grant(error) if error == if revision.0 == 0 { GrantError::Malformed } else { GrantError::OutOfScope });
        assert_eq!(store.state(), &original);
    }
    for (body, expected) in [
        (br#"{"model":"other","input":"private","max_output_tokens":8}"#.as_slice(), TemplateError::Model),
        (br#"{"model":"fixture","input":"private"}"#, TemplateError::GenerationCap),
        (br#"{"model":"fixture","input":"private","max_output_tokens":9}"#, TemplateError::GenerationCap),
        (br#"{"model":"fixture","input":"private","max_output_tokens":8,"temperature":0.5}"#, TemplateError::Settings),
        (br#"{"model":"fixture","input":"private","max_output_tokens":8,"reasoning":{"effort":"high"}}"#, TemplateError::Settings),
        (br#"{"model":"fixture","model":"other","input":"private","max_output_tokens":8}"#, TemplateError::Malformed),
    ] {
        let events = hellas_rpc::fetch::build_input_events_with_retention(
            "openai", "responses", body, test_responses_contract().manifest_id(),
            Assurance::ProducerSigned, &principal(1).1, Retention::Ephemeral,
        ).unwrap();
        let input: PreparedWorkInput = PreparedPaidFetchInputV1::new(
            &events, &test_responses_contract(),
        ).unwrap().into();
        let mut a = template;
        a.input_content = hellas_rpc::ContentRef::for_bytes(&input.encode().unwrap());
        a.prepared_input_digest = input.bound_digest(network(), a.channel_id.0).unwrap();
        a.request_commitment = RequestCommitment::from_digest(input.input_commitment().unwrap().digest());
        assert_err!(client.propose(&offer, a, &input, &principal(1).1, now).await, NodeStoreError::Resource(error) if error == expected);
        assert_eq!(client.next_nonce().unwrap(), 1);
        assert!(client.book().pending_proposal().is_none());
        let signature = principal(1).1.sign_digest(grant_work_id(network(), &a)).unwrap();
        let error = accept(&mut store, &application, (a, signature, &input), now.0).await.unwrap_err();
        assert!(matches!(error, NodeStoreError::Resource(actual) if actual == expected));
        assert_eq!(store.state(), &original);
    }
    let signature = client
        .propose(&offer, template, &valid_input, &principal(1).1, now)
        .await
        .unwrap();
    accept(
        &mut store,
        &application,
        (template, signature, &valid_input),
        now.0,
    )
    .await
    .unwrap();
    assert_eq!(
        store
            .state()
            .ledger()
            .reserved(BudgetNode::Machine, Meter::Requests),
        1
    );

    let mut changed = policy();
    changed.revision.0 += 1;
    changed.responses.as_mut().unwrap().max_output_tokens = 4;
    store
        .configure_resource(changed.clone(), now)
        .await
        .unwrap();
    let mut grant = store.state().grant(template.grant_id).unwrap().clone();
    grant.revision.0 += 1;
    grant.policies = vec![changed.clone()];
    store.define(grant, now).await.unwrap();
    assert_eq!(
        store
            .state()
            .ledger()
            .reserved(BudgetNode::Machine, Meter::Requests),
        0
    );
    assert_eq!(store.state().policy_for(&template).unwrap(), &policy());
    store.rotate().await.unwrap();
    drop(store);
    let store = NodeStore::open(
        &directory.path().join("provider"),
        network(),
        Some(crate::test_support::software_enrollment(2, [2; 32])),
        now,
    )
    .await
    .unwrap();
    assert_eq!(store.state().resource(changed.resource), Some(&changed));
    assert_eq!(store.state().policy_for(&template).unwrap(), &policy());
    let checkpoint = serde_json::to_value(store.state().snapshot().unwrap()).unwrap();
    for copy in PolicyCopy::ALL {
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!({"model":"fixture","max_output_tokens":0}),
        ] {
            let mut corrupt = checkpoint.clone();
            let policy = copy.get_mut(&mut corrupt);
            policy["responses"] = invalid;
            assert_err!(
                super::super::State::restore(serde_json::from_value(corrupt).unwrap()),
                NodeStoreError::Grant(GrantError::Malformed)
            );
        }
    }
}

#[test]
fn response_limits_are_mandatory_and_only_apply_to_their_sealed_schema() {
    let original = policy();
    assert_eq!(original.validate(), Ok(()));
    let mut missing = original.clone();
    missing.responses = None;
    assert_eq!(missing.validate(), Err(GrantError::Malformed));
    let mut wrong_schema = original.clone();
    if let WorkPolicy::Fetch { policy, .. } = &mut wrong_schema.work {
        policy.allowed_environment = test_items_contract().manifest_id();
    }
    assert_eq!(wrong_schema.validate(), Err(GrantError::Malformed));
    let mut zero = original.clone();
    zero.responses.as_mut().unwrap().max_output_tokens = 0;
    assert_eq!(zero.validate(), Err(GrantError::Malformed));
    let mut changed = original.clone();
    changed.responses.as_mut().unwrap().model = "other-model".into();
    assert_eq!(changed.work, original.work);
    assert_ne!(changed, original);
}

#[tokio::test]
async fn identical_interpreters_keep_separate_accounts_and_exact_signed_resource_selection() {
    let directory = tempfile::tempdir().unwrap();
    let (mut store, secret) = setup_with_credential(directory.path()).await;
    let now = UnixMillis(1000);
    let first = policy();
    let mut second = first.clone();
    second.resource = ResourceId(Digest::hash(b"second resource"));
    second.account = ResourceId(Digest::hash(b"second account"));
    second.name = "second".into();
    let pool = PoolId([2; 16]);
    let mut budgets = common_node::budgets(pool, principal(1).0, vec![], 2);
    budgets[0].node = BudgetNode::Account(second.account);
    budgets[1].parent = budgets[0].node;
    for budget in budgets {
        store.configure_budget(budget, now).await.unwrap();
    }
    store.configure_resource(second.clone(), now).await.unwrap();
    assert_eq!(first.work, second.work);
    let mut grant = definition(GrantId([2; 16]), principal(1).0);
    grant.policies = vec![second.clone()];
    let before = store.state().clone();
    assert_err!(
        store.define(grant.clone(), now).await,
        NodeStoreError::Grant(GrantError::OutOfScope)
    );
    assert_eq!(store.state(), &before);
    grant.budget = BudgetNode::Subject {
        pool,
        subject: principal(1).0,
    };
    store.define(grant, now).await.unwrap();
    let [one, two] = super::budgets::applications(&mut store, &secret).await;
    let (a, signature, input) = proposal(&store, 1);
    let mut wrong = a;
    wrong.resource_id = second.resource;
    assert_ne!(
        grant_work_id(network(), &a),
        grant_work_id(network(), &wrong)
    );
    for (signature, expected) in [
        (signature, GrantError::Signature),
        (
            principal(1)
                .1
                .sign_digest(grant_work_id(network(), &wrong))
                .unwrap(),
            GrantError::OutOfScope,
        ),
    ] {
        assert_err!(accept(&mut store, &one, (wrong, signature, &input), now.0)
                .await, NodeStoreError::Grant(error) if error == expected);
        assert_eq!(store.state().ledger().active_count(BudgetNode::Machine), 0);
    }
    for (caller, id) in [(&one, GrantId([1; 16])), (&two, GrantId([2; 16]))] {
        let (a, signature, input) = proposal_for(&store, id, 1, principal(1).1);
        accept(&mut store, caller, (a, signature, &input), now.0)
            .await
            .unwrap();
    }
    for resource in [&first, &second] {
        assert_eq!(
            store
                .state()
                .ledger()
                .reserved(BudgetNode::Account(resource.account), Meter::Requests),
            1
        );
    }
    assert_eq!(
        store
            .state()
            .ledger()
            .reserved(BudgetNode::Machine, Meter::Requests),
        2
    );
    store.rotate().await.unwrap();
    drop(store);
    let store = NodeStore::open(
        directory.path(),
        network(),
        Some(crate::test_support::software_enrollment(2, [2; 32])),
        now,
    )
    .await
    .unwrap();
    assert_eq!(store.state().resource(first.resource), Some(&first));
    assert_eq!(store.state().resource(second.resource), Some(&second));
    for resource in [&first, &second] {
        assert_eq!(
            store
                .state()
                .ledger()
                .reserved(BudgetNode::Account(resource.account), Meter::Requests),
            0
        );
    }
}

#[tokio::test]
async fn same_work_policy_uses_the_selected_resources_https_bounds() {
    use crate::model::grant::resource::*;
    let directory = tempfile::tempdir().unwrap();
    let (mut store, application) = setup(directory.path()).await;
    let now = UnixMillis(1000);
    let mut large = policy();
    large.revision.0 += 1;
    if let WorkPolicy::Fetch {
        policy, contract, ..
    } = &mut large.work
    {
        *contract = hellas_rpc::FetchContract::http().unwrap();
        policy.allowed_environment = contract.manifest_id();
    }
    large.responses = None;
    large.https = Some(chat_resource("https://glm.test", 8));
    let mut small = large.clone();
    small.resource = ResourceId(Digest::hash(b"smaller output"));
    small.name = "small".into();
    small.revision = Revision(1);
    small.https.as_mut().unwrap().max_output_tokens = 4;
    for resource in [&large, &small] {
        store
            .configure_resource(resource.clone(), now)
            .await
            .unwrap();
    }
    let mut grant = store.state().grant(GrantId([1; 16])).unwrap().clone();
    grant.revision.0 += 1;
    grant.policies = vec![large.clone(), small.clone()];
    store.define(grant, now).await.unwrap();
    let (a, signature, input) = proposal(&store, 1);
    let mut changed = a;
    changed.resource_id = small.resource;
    changed.resource_revision = small.revision;
    let changed_signature = principal(1)
        .1
        .sign_digest(grant_work_id(network(), &changed))
        .unwrap();
    assert_eq!(store.state().policy_for(&changed).unwrap(), &small);
    assert_err!(
        accept(
            &mut store,
            &application,
            (changed, changed_signature, &input),
            now.0
        )
        .await,
        NodeStoreError::Resource(TemplateError::GenerationCap)
    );
    assert_eq!(store.state().ledger().active_count(BudgetNode::Machine), 0);
    accept(&mut store, &application, (a, signature, &input), now.0)
        .await
        .unwrap();
}

async fn rename_resource(node: &mut TestNode) -> GrantPolicy {
    let mut changed = node
        .store
        .state()
        .resource(policy().resource)
        .unwrap()
        .clone();
    changed.revision.0 += 1;
    changed.name = "renamed".into();
    node.store
        .configure_resource(changed.clone(), node.clock.now())
        .await
        .unwrap();
    changed
}

#[tokio::test]
async fn resource_revision_releases_queued_work() {
    use crate::test_support::{actors::FRIEND, ids};
    let directory = tempfile::tempdir().unwrap();
    let mut node = work_node(directory.path()).build().await;
    let queued = node.proposal(FRIEND, ids::ALLOWANCE, 1);
    node.accept(FRIEND, ids::FRIEND_GRANT, &queued)
        .await
        .unwrap();

    rename_resource(&mut node).await;

    assert_eq!(
        node.store
            .state()
            .ledger()
            .active_count(BudgetNode::Machine),
        0
    );
    assert_eq!(
        node.store
            .state()
            .channel(queued.authorization.channel_id)
            .unwrap()
            .job_book()
            .terminal_by_id(queued.work())
            .unwrap()
            .outcome
            .outcome,
        GrantOutcome::Released
    );
    let before = node.snapshot();
    assert_err!(
        node.dispatch(FRIEND, ids::FRIEND_GRANT, &queued).await,
        NodeStoreError::Grant(GrantError::OutOfScope)
    );
    assert_eq!(node.snapshot(), before);
    let stale = node.proposal(FRIEND, ids::ALLOWANCE, 2);
    assert_err!(
        node.accept(FRIEND, ids::FRIEND_GRANT, &stale).await,
        NodeStoreError::Grant(GrantError::OutOfScope)
    );
    assert_eq!(node.snapshot(), before);
}

#[tokio::test]
async fn a_resource_revision_cannot_be_reused() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = work_node(directory.path()).build().await;
    let changed = rename_resource(&mut node).await;
    let expected = changed.revision;
    let before = node.snapshot();
    assert_err!(node.store.configure_resource(changed, node.clock.now()).await,
        NodeStoreError::Grant(GrantError::Revision(actual)) if actual == expected);
    assert_eq!(node.snapshot(), before);
}

#[tokio::test]
async fn a_resource_cannot_move_to_another_account() {
    let directory = tempfile::tempdir().unwrap();
    let mut node = work_node(directory.path()).build().await;
    let mut moved = policy();
    moved.revision.0 += 1;
    moved.account = ResourceId(Digest::hash(b"unrelated account"));
    let before = node.snapshot();
    assert_err!(
        node.store.configure_resource(moved, node.clock.now()).await,
        NodeStoreError::Grant(GrantError::OutOfScope)
    );
    assert_eq!(node.snapshot(), before);
}

#[tokio::test]
async fn checkpoints_bind_every_policy_copy_to_its_account() {
    use crate::test_support::{actors::FRIEND, ids};
    let directory = tempfile::tempdir().unwrap();
    let mut node = work_node(directory.path()).build().await;
    let request = node.proposal(FRIEND, ids::ALLOWANCE, 1);
    node.accept(FRIEND, ids::FRIEND_GRANT, &request)
        .await
        .unwrap();
    node.dispatch(FRIEND, ids::FRIEND_GRANT, &request)
        .await
        .unwrap();
    let changed = rename_resource(&mut node).await;
    let mut terms = node.store.state().grant(ids::ALLOWANCE).unwrap().clone();
    terms.revision.0 += 1;
    terms.policies = vec![changed];
    node.store.define(terms, node.clock.now()).await.unwrap();
    node.finish(&request, Usage::Observed(Charge([1, 0, 2, 0, 0])))
        .await;
    let checkpoint = serde_json::to_value(node.store.state().snapshot().unwrap()).unwrap();
    for copy in PolicyCopy::ALL {
        let mut corrupt = checkpoint.clone();
        let policy = copy.get_mut(&mut corrupt);
        policy["account"] =
            serde_json::to_value(ResourceId(Digest::hash(b"wrong account"))).unwrap();
        let result = super::super::State::restore(serde_json::from_value(corrupt).unwrap());
        match copy {
            PolicyCopy::History => {
                assert_err!(result, NodeStoreError::Grant(GrantError::OutOfScope))
            }
            PolicyCopy::Catalogue | PolicyCopy::Current => {
                assert_err!(result, NodeStoreError::Malformed)
            }
        }
    }
}

use hellas_work::test_support::test_responses_contract;

#[cfg(test)]
fn test_items_contract() -> hellas_rpc::FetchContract {
    hellas_rpc::FetchContract::new(
        "codex-responses-0.0.1",
        hellas_rpc::FetchSchema::ResponsesItemsV1,
        "codex-responses-driver-0.0.1",
        hellas_rpc::FetchEgress::FixedHttps(
            "https://chatgpt.com/backend-api/codex/responses".into(),
        ),
    )
    .unwrap()
}
