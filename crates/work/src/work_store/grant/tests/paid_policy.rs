use super::*;
use crate::model::work::{JobPaymentPolicyV2, PaidChannelPolicyV1};
use crate::model::{
    grant::admin::WorkControlCommand,
    paid_policy::{OfferPolicy, PaidPolicy},
};
use crate::test_support::common_node::{NoBackend, WorkAdmin};
use hellas_kernel::{EdgeValues, Fees};
use std::sync::Arc;

fn paid() -> PaidPolicy {
    PaidPolicy {
        channel_policy: PaidChannelPolicyV1 {
            compute_credit_limit: 40,
            delivery_credit_limit: 40,
        },
        work_policy: policy().work,
        payment_policy: JobPaymentPolicyV2 {
            fixed_price: 10,
            dispatch_margin_blocks: 4,
            delivery_margin_blocks: 2,
            oracle_grace_blocks: 6,
        },
        expected_payment_values: EdgeValues::new(201, 0, Fees::ZERO),
        min_omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        jobs_per_channel: 10,
        offers: OfferPolicy {
            max_stake_per_client: 12,
            bond_lifetime_blocks: 200,
            max_open_offers: 2,
            omission_bond: 101,
            redelegate_payout: true,
        },
    }
}

#[test]
fn default_ten_jobs_and_offer_bounds_are_checked_before_storage() {
    let original = paid();
    let mut json = serde_json::to_value(&original).unwrap();
    json.as_object_mut().unwrap().remove("jobs_per_channel");
    json["offers"]
        .as_object_mut()
        .unwrap()
        .remove("redelegate_payout");
    let decoded: PaidPolicy = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, original);
    decoded.check().unwrap();
    for mutation in [0, 1, 2, 3, 4, 5, 6, 7] {
        let mut invalid = original.clone();
        match mutation {
            0 => invalid.jobs_per_channel = 0,
            1 => invalid.jobs_per_channel = u64::MAX,
            2 => invalid.offers.omission_bond = 100,
            3 => invalid.offers.max_stake_per_client = 0,
            4 => invalid.offers.max_open_offers = 0,
            5 => invalid.offers.bond_lifetime_blocks = 0,
            6 => invalid.min_omit_response_blocks = hellas_kernel::MAX_OMIT_RESPONSE_BLOCKS + 1,
            _ => invalid.expected_payment_values = EdgeValues::new(202, 0, Fees::ZERO),
        }
        assert!(
            invalid.check().is_err(),
            "invalid paid-policy case {mutation}"
        );
    }
}

#[tokio::test]
async fn paid_policy_requires_owner_passkey_and_current_revision_and_survives_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let (store, secret) = setup_with_credential(dir.path()).await;
    let service = crate::grant_service::GrantService::new(
        store,
        Arc::new(principal(2).1),
        NoBackend,
        vec![],
        Arc::new(|| UnixMillis(1000)),
    )
    .unwrap();
    let admin = WorkAdmin::new(service.clone(), &secret, vec![policy()]).await;
    let node = service.node();
    let command = |revision| WorkControlCommand::SetPaidPolicy {
        expected_revision: Revision(revision),
        policy: Box::new(paid()),
    };
    let daily_key = device(admin.caller.subject());
    let daily = node
        .authenticate_session(&secret, crate::node::SessionKey::Node(&daily_key))
        .await
        .unwrap();
    assert!(matches!(
        admin
            .service
            .execute(&daily, GrantId([0; 16]), command(0))
            .await,
        Err(NodeStoreError::Authority(
            hellas_auth::authority::AuthorityError::StepUp
        ))
    ));
    assert!(node.paid_policy().await.unwrap().is_none());
    admin.command(command(0)).await.unwrap();
    let first = node.paid_policy().await.unwrap().unwrap();
    assert_eq!(first.policy, paid());
    assert_eq!(first.revision, Revision(1));
    assert!(matches!(
        admin.command(command(0)).await,
        Err(NodeStoreError::Authority(
            hellas_auth::authority::AuthorityError::Revision
        ))
    ));
    assert_eq!(node.paid_policy().await.unwrap(), Some(first.clone()));
    admin.command(command(1)).await.unwrap();
    let current = node.paid_policy().await.unwrap().unwrap();
    assert_eq!(current.revision, Revision(2));
    assert_ne!(current.policy_salt, first.policy_salt);
    let held = node.writer().await.unwrap();
    let restored =
        crate::work_store::grant::State::restore(held.state().snapshot().unwrap()).unwrap();
    assert_eq!(restored.paid_policy(), Some(&current));
    drop(held);
    drop(admin);
    drop(service);
    drop(node);
    let reopened = NodeStore::open(dir.path(), network(), None, UnixMillis(1000))
        .await
        .unwrap();
    assert_eq!(reopened.state().paid_policy(), Some(&current));
}
