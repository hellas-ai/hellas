use super::*;
use hellas_auth::test_support::actors::{FRIEND, ROOT};
use hellas_auth::{Digest, ProducerSigningKey};
use hellas_kernel::{EdgeValues, Fees};
use hellas_work::model::work::{EvaluatePolicyV2, JobPaymentPolicyV2, PaidChannelPolicyV1};
use hellas_work::work_store::discover_setups;

fn signer(seed: u8) -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar([seed; 32]).unwrap()
}
fn options(root: &Path) -> ProvisionOptions {
    let key = ProducerSigningKey::from_secret_bytes([0x22; 32]).unwrap();
    let provider = hellas_work::test_support::enrollment(&key, &key, [7; 32], [3; 32]);
    ProvisionOptions {
        network: NetworkId::new("hellas-devnet-1").unwrap(),
        journal_root: root.to_path_buf(),
        settlement_key: signer(0x22),
        provider,
        addresses: vec!["127.0.0.1:9000".into()],
        client_principal: FRIEND.principal(),
        client_node: signer(0x21).party_key(),
        peer: [8; 32],
        redelegate_payout: true,
        stake_coins: vec![CoinId::from_bytes([1; 32])],
        bond_timeout: 200,
        timeout_payout: 12,
        max_job_price: 10,
        omission_bond: 101,
        payment_funding: Funding::new(
            List::take([CoinId::from_bytes([2; 32]); MAX_PARTY_INPUTS], 1),
            List::empty(CoinId::from_bytes([0; 32])),
        ),
        policy: ProviderChannelPolicy {
            network: NetworkId::new("hellas-devnet-1").unwrap(),
            policy_salt: [9; 32],
            channel_policy: PaidChannelPolicyV1 {
                compute_credit_limit: 40,
                delivery_credit_limit: 40,
            },
            work_policy: EvaluatePolicyV2 {
                allowed_environment: hellas_rpc::ContentId::from_bytes([0x11; 32]),
                generation_policy_digest: Digest::from_bytes([0x12; 32]),
                identity_source_digest: Digest::from_bytes([0x13; 32]),
                max_prompt_tokens: 512,
                max_new_tokens: 128,
                max_stop_token_ids: 4,
                max_spool_bytes: 1 << 20,
                max_encoded_result_frame: 262144,
                max_encoded_prepared_input: 1 << 20,
                max_upload_bytes: 1 << 20,
            }
            .into(),
            payment_policy: JobPaymentPolicyV2 {
                fixed_price: 10,
                dispatch_margin_blocks: 4,
                delivery_margin_blocks: 2,
                oracle_grace_blocks: 6,
            },
            expected_payment_values: EdgeValues::new(201, 0, Fees::ZERO),
            min_omit_response_blocks: hellas_kernel::MIN_OMIT_RESPONSE_BLOCKS,
        },
    }
}
fn floor() -> SetupScan {
    SetupScan {
        height: 7,
        payload: [7; 32],
    }
}
fn planned(options: &ProvisionOptions, held: &[SetupState]) -> Result<Offer> {
    let candidate = BondCandidate::plan(options, ROOT.principal())?;
    Offer::plan(options, candidate, held)
}

#[tokio::test]
async fn offer_peer_policy_funding_and_scan_floor_are_durable_in_one_record() {
    let dir = tempfile::tempdir().unwrap();
    let options = options(&dir.path().join("journal"));
    let offered = planned(&options, &[])
        .unwrap()
        .journal(floor(), &std::sync::atomic::AtomicBool::new(false))
        .await
        .unwrap();
    offered.offer.check().unwrap();
    let mut store =
        open_provider_journal(&options.journal_root, options.network, offered.bond_edge)
            .await
            .unwrap();
    assert_eq!(
        store.len(),
        1,
        "no separately durable unsigned scan-floor stage"
    );
    assert_eq!(store.state().scan_armed(), Some(floor()));
    let (peer, offer) = store.state().offer().unwrap();
    assert_eq!(*peer, options.peer);
    assert_eq!(*offer, offered.offer);
    assert_eq!(offer.offer().policy, options.policy);
    assert_eq!(offer.offer().payment_funding, options.payment_funding);
    assert_eq!(
        offer
            .offer()
            .proposal
            .bond_terms()
            .parties
            .maker()
            .owner()
            .to_bytes(),
        *ROOT.principal().as_bytes()
    );
    assert_eq!(
        offer
            .offer()
            .proposal
            .bond_terms()
            .parties
            .taker()
            .owner()
            .to_bytes(),
        *FRIEND.principal().as_bytes()
    );
    store.rotate().await.unwrap();
    drop(store);
    let reopened = open_provider_journal(&options.journal_root, options.network, offered.bond_edge)
        .await
        .unwrap();
    assert_eq!(
        reopened.state().offer().unwrap().1.encode().unwrap(),
        offered.offer.encode().unwrap()
    );
    assert_eq!(reopened.state().scan_armed(), Some(floor()));
    drop(reopened);
    assert_eq!(
        discover_setups(&options.journal_root, options.network)
            .await
            .unwrap()
            .setups
            .len(),
        1
    );
}

#[tokio::test]
async fn every_unanswered_offer_reserves_its_coins_before_another_offer_is_signed() {
    let dir = tempfile::tempdir().unwrap();
    let first = options(dir.path());
    let offered = planned(&first, &[])
        .unwrap()
        .journal(floor(), &std::sync::atomic::AtomicBool::new(false))
        .await
        .unwrap();
    let store = open_provider_journal(dir.path(), first.network, offered.bond_edge)
        .await
        .unwrap();
    let held = store.state().clone();
    let mut second = options(dir.path());
    second.client_node = signer(0x23).party_key();
    assert!(
        matches!(planned(&second, &[held]), Err(ProvisionError::ReservedCoin { coin, .. }) if coin == first.stake_coins[0])
    );
    assert_eq!(store.len(), 1);
}

#[tokio::test]
async fn expired_or_excessive_lifetime_offers_leave_no_journal_or_signature() {
    let dir = tempfile::tempdir().unwrap();
    for timeout in [
        floor().height,
        floor().height + MAX_EDGE_LIFETIME_BLOCKS + 1,
    ] {
        let root = dir.path().join(timeout.to_string());
        let mut options = options(&root);
        options.bond_timeout = timeout;
        let write_started = std::sync::atomic::AtomicBool::new(false);
        assert!(matches!(
            planned(&options, &[])
                .unwrap()
                .journal(floor(), &write_started)
                .await,
            Err(ProvisionError::ExpiredBond { .. } | ProvisionError::BondLifetime)
        ));
        assert!(
            !write_started.load(std::sync::atomic::Ordering::Acquire),
            "preflight failures cannot disable the allocator"
        );
        assert!(!root.exists());
    }
}

#[tokio::test]
async fn a_crash_after_creating_an_unsigned_header_does_not_block_discovery_or_retry() {
    let dir = tempfile::tempdir().unwrap();
    let options = options(dir.path());
    let candidate = BondCandidate::plan(&options, ROOT.principal()).unwrap();
    drop(
        open_provider_journal(dir.path(), options.network, candidate.bond_edge)
            .await
            .unwrap(),
    );
    let found = discover_setups(dir.path(), options.network).await.unwrap();
    assert!(found.setups.is_empty() && found.unidentified.is_empty());
    let offered = planned(&options, &[])
        .unwrap()
        .journal(floor(), &std::sync::atomic::AtomicBool::new(false))
        .await
        .unwrap();
    assert_eq!(offered.bond_edge, candidate.bond_edge);
    let found = discover_setups(dir.path(), options.network).await.unwrap();
    assert_eq!(found.setups.len(), 1);
    assert!(found.unidentified.is_empty());
}

#[test]
fn oversized_or_duplicate_stake_is_refused_without_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = options(dir.path());
    options.stake_coins = (0..=MAX_PARTY_INPUTS)
        .map(|n| CoinId::from_bytes([n as u8; 32]))
        .collect();
    assert!(matches!(
        BondCandidate::plan(&options, ROOT.principal()),
        Err(ProvisionError::StakeCount(5))
    ));
    options.stake_coins = vec![CoinId::from_bytes([1; 32]); 2];
    assert!(matches!(
        BondCandidate::plan(&options, ROOT.principal()),
        Err(ProvisionError::DuplicateCoin(_))
    ));
}

#[tokio::test]
async fn signed_offer_rejects_changed_policy_funding_enrollment_and_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let options = options(dir.path());
    let offered = planned(&options, &[])
        .unwrap()
        .journal(floor(), &std::sync::atomic::AtomicBool::new(false))
        .await
        .unwrap();
    let original = serde_json::to_value(&offered.offer).unwrap();
    for field in [
        "policy",
        "omission_bond",
        "payment_funding",
        "provider",
        "addresses",
    ] {
        let mut changed = original.clone();
        match field {
            "policy" => changed["offer"][field]["payment_policy"]["fixed_price"] = 9.into(),
            "omission_bond" => changed["offer"][field] = 102.into(),
            "addresses" => changed["offer"][field] = serde_json::json!(["127.0.0.1:9001"]),
            _ => {
                let bytes = changed["offer"][field].as_array_mut().unwrap();
                bytes[0] = ((bytes[0].as_u64().unwrap() + 1) % 256).into();
            }
        }
        if let Ok(signed) =
            serde_json::from_value::<hellas_work::model::offer::SignedPaidOffer>(changed)
        {
            assert!(signed.check().is_err(), "mutated {field}");
        }
    }
}
