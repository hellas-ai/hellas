use super::*;
use crate::proof_verify::ProofVerifier;

fn request(fixture: &Fixture, owner: bool) -> GetObjectProofsRequest {
    GetObjectProofsRequest {
        object_ids: vec![fixture.old_coin.to_vec(), fixture.new_coin.to_vec()],
        payload: Some(fixture.applied.digest().to_vec()),
        owner: owner.then(|| fixture.owner.as_bytes().to_vec()),
        owner_limit: if owner { 32 } else { 0 },
        owner_after_key: None,
    }
}

fn verify(
    fixture: &Fixture,
    response: GetObjectProofsResponse,
    owner: bool,
) -> Result<crate::proof_verify::VerifiedObjects, crate::proof_verify::VerificationError> {
    let keys = BTreeSet::from([fixture.old_coin, fixture.new_coin]);
    fixture.verifier.verify_objects(
        response,
        &keys,
        FinalizedBlockQuery::Payload(fixture.applied.digest()),
        owner.then_some((fixture.owner, None, 32)),
    )
}

#[test]
fn current_witness_rejects_noncanonical_bytes_and_incomplete_key_sets() {
    run_qmdb(|runtime| async move {
        let fixture = fixture(runtime).await;
        let response = fixture
            .remote
            .get_object_proofs(request(&fixture, false))
            .await
            .unwrap();
        assert!(verify(&fixture, response.clone(), false).is_ok());

        let mut malformed = response.clone();
        malformed.proofs[0].proof.pop();
        assert!(verify(&fixture, malformed, false).is_err());

        let mut trailing = response.clone();
        trailing.proofs[0].proof.push(0);
        assert!(verify(&fixture, trailing, false).is_err());

        let mut missing = response.clone();
        missing.proofs.pop();
        assert!(verify(&fixture, missing, false).is_err());

        let mut duplicate = response.clone();
        duplicate.proofs[1] = duplicate.proofs[0].clone();
        assert!(verify(&fixture, duplicate, false).is_err());

        let mut extra = response;
        let mut unrelated = extra.proofs[0].clone();
        unrelated.object_id = vec![0xfa; 32];
        extra.proofs.push(unrelated);
        assert!(verify(&fixture, extra, false).is_err());
        fixture.stop().await;
    });
}

#[test]
fn current_witness_rejects_cryptographically_invalid_inclusion_and_exclusion() {
    run_qmdb(|runtime| async move {
        let fixture = fixture(runtime).await;
        let response = fixture
            .remote
            .get_object_proofs(request(&fixture, false))
            .await
            .unwrap();
        assert!(verify(&fixture, response.clone(), false).is_ok());
        assert_eq!(response.proofs.len(), 2);
        assert!(response.proofs.iter().any(|entry| entry.object.is_some()));
        assert!(response.proofs.iter().any(|entry| entry.object.is_none()));
        for index in 0..response.proofs.len() {
            let mut invalid = response.clone();
            let proof = &mut invalid.proofs[index].proof;
            *proof.last_mut().unwrap() ^= 1;
            assert!(
                verify(&fixture, invalid, false).is_err(),
                "tampered Current proof at index {index} must fail"
            );
        }
        fixture.stop().await;
    });
}

#[test]
fn current_owner_page_rejects_an_altered_root() {
    run_qmdb(|runtime| async move {
        let fixture = fixture(runtime).await;
        let response = fixture
            .remote
            .get_object_proofs(request(&fixture, true))
            .await
            .unwrap();
        assert!(verify(&fixture, response.clone(), true).is_ok());
        let mut altered = response;
        let page = altered.owner_page.as_mut().unwrap();
        assert!(!page.holdings.is_empty());
        page.summary.as_mut().unwrap().leaf = None;
        assert!(verify(&fixture, altered, true).is_err());
        fixture.stop().await;
    });
}

#[test]
fn current_witness_rejects_other_network_and_epoch_schedule() {
    run_qmdb(|runtime| async move {
        let fixture = fixture(runtime).await;
        let response = fixture
            .remote
            .get_object_proofs(request(&fixture, false))
            .await
            .unwrap();
        assert!(verify(&fixture, response.clone(), false).is_ok());

        let mut genesis: hellas_genesis::Genesis =
            serde_json::from_slice(&fixture.genesis_json).unwrap();
        let keys = BTreeSet::from([fixture.old_coin, fixture.new_coin]);
        let query = FinalizedBlockQuery::Payload(fixture.applied.digest());
        genesis.network_id = "other-network".into();
        let altered_json = serde_json::to_vec(&genesis).unwrap();
        let mut trust = fixture.trust.clone();
        trust.network_id = genesis.network_id;
        trust.genesis_sha256 = hex::encode(commonware_cryptography::Sha256::hash(&altered_json));
        let other_network = ProofVerifier::with_genesis(trust, &altered_json).unwrap();
        assert!(
            other_network
                .verify_objects(response.clone(), &keys, query, None)
                .is_err()
        );

        let mut wrong_epoch = fixture.trust.clone();
        wrong_epoch.epochs[0].epoch = 1;
        let wrong_epoch = ProofVerifier::with_genesis(wrong_epoch, &fixture.genesis_json).unwrap();
        assert!(
            wrong_epoch
                .verify_objects(response, &keys, query, None)
                .is_err()
        );
        fixture.stop().await;
    });
}
