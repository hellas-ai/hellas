use super::*;

fn request(fixture: &Fixture, owner: bool) -> GetObjectProofsRequest {
    GetObjectProofsRequest {
        object_ids: vec![fixture.old_coin.to_vec(), fixture.new_coin.to_vec()],
        payload: Some(fixture.applied.digest().to_vec()),
        owner: owner.then(|| fixture.owner.as_bytes().to_vec()),
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
        owner.then_some((fixture.owner, None)),
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
