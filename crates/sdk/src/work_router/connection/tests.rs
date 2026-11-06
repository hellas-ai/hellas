use super::*;

#[tokio::test]
async fn refused_and_malformed_paid_requests_do_not_return_admission_tokens() {
    let admission = admission::UnverifiedAdmission::default();
    let peer = iroh::SecretKey::generate().public();
    let now = tokio::time::Instant::now();
    for n in 0..8 {
        let connection = ConnectionWork {
            funding: Funding::Payment(MountedWork::default()),
            unverified: Mutex::new(Some(admission.admit(peer, now).unwrap())),
        };
        let response = wt(connection.accept_work(
            AcceptWorkRequest {
                route: (n % 2 == 0).then(|| WorkRoute::payment(Digest::from_bytes([0; 32]))),
                ..Default::default()
            },
            TransportContext::default(),
        ))
        .await;
        if n % 2 == 0 {
            assert!(matches!(
                response.unwrap().response.outcome,
                Some(hellas_rpc::pb::work::accept_work_response::Outcome::Refused(_))
            ));
        } else {
            assert!(response.is_err());
        }
    }
    assert!(admission.admit(peer, now).is_err());
}
