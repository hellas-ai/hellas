use super::*;

fn peer(n: u32) -> EndpointId {
    let mut seed = [0; 32];
    seed[..4].copy_from_slice(&n.to_be_bytes());
    iroh::SecretKey::from_bytes(&seed).public()
}

#[test]
fn attempts_refill_independently_and_authenticated_sessions_return_their_tokens() {
    let admission = UnverifiedAdmission::default();
    let now = Instant::now();
    for _ in 0..64 {
        admission.admit(peer(0), now).unwrap().authenticated();
    }
    for _ in 0..BURST {
        drop(admission.admit(peer(0), now).unwrap());
    }
    assert!(admission.admit(peer(0), now).is_err());
    drop(admission.admit(peer(1), now).unwrap());
    drop(admission.admit(peer(0), now + REFILL).unwrap());
    assert!(admission.admit(peer(0), now + REFILL).is_err());
    let later = now + Duration::from_secs(60);
    let active: Vec<_> = (0..BURST)
        .map(|_| admission.admit(peer(0), later).unwrap())
        .collect();
    assert!(
        admission
            .admit(peer(0), later + Duration::from_secs(60))
            .is_err()
    );
    drop(active);
    assert!(
        admission
            .admit(peer(0), later + Duration::from_secs(60))
            .is_ok()
    );
}

#[test]
fn a_full_map_refuses_new_endpoints_and_prunes_only_idle_unheld_buckets() {
    let admission = UnverifiedAdmission::default();
    let now = Instant::now();
    let held = admission.admit(peer(0), now).unwrap();
    for n in 1..MAX_PEERS as u32 {
        drop(admission.admit(peer(n), now).unwrap());
    }
    assert!(admission.admit(peer(MAX_PEERS as u32), now).is_err());
    assert_eq!(admission.0.lock().unwrap().len(), MAX_PEERS);
    let next = admission
        .admit(peer(MAX_PEERS as u32), now + REFILL)
        .unwrap();
    assert_eq!(admission.0.lock().unwrap().len(), 2);
    drop(next);
    drop(held);
}
