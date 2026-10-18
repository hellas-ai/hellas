use super::*;
use hellas_work::model::grant::records::Offer;
use hellas_work::test_support::{definition, ids, network, principal, software_enrollment};

fn bundle() -> AccessBundle {
    let (subject, _) = principal(7);
    let offer = SignedOffer::sign(
        Offer {
            network: network(),
            provider: software_enrollment(2, [2; 32]),
            grant: definition(ids::ALLOWANCE, subject),
            generation: 0,
            sequence: 1,
            valid_until: UnixMillis(1_000),
            addresses: vec![],
        },
        &principal(2).1,
    )
    .unwrap();
    AccessBundle {
        offer,
        authority: AuthorityId(hellas_auth::Digest::hash(b"access bundle")),
        authorization: GrantId([4; 16]),
        subject,
        credential: CredentialSecret::from_parts(CredentialId([5; 16]), [6; 32]),
        expires: UnixMillis(2_000),
        label: Some("provider".into()),
    }
}

#[test]
fn a_saved_bundle_is_private_and_installs_the_contact_profile() {
    let directory = tempfile::tempdir().unwrap();
    let original = bundle();
    let path = directory.path().join("friend.access");
    original.save(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(matches!(
        original.save(&path),
        Err(AccessBundleError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert!(matches!(
        AccessBundle::load(&path, &principal(8).0),
        Err(AccessBundleError::WrongSubject)
    ));
    let loaded = AccessBundle::load(&path, &original.subject).unwrap();
    assert_eq!(*loaded.encode().unwrap(), *original.encode().unwrap());
    let profile = profile::ClientProfile::load(
        &loaded
            .install_profile(&directory.path().join("profile"))
            .unwrap(),
    )
    .unwrap();
    let (offer, parts) = loaded.into_parts();
    assert_eq!(offer.encode().unwrap(), original.offer.encode().unwrap());
    for profile in [profile, parts] {
        assert_eq!(
            (profile.authority, profile.authorization),
            (original.authority, original.authorization)
        );
        assert_eq!(profile.credential.id(), original.credential.id());
        assert_eq!(
            profile.credential.expose_secret(),
            original.credential.expose_secret()
        );
        assert!(profile.local.is_none());
    }
}

#[test]
fn truncated_or_oversized_bundles_are_refused() {
    let original = bundle();
    let bytes = original.encode().unwrap();
    assert!(matches!(
        AccessBundle::decode(&bytes[..bytes.len() - 1], &original.subject),
        Err(AccessBundleError::Malformed)
    ));
    let oversized = vec![0; MAX_ACCESS_BUNDLE_BYTES + 1];
    assert!(matches!(
        AccessBundle::decode(&oversized, &original.subject),
        Err(AccessBundleError::TooLarge)
    ));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversized.access");
    hellas_private::write_atomically(&path, ".writing", &oversized).unwrap();
    assert!(matches!(
        AccessBundle::load(&path, &original.subject),
        Err(AccessBundleError::TooLarge)
    ));
}
