use super::*;
use hellas_authority::model::grant::records::Offer;
use {
    hellas_authority::test_support::definition, hellas_authority::test_support::ids,
    hellas_channel::test_support::network, hellas_channel::test_support::node_key,
    hellas_channel::test_support::principal, hellas_channel::test_support::software_enrollment,
};

fn offer(allowance: GrantId, subject: PrincipalId) -> SignedOffer {
    SignedOffer::sign(
        Offer {
            network: network(),
            provider: software_enrollment(2, [2; 32]),
            grant: definition(allowance, subject),
            generation: 0,
            sequence: 1,
            valid_until: UnixMillis(1_000),
            addresses: vec![],
        },
        &principal(2).1,
    )
    .unwrap()
}

/// Two shared allowances, one grant, one credential bound to the contact's node.
fn bundle() -> AccessBundle {
    let (subject, _) = principal(7);
    AccessBundle {
        offers: vec![
            offer(ids::ALLOWANCE, subject),
            offer(GrantId([12; 16]), subject),
        ],
        authority: AuthorityId(hellas_auth::Digest::hash(b"access bundle")),
        authorization: GrantId([4; 16]),
        subject,
        holder: node_key(7),
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
        AccessBundle::load(&path, &principal(8).0, &original.holder),
        Err(AccessBundleError::WrongSubject)
    ));
    // The same principal on another device cannot use the credential.
    assert!(matches!(
        AccessBundle::load(&path, &original.subject, &node_key(8)),
        Err(AccessBundleError::WrongHolder)
    ));
    let loaded = AccessBundle::load(&path, &original.subject, &original.holder).unwrap();
    assert_eq!(*loaded.encode().unwrap(), *original.encode().unwrap());
    let profile = profile::ClientProfile::load(
        &loaded
            .install_profile(&directory.path().join("profile"))
            .unwrap(),
    )
    .unwrap();
    let (offers, parts) = loaded.into_parts();
    assert_eq!(offers.len(), 2);
    for (offer, original) in offers.iter().zip(&original.offers) {
        assert_eq!(offer.encode().unwrap(), original.encode().unwrap());
    }
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
fn the_wire_carries_the_v2_tag_and_curve_tagged_keys() {
    #[derive(serde::Deserialize)]
    struct Probe {
        tag: String,
        subject: (u8, serde_bytes::ByteBuf),
        holder: (u8, serde_bytes::ByteBuf),
    }
    let original = bundle();
    let probe: Probe =
        hellas_rpc::protocol::value::decode_dag_cbor(&original.encode().unwrap()).unwrap();
    assert_eq!(probe.tag, "hellas.access-bundle.v2");
    assert_eq!(probe.subject.0, 3, "the subject is a P-256 principal");
    assert_eq!(probe.subject.1.as_slice(), original.subject.as_bytes());
    assert_eq!(probe.holder.0, 1, "the holder is a secp256k1 node key");
    assert_eq!(probe.holder.1.as_slice(), original.holder.as_bytes());
}

#[test]
fn bundles_name_one_provider_and_distinct_allowances() {
    let mut empty = bundle();
    empty.offers.clear();
    assert!(matches!(empty.encode(), Err(AccessBundleError::Malformed)));
    let mut repeated = bundle();
    repeated.offers[1] = repeated.offers[0].clone();
    assert!(matches!(
        repeated.encode(),
        Err(AccessBundleError::Malformed)
    ));
    let mut foreign = bundle();
    foreign.offers[1] = SignedOffer::sign(
        Offer {
            network: network(),
            provider: software_enrollment(3, [3; 32]),
            grant: definition(GrantId([13; 16]), foreign.subject),
            generation: 0,
            sequence: 1,
            valid_until: UnixMillis(1_000),
            addresses: vec![],
        },
        &principal(3).1,
    )
    .unwrap();
    assert!(matches!(
        foreign.encode(),
        Err(AccessBundleError::Malformed)
    ));
}

#[test]
fn truncated_or_oversized_bundles_are_refused() {
    let original = bundle();
    let bytes = original.encode().unwrap();
    assert!(matches!(
        AccessBundle::decode(
            &bytes[..bytes.len() - 1],
            &original.subject,
            &original.holder
        ),
        Err(AccessBundleError::Malformed)
    ));
    let oversized = vec![0; MAX_ACCESS_BUNDLE_BYTES + 1];
    assert!(matches!(
        AccessBundle::decode(&oversized, &original.subject, &original.holder),
        Err(AccessBundleError::TooLarge)
    ));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversized.access");
    hellas_private::write_atomically(&path, ".writing", &oversized).unwrap();
    assert!(matches!(
        AccessBundle::load(&path, &original.subject, &original.holder),
        Err(AccessBundleError::TooLarge)
    ));
}
