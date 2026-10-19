use super::*;

#[test]
fn identity_fingerprints_have_stable_full_key_vectors() {
    assert_eq!(
        ROOT.principal().public_key().kind(),
        crate::SignatureKind::P256
    );
    assert_eq!(
        [
            ROOT.principal().fingerprint(),
            OPERATOR.principal().fingerprint()
        ],
        ["OOST-ZQ4S-ICPH", "UET2-BGW4-OUWJ"]
    );
}

#[test]
fn a_secp256k1_principal_is_rejected() {
    let node = ROOT.node_key().public_key();
    assert!(NodeKey::from_public_key(node).is_ok());
    assert_eq!(
        PrincipalId::from_public_key(node),
        Err(AuthorityError::Invalid)
    );
    assert_ne!(OPERATOR.principal(), FRIEND.principal());
    for key in [PublicKey::P256([0; 33]), PublicKey::Ed25519([1; 32])] {
        assert_eq!(
            PrincipalId::from_public_key(key),
            Err(AuthorityError::Invalid)
        );
    }
    assert_eq!(
        NodeKey::from_public_key(ROOT.principal().public_key()),
        Err(AuthorityError::Invalid)
    );
}

#[test]
fn serialized_principals_carry_the_p256_curve_tag() {
    let principal = ROOT.principal();
    let bytes = serde_ipld_dagcbor::to_vec(&principal).unwrap();
    // [3, h'<33 bytes>']: kind 3 is P-256.
    assert_eq!(bytes[..4], [0x82, 0x03, 0x58, 0x21]);
    assert_eq!(bytes[4..], principal.as_bytes()[..]);
    assert_eq!(
        serde_ipld_dagcbor::from_slice::<PrincipalId>(&bytes).unwrap(),
        principal
    );
    let mut secp256k1 = bytes.clone();
    secp256k1[1] = 0x01;
    assert!(serde_ipld_dagcbor::from_slice::<PrincipalId>(&secp256k1).is_err());
    assert!(serde_ipld_dagcbor::from_slice::<PrincipalId>(&bytes[2..]).is_err());
    let node = NodeKey::from_public_key(ROOT.node_key().public_key()).unwrap();
    assert_eq!(
        serde_ipld_dagcbor::to_vec(&node).unwrap()[..2],
        [0x82, 0x01]
    );
}

#[test]
fn root_is_not_an_execution_bypass() {
    let s = state();
    assert_eq!(
        execute(&s, ROOT, ids::ROOT_GRANT, 1),
        Err(AuthorityError::Denied)
    );
}
