use super::*;

#[test]
fn identity_fingerprints_have_stable_full_key_vectors() {
    assert_eq!(
        [
            ROOT.principal().fingerprint(),
            OPERATOR.principal().fingerprint()
        ],
        ["6DQB-FHDC-NZYD", "CAVN-TWJ7-ZVKY"]
    );
}

#[test]
fn principals_require_a_valid_supported_key() {
    assert_ne!(OPERATOR.principal(), FRIEND.principal());
    for key in [PublicKey::Secp256k1([0; 33]), PublicKey::Ed25519([1; 32])] {
        assert_eq!(
            PrincipalId::from_public_key(key),
            Err(AuthorityError::Invalid)
        );
    }
}

#[test]
fn root_is_not_an_execution_bypass() {
    let s = state();
    assert_eq!(
        execute(&s, ROOT, ids::ROOT_GRANT, 1),
        Err(AuthorityError::Denied)
    );
}
