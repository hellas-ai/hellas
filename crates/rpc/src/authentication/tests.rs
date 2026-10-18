use super::*;
use hellas_auth::ProducerSigningKey;
use hellas_auth::authority::{
    AuthorityState, Credential, GRANT_ISSUE, GrantId, OperationId, Permission, PrincipalId,
};
use hellas_wire::{AuthLevel, PeerIdentity};

fn fixture() -> (AuthorityState, CredentialSecret, ProducerSigningKey) {
    let key = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
    let authority = AuthorityId(Digest::hash(b"session wire fixture"));
    let scope = hellas_auth::test_support::admin_spec(
        authority,
        PrincipalId::from_public_key(key.public_key()).unwrap(),
        &[],
        (UnixMillis(0), UnixMillis(1_000_000)),
        (1_000_000, 0),
        &[],
    );
    let (record, secret) = Credential::prepare(scope.clone(), 1).unwrap();
    (
        AuthorityState::bootstrap(GrantId([1; 16]), scope, record, UnixMillis(0)).unwrap(),
        secret,
        key,
    )
}

#[test]
fn bounded_canonical_messages_complete_authentication_and_reject_malformed_frames() {
    let (state, secret, key) = fixture();
    let context = TransportContext {
        open_exporter: Some([4; 32]),
        ..Default::default()
    };
    let binding = session_binding(&context, b"/authority/1").unwrap();
    let pending = state.begin_authentication(binding, UnixMillis(10)).unwrap();
    let bytes = encode_challenge(pending.challenge()).unwrap();
    let challenge = decode_challenge(&bytes).unwrap();
    assert_eq!(challenge, *pending.challenge());
    let signature = challenge
        .sign(state.authority(), binding, secret.id(), &key)
        .unwrap();
    let response = encode_response(&secret, &signature).unwrap();
    let (credential, signature) = decode_response(&response).unwrap();
    let session = pending
        .complete(&state, binding, &credential, &signature, UnixMillis(11))
        .unwrap();
    let caller = session
        .authenticate(&state, binding, UnixMillis(12))
        .unwrap();
    assert!(
        state
            .authorize_caller(
                caller,
                GrantId([1; 16]),
                &Permission {
                    operation: OperationId::new(GRANT_ISSUE).unwrap(),
                    resource: state.authority().resource(),
                },
                UnixMillis(12)
            )
            .is_ok()
    );

    for (message, is_challenge) in [(&bytes[..], true), (&response[..], false)] {
        let valid = |input: &[u8]| {
            if is_challenge {
                decode_challenge(input).is_ok()
            } else {
                decode_response(input).is_ok()
            }
        };
        assert!(message.len() <= MAX_AUTHENTICATION_MESSAGE_BYTES);
        for end in 0..message.len() {
            assert!(!valid(&message[..end]), "truncation at {end}");
        }
        let mut trailing = message.to_vec();
        trailing.push(0);
        assert!(!valid(&trailing));
        let mut nonminimal = message.to_vec();
        nonminimal[0] = 0x98;
        nonminimal.insert(1, if is_challenge { 8 } else { 4 });
        assert!(!valid(&nonminimal));
        let mut indefinite = message.to_vec();
        indefinite[0] = 0x9f;
        assert!(!valid(&indefinite));
        let mut wrong_version = message.to_vec();
        let version = wrong_version
            .windows(3)
            .position(|bytes| bytes == b".v1")
            .unwrap()
            + 2;
        wrong_version[version] = b'2';
        assert!(!valid(&wrong_version));
        assert!(!valid(&vec![0; MAX_AUTHENTICATION_MESSAGE_BYTES + 1]));
    }
    assert!(decode_challenge(&response).is_err());
    assert!(decode_response(&bytes).is_err());
    assert!(encode_response(&secret, &Signature::Ed25519([1; 64])).is_err());
    let mut excessive = challenge;
    excessive.session_expires = UnixMillis(u64::MAX);
    assert!(encode_challenge(&excessive).is_err());
    // Decoder errors redact attacker-controlled tags, even when they look secret.
    let mut hostile = DagCborEncoder::new();
    hostile.array(4);
    hostile.str("test-only-secret");
    assert_eq!(
        decode_response(&hostile.into_bytes())
            .unwrap_err()
            .to_string(),
        "invalid authentication message"
    );
}

#[test]
fn transport_binding_requires_an_exporter_and_separates_connections_and_services() {
    let alpn = b"/authority/1";
    for auth_level in [AuthLevel::None, AuthLevel::Vouched] {
        let context = TransportContext {
            auth_level,
            peer: Some(PeerIdentity([3; 32])),
            ..Default::default()
        };
        assert_eq!(
            session_binding(&context, alpn),
            Err(AuthenticationWireError::BindingUnavailable)
        );
    }
    let first = TransportContext {
        open_exporter: Some([1; 32]),
        ..Default::default()
    };
    let second = TransportContext {
        open_exporter: Some([2; 32]),
        ..Default::default()
    };
    assert_ne!(
        session_binding(&first, alpn).unwrap(),
        session_binding(&second, alpn).unwrap()
    );
    assert_ne!(
        session_binding(&first, alpn).unwrap(),
        session_binding(&first, b"/work/1").unwrap()
    );
    assert!(session_binding(&first, b"").is_err());
    assert!(session_binding(&first, &[1; 256]).is_err());
}
