use super::*;
use hellas_auth::authority::{
    AuthorityState, Credential, GRANT_ISSUE, GrantId, OperationId, Ownership, Permission,
};
use hellas_auth::test_support::{actors::*, approve};
use hellas_wire::{AuthLevel, PeerIdentity};

fn fixture() -> (AuthorityState, CredentialSecret) {
    let authority = AuthorityId(Digest::hash(b"session wire fixture"));
    let scope = hellas_auth::test_support::admin_spec(
        authority,
        ROOT.principal(),
        &[],
        (UnixMillis(0), UnixMillis(1_000_000)),
        (1_000_000, 0),
        &[],
    );
    let (record, secret) = Credential::prepare(scope.clone(), ROOT.holder(), 1).unwrap();
    let root = GrantId([1; 16]);
    let owner = approve(
        ROOT,
        Ownership::Bootstrap { root, target: None },
        &scope,
        &scope,
        ROOT.holder(),
    );
    (
        AuthorityState::bootstrap(root, None, scope, record, &owner, UnixMillis(0)).unwrap(),
        secret,
    )
}

#[test]
fn bounded_canonical_messages_complete_authentication_and_reject_malformed_frames() {
    let (state, secret) = fixture();
    let context = TransportContext {
        open_exporter: Some([4; 32]),
        ..Default::default()
    };
    let binding = session_binding(&context, b"/authority/1").unwrap();
    let mut messages = Vec::new();
    for passkey in [true, false] {
        let pending = state.begin_authentication(binding, UnixMillis(10)).unwrap();
        let bytes = encode_challenge(pending.challenge()).unwrap();
        let challenge = decode_challenge(&bytes).unwrap();
        assert_eq!(challenge, *pending.challenge());
        let proof = if passkey {
            SessionProof::Passkey(
                ROOT.assert(
                    challenge
                        .proof_digest(state.authority(), binding, secret.id())
                        .unwrap(),
                ),
            )
        } else {
            challenge
                .sign_daily(state.authority(), binding, secret.id(), &ROOT.node_key())
                .unwrap()
        };
        let response = encode_response(&secret, &proof).unwrap();
        let (credential, decoded) = decode_response(&response).unwrap();
        assert_eq!(decoded, proof);
        let session = pending
            .complete(&state, binding, &credential, &decoded, UnixMillis(11))
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
        messages.push((bytes, true));
        messages.push((response.to_vec(), false));
    }

    for (message, is_challenge) in &messages {
        let valid = |input: &[u8]| {
            if *is_challenge {
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
        nonminimal.insert(1, if *is_challenge { 8 } else { 4 });
        assert!(!valid(&nonminimal));
        let mut indefinite = message.to_vec();
        indefinite[0] = 0x9f;
        assert!(!valid(&indefinite));
        let mut wrong_version = message.to_vec();
        let version = wrong_version
            .windows(2)
            .position(|bytes| bytes == b".v")
            .unwrap()
            + 2;
        wrong_version[version] = b'9';
        assert!(!valid(&wrong_version));
        assert!(!valid(&vec![0; MAX_AUTHENTICATION_MESSAGE_BYTES + 1]));
    }
    let (challenge, response) = (&messages[0].0, &messages[1].0);
    assert!(decode_challenge(response).is_err());
    assert!(decode_response(challenge).is_err());
    // Proof kinds cannot borrow each other's shape.
    let daily = &messages[3].0;
    let kind = daily.len() - 32 - 2 - 64 - 2 - 1;
    assert_eq!(daily[kind], PROOF_DAILY as u8);
    let mut swapped = daily.clone();
    swapped[kind] = PROOF_PASSKEY as u8;
    assert!(decode_response(&swapped).is_err());
    let mut excessive = decode_challenge(challenge).unwrap();
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
fn the_largest_passkey_response_fits_the_message_bound() {
    let (_, secret) = fixture();
    let client_data_json = vec![b' '; hellas_webauthn::MAX_CLIENT_DATA_JSON_LEN];
    let largest = SessionProof::Passkey(
        PasskeyAssertion::new(
            [1; 64],
            vec![0; hellas_webauthn::AUTHENTICATOR_DATA_LEN],
            client_data_json,
        )
        .unwrap(),
    );
    let response = encode_response(&secret, &largest).unwrap();
    assert!(response.len() <= MAX_AUTHENTICATION_MESSAGE_BYTES);
    assert_eq!(decode_response(&response).unwrap().1, largest);
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
