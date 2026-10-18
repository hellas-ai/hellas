use super::*;
use crate::assert_err;

struct Connection {
    state: AuthorityState,
    secret: CredentialSecret,
}
impl Connection {
    fn new() -> Self {
        let mut scope = administrator(ROOT);
        // Deliberately independent of the production session-limit constant.
        scope.expires = UnixMillis(1_800_000);
        scope.issuance.as_mut().unwrap().max_validity_ms = 1_800_000;
        let (credential, secret) = Credential::prepare(scope.clone(), 1).unwrap();
        Self {
            state: AuthorityState::bootstrap(ids::ROOT_GRANT, scope, credential, UnixMillis(0))
                .unwrap(),
            secret,
        }
    }
    fn pending(&self) -> PendingAuthentication {
        self.state
            .begin_authentication(binding(), UnixMillis(10))
            .unwrap()
    }
    fn sign(&self, pending: &PendingAuthentication) -> crate::Signature {
        pending
            .challenge()
            .sign(authority(), binding(), self.secret.id(), &ROOT.key())
            .unwrap()
    }
    fn connect(&self) -> AuthenticatedSession {
        let pending = self.pending();
        let signature = self.sign(&pending);
        pending
            .complete(
                &self.state,
                binding(),
                &self.secret,
                &signature,
                UnixMillis(11),
            )
            .unwrap()
    }
    fn recover(&mut self) {
        self.state
            .recover(
                &super::recovery::command(&self.state, RECOVERY_OWNER),
                UnixMillis(12),
            )
            .unwrap();
    }
}
fn binding() -> Digest {
    Digest::hash(b"authenticated connection")
}
fn other_binding() -> Digest {
    Digest::hash(b"another connection")
}

#[test]
fn identity_proof_binds_every_challenge_field() {
    let connection = Connection::new();
    let changes: [fn(&mut SessionChallenge); 7] = [
        |c| c.authority = AuthorityId(Digest::hash(b"other authority")),
        |c| c.generation += 1,
        |c| c.nonce[0] ^= 1,
        |c| c.binding = other_binding(),
        |c| c.issued_at = UnixMillis(11),
        |c| c.deadline.0 -= 1,
        |c| c.session_expires.0 -= 1,
    ];
    for change in changes {
        let pending = connection.pending();
        let mut challenge = *pending.challenge();
        change(&mut challenge);
        let signature = challenge
            .sign(
                challenge.authority,
                challenge.binding,
                connection.secret.id(),
                &ROOT.key(),
            )
            .unwrap();
        assert_err!(
            pending.complete(
                &connection.state,
                binding(),
                &connection.secret,
                &signature,
                UnixMillis(11)
            ),
            AuthorityError::Credential
        );
    }
}

#[test]
fn identity_proof_binds_the_selected_credential() {
    let mut connection = Connection::new();
    let other = credentials::install(&mut connection.state, administrator(ROOT));
    let pending = connection.pending();
    let signature = pending
        .challenge()
        .sign(authority(), binding(), other.id(), &ROOT.key())
        .unwrap();
    assert_err!(
        pending.complete(
            &connection.state,
            binding(),
            &connection.secret,
            &signature,
            UnixMillis(11)
        ),
        AuthorityError::Credential
    );
}

#[test]
fn identity_proof_requires_the_credential_subjects_key() {
    let connection = Connection::new();
    let pending = connection.pending();
    let signature = pending
        .challenge()
        .sign(
            authority(),
            binding(),
            connection.secret.id(),
            &STRANGER.key(),
        )
        .unwrap();
    assert_err!(
        pending.complete(
            &connection.state,
            binding(),
            &connection.secret,
            &signature,
            UnixMillis(11)
        ),
        AuthorityError::Credential
    );
}

#[test]
fn a_valid_identity_signature_does_not_replace_the_credential_secret() {
    let connection = Connection::new();
    let pending = connection.pending();
    let signature = connection.sign(&pending);
    let wrong =
        CredentialSecret::from_parts(connection.secret.id(), STRANGER.key().to_secret_bytes());
    assert_err!(
        pending.complete(
            &connection.state,
            binding(),
            &wrong,
            &signature,
            UnixMillis(11)
        ),
        AuthorityError::Credential
    );
}

#[test]
fn clients_sign_only_the_expected_server_binding() {
    let connection = Connection::new();
    let pending = connection.pending();
    for (audience, transport) in [
        (AuthorityId(Digest::hash(b"wrong")), binding()),
        (authority(), other_binding()),
    ] {
        assert_err!(
            pending
                .challenge()
                .sign(audience, transport, connection.secret.id(), &ROOT.key()),
            AuthorityError::Credential
        );
    }
}

#[test]
fn authentication_completion_requires_the_original_connection() {
    let connection = Connection::new();
    let pending = connection.pending();
    let signature = connection.sign(&pending);
    // complete consumes the pending challenge even on refusal.
    assert_err!(
        pending.complete(
            &connection.state,
            other_binding(),
            &connection.secret,
            &signature,
            UnixMillis(11)
        ),
        AuthorityError::Credential
    );
}

#[test]
fn a_fresh_challenge_cannot_replay_a_previous_response() {
    let connection = Connection::new();
    let first = connection.pending();
    let next = connection.pending();
    assert_ne!(first.challenge().nonce, next.challenge().nonce);
    let signature = connection.sign(&first);
    assert_err!(
        next.complete(
            &connection.state,
            binding(),
            &connection.secret,
            &signature,
            UnixMillis(11)
        ),
        AuthorityError::Credential
    );
}

#[test]
fn the_challenge_lifetime_is_exactly_sixty_seconds() {
    let connection = Connection::new();
    for (elapsed, expected) in [(59_999, Ok(())), (60_000, Err(AuthorityError::Credential))] {
        let pending = connection.pending();
        assert_eq!(
            pending.challenge().deadline.0 - pending.challenge().issued_at.0,
            60_000
        );
        let signature = connection.sign(&pending);
        assert_eq!(
            pending
                .complete(
                    &connection.state,
                    binding(),
                    &connection.secret,
                    &signature,
                    UnixMillis(10 + elapsed)
                )
                .map(|_| ()),
            expected
        );
    }
    let mut challenge = *connection.pending().challenge();
    challenge.deadline = UnixMillis(challenge.issued_at.0 + 60_001);
    assert_eq!(challenge.validate(), Err(AuthorityError::Credential));
}

#[test]
fn challenge_time_overflow_is_refused() {
    let connection = Connection::new();
    assert_err!(
        connection
            .state
            .begin_authentication(binding(), UnixMillis(u64::MAX)),
        AuthorityError::Capacity
    );
}

#[test]
fn challenge_creation_respects_the_authority_clock_floor() {
    let connection = Connection::new();
    let mut advanced = connection.state.snapshot();
    advanced.now = UnixMillis(100);
    let restored = AuthorityState::restore(advanced).unwrap();
    assert_err!(
        restored.begin_authentication(binding(), UnixMillis(99)),
        AuthorityError::Clock
    );
}

#[test]
fn sessions_are_bound_to_the_original_connection() {
    let connection = Connection::new();
    let session = connection.connect();
    session
        .authenticate(&connection.state, binding(), UnixMillis(12))
        .unwrap();
    assert_err!(
        session.authenticate(&connection.state, other_binding(), UnixMillis(12)),
        AuthorityError::Credential
    );
}

#[test]
fn sessions_expire_after_fifteen_minutes_even_with_a_long_lived_credential() {
    let connection = Connection::new();
    let session = connection.connect();
    let caller = session
        .authenticate(&connection.state, binding(), UnixMillis(12))
        .unwrap();
    assert_eq!(session.expires(), UnixMillis(900_010));
    session
        .authenticate(&connection.state, binding(), UnixMillis(900_009))
        .unwrap();
    assert_err!(
        session.authenticate(&connection.state, binding(), UnixMillis(900_010)),
        AuthorityError::Credential
    );
    assert_err!(
        connection.state.authorize_caller(
            caller,
            ids::ROOT_GRANT,
            &permission("work.execute", resource(1)),
            UnixMillis(900_010)
        ),
        AuthorityError::Credential
    );
}

#[test]
fn credential_expiry_shortens_a_session() {
    let mut connection = Connection::new();
    connection.secret = credentials::install(&mut connection.state, spec(ROOT));
    let session = connection.connect();
    assert_eq!(session.expires(), UnixMillis(500));
    session
        .authenticate(&connection.state, binding(), UnixMillis(499))
        .unwrap();
    assert_err!(
        session.authenticate(&connection.state, binding(), UnixMillis(500)),
        AuthorityError::Credential
    );
}

#[test]
fn recovery_invalidates_pending_authentication() {
    let mut connection = Connection::new();
    let pending = connection.pending();
    let signature = connection.sign(&pending);
    connection.recover();
    assert_err!(
        pending.complete(
            &connection.state,
            binding(),
            &connection.secret,
            &signature,
            UnixMillis(12)
        ),
        AuthorityError::Credential
    );
}
