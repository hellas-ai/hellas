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
        let (credential, secret) = prepare(scope.clone(), 1);
        Self {
            state: bootstrap(ids::ROOT_GRANT, scope, credential, UnixMillis(0)).unwrap(),
            secret,
        }
    }
    fn pending(&self) -> PendingAuthentication {
        self.state
            .begin_authentication(binding(), UnixMillis(10))
            .unwrap()
    }
    fn sign(&self, pending: &PendingAuthentication) -> SessionProof {
        pending
            .challenge()
            .sign_daily(authority(), binding(), self.secret.id(), &ROOT.node_key())
            .unwrap()
    }
    fn passkey(&self, pending: &PendingAuthentication, actor: Actor) -> SessionProof {
        SessionProof::Passkey(
            actor.assert(
                pending
                    .challenge()
                    .proof_digest(authority(), binding(), self.secret.id())
                    .unwrap(),
            ),
        )
    }
    fn connect(&self) -> AuthenticatedSession {
        let pending = self.pending();
        let signature = self.sign(&pending);
        self.complete(pending, &signature).unwrap()
    }
    fn complete(
        &self,
        pending: PendingAuthentication,
        proof: &SessionProof,
    ) -> Result<AuthenticatedSession, AuthorityError> {
        pending.complete(&self.state, binding(), &self.secret, proof, UnixMillis(11))
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
            .sign_daily(
                challenge.authority,
                challenge.binding,
                connection.secret.id(),
                &ROOT.node_key(),
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
        .sign_daily(authority(), binding(), other.id(), &ROOT.node_key())
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
        .sign_daily(
            authority(),
            binding(),
            connection.secret.id(),
            &STRANGER.node_key(),
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
    let wrong = CredentialSecret::from_parts(
        connection.secret.id(),
        STRANGER.node_key().to_secret_bytes(),
    );
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
            pending.challenge().sign_daily(
                audience,
                transport,
                connection.secret.id(),
                &ROOT.node_key()
            ),
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

#[test]
fn a_passkey_session_verifies_and_a_cross_connection_replay_fails() {
    let connection = Connection::new();
    let pending = connection.pending();
    let proof = connection.passkey(&pending, ROOT);
    let session = connection.complete(pending, &proof).unwrap();
    let caller = session
        .authenticate(&connection.state, binding(), UnixMillis(12))
        .unwrap();
    assert_eq!(caller.session(), SessionKind::Passkey);
    // The same assertion answering a challenge on another connection.
    let other = connection
        .state
        .begin_authentication(other_binding(), UnixMillis(10))
        .unwrap();
    assert_err!(
        other.complete(
            &connection.state,
            other_binding(),
            &connection.secret,
            &proof,
            UnixMillis(11)
        ),
        AuthorityError::Credential
    );
    // Only the credential subject's passkey answers.
    let pending = connection.pending();
    let stranger = connection.passkey(&pending, STRANGER);
    assert_err!(
        connection.complete(pending, &stranger),
        AuthorityError::Credential
    );
}

#[test]
fn a_daily_session_verifies_only_with_the_bound_node_key() {
    let mut connection = Connection::new();
    let session = connection.connect();
    assert_eq!(
        session
            .authenticate(&connection.state, binding(), UnixMillis(12))
            .unwrap()
            .session(),
        SessionKind::Daily
    );
    // The same subject's credential held by another device.
    let (credential, secret) =
        Credential::prepare(spec(ROOT), FRIEND.holder(), connection.state.generation()).unwrap();
    connection
        .state
        .apply_credential(
            ROOT.principal(),
            &CredentialCommand::Issue {
                authorization: ids::ROOT_GRANT,
                credential: Box::new(credential),
            },
            UnixMillis(2),
        )
        .unwrap();
    connection.secret = secret;
    for (key, accepted) in [(ROOT.node_key(), false), (FRIEND.node_key(), true)] {
        let pending = connection.pending();
        let proof = pending
            .challenge()
            .sign_daily(authority(), binding(), connection.secret.id(), &key)
            .unwrap();
        assert_eq!(connection.complete(pending, &proof).is_ok(), accepted);
    }
}

#[test]
fn a_step_up_operation_is_refused_on_a_daily_session() {
    let connection = Connection::new();
    let pending = connection.pending();
    let proof = connection.passkey(&pending, ROOT);
    let sessions = [
        connection.complete(pending, &proof).unwrap(),
        connection.connect(),
    ];
    let [passkey, daily] = sessions.each_ref().map(|s| {
        s.authenticate(&connection.state, binding(), UnixMillis(12))
            .unwrap()
    });
    let contact = AdministrationCommand::Grant(GrantCommand::Issue {
        authorization: ids::ROOT_GRANT,
        id: ids::FRIEND_GRANT,
        spec: spec(FRIEND),
    });
    let credential = AdministrationCommand::Credential(CredentialCommand::Issue {
        authorization: ids::ROOT_GRANT,
        credential: Box::new(prepare(spec(FRIEND), 1).0),
    });
    for command in [contact, credential] {
        assert_err!(
            connection
                .state
                .record_administration(daily, command.clone(), UnixMillis(12)),
            AuthorityError::StepUp
        );
        connection
            .state
            .record_administration(passkey, command, UnixMillis(12))
            .unwrap();
    }
    // The principal's own execution grant is a daily operation.
    connection
        .state
        .record_administration(
            daily,
            AdministrationCommand::Grant(GrantCommand::Issue {
                authorization: ids::ROOT_GRANT,
                id: ids::EXECUTION,
                spec: spec(ROOT),
            }),
            UnixMillis(12),
        )
        .unwrap();
}
