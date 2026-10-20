use super::*;

pub(super) fn install(s: &mut AuthorityState, scope: GrantSpec) -> CredentialSecret {
    let (credential, secret) = prepare(scope, s.generation());
    s.apply_credential(
        ROOT.principal(),
        &CredentialCommand::Issue {
            authorization: ids::ROOT_GRANT,
            credential: Box::new(credential),
        },
        UnixMillis(2),
    )
    .unwrap();
    secret
}
fn issuance_record(
    state: &AuthorityState,
    caller: &AuthenticatedCaller,
    target: GrantSpec,
    now: UnixMillis,
) -> Result<AdministrationRecord, AuthorityError> {
    state.record_administration(
        caller,
        AdministrationCommand::Grant(GrantCommand::Issue {
            authorization: ids::ROOT_GRANT,
            id: ids::CANDIDATE,
            spec: target,
        }),
        now,
    )
}
struct Credentials {
    state: AuthorityState,
    secret: CredentialSecret,
}
impl Credentials {
    fn operator() -> Self {
        let mut state = state();
        issue(&mut state, ids::OPERATOR_GRANT, spec(OPERATOR));
        let secret = install(&mut state, spec(OPERATOR));
        Self { state, secret }
    }
    fn caller(&self) -> AuthenticatedCaller {
        self.state
            .authenticate_secret(&self.secret, SessionKind::Passkey, UnixMillis(3))
            .unwrap()
    }
    fn revoke(&mut self) {
        let expected = self.state.credential(self.secret.id()).unwrap().revision();
        self.state
            .apply_credential(
                ROOT.principal(),
                &CredentialCommand::Revoke {
                    authorization: ids::ROOT_GRANT,
                    id: self.secret.id(),
                    expected,
                },
                UnixMillis(4),
            )
            .unwrap();
    }
    fn authorize(
        &self,
        caller: &AuthenticatedCaller,
        now: u64,
    ) -> Result<Vec<(GrantId, Revision)>, AuthorityError> {
        self.state.authorize_caller(
            caller,
            ids::OPERATOR_GRANT,
            &permission("work.execute", resource(1)),
            UnixMillis(now),
        )
    }
}

#[test]
fn credential_scope_intersects_the_selected_grant() {
    struct Case {
        grant: &'static str,
        credential: &'static str,
        expected: Result<(), AuthorityError>,
    }
    for case in [
        Case {
            grant: "work.execute",
            credential: "work.execute",
            expected: Ok(()),
        },
        Case {
            grant: "host.status",
            credential: "work.execute",
            expected: Err(AuthorityError::Denied),
        },
        Case {
            grant: "work.execute",
            credential: "host.status",
            expected: Err(AuthorityError::Denied),
        },
    ] {
        let mut s = state();
        issue(
            &mut s,
            ids::OPERATOR_GRANT,
            Rights::new(authority(), OPERATOR)
                .allow(case.grant, resource(1))
                .build(),
        );
        let secret = install(
            &mut s,
            Rights::new(authority(), OPERATOR)
                .allow(case.credential, resource(1))
                .build(),
        );
        let caller = s
            .authenticate_secret(&secret, SessionKind::Passkey, UnixMillis(3))
            .unwrap();
        let before = s.clone();
        assert_eq!(caller.subject(), OPERATOR.principal());
        assert_eq!(
            s.authorize_caller(
                &caller,
                ids::OPERATOR_GRANT,
                &permission("work.execute", resource(1)),
                UnixMillis(4)
            )
            .map(|_| ()),
            case.expected
        );
        assert_eq!(s, before);
    }
}

#[test]
fn a_wrong_credential_secret_is_refused() {
    let w = Credentials::operator();
    let wrong = CredentialSecret::from_parts(w.secret.id(), STRANGER.node_key().to_secret_bytes());
    assert_err!(
        w.state
            .authenticate_secret(&wrong, SessionKind::Passkey, UnixMillis(4)),
        AuthorityError::Credential
    );
}

#[test]
fn credential_expiry_invalidates_previously_authenticated_callers() {
    let w = Credentials::operator();
    let caller = w.caller();
    w.authorize(&caller, 499).unwrap();
    assert_err!(
        w.state
            .authenticate_secret(&w.secret, SessionKind::Passkey, UnixMillis(500)),
        AuthorityError::Credential
    );
    assert_eq!(w.authorize(&caller, 500), Err(AuthorityError::Credential));
}

#[test]
fn caller_evidence_cannot_be_used_before_authentication() {
    let w = Credentials::operator();
    assert_eq!(w.authorize(&w.caller(), 2), Err(AuthorityError::Credential));
}

#[test]
fn grant_revocation_takes_effect_without_revoking_the_credential() {
    let mut w = Credentials::operator();
    let caller = w.caller();
    revoke(&mut w.state, ids::OPERATOR_GRANT, 4);
    w.state
        .authenticate_secret(&w.secret, SessionKind::Passkey, UnixMillis(4))
        .unwrap();
    assert_eq!(w.authorize(&caller, 4), Err(AuthorityError::Revoked));
}

#[test]
fn credential_issuance_requires_its_own_permission() {
    let mut s = state();
    let mut admin = administrator(OPERATOR);
    admin
        .permissions
        .retain(|p| p.operation.as_str() != CREDENTIAL_ISSUE);
    issue(&mut s, ids::OPERATOR_GRANT, admin);
    let (credential, _) = prepare(spec(FRIEND), 1);
    let before = s.clone();
    assert_eq!(
        s.apply_credential(
            OPERATOR.principal(),
            &CredentialCommand::Issue {
                authorization: ids::OPERATOR_GRANT,
                credential: Box::new(credential)
            },
            UnixMillis(2)
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(s, before);
}

#[test]
fn credential_revocation_requires_its_own_permission() {
    let mut w = Credentials::operator();
    let mut admin = administrator(OPERATOR);
    admin
        .permissions
        .retain(|p| p.operation.as_str() != CREDENTIAL_REVOKE);
    revise(&mut w.state, ids::OPERATOR_GRANT, admin, 3).unwrap();
    let before = w.state.clone();
    let expected = w.state.credential(w.secret.id()).unwrap().revision();
    assert_eq!(
        w.state.apply_credential(
            OPERATOR.principal(),
            &CredentialCommand::Revoke {
                authorization: ids::OPERATOR_GRANT,
                id: w.secret.id(),
                expected
            },
            UnixMillis(3)
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(w.state, before);
}

#[test]
fn credential_revocation_requires_the_expected_revision() {
    let mut w = Credentials::operator();
    let before = w.state.clone();
    let expected = w
        .state
        .credential(w.secret.id())
        .unwrap()
        .revision()
        .next()
        .unwrap();
    assert_eq!(
        w.state.apply_credential(
            ROOT.principal(),
            &CredentialCommand::Revoke {
                authorization: ids::ROOT_GRANT,
                id: w.secret.id(),
                expected
            },
            UnixMillis(3)
        ),
        Err(AuthorityError::Revision)
    );
    assert_eq!(w.state, before);
}

#[test]
fn credential_revocation_invalidates_all_caller_entry_points() {
    let mut w = Credentials::operator();
    let caller = w.caller();
    assert_eq!(
        issuance_record(&w.state, &caller, spec(FRIEND), UnixMillis(3)),
        Err(AuthorityError::Denied)
    );
    w.revoke();
    let before = w.state.clone();
    assert_err!(
        w.state
            .authenticate_secret(&w.secret, SessionKind::Passkey, UnixMillis(4)),
        AuthorityError::Credential
    );
    assert_eq!(w.authorize(&caller, 4), Err(AuthorityError::Credential));
    assert_eq!(
        issuance_record(&w.state, &caller, spec(FRIEND), UnixMillis(4)),
        Err(AuthorityError::Credential)
    );
    assert_eq!(w.state, before);
}

#[test]
fn credential_ids_remain_reserved_after_revocation() {
    let mut w = Credentials::operator();
    let original = w.state.credential(w.secret.id()).unwrap().clone();
    let command = CredentialCommand::Issue {
        authorization: ids::ROOT_GRANT,
        credential: Box::new(original),
    };
    let before = w.state.clone();
    assert_eq!(
        w.state
            .apply_credential(ROOT.principal(), &command, UnixMillis(3)),
        Err(AuthorityError::Duplicate)
    );
    assert_eq!(w.state, before);
    w.revoke();
    let before = w.state.clone();
    assert_eq!(
        w.state
            .apply_credential(ROOT.principal(), &command, UnixMillis(4)),
        Err(AuthorityError::Duplicate)
    );
    assert_eq!(w.state, before);
}

#[test]
fn administrative_credentials_cannot_borrow_a_wider_issuance_ceiling() {
    let root = administrator(ROOT);
    let mut scope = root.clone();
    scope.issuance = Some(IssuanceCeiling {
        resources: CeilingResources::Named([resource(1)].into()),
        operations: [operation("work.execute")].into(),
        max_validity_ms: 50,
        max_delegation_depth: 0,
    });
    let (credential, token) = prepare(scope, 1);
    let s = bootstrap(ids::ROOT_GRANT, root, credential, UnixMillis(0)).unwrap();
    let caller = s
        .authenticate_secret(&token, SessionKind::Passkey, UnixMillis(1))
        .unwrap();
    let mut target = spec(OPERATOR);
    target.expires = UnixMillis(50);
    issuance_record(&s, &caller, target.clone(), UnixMillis(1)).unwrap();
    let changes: [fn(&mut GrantSpec); 4] = [
        |s| s.permissions = [permission("work.execute", resource(2))].into(),
        |s| s.permissions = [permission("host.status", resource(1))].into(),
        |s| s.expires = UnixMillis(100),
        |s| s.issuance = administrator(ROOT).issuance,
    ];
    for change in changes {
        let mut denied = target.clone();
        change(&mut denied);
        assert_eq!(
            issuance_record(&s, &caller, denied, UnixMillis(1)),
            Err(AuthorityError::Denied)
        );
    }
}

#[test]
fn snapshots_never_contain_credential_secrets() {
    let w = Credentials::operator();
    let bytes = serde_ipld_dagcbor::to_vec(&w.state.snapshot()).unwrap();
    assert!(
        !bytes
            .windows(32)
            .any(|bytes| bytes == w.secret.expose_secret())
    );
    let restored =
        AuthorityState::restore(serde_ipld_dagcbor::from_slice(&bytes).unwrap()).unwrap();
    assert_eq!(restored, w.state);
    restored
        .authenticate_secret(&w.secret, SessionKind::Passkey, UnixMillis(3))
        .unwrap();
}

#[test]
fn credential_debug_redacts_the_secret() {
    let w = Credentials::operator();
    assert_eq!(format!("{:?}", w.secret), "CredentialSecret(redacted)");
}

#[test]
fn credential_verifiers_are_bound_to_the_authority() {
    let w = Credentials::operator();
    let mut other = w.state.snapshot();
    other.authority = AuthorityId(Digest::hash(b"other node"));
    for grant in &mut other.grants {
        grant.spec.authority = other.authority;
    }
    for credential in &mut other.credentials {
        credential.scope.authority = other.authority;
    }
    let other = AuthorityState::restore(other).unwrap();
    assert_err!(
        other.authenticate_secret(&w.secret, SessionKind::Passkey, UnixMillis(3)),
        AuthorityError::Credential
    );
}

#[test]
fn malformed_credential_snapshots_are_refused() {
    let w = Credentials::operator();
    let changes: [fn(&mut AuthoritySnapshot); 6] = [
        |s| s.credentials.push(s.credentials[0].clone()),
        |s| s.credentials.clear(),
        |s| s.credentials[0].scope.authority = AuthorityId(Digest::hash(b"other")),
        |s| s.credentials[0].generation += 1,
        |s| s.credentials[0].revision = Revision(0),
        |s| s.credentials = vec![s.credentials[0].clone(); 257],
    ];
    for change in changes {
        let mut snapshot = w.state.snapshot();
        change(&mut snapshot);
        assert_eq!(
            AuthorityState::restore(snapshot),
            Err(AuthorityError::Invalid)
        );
    }
}

#[test]
fn a_caller_authenticated_against_forged_state_has_no_authority() {
    let w = Credentials::operator();
    let forged = CredentialSecret::from_parts(w.secret.id(), STRANGER.node_key().to_secret_bytes());
    let mut fabricated = w.state.snapshot();
    fabricated
        .credentials
        .iter_mut()
        .find(|c| c.id == w.secret.id())
        .unwrap()
        .verifier = forged.verifier(authority(), 1);
    let fabricated = AuthorityState::restore(fabricated).unwrap();
    let caller = fabricated
        .authenticate_secret(&forged, SessionKind::Passkey, UnixMillis(3))
        .unwrap();
    assert_eq!(w.authorize(&caller, 3), Err(AuthorityError::Credential));
}

#[test]
fn recovery_replaces_credential_evidence_without_revoking_execution_grants() {
    let mut w = Credentials::operator();
    let caller = w.caller();
    let administrator = administrator(OPERATOR);
    let (credential, replacement) = prepare(administrator.clone(), 2);
    w.state
        .recover(
            &recovery(&w.state, administrator, credential, Default::default()),
            UnixMillis(4),
        )
        .unwrap();
    assert_eq!(w.state.credentials().count(), 1);
    assert_err!(
        w.state
            .authenticate_secret(&w.secret, SessionKind::Passkey, UnixMillis(4)),
        AuthorityError::Credential
    );
    assert_eq!(w.authorize(&caller, 4), Err(AuthorityError::Credential));
    let caller = w
        .state
        .authenticate_secret(&replacement, SessionKind::Passkey, UnixMillis(4))
        .unwrap();
    w.authorize(&caller, 4).unwrap();
}

#[test]
fn copying_an_old_verifier_cannot_revive_a_previous_generation_secret() {
    let mut w = Credentials::operator();
    w.state
        .recover(&recovery::command(&w.state, OPERATOR), UnixMillis(4))
        .unwrap();
    let mut snapshot = w.state.snapshot();
    snapshot.credentials[0].id = w.secret.id();
    snapshot.credentials[0].verifier = w.secret.verifier(authority(), 1);
    let restored = AuthorityState::restore(snapshot).unwrap();
    assert_err!(
        restored.authenticate_secret(&w.secret, SessionKind::Passkey, UnixMillis(4)),
        AuthorityError::Credential
    );
}

#[test]
fn only_gateway_bearer_credentials_authenticate_by_secret_alone() {
    let mut w = Credentials::operator();
    assert!(!w.state.credential(w.secret.id()).unwrap().bearer());
    assert_err!(
        w.state.authenticate(&w.secret, UnixMillis(3)),
        AuthorityError::Credential
    );
    assert_err!(
        Credential::prepare(spec(ROOT), CredentialHolder::Bearer, 1),
        AuthorityError::Invalid
    );
    let gateway = Rights::new(authority(), ROOT)
        .allow(GATEWAY_INVOKE, resource(1))
        .build();
    let (credential, secret) = Credential::prepare(gateway, CredentialHolder::Bearer, 1).unwrap();
    w.state
        .apply_credential(
            ROOT.principal(),
            &CredentialCommand::Issue {
                authorization: ids::ROOT_GRANT,
                credential: Box::new(credential),
            },
            UnixMillis(3),
        )
        .unwrap();
    let caller = w.state.authenticate(&secret, UnixMillis(3)).unwrap();
    assert_eq!(
        (caller.subject(), caller.session()),
        (ROOT.principal(), SessionKind::Bearer)
    );
    // A bearer secret opens no session, whatever proof accompanies it.
    let binding = Digest::hash(b"bearer connection");
    let pending = w
        .state
        .begin_authentication(binding, UnixMillis(3))
        .unwrap();
    let proof = pending
        .challenge()
        .sign_daily(authority(), binding, secret.id(), &ROOT.node_key())
        .unwrap();
    assert_err!(
        pending.complete(&w.state, binding, &secret, &proof, UnixMillis(3)),
        AuthorityError::Credential
    );
}

#[test]
fn the_257th_live_credential_is_refused_atomically() {
    let mut s = state();
    for _ in 1..256 {
        install(&mut s, spec(FRIEND));
    }
    assert_eq!(s.credentials().count(), 256);
    let before = s.clone();
    let (credential, _) = prepare(spec(FRIEND), 1);
    assert_eq!(
        s.apply_credential(
            ROOT.principal(),
            &CredentialCommand::Issue {
                authorization: ids::ROOT_GRANT,
                credential: Box::new(credential)
            },
            UnixMillis(3)
        ),
        Err(AuthorityError::Capacity)
    );
    assert_eq!(s, before);
}

#[test]
fn a_credential_cannot_borrow_another_subjects_grant() {
    let w = Credentials::operator();
    let before = w.state.clone();
    assert_eq!(
        w.state.authorize_caller(
            &w.caller(),
            ids::ROOT_GRANT,
            &permission("work.execute", resource(1)),
            UnixMillis(4)
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(w.state, before);
}
