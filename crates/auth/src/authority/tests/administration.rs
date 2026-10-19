use super::*;

fn enroll(s: &mut AuthorityState, scope: GrantSpec) -> AuthenticatedCaller {
    let secret = credentials::install(s, scope);
    s.authenticate_secret(&secret, SessionKind::Passkey, UnixMillis(3))
        .unwrap()
}
fn record(
    s: &AuthorityState,
    caller: &AuthenticatedCaller,
    command: GrantCommand,
) -> Result<AdministrationRecord, AuthorityError> {
    s.record_administration(caller, AdministrationCommand::Grant(command), UnixMillis(3))
}

#[test]
fn a_credential_needs_administrator_rights_to_issue_administrators() {
    let mut s = state();
    let mut scope = administrator(ROOT);
    scope
        .permissions
        .retain(|p| p.operation.as_str() != GRANT_ADMINISTER);
    let caller = enroll(&mut s, scope);
    let issuance = |spec| GrantCommand::Issue {
        authorization: ids::ROOT_GRANT,
        id: ids::FRIEND_GRANT,
        spec,
    };
    record(&s, &caller, issuance(spec(FRIEND))).unwrap();
    let before = s.clone();
    assert_eq!(
        record(&s, &caller, issuance(administrator(FRIEND))),
        Err(AuthorityError::Denied)
    );
    assert_eq!(s, before);
}

struct RestrictedAdministrator {
    state: AuthorityState,
    caller: AuthenticatedCaller,
    outside: GrantSpec,
}
impl RestrictedAdministrator {
    fn new() -> Self {
        let mut state = state();
        let mut scope = administrator(ROOT);
        scope.issuance.as_mut().unwrap().resources =
            CeilingResources::Named([resource(1), authority().resource()].into());
        let caller = enroll(&mut state, scope);
        let mut outside = spec(OPERATOR);
        outside.permissions = [permission("work.execute", resource(2))].into();
        state
            .issue(
                ROOT.principal(),
                ids::ROOT_GRANT,
                ids::OPERATOR_GRANT,
                outside.clone(),
                UnixMillis(3),
            )
            .unwrap();
        Self {
            state,
            caller,
            outside,
        }
    }
}

#[test]
fn credential_ceilings_bound_existing_grant_administration() {
    let w = RestrictedAdministrator::new();
    let expected = revision(&w.state, ids::OPERATOR_GRANT);
    let before = w.state.clone();
    for command in [
        GrantCommand::Issue {
            authorization: ids::ROOT_GRANT,
            id: ids::AGENT_GRANT,
            spec: w.outside.clone(),
        },
        GrantCommand::Revise {
            authorization: ids::ROOT_GRANT,
            id: ids::OPERATOR_GRANT,
            expected,
            spec: spec(OPERATOR),
        },
        GrantCommand::Revoke {
            authorization: ids::ROOT_GRANT,
            id: ids::OPERATOR_GRANT,
            expected,
        },
    ] {
        assert_eq!(
            record(&w.state, &w.caller, command),
            Err(AuthorityError::Denied)
        );
    }
    assert_eq!(w.state, before);
}

#[test]
fn credential_ceilings_bound_credential_administration() {
    let mut w = RestrictedAdministrator::new();
    let (outside, _) = prepare(w.outside, 1);
    let id = outside.id();
    let command = CredentialCommand::Issue {
        authorization: ids::ROOT_GRANT,
        credential: Box::new(outside),
    };
    let before = w.state.clone();
    assert_eq!(
        w.state.record_administration(
            &w.caller,
            AdministrationCommand::Credential(command.clone()),
            UnixMillis(3)
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(w.state, before);
    w.state
        .apply_credential(ROOT.principal(), &command, UnixMillis(3))
        .unwrap();
    let expected = w.state.credential(id).unwrap().revision();
    let before = w.state.clone();
    assert_eq!(
        w.state.record_administration(
            &w.caller,
            AdministrationCommand::Credential(CredentialCommand::Revoke {
                authorization: ids::ROOT_GRANT,
                id,
                expected
            }),
            UnixMillis(3)
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(w.state, before);
}

fn delegation() -> (AuthorityState, GrantSpec, GrantCommand) {
    let mut s = state();
    let parent = Rights::new(authority(), OPERATOR)
        .allow("work.execute", resource(1))
        .delegation_depth(2)
        .build();
    issue(&mut s, ids::OPERATOR_GRANT, parent.clone());
    let command = GrantCommand::Delegate {
        parent: ids::OPERATOR_GRANT,
        id: ids::FRIEND_GRANT,
        spec: spec(FRIEND),
    };
    (s, parent, command)
}

#[test]
fn delegation_requires_credential_depth() {
    let (mut s, _, command) = delegation();
    let insufficient = enroll(&mut s, spec(OPERATOR));
    let before = s.clone();
    assert_eq!(
        record(&s, &insufficient, command),
        Err(AuthorityError::Denied)
    );
    assert_eq!(s, before);
}

#[test]
fn replay_rejects_forged_administration_evidence() {
    let (mut s, parent, command) = delegation();
    let caller = enroll(&mut s, parent);
    let record = record(&s, &caller, command).unwrap();
    struct Tamper {
        change: fn(&mut CallerRecord),
        expected: AuthorityError,
    }
    for case in [
        Tamper {
            change: |r| r.actor = AGENT.principal(),
            expected: AuthorityError::Credential,
        },
        Tamper {
            change: |r| r.credential_revision = r.credential_revision.next().unwrap(),
            expected: AuthorityError::Credential,
        },
        Tamper {
            change: |r| r.generation += 1,
            expected: AuthorityError::Audience,
        },
        Tamper {
            change: |r| r.at = UnixMillis(500),
            expected: AuthorityError::Credential,
        },
    ] {
        let mut forged = record.clone();
        (case.change)(&mut forged.caller);
        let before = s.clone();
        assert_eq!(s.apply_administration(&forged), Err(case.expected));
        assert_eq!(s, before);
    }
}

#[test]
fn administration_records_replay_once() {
    let (mut s, parent, command) = delegation();
    let caller = enroll(&mut s, parent);
    let record = record(&s, &caller, command).unwrap();
    let bytes = serde_ipld_dagcbor::to_vec(&record).unwrap();
    let decoded: AdministrationRecord = serde_ipld_dagcbor::from_slice(&bytes).unwrap();
    assert_eq!(record, decoded);
    s.apply_administration(&decoded).unwrap();
    let before = s.clone();
    assert_eq!(
        s.apply_administration(&decoded),
        Err(AuthorityError::Revision)
    );
    assert_eq!(s, before);
}

#[test]
fn recorded_delegation_revocation_uses_the_parent_authority() {
    let (mut s, parent, command) = delegation();
    let caller = enroll(&mut s, parent);
    let accepted = record(&s, &caller, command).unwrap();
    s.apply_administration(&accepted).unwrap();
    let revoke = s
        .record_administration(
            &caller,
            AdministrationCommand::Grant(GrantCommand::Revoke {
                authorization: ids::OPERATOR_GRANT,
                id: ids::FRIEND_GRANT,
                expected: revision(&s, ids::FRIEND_GRANT),
            }),
            UnixMillis(4),
        )
        .unwrap();
    s.apply_administration(&revoke).unwrap();
    assert!(s.grant(ids::FRIEND_GRANT).unwrap().revoked());
}

#[test]
fn grant_admin_cannot_promote_itself_or_escape_its_ceiling() {
    let mut s = state();
    let id = ids::OPERATOR_GRANT;
    let mut admin = administrator(OPERATOR);
    admin
        .permissions
        .retain(|p| p.operation.as_str() != GRANT_ADMINISTER);
    admin.issuance.as_mut().unwrap().resources =
        CeilingResources::Named([resource(1), authority().resource()].into());
    admin.issuance.as_mut().unwrap().max_validity_ms = 100;
    admin.issuance.as_mut().unwrap().max_delegation_depth = 1;
    issue(&mut s, ids::OPERATOR_GRANT, admin);
    let mut allowed = spec(FRIEND);
    allowed.expires = UnixMillis(90);
    s.issue(
        OPERATOR.principal(),
        id,
        ids::FRIEND_GRANT,
        allowed.clone(),
        UnixMillis(2),
    )
    .unwrap();
    let mut denied = vec![];
    let mut outside = allowed.clone();
    outside.permissions = [permission("work.execute", resource(2))].into();
    denied.push(outside);
    let mut lifetime = allowed.clone();
    lifetime.expires = UnixMillis(103);
    denied.push(lifetime);
    let mut depth = allowed.clone();
    depth.delegation_depth = 2;
    denied.push(depth);
    let mut promote = allowed.clone();
    promote
        .permissions
        .insert(permission(GRANT_ADMINISTER, authority().resource()));
    denied.push(promote);
    let mut latent_admin = allowed;
    latent_admin.issuance = s.grant(id).unwrap().spec().issuance.clone();
    denied.push(latent_admin);
    for spec in denied {
        let before = s.clone();
        assert_eq!(
            s.issue(
                OPERATOR.principal(),
                id,
                ids::AGENT_GRANT,
                spec,
                UnixMillis(2)
            ),
            Err(AuthorityError::Denied)
        );
        assert_eq!(s, before);
    }
    let before = s.clone();
    assert_eq!(
        s.revoke(
            OPERATOR.principal(),
            id,
            ids::ROOT_GRANT,
            Revision(1),
            UnixMillis(2)
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(s, before);
}
