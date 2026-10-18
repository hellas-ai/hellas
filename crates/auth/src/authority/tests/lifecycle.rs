use super::*;

#[test]
fn execution_rights_cannot_issue_grants() {
    let mut s = state();
    issue(&mut s, ids::OPERATOR_GRANT, spec(OPERATOR));
    let before = s.clone();
    assert_eq!(
        s.issue(
            OPERATOR.principal(),
            ids::OPERATOR_GRANT,
            ids::FRIEND_GRANT,
            spec(FRIEND),
            UnixMillis(2)
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(s, before);
}

#[test]
fn foreign_authority_assignments_are_refused() {
    let mut s = state();
    let before = s.clone();
    let mut foreign = spec(FRIEND);
    foreign.authority = AuthorityId(Digest::hash(b"other node"));
    assert_eq!(
        s.issue(
            ROOT.principal(),
            ids::ROOT_GRANT,
            ids::FRIEND_GRANT,
            foreign,
            UnixMillis(1)
        ),
        Err(AuthorityError::Audience)
    );
    assert_eq!(s, before);
}

fn issuer() -> AuthorityState {
    let mut s = state();
    let mut admin = administrator(OPERATOR);
    admin.delegation_depth = 1;
    issue(&mut s, ids::OPERATOR_GRANT, admin);
    for (id, scope) in [
        (ids::FRIEND_GRANT, spec(FRIEND)),
        (ids::AGENT_GRANT, administrator(AGENT)),
    ] {
        s.issue(
            OPERATOR.principal(),
            ids::OPERATOR_GRANT,
            id,
            scope,
            UnixMillis(2),
        )
        .unwrap();
    }
    s
}

#[test]
fn node_assignments_survive_issuer_narrowing() {
    let mut s = issuer();
    let mut admin = s.grant(ids::OPERATOR_GRANT).unwrap().spec().clone();
    admin
        .issuance
        .as_mut()
        .unwrap()
        .operations
        .remove(&operation("work.execute"));
    revise(&mut s, ids::OPERATOR_GRANT, admin, 3).unwrap();
    execute(&s, FRIEND, ids::FRIEND_GRANT, 3).unwrap();
    let before = s.clone();
    assert_eq!(
        s.issue(
            OPERATOR.principal(),
            ids::OPERATOR_GRANT,
            ids::STRANGER_GRANT,
            spec(STRANGER),
            UnixMillis(3)
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(s, before);
}

#[test]
fn node_assignments_survive_issuer_revocation() {
    let mut s = issuer();
    let mut narrowed = s.grant(ids::OPERATOR_GRANT).unwrap().spec().clone();
    narrowed
        .issuance
        .as_mut()
        .unwrap()
        .operations
        .remove(&operation("work.execute"));
    revise(&mut s, ids::OPERATOR_GRANT, narrowed, 3).unwrap();
    revoke(&mut s, ids::OPERATOR_GRANT, 4);
    execute(&s, FRIEND, ids::FRIEND_GRANT, 4).unwrap();
    s.authorize(
        AGENT.principal(),
        ids::AGENT_GRANT,
        &permission(GRANT_ADMINISTER, authority().resource()),
        UnixMillis(4),
    )
    .unwrap();
    assert_eq!(AuthorityState::restore(s.snapshot()).unwrap(), s);
}

#[test]
fn delegated_rights_follow_issuer_revocation() {
    let mut s = issuer();
    s.delegate(
        OPERATOR.principal(),
        ids::OPERATOR_GRANT,
        ids::PROVIDER_GRANT,
        spec(PROVIDER),
        UnixMillis(2),
    )
    .unwrap();
    revoke(&mut s, ids::OPERATOR_GRANT, 3);
    assert_eq!(
        execute(&s, PROVIDER, ids::PROVIDER_GRANT, 3),
        Err(AuthorityError::Revoked)
    );
}

#[test]
fn stale_grant_revisions_are_refused_atomically() {
    let mut s = state();
    issue(&mut s, ids::OPERATOR_GRANT, spec(OPERATOR));
    let before = s.clone();
    let stale = Revision(revision(&s, ids::OPERATOR_GRANT).0 - 1);
    assert_eq!(
        s.revoke(
            ROOT.principal(),
            ids::ROOT_GRANT,
            ids::OPERATOR_GRANT,
            stale,
            UnixMillis(2)
        ),
        Err(AuthorityError::Revision)
    );
    assert_eq!(s, before);
}

#[test]
fn clock_rollback_cannot_revive_expired_access() {
    let mut s = state();
    let mut expired = spec(OPERATOR);
    expired.expires = UnixMillis(5);
    issue(&mut s, ids::OPERATOR_GRANT, expired);
    assert_eq!(
        execute(&s, OPERATOR, ids::OPERATOR_GRANT, 5),
        Err(AuthorityError::Expired)
    );
    s.issue(
        ROOT.principal(),
        ids::ROOT_GRANT,
        ids::FRIEND_GRANT,
        spec(FRIEND),
        UnixMillis(6),
    )
    .unwrap();
    let before = s.clone();
    assert_eq!(
        execute(&s, OPERATOR, ids::OPERATOR_GRANT, 2),
        Err(AuthorityError::Expired)
    );
    assert_eq!(
        s.issue(
            ROOT.principal(),
            ids::ROOT_GRANT,
            ids::AGENT_GRANT,
            spec(AGENT),
            UnixMillis(2)
        ),
        Err(AuthorityError::Clock)
    );
    assert_eq!(s, before);
}

#[test]
fn a_revoked_grant_cannot_be_revised_back_into_use() {
    let mut s = state();
    issue(&mut s, ids::OPERATOR_GRANT, spec(OPERATOR));
    revoke(&mut s, ids::OPERATOR_GRANT, 2);
    let before = s.clone();
    assert_eq!(
        revise(&mut s, ids::OPERATOR_GRANT, spec(OPERATOR), 2),
        Err(AuthorityError::Revoked)
    );
    assert_eq!(s, before);
}

#[test]
fn a_revoked_id_remains_reserved_until_reclamation() {
    let mut s = state();
    issue(&mut s, ids::OPERATOR_GRANT, spec(OPERATOR));
    revoke(&mut s, ids::OPERATOR_GRANT, 2);
    let before = s.clone();
    assert_eq!(
        s.issue(
            ROOT.principal(),
            ids::ROOT_GRANT,
            ids::OPERATOR_GRANT,
            spec(OPERATOR),
            UnixMillis(2)
        ),
        Err(AuthorityError::Duplicate)
    );
    assert_eq!(s, before);
}
