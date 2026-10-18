use super::*;

fn administrator_with_delegation() -> AuthorityState {
    let mut s = state();
    let mut admin = administrator(OPERATOR);
    admin.delegation_depth = 1;
    issue(&mut s, ids::OPERATOR_GRANT, admin);
    s
}

#[test]
fn a_delegated_issuer_cannot_mint_independent_assignments() {
    let mut s = administrator_with_delegation();
    let mut issuer = spec(FRIEND);
    issuer.permissions = [permission(GRANT_ISSUE, authority().resource())].into();
    issuer.issuance = Some(IssuanceCeiling {
        operations: [operation("work.execute")].into(),
        resources: CeilingResources::Named([resource(1)].into()),
        max_validity_ms: 1000,
        max_delegation_depth: 0,
    });
    s.delegate(
        OPERATOR.principal(),
        ids::OPERATOR_GRANT,
        ids::FRIEND_GRANT,
        issuer,
        UnixMillis(2),
    )
    .unwrap();
    let before = s.clone();
    assert_eq!(
        s.issue(
            FRIEND.principal(),
            ids::FRIEND_GRANT,
            ids::CANDIDATE,
            spec(ATTACKER),
            UnixMillis(2)
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(s, before);
}

#[test]
fn an_administrator_cannot_extend_its_own_administrative_rights() {
    let mut s = administrator_with_delegation();
    let mut renewed = administrator(OPERATOR);
    renewed.expires = UnixMillis(1400);
    let before = s.clone();
    assert_eq!(
        s.issue(
            OPERATOR.principal(),
            ids::OPERATOR_GRANT,
            ids::CANDIDATE,
            renewed.clone(),
            UnixMillis(400)
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(
        s.revise(
            OPERATOR.principal(),
            ids::OPERATOR_GRANT,
            ids::OPERATOR_GRANT,
            revision(&s, ids::OPERATOR_GRANT),
            renewed,
            UnixMillis(400)
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(s, before);
}

#[test]
fn self_assigned_execution_cannot_outlive_the_issuer() {
    let mut s = administrator_with_delegation();
    let mut own = spec(OPERATOR);
    own.expires = UnixMillis(501);
    let before = s.clone();
    assert_eq!(
        s.issue(
            OPERATOR.principal(),
            ids::OPERATOR_GRANT,
            ids::CANDIDATE,
            own,
            UnixMillis(400)
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(s, before);
    s.issue(
        OPERATOR.principal(),
        ids::OPERATOR_GRANT,
        ids::CANDIDATE,
        spec(OPERATOR),
        UnixMillis(400),
    )
    .unwrap();
}

#[test]
fn root_changes_only_through_offline_recovery() {
    let mut s = state();
    issue(&mut s, ids::AGENT_GRANT, administrator(AGENT));
    let mut moved = s.grant(ids::ROOT_GRANT).unwrap().spec().clone();
    moved.subject = ATTACKER.principal();
    for (actor, authorization) in [(AGENT, ids::AGENT_GRANT), (ROOT, ids::ROOT_GRANT)] {
        let before = s.clone();
        assert_eq!(
            s.revoke(
                actor.principal(),
                authorization,
                ids::ROOT_GRANT,
                revision(&s, ids::ROOT_GRANT),
                UnixMillis(2)
            ),
            Err(AuthorityError::Denied)
        );
        assert_eq!(
            s.revise(
                actor.principal(),
                authorization,
                ids::ROOT_GRANT,
                revision(&s, ids::ROOT_GRANT),
                moved.clone(),
                UnixMillis(2)
            ),
            Err(AuthorityError::Denied)
        );
        assert_eq!(s, before);
    }
}

fn delegation_tree() -> AuthorityState {
    let mut s = state();
    let mut parent = spec(OPERATOR);
    parent.delegation_depth = 1;
    issue(&mut s, ids::OPERATOR_GRANT, parent);
    for n in 0..32 {
        s.delegate(
            OPERATOR.principal(),
            ids::OPERATOR_GRANT,
            ids::slot(n),
            spec(FRIEND),
            UnixMillis(2),
        )
        .unwrap();
    }
    s
}
fn fill_table(s: &mut AuthorityState) {
    for index in 0..MAX_GRANTS - s.grants().count() {
        s.issue(
            ROOT.principal(),
            ids::ROOT_GRANT,
            ids::slot(1000 + index),
            spec(PROVIDER),
            UnixMillis(2),
        )
        .unwrap();
    }
}

#[test]
fn thirty_two_live_descendants_fill_the_delegation_capacity() {
    let mut s = delegation_tree();
    let before = s.clone();
    assert_eq!(
        s.delegate(
            OPERATOR.principal(),
            ids::OPERATOR_GRANT,
            ids::CANDIDATE,
            spec(FRIEND),
            UnixMillis(2)
        ),
        Err(AuthorityError::Capacity)
    );
    assert_eq!(s, before);
}

#[test]
fn reclamation_removes_entire_dead_lineages() {
    let mut s = delegation_tree();
    fill_table(&mut s);
    let before = s.clone();
    assert_eq!(
        s.issue(
            ROOT.principal(),
            ids::ROOT_GRANT,
            ids::CANDIDATE,
            spec(STRANGER),
            UnixMillis(3)
        ),
        Err(AuthorityError::Capacity)
    );
    assert_eq!(s, before);
    revoke(&mut s, ids::OPERATOR_GRANT, 3);
    s.issue(
        ROOT.principal(),
        ids::ROOT_GRANT,
        ids::CANDIDATE,
        spec(STRANGER),
        UnixMillis(3),
    )
    .unwrap();
    assert!(s.grant(ids::OPERATOR_GRANT).is_none());
    for child in 0..32 {
        assert!(
            s.grant(ids::slot(child)).is_none(),
            "dead descendant {child} survived reclamation"
        );
    }
    assert_eq!(AuthorityState::restore(s.snapshot()).unwrap(), s);
}

#[test]
fn temporarily_unusable_descendants_still_consume_capacity() {
    enum Dormant {
        Future,
        Narrowed,
    }
    for case in [Dormant::Future, Dormant::Narrowed] {
        let mut s = state();
        let mut parent = spec(OPERATOR);
        parent.delegation_depth = 1;
        parent
            .permissions
            .insert(permission("host.status", resource(1)));
        issue(&mut s, ids::OPERATOR_GRANT, parent.clone());
        let mut child = spec(OPERATOR);
        if matches!(case, Dormant::Future) {
            child.not_before = UnixMillis(100);
        }
        for index in 0..32 {
            s.delegate(
                OPERATOR.principal(),
                ids::OPERATOR_GRANT,
                ids::slot(index),
                child.clone(),
                UnixMillis(2),
            )
            .unwrap();
        }
        if matches!(case, Dormant::Narrowed) {
            parent
                .permissions
                .remove(&permission("work.execute", resource(1)));
            revise(&mut s, ids::OPERATOR_GRANT, parent, 2).unwrap();
            child.permissions = [permission("host.status", resource(1))].into();
        }
        let before = s.clone();
        assert_eq!(
            s.delegate(
                OPERATOR.principal(),
                ids::OPERATOR_GRANT,
                ids::CANDIDATE,
                child,
                UnixMillis(2)
            ),
            Err(AuthorityError::Capacity)
        );
        assert_eq!(s, before);
        s.issue(
            ROOT.principal(),
            ids::ROOT_GRANT,
            ids::CANDIDATE,
            spec(ATTACKER),
            UnixMillis(2),
        )
        .unwrap();
        assert_eq!(AuthorityState::restore(s.snapshot()).unwrap(), s);
    }
}

#[test]
fn revision_exhaustion_does_not_prune_the_grant_table() {
    let mut s = state();
    fill_table(&mut s);
    let mut snapshot = s.snapshot();
    snapshot.revision = Revision(u64::MAX);
    let mut s = AuthorityState::restore(snapshot).unwrap();
    let before = s.clone();
    let mut later = spec(FRIEND);
    later.expires = UnixMillis(900);
    assert_eq!(
        s.issue(
            ROOT.principal(),
            ids::ROOT_GRANT,
            ids::CANDIDATE,
            later,
            UnixMillis(500)
        ),
        Err(AuthorityError::Capacity)
    );
    assert_eq!(
        s, before,
        "an unsuccessful issue must not prune expired grants"
    );
}
