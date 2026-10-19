use super::*;

fn parent(depth: u8) -> AuthorityState {
    let mut s = state();
    let scope = Rights::new(authority(), OPERATOR)
        .allow("work.execute", resource(1))
        .delegation_depth(depth)
        .build();
    issue(&mut s, ids::OPERATOR_GRANT, scope);
    s
}
fn delegate(s: &mut AuthorityState, scope: GrantSpec) -> Result<(), AuthorityError> {
    s.delegate(
        OPERATOR.principal(),
        ids::OPERATOR_GRANT,
        ids::FRIEND_GRANT,
        scope,
        UnixMillis(2),
    )
}

#[test]
fn delegation_only_attenuates_the_parent_scope() {
    let changes: [fn(&mut GrantSpec); 5] = [
        |s| s.permissions = [permission("work.execute", resource(2))].into(),
        |s| s.permissions = [permission("host.status", resource(1))].into(),
        |s| s.expires = UnixMillis(501),
        |s| s.delegation_depth = 1,
        |s| s.issuance = administrator(FRIEND).issuance,
    ];
    for change in changes {
        let mut s = parent(1);
        let before = s.clone();
        let mut scope = spec(FRIEND);
        change(&mut scope);
        assert_eq!(delegate(&mut s, scope), Err(AuthorityError::Denied));
        assert_eq!(s, before);
    }
}

#[test]
fn a_child_cannot_begin_before_its_parent() {
    let mut s = parent(1);
    let mut scope = s.grant(ids::OPERATOR_GRANT).unwrap().spec().clone();
    scope.not_before = UnixMillis(1);
    revise(&mut s, ids::OPERATOR_GRANT, scope, 1).unwrap();
    let before = s.clone();
    assert_eq!(delegate(&mut s, spec(FRIEND)), Err(AuthorityError::Denied));
    assert_eq!(s, before);
}

#[test]
fn delegation_depth_nine_is_invalid() {
    let mut s = state();
    let before = s.clone();
    let scope = Rights::new(authority(), FRIEND)
        .allow("work.execute", resource(1))
        .delegation_depth(9)
        .build();
    assert_eq!(
        s.issue(
            ROOT.principal(),
            ids::ROOT_GRANT,
            ids::FRIEND_GRANT,
            scope,
            UnixMillis(1)
        ),
        Err(AuthorityError::Invalid)
    );
    assert_eq!(s, before);
}

#[test]
fn an_issuance_ceiling_cannot_allow_depth_nine() {
    let mut s = state();
    let before = s.clone();
    let mut scope = administrator(FRIEND);
    scope.issuance.as_mut().unwrap().max_delegation_depth = 9;
    assert_eq!(
        s.issue(
            ROOT.principal(),
            ids::ROOT_GRANT,
            ids::FRIEND_GRANT,
            scope,
            UnixMillis(1)
        ),
        Err(AuthorityError::Invalid)
    );
    assert_eq!(s, before);
}

fn eight_delegation_chain() -> AuthorityState {
    let mut s = parent(8);
    for depth in 0..8 {
        let (actor, parent) = if depth == 0 {
            (OPERATOR, ids::OPERATOR_GRANT)
        } else {
            (FRIEND, ids::slot(depth - 1))
        };
        let mut child = spec(FRIEND);
        child.delegation_depth = 7 - depth as u8;
        s.delegate(
            actor.principal(),
            parent,
            ids::slot(depth),
            child,
            UnixMillis(2),
        )
        .unwrap();
    }
    s
}

#[test]
fn eight_delegations_exhaust_the_depth_budget() {
    let mut s = eight_delegation_chain();
    assert_eq!(execute(&s, FRIEND, ids::slot(7), 2).unwrap().len(), 9);
    let before = s.clone();
    assert_eq!(
        s.delegate(
            FRIEND.principal(),
            ids::slot(7),
            ids::slot(8),
            spec(AGENT),
            UnixMillis(2)
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(s, before);
}

#[test]
fn delegation_cannot_replace_an_existing_id() {
    let mut s = parent(1);
    let before = s.clone();
    assert_eq!(
        s.delegate(
            OPERATOR.principal(),
            ids::OPERATOR_GRANT,
            ids::OPERATOR_GRANT,
            spec(FRIEND),
            UnixMillis(2)
        ),
        Err(AuthorityError::Duplicate)
    );
    assert_eq!(s, before);
}

#[test]
fn authorization_returns_the_current_lineage_revisions() {
    let mut s = parent(1);
    delegate(&mut s, spec(FRIEND)).unwrap();
    assert_eq!(
        execute(&s, FRIEND, ids::FRIEND_GRANT, 2).unwrap(),
        vec![
            (ids::FRIEND_GRANT, revision(&s, ids::FRIEND_GRANT)),
            (ids::OPERATOR_GRANT, revision(&s, ids::OPERATOR_GRANT))
        ]
    );
}

#[test]
fn parent_narrowing_disables_descendants_without_corrupting_history() {
    let mut s = eight_delegation_chain();
    revise(&mut s, ids::OPERATOR_GRANT, spec(OPERATOR), 3).unwrap();
    assert_eq!(
        execute(&s, FRIEND, ids::slot(7), 3),
        Err(AuthorityError::Denied)
    );
    assert_eq!(AuthorityState::restore(s.snapshot()).unwrap(), s);
}

#[test]
fn a_revision_preserves_the_delegation_parent() {
    let mut s = parent(1);
    delegate(&mut s, spec(FRIEND)).unwrap();
    let mut narrower = spec(FRIEND);
    narrower.expires = UnixMillis(400);
    revise(&mut s, ids::FRIEND_GRANT, narrower, 3).unwrap();
    assert_eq!(
        s.grant(ids::FRIEND_GRANT).unwrap().origin(),
        GrantOrigin::Delegated {
            parent: ids::OPERATOR_GRANT
        }
    );
}

#[test]
fn a_descendant_cannot_revise_its_ancestor() {
    let mut s = state();
    let mut parent = administrator(OPERATOR);
    parent.delegation_depth = 2;
    issue(&mut s, ids::OPERATOR_GRANT, parent.clone());
    let mut child = administrator(FRIEND);
    child.delegation_depth = 1;
    delegate(&mut s, child).unwrap();
    let before = s.clone();
    assert_eq!(
        s.revise(
            FRIEND.principal(),
            ids::FRIEND_GRANT,
            ids::OPERATOR_GRANT,
            revision(&s, ids::OPERATOR_GRANT),
            parent,
            UnixMillis(3)
        ),
        Err(AuthorityError::Denied)
    );
    assert_eq!(s, before);
}

#[test]
fn restoring_a_two_node_cycle_is_refused() {
    let mut s = parent(1);
    delegate(&mut s, spec(FRIEND)).unwrap();
    // Revision has no parent field; exercise a forged durable origin separately.
    let mut snapshot = s.snapshot();
    snapshot
        .grants
        .iter_mut()
        .find(|g| g.id == ids::OPERATOR_GRANT)
        .unwrap()
        .origin = GrantOrigin::Delegated {
        parent: ids::FRIEND_GRANT,
    };
    assert_eq!(
        AuthorityState::restore(snapshot),
        Err(AuthorityError::Invalid)
    );
}
