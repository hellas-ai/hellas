use super::*;

pub(super) fn command(s: &AuthorityState, owner: Actor) -> RecoveryCommand {
    RecoveryCommand {
        credential: Credential::prepare(administrator(owner), s.generation() + 1)
            .unwrap()
            .0,
        expected: s.revision(),
        administrator: administrator(owner),
        revoke: Default::default(),
    }
}

fn mixed_recovery_lineages() -> AuthorityState {
    let mut root = administrator(ROOT);
    root.delegation_depth = 1;
    let mut s = AuthorityState::bootstrap(
        ids::ROOT_GRANT,
        root.clone(),
        Credential::prepare(root, 1).unwrap().0,
        UnixMillis(0),
    )
    .unwrap();
    let mut admin = administrator(OPERATOR);
    admin.delegation_depth = 1;
    issue(&mut s, ids::OPERATOR_GRANT, admin);
    s.issue(
        OPERATOR.principal(),
        ids::OPERATOR_GRANT,
        ids::FRIEND_GRANT,
        spec(FRIEND),
        UnixMillis(2),
    )
    .unwrap();
    s.delegate(
        OPERATOR.principal(),
        ids::OPERATOR_GRANT,
        ids::AGENT_GRANT,
        spec(AGENT),
        UnixMillis(2),
    )
    .unwrap();
    s.delegate(
        ROOT.principal(),
        ids::ROOT_GRANT,
        ids::PROVIDER_GRANT,
        spec(PROVIDER),
        UnixMillis(2),
    )
    .unwrap();
    let mut service_admin = spec(STRANGER);
    service_admin.permissions = [permission("host.status", resource(1))].into();
    s.issue(
        ROOT.principal(),
        ids::ROOT_GRANT,
        ids::STRANGER_GRANT,
        service_admin,
        UnixMillis(2),
    )
    .unwrap();
    s
}

#[test]
fn recovery_keeps_independent_execution_but_invalidates_all_administrative_lineages() {
    let mut s = mixed_recovery_lineages();
    let retained = s.grant(ids::FRIEND_GRANT).unwrap().clone();
    let mut recover = command(&s, RECOVERY_OWNER);
    recover.revoke.insert(ids::STRANGER_GRANT);
    s.recover(&recover, UnixMillis(3)).unwrap();
    assert_eq!(s.generation(), 2);
    assert_eq!(s.grant(ids::FRIEND_GRANT), Some(&retained));
    s.authorize(
        FRIEND.principal(),
        retained.id(),
        &permission("work.execute", resource(1)),
        UnixMillis(3),
    )
    .unwrap();
    for (actor, id) in [
        (OPERATOR, ids::OPERATOR_GRANT),
        (AGENT, ids::AGENT_GRANT),
        (PROVIDER, ids::PROVIDER_GRANT),
        (STRANGER, ids::STRANGER_GRANT),
    ] {
        assert_eq!(
            s.authorize(
                actor.principal(),
                id,
                &permission("work.execute", resource(1)),
                UnixMillis(3)
            ),
            Err(AuthorityError::Revoked)
        );
    }
    assert_eq!(
        s.authorize(
            ROOT.principal(),
            ids::ROOT_GRANT,
            &permission(GRANT_ISSUE, authority().resource()),
            UnixMillis(3)
        ),
        Err(AuthorityError::Denied)
    );
    let audit = s.last_recovery().unwrap();
    assert_eq!(audit.previous_administrator, ROOT.principal());
    assert_eq!(audit.administrator, RECOVERY_OWNER.principal());
    assert_eq!(
        audit.revoked,
        [
            ids::ROOT_GRANT,
            ids::OPERATOR_GRANT,
            ids::PROVIDER_GRANT,
            ids::STRANGER_GRANT
        ]
        .into()
    );
    s.issue(
        RECOVERY_OWNER.principal(),
        ids::ROOT_GRANT,
        ids::EXECUTION,
        spec(SUCCESSOR),
        UnixMillis(4),
    )
    .unwrap();
    let encoded = serde_ipld_dagcbor::to_vec(&s.snapshot()).unwrap();
    assert_eq!(
        AuthorityState::restore(serde_ipld_dagcbor::from_slice(&encoded).unwrap()).unwrap(),
        s
    );
}

#[test]
fn recovery_works_at_full_grant_capacity() {
    let mut s = state();
    for n in 0..MAX_GRANTS - 1 {
        s.issue(
            ROOT.principal(),
            ids::ROOT_GRANT,
            ids::slot(n),
            spec(OPERATOR),
            UnixMillis(1),
        )
        .unwrap();
    }
    assert_eq!(s.grants().count(), MAX_GRANTS);
    s.recover(&command(&s, FRIEND), UnixMillis(3)).unwrap();
    assert_eq!(s.grants().count(), MAX_GRANTS);
    assert_eq!(s.grant(ids::ROOT_GRANT).unwrap().revision(), s.revision());
    assert_eq!(s.generation(), 2);
    s.recover(&command(&s, AGENT), UnixMillis(4)).unwrap();
    assert_eq!(s.grants().count(), MAX_GRANTS);
    assert_eq!(s.grant(ids::ROOT_GRANT).unwrap().revision(), s.revision());
    assert_eq!(s.generation(), 3);
    s.authorize(
        AGENT.principal(),
        ids::ROOT_GRANT,
        &permission(GRANT_ISSUE, authority().resource()),
        UnixMillis(4),
    )
    .unwrap();
    assert_eq!(AuthorityState::restore(s.snapshot()).unwrap(), s);
}

#[test]
fn invalid_recovery_is_atomic() {
    let mut s = state();
    issue(&mut s, ids::OPERATOR_GRANT, administrator(OPERATOR));
    let mut wrong_authority = command(&s, FRIEND);
    wrong_authority.administrator.authority = AuthorityId(Digest::hash(b"elsewhere"));
    let mut not_admin = command(&s, FRIEND);
    not_admin.administrator = spec(FRIEND);
    let mut unknown = command(&s, FRIEND);
    unknown.revoke.insert(ids::MISSING);
    let mut stale = command(&s, FRIEND);
    stale.expected = Revision(1);
    for (command, expected) in [
        (wrong_authority, AuthorityError::Audience),
        (not_admin, AuthorityError::Invalid),
        (unknown, AuthorityError::Missing),
        (stale, AuthorityError::Revision),
    ] {
        let before = s.clone();
        assert_eq!(s.recover(&command, UnixMillis(2)), Err(expected));
        assert_eq!(s, before);
    }
    let before = s.clone();
    assert_eq!(
        s.recover(&command(&s, FRIEND), UnixMillis(0)),
        Err(AuthorityError::Clock)
    );
    assert_eq!(s, before);
}

#[test]
fn recovery_revision_overflow_is_atomic() {
    let s = state();
    let mut snapshot = s.snapshot();
    snapshot.revision = Revision(u64::MAX);
    let mut full = AuthorityState::restore(snapshot).unwrap();
    let before = full.clone();
    assert_eq!(
        full.recover(&command(&full, FRIEND), UnixMillis(2)),
        Err(AuthorityError::Capacity)
    );
    assert_eq!(full, before);
}

#[test]
fn malformed_recovery_receipts_are_refused_on_restore() {
    let mut s = state();
    issue(&mut s, ids::OPERATOR_GRANT, administrator(OPERATOR));
    s.recover(&command(&s, FRIEND), UnixMillis(2)).unwrap();
    let mut no_epoch = s.snapshot();
    no_epoch.generation = 0;
    let mut no_receipt = s.snapshot();
    no_receipt.last_recovery = None;
    let mut wrong_epoch = s.snapshot();
    wrong_epoch.last_recovery.as_mut().unwrap().generation += 1;
    let mut missing_root = s.snapshot();
    missing_root.root_grant = ids::MISSING;
    let mut revived = s.snapshot();
    revived
        .grants
        .iter_mut()
        .find(|g| g.id == ids::OPERATOR_GRANT)
        .unwrap()
        .revoked = false;
    for invalid in [no_epoch, no_receipt, wrong_epoch, missing_root, revived] {
        assert_eq!(
            AuthorityState::restore(invalid),
            Err(AuthorityError::Invalid)
        );
    }
}

#[test]
fn recovery_receipts_survive_id_reclamation() {
    let mut s = state();
    let reused = ids::OPERATOR_GRANT;
    issue(&mut s, ids::OPERATOR_GRANT, administrator(OPERATOR));
    issue(&mut s, ids::AGENT_GRANT, administrator(AGENT));
    s.recover(&command(&s, FRIEND), UnixMillis(2)).unwrap();
    let receipt = s.last_recovery().unwrap().clone();
    for n in 0..MAX_GRANTS - 3 {
        s.issue(
            FRIEND.principal(),
            ids::ROOT_GRANT,
            ids::slot(n),
            spec(PROVIDER),
            UnixMillis(2),
        )
        .unwrap();
    }
    assert_eq!(s.grants().count(), MAX_GRANTS);
    s.issue(
        FRIEND.principal(),
        ids::ROOT_GRANT,
        ids::EXECUTION,
        spec(SUCCESSOR),
        UnixMillis(2),
    )
    .unwrap();
    assert!(s.grant(reused).is_none());
    assert_eq!(AuthorityState::restore(s.snapshot()).unwrap(), s);
    s.issue(
        FRIEND.principal(),
        ids::ROOT_GRANT,
        reused,
        spec(OPERATOR),
        UnixMillis(2),
    )
    .unwrap();
    assert!(revision(&s, reused) > receipt.revision);
    let bytes = serde_ipld_dagcbor::to_vec(&s.snapshot()).unwrap();
    let restored =
        AuthorityState::restore(serde_ipld_dagcbor::from_slice(&bytes).unwrap()).unwrap();
    assert_eq!(restored, s);
    assert_eq!(restored.last_recovery(), Some(&receipt));
    assert_eq!(
        s.revoke(
            FRIEND.principal(),
            ids::ROOT_GRANT,
            reused,
            receipt.revision,
            UnixMillis(2)
        ),
        Err(AuthorityError::Revision),
    );
}
