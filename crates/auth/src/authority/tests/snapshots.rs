use super::*;

fn delegated_snapshot() -> AuthoritySnapshot {
    let mut s = state();
    let mut parent = spec(OPERATOR);
    parent.delegation_depth = 1;
    issue(&mut s, ids::OPERATOR_GRANT, parent);
    s.delegate(
        OPERATOR.principal(),
        ids::OPERATOR_GRANT,
        ids::FRIEND_GRANT,
        spec(FRIEND),
        UnixMillis(2),
    )
    .unwrap();
    s.snapshot()
}

#[test]
fn structural_snapshot_corruption_is_rejected() {
    let changes: [fn(&mut AuthoritySnapshot); 3] = [
        |s| s.grants.push(s.grants[0].clone()),
        |s| {
            s.grants[2].origin = GrantOrigin::Delegated {
                parent: ids::FRIEND_GRANT,
            }
        },
        |s| s.grants[2].spec.authority = AuthorityId(Digest::hash(b"foreign")),
    ];
    for change in changes {
        let mut snapshot = delegated_snapshot();
        change(&mut snapshot);
        assert_eq!(
            AuthorityState::restore(snapshot),
            Err(AuthorityError::Invalid)
        );
    }
}

#[test]
fn decoding_cannot_introduce_an_invalid_operation_name() {
    let invalid = serde_ipld_dagcbor::to_vec("*").unwrap();
    assert_err!(
        serde_ipld_dagcbor::from_slice::<OperationId>(&invalid),
        serde_ipld_dagcbor::DecodeError::Msg(_)
    );
}
