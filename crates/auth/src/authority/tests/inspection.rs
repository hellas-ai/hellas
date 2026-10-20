use super::*;

fn caller(s: &mut AuthorityState, scope: GrantSpec) -> AuthenticatedCaller {
    let secret = credentials::install(s, scope);
    s.authenticate_secret(&secret, SessionKind::Passkey, UnixMillis(3))
        .unwrap()
}

#[test]
fn lost_mutation_reply_can_be_reconciled_after_other_mutations() {
    let mut s = state();
    issue(&mut s, ids::FRIEND_GRANT, spec(FRIEND));
    let caller = caller(&mut s, administrator(ROOT));
    let old = revision(&s, ids::FRIEND_GRANT);
    let command = |expected| {
        AdministrationCommand::Grant(GrantCommand::Revise {
            authorization: ids::ROOT_GRANT,
            id: ids::FRIEND_GRANT,
            expected,
            spec: spec(FRIEND),
        })
    };
    let record = s
        .record_administration(&caller, command(old), UnixMillis(3))
        .unwrap();
    s.apply_administration(&record).unwrap(); // its response is lost
    let committed = s.revision();
    s.issue(
        ROOT.principal(),
        ids::ROOT_GRANT,
        ids::AGENT_GRANT,
        spec(AGENT),
        UnixMillis(3),
    )
    .unwrap();
    assert!(s.revision() > committed);
    assert_eq!(
        s.record_administration(&caller, command(old), UnixMillis(3))
            .unwrap_err(),
        AuthorityError::Revision
    );
    let view = s
        .inspect(
            &caller,
            ids::ROOT_GRANT,
            &InspectionQuery::Grant {
                id: ids::FRIEND_GRANT,
            },
            UnixMillis(3),
        )
        .unwrap();
    let InspectionRecords::Grants { records, .. } = view.records else {
        panic!("grants")
    };
    assert_eq!(records[0].revision(), committed);
    s.record_administration(&caller, command(records[0].revision()), UnixMillis(3))
        .unwrap();
}

#[test]
fn lost_issuance_is_enumerable_without_secret_or_verifier_and_revocation_remains_visible() {
    let mut s = state();
    let caller = caller(&mut s, administrator(ROOT));
    let mut issued = Vec::new();
    for _ in 0..INSPECTION_PAGE_SIZE + 2 {
        let (credential, secret) = prepare(spec(FRIEND), s.generation());
        issued.push(secret.id());
        let record = s
            .record_administration(
                &caller,
                AdministrationCommand::Credential(CredentialCommand::Issue {
                    authorization: ids::ROOT_GRANT,
                    credential: Box::new(credential),
                }),
                UnixMillis(3),
            )
            .unwrap();
        s.apply_administration(&record).unwrap();
    }
    let mut found = Vec::new();
    let mut after = None;
    loop {
        let view = s
            .inspect(
                &caller,
                ids::ROOT_GRANT,
                &InspectionQuery::Credentials { after },
                UnixMillis(3),
            )
            .unwrap();
        let InspectionRecords::Credentials { records, next } = view.records else {
            panic!("credentials")
        };
        assert!(records.len() <= INSPECTION_PAGE_SIZE);
        found.extend(records.into_iter().map(|c| c.id));
        after = next;
        if after.is_none() {
            break;
        }
    }
    assert!(found.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(issued.iter().all(|id| found.contains(id)));
    let record = s
        .record_administration(
            &caller,
            AdministrationCommand::Credential(CredentialCommand::Revoke {
                authorization: ids::ROOT_GRANT,
                id: issued[0],
                expected: Revision(1),
            }),
            UnixMillis(3),
        )
        .unwrap();
    s.apply_administration(&record).unwrap();
    let view = s
        .inspect(
            &caller,
            ids::ROOT_GRANT,
            &InspectionQuery::Credential { id: issued[0] },
            UnixMillis(3),
        )
        .unwrap();
    let InspectionRecords::Credentials { records, .. } = view.records else {
        panic!("credentials")
    };
    assert!(records[0].revoked);
    assert_eq!(records[0].revision, Revision(2));
}

#[test]
fn both_credential_and_selected_grant_bound_inspection_and_stale_revision_disclosure() {
    let mut s = state();
    let mut outside = spec(FRIEND);
    outside.permissions = [permission("work.execute", resource(2))].into();
    issue(&mut s, ids::FRIEND_GRANT, outside.clone());
    let mut narrow = administrator(OPERATOR);
    narrow.issuance.as_mut().unwrap().resources =
        CeilingResources::Named([resource(1), authority().resource()].into());
    issue(&mut s, ids::OPERATOR_GRANT, narrow.clone());
    let caller = caller(&mut s, administrator(OPERATOR));
    for id in [ids::FRIEND_GRANT, ids::CANDIDATE] {
        assert_eq!(
            s.inspect(
                &caller,
                ids::OPERATOR_GRANT,
                &InspectionQuery::Grant { id },
                UnixMillis(3)
            )
            .unwrap_err(),
            AuthorityError::Denied
        );
    }
    let view = s
        .inspect(
            &caller,
            ids::OPERATOR_GRANT,
            &InspectionQuery::Grants { after: None },
            UnixMillis(3),
        )
        .unwrap();
    let InspectionRecords::Grants { records, .. } = view.records else {
        panic!("grants")
    };
    assert!(!records.iter().any(|g| g.id() == ids::FRIEND_GRANT));
    for command in [
        GrantCommand::Revoke {
            authorization: ids::OPERATOR_GRANT,
            id: ids::FRIEND_GRANT,
            expected: Revision(999),
        },
        GrantCommand::Revise {
            authorization: ids::OPERATOR_GRANT,
            id: ids::FRIEND_GRANT,
            expected: Revision(999),
            spec: spec(FRIEND),
        },
    ] {
        assert_eq!(
            s.record_administration(
                &caller,
                AdministrationCommand::Grant(command),
                UnixMillis(3)
            )
            .unwrap_err(),
            AuthorityError::Denied
        );
    }
    let (credential, secret) = prepare(outside.clone(), s.generation());
    s.apply_credential(
        ROOT.principal(),
        &CredentialCommand::Issue {
            authorization: ids::ROOT_GRANT,
            credential: Box::new(credential),
        },
        UnixMillis(3),
    )
    .unwrap();
    assert_eq!(
        s.record_administration(
            &caller,
            AdministrationCommand::Credential(CredentialCommand::Revoke {
                authorization: ids::OPERATOR_GRANT,
                id: secret.id(),
                expected: Revision(999),
            }),
            UnixMillis(3)
        )
        .unwrap_err(),
        AuthorityError::Denied
    );

    // A broad grant cannot widen a narrowed credential either.
    let mut s = state();
    issue(&mut s, ids::FRIEND_GRANT, outside);
    let mut narrow = administrator(ROOT);
    narrow.issuance.as_mut().unwrap().resources =
        CeilingResources::Named([resource(1), authority().resource()].into());
    let caller = self::caller(&mut s, narrow);
    assert_eq!(
        s.inspect(
            &caller,
            ids::ROOT_GRANT,
            &InspectionQuery::Grant {
                id: ids::FRIEND_GRANT
            },
            UnixMillis(3)
        )
        .unwrap_err(),
        AuthorityError::Denied
    );
    let secret = credentials::install(&mut s, spec(STRANGER));
    let stranger = s
        .authenticate_secret(&secret, SessionKind::Passkey, UnixMillis(3))
        .unwrap();
    assert_eq!(
        s.inspect(
            &stranger,
            ids::ROOT_GRANT,
            &InspectionQuery::Grants { after: None },
            UnixMillis(3)
        )
        .unwrap_err(),
        AuthorityError::Denied
    );
}
