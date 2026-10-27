use super::*;

#[test]
fn documented_operations_match_the_mounted_permission_table() {
    let mut rows = vec![
        "| Required operation | Resource | Mounted service |".to_owned(),
        "| --- | --- | --- |".to_owned(),
    ];
    let mut names = std::collections::BTreeSet::new();
    for op in OPERATIONS {
        assert!(names.insert(op.name));
        OperationId::new(op.name).unwrap();
        let resource = match op.scope {
            Scope::Host => "Host",
            Scope::Machine => "Work machine",
            Scope::Allowance => "Selected allowance",
        };
        let mount = match op.mount {
            Mount::Host => "Host",
            Mount::Machine => "Machine or provider",
            Mount::Work => "Provider",
        };
        rows.push(format!("| `{}` | {} | {} |", op.name, resource, mount));
    }
    let docs = include_str!("../../../../docs/admin.md");
    let documented = docs
        .split_once("<!-- operations:start -->\n")
        .unwrap()
        .1
        .split_once("\n<!-- operations:end -->")
        .unwrap()
        .0;
    assert_eq!(rows.join("\n"), documented);
    let authority = AuthorityId(hellas_auth::Digest::hash(b"operations"));
    assert!(Operation::named("host.unknown").is_err());
    assert!(
        Operation::named(grant_service::WORK_EXECUTE)
            .unwrap()
            .permission(authority, None)
            .is_err()
    );
    assert!(
        Operation::named(node::HOST_STATUS)
            .unwrap()
            .permission(authority, Some(GrantId([1; 16])))
            .is_err()
    );
}
