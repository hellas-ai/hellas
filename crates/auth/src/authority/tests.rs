use super::*;
use crate::test_support::{Actor, Rights, actors::*, ids};
use crate::{Digest, PublicKey, assert_err};
mod administration;
mod credentials;
mod delegation;
mod escalation;
mod identity;
mod lifecycle;
mod recovery;
mod sessions;
mod snapshots;

fn resource(n: u8) -> ResourceId {
    ResourceId(Digest::hash(&[n]))
}
fn authority() -> AuthorityId {
    AuthorityId(Digest::hash(b"node"))
}
fn operation(s: &str) -> OperationId {
    OperationId::new(s).unwrap()
}
fn permission(s: &str, resource: ResourceId) -> Permission {
    Permission {
        operation: operation(s),
        resource,
    }
}

const ACTORS: [Actor; 9] = [
    ROOT,
    OPERATOR,
    FRIEND,
    AGENT,
    PROVIDER,
    STRANGER,
    RECOVERY_OWNER,
    SUCCESSOR,
    ATTACKER,
];

fn actor(subject: PrincipalId) -> Actor {
    ACTORS
        .into_iter()
        .find(|actor| actor.principal() == subject)
        .unwrap()
}

/// A credential held by its own subject's device.
fn prepare(scope: GrantSpec, generation: u64) -> (Credential, CredentialSecret) {
    let holder = actor(scope.subject).holder();
    Credential::prepare(scope, holder, generation).unwrap()
}

/// Bootstrap with the administrator's own proof of possession.
fn bootstrap(
    id: GrantId,
    admin: GrantSpec,
    credential: Credential,
    now: UnixMillis,
) -> Result<AuthorityState, AuthorityError> {
    let CredentialHolder::Node(holder) = credential.holder() else {
        return Err(AuthorityError::Invalid);
    };
    let owner = actor(admin.subject).assert(ownership_digest(
        Ownership::Bootstrap { root: id },
        &admin,
        credential.scope(),
        holder,
    ));
    AuthorityState::bootstrap(id, admin, credential, &owner, now)
}

/// Recovery approved by the new administrator's own passkey.
fn recovery(
    s: &AuthorityState,
    administrator: GrantSpec,
    credential: Credential,
    revoke: std::collections::BTreeSet<GrantId>,
) -> RecoveryCommand {
    let CredentialHolder::Node(holder) = credential.holder() else {
        panic!("recovery credentials are device-held");
    };
    let expected = s.revision();
    let owner = actor(administrator.subject).assert(ownership_digest(
        Ownership::Recover { expected },
        &administrator,
        credential.scope(),
        holder,
    ));
    RecoveryCommand {
        credential,
        expected,
        administrator,
        revoke,
        owner,
    }
}

fn spec(subject: Actor) -> GrantSpec {
    Rights::new(authority(), subject)
        .allow("work.execute", resource(1))
        .build()
}

fn administrator(subject: Actor) -> GrantSpec {
    let mut s = spec(subject);
    s.permissions.extend(
        [
            GRANT_ISSUE,
            GRANT_REVOKE,
            GRANT_ADMINISTER,
            CREDENTIAL_ISSUE,
            CREDENTIAL_REVOKE,
        ]
        .map(|op| permission(op, authority().resource())),
    );
    s.issuance = Some(IssuanceCeiling {
        operations: [
            GRANT_ISSUE,
            GRANT_REVOKE,
            GRANT_ADMINISTER,
            CREDENTIAL_ISSUE,
            CREDENTIAL_REVOKE,
            "work.execute",
            "host.status",
            GATEWAY_INVOKE,
        ]
        .map(operation)
        .into(),
        resources: CeilingResources::Authority,
        max_validity_ms: 1000,
        max_delegation_depth: 8,
    });
    s
}

fn state() -> AuthorityState {
    let mut root = administrator(ROOT);
    root.expires = UnixMillis(1000);
    root.permissions
        .retain(|p| p.operation.as_str() != "work.execute");
    bootstrap(
        ids::ROOT_GRANT,
        root.clone(),
        prepare(root, 1).0,
        UnixMillis(0),
    )
    .unwrap()
}

fn revision(state: &AuthorityState, id: GrantId) -> Revision {
    state.grant(id).unwrap().revision()
}

fn issue(state: &mut AuthorityState, id: GrantId, spec: GrantSpec) {
    state
        .issue(ROOT.principal(), ids::ROOT_GRANT, id, spec, UnixMillis(1))
        .unwrap();
}

fn execute(
    s: &AuthorityState,
    actor: Actor,
    id: GrantId,
    at: u64,
) -> Result<Vec<(GrantId, Revision)>, AuthorityError> {
    s.authorize(
        actor.principal(),
        id,
        &permission("work.execute", resource(1)),
        UnixMillis(at),
    )
}
fn revise(
    s: &mut AuthorityState,
    id: GrantId,
    spec: GrantSpec,
    at: u64,
) -> Result<(), AuthorityError> {
    s.revise(
        ROOT.principal(),
        ids::ROOT_GRANT,
        id,
        revision(s, id),
        spec,
        UnixMillis(at),
    )
}
fn revoke(s: &mut AuthorityState, id: GrantId, at: u64) {
    s.revoke(
        ROOT.principal(),
        ids::ROOT_GRANT,
        id,
        revision(s, id),
        UnixMillis(at),
    )
    .unwrap();
}
