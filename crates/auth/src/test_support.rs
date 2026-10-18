//! Portable actors and authority builders shared by test fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use crate::{ProducerSigningKey, authority as auth, authority::*};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    Root,
    Operator,
    Friend,
    Agent,
    Provider,
    Stranger,
    RecoveryOwner,
    Successor,
    Attacker,
}
pub mod actors {
    use super::Actor;
    pub const ROOT: Actor = Actor::Root;
    pub const OPERATOR: Actor = Actor::Operator;
    pub const FRIEND: Actor = Actor::Friend;
    pub const AGENT: Actor = Actor::Agent;
    pub const PROVIDER: Actor = Actor::Provider;
    pub const STRANGER: Actor = Actor::Stranger;
    pub const RECOVERY_OWNER: Actor = Actor::RecoveryOwner;
    pub const SUCCESSOR: Actor = Actor::Successor;
    pub const ATTACKER: Actor = Actor::Attacker;
}
impl Actor {
    pub fn key(self) -> ProducerSigningKey {
        let seed = match self {
            Self::Root => 1,
            Self::Operator => 2,
            Self::Friend => 3,
            Self::Agent => 4,
            Self::Provider => 5,
            Self::Stranger => 6,
            Self::RecoveryOwner => 7,
            Self::Successor => 8,
            Self::Attacker => 9,
        };
        ProducerSigningKey::from_secret_bytes([seed; 32]).unwrap()
    }
    pub fn principal(self) -> PrincipalId {
        static PRINCIPALS: [std::sync::OnceLock<PrincipalId>; 9] =
            [const { std::sync::OnceLock::new() }; 9];
        *PRINCIPALS[self as usize]
            .get_or_init(|| PrincipalId::from_public_key(self.key().public_key()).unwrap())
    }
}

pub mod ids {
    use super::GrantId;
    pub const ROOT_GRANT: GrantId = GrantId([1; 16]);
    pub const OPERATOR_GRANT: GrantId = GrantId([2; 16]);
    pub const FRIEND_GRANT: GrantId = GrantId([3; 16]);
    pub const AGENT_GRANT: GrantId = GrantId([4; 16]);
    pub const PROVIDER_GRANT: GrantId = GrantId([5; 16]);
    pub const STRANGER_GRANT: GrantId = GrantId([6; 16]);
    pub const REPLACEMENT: GrantId = GrantId([7; 16]);
    pub const EXECUTION: GrantId = GrantId([8; 16]);
    pub const CANDIDATE: GrantId = GrantId([9; 16]);
    pub const MISSING: GrantId = GrantId([99; 16]);
    /// Disjoint IDs for capacity tests and model slots, never actor identities.
    pub fn slot(index: usize) -> GrantId {
        GrantId((index as u128).to_le_bytes())
    }
}

/// Explicit permission sets with named validity and delegation settings.
pub struct Rights(GrantSpec);
impl Rights {
    pub fn new(authority: AuthorityId, actor: Actor) -> Self {
        Self(GrantSpec {
            authority,
            subject: actor.principal(),
            permissions: Default::default(),
            not_before: UnixMillis(0),
            expires: UnixMillis(500),
            delegation_depth: 0,
            issuance: None,
        })
    }
    pub fn allow(mut self, operation: &str, resource: ResourceId) -> Self {
        self.0.permissions.insert(Permission {
            operation: OperationId::new(operation).unwrap(),
            resource,
        });
        self
    }
    pub fn valid_from(mut self, time: UnixMillis) -> Self {
        self.0.not_before = time;
        self
    }
    pub fn valid_until(mut self, time: UnixMillis) -> Self {
        self.0.expires = time;
        self
    }
    pub fn delegation_depth(mut self, depth: u8) -> Self {
        self.0.delegation_depth = depth;
        self
    }
    pub fn issuance(mut self, ceiling: IssuanceCeiling) -> Self {
        self.0.issuance = Some(ceiling);
        self
    }
    pub fn build(self) -> GrantSpec {
        self.0
    }
}

/// Match the error itself and print it on failure, without requiring Ok: Debug.
#[macro_export]
macro_rules! assert_err {
    ($actual:expr, $expected:pat $(if $guard:expr)? $(,)?) => {
        match $actual {
            Err($expected) $(if $guard)? => {},
            Err(actual) => panic!("expected {}, got {actual:?}", stringify!($expected)),
            Ok(_) => panic!("expected {}, operation succeeded", stringify!($expected)),
        }
    };
}

/// Initial authority grant and issuance scope for authentication fixtures.
pub fn admin_spec(
    authority: auth::AuthorityId,
    subject: auth::PrincipalId,
    extra: &[(&str, auth::ResourceId)],
    validity: (auth::UnixMillis, auth::UnixMillis),
    ceiling: (u64, u8),
    extra_issuance: &[&str],
) -> auth::GrantSpec {
    let permissions: std::collections::BTreeSet<_> = [
        auth::GRANT_ISSUE,
        auth::GRANT_REVOKE,
        auth::GRANT_ADMINISTER,
        auth::CREDENTIAL_ISSUE,
        auth::CREDENTIAL_REVOKE,
    ]
    .into_iter()
    .map(|op| (op, authority.resource()))
    .chain(extra.iter().copied())
    .map(|(op, resource)| auth::Permission {
        operation: auth::OperationId::new(op).unwrap(),
        resource,
    })
    .collect();
    auth::GrantSpec {
        authority,
        subject,
        issuance: Some(auth::IssuanceCeiling {
            operations: permissions
                .iter()
                .map(|p| p.operation.clone())
                .chain(
                    extra_issuance
                        .iter()
                        .map(|op| auth::OperationId::new(*op).unwrap()),
                )
                .collect(),
            resources: auth::CeilingResources::Authority,
            max_validity_ms: ceiling.0,
            max_delegation_depth: ceiling.1,
        }),
        permissions,
        not_before: validity.0,
        expires: validity.1,
        delegation_depth: 0,
    }
}
