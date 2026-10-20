//! Proof of possession for ownership changes: nobody can bootstrap or
//! recover an authority administered by someone else's passkey.
use super::*;
use crate::{Digest, hash_tuple};

/// The ownership change an owner approves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ownership {
    /// A new authority whose administrator grant is `root`.
    Bootstrap {
        root: GrantId,
        /// Remote machine transport pin; absent only for offline creation.
        target: Option<[u8; 32]>,
    },
    /// A new administrator for the authority at exactly revision `expected`.
    Recover { expected: Revision },
}

/// The challenge the administrator's passkey signs. It commits to the
/// administrator grant, the initial credential's scope and the node key that
/// will hold that credential. Remote bootstrap also commits to the machine pin.
pub fn ownership_digest(
    ownership: Ownership,
    administrator: &GrantSpec,
    credential: &GrantSpec,
    holder: NodeKey,
) -> Digest {
    let admin = administrator.commitment();
    let credential = credential.commitment();
    match ownership {
        Ownership::Bootstrap { root, target } => hash_tuple(
            "hellas.auth.bootstrap.v3",
            &[
                &root.0,
                target.as_ref().map_or(&[][..], |id| id.as_slice()),
                admin.as_bytes(),
                credential.as_bytes(),
                holder.as_bytes(),
            ],
        ),
        Ownership::Recover { expected } => hash_tuple(
            "hellas.auth.recovery.v2",
            &[
                &expected.0.to_be_bytes(),
                admin.as_bytes(),
                credential.as_bytes(),
                holder.as_bytes(),
            ],
        ),
    }
}

impl GrantSpec {
    /// Every field, unambiguously: `hash_tuple` length-prefixes each element
    /// and each nested tuple has a fixed arity.
    pub(super) fn commitment(&self) -> Digest {
        let permissions: Vec<&[u8]> = self
            .permissions
            .iter()
            .flat_map(|p| [p.operation.as_str().as_bytes(), p.resource.0.as_bytes()])
            .collect();
        let issuance = self.issuance.as_ref().map(|ceiling| {
            let operations: Vec<&[u8]> = ceiling
                .operations
                .iter()
                .map(|op| op.as_str().as_bytes())
                .collect();
            let resources = match &ceiling.resources {
                CeilingResources::Authority => hash_tuple("hellas.auth.ceiling.authority.v1", &[]),
                CeilingResources::Named(ids) => hash_tuple(
                    "hellas.auth.ceiling.named.v1",
                    &ids.iter()
                        .map(|id| id.0.as_bytes().as_slice())
                        .collect::<Vec<_>>(),
                ),
            };
            hash_tuple(
                "hellas.auth.ceiling.v1",
                &[
                    hash_tuple("hellas.auth.ceiling.operations.v1", &operations).as_bytes(),
                    resources.as_bytes(),
                    &ceiling.max_validity_ms.to_be_bytes(),
                    &[ceiling.max_delegation_depth],
                ],
            )
        });
        let subject = self.subject.public_key();
        hash_tuple(
            "hellas.auth.grant-spec.v2",
            &[
                self.authority.0.as_bytes(),
                &[subject.kind().to_byte()],
                subject.bytes(),
                hash_tuple("hellas.auth.permissions.v1", &permissions).as_bytes(),
                &self.not_before.0.to_be_bytes(),
                &self.expires.0.to_be_bytes(),
                &[self.delegation_depth],
                issuance
                    .as_ref()
                    .map_or(&[][..], |digest| digest.as_bytes()),
            ],
        )
    }
}
