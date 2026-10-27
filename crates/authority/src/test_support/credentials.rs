use crate::{node::NodeCoordinator, work_store::grant::NodeStore};
use hellas_auth::authority::*;

/// Store tests choose their journal time; service tests keep the checked node API.
pub enum Issuer<'a> {
    Store(&'a mut NodeStore, UnixMillis),
    Node(&'a NodeCoordinator),
}

/// Issue an optional grant and independent credentials with exactly the supplied
/// scope, each held by the subject's own device.
pub async fn issue<const N: usize>(
    mut issuer: Issuer<'_>,
    administrator: &AuthenticatedCaller,
    root: GrantId,
    grant: Option<GrantId>,
    scope: GrantSpec,
) -> [CredentialSecret; N] {
    if let Some(id) = grant {
        let command = GrantCommand::Issue {
            authorization: root,
            id,
            spec: scope.clone(),
        };
        match &mut issuer {
            Issuer::Store(store, now) => {
                store
                    .administer_authority(
                        administrator,
                        AdministrationCommand::Grant(command),
                        *now,
                    )
                    .await
                    .unwrap();
            }
            Issuer::Node(node) => {
                node.grant(administrator, command).await.unwrap();
            }
        }
    }
    let mut credentials = Vec::with_capacity(N);
    for _ in 0..N {
        let secret = match &mut issuer {
            Issuer::Store(store, now) => {
                let (credential, secret) = Credential::prepare(
                    scope.clone(),
                    super::holder(scope.subject),
                    store.state().authority().generation(),
                )
                .unwrap();
                store
                    .administer_authority(
                        administrator,
                        AdministrationCommand::Credential(CredentialCommand::Issue {
                            authorization: root,
                            credential: Box::new(credential),
                        }),
                        *now,
                    )
                    .await
                    .unwrap();
                secret
            }
            Issuer::Node(node) => {
                issue_one(
                    node,
                    administrator,
                    root,
                    scope.clone(),
                    super::holder(scope.subject),
                )
                .await
                .unwrap()
                .1
            }
        };
        credentials.push(secret);
    }
    credentials.try_into().unwrap()
}

/// Prepare on the issuing side, then submit only the verifier through the node API.
pub async fn issue_one(
    node: &NodeCoordinator,
    caller: &AuthenticatedCaller,
    authorization: GrantId,
    scope: GrantSpec,
    holder: CredentialHolder,
) -> Result<(AdministrationRecord, CredentialSecret), crate::work_store::grant::NodeStoreError> {
    let (credential, secret) = Credential::prepare(scope, holder, caller.generation())?;
    let record = node
        .issue_credential(caller, authorization, credential)
        .await?;
    Ok((record, secret))
}
