//! Pairing and local owner startup share exclusive authority ownership.
use anyhow::{Context, Result, ensure};
use hellas_auth::authority::{
    AuthorityId, CredentialSecret, GrantId, NodeKey, Ownership, PrincipalId, Revision, UnixMillis,
};
use hellas_authority::{
    authenticator::Authenticator,
    work_store::grant::{NodeStore, NodeStoreError, PreparedBootstrap, StartupLock},
};
use hellas_private::StoreLocation;
use hellas_sdk::node_control::{RemoteControlAdmission, bootstrap, profile};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub async fn prepare(
    home: &StoreLocation,
    transport_key: &iroh::SecretKey,
    enrollment: &hellas_rpc::ProviderEnrollmentBundle,
    port: Option<u16>,
    _ownership: &StartupLock,
) -> Result<(Option<iroh::Endpoint>, NodeStore)> {
    let journal = home.child("provider/authority");
    let now = UnixMillis::now()?;
    match NodeStore::open(
        &journal,
        hellas_authority::model::grant::grant_network(),
        Some(enrollment.clone()),
        now,
    )
    .await
    {
        Ok(store) => return Ok((None, store)),
        Err(NodeStoreError::Uninitialized) => {}
        Err(error) => return Err(error.into()),
    }
    prepare_tls(home)?;
    let endpoint = bootstrap::bind_transport(
        transport_key.clone(),
        port,
        RemoteControlAdmission::credential_gated(),
    )
    .await?;
    let invitation = bootstrap::Invitation::create(&endpoint, now)?;
    eprintln!(
        "Waiting for the owner. Copy this invite from the authenticated console and run `hellas pair INVITE`:"
    );
    println!("{}", invitation.encode()?);
    let store = hellas_wire::iroh::close_on_error(
        &endpoint,
        bootstrap::accept(
            &endpoint,
            &invitation,
            &journal,
            hellas_authority::model::grant::grant_network(),
            Some(enrollment.clone()),
        ),
    )
    .await
    .context(
        "owner bootstrap refused or expired; restart explicitly to create a new pairing invitation",
    )?;
    Ok((Some(endpoint), store))
}

fn prepare_tls(home: &StoreLocation) -> Result<()> {
    let root = home.child("provider");
    hellas_private::create_dir_all_durable(&root)?;
    let tls = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    hellas_private::write_atomically(&root.child("control.cert.der"), ".writing", tls.cert.der())?;
    hellas_private::write_atomically(
        &root.child("control.key.der"),
        ".writing",
        &tls.signing_key.serialize_der(),
    )?;
    Ok(())
}

/// Only pending initialization retains its signed approval. Issued credentials
/// live in one binary file shared with the admin profile, including after rebind.
#[derive(Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Startup {
    Pending {
        approval: PreparedBootstrap,
        authorization: GrantId,
        credential: PathBuf,
    },
    Initialized {
        authority: AuthorityId,
        authorization: GrantId,
        credential: PathBuf,
    },
}
impl Startup {
    fn load(home: &StoreLocation) -> Result<Self> {
        let bytes = hellas_private::read_private_bounded(
            hellas_private::open_regular_file(&home.join("provider/startup.json"))?,
            64 * 1024,
        )?;
        serde_json::from_slice(&bytes).context("incompatible or invalid local startup metadata; no automatic migration/reset is supported")
    }
    fn save(&self, home: &StoreLocation) -> Result<()> {
        Ok(hellas_private::write_atomically(
            &home.join("provider/startup.json"),
            ".startup",
            &serde_json::to_vec(self)?,
        )?)
    }
}

async fn pending(
    home: &StoreLocation,
    identity: &crate::identity::LocalIdentity,
    owner: &dyn Authenticator,
) -> Result<Startup> {
    let administrator = super::owner::administrator(owner.public_key()?)?;
    let authorization = GrantId([0; 16]);
    let holder = NodeKey::from_public_key(identity.node_key.public_key())?;
    let (approval, secret) = super::owner::approve(
        owner,
        Ownership::Bootstrap {
            root: authorization,
            target: None,
        },
        &administrator,
        &administrator,
        holder,
    )
    .await?
    .prepare(None)?;
    let credential = PathBuf::from("startup-profile/credential");
    let root = home.child("provider");
    hellas_private::create_dir_all_durable(&root.join("startup-profile"))?;
    // An orphan here is unissued: there is neither authority nor pending approval.
    profile::replace_credential(&root.join(&credential), &secret)?;
    let startup = Startup::Pending {
        approval,
        authorization,
        credential,
    };
    startup.save(home)?;
    Ok(startup)
}

pub(super) struct LocalStartup {
    pub store: NodeStore,
    pub credential: CredentialSecret,
    pub authorization: GrantId,
}

pub(super) async fn prepare_local(
    home: &StoreLocation,
    identity: &crate::identity::LocalIdentity,
    owner: &dyn Authenticator,
    _ownership: &StartupLock,
) -> Result<LocalStartup> {
    let root = home.child("provider");
    let journal = root.child("authority");
    let now = UnixMillis::now()?;
    let existing = match NodeStore::open(
        &journal,
        hellas_authority::model::grant::grant_network(),
        Some(identity.enrollment.clone()),
        now,
    )
    .await
    {
        Ok(store) => Some(store),
        Err(NodeStoreError::Uninitialized) => None,
        Err(error) => return Err(error.into()),
    };
    let startup = if root.join("startup.json").try_exists()? {
        Startup::load(home)?
    } else {
        ensure!(
            existing.is_none(),
            "authority exists without a local startup credential; refusing to replace it"
        );
        pending(home, identity, owner).await?
    };
    let (store, authority, authorization, credential) = match (startup, existing) {
        (Startup::Initialized { .. }, None) => anyhow::bail!(
            "authority journal is missing; refusing to reset initialized runtime state"
        ),
        (
            Startup::Initialized {
                authority,
                authorization,
                credential,
            },
            Some(store),
        ) => (store, authority, authorization, credential),
        (
            Startup::Pending {
                approval,
                authorization,
                credential,
            },
            existing,
        ) => {
            let principal = PrincipalId::from_public_key(hellas_auth::PublicKey::P256(
                owner.public_key()?.to_compressed(),
            ))?;
            ensure!(
                approval.administrator.subject == principal,
                "startup passkey differs from the approved owner"
            );
            let authority = approval.administrator.authority;
            let store = if let Some(store) = existing {
                store
            } else {
                prepare_tls(home)?;
                NodeStore::bootstrap_prepared(
                    &journal,
                    hellas_authority::model::grant::grant_network(),
                    authorization,
                    approval,
                    Some(identity.enrollment.clone()),
                    now,
                )
                .await?
            };
            Startup::Initialized {
                authority,
                authorization,
                credential: credential.clone(),
            }
            .save(home)?;
            (store, authority, authorization, credential)
        }
    };
    ensure!(
        store.state().authority().authority() == authority,
        "startup authority differs from the retained journal"
    );
    let principal = PrincipalId::from_public_key(hellas_auth::PublicKey::P256(
        owner.public_key()?.to_compressed(),
    ))?;
    let state = store.state().authority();
    ensure!(
        state
            .grant(state.root_grant())
            .context("missing owner")?
            .spec()
            .subject
            == principal,
        "startup passkey differs from the authority owner"
    );
    let canonical = root.join(&credential);
    let secret = profile::read_credential(&canonical)?;
    profile::write_local(
        &root.join("startup-profile/profile.json"),
        authority,
        authorization,
        &canonical,
        &root.join("control.cert.der"),
    )?;
    Ok(LocalStartup {
        store,
        credential: secret,
        authorization,
    })
}

/// Explicit operator recovery, including expired-root renewal. Accounting and
/// payment duties remain journaled; old administration is revoked by the normal
/// authority recovery API. Lost credential publication requires another recovery
/// at its newly inspected revision, never an automatic replay or reset.
pub(super) async fn rebind_local(
    home: &StoreLocation,
    identity: &crate::identity::LocalIdentity,
    owner: &dyn Authenticator,
    expected: Revision,
) -> Result<()> {
    let _ownership = StartupLock::acquire(&home.child("provider/authority"))?;
    let Startup::Initialized {
        authority,
        authorization: _,
        credential,
    } = Startup::load(home)?
    else {
        anyhow::bail!("local initialization is pending; finish startup before rebind");
    };
    let scope = super::owner::administrator_for(owner.public_key()?, authority)?;
    let holder = NodeKey::from_public_key(identity.node_key.public_key())?;
    let approval = super::owner::approve(
        owner,
        Ownership::Recover { expected },
        &scope,
        &scope,
        holder,
    )
    .await?;
    let (record, secret) = NodeStore::recover_offline(
        &home.child("provider/authority"),
        hellas_authority::model::grant::grant_network(),
        expected,
        approval,
        UnixMillis::now()?,
    )
    .await?;
    profile::replace_credential(&home.join("provider").join(credential), &secret)
        .with_context(|| format!("recovery committed at revision {}; credential replacement failed; inspect and explicitly recover again", record.revision.0))?;
    println!(
        "{}",
        serde_json::json!({"revision": record.revision.0, "authority": authority, "credential_id": secret.id()})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn startup_ownership_covers_pending_tls_and_open_store() {
        let directory = tempfile::tempdir().unwrap();
        let home = StoreLocation::from_home(directory.path(), hellas_private::Durability::Crash);
        let identity = crate::identity::load_or_create(&home.join("identity")).unwrap();
        let owner = hellas_kernel::SoftPasskey::from_secret_scalar([17; 32]).unwrap();
        let lock = StartupLock::acquire(&home.child("provider/authority")).unwrap();
        assert!(StartupLock::acquire(&home.child("provider/authority")).is_err());
        // This is the durable interrupted-init checkpoint, before any authority.
        pending(&home, &identity, &owner).await.unwrap();
        let credential = std::fs::read(home.join("provider/startup-profile/credential")).unwrap();
        let mut first = prepare_local(&home, &identity, &owner, &lock)
            .await
            .unwrap();
        let metadata = std::fs::read(home.join("provider/startup.json")).unwrap();
        let certificate = std::fs::read(home.join("provider/control.cert.der")).unwrap();
        assert!(StartupLock::acquire(&home.child("provider/authority")).is_err());
        assert_eq!(
            credential,
            std::fs::read(home.join("provider/startup-profile/credential")).unwrap()
        );
        assert_eq!(
            metadata,
            std::fs::read(home.join("provider/startup.json")).unwrap()
        );
        first.store.close().await;
        let mut restarted = prepare_local(&home, &identity, &owner, &lock)
            .await
            .unwrap();
        assert_eq!(first.credential.id(), restarted.credential.id());
        let profile =
            profile::ClientProfile::load(&home.join("provider/startup-profile/profile.json"))
                .unwrap();
        assert_eq!(profile.credential.id(), restarted.credential.id());
        assert_eq!(
            certificate,
            std::fs::read(home.join("provider/control.cert.der")).unwrap()
        );
        restarted.store.close().await;
        let other = hellas_kernel::SoftPasskey::from_secret_scalar([18; 32]).unwrap();
        assert!(
            prepare_local(&home, &identity, &other, &lock)
                .await
                .is_err()
        );
        std::fs::remove_dir_all(home.join("provider/authority")).unwrap();
        let error = prepare_local(&home, &identity, &owner, &lock)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("refusing to reset"));
    }

    #[tokio::test]
    async fn explicit_rebind_renews_expired_root_and_one_canonical_credential() {
        let directory = tempfile::tempdir().unwrap();
        let home = StoreLocation::from_home(directory.path(), hellas_private::Durability::Crash);
        let identity = crate::identity::load_or_create(&home.join("identity")).unwrap();
        let owner = hellas_kernel::SoftPasskey::from_secret_scalar([17; 32]).unwrap();
        let lock = StartupLock::acquire(&home.child("provider/authority")).unwrap();
        let mut scope = super::super::owner::administrator(owner.public_key().unwrap()).unwrap();
        let now = UnixMillis::now().unwrap();
        scope.not_before = UnixMillis(now.0 - 3 * 86400000);
        scope.expires = UnixMillis(now.0 - 86400000);
        let authorization = GrantId([0; 16]);
        let holder = NodeKey::from_public_key(identity.node_key.public_key()).unwrap();
        let (approval, secret) = super::super::owner::approve(
            &owner,
            Ownership::Bootstrap {
                root: authorization,
                target: None,
            },
            &scope,
            &scope,
            holder,
        )
        .await
        .unwrap()
        .prepare(None)
        .unwrap();
        hellas_private::create_dir_all_durable(&home.join("provider/startup-profile")).unwrap();
        let credential = PathBuf::from("startup-profile/credential");
        profile::replace_credential(&home.join("provider").join(&credential), &secret).unwrap();
        prepare_tls(&home).unwrap();
        let mut store = NodeStore::bootstrap_prepared(
            &home.child("provider/authority"),
            hellas_authority::model::grant::grant_network(),
            authorization,
            approval,
            Some(identity.enrollment.clone()),
            UnixMillis(now.0 - 2 * 86400000),
        )
        .await
        .unwrap();
        let expected = store.state().authority().revision();
        store.close().await;
        Startup::Initialized {
            authority: scope.authority,
            authorization,
            credential,
        }
        .save(&home)
        .unwrap();
        drop(lock);
        rebind_local(&home, &identity, &owner, expected)
            .await
            .unwrap();
        let replacement = std::fs::read(home.join("provider/startup-profile/credential")).unwrap();
        assert!(
            rebind_local(&home, &identity, &owner, expected)
                .await
                .is_err()
        );
        assert_eq!(
            replacement,
            std::fs::read(home.join("provider/startup-profile/credential")).unwrap()
        );
        // Fail canonical publication after the recovery commit, then explicitly
        // inspect/recover again. The old credential must never be replayed.
        let credential_path = home.join("provider/startup-profile/credential");
        std::fs::remove_file(&credential_path).unwrap();
        std::fs::create_dir(&credential_path).unwrap();
        let committed = expected.next().unwrap();
        let failure = rebind_local(&home, &identity, &owner, committed)
            .await
            .unwrap_err();
        assert!(failure.to_string().contains("recovery committed"));
        std::fs::remove_dir(&credential_path).unwrap();
        let mut inspection = NodeStore::open(
            &home.child("provider/authority"),
            hellas_authority::model::grant::grant_network(),
            None,
            UnixMillis::now().unwrap(),
        )
        .await
        .unwrap();
        let inspected = inspection.state().authority().revision();
        inspection.close().await;
        assert_eq!(inspected, committed.next().unwrap());
        rebind_local(&home, &identity, &owner, inspected)
            .await
            .unwrap();
        let lock = StartupLock::acquire(&home.child("provider/authority")).unwrap();
        let startup = prepare_local(&home, &identity, &owner, &lock)
            .await
            .unwrap();
        assert_ne!(startup.credential.id(), secret.id());
        assert_eq!(
            startup.store.state().authority().authority(),
            scope.authority
        );
        let node = hellas_authority::node::NodeCoordinator::new(
            startup.store,
            std::sync::Arc::new(move || now),
        );
        let retained_profile =
            profile::ClientProfile::load(&home.join("provider/startup-profile/profile.json"))
                .unwrap();
        assert_eq!(retained_profile.authorization, startup.authorization);
        assert_eq!(retained_profile.credential.id(), startup.credential.id());
        node.authenticate_session(
            &startup.credential,
            hellas_authority::node::SessionKey::Passkey(&owner),
        )
        .await
        .unwrap();
        node.close().await;
    }
}
