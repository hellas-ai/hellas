//! Normal node startup: an uninitialized node waits for its owner to pair.
use anyhow::{Context, Result, ensure};
use hellas_auth::authority::{
    CredentialId, CredentialSecret, GrantId, Ownership, ownership_digest,
};
use hellas_auth::authority::{NodeKey, PrincipalId};
use hellas_authority::authenticator::Authenticator;
use hellas_authority::work_store::grant::{
    NodeStore, NodeStoreError, OwnerApproval, PreparedBootstrap,
};
use serde::{Deserialize, Serialize};

use hellas_private::StoreLocation;
use hellas_sdk::node_control::{RemoteControlAdmission, bootstrap};

pub async fn prepare(
    home: &StoreLocation,
    transport_key: &iroh::SecretKey,
    enrollment: &hellas_rpc::ProviderEnrollmentBundle,
    port: Option<u16>,
) -> Result<Option<iroh::Endpoint>> {
    let root = home.child("provider");
    let journal = root.child("authority");
    let remote_control = RemoteControlAdmission::credential_gated();
    let now = hellas_auth::authority::UnixMillis::now()?;
    match hellas_authority::work_store::grant::NodeStore::open(
        &journal,
        hellas_authority::model::grant::grant_network(),
        Some(enrollment.clone()),
        now,
    )
    .await
    {
        Ok(mut store) => {
            store.close().await;
            return Ok(None);
        }
        Err(hellas_authority::work_store::grant::NodeStoreError::Uninitialized) => {}
        Err(error) => return Err(error.into()),
    }
    prepare_tls(home)?;
    let endpoint = hellas_sdk::node_control::bootstrap::bind_transport(
        transport_key.clone(),
        port,
        remote_control,
    )
    .await?;
    hellas_wire::iroh::close_on_error(&endpoint, pair(&endpoint, &journal, enrollment, now))
        .await?;
    Ok(Some(endpoint))
}

async fn pair(
    endpoint: &iroh::Endpoint,
    journal: &StoreLocation,
    enrollment: &hellas_rpc::ProviderEnrollmentBundle,
    now: hellas_auth::authority::UnixMillis,
) -> Result<()> {
    let invitation = bootstrap::Invitation::create(endpoint, now)?;
    // Pairing exists only for this process. A restart cannot reset the attempt
    // counter for an old secret: it generates an independent invitation instead.
    eprintln!(
        "Waiting for the owner. Copy the invite below from this console, never an untrusted channel, and run `hellas pair INVITE`:"
    );
    println!("{}", invitation.encode()?);
    let result = bootstrap::accept(
        endpoint,
        &invitation,
        journal,
        hellas_authority::model::grant::grant_network(),
        Some(enrollment.clone()),
    )
    .await;
    result.context(
        "owner bootstrap refused or expired; restart explicitly to create a new pairing invitation",
    )
}

pub(super) fn prepare_tls(home: &StoreLocation) -> Result<()> {
    let root = home.child("provider");
    hellas_private::create_dir_all_durable(&root)?;
    // No client trusts local TLS before initialization. Generate it before the
    // authority commit; after a crash, committed store state skips regeneration.
    let tls = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    hellas_private::write_atomically(&root.child("control.cert.der"), ".writing", tls.cert.der())?;
    hellas_private::write_atomically(
        &root.child("control.key.der"),
        ".writing",
        &tls.signing_key.serialize_der(),
    )?;
    Ok(())
}

/// Save the signed approval and its secret together before committing authority.
/// A restart can finish the same bootstrap; it cannot replace an existing owner.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Startup {
    approval: PreparedBootstrap,
    initialized: bool,
    pub authorization: GrantId,
    credential_id: CredentialId,
    secret: [u8; 32],
}
impl Startup {
    pub fn credential(&self) -> CredentialSecret {
        CredentialSecret::from_parts(self.credential_id, self.secret)
    }
}

pub(super) async fn prepare_local(
    home: &StoreLocation,
    identity: &crate::identity::LocalIdentity,
    owner: &dyn Authenticator,
) -> Result<Startup> {
    let root = home.child("provider");
    let journal = root.child("authority");
    let saved = root.child("startup.json");
    let now = hellas_auth::authority::UnixMillis::now()?;
    // Opening first prevents adopting an already initialized authority when no
    // local startup credential exists. No recovery/reset is attempted here.
    let existing = match NodeStore::open(
        &journal,
        hellas_authority::model::grant::grant_network(),
        Some(identity.enrollment.clone()),
        now,
    )
    .await
    {
        Ok(mut store) => {
            store.close().await;
            true
        }
        Err(NodeStoreError::Uninitialized) => false,
        Err(error) => return Err(error.into()),
    };
    let mut startup = if saved.try_exists()? {
        let bytes = hellas_private::read_private_bounded(
            hellas_private::open_regular_file(&saved)?,
            64 * 1024,
        )?;
        serde_json::from_slice::<Startup>(&bytes).context("invalid local startup approval")?
    } else {
        ensure!(
            !existing,
            "authority already exists without a local startup credential; refusing to replace it"
        );
        let administrator = super::admin::owner_scope::administrator(owner.public_key()?)?;
        let authorization = GrantId([0; 16]);
        let holder = NodeKey::from_public_key(identity.node_key.public_key())?;
        let assertion = owner
            .assert(ownership_digest(
                Ownership::Bootstrap {
                    root: authorization,
                    target: None,
                },
                &administrator,
                &administrator,
                holder,
            ))
            .await?;
        let (approval, credential) = OwnerApproval {
            administrator: administrator.clone(),
            credential: administrator,
            holder,
            assertion,
        }
        .prepare(None)?;
        let startup = Startup {
            initialized: false,
            approval,
            authorization,
            credential_id: credential.id(),
            secret: *credential.expose_secret(),
        };
        hellas_private::create_dir_all_durable(&root)?;
        hellas_private::write_atomically(&saved, ".preparing", &serde_json::to_vec(&startup)?)?;
        startup
    };
    // Check the provisioned passkey even before completing an interrupted bootstrap.
    let principal = PrincipalId::from_public_key(hellas_auth::PublicKey::P256(
        owner.public_key()?.to_compressed(),
    ))?;
    ensure!(
        startup.approval.administrator.subject == principal,
        "startup passkey differs from the approved owner"
    );
    if !existing {
        ensure!(
            !startup.initialized,
            "authority journal is missing; refusing to reset initialized runtime state"
        );
        prepare_tls(home)?;
        let mut store = NodeStore::bootstrap_prepared(
            &journal,
            hellas_authority::model::grant::grant_network(),
            startup.authorization,
            startup.approval.clone(),
            Some(identity.enrollment.clone()),
            now,
        )
        .await?;
        store.close().await;
    }
    if !startup.initialized {
        startup.initialized = true;
        hellas_private::write_atomically(&saved, ".initialized", &serde_json::to_vec(&startup)?)?;
    }
    let profile_root = root.child("startup-profile");
    if !profile_root.try_exists()? {
        let staging = tempfile::Builder::new()
            .prefix(".startup-profile-")
            .tempdir_in(&root)?;
        let profile = hellas_sdk::node_control::profile::install_remote(
            staging.path(),
            startup.approval.administrator.authority,
            startup.authorization,
            &startup.credential(),
        )?;
        hellas_sdk::node_control::profile::pin_local(&profile, &root.join("control.cert.der"))?;
        std::fs::rename(staging.path(), &profile_root)?;
        hellas_private::sync_directory(&root)?;
    }
    Ok(startup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_bootstrap_resumes_prepared_approval_and_refuses_lost_journals() {
        let directory = tempfile::tempdir().unwrap();
        let home = StoreLocation::from_home(directory.path(), hellas_private::Durability::Crash);
        let identity = crate::identity::load_or_create(&directory.path().join("identity")).unwrap();
        let owner = hellas_kernel::SoftPasskey::from_secret_scalar([17; 32]).unwrap();
        let startup = prepare_local(&home, &identity, &owner).await.unwrap();
        let certificate = std::fs::read(home.join("provider/control.cert.der")).unwrap();
        let restarted = prepare_local(&home, &identity, &owner).await.unwrap();
        assert_eq!(startup.credential_id, restarted.credential_id);
        assert_eq!(
            certificate,
            std::fs::read(home.join("provider/control.cert.der")).unwrap()
        );
        let other = hellas_kernel::SoftPasskey::from_secret_scalar([18; 32]).unwrap();
        assert!(prepare_local(&home, &identity, &other).await.is_err());

        // Model the durable checkpoint after approval/secret publication but
        // before authority bootstrap. Retry uses that exact approval and secret.
        let pending = directory.path().join("pending");
        std::fs::create_dir_all(pending.join("provider")).unwrap();
        let mut approval = serde_json::to_value(&startup).unwrap();
        approval["initialized"] = false.into();
        hellas_private::write_atomically(
            &pending.join("provider/startup.json"),
            ".writing",
            &serde_json::to_vec(&approval).unwrap(),
        )
        .unwrap();
        let pending = StoreLocation::from_home(&pending, hellas_private::Durability::Crash);
        let resumed = prepare_local(&pending, &identity, &owner).await.unwrap();
        assert!(resumed.initialized);
        assert_eq!(resumed.credential_id, startup.credential_id);
        assert_eq!(resumed.secret, startup.secret);
        std::fs::remove_dir_all(pending.join("provider/authority")).unwrap();
        let failure = prepare_local(&pending, &identity, &owner)
            .await
            .err()
            .unwrap();
        assert!(
            failure.to_string().contains("refusing to reset"),
            "{failure:#}"
        );
    }
}
