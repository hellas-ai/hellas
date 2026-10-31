pub mod local;

use super::CliResult;
use crate::identity::LocalIdentity;
use hellas_sdk::grant_client::{GrantSessionOptions, PinnedOffer};
use std::{path::Path, sync::Arc, time::Duration};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolFile {
    channels: Vec<PoolChannelFile>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolChannelFile {
    offer: String,
    work_profile: String,
    trust_policy: String,
    resources: Vec<String>,
}

/// Resolve a static pool from private stores without contacting a provider.
pub fn load_pool(
    path: &Path,
    root: &Path,
    trust_directory: &Path,
    identity: &LocalIdentity,
    client: hellas_auth::authority::PrincipalId,
    assurance: hellas_rpc::Assurance,
) -> CliResult<hellas_sdk::grant_gateway::GrantPoolOptions> {
    let bytes = super::read_bounded_regular_file(path, "grant pool config", 1024 * 1024)?;
    let file: PoolFile = serde_json::from_slice(&bytes)?;
    let store = hellas_sdk::grant_store::GrantStore::new(root);
    let trust = hellas_sdk::trust_policy::TrustPolicyStore::new(trust_directory);
    let holder = hellas_auth::authority::NodeKey::from_public_key(identity.node_key.public_key())?;
    let counters = crate::identity::assertion_counters()?;
    let mut channels = Vec::with_capacity(file.channels.len());
    for entry in file.channels {
        let offer = store.load_offer(&entry.offer)?;
        let anchor = trust.resolve(&entry.trust_policy, assurance, counters.clone())?;
        let target = hellas_sdk::grant_client::UnpinnedOffer::decode(
            &offer.encode()?,
            hellas_auth::authority::UnixMillis(0),
        )?
        .pin(&anchor)?;
        let application = Arc::new(store.load_profile(&entry.work_profile, &client, &holder)?);
        let mut resources = Vec::with_capacity(entry.resources.len());
        for text in entry.resources {
            let digest: hellas_auth::Digest = text.parse()?;
            anyhow::ensure!(
                digest.to_string() == text,
                "resource IDs must use canonical lowercase form"
            );
            resources.push(hellas_auth::authority::ResourceId(digest));
        }
        channels.push(hellas_sdk::grant_gateway::GrantPoolChannel {
            session: GrantSessionOptions {
                target,
                principal: client,
                signer: Arc::new(identity.node_key.clone()),
                application,
                journal_root: root.join("channels"),
                control_timeout: Duration::from_secs(90),
            },
            resources,
        });
    }
    let pool = hellas_sdk::grant_gateway::GrantPoolOptions { channels };
    pool.validate()?;
    pool.http_config()?;
    Ok(pool)
}

pub fn session(
    target: PinnedOffer,
    identity: &LocalIdentity,
    client: hellas_auth::authority::PrincipalId,
    application: Arc<hellas_sdk::node_control::profile::ClientProfile>,
) -> CliResult<GrantSessionOptions> {
    Ok(GrantSessionOptions {
        target,
        principal: client,
        signer: Arc::new(identity.node_key.clone()),
        application,
        journal_root: super::contributions::client_journal_root(&client)?,
        control_timeout: Duration::from_secs(90),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_auth::authority::{
        AuthorityId, CredentialId, CredentialSecret, GrantId, NodeKey, UnixMillis,
    };
    use hellas_authority::model::grant::records::{Offer, SignedOffer};
    use hellas_authority::test_support::definition;
    use hellas_channel::test_support::{network, principal, software_enrollment};
    use hellas_sdk::{
        access_bundle::AccessBundle,
        grant_store::GrantStore,
        trust_policy::{TrustPolicy, TrustPolicyStore},
    };

    #[test]
    fn offline_pool_loads_real_private_stores_and_rejects_wrong_device_and_resource() {
        let dir = tempfile::tempdir().unwrap();
        let identity = crate::identity::load_or_create(Some(&dir.path().join("identity"))).unwrap();
        let subject = principal(7).0;
        let holder = NodeKey::from_public_key(identity.node_key.public_key()).unwrap();
        let transport = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let provider = software_enrollment(2, *transport.as_bytes());
        let grant = definition(GrantId([1; 16]), subject);
        let resource = grant.policies[0].resource;
        let offer = SignedOffer::sign(
            Offer {
                network: network(),
                provider: provider.clone(),
                grant,
                generation: 0,
                sequence: 1,
                valid_until: UnixMillis(1000),
                addresses: vec![],
            },
            &principal(2).1,
        )
        .unwrap();
        let bundle = AccessBundle {
            offers: vec![offer],
            authority: AuthorityId(hellas_auth::Digest::hash(b"pool-test")),
            authorization: GrantId([4; 16]),
            subject,
            holder,
            credential: CredentialSecret::from_parts(CredentialId([5; 16]), [6; 32]),
            expires: UnixMillis(2000),
            label: None,
        };
        let bundle_path = dir.path().join("bundle");
        bundle.save(&bundle_path).unwrap();
        let root = dir.path().join("private");
        let imported = GrantStore::new(&root)
            .import_bundle(&bundle_path, "shared", &subject, &holder, false)
            .unwrap();
        let trust = dir.path().join("trust");
        TrustPolicyStore::new(&trust)
            .approve(
                "provider",
                0,
                TrustPolicy {
                    provider_genesis: provider.content_id(),
                    assurance: hellas_rpc::Assurance::ProducerSigned,
                    apple: None,
                },
                "local approval".into(),
            )
            .unwrap();
        let config = dir.path().join("pool.json");
        let write_config = |resource: String| {
            std::fs::write(&config, serde_json::to_vec(&serde_json::json!({"channels":[{"offer": imported.offers[0].name,"work_profile":"shared","trust_policy":"provider","resources":[resource]}]})).unwrap()).unwrap()
        };
        write_config(resource.0.to_string());
        let pool = load_pool(
            &config,
            &root,
            &trust,
            &identity,
            subject,
            hellas_rpc::Assurance::ProducerSigned,
        )
        .unwrap();
        assert_eq!(pool.channels.len(), 1);
        assert_eq!(pool.channels[0].resources, vec![resource]);
        let other = crate::identity::load_or_create(Some(&dir.path().join("other"))).unwrap();
        assert!(
            load_pool(
                &config,
                &root,
                &trust,
                &other,
                subject,
                hellas_rpc::Assurance::ProducerSigned
            )
            .is_err()
        );
        write_config(hellas_auth::Digest::hash(b"wrong").to_string());
        assert!(
            load_pool(
                &config,
                &root,
                &trust,
                &identity,
                subject,
                hellas_rpc::Assurance::ProducerSigned
            )
            .is_err()
        );
    }
}
