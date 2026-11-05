//! Execute a saved job through an imported, device-bound allowance.
use super::*;
use hellas_auth::authority::{NodeKey, ResourceId, UnixMillis};
use hellas_sdk::{
    execution::{Executor, GrantExecutor},
    grant_client::{GrantSessionOptions, GrantTransport, UnpinnedOffer},
};

#[derive(Debug, Default, Args)]
pub(super) struct GrantArgs {
    /// Imported access bundle offer NAME.POLICY. Executes using its bound Work profile.
    #[arg(long, conflicts_with_all = ["settle", "buy_again", "validators", "trust", "genesis", "addresses", "state_dir", "acceptance_blocks", "terminal_blocks", "payment_blocks"])]
    pub offer: Option<String>,
    /// Select a resource ID in an imported allowance containing several policies.
    #[arg(long, requires = "offer")]
    resource: Option<ResourceId>,
    /// Durable attempt record (default: under the client state, by offer and job).
    #[arg(long, requires = "offer", value_name = "FILE")]
    attempt: Option<PathBuf>,
}

impl GrantArgs {
    pub(super) fn options(
        &self,
        args: &ClientArgs,
        context: &Context,
        assurance: Assurance,
    ) -> super::super::CliResult<GrantSessionOptions> {
        let principal = super::super::contributions::principal(&context.owner)?;
        let holder = NodeKey::from_public_key(context.producer.public_key())?;
        let store = hellas_sdk::grant_store::GrantStore::new(
            super::super::contributions::data_root(&principal)?,
        );
        let (offer, application) = store.load_access(
            self.offer.as_deref().context("missing --offer")?,
            &principal,
            &holder,
        )?;
        let provider = hellas_sdk::client::ProviderAddress::of(&offer.offer().provider)?;
        if let Some(expected) = &args.provider {
            ensure!(
                expected.addresses.is_empty(),
                "grant addresses come from the signed offer"
            );
            ensure!(
                provider == expected.address,
                "offer does not match --provider"
            );
        }
        let trust = match (&args.trust_store, &args.trust_policy, assurance) {
            (Some(directory), Some(id), assurance) => {
                hellas_sdk::trust_policy::TrustPolicyStore::new(directory).resolve(
                    id,
                    assurance,
                    crate::identity::assertion_counters()?,
                )?
            }
            (None, None, Assurance::ProducerSigned) => hellas_client::ProviderTrustAnchor {
                expected_genesis: provider.enrollment,
                required_assurance: Assurance::ProducerSigned,
                apple_app_attest: None,
            },
            _ => bail!("Apple providers require --trust-store and --trust-policy"),
        };
        let target = UnpinnedOffer::decode(&offer.encode()?, UnixMillis(0))?.pin(&trust)?;
        Ok(GrantSessionOptions {
            target,
            principal,
            signer: Arc::new(context.producer.clone()),
            application: Arc::new(application),
            journal_root: super::super::contributions::client_journal_root(&principal)?,
            control_timeout: Duration::from_secs(90),
        })
    }

    pub(super) fn policy<'a>(
        &self,
        options: &'a GrantSessionOptions,
    ) -> anyhow::Result<&'a hellas_authority::model::grant::records::GrantPolicy> {
        select_policy(&options.target.offer().grant.policies, self.resource)
    }

    pub(super) async fn executor(
        &self,
        args: &ClientArgs,
        context: &Context,
        job: &Job,
        options: GrantSessionOptions,
    ) -> super::super::CliResult<Executor> {
        let policy = self.policy(&options)?;
        job.input().admits(&policy.invocation_policy, false)?;
        let resource = policy.resource;
        let offer = options.target.offer();
        let provider = hellas_sdk::client::ProviderAddress::of(&offer.provider)?;
        let default_attempt = args
            .root(context)
            .join("grant-attempts")
            .join(provider.to_string())
            .join(offer.grant.id.to_string())
            .join(format!("{}.json", job.digest()));
        let attempt = ExecutionAttempt::open(
            self.attempt.as_deref().unwrap_or(&default_attempt),
            job.input(),
            ExecutionTerms::Grant { resource },
        )?;
        let endpoint = hellas_sdk::grant_client::bind_endpoint(context.transport.clone()).await?;
        Ok(Executor::Grant(GrantExecutor {
            options,
            transport: GrantTransport::Remote(endpoint),
            resource,
            attempt,
        }))
    }
}

fn select_policy(
    policies: &[hellas_authority::model::grant::records::GrantPolicy],
    resource: Option<ResourceId>,
) -> anyhow::Result<&hellas_authority::model::grant::records::GrantPolicy> {
    match resource {
        Some(id) => policies
            .iter()
            .find(|policy| policy.resource == id)
            .context("selected --resource is absent from the offer"),
        None => {
            ensure!(
                policies.len() == 1,
                "offer must contain one policy unless --resource selects an explicit resource ID"
            );
            Ok(&policies[0])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiple_policy_offers_require_and_honor_explicit_resource_selection() {
        let first = hellas_authority::test_support::policy();
        let mut second = first.clone();
        second.resource = ResourceId(hellas_auth::Digest::hash(b"second resource"));
        let policies = [first, second];
        assert!(select_policy(&policies, None).is_err());
        assert_eq!(
            select_policy(&policies, Some(policies[1].resource))
                .unwrap()
                .resource,
            policies[1].resource
        );
        assert!(
            select_policy(
                &policies,
                Some(ResourceId(hellas_auth::Digest::hash(b"absent")))
            )
            .is_err()
        );
        assert!(select_policy(&[], None).is_err());
        assert_eq!(
            select_policy(&policies[..1], None).unwrap().resource,
            policies[0].resource
        );
    }
}
