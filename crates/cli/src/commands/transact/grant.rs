//! Execute a saved job through an imported, device-bound allowance.
use super::*;
use hellas_auth::authority::{NodeKey, ResourceId, UnixMillis};
use hellas_sdk::{
    execution::{ExecutionTarget, RetainedExecutionResult},
    grant_client::{GrantSessionOptions, GrantTransport, UnpinnedOffer},
};

#[derive(Debug, Default, Args)]
pub(super) struct GrantArgs {
    /// Imported access bundle offer NAME.POLICY. Executes using its bound Work profile.
    #[arg(long, conflicts_with_all = ["settle", "buy_again", "validators", "addresses", "acceptance_blocks", "terminal_blocks", "payment_blocks"])]
    pub offer: Option<String>,
    /// Select a resource ID in an imported allowance containing several policies.
    #[arg(long, requires = "offer")]
    resource: Option<ResourceId>,
    /// Durable attempt record (default: under the client state, by offer and job).
    #[arg(long, requires = "offer", value_name = "FILE")]
    attempt: Option<PathBuf>,
}

pub(super) struct GrantResult {
    pub attempt: ExecutionAttempt,
    pub retained: RetainedExecutionResult,
    resource: ResourceId,
    provider_key: hellas_auth::PublicKey,
    provider: hellas_sdk::client::ProviderAddress,
}

impl GrantResult {
    pub fn save(&self, directory: &Path, job: &Job) -> anyhow::Result<()> {
        hellas_private::create_dir_all_durable(directory)?;
        write(
            &directory.join("transcript.cbor"),
            &self.retained.transcript,
        )?;
        write(
            &directory.join("result.json"),
            &serde_json::to_vec_pretty(&serde_json::json!({
                "job": job.digest().to_string(), "provider": self.provider.to_string(),
                "funding": "grant", "resource": self.resource.to_string(),
                "work": self.attempt.inspect()?.work.context("completed grant has no work ID")?.to_string(),
                "outcome": self.retained.output.outcome,
            }))?,
        )?;
        save_invocation_outputs(directory, job, &self.retained.output, &self.provider_key)?;
        Ok(())
    }
    pub fn ensure_succeeded(&self) -> anyhow::Result<()> {
        if let hellas_rpc::protocol::invocation::output::Outcome::Failed(reason) =
            &self.retained.output.outcome
        {
            bail!("grant work failed: {reason:?}");
        }
        Ok(())
    }
}

pub(super) async fn execute(
    grant: &GrantArgs,
    args: &ClientArgs,
    context: &Context,
    job: &Job,
) -> super::super::CliResult<GrantResult> {
    let principal = super::super::contributions::principal(&context.owner)?;
    let holder = NodeKey::from_public_key(context.producer.public_key())?;
    let store = hellas_sdk::grant_store::GrantStore::new(super::super::contributions::data_root(
        &context.home,
        &principal,
    )?);
    let (offer, application) = store.load_access(
        grant.offer.as_deref().context("missing --offer")?,
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
    let trust = match (&args.trust_store, &args.trust_policy, job.assurance()) {
        (Some(directory), Some(id), assurance) => {
            hellas_sdk::trust_policy::TrustPolicyStore::new(directory).resolve(
                id,
                assurance,
                crate::identity::assertion_counters(&context.home)?,
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
    let policy = select_policy(&offer.offer().grant.policies, grant.resource)?;
    let resource = policy.resource;
    job.input().admits(&policy.invocation_policy, false)?;
    let application = Arc::new(application);
    let provider_key = hellas_auth::PublicKey::Secp256k1(
        hellas_authority::model::grant::records::grant_producer(&offer.offer().provider)?
            .to_bytes(),
    );
    let terms = ExecutionTerms::Grant { resource };
    let default_attempt = context
        .home
        .join("grants")
        .join("grant-attempts")
        .join(provider.to_string())
        .join(offer.offer().grant.id.to_string())
        .join(format!("{}.json", job.digest()));
    let mut attempt = ExecutionAttempt::open(
        grant.attempt.as_deref().unwrap_or(&default_attempt),
        job.input(),
        terms,
    )?;
    attempt.bind_target(ExecutionTarget {
        network: offer.offer().network,
        provider,
    })?;
    let retained = if let Some(result) = attempt.retained_result()? {
        result
    } else {
        let options = GrantSessionOptions {
            target,
            principal,
            signer: Arc::new(context.producer.clone()),
            application,
            journal_root: super::super::contributions::client_journal_root(
                &context.home,
                &principal,
            )?,
            control_timeout: Duration::from_secs(90),
        };
        let endpoint = context.grant_endpoint().await?;
        let mut session = attempt
            .open_grant_session(options, GrantTransport::Remote(endpoint))
            .await?;
        let result = async {
            let mut session = ExecutionSession::Grant(&mut session);
            match session.execute(job.input().clone(), terms, &context.producer, Default::default(), Some(&mut attempt)).await {
                Ok(ExecutionResult::Grant(result)) => Ok(RetainedExecutionResult {
                    output: result.output,
                    transcript: hellas_channel::model::work::encode_transcript(&result.events)?,
                }),
                Ok(ExecutionResult::Paid(_)) => unreachable!("grant session returned paid result"),
                Err(hellas_sdk::execution::ExecutionError::RecoveryRequired) => {
                    let facts = session.recover(&mut attempt).await?;
                    bail!("existing grant attempt: work {:?}, terminal {:?}, result available: {}; no new work submitted", facts.work, facts.terminal, facts.result_available)
                }
                Err(error) => Err(anyhow::Error::from(error)),
            }
        }.await;
        let closed = session.shutdown().await;
        let result = result?;
        closed?;
        result
    };
    Ok(GrantResult {
        attempt,
        retained,
        resource,
        provider_key,
        provider,
    })
}

pub(super) async fn run(
    grant: &GrantArgs,
    args: &ClientArgs,
    context: &Context,
    job: &Job,
    output: Option<&Path>,
) -> super::super::CliResult<()> {
    let mut result = execute(grant, args, context, job).await?;
    if let Some(directory) = output {
        result.save(directory, job)?;
    } else {
        println!(
            "output: {}",
            serde_json::to_string(&result.retained.output)?
        );
    }
    result.ensure_succeeded()?;
    let work = result
        .attempt
        .inspect()?
        .work
        .context("completed grant has no work ID")?;
    println!("grant work {work} completed on {}", result.provider);
    std::io::stdout().lock().flush()?;
    result.attempt.reported()?;
    Ok(())
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
