//! Execute a saved job through an imported, device-bound allowance.
use super::*;
use hellas_auth::authority::{NodeKey, ResourceId, UnixMillis};
use hellas_sdk::{
    execution::{ExecutionTarget, RetainedExecutionResult},
    grant_client::{GrantSessionOptions, GrantTransport, UnpinnedOffer},
    node_control::profile::ClientProfile,
};

#[derive(Debug, Default, Args)]
pub(super) struct GrantArgs {
    /// Imported allowance offer. Executes without funding or paying a channel.
    #[arg(long, requires_all = ["work_profile", "resource", "attempt"], conflicts_with_all = ["settle", "buy_again", "validators", "trust", "genesis", "addresses", "state_dir"])]
    pub offer: Option<String>,
    /// Device-bound Work profile installed by `hellas offer import-bundle`.
    #[arg(long, requires = "offer", value_name = "FILE")]
    work_profile: Option<PathBuf>,
    /// Exact resource ID admitted by the allowance.
    #[arg(long, requires = "offer", value_name = "ID")]
    resource: Option<hellas_auth::Digest>,
    /// Durable attempt record. Reuse it to recover; a new path requests new work.
    #[arg(long, requires = "offer", value_name = "FILE")]
    attempt: Option<PathBuf>,
}

pub(super) async fn run(
    grant: &GrantArgs,
    args: &ClientArgs,
    context: &Context,
    job: &Job,
    output: Option<&Path>,
) -> super::super::CliResult<()> {
    ensure!(
        args.provider.addresses.is_empty(),
        "grant addresses come from the signed offer"
    );
    let principal = super::super::contributions::principal(&context.owner)?;
    let offer = super::super::contributions::load_offer(
        &principal,
        grant.offer.as_deref().context("missing --offer")?,
    )?;
    let provider = hellas_sdk::client::ProviderAddress::of(&offer.offer().provider)?;
    ensure!(
        provider == args.provider.address,
        "offer does not match --provider"
    );
    let trust = match (&args.trust_store, &args.trust_policy, job.assurance()) {
        (Some(directory), Some(id), assurance) => hellas_sdk::trust_policy::TrustPolicyStore::new(
            directory,
        )
        .resolve(id, assurance, crate::identity::assertion_counters()?)?,
        (None, None, Assurance::ProducerSigned) => hellas_client::ProviderTrustAnchor {
            expected_genesis: provider.enrollment,
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        },
        _ => bail!("Apple providers require --trust-store and --trust-policy"),
    };
    let target = UnpinnedOffer::decode(&offer.encode()?, UnixMillis(0))?.pin(&trust)?;
    let resource = ResourceId(grant.resource.context("missing --resource")?);
    let policy = offer
        .offer()
        .grant
        .policies
        .iter()
        .find(|policy| policy.resource == resource)
        .context("offer does not admit --resource")?;
    job.input().admits(&policy.invocation_policy, false)?;
    let holder = NodeKey::from_public_key(context.producer.public_key())?;
    let application = Arc::new(ClientProfile::load_bound(
        grant
            .work_profile
            .as_deref()
            .context("missing --work-profile")?,
        &principal,
        &holder,
    )?);
    let provider_key = hellas_auth::PublicKey::Secp256k1(
        hellas_authority::model::grant::records::grant_producer(&offer.offer().provider)?
            .to_bytes(),
    );
    let terms = ExecutionTerms::Grant { resource };
    let mut attempt = ExecutionAttempt::open(
        grant.attempt.as_deref().context("missing --attempt")?,
        job.input(),
        terms,
    )?;
    attempt.retain_results(true);
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
            journal_root: super::super::contributions::client_journal_root(&principal)?,
            control_timeout: Duration::from_secs(90),
        };
        let endpoint = hellas_sdk::grant_client::bind_endpoint(context.transport.clone()).await?;
        let session = attempt
            .open_grant_session(options, GrantTransport::Remote(endpoint.clone()))
            .await;
        let mut session = match session {
            Ok(session) => session,
            Err(error) => {
                endpoint.close().await;
                return Err(error.into());
            }
        };
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
        // Closing acknowledges the provider's final frames; dropping the
        // endpoint would leave it waiting for them until its write timeout.
        endpoint.close().await;
        let result = result?;
        closed?;
        result
    };
    let work = attempt
        .inspect()?
        .work
        .context("completed grant has no work ID")?;
    if let Some(directory) = output {
        hellas_private::create_dir_all_durable(directory)?;
        write(&directory.join("transcript.cbor"), &retained.transcript)?;
        write(
            &directory.join("result.json"),
            &serde_json::to_vec_pretty(&serde_json::json!({
                "job": job.digest().to_string(), "provider": provider.to_string(),
                "funding": "grant", "resource": resource.0.to_string(), "work": work.to_string(),
                "outcome": retained.output.outcome,
            }))?,
        )?;
        save_invocation_outputs(directory, job, &retained.output, &provider_key)?;
    } else {
        println!("output: {}", serde_json::to_string(&retained.output)?);
    }
    if let hellas_rpc::protocol::invocation::output::Outcome::Failed(reason) =
        retained.output.outcome
    {
        bail!("grant work {work} failed: {reason:?}");
    }
    println!("grant work {work} completed on {provider}");
    std::io::stdout().lock().flush()?;
    attempt.reported()?;
    Ok(())
}
