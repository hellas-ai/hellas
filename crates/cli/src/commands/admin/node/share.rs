//! One resumable share per principal and resource, composed from checked commands.
use super::*;
use hellas_auth::authority::{
    AuthorityId, AuthorityInspection, ContactCard, Grant, InspectionQuery, InspectionRecords,
    OperationId, Permission, PrincipalId, ResourceId, UnixMillis,
};
use hellas_authority::model::grant::{
    admin::AllowanceTerms,
    budget::{BudgetDef, BudgetNode, Limit, PoolId},
};
use hellas_sdk::access_bundle::{AccessBundle, MAX_LABEL_BYTES};
use std::{
    num::{NonZeroU16, NonZeroU64},
    path::PathBuf,
};

pub(super) struct ShareRequest {
    pub contact: ContactCard,
    pub holder: CredentialHolder,
    pub resource: String,
    pub limits: Vec<Limit>,
    pub max_job: Duration,
    pub expires: Duration,
    pub label: Option<String>,
    pub out: PathBuf,
}

fn share_id(
    kind: &str,
    authority: AuthorityId,
    subject: PrincipalId,
    resource: ResourceId,
) -> [u8; 16] {
    let digest = hellas_auth::hash_tuple(
        &format!("hellas.share.{kind}.v1"),
        &[
            authority.0.as_bytes(),
            subject.as_bytes(),
            resource.0.as_bytes(),
        ],
    );
    digest.as_bytes()[..16].try_into().expect("16 of 32 bytes")
}

async fn inspect<T>(
    client: &HostControlClientImpl<T>,
    authorization: GrantId,
    query: InspectionQuery,
) -> Result<AuthorityInspection>
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send + 'static,
{
    let response = client
        .inspect_authority(InspectAuthorityRequest {
            authorization: authorization.0.to_vec(),
            query: canonical_dag_cbor(&query)?,
        })
        .await?;
    ensure!(
        response.reply.len() <= MAX_ADMIN_BYTES,
        "authority reply exceeds limit"
    );
    Ok(decode_dag_cbor(&response.reply)?)
}

async fn find_grant<T>(
    client: &HostControlClientImpl<T>,
    authorization: GrantId,
    id: GrantId,
    mut page: AuthorityInspection,
) -> Result<Option<Grant>>
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send + 'static,
{
    // Individual missing and hidden targets are both denied. A successful page
    // lets the normal Issue command enforce absence and the issuance ceiling.
    let mut after = None;
    loop {
        let InspectionRecords::Grants { records, next } = page.records else {
            anyhow::bail!("grant inspection required")
        };
        if let Some(grant) = records.into_iter().find(|g| g.id() == id) {
            return Ok(Some(grant));
        }
        let Some(next) = next else { return Ok(None) };
        ensure!(
            after.is_none_or(|old| next > old),
            "grant inspection did not advance"
        );
        after = Some(next);
        page = inspect(client, authorization, InspectionQuery::Grants { after }).await?;
    }
}

fn grant_spec(
    authority: AuthorityId,
    subject: PrincipalId,
    allowance: GrantId,
    now: UnixMillis,
    validity: Duration,
    old: Option<&Grant>,
) -> Result<GrantSpec> {
    let duration = u64::try_from(validity.as_millis()).context("--expires is too long")?;
    ensure!(duration > 0, "--expires must be positive");
    let mut spec = GrantSpec {
        authority,
        subject,
        permissions: [Permission {
            operation: OperationId::new(hellas_authority::grant_service::WORK_EXECUTE)?,
            resource: hellas_authority::grant_service::allowance_resource(authority, allowance),
        }]
        .into(),
        not_before: now,
        expires: UnixMillis(
            now.0
                .checked_add(duration)
                .context("--expires is too long")?,
        ),
        delegation_depth: 0,
        issuance: None,
    };
    if let Some(old) = old {
        ensure!(
            !old.revoked(),
            "this share's grant is revoked; revocation is permanent"
        );
        let previous = old.spec();
        // Keep other devices' credentials valid on a rerun. A changed duration
        // or an expired grant starts a new validity period on this same ID.
        if previous.authority == authority
            && previous.subject == subject
            && previous.permissions == spec.permissions
            && previous.issuance.is_none()
            && previous.delegation_depth == 0
            && previous.not_before <= now
            && previous.expires > now
            && previous.expires.0.checked_sub(previous.not_before.0) == Some(duration)
        {
            spec = previous.clone();
        }
    }
    Ok(spec)
}

pub(super) async fn share<T>(
    client: &HostControlClientImpl<T>,
    authorization: GrantId,
    generation: u64,
    mut request: ShareRequest,
) -> Result<()>
where
    T: StreamTransport + Send + Sync,
    T::Stream: Send + 'static,
{
    ensure!(!request.out.try_exists()?, "bundle output already exists");
    ensure!(
        request
            .label
            .as_ref()
            .is_none_or(|label| label.len() <= MAX_LABEL_BYTES),
        "label exceeds {MAX_LABEL_BYTES} bytes"
    );
    let CredentialHolder::Node(holder) = request.holder else {
        anyhow::bail!("a share's credential is held by the receiving device");
    };
    request
        .limits
        .sort_by_key(|limit| (limit.meter, limit.window));
    ensure!(
        !request.limits.windows(2).any(
            |limits| (limits[0].meter, limits[0].window) == (limits[1].meter, limits[1].window)
        ),
        "a meter/window limit may be specified only once"
    );
    let max_job_millis = NonZeroU64::new(
        u64::try_from(request.max_job.as_millis()).context("--max-job is too long")?,
    )
    .context("--max-job must be positive")?;
    let subject = request.contact.principal();
    let WorkControlReply::Catalogue(catalogue) =
        work(client, authorization, &WorkControlCommand::Catalogue).await?
    else {
        anyhow::bail!("catalogue reply required")
    };
    let policy = catalogue
        .into_iter()
        .find(|policy| policy.name == request.resource)
        .with_context(|| format!("the node serves no resource named {:?}", request.resource))?;
    // A restricted issuer's own administrative grant can be outside its
    // issuance ceiling. Page metadata is visible without exposing that grant.
    let grants = inspect(
        client,
        authorization,
        InspectionQuery::Grants { after: None },
    )
    .await?;
    let authority = grants.authority;
    let pool = PoolId(share_id("pool", authority, subject, policy.resource));
    let allowance = GrantId(share_id("allowance", authority, subject, policy.resource));
    let grant = GrantId(share_id("grant", authority, subject, policy.resource));
    let old_grant = find_grant(client, authorization, grant, grants).await?;
    let spec = grant_spec(
        authority,
        subject,
        allowance,
        UnixMillis::now()?,
        request.expires,
        old_grant.as_ref(),
    )?;

    // A revision-1 create cannot overwrite a hidden/existing budget. Work maps
    // missing budget reads and other store failures to Unavailable; only this
    // checked create probes absence, and all other read errors stop the share.
    for (node, parent, limits) in [
        (
            BudgetNode::Pool(pool),
            BudgetNode::Account(policy.account),
            vec![],
        ),
        (
            BudgetNode::Subject { pool, subject },
            BudgetNode::Pool(pool),
            request.limits,
        ),
    ] {
        let current = work(
            client,
            authorization,
            &WorkControlCommand::InspectBudget { node },
        )
        .await;
        let revision = match current {
            Ok(WorkControlReply::Budget { definition, .. }) => {
                ensure!(
                    definition.parent == parent,
                    "share budget has a different parent"
                );
                if definition.limits == limits && definition.max_in_flight == NonZeroU16::MIN {
                    continue;
                }
                definition
                    .revision
                    .next()
                    .context("budget revision overflow")?
            }
            Ok(_) => anyhow::bail!("budget reply required"),
            Err(error)
                if error
                    .downcast_ref::<hellas_wire::WireStatus>()
                    .is_some_and(|status| status.code() == hellas_wire::WireCode::Unavailable) =>
            {
                Revision(1)
            }
            Err(error) => return Err(error),
        };
        let definition = BudgetDef {
            node,
            parent,
            revision,
            limits,
            max_in_flight: NonZeroU16::MIN,
        };
        work(
            client,
            authorization,
            &WorkControlCommand::ConfigureBudget { definition },
        )
        .await
        .with_context(|| {
            format!("could not configure share budget {node:?}; rerun after inspecting the node")
        })?;
    }
    let terms = AllowanceTerms {
        policies: vec![policy.name.clone()],
        budget: BudgetNode::Subject { pool, subject },
        max_job_millis,
        enabled: true,
        allow_account_backed: true,
    };
    let WorkControlReply::Allowances(allowances) =
        work(client, authorization, &WorkControlCommand::List).await?
    else {
        anyhow::bail!("allowance list required")
    };
    match allowances.into_iter().find(|item| item.id == allowance) {
        None => {
            work(
                client,
                authorization,
                &WorkControlCommand::Create {
                    id: allowance,
                    terms,
                },
            )
            .await?;
        }
        Some(old) => {
            let unchanged = if old.enabled {
                let WorkControlReply::Offers(offers) = work(
                    client,
                    authorization,
                    &WorkControlCommand::Offers {
                        id: Some(allowance),
                    },
                )
                .await?
                else {
                    anyhow::bail!("offer reply required")
                };
                let [offer] = <[_; 1]>::try_from(offers)
                    .map_err(|_| anyhow::anyhow!("allowance {allowance} needs one active offer"))?;
                let current = &offer.offer().grant;
                current.policies == [policy.clone()]
                    && current.budget == terms.budget
                    && current.max_job_millis == terms.max_job_millis
                    && current.allow_account_backed
            } else {
                false
            };
            if !unchanged {
                work(
                    client,
                    authorization,
                    &WorkControlCommand::Revise {
                        id: allowance,
                        expected_revision: old.revision,
                        terms,
                    },
                )
                .await?;
            }
        }
    }
    let command = match old_grant {
        Some(old) if old.spec() == &spec => None,
        Some(old) => Some(GrantCommand::Revise {
            authorization,
            id: grant,
            expected: old.revision(),
            spec: spec.clone(),
        }),
        None => Some(GrantCommand::Issue {
            authorization,
            id: grant,
            spec: spec.clone(),
        }),
    };
    if let Some(command) = command {
        let response = client
            .grant_control(GrantControlRequest {
                command: canonical_dag_cbor(&command)?,
            })
            .await?;
        ensure!(
            response.reply.len() <= MAX_ADMIN_BYTES,
            "grant reply exceeds limit"
        );
        let record: AdministrationRecord = decode_dag_cbor(&response.reply)?;
        ensure!(
            record.command() == &AdministrationCommand::Grant(command),
            "grant reply differs from request"
        );
    }
    let WorkControlReply::Offers(offers) = work(
        client,
        authorization,
        &WorkControlCommand::Offers {
            id: Some(allowance),
        },
    )
    .await?
    else {
        anyhow::bail!("offer reply required")
    };
    ensure!(offers.len() == 1, "share needs one active offer");
    let provider = hellas_sdk::client::ProviderAddress::of(&offers[0].offer().provider)?;
    let (prepared, credential) =
        Credential::prepare(spec.clone(), CredentialHolder::Node(holder), generation)?;
    let id = credential.id();
    let bundle = AccessBundle {
        offers,
        authority,
        authorization: grant,
        subject,
        holder,
        credential,
        expires: spec.expires,
        label: request.label,
    };
    bundle.save(&request.out)?;
    issue(client, authorization, &prepared).await.with_context(|| format!(
        "bundle credential {id} is retained at {} pending confirmation; inspect Credential {{ id }} before sharing it or retrying issuance", request.out.display(),
    ))?;
    for offer in &bundle.offers {
        offer_fingerprints(offer)?;
    }
    println!(
        "{}",
        serde_json::json!({
            "bundle_file": request.out, "credential_id": id.to_string(),
            "subject": subject.to_string(), "subject_fingerprint": subject.fingerprint(),
            "authority": authority.to_string(), "resource": policy.name,
            "provider": provider.to_string(),
            "allowance": allowance.to_string(), "grant": grant.to_string(),
            "pool": pool.to_string(), "expires": spec.expires.0,
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_channel::test_support::principal;

    fn ids() -> (AuthorityId, PrincipalId, ResourceId) {
        (
            AuthorityId(hellas_auth::Digest::hash(b"authority")),
            principal(7).0,
            ResourceId(hellas_auth::Digest::hash(b"resource")),
        )
    }

    fn grant(spec: GrantSpec, revoked: bool) -> Grant {
        serde_json::from_value(serde_json::json!({
            "id": GrantId([3; 16]), "revision": Revision(1), "spec": spec,
            "origin": {"Node": {"issuer": principal(2).0}}, "revoked": revoked,
        }))
        .unwrap()
    }

    #[test]
    fn share_ids_bind_authority_principal_resource_and_kind() {
        let (authority, subject, resource) = ids();
        let id = share_id("pool", authority, subject, resource);
        assert_eq!(id, share_id("pool", authority, subject, resource));
        assert_ne!(id, share_id("grant", authority, subject, resource));
        assert_ne!(id, share_id("allowance", authority, subject, resource));
        assert_ne!(
            id,
            share_id(
                "pool",
                AuthorityId(hellas_auth::Digest::hash(b"other")),
                subject,
                resource
            )
        );
        assert_ne!(id, share_id("pool", authority, principal(8).0, resource));
        assert_ne!(
            id,
            share_id(
                "pool",
                authority,
                subject,
                ResourceId(hellas_auth::Digest::hash(b"other"))
            )
        );
    }

    #[test]
    fn reruns_keep_live_validity_and_renew_expired_grants_without_restoring_revocation() {
        let (authority, subject, _) = ids();
        let allowance = GrantId([2; 16]);
        let duration = Duration::from_secs(300);
        let original = grant_spec(
            authority,
            subject,
            allowance,
            UnixMillis(1000),
            duration,
            None,
        )
        .unwrap();
        let old = grant(original.clone(), false);
        assert_eq!(
            grant_spec(
                authority,
                subject,
                allowance,
                UnixMillis(2000),
                duration,
                Some(&old)
            )
            .unwrap(),
            original
        );
        let renewed = grant_spec(
            authority,
            subject,
            allowance,
            UnixMillis(302_000),
            duration,
            Some(&old),
        )
        .unwrap();
        assert_eq!(renewed.not_before, UnixMillis(302_000));
        assert_eq!(renewed.expires, UnixMillis(602_000));
        let changed = grant_spec(
            authority,
            subject,
            allowance,
            UnixMillis(2000),
            Duration::from_secs(600),
            Some(&old),
        )
        .unwrap();
        assert_eq!(changed.expires, UnixMillis(602_000));
        let revoked = grant(original, true);
        assert!(
            grant_spec(
                authority,
                subject,
                allowance,
                UnixMillis(2000),
                duration,
                Some(&revoked)
            )
            .is_err()
        );
        assert!(
            grant_spec(
                authority,
                subject,
                allowance,
                UnixMillis(u64::MAX),
                duration,
                None
            )
            .is_err()
        );
        assert!(
            grant_spec(
                authority,
                subject,
                allowance,
                UnixMillis(0),
                Duration::ZERO,
                None
            )
            .is_err()
        );
    }
}
