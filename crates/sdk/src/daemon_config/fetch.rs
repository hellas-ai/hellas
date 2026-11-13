use super::{BackendKind, Upstream};
use crate::{Backend, FetchRoute, FetchRouteEntry, FetchRouteRegistry};
use hellas_executor::ExecutorSpawnConfig;
use hellas_rpc::protocol::invocation::{
    Admission, InvocationPolicy, Limits,
    fetch::{FetchAdmission, FetchLimits, FetchRoutePolicy},
};
use std::sync::Arc;

impl super::Backend {
    pub fn fetch_policy(&self) -> Result<InvocationPolicy, crate::daemon::Error> {
        let BackendKind::Fetch {
            service,
            method,
            upstream,
        } = &self.kind
        else {
            return Err("not a Fetch backend".into());
        };
        let contract = match upstream {
            Upstream::Http { .. } | Upstream::OpenaiHttp { .. } => {
                hellas_rpc::FetchContract::http()?
            }
            Upstream::OpenaiResponses { .. } => {
                hellas_adaptors::openai::responses::fetch::responses_contract()?
            }
        };
        Ok(InvocationPolicy {
            admissions: vec![Admission::Fetch {
                admission: FetchAdmission {
                    contract,
                    route: FetchRoutePolicy::sealed_route(service, method)?,
                    limits: FetchLimits {
                        max_request_body_bytes: hellas_rpc::fetch::MAX_FETCH_REQUEST_BODY_BYTES
                            as u32,
                        max_output_events: 65536,
                        max_spool_bytes: hellas_rpc::http_fetch::MAX_HTTP_RESPONSE_BYTES as u64,
                        max_encoded_result_frame:
                            hellas_rpc::protocol::invocation::MAX_INVOCATION_BYTES as u32,
                        max_encoded_prepared_input:
                            hellas_rpc::protocol::invocation::MAX_INVOCATION_BYTES as u32,
                    },
                },
            }],
            limits: Limits {
                max_upload_bytes: hellas_rpc::protocol::invocation::MAX_INVOCATION_BYTES as u64,
                max_output_bytes: hellas_rpc::protocol::invocation::MAX_INVOCATION_BYTES as u64,
                max_steps: 1,
                execution_timeout_ms: 86_400_000,
            },
        })
    }
    pub async fn open_fetch(
        &self,
        signer: Arc<hellas_auth::ProducerSigningKey>,
    ) -> Result<Backend, Box<dyn std::error::Error + Send + Sync>> {
        let BackendKind::Fetch {
            service,
            method,
            upstream,
        } = &self.kind
        else {
            return Err("not a Fetch backend".into());
        };
        let (entry, _) = upstream.entry()?;
        let policy = self.fetch_policy()?;
        let mut routes = FetchRouteRegistry::new();
        routes.register(FetchRoute::new(service, method), entry)?;
        let mut config = ExecutorSpawnConfig::new(signer, routes);
        config.fetch_max_in_flight = self.max_in_flight.get();
        config.fetch_queue_capacity = 0;
        Ok(Backend::Fetch {
            execution: hellas_executor::Executor::spawn_configured(config).await?,
            policy,
        })
    }
}

impl Upstream {
    fn entry(
        &self,
    ) -> Result<
        (FetchRouteEntry, hellas_rpc::FetchContract),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let capabilities = Default::default();
        Ok(match self {
            Self::OpenaiHttp { .. } => return self.http_configuration()?.entry(),
            Self::Http { allowed_hosts, allow_private_addresses, credentials } => {
                let credentials = credentials.iter().map(|(id, credential)| {
                    Ok((id.clone(), hellas_providers::HttpCredential {
                        allowed_origins: credential.allowed_origins.clone(),
                        allowed_paths: credential.allowed_paths.clone(),
                        allowed_methods: credential.allowed_methods.clone(),
                        trust_roots: hellas_rpc::http_fetch::HttpTrustRoots::WebPki,
                        header_name: credential.header_name.clone(),
                        header_value: hellas_providers::HttpSecret::Value(credential.secret.clone().ok_or("missing upstream credential")?),
                    }))
                }).collect::<Result<_, Box<dyn std::error::Error + Send + Sync>>>()?;
                (FetchRouteEntry::new(
                    Arc::new(hellas_providers::HttpFetchProvider::new(hellas_providers::HttpEgressPolicy { allowed_hosts: allowed_hosts.clone(), allow_private_addresses: *allow_private_addresses }, credentials)?),
                    Arc::new(hellas_providers::HttpFetchAdaptorFactory::new()?),
                    capabilities,
                )?, hellas_rpc::FetchContract::http()?)
            }
            Self::OpenaiResponses { secret } => (
                FetchRouteEntry::new(
                    Arc::new(hellas_providers::OpenAiResponsesFetchProvider::with_bearer(secret.as_deref().ok_or("missing upstream credential")?)?),
                    Arc::new(hellas_adaptors::openai::responses::fetch::OpenAiResponsesAdaptorFactory::new()?),
                    capabilities,
                )?, hellas_adaptors::openai::responses::fetch::responses_contract()?,
            ),
        })
    }
}
