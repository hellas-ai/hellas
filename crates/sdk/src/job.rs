//! Caller-owned job folders. Purchase nonces are derived from durable channel
//! state rather than stored with the reusable application input.
use hellas_auth::{Digest, ProducerSigningKey, PublicKey, hash_tuple};
use hellas_rpc::{Assurance, CausalLmEnvironment, FetchContract, ProgramManifest};
use hellas_work::model::{fetch::PreparedPaidFetchInputV1, profile::PreparedWorkInput};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const FORMAT: &str = "hellas.job.v1";
const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("invalid job: {0}")]
    Invalid(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error(transparent)]
    EncodeToml(#[from] toml::ser::Error),
    #[error(transparent)]
    Canonical(#[from] hellas_rpc::protocol::value::CanonicalDecodeError),
    #[error(transparent)]
    Fetch(#[from] hellas_rpc::fetch::FetchProtocolError),
    #[error(transparent)]
    Work(#[from] hellas_work::model::work::PaidWorkError),
    #[error(transparent)]
    Gateway(#[from] hellas_gateway::WorkGatewayError),
}
type Result<T> = std::result::Result<T, JobError>;
fn invalid(message: impl Into<String>) -> JobError {
    JobError::Invalid(message.into())
}

#[derive(Clone, Debug)]
pub struct Job {
    price: u64,
    input: JobInput,
}

#[derive(Clone, Debug)]
pub enum JobInput {
    Fetch {
        contract: FetchContract,
        service: String,
        method: String,
        request: Vec<u8>,
        assurance: Assurance,
    },
    CausalLm {
        environment: CausalLmEnvironment,
        input_ids: Vec<u32>,
        max_new_tokens: u32,
        stop_token_ids: Vec<u32>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: String,
    application: Application,
    payment: Payment,
    #[serde(skip_serializing_if = "Option::is_none")]
    fetch: Option<FetchFiles>,
    #[serde(skip_serializing_if = "Option::is_none")]
    causal_lm: Option<CausalLmFiles>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Application {
    evaluator: String,
    adaptor: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payment {
    price: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchFiles {
    contract: String,
    service: String,
    method: String,
    request: String,
    assurance: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CausalLmFiles {
    environment: String,
    tokens: String,
    max_new_tokens: u32,
    #[serde(default)]
    stop_token_ids: Vec<u32>,
}

impl Job {
    pub fn from_input(price: u64, input: JobInput) -> Result<Self> {
        match input {
            JobInput::Fetch {
                contract,
                service,
                method,
                request,
                assurance,
            } => Self::fetch(price, contract, service, method, request, assurance),
            JobInput::CausalLm {
                environment,
                input_ids,
                max_new_tokens,
                stop_token_ids,
            } => Self::causal_lm(
                price,
                environment,
                input_ids,
                max_new_tokens,
                stop_token_ids,
            ),
        }
    }
    pub fn fetch(
        price: u64,
        contract: FetchContract,
        service: String,
        method: String,
        request: Vec<u8>,
        assurance: Assurance,
    ) -> Result<Self> {
        if service.is_empty()
            || method.is_empty()
            || service.len() > hellas_rpc::fetch::MAX_FETCH_ROUTE_COMPONENT_BYTES
            || method.len() > hellas_rpc::fetch::MAX_FETCH_ROUTE_COMPONENT_BYTES
        {
            return Err(invalid(
                "Fetch service and method must be nonempty bounded route components",
            ));
        }
        if request.len() > hellas_rpc::fetch::MAX_FETCH_REQUEST_BODY_BYTES {
            return Err(invalid("Fetch request exceeds byte limit"));
        }
        serde_json::from_slice::<serde_json::Value>(&request)?;
        if contract.schema() == hellas_rpc::FetchSchema::HttpV1 {
            hellas_rpc::http_fetch::HttpFetchRequest::decode(&request)
                .map_err(|e| invalid(e.to_string()))?;
        }
        Self::new(
            price,
            JobInput::Fetch {
                contract,
                service,
                method,
                request,
                assurance,
            },
        )
    }

    pub fn causal_lm(
        price: u64,
        environment: CausalLmEnvironment,
        input_ids: Vec<u32>,
        max_new_tokens: u32,
        stop_token_ids: Vec<u32>,
    ) -> Result<Self> {
        hellas_client::execution::validate_causal_lm_invocation(
            &environment,
            &input_ids,
            max_new_tokens,
            &stop_token_ids,
        )
        .map_err(|e| invalid(e.to_string()))?;
        Self::new(
            price,
            JobInput::CausalLm {
                environment,
                input_ids,
                max_new_tokens,
                stop_token_ids,
            },
        )
    }

    fn new(price: u64, input: JobInput) -> Result<Self> {
        if price == 0 || price > i64::MAX as u64 {
            return Err(invalid("payment price must be a positive TOML integer"));
        }
        Ok(Self { price, input })
    }
    pub fn price(&self) -> u64 {
        self.price
    }
    pub fn input(&self) -> &JobInput {
        &self.input
    }
    pub fn assurance(&self) -> Assurance {
        match &self.input {
            JobInput::Fetch { assurance, .. } => *assurance,
            JobInput::CausalLm { .. } => Assurance::ProducerSigned,
        }
    }
    pub fn manifest(&self) -> ProgramManifest {
        match &self.input {
            JobInput::Fetch { contract, .. } => contract.manifest(),
            JobInput::CausalLm { environment, .. } => environment.manifest(),
        }
    }

    /// Check unsigned application constraints before asking the owner to fund.
    pub fn check_policy(
        &self,
        policy: &hellas_work::model::setup::ProviderChannelPolicy,
    ) -> Result<()> {
        use hellas_work::model::{fetch::FetchRoutePolicy, profile::WorkPolicy};
        if self.price != policy.payment_policy.fixed_price {
            return Err(invalid(format!(
                "provider charges {} per job; this job says {}. Nothing was signed or paid.",
                policy.payment_policy.fixed_price, self.price
            )));
        }
        if self.manifest().content_id() != policy.work_policy.allowed_environment() {
            return Err(invalid(
                "application is not admitted by this provider. Nothing was signed or paid.",
            ));
        }
        if !matches!(
            (&self.input, &policy.work_policy),
            (JobInput::Fetch { .. }, WorkPolicy::Fetch { .. })
                | (JobInput::CausalLm { .. }, WorkPolicy::Evaluate(_))
        ) {
            return Err(invalid(
                "application profile is not admitted. Nothing was signed or paid.",
            ));
        }
        if let (
            JobInput::CausalLm {
                input_ids,
                max_new_tokens,
                stop_token_ids,
                ..
            },
            WorkPolicy::Evaluate(expected),
        ) = (&self.input, &policy.work_policy)
        {
            use hellas_rpc::protocol::artifacts::{
                BoundTermId, Canonical as _, TextArtifact, TextPolicy,
            };
            let generation =
                TextPolicy::from_u32_stop_tokens(*max_new_tokens, stop_token_ids.clone());
            let identity = TextArtifact::identity(BoundTermId::from_digest(
                self.manifest().content_id().digest(),
            ));
            if !hellas_work::model::work::matches_generation_policy(expected, &generation)?
                || hellas_work::model::work::identity_source_digest(&identity.canonical_bytes())?
                    != expected.identity_source_digest
            {
                return Err(invalid(
                    "generation or identity policy is not admitted. Nothing was signed or paid.",
                ));
            }
            if input_ids.len() > expected.max_prompt_tokens as usize
                || generation.stop_token_ids().len() > usize::from(expected.max_stop_token_ids)
            {
                return Err(invalid(
                    "prompt or stop-token count exceeds the provider's limit. Nothing was paid.",
                ));
            }
        }
        if let (
            JobInput::Fetch {
                contract,
                service,
                method,
                request,
                ..
            },
            WorkPolicy::Fetch { policy, route, .. },
        ) = (&self.input, &policy.work_policy)
        {
            if request.len() > policy.max_request_body_bytes as usize {
                return Err(invalid(
                    "request exceeds the provider's byte limit. Nothing was paid.",
                ));
            }
            match route {
                FetchRoutePolicy::SealedRoute {
                    service: expected_service,
                    method: expected_method,
                } if service != expected_service || method != expected_method => {
                    return Err(invalid(
                        "route is not admitted. Nothing was signed or paid.",
                    ));
                }
                FetchRoutePolicy::OpenFetch {
                    require_spki_pin,
                    allowed_hosts,
                } => {
                    let request = hellas_rpc::http_fetch::HttpFetchRequest::decode(request)
                        .map_err(|error| invalid(error.to_string()))?;
                    let url = request
                        .parsed_url()
                        .map_err(|error| invalid(error.to_string()))?;
                    if (*require_spki_pin && request.tls.spki_sha256.is_empty())
                        || (!allowed_hosts.is_empty()
                            && !allowed_hosts
                                .iter()
                                .any(|h| Some(h.as_str()) == url.host_str()))
                    {
                        return Err(invalid(
                            "host or SPKI pin is not admitted. Nothing was signed or paid.",
                        ));
                    }
                    if u64::from(request.max_response_bytes)
                        > u64::from(policy.max_output_bytes) / 4 * 3
                    {
                        return Err(invalid(
                            "response cap exceeds the provider's output limit. Nothing was paid.",
                        ));
                    }
                }
                _ => {}
            }
            if let hellas_rpc::FetchEgress::FixedHttps(url) = contract.egress() {
                let request = hellas_rpc::http_fetch::HttpFetchRequest::decode(request)
                    .map_err(|error| invalid(error.to_string()))?;
                if &request.url != url {
                    return Err(invalid(
                        "URL differs from the contract endpoint. Nothing was signed or paid.",
                    ));
                }
            }
        }
        // Keys and compact signatures have fixed encoded widths. Fetch's nonce
        // payload is an integer array, so all-255 measures its largest encoding
        // (at most 32 bytes above a particular purchase). The throwaway key
        // authorizes nothing with the requester's identity.
        let encoded = self
            .prepare(&ProducerSigningKey::generate(), [255; 32])?
            .encode()?;
        let limit = match &policy.work_policy {
            WorkPolicy::Evaluate(policy) => {
                u64::from(policy.max_encoded_prepared_input).min(policy.max_upload_bytes)
            }
            WorkPolicy::Fetch { policy, .. } => {
                u64::from(policy.max_encoded_prepared_input).min(policy.max_upload_bytes)
            }
        };
        if encoded.len() as u64 > limit {
            return Err(invalid(
                "prepared input exceeds the provider's byte limit. Nothing was paid.",
            ));
        }
        Ok(())
    }

    /// Canonical semantic content: neither filenames nor purchase randomness
    /// can change a reusable job's identity.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let bytes = match &self.input {
            JobInput::Fetch {
                contract,
                service,
                method,
                request,
                assurance,
            } => hellas_rpc::canonical_dag_cbor(&(
                FORMAT,
                self.price,
                "fetch",
                serde_bytes::Bytes::new(&contract.canonical_bytes()),
                service,
                method,
                assurance.to_byte(),
                serde_bytes::Bytes::new(request),
            )),
            JobInput::CausalLm {
                environment,
                input_ids,
                max_new_tokens,
                stop_token_ids,
            } => hellas_rpc::canonical_dag_cbor(&(
                FORMAT,
                self.price,
                "causal_lm",
                serde_bytes::Bytes::new(&environment.canonical_bytes()),
                input_ids,
                max_new_tokens,
                stop_token_ids,
            )),
        };
        bytes.expect("job contains only supported canonical strings, integers and bytes")
    }
    pub fn digest(&self) -> Digest {
        hash_tuple(FORMAT, &[&self.canonical_bytes()])
    }
    pub fn purchase_nonce(&self, channel: Digest, proposal_nonce: u64) -> [u8; 32] {
        *hash_tuple(
            "hellas.job.purchase.v1",
            &[
                self.digest().as_bytes(),
                channel.as_bytes(),
                &proposal_nonce.to_be_bytes(),
            ],
        )
        .as_bytes()
    }
    pub fn prepare(&self, key: &ProducerSigningKey, nonce: [u8; 32]) -> Result<PreparedWorkInput> {
        match &self.input {
            JobInput::Fetch {
                contract,
                service,
                method,
                request,
                assurance,
            } => {
                let events = hellas_rpc::fetch::build_input_events_with_nonce(
                    service,
                    method,
                    request,
                    contract.manifest_id(),
                    *assurance,
                    key,
                    hellas_rpc::Retention::Ephemeral,
                    nonce,
                )?;
                Ok(PreparedWorkInput::Fetch(PreparedPaidFetchInputV1::new(
                    &events, contract,
                )?))
            }
            JobInput::CausalLm {
                environment,
                input_ids,
                max_new_tokens,
                stop_token_ids,
            } => Ok(PreparedWorkInput::Evaluate(
                crate::gateway_work::prepare_evaluate_with_nonce(
                    hellas_gateway::WorkExecutionRequest {
                        environment: environment.clone(),
                        input_ids: input_ids.clone(),
                        max_new_tokens: *max_new_tokens,
                        stop_token_ids: stop_token_ids.clone(),
                    },
                    match key.public_key() {
                        public @ PublicKey::Secp256k1(_) => public,
                        _ => return Err(invalid("job signer must be secp256k1")),
                    },
                    nonce,
                )?,
            )),
        }
    }

    pub fn load(root: &Path) -> Result<Self> {
        let directory = hellas_private::ReadDirectory::open(root)?;
        let read = |name: &str, limit| directory.read(Path::new(name), limit);
        let bytes = read("job.toml", MAX_DOCUMENT_BYTES)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid("job.toml must be UTF-8"))?;
        let doc: Document = toml::from_str(text)?;
        if doc.format != FORMAT {
            return Err(invalid("unsupported job format"));
        }
        let job = match (doc.fetch, doc.causal_lm) {
            (Some(fetch), None) => {
                let contract = serde_json::from_slice(&read(
                    &fetch.contract,
                    hellas_rpc::protocol::fetch_contract::MAX_FETCH_CONTRACT_BYTES,
                )?)?;
                let assurance = match fetch.assurance.as_str() {
                    "producer-signed" => Assurance::ProducerSigned,
                    "apple-app-attest" => Assurance::AppleAppAttest,
                    _ => return Err(invalid("unknown assurance")),
                };
                Self::fetch(
                    doc.payment.price,
                    contract,
                    fetch.service,
                    fetch.method,
                    read(
                        &fetch.request,
                        hellas_rpc::fetch::MAX_FETCH_REQUEST_BODY_BYTES,
                    )?,
                    assurance,
                )?
            }
            (None, Some(causal)) => {
                let environment = CausalLmEnvironment::from_canonical_bytes(&read(
                    &causal.environment,
                    hellas_rpc::MAX_CAUSAL_LM_ENVIRONMENT_BYTES,
                )?)
                .map_err(|e| invalid(e.to_string()))?;
                let tokens = serde_json::from_slice(&read(
                    &causal.tokens,
                    hellas_rpc::fetch::MAX_FETCH_REQUEST_BODY_BYTES,
                )?)?;
                Self::causal_lm(
                    doc.payment.price,
                    environment,
                    tokens,
                    causal.max_new_tokens,
                    causal.stop_token_ids,
                )?
            }
            _ => return Err(invalid("job must contain exactly one application input")),
        };
        let manifest = job.manifest();
        let app = manifest.application();
        if doc.application.evaluator != app.evaluator() || doc.application.adaptor != app.adaptor()
        {
            return Err(invalid(
                "application identity differs from its input manifest",
            ));
        }
        Ok(job)
    }

    /// Writes caller-owned input, with the manifest published last. Existing
    /// folders are reused only when they already describe this exact job.
    pub fn save(&self, root: &Path) -> Result<()> {
        if root.exists() && std::fs::read_dir(root)?.next().is_some() {
            if Self::load(root)?.canonical_bytes() == self.canonical_bytes() {
                return Ok(());
            }
            return Err(invalid("destination contains a different job"));
        }
        hellas_private::create_dir_all_durable(root)?;
        let write = |name: &str, bytes: &[u8]| {
            hellas_private::write_atomically(&root.join(name), ".writing", bytes)
        };
        let manifest = self.manifest();
        let app = manifest.application();
        let mut doc = Document {
            format: FORMAT.into(),
            application: Application {
                evaluator: app.evaluator().into(),
                adaptor: app.adaptor().into(),
            },
            payment: Payment { price: self.price },
            fetch: None,
            causal_lm: None,
        };
        match &self.input {
            JobInput::Fetch {
                contract,
                service,
                method,
                request,
                assurance,
            } => {
                write("contract.json", &serde_json::to_vec_pretty(contract)?)?;
                write("request.json", request)?;
                doc.fetch = Some(FetchFiles {
                    contract: "contract.json".into(),
                    service: service.clone(),
                    method: method.clone(),
                    request: "request.json".into(),
                    assurance: match assurance {
                        Assurance::ProducerSigned => "producer-signed",
                        Assurance::AppleAppAttest => "apple-app-attest",
                    }
                    .into(),
                });
            }
            JobInput::CausalLm {
                environment,
                input_ids,
                max_new_tokens,
                stop_token_ids,
            } => {
                write("model.environment", &environment.canonical_bytes())?;
                write("tokens.json", &serde_json::to_vec(input_ids)?)?;
                doc.causal_lm = Some(CausalLmFiles {
                    environment: "model.environment".into(),
                    tokens: "tokens.json".into(),
                    max_new_tokens: *max_new_tokens,
                    stop_token_ids: stop_token_ids.clone(),
                });
            }
        }
        write("job.toml", toml::to_string_pretty(&doc)?.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
