//! Caller-owned job folders. Purchase nonces derive from durable channel state.
use hellas_auth::{Digest, ProducerSigningKey, PublicKey, hash_tuple};
use hellas_channel::content::{EphemeralContent, InvocationContent};
use hellas_rpc::{
    Assurance, ContentRef, FetchContract, JsonBytes, ProgramManifest,
    protocol::invocation::{
        Artifact, InvocationInput, InvocationPolicy, InvocationRequest, PreparedInvocation,
        compute, fetch,
    },
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

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
    Content(#[from] hellas_channel::content::ContentError),
}
type Result<T> = std::result::Result<T, JobError>;
fn invalid(message: impl Into<String>) -> JobError {
    JobError::Invalid(message.into())
}

#[derive(Clone, Debug)]
pub struct Job {
    price: u64,
    input: JobInput,
    manifest: ProgramManifest,
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
    Compute {
        environment: compute::Environment,
        plan: compute::Plan,
        inputs: Vec<Artifact>,
        content: InvocationContent,
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
    compute: Option<ComputeFiles>,
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
struct ComputeFiles {
    environment: String,
    plan: compute::Plan,
    inputs: Vec<FileArtifact>,
    objects: Vec<ContentFile>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileArtifact {
    name: String,
    format: String,
    path: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContentFile {
    object: ContentRef,
    path: String,
}

impl JobInput {
    /// Checks the input's own bounds and returns its program manifest.
    pub fn manifest(&self) -> Result<ProgramManifest> {
        Ok(match self {
            JobInput::Fetch {
                contract,
                service,
                method,
                request,
                ..
            } => {
                if service.is_empty()
                    || method.is_empty()
                    || service.len() > hellas_rpc::fetch::MAX_FETCH_ROUTE_COMPONENT_BYTES
                    || method.len() > hellas_rpc::fetch::MAX_FETCH_ROUTE_COMPONENT_BYTES
                {
                    return Err(invalid(
                        "Fetch route components must be nonempty and bounded",
                    ));
                }
                if request.len() > hellas_rpc::fetch::MAX_FETCH_REQUEST_BODY_BYTES {
                    return Err(invalid("Fetch request exceeds byte limit"));
                }
                serde_json::from_slice::<serde_json::Value>(request)?;
                if contract.schema() == hellas_rpc::FetchSchema::HttpV1 {
                    hellas_rpc::http_fetch::HttpFetchRequest::decode(request)
                        .map_err(|e| invalid(e.to_string()))?;
                }
                contract.manifest()
            }
            JobInput::Compute {
                environment,
                plan,
                inputs,
                content,
            } => {
                let root = environment.canonical_bytes()?;
                let manifest = environment.manifest()?;
                if content
                    .read_bounded(manifest.root(), compute::MAX_ENVIRONMENT_BYTES as u64)?
                    .as_slice()
                    != root
                {
                    return Err(invalid(
                        "compute content does not open the environment root",
                    ));
                }
                InvocationInput {
                    parameters: JsonBytes(plan.canonical_bytes()?),
                    artifacts: inputs.clone(),
                }
                .validate()?;
                manifest
            }
        })
    }

    /// Builds the signed invocation for `runner` under `policy`. Paid jobs are
    /// retained by the provider; grant and local jobs are memory-only.
    pub fn prepare(
        &self,
        manifest: &ProgramManifest,
        key: &ProducerSigningKey,
        nonce: [u8; 32],
        runner: PublicKey,
        policy: &InvocationPolicy,
        retain: bool,
    ) -> Result<PreparedInvocation> {
        let prepared = match self {
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
                fetch::prepare(&events, contract, runner, policy.canonical_bytes()?, nonce)?
            }
            JobInput::Compute { plan, inputs, .. } => {
                let input = InvocationInput {
                    parameters: JsonBytes(plan.canonical_bytes()?),
                    artifacts: inputs.clone(),
                };
                let request = InvocationRequest {
                    execution_environment: manifest.content_id(),
                    input: input.content_id()?,
                    runner_public_key: runner,
                    nonce,
                    assurance: Assurance::ProducerSigned,
                    retain,
                };
                PreparedInvocation::new(request, manifest, input, policy.canonical_bytes()?)?
            }
        };
        policy.admit(&prepared, &key.public_key())?;
        Ok(prepared)
    }

    /// The content the provider reads; a Fetch carries none.
    pub fn content(&self) -> InvocationContent {
        match self {
            JobInput::Compute { content, .. } => content.clone(),
            JobInput::Fetch { .. } => InvocationContent::Ephemeral(EphemeralContent::default()),
        }
    }

    /// Whether `policy` admits this input within the provider's upload bound.
    /// Nothing is signed with the requester's identity.
    pub fn admits(&self, policy: &InvocationPolicy, retain: bool) -> Result<()> {
        let manifest = self.manifest()?;
        // The all-255 nonce measures the largest encoding; the throwaway key
        // authorizes nothing.
        let key = ProducerSigningKey::generate();
        let prepared =
            self.prepare(&manifest, &key, [255; 32], key.public_key(), policy, retain)?;
        if prepared.canonical_bytes()?.len() as u64 > policy.limits.max_upload_bytes {
            return Err(invalid(
                "prepared input exceeds the provider's upload limit. Nothing was paid.",
            ));
        }
        Ok(())
    }
}

impl Job {
    pub fn from_input(price: u64, input: JobInput) -> Result<Self> {
        if price == 0 || price > i64::MAX as u64 {
            return Err(invalid("payment price must be a positive TOML integer"));
        }
        let manifest = input.manifest()?;
        Ok(Self {
            price,
            input,
            manifest,
        })
    }
    pub fn fetch(
        price: u64,
        contract: FetchContract,
        service: String,
        method: String,
        request: Vec<u8>,
        assurance: Assurance,
    ) -> Result<Self> {
        Self::from_input(
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
    pub fn compute(
        price: u64,
        environment: compute::Environment,
        plan: compute::Plan,
        inputs: Vec<Artifact>,
        content: InvocationContent,
    ) -> Result<Self> {
        Self::from_input(
            price,
            JobInput::Compute {
                environment,
                plan,
                inputs,
                content,
            },
        )
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
            JobInput::Compute { .. } => Assurance::ProducerSigned,
        }
    }
    pub fn manifest(&self) -> ProgramManifest {
        self.manifest.clone()
    }
    pub fn content(&self) -> InvocationContent {
        self.input.content()
    }
    /// Check the quoted application before asking the owner to fund anything.
    pub fn check_policy(
        &self,
        policy: &hellas_channel::model::setup::ProviderChannelPolicy,
    ) -> Result<()> {
        if self.price != policy.payment_policy.fixed_price {
            return Err(invalid(format!(
                "provider charges {} per job; this job says {}. Nothing was signed or paid.",
                policy.payment_policy.fixed_price, self.price
            )));
        }
        self.input.admits(&policy.invocation_policy, true)
    }
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
            JobInput::Compute {
                environment,
                plan,
                inputs,
                ..
            } => hellas_rpc::canonical_dag_cbor(&(
                FORMAT,
                self.price,
                "compute",
                environment,
                plan,
                inputs,
            )),
        };
        bytes.expect("job contains only canonical strings, integers and bytes")
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
    pub fn prepare(
        &self,
        key: &ProducerSigningKey,
        nonce: [u8; 32],
        runner: PublicKey,
        policy: &InvocationPolicy,
    ) -> Result<PreparedInvocation> {
        self.input
            .prepare(&self.manifest, key, nonce, runner, policy, true)
    }
    pub fn load(root: &Path) -> Result<Self> {
        let directory = hellas_private::ReadDirectory::open(root)?;
        let read = |name: &str, limit| directory.read(Path::new(name), limit);
        let bytes = read("job.toml", MAX_DOCUMENT_BYTES)?;
        let doc: Document = toml::from_str(
            std::str::from_utf8(&bytes).map_err(|_| invalid("job.toml must be UTF-8"))?,
        )?;
        if doc.format != FORMAT {
            return Err(invalid("unsupported job format"));
        }
        let job = match (doc.fetch, doc.compute) {
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
            (None, Some(compute)) => {
                let bytes = read(&compute.environment, compute::MAX_ENVIRONMENT_BYTES)?;
                let environment = compute::Environment::from_canonical_bytes(&bytes)?;
                let mut content = EphemeralContent::default();
                content.insert(bytes);
                for file in compute.objects {
                    let bytes = read(
                        &file.path,
                        usize::try_from(file.object.bytes())
                            .map_err(|_| invalid("content length overflow"))?,
                    )?;
                    if content.insert(bytes) != file.object {
                        return Err(invalid("job content identity or length mismatch"));
                    }
                }
                let inputs = compute
                    .inputs
                    .into_iter()
                    .map(|file| {
                        Ok(Artifact::new(
                            file.name,
                            file.format,
                            read(
                                &file.path,
                                hellas_rpc::protocol::invocation::MAX_INVOCATION_BYTES,
                            )?,
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?;
                Self::compute(
                    doc.payment.price,
                    environment,
                    compute.plan,
                    inputs,
                    InvocationContent::Ephemeral(content),
                )?
            }
            _ => return Err(invalid("job must contain exactly one application input")),
        };
        let app = job.manifest.application();
        if doc.application.evaluator != app.evaluator() || doc.application.adaptor != app.adaptor()
        {
            return Err(invalid(
                "application identity differs from its input manifest",
            ));
        }
        Ok(job)
    }
    /// Publish job.toml after its caller-owned inputs. Reuse only an exact job.
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
        let app = self.manifest.application();
        let mut doc = Document {
            format: FORMAT.into(),
            application: Application {
                evaluator: app.evaluator().into(),
                adaptor: app.adaptor().into(),
            },
            payment: Payment { price: self.price },
            fetch: None,
            compute: None,
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
            JobInput::Compute {
                environment,
                plan,
                inputs,
                content,
            } => {
                write("environment.cbor", &environment.canonical_bytes()?)?;
                let mut files = Vec::new();
                for (i, artifact) in inputs.iter().enumerate() {
                    let path = format!("input-{i}.bin");
                    write(&path, artifact.bytes.as_bytes())?;
                    files.push(FileArtifact {
                        name: artifact.name.clone(),
                        format: artifact.format.clone(),
                        path,
                    });
                }
                let mut objects = BTreeMap::new();
                for object in environment
                    .sources
                    .iter()
                    .copied()
                    .chain(environment.assets.iter().map(|a| a.object))
                {
                    objects.insert(object.id(), object);
                }
                let mut object_files = Vec::new();
                for (i, object) in objects.into_values().enumerate() {
                    let path = format!("object-{i}.bin");
                    write(&path, &content.read(object)?)?;
                    object_files.push(ContentFile { object, path });
                }
                doc.compute = Some(ComputeFiles {
                    environment: "environment.cbor".into(),
                    plan: plan.clone(),
                    inputs: files,
                    objects: object_files,
                });
            }
        }
        write("job.toml", toml::to_string_pretty(&doc)?.as_bytes())?;
        Ok(())
    }
}
#[cfg(test)]
mod tests;
