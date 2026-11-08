//! Caller-owned job folders. Purchase nonces derive from durable channel state.
use hellas_auth::{Digest, ProducerSigningKey, PublicKey, hash_tuple};
use hellas_rpc::{
    Assurance, ContentRef, FetchContract, JsonBytes, ProgramManifest,
    protocol::invocation::{
        Artifact, InvocationInput, InvocationPolicy, InvocationRequest, PreparedInvocation,
        compute, fetch,
    },
};
use hellas_store::content::{LocalStore, MemoryStore, Reservations, Scope};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, sync::Arc};

pub const FORMAT: &str = "hellas.job.v1";
// Model plans name hundreds of weight views; their TOML exceeds 64 KiB.
const MAX_DOCUMENT_BYTES: usize = 1 << 20;
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
    Content(#[from] hellas_store::content::Error),
}
type Result<T> = std::result::Result<T, JobError>;
fn invalid(message: impl Into<String>) -> JobError {
    JobError::Invalid(message.into())
}

#[derive(Clone)]
pub struct Job {
    price: u64,
    input: Arc<JobInput>,
    manifest: ProgramManifest,
}
#[derive(Clone)]
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
        content: Arc<(LocalStore, Scope)>,
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
    /// Stable semantic identity for caller-owned attempt tracking. Paths and
    /// invocation randomness are deliberately excluded.
    pub fn tracking_digest(&self) -> Digest {
        let bytes = match self {
            Self::Fetch {
                contract,
                service,
                method,
                request,
                assurance,
            } => hellas_rpc::canonical_dag_cbor(&(
                "fetch",
                serde_bytes::Bytes::new(&contract.canonical_bytes()),
                service,
                method,
                assurance.to_byte(),
                serde_bytes::Bytes::new(request),
            )),
            Self::Compute {
                environment,
                plan,
                inputs,
                ..
            } => hellas_rpc::canonical_dag_cbor(&("compute", environment, plan, inputs)),
        }
        .expect("job input contains only canonical strings, integers and bytes");
        hash_tuple("hellas.work.attempt.input.v1", &[&bytes])
    }
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
                ..
            } => {
                let manifest = environment.manifest()?;
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
    pub fn content(&self) -> (LocalStore, Scope) {
        match self {
            JobInput::Compute { content, .. } => content.as_ref().clone(),
            JobInput::Fetch { .. } => (
                LocalStore::Memory(MemoryStore::new(Reservations::ram(
                    hellas_channel::content::DEFAULT_MAX_STAGING_BYTES,
                ))),
                Scope::Owner,
            ),
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
        if price > i64::MAX as u64 {
            return Err(invalid("payment price must be a non-negative TOML integer"));
        }
        let manifest = input.manifest()?;
        Ok(Self {
            price,
            input: Arc::new(input),
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
    pub async fn compute(
        price: u64,
        environment: compute::Environment,
        plan: compute::Plan,
        inputs: Vec<Artifact>,
        content: (LocalStore, Scope),
    ) -> Result<Self> {
        let job = Self::from_input(
            price,
            JobInput::Compute {
                environment,
                plan,
                inputs,
                content: Arc::new(content),
            },
        )?;
        job.validate_content().await?;
        Ok(job)
    }
    /// Validate the exact local environment before any funding or proposal.
    pub async fn validate_content(&self) -> Result<()> {
        if let JobInput::Compute {
            environment,
            content,
            ..
        } = self.input.as_ref()
        {
            let expected = environment.canonical_bytes()?;
            let bytes =
                hellas_channel::content::root(&content.0, &content.1, self.manifest.root()).await?;
            if bytes.as_ref() != expected {
                return Err(invalid(
                    "compute content does not open the environment root",
                ));
            }
        }
        Ok(())
    }
    pub fn price(&self) -> u64 {
        self.price
    }
    pub fn input(&self) -> &JobInput {
        &self.input
    }
    pub fn assurance(&self) -> Assurance {
        match self.input.as_ref() {
            JobInput::Fetch { assurance, .. } => *assurance,
            JobInput::Compute { .. } => Assurance::ProducerSigned,
        }
    }
    pub fn manifest(&self) -> ProgramManifest {
        self.manifest.clone()
    }
    pub fn content(&self) -> (LocalStore, Scope) {
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
        let bytes = match self.input.as_ref() {
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
        purchase_nonce(self.digest(), channel, proposal_nonce, None)
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
    pub async fn load(root: &Path) -> Result<Self> {
        let root = root.to_owned();
        let directory = Arc::new(
            tokio::task::spawn_blocking(move || hellas_private::ReadDirectory::open(&root))
                .await
                .map_err(|error| invalid(error.to_string()))??,
        );
        let read = async |name: &str, maximum| {
            let directory = directory.clone();
            let name = name.to_owned();
            tokio::task::spawn_blocking(move || directory.read(Path::new(&name), maximum))
                .await
                .map_err(|error| invalid(error.to_string()))?
                .map_err(JobError::from)
        };
        let bytes = read("job.toml", MAX_DOCUMENT_BYTES).await?;
        let doc: Document = toml::from_str(
            std::str::from_utf8(&bytes).map_err(|_| invalid("job.toml must be UTF-8"))?,
        )?;
        if doc.format != FORMAT {
            return Err(invalid("unsupported job format"));
        }
        let job = match (doc.fetch, doc.compute) {
            (Some(fetch), None) => {
                let contract = serde_json::from_slice(
                    &read(
                        &fetch.contract,
                        hellas_rpc::protocol::fetch_contract::MAX_FETCH_CONTRACT_BYTES,
                    )
                    .await?,
                )?;
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
                    )
                    .await?,
                    assurance,
                )?
            }
            (None, Some(compute)) => {
                let bytes = read(&compute.environment, compute::MAX_ENVIRONMENT_BYTES).await?;
                let environment = compute::Environment::from_canonical_bytes(&bytes)?;
                let content = (
                    LocalStore::Memory(MemoryStore::new(Reservations::ram(
                        hellas_channel::content::DEFAULT_MAX_STAGING_BYTES,
                    ))),
                    Scope::Owner,
                );
                hellas_channel::content::upload_object(&content.0, &bytes).await?;
                for file in compute.objects {
                    use hellas_store::content::ContentStore;
                    // Admission precedes even opening an attacker-declared large object.
                    let mut upload = content
                        .0
                        .upload(
                            &content.1,
                            file.object,
                            Some(hellas_channel::content::object_pin(file.object)?),
                        )
                        .await?;
                    if !upload.complete() {
                        let directory = directory.clone();
                        let reader = tokio::task::spawn_blocking(move || {
                            directory.open_file(Path::new(&file.path))
                        })
                        .await
                        .map_err(|error| invalid(error.to_string()))??;
                        upload.copy_from(reader, &content.0.ram_pool()).await?;
                    }
                }
                let mut inputs = Vec::new();
                let mut remaining = hellas_rpc::protocol::invocation::MAX_INVOCATION_BYTES;
                for file in compute.inputs {
                    let bytes = read(&file.path, remaining).await?;
                    remaining = remaining
                        .checked_sub(bytes.len())
                        .ok_or_else(|| invalid("input byte limit"))?;
                    inputs.push(Artifact::new(file.name, file.format, bytes));
                }
                Self::compute(
                    doc.payment.price,
                    environment,
                    compute.plan,
                    inputs,
                    content,
                )
                .await?
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
    pub async fn save(&self, root: &Path) -> Result<()> {
        self.validate_content().await?;
        let root = root.to_owned();
        let check = root.clone();
        let occupied = tokio::task::spawn_blocking(move || -> std::io::Result<bool> {
            Ok(check.exists() && std::fs::read_dir(check)?.next().is_some())
        })
        .await
        .map_err(|error| invalid(error.to_string()))??;
        if occupied {
            if Self::load(&root).await?.canonical_bytes() == self.canonical_bytes() {
                return Ok(());
            }
            return Err(invalid("destination contains a different job"));
        }
        let mut readers = Vec::new();
        if let JobInput::Compute {
            environment,
            content,
            ..
        } = self.input.as_ref()
        {
            let mut objects = BTreeMap::new();
            for object in environment
                .sources
                .iter()
                .copied()
                .chain(environment.assets.iter().map(|asset| asset.object))
            {
                objects.insert(object.id(), object);
            }
            for object in objects.into_values() {
                match content.0.open_verified(&content.1, object, None).await? {
                    Some(reader) => readers.push((object, reader)),
                    None if !environment.sources.contains(&object) => {}
                    None => return Err(hellas_store::content::Error::Missing.into()),
                }
            }
        }
        let job = self.clone();
        tokio::task::spawn_blocking(move || job.save_sync(&root, readers))
            .await
            .map_err(|error| invalid(error.to_string()))?
    }
    fn save_sync(
        &self,
        root: &Path,
        readers: Vec<(ContentRef, hellas_store::content::VerifiedReader)>,
    ) -> Result<()> {
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
        match self.input.as_ref() {
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
                ..
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
                let mut object_files = Vec::new();
                for (i, (object, mut reader)) in readers.into_iter().enumerate() {
                    use std::io::{Read, Write};
                    let path = format!("object-{i}.bin");
                    let mut output = tempfile::NamedTempFile::new_in(root)?;
                    let mut hash = hellas_xet::XetFileHasher::new();
                    let mut remaining = object.bytes();
                    let mut scratch = vec![0; hellas_xet::MAX_CHUNK_SIZE];
                    while remaining != 0 {
                        let count = remaining.min(scratch.len() as u64) as usize;
                        reader.read_exact(&mut scratch[..count])?;
                        hash.update(&scratch[..count]);
                        output.write_all(&scratch[..count])?;
                        remaining -= count as u64;
                    }
                    if reader.read(&mut [0])? != 0
                        || hellas_xet::file_hash(&hash.finalize_chunks()) != object.id().digest()
                    {
                        return Err(invalid("job content changed while saving"));
                    }
                    output.as_file().sync_all()?;
                    output
                        .persist(root.join(&path))
                        .map_err(|error| error.error)?;
                    hellas_private::sync_directory(root)?;
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
        let document = toml::to_string_pretty(&doc)?;
        if document.len() > MAX_DOCUMENT_BYTES {
            return Err(invalid("job.toml exceeds document limit"));
        }
        write("job.toml", document.as_bytes())?;
        Ok(())
    }
}

pub(crate) fn purchase_nonce(
    job: Digest,
    channel: Digest,
    proposal_nonce: u64,
    attempt: Option<&[u8; 32]>,
) -> [u8; 32] {
    let counter = proposal_nonce.to_be_bytes();
    let fields = [
        job.as_bytes().as_slice(),
        channel.as_bytes().as_slice(),
        &counter,
    ];
    *match attempt {
        Some(attempt) => hash_tuple(
            "hellas.job.attempt.v1",
            &[fields[0], fields[1], fields[2], attempt],
        ),
        None => hash_tuple("hellas.job.purchase.v1", &fields),
    }
    .as_bytes()
}
#[cfg(test)]
mod tests;
