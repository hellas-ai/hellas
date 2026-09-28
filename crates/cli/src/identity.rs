use anyhow::{Context, bail};
use hellas_attestation::{AssertionCounterStore, AttestationError};
use hellas_rpc::signature::verify_digest_signature;
use hellas_rpc::{
    DagCborDecoder, Digest, PlatformCredential, ProducerSigningKey, ProviderGenesisStatement,
    PublicKey, RootKind, RootProof, SignedProviderGenesis,
};
#[cfg(feature = "node")]
use hellas_rpc::{
    OPEN_NONCE_LEN,
    open::OpenHandler,
    open_proof_binding,
    pb::execute::{OpenRequest, OpenResponse, open_response},
    run_ticket::signature_to_pb,
};
use hellas_rpc::{PlatformEnrollment, ProviderEnrollmentBundle};
#[cfg(feature = "node")]
use hellas_wire::{TransportContext, WireCode, WireStatus};
use iroh::SecretKey;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const IDENTITY_DIR: &str = ".hellas";
const IDENTITY_FILE: &str = "identity";
const APPLE_OPEN_COUNTER_STORE_DIR: &str = "apple-app-attest-open-counters";
#[cfg(feature = "node")]
const ARTIFACT_STORE_DIR: &str = "artifacts";
const VERSION: u8 = 3;
const IDENTITY_TAG: &str = "hellas.provider.identity.persistence.v3";

/// Filesystem-backed assertion-counter high-water marks, keyed by public key.
#[derive(Clone, Debug)]
struct FilesystemAssertionCounterStore {
    directory: PathBuf,
}

impl FilesystemAssertionCounterStore {
    fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn counter_path(&self, public_key: &[u8; 33]) -> PathBuf {
        self.directory
            .join(format!("{}.counter", Self::key_name(public_key)))
    }

    fn lock_path(&self, public_key: &[u8; 33]) -> PathBuf {
        self.directory
            .join(format!("{}.counter.lock", Self::key_name(public_key)))
    }

    fn key_name(public_key: &[u8; 33]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = String::with_capacity(public_key.len() * 2);
        for byte in public_key {
            name.push(HEX[(byte >> 4) as usize] as char);
            name.push(HEX[(byte & 0xf) as usize] as char);
        }
        name
    }
}

impl AssertionCounterStore for FilesystemAssertionCounterStore {
    fn advance(&self, public_key: &[u8; 33], counter: u32) -> Result<(), AttestationError> {
        create_dir_restricted(&self.directory).map_err(|_| AttestationError::State)?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.lock_path(public_key))
            .map_err(|_| AttestationError::State)?;
        fs::File::lock(&lock).map_err(|_| AttestationError::State)?;

        let counter_path = self.counter_path(public_key);
        let previous = match fs::read(&counter_path) {
            Ok(stored) => match stored.as_slice() {
                [a, b, c, d] => u32::from_be_bytes([*a, *b, *c, *d]),
                _ => return Err(AttestationError::State),
            },
            Err(error) if error.kind() == ErrorKind::NotFound => 0,
            Err(_) => return Err(AttestationError::State),
        };
        if counter <= previous {
            return Err(AttestationError::Counter);
        }

        let mut temp = tempfile::NamedTempFile::new_in(&self.directory)
            .map_err(|_| AttestationError::State)?;
        #[cfg(unix)]
        temp.as_file()
            .set_permissions({
                use std::os::unix::fs::PermissionsExt;
                fs::Permissions::from_mode(0o600)
            })
            .map_err(|_| AttestationError::State)?;
        temp.write_all(&counter.to_be_bytes())
            .map_err(|_| AttestationError::State)?;
        temp.flush().map_err(|_| AttestationError::State)?;
        temp.as_file()
            .sync_all()
            .map_err(|_| AttestationError::State)?;
        temp.persist(&counter_path)
            .map_err(|_| AttestationError::State)?;
        #[cfg(unix)]
        fs::File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| AttestationError::State)?;
        Ok(())
    }
}

pub(crate) struct LocalIdentity {
    pub(crate) transport_key: SecretKey,
    pub(crate) producer_key: ProducerSigningKey,
    #[cfg(any(feature = "node", test))]
    pub(crate) genesis: SignedProviderGenesis,
    pub(crate) enrollment: ProviderEnrollmentBundle,
    #[cfg(feature = "node")]
    open_identity: Arc<OpenIdentity>,
}

#[cfg(feature = "node")]
pub(crate) struct OpenIdentity {
    signer: OpenSigner,
    enrollment: ProviderEnrollmentBundle,
}

#[cfg(feature = "node")]
#[derive(Clone)]
enum OpenSigner {
    Software(ProducerSigningKey),
}

struct StoredIdentity {
    version: u8,
    root: StoredRoot,
    producer_key: [u8; 32],
    transport_key: [u8; 32],
    enrollment: ProviderEnrollmentBundle,
}

enum StoredRoot {
    Software([u8; 32]),
}

enum PlatformRoot {
    Software(ProducerSigningKey),
}

impl PlatformRoot {
    fn prove(&self, statement: &[u8]) -> anyhow::Result<RootProof> {
        match self {
            Self::Software(key) => Ok(RootProof::Software(
                key.sign_digest(Digest::hash(statement))?,
            )),
        }
    }
}

#[cfg(feature = "node")]
impl OpenIdentity {
    async fn proof(&self, binding: Digest) -> Result<RootProof, WireStatus> {
        match &self.signer {
            // Software enrollment authenticates the producer key once; the
            // producer then proves each live transport binding.
            OpenSigner::Software(key) => {
                key.sign_digest(binding)
                    .map(RootProof::Software)
                    .map_err(|error| {
                        tracing::warn!(%error, "confidential open proof generation failed");
                        WireStatus::internal("confidential open proof generation failed")
                    })
            }
        }
    }
}

#[cfg(feature = "node")]
impl OpenHandler for OpenIdentity {
    async fn open(
        &self,
        request: OpenRequest,
        context: TransportContext,
        alpn: &'static [u8],
    ) -> Result<OpenResponse, WireStatus> {
        let nonce: [u8; OPEN_NONCE_LEN] = request.nonce.try_into().map_err(|bytes: Vec<u8>| {
            WireStatus::new(
                WireCode::InvalidArgument,
                format!(
                    "confidential open nonce must be {OPEN_NONCE_LEN} bytes, got {}",
                    bytes.len()
                ),
            )
        })?;
        let exporter = context.open_exporter.ok_or_else(|| {
            WireStatus::new(
                WireCode::FailedPrecondition,
                "transport does not expose a confidential-open exporter",
            )
        })?;
        let binding = open_proof_binding(
            &exporter,
            &nonce,
            &self.enrollment.genesis.statement.producer_public_key,
            self.enrollment.content_id(),
            alpn,
        );
        let proof = match self.proof(binding).await? {
            RootProof::Software(signature) => {
                open_response::Proof::ProducerSignature(signature_to_pb(&signature))
            }
            RootProof::AppleAppAttest(assertion) => {
                open_response::Proof::AppleAppAttestAssertion(assertion)
            }
        };
        Ok(OpenResponse {
            provider_genesis: self.enrollment.canonical_bytes(),
            proof: Some(proof),
        })
    }
}

#[cfg(feature = "node")]
impl LocalIdentity {
    pub(crate) fn open_identity(&self) -> Arc<OpenIdentity> {
        self.open_identity.clone()
    }
}

#[cfg(feature = "node")]
fn build_open_identity(
    root: &Arc<PlatformRoot>,
    producer_key: &ProducerSigningKey,
    enrollment: &ProviderEnrollmentBundle,
) -> Arc<OpenIdentity> {
    let signer = match root.as_ref() {
        // The enrollment root authenticates the producer once. It is not an
        // online software key and must not survive identity materialization.
        PlatformRoot::Software(_) => OpenSigner::Software(producer_key.clone()),
    };
    Arc::new(OpenIdentity {
        signer,
        enrollment: enrollment.clone(),
    })
}

pub(crate) fn load_or_create(path: Option<&Path>) -> anyhow::Result<LocalIdentity> {
    let path = path
        .map(Path::to_owned)
        .map(Ok)
        .unwrap_or_else(default_path)?;
    match fs::read(&path) {
        Ok(bytes) => decode(&path, &bytes),
        Err(error) if error.kind() == ErrorKind::NotFound => create(&path),
        Err(error) => {
            Err(error).with_context(|| format!("failed to read identity file {}", path.display()))
        }
    }
}

/// The key this identity settles a paid channel with.
///
/// Not a second key and not a new one: the provider's on-chain party key
/// *is* its producer identity, one secp256k1 scalar read through two
/// primitive crates ([`hellas_executor::kernel_signer`]). So `identity
/// init` is where an operator's settlement key comes from, and there is
/// nothing here that could invent one — a party nobody has funded stakes
/// no bond and settles no channel.
#[cfg(feature = "node")]
pub(crate) fn settlement_signer(identity: &LocalIdentity) -> hellas_kernel::Secp256k1Signer {
    hellas_executor::kernel_signer(&identity.producer_key)
}

pub(crate) fn load_existing(path: Option<&Path>) -> anyhow::Result<LocalIdentity> {
    let path = path
        .map(Path::to_owned)
        .map(Ok)
        .unwrap_or_else(default_path)?;
    let bytes = fs::read(&path)
        .with_context(|| format!("failed to read identity file {}", path.display()))?;
    decode(&path, &bytes)
}

fn default_path() -> anyhow::Result<PathBuf> {
    default_hellas_path(IDENTITY_FILE, "--identity")
}

#[cfg(feature = "gateway")]
pub(crate) fn default_gateway_archive_path() -> anyhow::Result<PathBuf> {
    default_hellas_path("gateway-archive", "--archive-dir")
}

#[cfg(feature = "node")]
pub(crate) fn default_artifact_store_path() -> anyhow::Result<PathBuf> {
    default_hellas_path(ARTIFACT_STORE_DIR, "--artifact-store-path")
}

pub(crate) fn provider_trust(
    expected_genesis: Option<hellas_rpc::ContentId>,
    required_assurance: hellas_rpc::Assurance,
    app_id: Option<String>,
    allowed_cd_hashes: Vec<[u8; 32]>,
) -> anyhow::Result<hellas_client::ProviderTrustAnchor> {
    let expected_genesis =
        expected_genesis.context("remote execution requires --provider <content-id>")?;
    let apple_app_attest = match (app_id, allowed_cd_hashes.is_empty()) {
        (None, true) if required_assurance == hellas_rpc::Assurance::ProducerSigned => None,
        (Some(app_id), false) => Some(hellas_client::AppleAppAttestTrust::new(
            app_id,
            allowed_cd_hashes,
            Arc::new(FilesystemAssertionCounterStore::new(default_hellas_path(
                APPLE_OPEN_COUNTER_STORE_DIR,
                "--apple-app-attest-cdhashes",
            )?)),
        )),
        (None, _) => {
            bail!("Apple App Attest trust requires --apple-app-attest-app-id <team-id.bundle-id>")
        }
        (Some(_), true) => {
            bail!("Apple App Attest trust requires --apple-app-attest-cdhashes <hex>")
        }
    };
    Ok(hellas_client::ProviderTrustAnchor {
        expected_genesis,
        required_assurance,
        apple_app_attest,
    })
}

fn default_hellas_path(file: &str, flag: &str) -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").with_context(|| {
        format!("HOME environment variable not set; use {flag} to specify path")
    })?;
    Ok(PathBuf::from(home).join(IDENTITY_DIR).join(file))
}

fn create_root(_installation_nonce: [u8; 32]) -> anyhow::Result<PlatformRoot> {
    Ok(PlatformRoot::Software(ProducerSigningKey::generate()))
}

fn create(path: &Path) -> anyhow::Result<LocalIdentity> {
    let producer_key = ProducerSigningKey::generate();
    let transport_key = SecretKey::generate();
    let installation_nonce = rand::random();
    let root = Arc::new(create_root(installation_nonce)?);
    let statement = statement(&root, &producer_key, &transport_key, installation_nonce);
    let genesis = SignedProviderGenesis {
        root_proof: root.prove(&statement.canonical_bytes())?,
        statement,
    };
    let enrollment = enrollment_bundle(&root, genesis.clone());
    let stored_root = match root.as_ref() {
        PlatformRoot::Software(key) => StoredRoot::Software(key.to_secret_bytes()),
    };
    let stored = StoredIdentity {
        version: VERSION,
        root: stored_root,
        producer_key: producer_key.to_secret_bytes(),
        transport_key: transport_key.to_bytes(),
        enrollment: enrollment.clone(),
    };
    #[cfg(feature = "node")]
    let open_identity = build_open_identity(&root, &producer_key, &enrollment);
    let identity = LocalIdentity {
        transport_key,
        producer_key,
        #[cfg(any(feature = "node", test))]
        genesis,
        enrollment,
        #[cfg(feature = "node")]
        open_identity,
    };
    if !persist(path, &stored)? {
        return load_existing(Some(path));
    }
    info!(
        node_id = %identity.transport_key.public(),
        producer_id = ?identity.producer_key.producer_id(),
        path = %path.display(),
        "created provider identity"
    );
    Ok(identity)
}

fn materialize(stored: &StoredIdentity) -> anyhow::Result<LocalIdentity> {
    if stored.version != VERSION {
        bail!("unsupported identity version {}", stored.version);
    }
    let root = Arc::new(match &stored.root {
        StoredRoot::Software(secret) => PlatformRoot::Software(
            ProducerSigningKey::from_secret_bytes(*secret).context("invalid software root key")?,
        ),
    });
    let producer_key = ProducerSigningKey::from_secret_bytes(stored.producer_key)
        .context("invalid producer key")?;
    let transport_key = SecretKey::from(stored.transport_key);
    let statement = statement(
        &root,
        &producer_key,
        &transport_key,
        stored.enrollment.genesis.statement.installation_nonce,
    );
    #[cfg_attr(not(any(feature = "node", test)), allow(unused_variables))]
    let root_proof = match (root.as_ref(), &stored.enrollment.genesis.root_proof) {
        (PlatformRoot::Software(_), RootProof::Software(signature)) => {
            verify_digest_signature(
                &statement.root_public_key,
                signature,
                Digest::hash(&statement.canonical_bytes()),
            )
            .context("invalid provider genesis root signature")?;
            RootProof::Software(*signature)
        }
        (PlatformRoot::Software(_), _) => bail!("software root requires a software root proof"),
    };
    #[cfg_attr(
        not(any(feature = "node", feature = "evaluate", test)),
        allow(unused_variables)
    )]
    let genesis = SignedProviderGenesis {
        statement,
        root_proof,
    };
    let enrollment = enrollment_bundle(&root, genesis.clone());
    if enrollment != stored.enrollment {
        bail!("stored provider enrollment does not match the persisted keys");
    }
    #[cfg(feature = "node")]
    let open_identity = build_open_identity(&root, &producer_key, &enrollment);
    Ok(LocalIdentity {
        transport_key,
        producer_key,
        #[cfg(any(feature = "node", test))]
        genesis,
        enrollment,
        #[cfg(feature = "node")]
        open_identity,
    })
}

fn enrollment_bundle(
    root: &PlatformRoot,
    genesis: SignedProviderGenesis,
) -> ProviderEnrollmentBundle {
    let platform = match root {
        PlatformRoot::Software(_) => PlatformEnrollment::Absent,
    };
    ProviderEnrollmentBundle { genesis, platform }
}

fn statement(
    root: &PlatformRoot,
    producer: &ProducerSigningKey,
    transport: &SecretKey,
    installation_nonce: [u8; 32],
) -> ProviderGenesisStatement {
    let (root_kind, root_public_key, platform_credential) = match root {
        PlatformRoot::Software(key) => (
            RootKind::Software,
            key.public_key(),
            PlatformCredential::Absent,
        ),
    };
    ProviderGenesisStatement {
        root_kind,
        root_public_key,
        producer_public_key: producer.public_key(),
        transport_public_key: PublicKey::Ed25519(*transport.public().as_bytes()),
        platform_credential,
        installation_nonce,
    }
}

impl StoredIdentity {
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut encoder = hellas_rpc::DagCborEncoder::new();
        encoder.array(6);
        encoder.str(IDENTITY_TAG);
        encoder.u64(u64::from(self.version));
        match &self.root {
            StoredRoot::Software(secret) => {
                encoder.array(2);
                encoder.u64(0);
                encoder.bytes(secret);
            }
        }
        encoder.bytes(&self.producer_key);
        encoder.bytes(&self.transport_key);
        encoder.bytes(&self.enrollment.canonical_bytes());
        encoder.into_bytes()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut decoder = DagCborDecoder::new(bytes);
        decoder.array(6, "identity")?;
        decoder.tag(IDENTITY_TAG)?;
        let version = u8::try_from(decoder.u64("identity version")?)
            .context("identity version does not fit in one byte")?;
        let root_len = decoder.array_len("identity root")?;
        if root_len != 2 {
            bail!("identity root must contain 2 items, got {root_len}");
        }
        let root = match decoder.u64("identity root kind")? {
            0 => StoredRoot::Software(decoder.fixed_bytes("software root key")?),
            1 => bail!("Apple App Attest identity is not supported on this platform"),
            value => bail!("unknown identity root kind {value}"),
        };
        let producer_key = decoder.fixed_bytes("producer key")?;
        let transport_key = decoder.fixed_bytes("transport key")?;
        let enrollment =
            ProviderEnrollmentBundle::from_canonical_bytes(decoder.bytes("provider enrollment")?)
                .context("invalid canonical provider enrollment")?;
        decoder.finish()?;
        let stored = Self {
            version,
            root,
            producer_key,
            transport_key,
            enrollment,
        };
        if stored.canonical_bytes() != bytes {
            bail!("identity is not canonical DAG-CBOR");
        }
        Ok(stored)
    }
}

fn decode(path: &Path, bytes: &[u8]) -> anyhow::Result<LocalIdentity> {
    let stored = StoredIdentity::from_canonical_bytes(bytes).with_context(|| {
        format!(
            "identity file {} has an unsupported encoding",
            path.display()
        )
    })?;
    let identity = materialize(&stored)
        .with_context(|| format!("invalid identity file {}", path.display()))?;
    info!(
        node_id = %identity.transport_key.public(),
        producer_id = ?identity.producer_key.producer_id(),
        path = %path.display(),
        "loaded provider identity"
    );
    Ok(identity)
}

fn persist(path: &Path, stored: &StoredIdentity) -> anyhow::Result<bool> {
    let dir = path
        .parent()
        .context("identity path has no parent directory")?;
    create_dir_restricted(dir)
        .with_context(|| format!("failed to create identity directory {}", dir.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("failed to create temporary identity in {}", dir.display()))?;
    #[cfg(unix)]
    temp.as_file().set_permissions({
        use std::os::unix::fs::PermissionsExt;
        fs::Permissions::from_mode(0o600)
    })?;
    temp.write_all(&stored.canonical_bytes())?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    match temp.persist_noclobber(path) {
        Ok(_) => {
            #[cfg(unix)]
            fs::File::open(dir)?.sync_all()?;
            Ok(true)
        }
        Err(_error) if path.exists() => Ok(false),
        Err(error) => Err(error.error)
            .with_context(|| format!("failed to persist identity file {}", path.display())),
    }
}

fn create_dir_restricted(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

#[cfg(test)]
mod tests;
