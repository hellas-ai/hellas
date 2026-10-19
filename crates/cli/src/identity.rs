use anyhow::{Context, bail};
use hellas_attestation::AssertionCounterStore;
use hellas_auth::signature::verify_digest_signature;
use hellas_auth::{Digest, ProducerSigningKey, PublicKey};
use hellas_rpc::{
    DagCborDecoder, PlatformCredential, ProviderGenesisStatement, RootKind, RootProof,
    SignedProviderGenesis,
};
use hellas_rpc::{PlatformEnrollment, ProviderEnrollmentBundle};
use hellas_sdk::{FilesystemAssertionCounterStore, ProviderOpen};
use iroh::SecretKey;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const IDENTITY_DIR: &str = ".hellas";
const IDENTITY_FILE: &str = "identity";
const APPLE_OPEN_COUNTER_STORE_DIR: &str = "apple-app-attest-open-counters";
#[cfg(feature = "evaluate")]
const CONTENT_INDEX_FILE: &str = "content-index.bin";
const VERSION: u8 = 3;
const IDENTITY_TAG: &str = "hellas.provider.identity.persistence.v3";

pub(crate) struct LocalIdentity {
    pub(crate) transport_key: SecretKey,
    pub(crate) node_key: ProducerSigningKey,
    #[cfg(test)]
    pub(crate) genesis: SignedProviderGenesis,
    pub(crate) enrollment: ProviderEnrollmentBundle,
    open_identity: Arc<ProviderOpen<ProducerSigningKey>>,
}

struct StoredIdentity {
    version: u8,
    root: StoredRoot,
    node_key: [u8; 32],
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

impl LocalIdentity {
    pub(crate) fn open_identity(&self) -> Arc<ProviderOpen<ProducerSigningKey>> {
        self.open_identity.clone()
    }
}

fn build_open_identity(
    node_key: &ProducerSigningKey,
    enrollment: &ProviderEnrollmentBundle,
) -> anyhow::Result<Arc<ProviderOpen<ProducerSigningKey>>> {
    Ok(Arc::new(ProviderOpen::new(
        Arc::new(node_key.clone()),
        enrollment.clone(),
        None,
    )?))
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

/// The node key as the kernel signer of this node's channel moves: one
/// machine key signs its transcripts and its channels.
pub(crate) fn settlement_signer(
    identity: &LocalIdentity,
) -> anyhow::Result<hellas_kernel::Secp256k1Signer> {
    hellas_kernel::Secp256k1Signer::from_secret_scalar(identity.node_key.to_secret_bytes())
        .map_err(|_| anyhow::anyhow!("the node key is not a valid secp256k1 scalar"))
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

pub(crate) fn default_grant_data_path() -> anyhow::Result<PathBuf> {
    default_hellas_path("grants", "HELLAS_GRANT_DATA_DIR")
}

fn default_path() -> anyhow::Result<PathBuf> {
    default_hellas_path(IDENTITY_FILE, "--identity")
}

pub(crate) fn default_gateway_archive_path() -> anyhow::Result<PathBuf> {
    default_hellas_path("gateway-archive", "--archive-dir")
}

#[cfg(feature = "evaluate")]
pub(crate) fn default_content_index_path() -> anyhow::Result<PathBuf> {
    default_hellas_path(CONTENT_INDEX_FILE, "--content-index")
}

pub(crate) fn assertion_counters() -> anyhow::Result<Arc<dyn AssertionCounterStore + Send + Sync>> {
    Ok(Arc::new(FilesystemAssertionCounterStore::new(
        default_hellas_path(
            APPLE_OPEN_COUNTER_STORE_DIR,
            "caller assertion-counter directory",
        )?,
    )))
}

fn default_hellas_path(file: &str, flag: &str) -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME").with_context(|| {
        format!("HOME environment variable not set; use {flag} to specify path")
    })?;
    Ok(PathBuf::from(home).join(IDENTITY_DIR).join(file))
}

pub(crate) fn default_chain_path(network: &str) -> anyhow::Result<PathBuf> {
    Ok(default_hellas_path("chain", "--chain-store-dir")?.join(network))
}

fn create_root(_installation_nonce: [u8; 32]) -> anyhow::Result<PlatformRoot> {
    Ok(PlatformRoot::Software(ProducerSigningKey::generate()))
}

fn create(path: &Path) -> anyhow::Result<LocalIdentity> {
    let node_key = ProducerSigningKey::generate();
    let transport_key = SecretKey::generate();
    let installation_nonce = rand::random();
    let root = Arc::new(create_root(installation_nonce)?);
    let statement = statement(&root, &node_key, &transport_key, installation_nonce);
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
        node_key: node_key.to_secret_bytes(),
        transport_key: transport_key.to_bytes(),
        enrollment: enrollment.clone(),
    };
    let open_identity = build_open_identity(&node_key, &enrollment)?;
    let identity = LocalIdentity {
        transport_key,
        node_key,
        #[cfg(test)]
        genesis,
        enrollment,
        open_identity,
    };
    if !persist(path, &stored)? {
        return load_existing(Some(path));
    }
    info!(
        node_id = %identity.transport_key.public(),
        producer_id = ?identity.node_key.producer_id(),
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
    let node_key =
        ProducerSigningKey::from_secret_bytes(stored.node_key).context("invalid node key")?;
    let transport_key = SecretKey::from(stored.transport_key);
    let statement = statement(
        &root,
        &node_key,
        &transport_key,
        stored.enrollment.genesis.statement.installation_nonce,
    );
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
    let genesis = SignedProviderGenesis {
        statement,
        root_proof,
    };
    let enrollment = enrollment_bundle(&root, genesis.clone());
    if enrollment != stored.enrollment {
        bail!("stored provider enrollment does not match the persisted keys");
    }
    let open_identity = build_open_identity(&node_key, &enrollment)?;
    Ok(LocalIdentity {
        transport_key,
        node_key,
        #[cfg(test)]
        genesis,
        enrollment,
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
        encoder.bytes(&self.node_key);
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
        let node_key = decoder.fixed_bytes("node key")?;
        let transport_key = decoder.fixed_bytes("transport key")?;
        let enrollment =
            ProviderEnrollmentBundle::from_canonical_bytes(decoder.bytes("provider enrollment")?)
                .context("invalid canonical provider enrollment")?;
        decoder.finish()?;
        let stored = Self {
            version,
            root,
            node_key,
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
        producer_id = ?identity.node_key.producer_id(),
        path = %path.display(),
        "loaded provider identity"
    );
    Ok(identity)
}

fn persist(path: &Path, stored: &StoredIdentity) -> anyhow::Result<bool> {
    let dir = path
        .parent()
        .context("identity path has no parent directory")?;
    hellas_private::create_dir_all_durable(dir)
        .with_context(|| format!("failed to create identity directory {}", dir.display()))?;
    let mut temp = hellas_private::private_tempfile(dir, ".identity-", ".tmp")
        .with_context(|| format!("failed to create temporary identity in {}", dir.display()))?;
    temp.write_all(&stored.canonical_bytes())?;
    temp.flush()?;
    temp.as_file().sync_all()?;
    match temp.persist_noclobber(path) {
        Ok(_) => {
            hellas_private::sync_directory(dir)?;
            Ok(true)
        }
        Err(_error) if path.exists() => Ok(false),
        Err(error) => Err(error.error)
            .with_context(|| format!("failed to persist identity file {}", path.display())),
    }
}

#[cfg(test)]
mod tests;
