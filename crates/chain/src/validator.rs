use crate::domain::{
    Address, PublicKey, Scheme, SettlementKey, ThresholdPolynomial, ThresholdShare,
    ThresholdVariant, UserPublicKey,
};
use crate::{
    ActivityReporter, Application, ApplicationConfig, BlockStore, ChainIndexer, ConsensusInfo,
    LightClientRpcState, Mempool, OwnerIndex, UtxoDb,
    config::{
        Config, ConfigError, Genesis, GenesisEntry, GenesisValidator, PeerEntry, ValidatorConfig,
        encode_private_key, encode_threshold_polynomial, encode_threshold_share,
        parse_genesis_settlement_key,
    },
    init_block_store, init_finalization_store,
    relay::{authenticated_relay_request, serve_light_client_relay},
    rpc::LocalLightClient,
    spawn_light_client_server, utxo_db_config,
};
use commonware_broadcast::buffered;
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{
    marshal::{
        self,
        core::Actor as MarshalActor,
        resolver::p2p as marshal_resolver,
        standard::{Deferred, Standard},
    },
    simplex::{self, config::ForwardingPolicy, elector::RoundRobin},
    types::{Epoch, FixedEpocher, Height, ViewDelta},
};
use commonware_cryptography::bls12381::dkg::feldman_desmedt::deal;
use commonware_cryptography::certificate::ConstantProvider;
use commonware_cryptography::{Digestible as _, Signer, ed25519};
use commonware_glue::stateful::{
    Config as StatefulConfig, Stateful as StatefulActor, SyncPlan,
    db::{SyncEngineConfig, p2p::standard as qmdb_resolver},
};
use commonware_p2p::{AddressableManager, authenticated::lookup};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Quota, Runner, Spawner, Storage, Supervisor as _, tokio,
};
use commonware_storage::{
    archive::{Archive as _, Identifier as ArchiveIdentifier},
    mmr,
};
use commonware_utils::{N3f1, NZU64, NZUsize, ordered::Set};
use futures::FutureExt;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{WithExportConfig as _, WithHttpConfig as _};
use prometheus_client::metrics::gauge::Gauge;
use rand::{Rng, SeedableRng, rngs::StdRng};
use std::io;
use std::sync::atomic::AtomicI64;
use std::time::{Duration, Instant};
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
};
use thiserror::Error;
use tracing::{error, info, warn};

const NAMESPACE: &[u8] = b"hellas";
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;
const CHANNEL_BACKLOG: usize = 1024;
const DEFAULT_OTLP_SERVICE_NAME: &str = "hellas-validator";
const DEFAULT_OTLP_SAMPLE_RATE: f64 = 1.0;
const OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT";
const OTLP_SERVICE_NAME_ENV: &str = "OTEL_SERVICE_NAME";
const OTLP_SAMPLE_RATE_ENV: &str = "OTEL_TRACES_SAMPLER_ARG";
const OTLP_HEADERS_ENV: &str = "OTEL_EXPORTER_OTLP_HEADERS";
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

fn random_private_key() -> ed25519::PrivateKey {
    let mut raw = [0u8; 32];
    rand::rng().fill_bytes(&mut raw);
    ed25519::PrivateKey::decode(raw.as_slice())
        .expect("decoding 32 random bytes as an ed25519 private key should always succeed")
}

fn deal_threshold_shares(
    seed: Option<u64>,
    participants: Set<PublicKey>,
) -> Result<
    (
        ThresholdPolynomial,
        commonware_utils::ordered::Map<PublicKey, ThresholdShare>,
    ),
    ValidatorError,
> {
    let dealt = match seed {
        Some(seed) => {
            let mut rng = StdRng::seed_from_u64(seed ^ 0x4845_4c4c_4153_424c);
            deal::<ThresholdVariant, _, N3f1>(&mut rng, Default::default(), participants)
        }
        None => {
            let mut rng: StdRng = rand::make_rng();
            deal::<ThresholdVariant, _, N3f1>(&mut rng, Default::default(), participants)
        }
    }
    .map_err(|e| ValidatorError::InvalidSetup(format!("failed to deal threshold shares: {e}")))?;

    let (output, shares) = dealt;
    Ok((output.public().clone(), shares))
}

#[derive(Debug, Error)]
pub enum ValidatorError {
    #[error("invalid setup args: {0}")]
    InvalidSetup(String),
    #[error("failed to serialize config")]
    SerializeConfig(#[from] toml::ser::Error),
    #[error("failed to read config file")]
    ReadConfig(#[from] io::Error),
    #[error("failed to parse config file")]
    ParseConfig(#[from] toml::de::Error),
    #[error("failed to parse genesis JSON")]
    ParseGenesis(#[from] serde_json::Error),
    #[error("invalid validator configuration")]
    Config(#[from] ConfigError),
    #[error("invalid listen address")]
    InvalidListenAddress(#[from] std::net::AddrParseError),
    #[error("failed to build consensus scheme: {0}")]
    Scheme(String),
    #[error("storage directory is not valid UTF-8: {0}")]
    NonUtf8StorageDirectory(PathBuf),
    #[error("failed to replay owner index: {0}")]
    OwnerIndex(String),
    #[error("failed to bind light-client server at {addr}: {source}")]
    LightClientBind { addr: SocketAddr, source: io::Error },
    #[error("invalid relay configuration")]
    Relay(#[from] crate::relay::RelayConnectError),
}

#[derive(Debug)]
pub enum Command {
    ExportTrust {
        config: PathBuf,
        genesis: PathBuf,
    },
    GenerateNetwork {
        network_id: String,
        validators: u32,
        labels: Vec<String>,
        addresses: Vec<String>,
        start_port: u16,
        metrics_base_port: u16,
        relay_urls: Vec<String>,
        genesis_allocations: Vec<String>,
        treasury_balance: Option<u64>,
        output_dir: PathBuf,
    },
    Config {
        validators: u32,
        validator: u32,
        start_port: u16,
        seed: Option<u64>,
        addresses: Option<Vec<String>>,
        relay_urls: Vec<String>,
        metrics_port: Option<u16>,
        light_client_bind: Option<SocketAddr>,
        genesis: Option<PathBuf>,
        genesis_allocations: Vec<String>,
    },
    Run {
        config: PathBuf,
    },
    CheckConfig {
        config: PathBuf,
    },
}

pub fn run_command(command: Command) -> Result<(), ValidatorError> {
    match command {
        Command::ExportTrust { config, genesis } => {
            let config: ValidatorConfig = toml::from_str(&std::fs::read_to_string(config)?)?;
            let trust = export_trust(&config, &std::fs::read(genesis)?)?;
            println!("{}", serde_json::to_string_pretty(&trust)?);
            Ok(())
        }
        Command::GenerateNetwork {
            network_id,
            validators,
            labels,
            addresses,
            start_port,
            metrics_base_port,
            relay_urls,
            genesis_allocations,
            treasury_balance,
            output_dir,
        } => generate_network(GenerateNetworkArgs {
            network_id,
            validators,
            labels,
            addresses,
            start_port,
            metrics_base_port,
            relay_urls,
            genesis_allocations,
            treasury_balance,
            output_dir,
        }),
        Command::Config {
            validators,
            validator,
            start_port,
            seed,
            addresses,
            relay_urls,
            metrics_port,
            light_client_bind,
            genesis,
            genesis_allocations,
        } => setup(SetupArgs {
            validators,
            validator,
            start_port,
            seed,
            addresses,
            relay_urls,
            metrics_port,
            light_client_bind,
            genesis,
            genesis_allocations,
        }),
        Command::Run { config } => run(config),
        Command::CheckConfig { config } => check_config(config),
    }
}

struct SetupArgs {
    validators: u32,
    validator: u32,
    start_port: u16,
    seed: Option<u64>,
    addresses: Option<Vec<String>>,
    relay_urls: Vec<String>,
    metrics_port: Option<u16>,
    light_client_bind: Option<SocketAddr>,
    genesis: Option<PathBuf>,
    genesis_allocations: Vec<String>,
}

struct GenerateNetworkArgs {
    network_id: String,
    validators: u32,
    labels: Vec<String>,
    addresses: Vec<String>,
    start_port: u16,
    metrics_base_port: u16,
    relay_urls: Vec<String>,
    genesis_allocations: Vec<String>,
    treasury_balance: Option<u64>,
    output_dir: PathBuf,
}

fn generate_network(args: GenerateNetworkArgs) -> Result<(), ValidatorError> {
    let GenerateNetworkArgs {
        network_id,
        validators,
        labels,
        addresses,
        start_port,
        metrics_base_port,
        relay_urls,
        genesis_allocations,
        treasury_balance,
        output_dir,
    } = args;

    if validators == 0 {
        return Err(ValidatorError::InvalidSetup(
            "need at least one validator".to_string(),
        ));
    }
    let validator_count = validators as usize;
    if labels.len() != validator_count {
        return Err(ValidatorError::InvalidSetup(format!(
            "--labels must have exactly {validators} entries, got {}",
            labels.len(),
        )));
    }
    if addresses.len() != validator_count {
        return Err(ValidatorError::InvalidSetup(format!(
            "--addresses must have exactly {validators} entries, got {}",
            addresses.len(),
        )));
    }
    let last_p2p_offset = u16::try_from(validator_count.saturating_sub(1))
        .map_err(|_| ValidatorError::InvalidSetup("too many validators".to_string()))?;
    start_port
        .checked_add(last_p2p_offset)
        .ok_or_else(|| ValidatorError::InvalidSetup("P2P port range overflow".to_string()))?;
    metrics_base_port
        .checked_add(last_p2p_offset)
        .ok_or_else(|| ValidatorError::InvalidSetup("metrics port range overflow".to_string()))?;

    let keys = (0..validators)
        .map(|_| random_private_key())
        .collect::<Vec<_>>();
    let participants = Set::try_from(
        keys.iter()
            .map(|key| key.public_key())
            .collect::<Vec<PublicKey>>(),
    )
    .map_err(|_| {
        ValidatorError::InvalidSetup("generated duplicate validator identity keys".to_string())
    })?;
    let (threshold_polynomial, threshold_shares) = deal_threshold_shares(None, participants)?;

    let mut allocations = genesis_allocations
        .iter()
        .map(|raw| parse_genesis_allocation(raw))
        .collect::<Result<Vec<_>, _>>()?;
    let treasury_key = treasury_balance.map(|balance| {
        let signing_key = loop {
            let mut raw = [0u8; 32];
            rand::rng().fill_bytes(&mut raw);
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&raw) {
                break key;
            }
        };
        allocations.push(GenesisEntry {
            address: SettlementKey::from(Address::from(UserPublicKey::from(
                signing_key.verifying_key().to_owned(),
            )))
            .to_string(),
            balance,
        });
        signing_key
    });
    let genesis = Genesis {
        schema_version: crate::genesis::GENESIS_SCHEMA_VERSION,
        network_id,
        validators: keys
            .iter()
            .zip(labels)
            .map(|(key, label)| GenesisValidator {
                public_key: hex::encode(key.public_key().encode()),
                label,
            })
            .collect(),
        allocations,
    };
    genesis.validate().map_err(ConfigError::from)?;

    std::fs::create_dir(&output_dir)?;
    let mut genesis_json = serde_json::to_vec_pretty(&genesis)?;
    genesis_json.push(b'\n');
    std::fs::write(output_dir.join("genesis.json"), genesis_json)?;
    if let Some(treasury_key) = treasury_key {
        let path = output_dir.join("treasury.key");
        std::fs::write(&path, treasury_key.to_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }

    for (index, my_key) in keys.iter().enumerate() {
        let my_public_key = my_key.public_key();
        let my_threshold_share = threshold_shares.get_value(&my_public_key).ok_or_else(|| {
            ValidatorError::InvalidSetup(
                "missing threshold share for generated validator".to_string(),
            )
        })?;
        let peers = keys
            .iter()
            .enumerate()
            .filter(|(peer_index, _)| *peer_index != index)
            .map(|(peer_index, key)| PeerEntry {
                public_key: hex::encode(key.public_key().encode()),
                address: format!(
                    "{}:{}",
                    addresses[peer_index],
                    start_port + peer_index as u16
                ),
            })
            .collect();
        let config = ValidatorConfig {
            private_key: encode_private_key(my_key),
            threshold_share: encode_threshold_share(my_threshold_share),
            threshold_polynomial: encode_threshold_polynomial(&threshold_polynomial),
            listen_port: start_port + index as u16,
            metrics_port: Some(metrics_base_port + index as u16),
            light_client_bind: None,
            relay_urls: relay_urls.clone(),
            genesis: genesis.clone(),
            peers,
        };
        let rendered = toml::to_string_pretty(&config)?;
        let path = output_dir.join(format!("validator-{index}.toml"));
        std::fs::write(&path, rendered)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }

    println!("{}", output_dir.join("genesis.json").display());
    Ok(())
}

fn setup(args: SetupArgs) -> Result<(), ValidatorError> {
    let SetupArgs {
        validators,
        validator,
        start_port,
        seed,
        addresses,
        relay_urls,
        metrics_port,
        light_client_bind,
        genesis,
        genesis_allocations,
    } = args;

    if validators == 0 {
        return Err(ValidatorError::InvalidSetup(
            "need at least one validator".to_string(),
        ));
    }
    if validator >= validators {
        return Err(ValidatorError::InvalidSetup(
            "validator index must be less than validators".to_string(),
        ));
    }
    if let Some(ref addrs) = addresses
        && addrs.len() != validators as usize
    {
        return Err(ValidatorError::InvalidSetup(format!(
            "--addresses must have exactly {validators} entries (one per validator), got {}",
            addrs.len(),
        )));
    }

    if seed.is_none() {
        eprintln!(
            "warning: generating cryptographically random keys without --seed; configs will not be reproducible"
        );
    }
    let keys: Vec<ed25519::PrivateKey> = (0..validators)
        .map(|i| match seed {
            Some(s) => ed25519::PrivateKey::from_seed(s + i as u64),
            None => random_private_key(),
        })
        .collect();
    let threshold_participants = Set::try_from(
        keys.iter()
            .map(|key| key.public_key())
            .collect::<Vec<PublicKey>>(),
    )
    .map_err(|_| {
        ValidatorError::InvalidSetup("generated duplicate validator identity keys".to_string())
    })?;
    let (threshold_polynomial, threshold_shares) =
        deal_threshold_shares(seed, threshold_participants)?;

    let my_key = &keys[validator as usize];
    let my_public_key = my_key.public_key();
    let my_threshold_share = threshold_shares.get_value(&my_public_key).ok_or_else(|| {
        ValidatorError::InvalidSetup("missing threshold share for generated validator".to_string())
    })?;
    let peers: Vec<PeerEntry> = keys
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != validator as usize)
        .map(|(i, k)| {
            let host = addresses
                .as_ref()
                .map(|a| a[i].as_str())
                .unwrap_or("127.0.0.1");
            PeerEntry {
                public_key: hex::encode(k.public_key().encode()),
                address: format!("{}:{}", host, start_port + i as u16),
            }
        })
        .collect();
    let generated_validators = keys
        .iter()
        .enumerate()
        .map(|(index, key)| GenesisValidator {
            public_key: hex::encode(key.public_key().encode()),
            label: format!("validator-{index}"),
        })
        .collect::<Vec<_>>();
    let genesis = match genesis {
        Some(path) => {
            if !genesis_allocations.is_empty() {
                return Err(ValidatorError::InvalidSetup(
                    "--genesis cannot be combined with --genesis-allocation".to_string(),
                ));
            }
            let bytes = std::fs::read(&path)?;
            let genesis: Genesis = serde_json::from_slice(&bytes)?;
            genesis.validate().map_err(ConfigError::from)?;
            if genesis.validators != generated_validators {
                return Err(ValidatorError::InvalidSetup(format!(
                    "validator identities generated by --seed do not match genesis {}",
                    path.display(),
                )));
            }
            genesis
        }
        None => Genesis {
            schema_version: crate::genesis::GENESIS_SCHEMA_VERSION,
            network_id: crate::genesis::HELLAS_DEVNET_1_ID.to_string(),
            validators: generated_validators,
            allocations: genesis_allocations
                .iter()
                .map(|raw| parse_genesis_allocation(raw))
                .collect::<Result<Vec<_>, _>>()?,
        },
    };

    let config = ValidatorConfig {
        private_key: encode_private_key(my_key),
        threshold_share: encode_threshold_share(my_threshold_share),
        threshold_polynomial: encode_threshold_polynomial(&threshold_polynomial),
        listen_port: start_port + validator as u16,
        metrics_port: Some(metrics_port.unwrap_or(9090 + validator as u16)),
        light_client_bind,
        relay_urls,
        genesis,
        peers,
    };
    config.genesis_allocations()?;

    let rendered = toml::to_string_pretty(&config)?;
    println!("{rendered}");
    Ok(())
}

fn parse_genesis_allocation(raw: &str) -> Result<GenesisEntry, ValidatorError> {
    let (address, balance) = raw.rsplit_once(':').ok_or_else(|| {
        ValidatorError::InvalidSetup(
            "genesis allocation must have the form address:balance".to_string(),
        )
    })?;
    let address = parse_genesis_settlement_key(address)
        .map_err(|err| ValidatorError::InvalidSetup(err.to_string()))?;
    let balance = balance.parse::<u64>().map_err(|err| {
        ValidatorError::InvalidSetup(format!("invalid genesis allocation balance: {err}"))
    })?;
    Ok(GenesisEntry {
        address: address.to_string(),
        balance,
    })
}

#[cfg(test)]
mod genesis_allocation_tests {
    use super::*;
    use crate::domain::{SettlementKey, addr_from_signing_key, secp256r1_key_from_seed};

    #[test]
    fn generated_network_exports_public_trust_bound_to_exact_genesis() {
        use commonware_cryptography::{Hasher as _, Sha256};
        let directory = tempfile::tempdir().unwrap();
        let output_dir = directory.path().join("network");
        generate_network(GenerateNetworkArgs {
            network_id: hellas_genesis::HELLAS_DEVNET_1_ID.into(),
            validators: 1,
            labels: vec!["demo".into()],
            addresses: vec!["127.0.0.1".into()],
            start_port: 3000,
            metrics_base_port: 9090,
            relay_urls: vec![],
            genesis_allocations: vec![],
            treasury_balance: Some(100),
            output_dir: output_dir.clone(),
        })
        .unwrap();
        let config: ValidatorConfig =
            toml::from_str(&std::fs::read_to_string(output_dir.join("validator-0.toml")).unwrap())
                .unwrap();
        let document = std::fs::read(output_dir.join("genesis.json")).unwrap();
        let trust = export_trust(&config, &document).unwrap();
        assert_eq!(trust.genesis_sha256, hex::encode(Sha256::hash(&document)));
        assert_eq!(trust.epochs[0].threshold_identity.len(), 96);
        #[cfg(feature = "proof-verify")]
        assert!(crate::proof_verify::ProofVerifier::with_genesis(trust.clone(), &document).is_ok());
        let public = serde_json::to_string(&trust).unwrap();
        assert!(!public.contains(&config.private_key));
        assert!(!public.contains(&config.threshold_share));
        let mut changed = document.clone();
        changed.push(b'\n');
        assert_ne!(
            trust.genesis_sha256,
            export_trust(&config, &changed).unwrap().genesis_sha256
        );
        let mut wrong = config.genesis.clone();
        wrong.validators[0].label = "other".into();
        assert!(export_trust(&config, &serde_json::to_vec(&wrong).unwrap()).is_err());
    }

    #[test]
    fn rejects_settlement_key_valid_on_neither_curve() {
        let key = SettlementKey::from_bytes([0xa5; SettlementKey::LENGTH]);
        let err = match parse_genesis_allocation(&format!("{key}:10")) {
            Ok(_) => panic!("invalid genesis owner was accepted"),
            Err(err) => err,
        };
        assert!(matches!(
            err,
            ValidatorError::InvalidSetup(message)
                if message.contains(&key.to_string())
                    && message.contains("P-256")
                    && message.contains("secp256k1")
        ));
    }

    #[test]
    fn accepts_p256_settlement_key() {
        let address = addr_from_signing_key(&secp256r1_key_from_seed(11));
        let key = SettlementKey::from(address);
        let entry =
            parse_genesis_allocation(&format!("{key}:10")).expect("valid P-256 genesis owner");
        assert_eq!(entry.address, key.to_string());
        assert_eq!(entry.balance, 10);
    }
}

#[cfg(test)]
mod owner_index_replay_tests {
    use super::*;
    use crate::HellasBlock;
    use crate::execution::test_support::{index_block, index_genesis};
    use commonware_consensus::Heightable as _;
    use commonware_cryptography::{Digest as _, sha256::Digest};
    use commonware_runtime::deterministic;

    /// Builds a chain of `len` empty blocks above genesis and stores every
    /// height except those in `skip`.
    async fn archive(
        context: deterministic::Context,
        genesis: &HellasBlock,
        len: u64,
        skip: &[u64],
    ) -> (BlockStore<deterministic::Context>, Vec<HellasBlock>) {
        let mut store = init_block_store(context, "replay", &Config::default()).await;
        let mut chain = vec![genesis.clone()];
        for _ in 0..len {
            let next = index_block(chain.last().unwrap(), Digest::EMPTY, Vec::new());
            chain.push(next);
        }
        for block in &chain {
            let height = block.height().get();
            if skip.contains(&height) {
                continue;
            }
            store
                .put(height, block.digest(), block.clone())
                .await
                .expect("put");
        }
        store.sync().await.expect("sync");
        (store, chain)
    }

    #[test]
    fn owner_index_replay_stops_at_archive_hole() {
        deterministic::Runner::default().start(|context| async move {
            let genesis = index_genesis();
            let (store, chain) = archive(context, &genesis, 6, &[3, 4]).await;
            assert_eq!(store.ranges().collect::<Vec<_>>(), vec![(0, 2), (5, 6)]);
            let index = OwnerIndex::new(crate::domain::TEST_NETWORK, &genesis, Vec::new());

            replay_owner_index(&index, &store).await.expect("replay");

            let cursor = index.cursor();
            assert_eq!(cursor.height, 2);
            assert_eq!(cursor.payload, chain[2].digest());
        });
    }

    #[test]
    fn owner_index_replay_covers_contiguous_archive() {
        deterministic::Runner::default().start(|context| async move {
            let genesis = index_genesis();
            let (store, chain) = archive(context, &genesis, 6, &[]).await;
            let index = OwnerIndex::new(crate::domain::TEST_NETWORK, &genesis, Vec::new());

            replay_owner_index(&index, &store).await.expect("replay");

            let cursor = index.cursor();
            assert_eq!(cursor.height, 6);
            assert_eq!(cursor.payload, chain[6].digest());
        });
    }

    #[test]
    fn owner_index_must_reach_marshal_processed_height() {
        assert!(check_owner_index_reaches_marshal(2, None).is_ok());
        assert!(check_owner_index_reaches_marshal(2, Some(Height::new(1))).is_ok());
        assert!(check_owner_index_reaches_marshal(2, Some(Height::new(2))).is_ok());
        let err = check_owner_index_reaches_marshal(2, Some(Height::new(5)))
            .expect_err("processed height above the replayed prefix");
        assert!(matches!(
            err,
            ValidatorError::OwnerIndex(ref message)
                if message.contains("processed finalized height 5")
                    && message.contains("through height 2")
                    && message.contains("3..=5")
        ));
    }
}

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn otlp_sample_rate() -> f64 {
    let Some(raw) = env_non_empty(OTLP_SAMPLE_RATE_ENV) else {
        return DEFAULT_OTLP_SAMPLE_RATE;
    };
    match raw.parse::<f64>() {
        Ok(value) if (0.0..=1.0).contains(&value) => value,
        _ => {
            eprintln!(
                "warning: invalid OTLP sample rate `{raw}` in {OTLP_SAMPLE_RATE_ENV}; expected a value in [0.0, 1.0], using {}",
                DEFAULT_OTLP_SAMPLE_RATE,
            );
            DEFAULT_OTLP_SAMPLE_RATE
        }
    }
}

/// Initialise the tracing subscriber.
///
/// When `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set (and non-empty), an
/// OpenTelemetry OTLP layer is added that exports traces over HTTP/protobuf.
///
/// Supported environment variables:
///   RUST_LOG                             — log filter (default: info)
///   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT   — collector URL
///   OTEL_SERVICE_NAME                    — service name (default: hellas-validator)
///   OTEL_TRACES_SAMPLER_ARG             — sample rate 0.0–1.0 (default: 1.0)
///   OTEL_EXPORTER_OTLP_HEADERS          — extra headers as k=v,k=v
fn init_telemetry() -> Option<opentelemetry_sdk::trace::SdkTracerProvider> {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::util::SubscriberInitExt;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_line_number(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .compact();

    let (otel_layer, provider) = init_otlp_layer();

    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer);

    match subscriber.try_init() {
        Ok(()) => provider,
        Err(err) => {
            eprintln!("warning: validator tracing subscriber not installed: {err}");
            if let Some(provider) = provider
                && let Err(shutdown_err) = provider.shutdown()
            {
                eprintln!("warning: failed to shut down unused validator tracer: {shutdown_err}");
            }
            None
        }
    }
}

fn init_otlp_layer<S>() -> (
    Option<tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::Tracer>>,
    Option<opentelemetry_sdk::trace::SdkTracerProvider>,
)
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    let endpoint = match env_non_empty(OTLP_ENDPOINT_ENV) {
        Some(v) => v,
        None => return (None, None),
    };

    let service_name = env_non_empty(OTLP_SERVICE_NAME_ENV)
        .unwrap_or_else(|| DEFAULT_OTLP_SERVICE_NAME.to_string());

    let sample_rate = otlp_sample_rate();

    let headers: std::collections::HashMap<String, String> = env_non_empty(OTLP_HEADERS_ENV)
        .map(|raw| {
            raw.split(',')
                .filter_map(|pair| {
                    let (k, v) = pair.split_once('=')?;
                    Some((k.trim().to_string(), v.trim().to_string()))
                })
                .collect()
        })
        .unwrap_or_default();

    let mut http = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(&endpoint);

    if !headers.is_empty() {
        http = http.with_headers(headers);
    }

    let exporter = match http.build() {
        Ok(e) => e,
        Err(err) => {
            eprintln!("warning: failed to build OTLP exporter: {err}");
            return (None, None);
        }
    };

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(
            sample_rate,
        ))
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(service_name.clone())
                .build(),
        )
        .build();

    opentelemetry::global::set_tracer_provider(provider.clone());
    let tracer = provider.tracer(service_name.clone());

    eprintln!("otlp: enabled endpoint={endpoint} service={service_name} sample_rate={sample_rate}");

    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    (Some(layer), Some(provider))
}

fn spawn_metrics_server(context: tokio::Context, addr: SocketAddr) {
    use axum::{Router, routing::get};

    context.child("metrics").spawn(move |context| async move {
        let listener = ::tokio::net::TcpListener::bind(addr)
            .await
            .expect("failed to bind metrics server");
        let metrics_context = std::sync::Arc::new(context);

        let app = Router::new().route(
            "/metrics",
            get({
                let metrics_context = metrics_context.clone();
                move || {
                    let metrics_context = metrics_context.clone();
                    async move {
                        axum::http::Response::builder()
                            .status(axum::http::StatusCode::OK)
                            .header(
                                axum::http::header::CONTENT_TYPE,
                                "text/plain; version=0.0.4",
                            )
                            .body(axum::body::Body::from(metrics_context.encode()))
                            .expect("failed to create response")
                    }
                }
            }),
        );

        axum::serve(listener, app.into_make_service())
            .await
            .expect("could not serve metrics");
    });
}

async fn wait_for_shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use ::tokio::signal::unix::{SignalKind, signal};
        use futures::future::Either;

        let ctrl_c = ::tokio::signal::ctrl_c();
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                let sigterm_wait = sigterm.recv();
                futures::pin_mut!(ctrl_c);
                futures::pin_mut!(sigterm_wait);
                match futures::future::select(ctrl_c, sigterm_wait).await {
                    Either::Left((res, _)) => {
                        if let Err(err) = res {
                            warn!(?err, "failed waiting for SIGINT");
                        }
                        "sigint"
                    }
                    Either::Right((_res, _)) => "sigterm",
                }
            }
            Err(err) => {
                warn!(
                    ?err,
                    "failed to install SIGTERM handler, falling back to SIGINT only"
                );
                if let Err(wait_err) = ctrl_c.await {
                    warn!(?wait_err, "failed waiting for SIGINT");
                }
                "sigint"
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(err) = ::tokio::signal::ctrl_c().await {
            warn!(?err, "failed waiting for shutdown signal");
        }
        "ctrl_c"
    }
}

#[derive(Clone, Copy)]
enum ShutdownTrigger {
    Signal(&'static str),
    NetworkExited,
    EngineExited,
    LightClientServerExited,
    RelayExited,
}

async fn graceful_stop(context: tokio::Context, monitor_second_signal: bool) {
    if monitor_second_signal {
        let stop = context.stop(0, Some(SHUTDOWN_TIMEOUT));
        let second_signal = wait_for_shutdown_signal();
        futures::pin_mut!(stop);
        futures::pin_mut!(second_signal);
        match futures::future::select(stop, second_signal).await {
            futures::future::Either::Left((stop_result, _)) => {
                if let Err(err) = stop_result {
                    warn!(?err, "runtime stop failed or timed out");
                }
            }
            futures::future::Either::Right((second, _)) => {
                eprintln!("received second shutdown signal ({second}), forcing exit");
                std::process::exit(1);
            }
        }
        return;
    }

    if let Err(err) = context.stop(0, Some(SHUTDOWN_TIMEOUT)).await {
        warn!(?err, "runtime stop failed or timed out");
    }
}

/// Replays the contiguous prefix of the archive. The index needs every block
/// in order from genesis, so a range beyond a hole is left for marshal, which
/// backfills the hole and delivers it in order.
async fn replay_owner_index<E>(
    indexer: &OwnerIndex,
    finalized_blocks: &BlockStore<E>,
) -> Result<(), ValidatorError>
where
    E: BufferPooler + Clock + Metrics + Storage,
{
    for (start, end) in finalized_blocks.ranges() {
        let cursor = indexer.cursor().height;
        if start > cursor.saturating_add(1) {
            warn!(
                missing_from = cursor + 1,
                missing_to = start - 1,
                "finalized block archive has a hole; owner index replay stops before it",
            );
            break;
        }
        for height in start..=end {
            let block = finalized_blocks
                .get(ArchiveIdentifier::Index(height))
                .await
                .map_err(|err| {
                    ValidatorError::OwnerIndex(format!(
                        "failed to load finalized block at height {height}: {err}"
                    ))
                })?;
            let Some(block) = block else {
                continue;
            };
            indexer.apply_finalized(&block).map_err(|err| {
                ValidatorError::OwnerIndex(format!(
                    "failed to index finalized block at height {height}: {err}"
                ))
            })?;
        }
    }
    Ok(())
}

/// Marshal resumes delivery above its processed height and never refetches
/// below it, so an index that stops short of that height can never be
/// completed and must not run.
fn check_owner_index_reaches_marshal(
    indexed: u64,
    processed: Option<Height>,
) -> Result<(), ValidatorError> {
    let Some(processed) = processed.map(|height| height.get()) else {
        return Ok(());
    };
    if processed <= indexed {
        return Ok(());
    }
    Err(ValidatorError::OwnerIndex(format!(
        "marshal has already processed finalized height {processed} but the finalized \
         block archive is only contiguous from genesis through height {indexed}; the owner \
         index needs every finalized block and heights {}..={processed} cannot be recovered \
         from peers. Restore the finalized block archive from a complete copy or resync this \
         validator from genesis.",
        indexed + 1,
    )))
}

/// Run all `ValidatorConfig` validations the runtime would perform at startup.
/// Used by `validator check-config` and by `nix build` via runCommand.
fn validate_relay_urls(
    validator_config: &ValidatorConfig,
    private_key: &ed25519::PrivateKey,
) -> Result<(), ValidatorError> {
    let mut seen = BTreeSet::new();
    for relay_url in &validator_config.relay_urls {
        let request = authenticated_relay_request(
            relay_url,
            &validator_config.genesis,
            private_key,
            0,
            [0; hellas_wire::relay_auth::NONCE_BYTES],
        )?;
        let canonical = request.uri().to_string();
        if !seen.insert(canonical) {
            return Err(ValidatorError::InvalidSetup(format!(
                "duplicate relay URL: {relay_url}"
            )));
        }
    }
    Ok(())
}

/// Export epoch-zero trust from a provisioned validator config, bound to exact genesis bytes.
/// Only public data is returned. Authenticate this output independently before deployment.
pub fn export_trust(
    config: &ValidatorConfig,
    genesis_json: &[u8],
) -> Result<hellas_genesis::TrustDocument, ValidatorError> {
    use commonware_cryptography::{Hasher as _, Sha256};
    let genesis: Genesis = serde_json::from_slice(genesis_json)?;
    config.validate_genesis()?;
    if genesis != config.genesis || genesis.network_id != hellas_genesis::HELLAS_DEVNET_1_ID {
        return Err(ValidatorError::InvalidSetup(
            "genesis file must match the validator's devnet genesis".into(),
        ));
    }
    let scheme = Scheme::signer(
        NAMESPACE,
        config.participants()?,
        config.decode_threshold_polynomial()?,
        config.decode_threshold_share()?,
    )
    .ok_or_else(|| ValidatorError::Scheme("threshold share does not match polynomial".into()))?;
    let trust = hellas_genesis::TrustDocument {
        schema_version: hellas_genesis::TRUST_SCHEMA_VERSION,
        network_id: genesis.network_id,
        genesis_sha256: hex::encode(Sha256::hash(genesis_json)),
        epochs: vec![hellas_genesis::TrustEpoch {
            epoch: 0,
            start_height: 0,
            end_height: None,
            threshold_identity: hex::encode(scheme.identity().encode()),
        }],
    };
    trust
        .validate()
        .map_err(|error| ValidatorError::InvalidSetup(error.to_string()))?;
    Ok(trust)
}

fn check_config(config_path: PathBuf) -> Result<(), ValidatorError> {
    let config_str = std::fs::read_to_string(&config_path)?;
    let validator_config: ValidatorConfig = toml::from_str(&config_str)?;
    let private_key = validator_config.decode_private_key()?;
    validator_config.decode_threshold_share()?;
    validator_config.decode_threshold_polynomial()?;
    validator_config.participants()?;
    validator_config.peer_address_map()?;
    validator_config.genesis_allocations()?;
    validate_relay_urls(&validator_config, &private_key)?;
    println!("ok");
    Ok(())
}

fn run(config_path: PathBuf) -> Result<(), ValidatorError> {
    let config_str = std::fs::read_to_string(&config_path)?;
    let mut validator_config: ValidatorConfig = toml::from_str(&config_str)?;

    // A production deployment can either load the complete TOML as a systemd
    // credential or overlay the three key fields onto a public template.
    // Development configs may still contain key material directly.
    let config_is_credential = std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .is_some_and(|directory| config_path.parent() == Some(directory.as_path()));
    if !config_is_credential && !validator_config.load_credentials()? {
        eprintln!(
            "WARNING: CREDENTIALS_DIRECTORY not set; using key material from {}. \
             Production must supply keys via systemd LoadCredential.",
            config_path.display(),
        );
    }

    let network_id = validator_config.network_id()?;
    let private_key = validator_config.decode_private_key()?;
    let me = private_key.public_key();
    let threshold_share = validator_config.decode_threshold_share()?;
    let threshold_polynomial = validator_config.decode_threshold_polynomial()?;
    let genesis_allocations = validator_config.genesis_allocations()?;

    let git_rev = option_env!("GIT_REV").unwrap_or("unknown");

    let participants = validator_config.participants()?;
    let peer_map = validator_config.peer_address_map()?;
    validate_relay_urls(&validator_config, &private_key)?;
    let relay_private_key = private_key.clone();

    let listen_addr: SocketAddr = format!("0.0.0.0:{}", validator_config.listen_port).parse()?;

    // Build consensus scheme
    let scheme = match Scheme::signer(
        NAMESPACE,
        participants,
        threshold_polynomial,
        threshold_share,
    ) {
        Some(scheme) => scheme,
        None => {
            return Err(ValidatorError::Scheme(
                "threshold share does not match configured participants".to_string(),
            ));
        }
    };
    let consensus_info = ConsensusInfo {
        validators: scheme
            .participants()
            .iter()
            .map(|public_key| hex::encode(public_key.encode()))
            .collect(),
        threshold_identity: scheme.identity().encode().to_vec(),
        network_id: validator_config.genesis.network_id.clone(),
    };

    // Configure tokio runtime
    let storage_dir = validator_config.storage_directory()?;
    let storage_dir_utf8 = storage_dir
        .to_str()
        .ok_or_else(|| ValidatorError::NonUtf8StorageDirectory(storage_dir.clone()))?;
    let metrics_addr = validator_config
        .metrics_port
        .map(|metrics_port| format!("0.0.0.0:{metrics_port}").parse())
        .transpose()?;
    let runtime_cfg = tokio::Config::new()
        .with_storage_directory(storage_dir_utf8)
        .with_tcp_nodelay(Some(true));
    let runner = tokio::Runner::new(runtime_cfg);

    runner.start(move |context| async move {
        let tracer_provider = init_telemetry();

        if let Some(addr) = metrics_addr {
            spawn_metrics_server(context.child("telemetry"), addr);
        }

        info!(
            git_rev,
            version = env!("CARGO_PKG_VERSION"),
            "hellas validator starting",
        );
        if let Some(metrics_port) = validator_config.metrics_port {
            info!(metrics_port, "prometheus metrics server started");
        }

        // Create lookup-based p2p network
        let p2p_cfg = lookup::Config::local(private_key, NAMESPACE, listen_addr, MAX_MESSAGE_SIZE);
        let (mut network, mut oracle) = lookup::Network::new(context.child("network"), p2p_cfg);

        // Register all validators with the oracle, then allow address refreshes
        // without introducing a new peer-set epoch.
        oracle.track(0, peer_map.clone());
        oracle.overwrite(peer_map);

        // Register consensus, marshal resolver, and block broadcast channels.
        let quota = Quota::per_second(NonZeroU32::MAX);
        let vote = network.register(0, quota, CHANNEL_BACKLOG);
        let certificate = network.register(1, quota, CHANNEL_BACKLOG);
        let consensus_resolver = network.register(2, quota, CHANNEL_BACKLOG);
        let marshal_resolver_network = network.register(3, quota, CHANNEL_BACKLOG);
        let broadcast_blocks = network.register(4, quota, CHANNEL_BACKLOG);
        let qmdb_resolver_network = network.register(5, quota, CHANNEL_BACKLOG);

        // Publish process uptime as a prometheus gauge, updated every second.
        let uptime_gauge: Gauge<i64, AtomicI64> = Gauge::default();
        let _uptime_registration = context.child("process").register(
            "uptime_seconds",
            "seconds since the validator process started",
            uptime_gauge.clone(),
        );
        let boot = Instant::now();
        ::tokio::spawn(async move {
            let mut tick = ::tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                uptime_gauge.set(boot.elapsed().as_secs() as i64);
            }
        });

        let chain_config = Config::default();
        let partition_prefix = format!("hellas_{me}");
        let page_cache = chain_config.page_cache(&context);
        let finalizations_by_height = init_finalization_store(
            context.child("finalizations_by_height"),
            &partition_prefix,
            &chain_config,
        )
        .await;
        let finalized_blocks = init_block_store(
            context.child("finalized_blocks"),
            &partition_prefix,
            &chain_config,
        )
        .await;

        let mailbox_size =
            NonZeroUsize::new(chain_config.mailbox_size).unwrap_or(NonZeroUsize::MIN);
        let fetch_concurrent =
            NonZeroUsize::new(chain_config.fetch_concurrent).unwrap_or(NonZeroUsize::MIN);
        let max_pending_acks = NZUsize!(1);
        let mempool = Mempool::default();
        let genesis_leader = scheme
            .participants()
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| me.clone());
        let application = Application::new(
            context.child("app"),
            network_id,
            genesis_leader,
            genesis_allocations.clone(),
            &partition_prefix,
            ApplicationConfig {
                page_cache_size: chain_config.page_cache_size,
                page_cache_count: chain_config.page_cache_count,
            },
        )
        .await;
        let owner_index = application.owner_index();
        if let Err(err) = replay_owner_index(&owner_index, &finalized_blocks).await {
            error!(?err, "owner index replay failed");
            panic!("{err}");
        }
        let owner_index_cursor = owner_index.cursor();
        info!(
            height = owner_index_cursor.height,
            payload = ?owner_index_cursor.payload,
            "owner index replayed",
        );
        let genesis_block = application.genesis_block();
        let stateful_startup_context = context.child("stateful_startup");
        let plan = SyncPlan::<_, Scheme, Standard<crate::HellasBlock>>::init(
            &stateful_startup_context,
            partition_prefix.clone(),
        )
        .await;
        let sync_floor = plan.floor().cloned();

        let epocher = FixedEpocher::new(NonZeroU64::new(u64::MAX).unwrap());
        let marshal_config = marshal::Config {
            provider: ConstantProvider::new(scheme.clone()),
            epocher: epocher.clone(),
            start: plan.marshal_start(genesis_block.clone()),
            partition_prefix: partition_prefix.clone(),
            mailbox_size,
            view_retention_timeout: ViewDelta::new(chain_config.activity_timeout),
            prunable_items_per_section: NZU64!(256),
            page_cache: page_cache.clone(),
            replay_buffer: NonZeroUsize::new(chain_config.replay_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            key_write_buffer: NonZeroUsize::new(chain_config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            value_write_buffer: NonZeroUsize::new(chain_config.write_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            block_codec_config: (),
            max_repair: NonZeroUsize::new(chain_config.max_repair).unwrap_or(NonZeroUsize::MIN),
            max_pending_acks,
            strategy: Sequential,
        };
        let (marshal_actor, marshal_mailbox, marshal_processed_height) =
            MarshalActor::<_, Standard<crate::HellasBlock>, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal_config,
            )
            .await;
        if let Err(err) =
            check_owner_index_reaches_marshal(owner_index_cursor.height, marshal_processed_height)
        {
            error!(?err, "owner index cannot reach marshal's processed height");
            panic!("{err}");
        }

        let broadcast_config = buffered::Config {
            public_key: me.clone(),
            mailbox_size,
            deque_size: chain_config.broadcast_cache_per_peer,
            priority: false,
            codec_config: (),
            peer_provider: oracle.clone(),
        };
        let (broadcast_engine, buffer) =
            buffered::Engine::new(context.child("broadcast"), broadcast_config);
        let broadcast_handle = broadcast_engine.start(broadcast_blocks);

        let resolver_cfg = marshal_resolver::Config {
            public_key: me.clone(),
            peer_provider: oracle.clone(),
            blocker: oracle.clone(),
            mailbox_size,
            initial: Duration::from_secs(1),
            timeout: chain_config.fetch_timeout,
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let resolver = marshal_resolver::init(
            context.child("marshal_resolver"),
            resolver_cfg,
            marshal_resolver_network,
        );

        let (qmdb_resolver_actor, qmdb_sync_resolver) =
            qmdb_resolver::Actor::<_, PublicKey, _, _, mmr::Family, UtxoDb<_>>::new(
                context.child("qmdb_resolver"),
                qmdb_resolver::Config {
                    peer_provider: oracle.clone(),
                    blocker: oracle.clone(),
                    database: None,
                    mailbox_size,
                    me: Some(me.clone()),
                    initial: Duration::from_secs(1),
                    timeout: chain_config.fetch_timeout,
                    fetch_retry_timeout: Duration::from_millis(100),
                    max_serve_ops: NZU64!(64),
                    priority_requests: false,
                    priority_responses: false,
                },
            );
        let qmdb_resolver_handle = qmdb_resolver_actor.start(qmdb_resolver_network);

        let db_config = utxo_db_config(
            &context,
            &partition_prefix,
            chain_config.page_cache_size,
            chain_config.page_cache_count,
        );
        let (stateful_actor, stateful_mailbox) = StatefulActor::init(
            context.child("stateful"),
            StatefulConfig {
                application,
                db_config,
                input_provider: mempool.clone(),
                marshal: marshal_mailbox.clone(),
                mailbox_size,
                plan,
                resolvers: qmdb_sync_resolver.clone(),
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(64),
                    apply_batch_size: 1024,
                    max_outstanding_requests: 8,
                    update_channel_size: NZUsize!(256),
                    max_retained_roots: 8,
                },
                prune_config: None,
            },
        );

        let deferred = Deferred::new(
            context.child("deferred"),
            stateful_mailbox.clone(),
            marshal_mailbox.clone(),
            epocher,
        );
        let (activity_tx, _) = ::tokio::sync::broadcast::channel(1024);
        let simplex_config = simplex::Config {
            scheme,
            elector: RoundRobin::<commonware_cryptography::Sha256>::default(),
            blocker: oracle.clone(),
            automaton: deferred.clone(),
            relay: deferred,
            reporter: ActivityReporter::new(marshal_mailbox.clone(), activity_tx.clone()),
            strategy: Sequential,
            partition: format!("{partition_prefix}-simplex"),
            mailbox_size,
            epoch: Epoch::zero(),
            floor: sync_floor.map_or_else(
                || simplex::config::Floor::Genesis(genesis_block.digest()),
                simplex::config::Floor::Finalized,
            ),
            replay_buffer: NonZeroUsize::new(chain_config.replay_buffer)
                .unwrap_or(NonZeroUsize::MIN),
            write_buffer: NonZeroUsize::new(chain_config.write_buffer).unwrap_or(NonZeroUsize::MIN),
            page_cache,
            leader_timeout: chain_config.leader_timeout,
            certification_timeout: chain_config.certification_timeout,
            timeout_retry: chain_config.nullify_retry,
            activity_timeout: ViewDelta::new(chain_config.activity_timeout),
            skip_timeout: chain_config.skip_timeout,
            fetch_timeout: chain_config.fetch_timeout,
            fetch_concurrent,
            forwarding: ForwardingPolicy::Disabled,
        };
        let simplex_engine = simplex::Engine::new(context.child("simplex"), simplex_config);

        let marshal_handle = marshal_actor.start(stateful_mailbox.clone(), buffer, resolver);
        let stateful_handle = stateful_actor.start();

        let databases = stateful_mailbox.subscribe_databases().await;
        let startup_root = databases.read().await.root();
        info!(?startup_root, "application startup barrier passed");

        // Simplex can immediately ask Marshal for its proposal parent. That
        // lookup uses the broadcast buffer, whose peer subscription is served
        // only after the network starts below. If it overtakes Stateful's
        // startup block lookup, startup waits in a circle. Start consensus only
        // once the application database handoff is complete.
        let engine_handle = simplex_engine.start(vote, certificate, consensus_resolver);

        let light_client = LocalLightClient::new(
            databases.clone(),
            owner_index.clone(),
            mempool.clone(),
            ChainIndexer::new(marshal_mailbox.clone()),
            consensus_info.clone(),
        );
        let light_client_rpc_state = LightClientRpcState::default();
        let light_client_server_handle = if let Some(addr) = validator_config.light_client_bind {
            Some(
                spawn_light_client_server(
                    addr,
                    light_client.clone(),
                    activity_tx.clone(),
                    light_client_rpc_state.clone(),
                )
                .await
                .unwrap_or_else(|source| {
                    panic!("{}", ValidatorError::LightClientBind { addr, source })
                }),
            )
        } else {
            None
        };
        let relay_handles: Vec<_> = validator_config
            .relay_urls
            .iter()
            .cloned()
            .map(|relay_url| {
                let genesis = validator_config.genesis.clone();
                let private_key = relay_private_key.clone();
                let light_client = light_client.clone();
                let activity_tx = activity_tx.clone();
                let rpc_state = light_client_rpc_state.clone();
                ::tokio::spawn(async move {
                    let mut retry = Duration::from_secs(1);
                    loop {
                        let connected_at = Instant::now();
                        info!(%relay_url, "connecting light client relay");
                        match serve_light_client_relay(
                            &relay_url,
                            &genesis,
                            &private_key,
                            light_client.clone(),
                            activity_tx.clone(),
                            rpc_state.clone(),
                        )
                        .await
                        {
                            Ok(()) => warn!(%relay_url, "light client relay disconnected"),
                            Err(error) => {
                                warn!(%relay_url, %error, "light client relay connection failed");
                            }
                        }
                        let next_retry = if connected_at.elapsed() >= Duration::from_secs(60) {
                            Duration::from_secs(1)
                        } else {
                            retry.saturating_mul(2).min(Duration::from_secs(30))
                        };
                        ::tokio::time::sleep(retry).await;
                        retry = next_retry;
                    }
                })
            })
            .collect();

        // Start networking only after the app + consensus engine are initialized.
        let network_handle = network.start();

        let signal_waiter = wait_for_shutdown_signal()
            .map(ShutdownTrigger::Signal)
            .boxed();
        let network_waiter = network_handle
            .map(|_| ShutdownTrigger::NetworkExited)
            .boxed();
        let engine_waiter = engine_handle.map(|_| ShutdownTrigger::EngineExited).boxed();
        let marshal_waiter = marshal_handle
            .map(|_| ShutdownTrigger::EngineExited)
            .boxed();
        let broadcast_waiter = broadcast_handle
            .map(|_| ShutdownTrigger::EngineExited)
            .boxed();
        let stateful_waiter = stateful_handle
            .map(|_| ShutdownTrigger::EngineExited)
            .boxed();
        let qmdb_resolver_waiter = qmdb_resolver_handle
            .map(|_| ShutdownTrigger::EngineExited)
            .boxed();
        let light_client_server_waiter = light_client_server_handle.map(|handle| {
            handle
                .map(|_| ShutdownTrigger::LightClientServerExited)
                .boxed()
        });
        let mut waiters = vec![
            signal_waiter,
            network_waiter,
            engine_waiter,
            marshal_waiter,
            broadcast_waiter,
            stateful_waiter,
            qmdb_resolver_waiter,
        ];
        if let Some(waiter) = light_client_server_waiter {
            waiters.push(waiter);
        }
        waiters.extend(
            relay_handles
                .into_iter()
                .map(|handle| handle.map(|_| ShutdownTrigger::RelayExited).boxed()),
        );

        let (trigger, _, _) = futures::future::select_all(waiters).await;

        let signal_triggered = matches!(trigger, ShutdownTrigger::Signal(_));
        match trigger {
            ShutdownTrigger::Signal(signal) => {
                info!(signal, "received shutdown signal");
            }
            ShutdownTrigger::NetworkExited => {
                warn!("network task exited unexpectedly; triggering shutdown");
            }
            ShutdownTrigger::EngineExited => {
                warn!("engine task exited unexpectedly; triggering shutdown");
            }
            ShutdownTrigger::LightClientServerExited => {
                warn!("light-client server exited unexpectedly; triggering shutdown");
            }
            ShutdownTrigger::RelayExited => {
                warn!("relay task exited unexpectedly; triggering shutdown");
            }
        }

        graceful_stop(context, signal_triggered).await;

        if let Some(provider) = tracer_provider
            && let Err(err) = provider.shutdown()
        {
            warn!(?err, "failed to flush OTLP traces on shutdown");
        }

        // Any non-signal trigger means a sibling actor died unexpectedly. Exit non-zero so
        // systemd's `Restart=on-failure` kicks in instead of treating us as a clean shutdown.
        if !signal_triggered {
            std::process::exit(1);
        }
    });
    Ok(())
}
