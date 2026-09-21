use std::time::Duration;
use std::{fs, path::PathBuf};

use anyhow::Context as _;
use clap::{Args, Subcommand, ValueEnum};
use hellas_chain::domain::{Digest, SettlementKey, Transaction};
use hellas_chain::genesis::{Genesis, known_network, known_network_names};
use hellas_chain::{FinalizedBlockQuery, LightClient as _, QueryError, client::RemoteLightClient};
use hellas_kernel::{
    BlockHeight, CloseKind as KernelCloseKind, CoinId, Decode as _, EdgeId, Encode as _, Funding,
    List, MAX_EDGE_OUTPUTS, MAX_PARTY_INPUTS, NetworkId, Parties, Payout, Proof, ProtocolCode,
    Terms, Tx,
};

use self::signer::{AuthScheme, DevSigner};
use crate::commands::CliResult;

#[derive(Subcommand)]
pub enum ChainCommand {
    /// Query the chain light-client API
    Query {
        /// RPC endpoint
        #[arg(long)]
        rpc: String,
        #[command(subcommand)]
        query: QueryCommand,
    },
    /// Sign and submit a kernel edge Open transaction
    Open(OpenArgs),
    /// Sign and submit a kernel edge Close transaction
    Close(CloseArgs),
    /// Run or manage a local indexer
    #[cfg(feature = "indexer")]
    Indexer {
        #[command(subcommand)]
        command: IndexerCommand,
    },
    /// Run or manage a validator
    #[cfg(feature = "validator")]
    Validator {
        #[command(subcommand)]
        command: ValidatorCommand,
    },
}

#[derive(Args)]
pub struct OpenArgs {
    /// Chain light-client RPC endpoint
    #[arg(long)]
    rpc: String,
    /// Network to sign for: a shipped name (`devnet`) or a
    /// full network id
    #[arg(long, default_value = "devnet", conflicts_with = "genesis")]
    network: String,
    /// Genesis document to sign for, instead of a shipped network
    #[arg(long)]
    genesis: Option<PathBuf>,
    /// Maker secret-scalar file path (32 raw bytes or 64 hex digits)
    #[arg(long)]
    maker_key: PathBuf,
    /// Maker authorization scheme
    #[arg(long, value_enum)]
    maker_auth: AuthScheme,
    /// Taker secret-scalar file path (32 raw bytes or 64 hex digits)
    #[arg(long)]
    taker_key: PathBuf,
    /// Taker authorization scheme
    #[arg(long, value_enum)]
    taker_auth: AuthScheme,
    /// Maker funding coin ID; repeat or comma-separate values
    #[arg(long = "maker-funding", value_delimiter = ',')]
    maker_funding: Vec<String>,
    /// Taker funding coin ID; repeat or comma-separate values
    #[arg(long = "taker-funding", value_delimiter = ',')]
    taker_funding: Vec<String>,
    /// Chain-version-local protocol code
    #[arg(long)]
    protocol: u8,
    /// Earliest block height at which the timeout close is valid
    #[arg(long)]
    timeout: u64,
    /// Committed timeout payout as SETTLEMENT_KEY:VALUE; repeat or comma-separate values
    #[arg(long = "timeout-payout", value_delimiter = ',')]
    timeout_payouts: Vec<String>,
    /// Write the exact canonical Terms reveal needed by a future timeout close
    #[arg(long)]
    terms_out: Option<PathBuf>,
}

#[derive(Args)]
pub struct CloseArgs {
    /// Chain light-client RPC endpoint
    #[arg(long)]
    rpc: String,
    /// Network to sign for: a shipped name (`devnet`) or a
    /// full network id
    #[arg(long, default_value = "devnet", conflicts_with = "genesis")]
    network: String,
    /// Genesis document to sign for, instead of a shipped network
    #[arg(long)]
    genesis: Option<PathBuf>,
    /// Hex-encoded kernel edge ID
    #[arg(long)]
    edge_id: String,
    /// Close proof kind
    #[arg(long, value_enum)]
    kind: CloseKind,
    /// Close payout as SETTLEMENT_KEY:VALUE; repeat or comma-separate values
    #[arg(long = "payout", value_delimiter = ',')]
    payouts: Vec<String>,
    /// Maker secret-scalar file path; required for a mutual close
    #[arg(long)]
    maker_key: Option<PathBuf>,
    /// Maker authorization scheme; required for a mutual close
    #[arg(long, value_enum)]
    maker_auth: Option<AuthScheme>,
    /// Taker secret-scalar file path; required for a mutual close
    #[arg(long)]
    taker_key: Option<PathBuf>,
    /// Taker authorization scheme; required for a mutual close
    #[arg(long, value_enum)]
    taker_auth: Option<AuthScheme>,
    /// Canonical Terms file written by Open; required for a timeout close
    #[arg(long)]
    terms_file: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CloseKind {
    Mutual,
    Timeout,
}

#[derive(Subcommand)]
pub enum QueryCommand {
    /// Get the latest finalized block
    LatestBlock,
    /// Get the current state root
    StateRoot,
    /// Get the finalization certificate for a payload
    Finalization {
        /// Hex-encoded 32-byte payload digest
        #[arg(long)]
        payload: String,
    },
    /// Get a finalized block by height, payload, or latest when neither is set
    FinalizedBlock {
        /// Finalized block height
        #[arg(long)]
        height: Option<u64>,
        /// Hex-encoded 32-byte payload digest
        #[arg(long)]
        payload: Option<String>,
    },
    /// Look up a coin by object ID at an indexed payload
    Coin {
        /// Hex-encoded 32-byte object ID
        #[arg(long)]
        object_id: String,
        /// Hex-encoded finalized payload to query
        #[arg(long)]
        payload: String,
    },
    /// Look up a kernel edge by object ID at an indexed payload
    Edge {
        /// Hex-encoded 32-byte object ID
        #[arg(long)]
        object_id: String,
        /// Hex-encoded finalized payload to query
        #[arg(long)]
        payload: String,
    },
    /// List all known validators
    Validators,
    /// List coins owned by an address
    CoinsByOwner {
        /// Base58-encoded settlement key
        #[arg(long)]
        owner: String,
    },
    /// List edge records associated with a settlement key
    EdgesByOwner {
        /// Base58-encoded settlement key
        #[arg(long)]
        owner: String,
    },
}

#[cfg(feature = "indexer")]
#[derive(Subcommand)]
pub enum IndexerCommand {
    /// Serve verified proofs from a local full follower on a loopback listener
    Serve {
        #[arg(long)]
        rpc: String,
        /// Authenticated trust document, provisioned independently of the RPC origin
        #[arg(long)]
        trust: PathBuf,
        /// Exact authenticated genesis JSON; defaults to the embedded devnet document
        #[arg(long)]
        genesis: Option<PathBuf>,
        #[arg(long)]
        storage_dir: PathBuf,
        #[arg(long, default_value = "hellas-explorer")]
        partition_prefix: String,
        /// Loopback listener for the local tunnel daemon
        #[arg(long, default_value = "127.0.0.1:8788")]
        listen: std::net::SocketAddr,
    },
    /// Follow a validator and maintain a verified finalized-block archive
    Follow {
        /// Chain light-client RPC endpoint
        #[arg(long)]
        rpc: String,
        /// Local storage directory
        #[arg(long)]
        storage_dir: Option<PathBuf>,
        /// Storage partition prefix
        #[arg(long, default_value = "hellas-follower")]
        partition_prefix: String,
    },
}

#[cfg(feature = "validator")]
#[derive(Subcommand)]
pub enum ValidatorCommand {
    /// Export public epoch-zero explorer trust from a validator config and exact genesis file
    ExportTrust {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        genesis: PathBuf,
    },
    /// Generate one cryptographically random validator configuration per committee member
    GenerateNetwork {
        /// Stable lowercase network identifier
        #[arg(long)]
        network_id: String,
        /// Total number of validators in the network
        #[arg(short = 'n', long)]
        validators: u32,
        /// Validator labels in canonical committee order
        #[arg(long, value_delimiter = ',')]
        labels: Vec<String>,
        /// Validator addresses in canonical committee order
        #[arg(long, value_delimiter = ',')]
        addresses: Vec<String>,
        /// Starting consensus P2P port
        #[arg(long, default_value = "3000")]
        start_port: u16,
        /// Starting Prometheus metrics port
        #[arg(long, default_value = "9090")]
        metrics_base_port: u16,
        /// Relay or indexer WebSocket origins to serve through
        #[arg(long = "relay-url", value_delimiter = ',')]
        relay_urls: Vec<String>,
        /// Genesis allocation as address:balance
        #[arg(long = "genesis-allocation")]
        genesis_allocations: Vec<String>,
        /// Generate a new P-256 treasury key and allocate this balance to it
        #[arg(long)]
        treasury_balance: Option<u64>,
        /// New directory that will receive genesis.json and validator-N.toml
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Generate a TOML config for one validator
    Config {
        /// Total number of validators in the network
        #[arg(short = 'n', long)]
        validators: u32,
        /// This validator's index
        #[arg(short = 'i', long = "validator", default_value = "0")]
        validator: u32,
        /// Starting port number
        #[arg(long, default_value = "3000")]
        start_port: u16,
        /// Deterministic seed for local setups
        #[arg(long)]
        seed: Option<u64>,
        /// Validator addresses in index order
        #[arg(long, value_delimiter = ',')]
        addresses: Option<Vec<String>>,
        /// Relay or indexer WebSocket origins to serve through
        #[arg(long = "relay-url", value_delimiter = ',')]
        relay_urls: Vec<String>,
        /// Prometheus metrics port
        #[arg(long)]
        metrics_port: Option<u16>,
        /// Direct light-client RPC bind address
        #[arg(long)]
        light_client_bind: Option<std::net::SocketAddr>,
        /// Canonical genesis JSON; validator identities must match --seed
        #[arg(long)]
        genesis: Option<PathBuf>,
        /// Genesis allocation as address:balance
        #[arg(long = "genesis-allocation")]
        genesis_allocations: Vec<String>,
    },
    /// Run a validator
    Run {
        /// Path to validator TOML config
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate a validator TOML config
    CheckConfig {
        /// Path to validator TOML config
        #[arg(long)]
        config: PathBuf,
    },
}

pub async fn run(command: ChainCommand) -> CliResult {
    match command {
        ChainCommand::Query { rpc, query } => run_query(rpc, query).await,
        ChainCommand::Open(args) => run_open(args).await,
        ChainCommand::Close(args) => run_close(args).await,
        #[cfg(feature = "indexer")]
        ChainCommand::Indexer { command } => run_indexer(command).await,
        #[cfg(feature = "validator")]
        ChainCommand::Validator { command } => run_validator(command).await,
    }
}

async fn run_query(rpc: String, query: QueryCommand) -> CliResult {
    let client = connect_verified(rpc).await?;
    match query {
        QueryCommand::LatestBlock => match client.get_latest_block().await? {
            Some(block) => {
                println!("height {}", block.height);
                println!("payload {}", hex::encode(block.payload));
                println!("state_root {}", hex::encode(block.state_root));
                println!("finalization {}", hex::encode(block.finalization));
            }
            None => println!("none"),
        },
        QueryCommand::StateRoot => match client.get_state_root().await? {
            Some(root) => println!("{}", hex::encode(root)),
            None => println!("none"),
        },
        QueryCommand::Finalization { payload } => {
            let payload = parse_hex_digest(&payload, "payload")?;
            match client.get_finalization(payload).await? {
                Some(finalization) => println!("{}", hex::encode(finalization)),
                None => println!("none"),
            }
        }
        QueryCommand::FinalizedBlock { height, payload } => {
            let query = finalized_block_query(height, payload)?;
            match client.get_finalized_block(query).await? {
                Some(block) => {
                    println!("height {}", block.snapshot.height);
                    println!("payload {}", hex::encode(block.snapshot.payload));
                    println!("state_root {}", hex::encode(block.snapshot.state_root));
                    println!("finalization {}", hex::encode(block.snapshot.finalization));
                    println!("block {}", hex::encode(block.block));
                }
                None => println!("none"),
            }
        }
        QueryCommand::Coin { object_id, payload } => {
            let object_id = parse_hex_digest(&object_id, "object_id")?;
            let payload = parse_hex_digest(&payload, "payload")?;
            match client.get_coin(payload, object_id).await? {
                Some(coin) => println!("{} {}", coin.owner, coin.value),
                None => println!("none"),
            }
        }
        QueryCommand::Edge { object_id, payload } => {
            let object_id = parse_hex_digest(&object_id, "object_id")?;
            let payload = parse_hex_digest(&payload, "payload")?;
            match client.get_edge(payload, object_id).await? {
                Some(lookup) => {
                    println!("state_root {}", hex::encode(lookup.state_root));
                    match lookup.edge {
                        Some(edge) => {
                            println!("value {}", edge.value);
                            println!("reserve {}", edge.reserve);
                            println!("close_fee_base {}", edge.close_fees.base());
                            println!("close_fee_slot {}", edge.close_fees.slot());
                            println!("close_fee_proof {}", edge.close_fees.proof());
                            println!("close_fee_lifetime {}", edge.close_fees.lifetime());
                            println!("timeout {}", edge.timeout.get());
                            println!("maker {}", edge.maker);
                            println!("taker {}", edge.taker);
                            println!("terms_hash {}", hex::encode(edge.terms_hash.to_bytes()));
                        }
                        None => println!("none"),
                    }
                }
                None => println!("none"),
            }
        }
        QueryCommand::Validators => {
            for validator in client.get_validators().await? {
                println!("{validator}");
            }
        }
        QueryCommand::CoinsByOwner { owner } => {
            let owner = owner
                .parse::<SettlementKey>()
                .map_err(|err| anyhow::anyhow!("invalid owner settlement key: {err}"))?;
            match client.get_coins_by_owner(owner).await? {
                Some(owner_coins) => {
                    println!("height {}", owner_coins.snapshot.height);
                    println!("payload {}", hex::encode(owner_coins.snapshot.payload));
                    println!(
                        "state_root {}",
                        hex::encode(owner_coins.snapshot.state_root)
                    );
                    println!(
                        "finalization {}",
                        hex::encode(owner_coins.snapshot.finalization)
                    );
                    for (object_id, value) in owner_coins.coins {
                        println!("{} {}", hex::encode(object_id), value);
                    }
                }
                None => println!("none"),
            }
        }
        QueryCommand::EdgesByOwner { owner } => {
            let owner = owner
                .parse::<SettlementKey>()
                .map_err(|err| anyhow::anyhow!("invalid owner settlement key: {err}"))?;
            match client.get_edges_by_owner(owner).await? {
                Some(owner_edges) => {
                    println!("height {}", owner_edges.snapshot.height);
                    println!("payload {}", hex::encode(owner_edges.snapshot.payload));
                    println!(
                        "state_root {}",
                        hex::encode(owner_edges.snapshot.state_root)
                    );
                    println!(
                        "finalization {}",
                        hex::encode(owner_edges.snapshot.finalization)
                    );
                    for edge in owner_edges.edges {
                        println!(
                            "{} {} {}",
                            hex::encode(edge.object_id),
                            edge.maker,
                            edge.taker
                        );
                    }
                }
                None => println!("none"),
            }
        }
    }
    Ok(())
}

async fn run_open(args: OpenArgs) -> CliResult {
    let maker = DevSigner::load(args.maker_auth, &args.maker_key)?;
    let taker = DevSigner::load(args.taker_auth, &args.taker_key)?;
    let funding = Funding::new(
        parse_coin_ids(&args.maker_funding, "maker funding")?,
        parse_coin_ids(&args.taker_funding, "taker funding")?,
    );
    let timeout_outputs = parse_payouts(&args.timeout_payouts, "timeout payout")?;
    let terms = Terms::basic(
        ProtocolCode::new(args.protocol),
        Parties::new(maker.party_key(), taker.party_key()),
        BlockHeight::new(args.timeout),
        timeout_outputs,
    );
    let edge_id = Tx::edge_id_of(&funding, &terms);
    let network = selected_network(&args.network, args.genesis)?;
    let client = connect_verified(args.rpc).await?;
    let network = confirm_network(network, &client).await?;
    let open_hash = Tx::open_hash(network, &funding, &terms);
    let tx = Tx::open(
        funding,
        terms.clone(),
        maker.sign(open_hash)?,
        taker.sign(open_hash)?,
    );

    // Persist the reveal before submission. A failed submission leaves only a
    // harmless public terms file; a successful submission can never strand a
    // timeout edge because its reveal failed to reach disk afterward.
    if let Some(path) = args.terms_out {
        write_terms(&path, &terms)?;
    }
    let outcome = client.submit_tx(Transaction::Kernel(tx)).await?;
    println!("{outcome}");

    println!("edge_id {}", hex::encode(edge_id.to_bytes()));
    println!("terms_hash {}", hex::encode(terms.hash().to_bytes()));
    println!("maker {}", SettlementKey::from(maker.party_key()));
    println!("taker {}", SettlementKey::from(taker.party_key()));
    Ok(())
}

async fn run_close(args: CloseArgs) -> CliResult {
    let edge_id = parse_edge_id(&args.edge_id)?;
    let outputs = parse_payouts(&args.payouts, "payout")?;
    let network = selected_network(&args.network, args.genesis)?;
    let client = connect_verified(args.rpc).await?;
    let network = confirm_network(network, &client).await?;
    let edge = get_live_edge(&client, edge_id).await?;

    let proof = match args.kind {
        CloseKind::Mutual => {
            if args.terms_file.is_some() {
                anyhow::bail!("--terms-file is only valid with --kind timeout");
            }
            let maker = load_mutual_signer("maker", args.maker_auth, args.maker_key.as_deref())?;
            let taker = load_mutual_signer("taker", args.taker_auth, args.taker_key.as_deref())?;
            if SettlementKey::from(maker.party_key()) != edge.maker {
                anyhow::bail!("maker key file does not control the live edge maker");
            }
            if SettlementKey::from(taker.party_key()) != edge.taker {
                anyhow::bail!("taker key file does not control the live edge taker");
            }
            let hash = Tx::payload_hash(
                network,
                edge_id,
                KernelCloseKind::Mutual,
                edge.terms_hash,
                &outputs,
            );
            Proof::mutual(maker.sign(hash)?, taker.sign(hash)?)
        }
        CloseKind::Timeout => {
            if args.maker_key.is_some()
                || args.maker_auth.is_some()
                || args.taker_key.is_some()
                || args.taker_auth.is_some()
            {
                anyhow::bail!("signer options are only valid with --kind mutual");
            }
            let path = args
                .terms_file
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--terms-file is required with --kind timeout"))?;
            let terms = read_terms(path)?;
            if terms.hash() != edge.terms_hash {
                anyhow::bail!("terms file does not match the live edge commitment");
            }
            if terms.timeout_outputs() != Some(&outputs) {
                anyhow::bail!("timeout payouts do not match the committed Terms file");
            }
            Proof::timeout(terms)
        }
    };

    let output_ids = Tx::close_output_ids(edge_id, &outputs);
    let outcome = client
        .submit_tx(Transaction::Kernel(Tx::close(edge_id, proof, outputs)))
        .await?;
    println!("{outcome}");
    println!("edge_id {}", hex::encode(edge_id.to_bytes()));
    for output_id in output_ids {
        println!("payout_id {}", hex::encode(output_id.to_bytes()));
    }
    Ok(())
}

async fn connect_verified(rpc: String) -> CliResult<RemoteLightClient> {
    let client = RemoteLightClient::connect(rpc).await?;
    let consensus_info = client.get_consensus_info().await?;
    Ok(client.with_consensus_info(&consensus_info)?)
}

/// Resolves the network to sign for, and refuses if the node on the
/// other end is not on it.
///
/// The genesis document is the authority — a signature has to be built
/// before anyone can tell you whether it was wanted — but the node
/// reports its own network, so the mismatch is worth catching here
/// rather than as an unexplained rejected transaction. Pointing devnet
/// keys at a different network node is exactly the mistake this slice makes
/// impossible to get away with silently.
/// Resolves the network to sign for, without touching the network.
///
/// `--network` names one of the documents compiled into this binary;
/// `--genesis` hands over a document instead, for a network this binary
/// does not ship. Local and fallible first, so a mistyped network is
/// reported as a mistyped network rather than as whatever the RPC
/// endpoint happens to say.
fn selected_network(network: &str, genesis: Option<PathBuf>) -> CliResult<NetworkId> {
    let document = match genesis {
        Some(path) => std::fs::read_to_string(&path)
            .with_context(|| format!("reading genesis document {}", path.display()))?,
        None => known_network(network)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown network `{network}`; this binary ships {}. \
                     Pass --genesis <path> for a network it does not ship.",
                    known_network_names().join(", "),
                )
            })?
            .json
            .to_string(),
    };
    let genesis: Genesis =
        serde_json::from_str(&document).context("parsing the genesis document")?;
    Ok(hellas_chain::domain::network_id(&genesis)?)
}

/// Refuses if the node on the other end is not on `network`.
///
/// The local selection is the authority — a signature has to be built
/// before anyone can tell you whether it was wanted — but the node
/// reports its own network, so the mismatch is caught here rather than
/// as an unexplained rejected transaction. Pointing devnet keys at a
/// different network node is exactly the mistake this makes impossible to get
/// away with silently.
async fn confirm_network(network: NetworkId, client: &RemoteLightClient) -> CliResult<NetworkId> {
    let reported = client.get_consensus_info().await?.network_id;
    if reported != network.as_str() {
        anyhow::bail!(
            "signing for network `{network}`, but the node at the other end reports `{reported}`",
        );
    }
    Ok(network)
}

async fn get_live_edge(
    client: &RemoteLightClient,
    edge_id: EdgeId,
) -> CliResult<hellas_chain::EdgeState> {
    const SNAPSHOT_RETRIES: usize = 40;
    const SNAPSHOT_RETRY_DELAY: Duration = Duration::from_millis(250);

    for attempt in 0..SNAPSHOT_RETRIES {
        let latest = client
            .get_latest_block()
            .await?
            .ok_or_else(|| anyhow::anyhow!("chain has no finalized block"))?;
        match client
            .get_edge(latest.payload, Digest::from(edge_id.to_bytes()))
            .await
        {
            Ok(Some(lookup)) => {
                return lookup
                    .edge
                    .ok_or_else(|| anyhow::anyhow!("edge does not exist"));
            }
            Ok(None) => {}
            Err(QueryError::StateUnavailable(_)) => {}
            Err(error) => return Err(error.into()),
        }
        if attempt + 1 < SNAPSHOT_RETRIES {
            tokio::time::sleep(SNAPSHOT_RETRY_DELAY).await;
        }
    }
    Err(anyhow::anyhow!("edge state is not indexed yet"))
}

fn load_mutual_signer(
    party: &'static str,
    scheme: Option<AuthScheme>,
    path: Option<&std::path::Path>,
) -> CliResult<DevSigner> {
    let scheme = scheme.ok_or_else(|| anyhow::anyhow!("--{party}-auth is required"))?;
    let path = path.ok_or_else(|| anyhow::anyhow!("--{party}-key is required"))?;
    DevSigner::load(scheme, path)
}

fn parse_coin_ids(
    raw: &[String],
    field: &'static str,
) -> CliResult<List<CoinId, MAX_PARTY_INPUTS>> {
    if raw.len() > MAX_PARTY_INPUTS {
        anyhow::bail!(
            "{field} accepts at most {MAX_PARTY_INPUTS} coin ids, got {}",
            raw.len()
        );
    }
    let mut ids = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS];
    for (slot, value) in ids.iter_mut().zip(raw) {
        *slot = CoinId::from_bytes(parse_hex_32(value, field)?);
    }
    List::new(ids, raw.len()).ok_or_else(|| anyhow::anyhow!("{field} exceeded its kernel bound"))
}

fn parse_payouts(raw: &[String], field: &'static str) -> CliResult<List<Payout, MAX_EDGE_OUTPUTS>> {
    if raw.len() > MAX_EDGE_OUTPUTS {
        anyhow::bail!(
            "{field} accepts at most {MAX_EDGE_OUTPUTS} entries, got {}",
            raw.len()
        );
    }
    let mut payouts = [Payout::default(); MAX_EDGE_OUTPUTS];
    for (slot, value) in payouts.iter_mut().zip(raw) {
        let (owner, value) = value
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("{field} must have the form SETTLEMENT_KEY:VALUE"))?;
        let owner = owner
            .parse::<SettlementKey>()
            .map_err(|error| anyhow::anyhow!("invalid {field} settlement key: {error}"))?;
        let value = value
            .parse::<u64>()
            .map_err(|error| anyhow::anyhow!("invalid {field} value: {error}"))?;
        *slot = Payout::new(owner.into_kernel(), value);
    }
    List::new(payouts, raw.len())
        .ok_or_else(|| anyhow::anyhow!("{field} exceeded its kernel bound"))
}

fn parse_edge_id(raw: &str) -> CliResult<EdgeId> {
    Ok(EdgeId::from_bytes(parse_hex_32(raw, "edge_id")?))
}

fn parse_hex_32(raw: &str, field: &'static str) -> CliResult<[u8; 32]> {
    let bytes =
        hex::decode(raw).map_err(|error| anyhow::anyhow!("bad hex for {field}: {error}"))?;
    let actual = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must be 32 bytes, got {actual}"))
}

fn write_terms(path: &std::path::Path, terms: &Terms) -> CliResult {
    let mut bytes = vec![0_u8; Terms::MAX_ENCODED_SIZE];
    let len = terms.write_to(&mut bytes);
    bytes.truncate(len);
    fs::write(path, bytes)
        .map_err(|error| anyhow::anyhow!("failed to write terms file {}: {error}", path.display()))
}

fn read_terms(path: &std::path::Path) -> CliResult<Terms> {
    let bytes = fs::read(path).map_err(|error| {
        anyhow::anyhow!("failed to read terms file {}: {error}", path.display())
    })?;
    Terms::decode_exact(&bytes).map_err(|error| {
        anyhow::anyhow!("invalid canonical terms file {}: {error:?}", path.display())
    })
}

#[cfg(feature = "indexer")]
async fn run_indexer(command: IndexerCommand) -> CliResult {
    match command {
        IndexerCommand::Serve {
            rpc,
            trust,
            genesis,
            storage_dir,
            partition_prefix,
            listen,
        } => {
            let trust = serde_json::from_slice(&fs::read(&trust)?)?;
            let genesis_json = genesis.map(fs::read).transpose()?;
            tokio::task::spawn_blocking(move || {
                hellas_chain::explorer_origin::run(hellas_chain::explorer_origin::OriginOptions {
                    rpc,
                    trust,
                    genesis_json,
                    storage_dir,
                    partition_prefix,
                    listen,
                    status: follower_status_sink(),
                })
            })
            .await?
            .map_err(anyhow::Error::from_boxed)?;
        }

        IndexerCommand::Follow {
            rpc,
            storage_dir,
            partition_prefix,
        } => {
            tokio::task::spawn_blocking(move || {
                hellas_chain::follower::run(hellas_chain::follower::FollowerOptions {
                    rpc,
                    storage_dir,
                    partition_prefix,
                    status: follower_status_sink(),
                })
            })
            .await??
        }
    }
    Ok(())
}

#[cfg(feature = "indexer")]
fn follower_status_sink() -> hellas_chain::follower::FollowerStatusSink {
    hellas_chain::follower::FollowerStatusSink::callback(|status| match status {
        hellas_chain::follower::FollowerStatus::ActivityStreamSubscribed => {
            println!("activity stream subscribed");
        }
        hellas_chain::follower::FollowerStatus::ActivityFinalization { payload } => {
            println!("activity finalization {}", hex::encode(payload));
        }
        hellas_chain::follower::FollowerStatus::BlockIngested { height, outcome } => {
            println!("height {height} {outcome:?}");
        }
    })
}

#[cfg(feature = "validator")]
async fn run_validator(command: ValidatorCommand) -> CliResult {
    let command = match command {
        ValidatorCommand::ExportTrust { config, genesis } => {
            hellas_chain::validator::Command::ExportTrust { config, genesis }
        }
        ValidatorCommand::GenerateNetwork {
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
        } => hellas_chain::validator::Command::GenerateNetwork {
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
        },
        ValidatorCommand::Config {
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
        } => hellas_chain::validator::Command::Config {
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
        },
        ValidatorCommand::Run { config } => hellas_chain::validator::Command::Run { config },
        ValidatorCommand::CheckConfig { config } => {
            hellas_chain::validator::Command::CheckConfig { config }
        }
    };
    tokio::task::spawn_blocking(move || hellas_chain::validator::run_command(command)).await??;
    Ok(())
}

fn parse_hex_digest(raw: &str, field: &'static str) -> CliResult<Digest> {
    Ok(Digest::from(parse_hex_32(raw, field)?))
}

fn finalized_block_query(
    height: Option<u64>,
    payload: Option<String>,
) -> CliResult<FinalizedBlockQuery> {
    match (height, payload) {
        (Some(height), None) => Ok(FinalizedBlockQuery::Height(height)),
        (None, Some(payload)) => Ok(FinalizedBlockQuery::Payload(parse_hex_digest(
            &payload, "payload",
        )?)),
        (None, None) => Ok(FinalizedBlockQuery::Latest),
        (Some(_), Some(_)) => Err(anyhow::anyhow!(
            "--height and --payload are mutually exclusive"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_kernel::Key;

    #[test]
    fn canonical_terms_file_round_trips_and_rejects_trailing_bytes() {
        let owner = SettlementKey::from(Key::from_bytes([2; Key::LENGTH]));
        let payouts =
            parse_payouts(&[format!("{owner}:42")], "timeout payout").expect("valid payout");
        let terms = Terms::basic(
            ProtocolCode::new(7),
            Parties::new(owner.into_kernel(), owner.into_kernel()),
            BlockHeight::new(99),
            payouts,
        );
        let directory = tempfile::tempdir().expect("temporary terms directory");
        let path = directory.path().join("edge.terms");
        write_terms(&path, &terms).expect("write terms");
        assert_eq!(read_terms(&path).expect("read terms"), terms);

        let mut bytes = fs::read(&path).expect("read terms bytes");
        bytes.push(0);
        fs::write(&path, bytes).expect("write trailing byte");
        assert!(read_terms(&path).is_err());
    }

    #[test]
    fn funding_and_payout_parsers_enforce_kernel_bounds() {
        let too_many = vec!["00".repeat(CoinId::LENGTH); MAX_PARTY_INPUTS + 1];
        assert!(parse_coin_ids(&too_many, "maker funding").is_err());

        let owner = SettlementKey::from(Key::from_bytes([2; Key::LENGTH]));
        let too_many = vec![format!("{owner}:1"); MAX_EDGE_OUTPUTS + 1];
        assert!(parse_payouts(&too_many, "payout").is_err());
    }
}

mod signer {
    //! File-backed development signers for kernel settlement transactions.
    //!
    //! This is deliberately a CLI-edge facility, not wallet key custody. Secret
    //! material is read only from the file paths supplied to the chain commands;
    //! no command accepts a scalar value directly.

    use std::{fs, path::Path};

    use anyhow::{Context as _, Result, anyhow};
    use clap::ValueEnum;
    use hellas_kernel::{Auth, Key, PayloadHash, Secp256k1Signer, SoftPasskey};

    const SCALAR_LENGTH: usize = 32;

    /// Kernel authorization scheme produced by the development signer.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
    pub(crate) enum AuthScheme {
        /// Portable P-256 WebAuthn envelope defined by the kernel wire v1 spec.
        Webauthn,
        /// Compact secp256k1 ECDSA signature over the canonical payload hash.
        Native,
    }

    /// One file-backed kernel signer.
    pub(crate) enum DevSigner {
        Webauthn(SoftPasskey),
        Native(Secp256k1Signer),
    }

    impl DevSigner {
        /// Loads one exact 32-byte scalar from `path`.
        ///
        /// Files may contain either 32 raw bytes or 64 ASCII hexadecimal digits
        /// with surrounding ASCII whitespace. The scalar itself is never accepted
        /// as a command-line value.
        pub(crate) fn load(scheme: AuthScheme, path: &Path) -> Result<Self> {
            let scalar = read_scalar(path)?;
            match scheme {
                AuthScheme::Webauthn => Self::webauthn(scalar),
                AuthScheme::Native => Self::native(scalar),
            }
        }

        fn webauthn(scalar: [u8; SCALAR_LENGTH]) -> Result<Self> {
            SoftPasskey::from_secret_scalar(scalar)
                .map(Self::Webauthn)
                .map_err(|_| anyhow!("P-256 key file contains an invalid secret scalar"))
        }

        fn native(scalar: [u8; SCALAR_LENGTH]) -> Result<Self> {
            Secp256k1Signer::from_secret_scalar(scalar)
                .map(Self::Native)
                .map_err(|_| anyhow!("secp256k1 key file contains an invalid secret scalar"))
        }

        /// Returns the compressed settlement key controlled by this signer.
        pub(crate) const fn party_key(&self) -> Key {
            match self {
                Self::Webauthn(signer) => signer.party_key(),
                Self::Native(signer) => signer.party_key(),
            }
        }

        /// Signs one canonical kernel authorization payload.
        pub(crate) fn sign(&self, hash: PayloadHash) -> Result<Auth> {
            match self {
                Self::Webauthn(signer) => signer
                    .sign(hash)
                    .map(Auth::webauthn)
                    .map_err(|error| anyhow!("kernel WebAuthn signing failed: {error:?}")),
                Self::Native(signer) => Ok(Auth::native(signer.sign(hash))),
            }
        }
    }

    fn read_scalar(path: &Path) -> Result<[u8; SCALAR_LENGTH]> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read key file {}", path.display()))?;
        let trimmed = bytes.trim_ascii();
        let material =
            if trimmed.len() == 2 * SCALAR_LENGTH && trimmed.iter().all(u8::is_ascii_hexdigit) {
                hex::decode(trimmed)
                    .with_context(|| format!("invalid hex key file {}", path.display()))?
            } else {
                bytes
            };
        let actual = material.len();
        material.try_into().map_err(|_| {
            anyhow!(
                "key file {} must contain 32 raw bytes or 64 hex digits, got {actual} bytes",
                path.display()
            )
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use hellas_kernel::{Secp256k1Verifier, SigVerifier as _};

        fn key_file(contents: &[u8]) -> tempfile::NamedTempFile {
            let file = tempfile::NamedTempFile::new().expect("temporary key file");
            fs::write(file.path(), contents).expect("write temporary key");
            file
        }

        #[test]
        fn native_signer_uses_compact_secp256k1_over_payload_hash() {
            let file =
                key_file(b"0000000000000000000000000000000000000000000000000000000000000001\n");
            let signer = DevSigner::load(AuthScheme::Native, file.path()).expect("native signer");
            let expected: [u8; Key::LENGTH] =
                hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                    .expect("public key hex")
                    .try_into()
                    .expect("public key length");
            assert_eq!(signer.party_key().to_bytes(), expected);
            let hash = PayloadHash::default();
            let auth = signer.sign(hash).expect("native auth");
            assert!(Secp256k1Verifier::new().verify_auth(&auth, signer.party_key(), hash));
        }

        #[test]
        fn malformed_key_file_is_rejected_without_scalar_cli_fallback() {
            let file = key_file(b"not-a-secret-scalar");
            let error = match DevSigner::load(AuthScheme::Native, file.path()) {
                Ok(_) => panic!("malformed key was accepted"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("key file"));
        }

        #[test]
        fn validator_kernel_accepts_both_cli_auth_envelopes() {
            let hash = PayloadHash::default();
            for scheme in [AuthScheme::Webauthn, AuthScheme::Native] {
                let file =
                    key_file(b"0000000000000000000000000000000000000000000000000000000000000001\n");
                let signer = DevSigner::load(scheme, file.path()).expect("CLI signer");
                let auth = signer.sign(hash).expect("CLI auth");
                assert!(Secp256k1Verifier::new().verify_auth(&auth, signer.party_key(), hash));
            }
        }
    }
}
