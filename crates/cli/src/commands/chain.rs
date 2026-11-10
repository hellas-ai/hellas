use hellas_authority::authenticator::{Authenticator, kernel_auth};
use std::time::Duration;
use std::{fs, path::PathBuf};

use anyhow::Context as _;
use clap::{Args, Subcommand, ValueEnum};
use hellas_chain::domain::{Digest, ObjectKey, SettlementKey, Transaction};
use hellas_chain::genesis::ChainProfile;
use hellas_chain::{FinalizedBlockQuery, LightClient as _, QueryError, client::RemoteLightClient};
use hellas_kernel::{
    BlockHeight, CloseKind as KernelCloseKind, CoinId, Decode as _, EdgeId, Encode as _, Funding,
    List, MAX_EDGE_INPUTS, MAX_EDGE_OUTPUTS, NetworkId, Parties, PartyAuth, PartyKeys, Payout,
    Proof, ProtocolCode, Terms, Tx,
};

pub(crate) use self::signer::passkey;
use self::signer::{AuthScheme, DevSigner};
use crate::commands::CliResult;

#[derive(Subcommand)]
pub enum ChainCommand {
    /// Query the chain light-client API
    Query {
        /// RPC endpoint; defaults to the selected chain's first validator.
        #[arg(long)]
        rpc: Option<String>,
        /// Read coins and edges without proofs from this endpoint, which you
        /// trust to answer honestly (such as your own node).
        #[arg(long, conflicts_with = "rpc")]
        trusted_rpc: Option<String>,
        #[command(subcommand)]
        query: QueryCommand,
    },
    /// Delegate selected coins to a node using the global owner passkey
    Delegate {
        #[command(flatten)]
        coins: OwnerCoinArgs,
        /// Secp256k1 node settlement key (base58)
        #[arg(long)]
        node: SettlementKey,
        /// Create up to three delegated coins of this value, leaving undelegated change.
        #[arg(long)]
        split: Option<u64>,
    },
    /// Reclaim selected coins without a delegate using the global owner passkey
    Sweep(OwnerCoinArgs),
    /// Send coins to an owner, returning unused value as undelegated change
    Send {
        #[command(flatten)]
        coins: OwnerCoinArgs,
        /// Recipient owner key (base58)
        #[arg(long)]
        to: SettlementKey,
        #[arg(long)]
        amount: u64,
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
pub struct OwnerCoinArgs {
    #[arg(long)]
    rpc: Option<String>,
    /// Live coin ID; repeat or comma-separate values
    #[arg(long = "coin", value_delimiter = ',', required = true)]
    coins: Vec<String>,
}

#[derive(Args)]
pub struct OpenArgs {
    /// Chain light-client RPC endpoint
    #[arg(long)]
    rpc: Option<String>,
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
    rpc: Option<String>,
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
    /// Look up a coin by object ID at the latest applied state
    Coin {
        /// Hex-encoded 32-byte object ID
        #[arg(long)]
        object_id: String,
    },
    /// Look up a kernel edge by object ID at the latest applied state
    Edge {
        /// Hex-encoded 32-byte object ID
        #[arg(long)]
        object_id: String,
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
    /// Serve verified proofs from a full node on a loopback listener
    Serve {
        /// Validator transaction ingress URL; repeat for multiple validators
        #[arg(long)]
        rpc: Vec<String>,
        /// ChainSync peer as ENDPOINT_ID@IP:PORT; repeat for multiple peers
        #[arg(long = "peer", value_parser = parse_chain_peer)]
        peers: Vec<iroh::EndpointAddr>,
        #[arg(long, default_value = "hellas-explorer")]
        partition_prefix: String,
        /// Retain only the last N executed blocks; the default keeps the complete archive
        #[arg(long)]
        chain_archive_blocks: Option<std::num::NonZeroU64>,
        /// Loopback listener for the local tunnel daemon
        #[arg(long, default_value = "127.0.0.1:8788")]
        listen: std::net::SocketAddr,
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
        /// Network ID for a newly generated genesis; omitted for the shipped devnet.
        #[arg(long, conflicts_with = "genesis")]
        network_id: Option<String>,
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
        /// Metrics listener IP; remote scrapers require an explicit address
        #[arg(long, default_value = "127.0.0.1")]
        metrics_bind_address: std::net::IpAddr,
        /// Direct light-client RPC bind address
        #[arg(long)]
        light_client_bind: Option<std::net::SocketAddr>,
        /// ChainSync (Iroh) bind address for full nodes and indexers
        #[arg(long)]
        chain_sync_bind: Option<std::net::SocketAddr>,
        /// Retain only the last N finalized blocks; the default keeps the complete archive
        #[arg(long)]
        archive_blocks: Option<std::num::NonZeroU64>,
        /// Canonical genesis JSON; validator identities must match --seed
        #[arg(long)]
        genesis: Option<PathBuf>,
        /// Write the exact generated genesis JSON to this file.
        #[arg(long)]
        genesis_out: Option<PathBuf>,
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

pub async fn run(
    command: ChainCommand,
    owner: Option<&hellas_kernel::SoftPasskey>,
    profile: &ChainProfile,
    _home: &hellas_private::StoreLocation,
) -> CliResult {
    match command {
        ChainCommand::Delegate { coins, node, split } => {
            anyhow::ensure!(
                hellas_kernel::Secp256k1Verifier::is_valid_key(node.into_kernel()),
                "delegate must be a valid secp256k1 node key"
            );
            run_owner_coins(coins, Some(node.into_kernel()), split, None, owner, profile).await
        }
        ChainCommand::Sweep(coins) => {
            run_owner_coins(coins, None, None, None, owner, profile).await
        }
        ChainCommand::Send { coins, to, amount } => {
            anyhow::ensure!(amount > 0, "amount must be positive");
            hellas_sdk::coin_owner::OwnerReshape::validate_recipient(to.into_kernel())?;
            run_owner_coins(
                coins,
                None,
                None,
                Some((to.into_kernel(), amount)),
                owner,
                profile,
            )
            .await
        }
        ChainCommand::Query {
            rpc,
            trusted_rpc,
            query,
        } => run_query(rpc, trusted_rpc, profile, query).await,
        ChainCommand::Open(args) => run_open(args, profile).await,
        ChainCommand::Close(args) => run_close(args, profile).await,
        #[cfg(feature = "indexer")]
        ChainCommand::Indexer { command } => run_indexer(command, profile, _home).await,
        #[cfg(feature = "validator")]
        ChainCommand::Validator { command } => run_validator(command, profile, _home).await,
    }
}

async fn run_owner_coins(
    args: OwnerCoinArgs,
    delegate: Option<hellas_kernel::Key>,
    split: Option<u64>,
    payment: Option<(hellas_kernel::Key, u64)>,
    owner: Option<&hellas_kernel::SoftPasskey>,
    profile: &ChainProfile,
) -> CliResult {
    let owner = owner.context(
        "chain delegate/sweep/send spends the principal's coins; this home has no principal key (run `hellas faucet` or pass --passkey)",
    )?;
    let selected = parse_coin_ids::<MAX_EDGE_INPUTS>(&args.coins, "coin")?;
    let network = NetworkId::new(profile.network_id()).expect("validated profile");
    let client = connect_with_verified_snapshots(args.rpc, profile).await?;
    let key = hellas_kernel::Key::from_bytes(owner.public_key()?.to_compressed());
    let plan = if let Some((recipient, amount)) = payment {
        hellas_sdk::coin_owner::OwnerReshape::pay(
            &client,
            network,
            key,
            selected.as_slice(),
            recipient,
            amount,
        )
        .await?
    } else {
        hellas_sdk::coin_owner::OwnerReshape::prepare(
            &client,
            network,
            key,
            selected.as_slice(),
            delegate,
            split,
        )
        .await?
    };
    let output_ids = plan.output_ids();
    let auth = kernel_auth(
        &owner.public_key()?,
        &owner
            .assert(hellas_auth::Digest::from(*plan.payload_hash().as_bytes()))
            .await?,
    )?;
    let outcome = client
        .submit_tx(Transaction::Kernel(plan.authorize(auth)?))
        .await?;
    println!("{outcome}");
    for id in output_ids.as_slice() {
        println!("coin_id {}", hex::encode(id.to_bytes()));
    }
    Ok(())
}

/// Object reads for display: proven by default, plain from a trusted peer.
enum ObjectReader {
    Proven(RemoteLightClient),
    Trusted(hellas_chain::client::TrustedReader),
}

impl ObjectReader {
    async fn objects(&self, key: ObjectKey) -> CliResult<Option<hellas_chain::ObjectSnapshot>> {
        Ok(match self {
            Self::Proven(client) => client
                .get_objects(vec![key])
                .await?
                .map(hellas_chain::Verified::into_inner),
            Self::Trusted(reader) => reader.get_objects(vec![key]).await?,
        })
    }

    /// Every holdings page of `owner`. Pages are read at successive roots, so
    /// a listing that crosses a state change is refused rather than mixed.
    async fn holdings(&self, owner: SettlementKey) -> CliResult<Vec<hellas_chain::ObjectSnapshot>> {
        let mut pages: Vec<hellas_chain::ObjectSnapshot> = Vec::new();
        let mut after = None;
        loop {
            let page = match self {
                Self::Proven(client) => client
                    .get_holdings(owner, after)
                    .await?
                    .map(hellas_chain::Verified::into_inner),
                Self::Trusted(reader) => reader.get_holdings(owner, after).await?,
            };
            let Some(page) = page else {
                return Ok(pages);
            };
            if pages
                .first()
                .is_some_and(|first| first.block.payload != page.block.payload)
            {
                anyhow::bail!("owner state changed during the listing; retry");
            }
            after = page.next_holdings();
            pages.push(page);
            if after.is_none() {
                return Ok(pages);
            }
        }
    }
}

fn print_snapshot(block: &hellas_chain::LatestBlock) {
    println!("height {}", block.height);
    println!("payload {}", hex::encode(block.payload));
    println!("state_root {}", hex::encode(block.state_root));
    println!("finalization {}", hex::encode(&block.finalization));
}

async fn run_query(
    rpc: Option<String>,
    trusted_rpc: Option<String>,
    profile: &ChainProfile,
    query: QueryCommand,
) -> CliResult {
    let objects = matches!(
        query,
        QueryCommand::Coin { .. }
            | QueryCommand::Edge { .. }
            | QueryCommand::CoinsByOwner { .. }
            | QueryCommand::EdgesByOwner { .. }
    );
    if let Some(trusted_rpc) = trusted_rpc {
        anyhow::ensure!(objects, "--trusted-rpc serves only coin and edge queries");
        let reader = hellas_chain::client::TrustedReader::connect(
            trusted_rpc,
            hellas_kernel::NetworkId::new(profile.network_id()).context("invalid chain network")?,
        )
        .await?;
        return run_object_query(ObjectReader::Trusted(reader), query).await;
    }
    let client = connect_with_verified_snapshots(rpc, profile).await?;
    if objects {
        return run_object_query(ObjectReader::Proven(client), query).await;
    }
    if matches!(
        query,
        QueryCommand::Validators | QueryCommand::Finalization { .. }
    ) {
        eprintln!("this RPC record is unverified; use finalized block evidence for authentication");
    }
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
        QueryCommand::Validators => {
            for validator in client.get_validators().await? {
                println!("{validator}");
            }
        }
        QueryCommand::Coin { .. }
        | QueryCommand::Edge { .. }
        | QueryCommand::CoinsByOwner { .. }
        | QueryCommand::EdgesByOwner { .. } => unreachable!("object queries returned above"),
    }
    Ok(())
}

async fn run_object_query(reader: ObjectReader, query: QueryCommand) -> CliResult {
    let parse_owner = |owner: String| {
        owner
            .parse::<SettlementKey>()
            .map_err(|err| anyhow::anyhow!("invalid owner settlement key: {err}"))
    };
    match query {
        QueryCommand::Coin { object_id } => {
            let id = CoinId::from_bytes(parse_hex_32(&object_id, "object_id")?);
            let found = reader.objects(ObjectKey::Coin(id)).await?;
            match found
                .map(|snapshot| snapshot.coin(id))
                .transpose()?
                .flatten()
            {
                Some(coin) => println!("{} {}", coin.owner, coin.value),
                None => println!("none"),
            }
        }
        QueryCommand::Edge { object_id } => {
            let id = EdgeId::from_bytes(parse_hex_32(&object_id, "object_id")?);
            let Some(snapshot) = reader.objects(ObjectKey::Edge(id)).await? else {
                println!("none");
                return Ok(());
            };
            println!("state_root {}", hex::encode(snapshot.block.state_root));
            match snapshot.edge(id)? {
                Some(edge) => {
                    let edge = hellas_chain::EdgeState::from(edge);
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
        QueryCommand::CoinsByOwner { owner } => {
            let owner = parse_owner(owner)?;
            let pages = reader.holdings(owner).await?;
            let Some(first) = pages.first() else {
                println!("none");
                return Ok(());
            };
            print_snapshot(&first.block);
            for page in &pages {
                for (id, coin) in page.owned_coins(owner) {
                    println!("{} {}", hex::encode(id.to_bytes()), coin.value);
                }
            }
        }
        QueryCommand::EdgesByOwner { owner } => {
            let owner = parse_owner(owner)?;
            let pages = reader.holdings(owner).await?;
            let Some(first) = pages.first() else {
                println!("none");
                return Ok(());
            };
            print_snapshot(&first.block);
            for page in &pages {
                for (id, edge) in page.edges() {
                    println!(
                        "{} {} {}",
                        hex::encode(id.to_bytes()),
                        edge.maker,
                        edge.taker
                    );
                }
            }
        }
        _ => unreachable!("only object queries reach here"),
    }
    Ok(())
}

async fn run_open(args: OpenArgs, profile: &ChainProfile) -> CliResult {
    let maker = DevSigner::load(args.maker_auth, &args.maker_key)?;
    let taker = DevSigner::load(args.taker_auth, &args.taker_key)?;
    let funding = Funding::new(
        parse_coin_ids(&args.maker_funding, "maker funding")?,
        parse_coin_ids(&args.taker_funding, "taker funding")?,
    );
    let timeout_outputs = parse_payouts(&args.timeout_payouts, "timeout payout")?;
    let terms = Terms::basic(
        ProtocolCode::new(args.protocol),
        Parties::new(
            PartyKeys::sole(maker.party_key()?),
            PartyKeys::sole(taker.party_key()?),
        ),
        BlockHeight::new(args.timeout),
        timeout_outputs,
    );
    let edge_id = Tx::edge_id_of(&funding, &terms);
    let network = NetworkId::new(profile.network_id()).expect("validated profile");
    let client = connect_with_verified_snapshots(args.rpc, profile).await?;
    let network = confirm_network(network, &client).await?;
    let open_hash = Tx::open_hash(network, &funding, &terms);
    let tx = Tx::open(
        funding,
        terms.clone(),
        PartyAuth::owner(maker.sign(open_hash).await?),
        PartyAuth::owner(taker.sign(open_hash).await?),
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
    println!("maker {}", SettlementKey::from(maker.party_key()?));
    println!("taker {}", SettlementKey::from(taker.party_key()?));
    Ok(())
}

async fn run_close(args: CloseArgs, profile: &ChainProfile) -> CliResult {
    let edge_id = parse_edge_id(&args.edge_id)?;
    let outputs = parse_payouts(&args.payouts, "payout")?;
    let network = NetworkId::new(profile.network_id()).expect("validated profile");
    let client = connect_with_verified_snapshots(args.rpc, profile).await?;
    let network = confirm_network(network, &client).await?;
    let edge = get_live_edge(&client, edge_id).await?;

    let proof = match args.kind {
        CloseKind::Mutual => {
            if args.terms_file.is_some() {
                anyhow::bail!("--terms-file is only valid with --kind timeout");
            }
            let maker = load_mutual_signer("maker", args.maker_auth, args.maker_key.as_deref())?;
            let taker = load_mutual_signer("taker", args.taker_auth, args.taker_key.as_deref())?;
            if SettlementKey::from(maker.party_key()?) != edge.maker {
                anyhow::bail!("maker key file does not control the live edge maker");
            }
            if SettlementKey::from(taker.party_key()?) != edge.taker {
                anyhow::bail!("taker key file does not control the live edge taker");
            }
            let hash = Tx::payload_hash(
                network,
                edge_id,
                KernelCloseKind::Mutual,
                edge.terms_hash,
                &outputs,
            );
            Proof::mutual(
                PartyAuth::owner(maker.sign(hash).await?),
                PartyAuth::owner(taker.sign(hash).await?),
            )
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
            Proof::timeout(terms, None)
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

pub(super) async fn connect_with_verified_snapshots(
    rpc: Option<String>,
    profile: &ChainProfile,
) -> CliResult<RemoteLightClient> {
    let rpc = rpc
        .or_else(|| profile.validators().first().cloned())
        .context("selected chain has no validator routes")?;
    let verifier = std::sync::Arc::new(hellas_chain::proof_verify::ProofVerifier::for_profile(
        profile,
    )?);
    Ok(RemoteLightClient::connect(rpc, verifier).await?)
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
    const INDEX_WAIT: Duration = Duration::from_secs(10);

    let mut blocks = client.finalized_blocks().await?;
    let read = async {
        loop {
            let latest = client
                .get_latest_block()
                .await?
                .ok_or_else(|| anyhow::anyhow!("chain has no finalized block"))?;
            match client.get_objects(vec![ObjectKey::Edge(edge_id)]).await {
                // The close is decided at state at least as new as the latest
                // finalized block seen above.
                Ok(Some(snapshot)) if snapshot.block.height >= latest.height => {
                    return snapshot
                        .edge(edge_id)?
                        .map(hellas_chain::EdgeState::from)
                        .ok_or_else(|| anyhow::anyhow!("edge does not exist"));
                }
                Ok(_) | Err(QueryError::StateUnavailable(_)) => blocks.next().await?,
                Err(error) => return Err(error.into()),
            }
        }
    };
    tokio::time::timeout(INDEX_WAIT, read)
        .await
        .map_err(|_| anyhow::anyhow!("edge state is not indexed yet"))?
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

fn parse_coin_ids<const N: usize>(
    raw: &[String],
    field: &'static str,
) -> CliResult<List<CoinId, N>> {
    if raw.len() > N {
        anyhow::bail!("{field} accepts at most {N} coin ids, got {}", raw.len());
    }
    let mut ids = [CoinId::from_bytes([0; CoinId::LENGTH]); N];
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
    hellas_auth::hex::parse(raw).with_context(|| format!("{field} must be 32 bytes of hex"))
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
async fn run_indexer(
    command: IndexerCommand,
    profile: &ChainProfile,
    home: &hellas_private::StoreLocation,
) -> CliResult {
    match command {
        IndexerCommand::Serve {
            rpc,
            peers,
            partition_prefix,
            chain_archive_blocks,
            listen,
        } => {
            let selected = if rpc.is_empty() {
                profile.clone()
            } else {
                profile.clone().with_validators(rpc)?
            };
            let chain = hellas_chain::chain_dir::ChainDir::open(home, &selected)?;
            tokio::task::spawn_blocking(move || {
                hellas_chain::indexer_api::run(hellas_chain::indexer_api::OriginOptions {
                    chain,
                    peers,
                    partition_prefix,
                    listen,
                    archive_blocks: chain_archive_blocks,
                })
            })
            .await?
            .map_err(anyhow::Error::from_boxed)?;
        }
    }
    Ok(())
}

#[cfg(feature = "indexer")]
fn parse_chain_peer(raw: &str) -> Result<iroh::EndpointAddr, String> {
    let (id, address) = raw.split_once('@').ok_or("expected ENDPOINT_ID@IP:PORT")?;
    let id = id
        .parse()
        .map_err(|error| format!("invalid peer ID: {error}"))?;
    let address = address
        .parse()
        .map_err(|error| format!("invalid peer address: {error}"))?;
    Ok(iroh::EndpointAddr::new(id).with_ip_addr(address))
}

#[cfg(feature = "validator")]
async fn run_validator(
    command: ValidatorCommand,
    profile: &ChainProfile,
    home: &hellas_private::StoreLocation,
) -> CliResult {
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
            network_id,
            validators,
            validator,
            start_port,
            seed,
            addresses,
            relay_urls,
            metrics_port,
            metrics_bind_address,
            light_client_bind,
            chain_sync_bind,
            archive_blocks,
            genesis,
            genesis_out,
            genesis_allocations,
        } => hellas_chain::validator::Command::Config {
            network_id,
            validators,
            validator,
            start_port,
            seed,
            addresses,
            relay_urls,
            metrics_port,
            metrics_bind_address,
            light_client_bind,
            chain_sync_bind,
            archive_blocks,
            genesis,
            genesis_out,
            genesis_allocations,
        },
        ValidatorCommand::Run { config } => hellas_chain::validator::Command::Run {
            config,
            profile: profile.clone(),
            home: home.clone(),
        },
        ValidatorCommand::CheckConfig { config } => hellas_chain::validator::Command::CheckConfig {
            config,
            profile: profile.clone(),
        },
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
    use hellas_kernel::{Key, MAX_PARTY_INPUTS};

    #[test]
    fn owner_commands_use_global_passkey_and_one_coin_parser() {
        use clap::Parser as _;
        let node = hellas_kernel::Secp256k1Signer::from_secret_scalar([19; 32]).unwrap();
        let key = SettlementKey::from(node.party_key()).to_string();
        let coin = "01".repeat(32);
        for operation in ["delegate", "sweep", "send"] {
            let mut args = vec![
                "hellas",
                "--passkey",
                "owner.key",
                "chain",
                operation,
                "--rpc",
                "ws://127.0.0.1:1",
                "--coin",
                &coin,
            ];
            if operation == "delegate" {
                args.extend(["--node", &key]);
            } else if operation == "send" {
                args.extend(["--to", &key, "--amount", "37"]);
            }
            assert!(crate::Cli::try_parse_from(&args).is_ok());
        }
        let maximum = vec![coin; MAX_EDGE_INPUTS];
        assert_eq!(
            parse_coin_ids::<MAX_EDGE_INPUTS>(&maximum, "coin")
                .unwrap()
                .len(),
            MAX_EDGE_INPUTS
        );
    }

    #[tokio::test]
    async fn delegate_rejects_an_invalid_node_before_network_or_owner_access() {
        let home = tempfile::tempdir().unwrap();
        let error = run(
            ChainCommand::Delegate {
                split: None,
                coins: OwnerCoinArgs {
                    rpc: Some("invalid".into()),
                    coins: vec!["01".repeat(32)],
                },
                node: SettlementKey::from(Key::from_bytes([0; Key::LENGTH])),
            },
            None,
            &ChainProfile::known(hellas_chain::genesis::Chain::Devnet),
            &hellas_private::StoreLocation::for_test(home.path()),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("secp256k1"));
    }

    #[test]
    fn canonical_terms_file_round_trips_and_rejects_trailing_bytes() {
        let owner = SettlementKey::from(Key::from_bytes([2; Key::LENGTH]));
        let payouts =
            parse_payouts(&[format!("{owner}:42")], "timeout payout").expect("valid payout");
        let terms = Terms::basic(
            ProtocolCode::new(7),
            Parties::new(
                PartyKeys::sole(owner.into_kernel()),
                PartyKeys::sole(owner.into_kernel()),
            ),
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
        assert!(parse_coin_ids::<MAX_PARTY_INPUTS>(&too_many, "maker funding").is_err());

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

    use hellas_authority::authenticator::{Authenticator, kernel_auth};
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

    /// Loads a software passkey from a 32-byte P-256 scalar file.
    pub(crate) fn passkey(path: &Path) -> Result<SoftPasskey> {
        SoftPasskey::from_secret_scalar(read_scalar(path)?)
            .map_err(|_| anyhow!("P-256 key file contains an invalid secret scalar"))
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
        pub(crate) fn party_key(&self) -> Result<Key> {
            match self {
                Self::Webauthn(signer) => Ok(Key::from_bytes(signer.public_key()?.to_compressed())),
                Self::Native(signer) => Ok(signer.party_key()),
            }
        }

        /// Signs one canonical kernel authorization payload.
        pub(crate) async fn sign(&self, hash: PayloadHash) -> Result<Auth> {
            match self {
                Self::Webauthn(signer) => Ok(kernel_auth(
                    &signer.public_key()?,
                    &signer
                        .assert(hellas_auth::Digest::from(*hash.as_bytes()))
                        .await?,
                )?),
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

        #[tokio::test]
        async fn native_signer_uses_compact_secp256k1_over_payload_hash() {
            let file =
                key_file(b"0000000000000000000000000000000000000000000000000000000000000001\n");
            let signer = DevSigner::load(AuthScheme::Native, file.path()).expect("native signer");
            let expected: [u8; Key::LENGTH] =
                hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                    .expect("public key hex")
                    .try_into()
                    .expect("public key length");
            assert_eq!(signer.party_key().unwrap().to_bytes(), expected);
            let hash = PayloadHash::default();
            let auth = signer.sign(hash).await.expect("native auth");
            assert!(Secp256k1Verifier::new().verify_auth(&auth, signer.party_key().unwrap(), hash));
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

        #[tokio::test]
        async fn validator_kernel_accepts_both_cli_auth_envelopes() {
            let hash = PayloadHash::default();
            for scheme in [AuthScheme::Webauthn, AuthScheme::Native] {
                let file =
                    key_file(b"0000000000000000000000000000000000000000000000000000000000000001\n");
                let signer = DevSigner::load(scheme, file.path()).expect("CLI signer");
                let auth = signer.sign(hash).await.expect("CLI auth");
                assert!(Secp256k1Verifier::new().verify_auth(
                    &auth,
                    signer.party_key().unwrap(),
                    hash
                ));
            }
        }
    }
}
