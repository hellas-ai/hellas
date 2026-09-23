use std::fs;

use hellas_kernel::{EdgeValues, Fees, MIN_OMIT_RESPONSE_BLOCKS};
use hellas_rpc::protocol::Digest;
use hellas_rpc::protocol::work::{PaidChannelPolicyV1, PaidExecutionPolicyV1};
use hellas_rpc::protocol::work_setup::ProviderChannelPolicy;
use hellas_work::work_close::{BlockSourceError, FinalizedWork};

use super::*;
use crate::work_config::load_work_config;

fn network() -> NetworkId {
    let Some(network) = NetworkId::new("hellas-devnet") else {
        panic!("the fixture network id is one");
    };
    network
}

fn signer(byte: u8) -> Secp256k1Signer {
    let Ok(signer) = Secp256k1Signer::from_secret_scalar([byte; 32]) else {
        panic!("a fixed scalar is a key");
    };
    signer
}

/// The provider whose identity this offer is staked by.
fn provider() -> Secp256k1Signer {
    signer(0x22)
}

/// The client the bond names as taker.
fn client() -> Secp256k1Signer {
    signer(0x21)
}

/// The floor a validator answered with.
fn floor() -> SetupScan {
    SetupScan {
        height: 7,
        payload: [0x47; 32],
    }
}

fn policy() -> ProviderChannelPolicy {
    let Ok(environment) = hex::encode([0x11; 32]).parse() else {
        panic!("the fixture environment id is one");
    };
    ProviderChannelPolicy {
        network: network(),
        policy_salt: [0x5a; 32],
        channel_policy: PaidChannelPolicyV1 {
            compute_credit_limit: 40,
            delivery_credit_limit: 40,
        },
        execution_policy: PaidExecutionPolicyV1 {
            allowed_environment: environment,
            generation_policy_digest: Digest::from_bytes([0x12; 32]),
            identity_source_digest: Digest::from_bytes([0x13; 32]),
            max_prompt_tokens: 512,
            max_new_tokens: 128,
            max_stop_token_ids: 4,
            max_spool_bytes: 1 << 20,
            max_encoded_result_frame: 262_144,
            max_encoded_quote_response: 1 << 20,
            dispatch_margin_blocks: 4,
            delivery_margin_blocks: 2,
            oracle_grace_blocks: 6,
            fixed_price: 10,
        }
        .into(),
        expected_payment_values: EdgeValues::new(1_000, 200, Fees::new(0, 0, 0, 0)),
        min_omit_response_blocks: MIN_OMIT_RESPONSE_BLOCKS,
    }
}

/// A threshold identity the real work-config loader accepts.
const THRESHOLD_IDENTITY: [u8; 48] = [
    0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f,
    0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58,
    0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
];

fn route(peer: u8, bond: EdgeId, client: Key) -> serde_json::Value {
    serde_json::json!({
        "peer": hex::encode([peer; 32]),
        "bond": hex::encode(bond.to_bytes()),
        "client": hex::encode(client.to_bytes()),
    })
}

/// Loads routes through the production parser, so their duplicate-peer
/// and duplicate-bond invariants are facts these provisioning tests use,
/// not a test-only constructor that can make impossible route tables.
fn routed_work_config(root: &Path, routes: Vec<serde_json::Value>) -> CliResult<WorkConfig> {
    let validators: Vec<String> = (1..=6)
        .map(|index| format!("http://127.0.0.1:900{index}"))
        .collect();
    let file = serde_json::json!({
        "chain": {
            "network_id": network().as_str(),
            "genesis_payload_digest": hex::encode([0x01; 32]),
            "threshold_identity": hex::encode(THRESHOLD_IDENTITY),
        },
        "validators": validators,
        "journal": { "root": root.display().to_string() },
        "routes": routes,
        "policies": {
            "policy_salt": hex::encode([0x5a; 32]),
            "channel": {
                "compute_credit_limit": 40,
                "delivery_credit_limit": 40,
            },
            "execution": {
                "allowed_environment": hex::encode([0x11; 32]),
                "generation_policy_digest": hex::encode([0x12; 32]),
                "identity_source_digest": hex::encode([0x13; 32]),
                "max_prompt_tokens": 512,
                "max_new_tokens": 128,
                "max_stop_token_ids": 4,
                "max_spool_bytes": 1_048_576_u64,
                "max_encoded_result_frame": 262_144,
                "max_encoded_quote_response": 1_048_576_u64,
                "dispatch_margin_blocks": 4,
                "delivery_margin_blocks": 2,
                "oracle_grace_blocks": 6,
                "fixed_price": 10,
            },
        },
        "poll_ms": 250,
        "expected_payment_values": {
            "value": 1_000,
            "reserve": 200,
            "close_fees": { "base": 0, "slot": 0, "proof": 0, "lifetime": 0 },
        },
        "min_omit_response_blocks": MIN_OMIT_RESPONSE_BLOCKS,
    });
    let path = root.join("work-config.json");
    fs::write(&path, file.to_string())
        .with_context(|| format!("the route fixture writes {}", path.display()))?;
    load_work_config(&path)
}

fn options(root: &Path, max_job_price: u64) -> ProvisionOptions {
    let client = client().party_key();
    let bond = expected_bond_for(client, &[0xa1], max_job_price);
    let work_config = routed_work_config(root, vec![route(0x51, bond, client)])
        .unwrap_or_else(|error| panic!("the route fixture loads: {error:#}"));
    options_for(work_config, client, &[0xa1], max_job_price)
}

fn options_for(
    work_config: WorkConfig,
    client: Key,
    stake_coins: &[u8],
    max_job_price: u64,
) -> ProvisionOptions {
    ProvisionOptions {
        work_config,
        settlement_key: provider(),
        client: hex::encode(client.to_bytes()),
        stake_coins: stake_coins
            .iter()
            .map(|coin| hex::encode([*coin; 32]))
            .collect(),
        bond_timeout: 500,
        timeout_payout: 64,
        max_job_price,
        print_bond_only: false,
    }
}

/// The whole command, minus the one step that needs a validator.
fn provision(
    root: &Path,
    policy: ProviderChannelPolicy,
    max_job_price: u64,
) -> CliResult<Provisioned> {
    provision_options(&options(root, max_job_price), policy)
}

fn provision_options(
    options: &ProvisionOptions,
    policy: ProviderChannelPolicy,
) -> CliResult<Provisioned> {
    let candidate = BondCandidate::plan(options)?;
    Offer::plan(options, policy, candidate)?.journal(floor())
}

/// The bond the fixture inputs name, spelled out here rather than
/// taken from the command: the parties are positional, so a maker
/// and taker the other way round is a different edge and this
/// notices.
fn bond_funding_for(stake_coins: &[u8]) -> Funding {
    let mut slots = [CoinId::from_bytes([0; CoinId::LENGTH]); MAX_PARTY_INPUTS];
    for (slot, coin) in slots.iter_mut().zip(stake_coins) {
        *slot = CoinId::from_bytes([*coin; CoinId::LENGTH]);
    }
    Funding::new(
        List::take(slots, stake_coins.len()),
        List::empty(CoinId::from_bytes([0; CoinId::LENGTH])),
    )
}

fn bond_terms_for(client: Key, max_job_price: u64) -> WorkStakeBondTerms {
    WorkStakeBondTerms {
        parties: Parties::new(provider().party_key(), client),
        timeout: BlockHeight::new(500),
        timeout_outputs: List::take(
            [Payout::new(provider().party_key(), 64); MAX_EDGE_OUTPUTS],
            1,
        ),
        max_job_price,
    }
}

fn expected_bond_for(client: Key, stake_coins: &[u8], max_job_price: u64) -> EdgeId {
    Tx::edge_id_of(
        &bond_funding_for(stake_coins),
        &Terms::work_stake_bond(bond_terms_for(client, max_job_price)),
    )
}

fn expected_bond(max_job_price: u64) -> EdgeId {
    expected_bond_for(client().party_key(), &[0xa1], max_job_price)
}

#[test]
fn preview_and_real_offer_use_the_identical_bond_candidate() {
    let root = tempfile::tempdir().unwrap();
    let options = options(root.path(), 40);
    let preview = BondCandidate::plan(&options)
        .unwrap_or_else(|error| panic!("the bond previews: {error:#}"));
    let expected = preview.bond_edge;
    let candidate = BondCandidate::plan(&options)
        .unwrap_or_else(|error| panic!("the same bond plans: {error:#}"));
    let offer = Offer::plan(&options, policy(), candidate)
        .unwrap_or_else(|error| panic!("the routed offer plans: {error:#}"));
    assert_eq!(expected, expected_bond(40));
    assert_eq!(offer.bond_edge, expected);
}

#[tokio::test]
async fn preview_needs_neither_a_route_nor_a_chain_nor_a_journal() {
    let root = tempfile::tempdir().unwrap();
    let config = routed_work_config(root.path(), Vec::new())
        .unwrap_or_else(|error| panic!("a route-free config loads: {error:#}"));
    let mut options = options_for(config, client().party_key(), &[0xa1], 40);
    options.print_bond_only = true;

    run_provision(options)
        .await
        .unwrap_or_else(|error| panic!("the isolated preview succeeds: {error:#}"));
    assert_eq!(
        provider_setups(root.path()),
        0,
        "preview created no provider journal",
    );
}

fn provider_setups(root: &Path) -> usize {
    let Ok(found) = discover_setups(root, network()) else {
        panic!("the fixture root enumerates");
    };
    assert!(
        found.unidentified.is_empty(),
        "a journal under the root could not be named: {:?}",
        found.unidentified,
    );
    found
        .setups
        .iter()
        .filter(|setup| setup.role == Role::Provider)
        .count()
}

fn proposal_signature(client: Key, stake_coins: &[u8], max_job_price: u64) -> [u8; 64] {
    provider()
        .sign(Tx::open_hash(
            network(),
            &bond_funding_for(stake_coins),
            &Terms::work_stake_bond(bond_terms_for(client, max_job_price)),
        ))
        .to_bytes()
}

/// Whether any file under `root` holds `signature` verbatim.
///
/// A settlement signature is deterministic (RFC 6979), so the exact bytes
/// a refused candidate would have exported are computable without letting
/// it export them. This is asked of an offer that *was* made as well as
/// of one that was refused: a scan that finds nothing everywhere would
/// answer "no signature was written" about a root full of them.
fn root_holds_signature(root: &Path, signature: &[u8]) -> bool {
    fs::read_dir(root)
        .unwrap_or_else(|error| panic!("the fixture root enumerates: {error}"))
        .any(|entry| {
            let entry = entry.unwrap_or_else(|error| panic!("a fixture entry reads: {error}"));
            let bytes = fs::read(entry.path())
                .unwrap_or_else(|error| panic!("a fixture file reads: {error}"));
            bytes
                .windows(signature.len())
                .any(|window| window == signature)
        })
}

/// No file, no discoverable revision, and no retained signature are three
/// assertions because opening the absent store to inspect it would create
/// the revisionless journal this test is meant to rule out.
fn assert_no_offer_artifact(root: &Path, bond: EdgeId, signature: &[u8]) {
    let key = hellas_work::work_store::setup::setup_key(network(), bond);
    let stem = format!("setup-{}.", hex::encode(key.into_bytes()));
    let entries: Vec<_> = fs::read_dir(root)
        .unwrap_or_else(|error| panic!("the fixture root enumerates: {error}"))
        .map(|entry| entry.unwrap_or_else(|error| panic!("a fixture entry reads: {error}")))
        .collect();
    assert!(
        entries
            .iter()
            .all(|entry| !entry.file_name().to_string_lossy().starts_with(&stem)),
        "the refused candidate left its setup journal behind",
    );
    assert!(
        !root_holds_signature(root, signature),
        "the refused candidate's bond signature was retained under the root",
    );

    let found = discover_setups(root, network())
        .unwrap_or_else(|error| panic!("the fixture root enumerates: {error}"));
    assert!(
        found.unidentified.is_empty(),
        "the refusal left an unidentified, revisionless journal: {:?}",
        found.unidentified,
    );
    assert!(
        found.setups.iter().all(|setup| setup.bond_edge != bond),
        "the refused candidate left revision one discoverable",
    );
}

/// A provisioned root is an offer the runner finds: the journal names
/// the bond and the role `WorkRunner::discover` looks for, and the
/// revision under them is the proposal.
#[test]
fn a_provisioned_root_is_the_offer_a_runner_discovers() {
    let dir = tempfile::tempdir().unwrap();
    let Ok(made) = provision(dir.path(), policy(), 40) else {
        panic!("a configured provider makes its offer");
    };
    assert_eq!(made.bond_edge, expected_bond(40));
    assert_eq!(made.floor, floor());

    let Ok(found) = discover_setups(dir.path(), network()) else {
        panic!("the provisioned root enumerates");
    };
    assert!(found.unidentified.is_empty(), "{:?}", found.unidentified);
    let [discovered] = found.setups.as_slice() else {
        panic!("one offer was made, one is found: {:?}", found.setups);
    };
    assert_eq!(discovered.bond_edge, made.bond_edge);
    assert_eq!(discovered.role, Role::Provider);

    // Reopened by bond and role alone, which is all the runner is
    // told. The open re-verifies every signature the revision
    // carries, so a proposal staked by some other party would not
    // survive this line.
    let Ok(store) = open_provider_journal(dir.path(), network(), discovered.bond_edge) else {
        panic!("the discovered journal reopens");
    };
    let Some(bundle) = store.state().bundle() else {
        panic!("a discovered offer holds the revision it was discovered by");
    };
    assert_eq!(bundle.revision(), 1);
    assert_eq!(bundle.network(), network());
    assert_eq!(bundle.bond_edge(), made.bond_edge);
    assert_eq!(store.state().scan_armed(), Some(floor()));
}

/// More than one offer is safe when its complete capital and routing
/// identity are separate. Discovery sees both without needing either
/// client to have answered revision one.
#[test]
fn disjoint_routes_bonds_and_stakes_make_two_discoverable_offers() {
    let dir = tempfile::tempdir().unwrap();
    let first_client = client().party_key();
    let second_client = signer(0x23).party_key();
    let first_bond = expected_bond_for(first_client, &[0xa1], 40);
    let second_bond = expected_bond_for(second_client, &[0xb1], 41);
    let config = routed_work_config(
        dir.path(),
        vec![
            route(0x51, first_bond, first_client),
            route(0x52, second_bond, second_client),
        ],
    )
    .unwrap_or_else(|error| panic!("the two-route fixture loads: {error:#}"));
    let first = options_for(config.clone(), first_client, &[0xa1], 40);
    let second = options_for(config, second_client, &[0xb1], 41);

    provision_options(&first, policy())
        .unwrap_or_else(|error| panic!("the first offer is made: {error:#}"));
    provision_options(&second, policy())
        .unwrap_or_else(|error| panic!("the disjoint second offer is made: {error:#}"));

    let found = discover_setups(dir.path(), network())
        .unwrap_or_else(|error| panic!("the two-offer root enumerates: {error}"));
    assert!(found.unidentified.is_empty(), "{:?}", found.unidentified);
    assert_eq!(provider_setups(dir.path()), 2);
    assert!(
        found
            .setups
            .iter()
            .any(|setup| setup.bond_edge == first_bond)
    );
    assert!(
        found
            .setups
            .iter()
            .any(|setup| setup.bond_edge == second_bond)
    );
}

/// The reservation comes back from A's revision-one bytes after every
/// in-memory value has been dropped. In particular, `funding_coins()` is
/// empty at that stage, so it cannot be the source this refusal uses.
#[test]
fn a_restart_refuses_a_coin_reserved_by_an_unanswered_offer_before_signing_or_writing() {
    let dir = tempfile::tempdir().unwrap();
    let first_client = client().party_key();
    let second_client = signer(0x23).party_key();
    let first_bond = expected_bond_for(first_client, &[0xa1, 0xa2], 40);
    let second_bond = expected_bond_for(second_client, &[0xa2, 0xb2], 41);
    let config = routed_work_config(
        dir.path(),
        vec![
            route(0x51, first_bond, first_client),
            route(0x52, second_bond, second_client),
        ],
    )
    .unwrap_or_else(|error| panic!("the two-route fixture loads: {error:#}"));
    let first = options_for(config.clone(), first_client, &[0xa1, 0xa2], 40);
    provision_options(&first, policy())
        .unwrap_or_else(|error| panic!("the first offer is made: {error:#}"));

    let store = open_provider_journal(dir.path(), network(), first_bond)
        .unwrap_or_else(|error| panic!("the first offer reopens: {error:#}"));
    assert_eq!(store.state().revision(), Some(1));
    assert!(
        store.state().funding_coins().is_empty(),
        "revision one unexpectedly exposes an executable Open",
    );
    drop(store);
    drop(first);
    drop(config);

    // The configuration and every setup fact are loaded again from disk;
    // no reservation value from the first call crosses this line.
    let config_path = dir.path().join("work-config.json");
    let restarted = load_work_config(&config_path)
        .unwrap_or_else(|error| panic!("the restarted configuration loads: {error:#}"));
    let second = options_for(restarted, second_client, &[0xa2, 0xb2], 41);
    let Err(error) = provision_options(&second, policy()) else {
        panic!("a restarted provider accepted stake reserved by revision one");
    };

    let said = format!("{error:#}");
    assert!(
        said.contains(&hex::encode([0xa2; CoinId::LENGTH])),
        "the refusal does not name the colliding coin: {said}",
    );
    assert!(
        said.contains(&hex::encode(first_bond.to_bytes())),
        "the refusal does not name the offer holding the coin: {said}",
    );
    assert_eq!(provider_setups(dir.path()), 1);
    // The same scan, over the offer that was made: what rules out B's
    // signature has to be able to find A's, or it rules out nothing.
    assert!(
        root_holds_signature(
            dir.path(),
            &proposal_signature(first_client, &[0xa1, 0xa2], 40),
        ),
        "the signature scan cannot find the offer that was made",
    );
    assert_no_offer_artifact(
        dir.path(),
        second_bond,
        &proposal_signature(second_client, &[0xa2, 0xb2], 41),
    );
}

/// Route-table construction itself is the pre-signing peer collision
/// gate. A duplicate peer cannot become the configuration passed to the
/// second provisioning attempt.
#[test]
fn a_second_offer_cannot_reuse_the_first_offers_peer() {
    let dir = tempfile::tempdir().unwrap();
    let first_client = client().party_key();
    let second_client = signer(0x23).party_key();
    let first_bond = expected_bond_for(first_client, &[0xa1], 40);
    let second_bond = expected_bond_for(second_client, &[0xb1], 41);
    let first_config = routed_work_config(dir.path(), vec![route(0x51, first_bond, first_client)])
        .unwrap_or_else(|error| panic!("the first route loads: {error:#}"));
    let first = options_for(first_config, first_client, &[0xa1], 40);
    provision_options(&first, policy())
        .unwrap_or_else(|error| panic!("the first offer is made: {error:#}"));

    let error = routed_work_config(
        dir.path(),
        vec![
            route(0x51, first_bond, first_client),
            route(0x51, second_bond, second_client),
        ],
    )
    .expect_err("one authenticated peer cannot name the second offer too");
    let said = format!("{error:#}");
    assert!(
        said.contains("names peer") && said.contains("twice"),
        "unexpected duplicate-peer refusal: {said}",
    );
    assert_eq!(provider_setups(dir.path()), 1);
    assert!(
        root_holds_signature(dir.path(), &proposal_signature(first_client, &[0xa1], 40)),
        "the signature scan cannot find the offer that was made",
    );
    assert_no_offer_artifact(
        dir.path(),
        second_bond,
        &proposal_signature(second_client, &[0xb1], 41),
    );
}

/// A repeated provision is still a second promise over the same bond.
/// It is refused during planning even though the journal could replay an
/// identical revision idempotently.
#[test]
fn a_second_offer_cannot_reuse_the_first_offers_bond() {
    let dir = tempfile::tempdir().unwrap();
    let options = options(dir.path(), 40);
    let first = provision_options(&options, policy())
        .unwrap_or_else(|error| panic!("the first offer is made: {error:#}"));

    let Err(error) = provision_options(&options, policy()) else {
        panic!("a second offer reused the first offer's bond");
    };
    let said = format!("{error:#}");
    assert!(
        said.contains("candidate bond")
            && said.contains("collides")
            && said.contains(&hex::encode(first.bond_edge.to_bytes())),
        "unexpected duplicate-bond refusal: {said}",
    );
    assert_eq!(provider_setups(dir.path()), 1);
}

/// Success is a statement about the disk. The journal is closed
/// before this reads it, so this open is the one a restarted runner
/// makes, and it takes the exclusive lock the writer would still
/// hold.
#[test]
fn the_offer_is_on_the_disk_before_the_command_returns() {
    let dir = tempfile::tempdir().unwrap();
    let Ok(made) = provision(dir.path(), policy(), 40) else {
        panic!("the offer is made");
    };

    let Ok(store) = open_provider_journal(dir.path(), network(), made.bond_edge) else {
        panic!("the journal reopens");
    };
    assert_eq!(store.state().revision(), Some(1));
    assert!(
        !store.recovered_torn_tail(),
        "the offer this command reported was an interrupted write",
    );
    assert_eq!(
        store.len(),
        2,
        "the armed floor and the revision are both frames in the file",
    );
}

/// A stake no open could carry is refused rather than quietly cut
/// down to the four coins a party may fund with.
#[test]
fn a_stake_wider_than_an_open_is_refused_rather_than_truncated() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = options(dir.path(), 40);
    options.stake_coins = (0..=u8::try_from(MAX_PARTY_INPUTS).unwrap())
        .map(|byte| hex::encode([byte; 32]))
        .collect();

    let Err(error) = BondCandidate::plan(&options) else {
        panic!("an open funded by five coins is not one this stake can be");
    };
    assert!(
        format!("{error:#}").contains("at most 4"),
        "the refusal does not name the bound: {error:#}",
    );
}

/// One block answers both halves of a floor. A payload taken from
/// any block but the one at the tip is a history that can never be
/// contiguous, and nothing later would say so.
#[tokio::test]
async fn the_floor_is_the_payload_of_the_block_at_the_tip() {
    let source = Chain {
        tip: Some(9),
        block: Some(FinalizedWork {
            height: 9,
            parent: [0x08; 32],
            payload: [0x09; 32],
            txs: Vec::new(),
        }),
    };

    let Ok(read) = floor_of(&source).await else {
        panic!("a finalized chain answers with a floor");
    };
    assert_eq!(
        read,
        Some(SetupScan {
            height: 9,
            payload: [0x09; 32],
        }),
    );

    let empty = Chain {
        tip: None,
        block: None,
    };
    let Ok(read) = floor_of(&empty).await else {
        panic!("a chain that has finalized nothing is an answer, not a failure");
    };
    assert_eq!(read, None);
}

/// A chain holding at most one finalized block.
struct Chain {
    tip: Option<u64>,
    block: Option<FinalizedWork>,
}

impl FinalizedBlocks for Chain {
    fn latest_height(
        &self,
    ) -> impl core::future::Future<Output = Result<Option<u64>, BlockSourceError>> + Send {
        core::future::ready(Ok(self.tip))
    }

    fn block_at(
        &self,
        height: u64,
    ) -> impl core::future::Future<Output = Result<Option<FinalizedWork>, BlockSourceError>> + Send
    {
        core::future::ready(Ok(self
            .block
            .clone()
            .filter(|block| block.height == height)))
    }
}
