#![cfg(feature = "validator")]

use hellas_chain::{
    LightClient as _,
    client::RemoteLightClient,
    config::ValidatorConfig,
    domain::{SettlementKey, Transaction},
};
use hellas_kernel::SoftPasskey;
use hellas_kernel::{Auth, CoinId, Secp256k1Signer};
use hellas_sdk::coin_owner::OwnerReshape;
use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::Duration,
};

const CLI: &str = env!("CARGO_BIN_EXE_hellas-cli");
fn command(home: &Path) -> Command {
    let mut command = Command::new(CLI);
    command
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"));
    command
}
fn output(mut command: Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
struct Validator {
    process: Child,
    log: PathBuf,
}
impl Drop for Validator {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
async fn coin(client: &RemoteLightClient, id: CoinId) -> hellas_chain::domain::Coin {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(Some(block)) = client.get_latest_block().await
                && let Ok(Some(coin)) = client.get_coin(block.payload, id.to_bytes().into()).await
            {
                return coin;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("coin finalized")
}
fn result_coin(output: Output) -> CoinId {
    let text = String::from_utf8(output.stdout).unwrap();
    let id = text
        .lines()
        .find_map(|line| line.strip_prefix("coin_id "))
        .expect("output coin id");
    CoinId::from_bytes(hex::decode(id).unwrap().try_into().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owner_prepare_and_cli_delegate_sweep_execute_on_a_real_validator() {
    let home = tempfile::tempdir().unwrap();
    let passkey = SoftPasskey::from_secret_scalar([21; 32]).unwrap();
    let native = Secp256k1Signer::from_secret_scalar([22; 32]).unwrap();
    let node = Secp256k1Signer::from_secret_scalar([23; 32]).unwrap();
    let key_path = home.path().join("owner.key");
    std::fs::write(&key_path, [21; 32]).unwrap();
    let rpc = format!("ws://127.0.0.1:{}", port());
    let mut config_command = command(home.path());
    config_command.args([
        "chain",
        "validator",
        "config",
        "-n",
        "1",
        "--seed",
        "719",
        "--start-port",
        &port().to_string(),
        "--light-client-bind",
        rpc.strip_prefix("ws://").unwrap(),
        "--genesis-allocation",
        &format!("{}:1000", SettlementKey::from(passkey.party_key())),
        "--genesis-allocation",
        &format!("{}:2000", SettlementKey::from(native.party_key())),
    ]);
    let config_output = output(config_command);
    let config: ValidatorConfig =
        toml::from_str(std::str::from_utf8(&config_output.stdout).unwrap()).unwrap();
    let network = config.network_id().unwrap();
    let config_path = home.path().join("validator.toml");
    std::fs::write(&config_path, &config_output.stdout).unwrap();
    let genesis_path = home.path().join("genesis.json");
    std::fs::write(&genesis_path, serde_json::to_vec(&config.genesis).unwrap()).unwrap();
    let log = home.path().join("validator.log");
    let mut start = command(home.path());
    start
        .args(["chain", "validator", "run", "--config"])
        .arg(&config_path)
        .stdout(Stdio::from(std::fs::File::create(&log).unwrap()))
        .stderr(Stdio::from(
            std::fs::OpenOptions::new().append(true).open(&log).unwrap(),
        ));
    let validator = Validator {
        process: start.spawn().unwrap(),
        log,
    };
    let client = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(client) = RemoteLightClient::connect(rpc.clone()).await
                && let Ok(info) = client.get_consensus_info().await
            {
                break client.with_consensus_info(&info).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "validator did not start: {}",
            std::fs::read_to_string(&validator.log).unwrap()
        )
    });
    let mut owner_ids = Vec::new();
    for index in 0..2 {
        let id = CoinId::from_bytes(hellas_chain::domain::genesis_object_id(index).into());
        let found = coin(&client, id).await;
        owner_ids.push((found.owner.into_kernel(), id));
    }
    // Both owner curves use the identical SDK preparation and Auth verification
    // path against finalized state; consensus executes the submitted reshapes.
    for owner in [passkey.party_key(), native.party_key()] {
        let id = owner_ids.iter().find(|(key, _)| *key == owner).unwrap().1;
        for selected in [
            vec![],
            vec![id, id],
            vec![id; hellas_kernel::MAX_EDGE_INPUTS + 1],
        ] {
            assert!(matches!(
                OwnerReshape::prepare(&client, network, owner, &selected, None).await,
                Err(hellas_sdk::coin_owner::CoinOwnerError::Inputs)
            ));
        }
        let foreign = owner_ids.iter().find(|(key, _)| *key != owner).unwrap().1;
        for absent in [foreign, CoinId::from_bytes([0xff; 32])] {
            assert!(
                matches!(OwnerReshape::prepare(&client, network, owner, &[absent], None).await,
                Err(hellas_sdk::coin_owner::CoinOwnerError::Missing(actual)) if actual == absent)
            );
        }
        let plan = OwnerReshape::prepare(&client, network, owner, &[id], Some(node.party_key()))
            .await
            .unwrap();
        let auth = if owner == passkey.party_key() {
            Auth::webauthn(passkey.sign(plan.payload_hash()).unwrap())
        } else {
            Auth::native(native.sign(plan.payload_hash()))
        };
        let delegated = plan.output_ids().as_slice()[0];
        client
            .submit_tx(Transaction::Kernel(plan.authorize(auth).unwrap()))
            .await
            .unwrap();
        let found = coin(&client, delegated).await;
        assert_eq!(found.owner.into_kernel(), owner);
        assert_eq!(
            found.delegate.map(SettlementKey::into_kernel),
            Some(node.party_key())
        );
        let mut final_id = delegated;
        if owner == passkey.party_key() {
            let mut sweep = command(home.path());
            sweep
                .arg("--passkey")
                .arg(&key_path)
                .args(["chain", "sweep", "--rpc", &rpc, "--genesis"])
                .arg(&genesis_path)
                .args(["--coin", &hex::encode(delegated.to_bytes())]);
            let swept = result_coin(output(sweep));
            assert_eq!(coin(&client, swept).await.delegate, None);
            let mut delegate = command(home.path());
            delegate
                .arg("--passkey")
                .arg(&key_path)
                .args(["chain", "delegate", "--rpc", &rpc, "--genesis"])
                .arg(&genesis_path)
                .args([
                    "--coin",
                    &hex::encode(swept.to_bytes()),
                    "--node",
                    &SettlementKey::from(node.party_key()).to_string(),
                ]);
            let restored = result_coin(output(delegate));
            let found = coin(&client, restored).await;
            assert_eq!(
                found.delegate.map(SettlementKey::into_kernel),
                Some(node.party_key())
            );
            assert_eq!(found.value, 1000);
            final_id = restored;
        }
        let sweep = OwnerReshape::prepare(&client, network, owner, &[final_id], None)
            .await
            .unwrap();
        let auth = if owner == passkey.party_key() {
            Auth::webauthn(passkey.sign(sweep.payload_hash()).unwrap())
        } else {
            Auth::native(native.sign(sweep.payload_hash()))
        };
        let swept = sweep.output_ids().as_slice()[0];
        client
            .submit_tx(Transaction::Kernel(sweep.authorize(auth).unwrap()))
            .await
            .unwrap();
        let found = coin(&client, swept).await;
        assert_eq!(found.owner.into_kernel(), owner);
        assert_eq!(found.delegate, None);
    }
}
