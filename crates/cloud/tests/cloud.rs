#![cfg(unix)]

use clap::{Parser, Subcommand};
use hellas_cloud::{
    cloud::{CloudArgs, CloudCommand, RunpodArgs, RunpodCommand},
    config::{Credentials, Deployment, ProviderConfig, Spec, Trust, read_json, save_state},
    deployment,
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Cloud(CloudArgs),
}

fn receipt() -> Deployment {
    Deployment {
        spec: Spec {
            name: "test".into(),
            image: format!("registry/image@sha256:{}", "a".repeat(64)),
            provider: ProviderConfig::Runpod {
                account: Some("work".into()),
                gpu_type: "NVIDIA L4".into(),
                disk_gb: 20,
                volume_gb: 20,
                container_registry_auth_id: None,
            },
            trust: Trust::Token,
            serve_args: vec![],
        },
        credentials: Credentials::generate(),
        resource_id: Some("test-pod".into()),
        enrollment: None,
        destroyed: false,
    }
}

#[test]
fn command_contract_requires_info_target_and_explicit_destroy_target() {
    assert!(Cli::try_parse_from(["hellas", "cloud", "runpod", "info"]).is_err());
    assert!(Cli::try_parse_from(["hellas", "cloud", "runpod", "destroy"]).is_err());
    let cli = Cli::try_parse_from([
        "hellas",
        "cloud",
        "runpod",
        "info",
        "pod-123",
        "--account",
        "work",
    ])
    .unwrap();
    let Command::Cloud(CloudArgs {
        provider: CloudCommand::Runpod(args),
        ..
    }) = cli.command;
    assert_eq!(args.account.as_deref(), Some("work"));
    assert!(matches!(args.command, RunpodCommand::Info { pod_id } if pod_id == "pod-123"));
}

#[tokio::test]
async fn dry_run_needs_no_profile_credentials_or_receipt() {
    let image = format!("registry/image@sha256:{}", "a".repeat(64));
    let cli = Cli::try_parse_from([
        "hellas",
        "cloud",
        "runpod",
        "--account",
        "unconfigured",
        "create",
        "--name",
        "trial",
        "--image",
        &image,
        "--gpu",
        "NVIDIA L4",
        "--dry-run",
    ])
    .unwrap();
    let Command::Cloud(CloudArgs {
        provider: CloudCommand::Runpod(args),
        ..
    }) = cli.command;
    let value = args.run().await.unwrap();
    assert_eq!(value["account"], "unconfigured");
    assert_eq!(value["result"]["env"], serde_json::json!({}));
}

#[tokio::test]
async fn conflicting_account_or_pod_cannot_destroy_or_modify_a_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("receipt.json");
    let state = receipt();
    save_state(&path, &state, true).unwrap();
    let before = std::fs::read(&path).unwrap();
    let args = RunpodArgs {
        account: Some("personal".into()),
        command: RunpodCommand::Destroy {
            pod_id: None,
            state: Some(path.clone()),
        },
    };
    assert!(
        args.run()
            .await
            .unwrap_err()
            .to_string()
            .contains("--account does not match")
    );
    let error = deployment::destroy(&path, None, Some("different-pod"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("pod ID does not match"));
    assert_eq!(before, std::fs::read(&path).unwrap());
    let reread: Deployment = read_json(&path).unwrap();
    assert!(!reread.destroyed);
    assert_eq!(reread.spec.provider, state.spec.provider);
}

#[tokio::test]
async fn duplicate_create_keeps_the_original_receipt_before_contacting_provider() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("receipt.json");
    let mut state = receipt();
    if let ProviderConfig::Runpod { account, .. } = &mut state.spec.provider {
        *account = None;
    }
    save_state(&path, &state, true).unwrap();
    let before = std::fs::read(&path).unwrap();
    let error = deployment::create(state.spec, &path).await.unwrap_err();
    assert!(error.to_string().contains("allocation was not attempted"));
    assert_eq!(before, std::fs::read(&path).unwrap());
}
