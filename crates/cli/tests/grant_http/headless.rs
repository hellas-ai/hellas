use super::*;
use std::os::unix::fs::PermissionsExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn headless_gateway_hands_its_bearer_to_an_authenticated_client() {
    let root = tempfile::tempdir().unwrap();
    let cli = Cli::new(root.path(), "headless", ROOT_PASSKEY);
    let key = root.path().join("upstream.key");
    let bearer = root.path().join("bearer");
    std::fs::write(&key, "upstream-secret").unwrap();
    // Replacing an existing public file must still publish a private one.
    std::fs::write(&bearer, "old").unwrap();
    std::fs::set_permissions(&bearer, std::fs::Permissions::from_mode(0o644)).unwrap();
    let upstream = format!("api=https://example.com/v1,key-file={}", key.display());
    let log = root.path().join("headless.log");
    let output = std::fs::File::create(&log).unwrap();
    let mut command = cli.command(&[
        "gateway",
        "--bind",
        "127.0.0.1:0",
        "--upstream",
        &upstream,
        "--model",
        "model@api",
        "--bearer-file",
        string(&bearer),
    ]);
    // A new session has no controlling terminal, regardless of the test runner.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command
        .stdout(output.try_clone().unwrap())
        .stderr(output)
        .spawn()
        .unwrap();
    let mut process = Process { child, log };
    let address = process.wait_for("Gateway: ").await;
    let token = std::fs::read_to_string(&bearer).unwrap();
    assert_ne!(token.trim(), "old");
    assert_eq!(
        std::fs::metadata(&bearer).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .get(format!("{address}/v1/models"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let discovery = client
        .get(format!("{address}/v1/models"))
        .bearer_auth(token.trim())
        .send()
        .await
        .unwrap();
    assert_eq!(discovery.status(), reqwest::StatusCode::OK);
    let models: Value = discovery.json().await.unwrap();
    assert_eq!(models["data"].as_array().unwrap().len(), 1);
    assert_eq!(models["data"][0]["id"], "model");
    assert_eq!(
        client
            .post(format!("{address}/v1/chat/completions"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let response = client
        .post(format!("{address}/v1/chat/completions"))
        .bearer_auth(token.trim())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(!response.text().await.unwrap().is_empty());
    assert!(
        !std::fs::read_to_string(&process.log)
            .unwrap()
            .contains(token.trim())
    );
    process.stop().await;

    let mut command = cli.command(&["gateway", "--upstream", &upstream, "--model", "model@api"]);
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let rejected = tokio::time::timeout(HANG_GUARD, command.output())
        .await
        .unwrap()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("--bearer-file"));
}
