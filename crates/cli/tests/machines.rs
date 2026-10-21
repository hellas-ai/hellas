#![cfg(feature = "test-support")]

use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    time::Duration,
};

#[tokio::test]
async fn generic_machine_commands_use_the_documented_provider_and_real_http_driver() {
    let root = tempfile::tempdir().unwrap();
    let mut documented: Value =
        serde_json::from_str(include_str!("../../../docs/machine-provider.json")).unwrap();
    let image = format!("registry/hellas@sha256:{}", "a".repeat(64));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let configuration = &mut documented["config"];
    configuration["api_base"] = json!(base);
    let template = configuration["template"].as_str().unwrap().to_owned();
    let source = root.path().join("source.json");
    let secret = root.path().join("account.json");
    let config = root.path().join("provider.json");
    let spec = root.path().join("machine.json");
    hellas_private::write_atomically(&secret, ".writing", br#"{"token":"fixture-token"}"#).unwrap();
    std::fs::write(
        &source,
        json!({"secret_file":secret,"secret_field":"token"}).to_string(),
    )
    .unwrap();
    std::fs::write(&config, documented.to_string()).unwrap();
    std::fs::write(
        &spec,
        json!({
            "name": "fixture",
            "image": image,
            "accelerator": "test accelerator",
            "accelerator_count": 1,
            "interruptible": false
        })
        .to_string(),
    )
    .unwrap();
    let server = std::thread::spawn(move || {
        let pod = json!({"id":"machine1","name":"fixture","desiredStatus":"RUNNING", "image":image,"templateId":template,"env":{"secret":"must-not-appear"}});
        for step in 0..5 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
            }
            let headers = String::from_utf8(headers).unwrap();
            assert!(
                headers
                    .to_lowercase()
                    .contains("authorization: bearer fixture-token")
            );
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    line.to_lowercase()
                        .strip_prefix("content-length: ")
                        .map(|value| value.parse().unwrap())
                })
                .unwrap_or(0);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            let response = match step {
                0 => {
                    assert!(headers.starts_with(&format!("GET /templates/{template} ")));
                    json!({
                        "id": template,
                        "imageName": image,
                        "volumeMountPath": "/var/lib/hellas",
                        "containerDiskInGb": 20,
                        "volumeInGb": 10
                    })
                }
                1 => {
                    assert!(headers.starts_with("POST /pods "));
                    let body: Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(
                        body,
                        json!({
                            "name": "fixture",
                            "templateId": template,
                            "computeType": "GPU",
                            "cloudType": "SECURE",
                            "gpuTypeIds": ["test accelerator"],
                            "gpuCount": 1,
                            "interruptible": false
                        })
                    );
                    json!({"id": "machine1"})
                }
                2 => {
                    assert!(headers.starts_with("GET /pods/machine1 "));
                    pod.clone()
                }
                3 => {
                    assert!(headers.starts_with("GET /pods "));
                    json!([pod])
                }
                _ => {
                    assert!(headers.starts_with("DELETE /pods/machine1 "));
                    Value::Null
                }
            }
            .to_string();
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).unwrap();
        }
    });
    for command in [
        vec!["create", "--spec", spec.to_str().unwrap()],
        vec!["list"],
        vec!["destroy", "machine1"],
    ] {
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::process::Command::new(env!("CARGO_BIN_EXE_hellas-cli"))
                .args([
                    "machines",
                    "--credential-source",
                    source.to_str().unwrap(),
                    "--provider-config",
                    config.to_str().unwrap(),
                ])
                .args(&command)
                .env("OTEL_SDK_DISABLED", "true")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            output.status.success(),
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(!stdout.contains("must-not-appear"));
        assert!(!stdout.contains("fixture-token"));
        if command[0] == "create" {
            assert_eq!(
                serde_json::from_str::<Value>(&stdout).unwrap()["id"],
                "machine1"
            );
        }
        if command[0] == "list" {
            assert_eq!(
                serde_json::from_str::<Value>(&stdout).unwrap()[0]["id"],
                "machine1"
            );
        }
    }
    server.join().unwrap();
}
