use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use serde_json::{Value, json};
use tokio::{io::AsyncWriteExt, process::Command};

use crate::config::{Credentials, ProviderConfig, Spec};

/// Providers own allocation only; administration and Hellas routing are shared.
/// An additional backend implements these methods and adds one config variant.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Pure, credential-free description for review before allocation.
    fn plan(&self, spec: &Spec) -> Result<Value>;
    /// Resolve provider metadata before saving the pending allocation receipt.
    async fn prepare(&self, spec: &mut Spec) -> Result<()> {
        spec.validate()
    }
    async fn create(&self, spec: &Spec, credentials: &Credentials) -> Result<String>;
    /// Check the allocated resource after its ID is safely recorded.
    async fn verify(&self, _spec: &Spec, _id: &str) -> Result<()> {
        Ok(())
    }
    async fn inspect(&self, id: &str) -> Result<Value>;
    async fn destroy(&self, id: &str) -> Result<()>;
}

pub fn adapter(config: &ProviderConfig) -> Result<Box<dyn Provider>> {
    match config {
        ProviderConfig::Docker { gpus } => Ok(Box::new(Docker { gpus: *gpus })),
        ProviderConfig::Runpod { account, .. } => Ok(Box::new(Cloud::runpod(account.as_deref())?)),
        ProviderConfig::Vast { .. } => Ok(Box::new(Cloud::new(CloudKind::Vast)?)),
    }
}

pub struct Docker {
    pub gpus: bool,
}

async fn docker(args: &[&str], input: Option<&[u8]>) -> Result<String> {
    let mut command = Command::new("docker");
    command
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    if input.is_some() {
        command.stdin(std::process::Stdio::piped());
    }
    let mut child = command.spawn().context("start docker")?;
    if let Some(bytes) = input {
        child.stdin.take().unwrap().write_all(bytes).await?;
    }
    let output = tokio::time::timeout(Duration::from_secs(600), child.wait_with_output()).await??;
    ensure!(
        output.status.success(),
        "docker operation failed (details suppressed to avoid leaking bootstrap credentials)"
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

#[async_trait]
impl Provider for Docker {
    fn plan(&self, spec: &Spec) -> Result<Value> {
        spec.validate()?;
        Ok(
            json!({"provider":"docker", "name":spec.name, "image":spec.image,
            "gpus":self.gpus, "data_volume":format!("{}-data",spec.name), "publish_ports":[], "trust":"token"}),
        )
    }

    async fn create(&self, spec: &Spec, credentials: &Credentials) -> Result<String> {
        self.plan(spec)?;
        let env = credentials
            .env(spec)?
            .into_iter()
            .map(|(k, v)| format!("{k}={v}\n"))
            .collect::<String>();
        // Credentials travel over stdin, never in argv or a printed command.
        let mut args = vec![
            "run",
            "--detach",
            "--name",
            &spec.name,
            "--env-file",
            "/dev/stdin",
            "--mount",
        ];
        let mount = format!(
            "type=volume,source={}-data,target=/var/lib/hellas",
            spec.name
        );
        args.push(&mount);
        if self.gpus {
            args.extend(["--gpus", "all"]);
        }
        args.push(&spec.image);
        docker(&args, Some(env.as_bytes())).await
    }

    async fn inspect(&self, id: &str) -> Result<Value> {
        validate_id(id)?;
        let output = docker(&["inspect", "--format", "{{json .State}}", id], None).await?;
        let state: Value = serde_json::from_str(&output)?;
        Ok(json!({"id":id, "status":state["Status"], "exit_code":state["ExitCode"]}))
    }

    async fn destroy(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        docker(&["rm", "--force", id], None).await?;
        Ok(()) // Deliberately retain the data volume and enrollment identity.
    }
}

#[derive(Clone, Copy)]
pub enum CloudKind {
    Runpod,
    Vast,
}

pub struct Cloud {
    kind: CloudKind,
    client: reqwest::Client,
    base: String,
    credential: crate::accounts::CredentialSource,
}

impl Cloud {
    pub fn new(kind: CloudKind) -> Result<Self> {
        Ok(Self {
            kind,
            client: reqwest::Client::builder()
                .user_agent(concat!("hellas-cloud/", env!("CARGO_PKG_VERSION")))
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(60))
                .build()?,
            base: match kind {
                CloudKind::Runpod => "https://rest.runpod.io/v1",
                CloudKind::Vast => "https://console.vast.ai/api/v0",
            }
            .into(),
            credential: crate::accounts::CredentialSource::Env(
                match kind {
                    CloudKind::Runpod => "RUNPOD_API_KEY",
                    CloudKind::Vast => "VAST_API_KEY",
                }
                .into(),
            ),
        })
    }

    pub fn runpod(account: Option<&str>) -> Result<Self> {
        let mut client = Self::new(CloudKind::Runpod)?;
        client.credential = crate::accounts::runpod(account)?;
        Ok(client)
    }

    pub async fn list(&self) -> Result<Value> {
        ensure!(
            matches!(self.kind, CloudKind::Runpod),
            "listing is not implemented for this provider"
        );
        let value = self.request(reqwest::Method::GET, "/pods", None).await?;
        let pods = value.as_array().context("invalid pod list")?;
        Ok(Value::Array(pods.iter().map(runpod_summary).collect()))
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        let key = self.credential.token().await.map_err(|error| {
            if matches!(self.kind, CloudKind::Runpod)
                && error.is::<crate::accounts::MissingCredential>()
            {
                error.context(crate::accounts::RunpodAccountRequired)
            } else {
                error
            }
        })?;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(key);
        if let Some(body) = body {
            request = request.json(&body);
        }
        // Do not retry allocation: a lost response can hide a billable resource.
        let mut response = request.send().await.context(
            "provider request failed; reconcile resource by name before retrying allocation",
        )?;
        let status = response.status();
        ensure!(
            status.is_success(),
            "provider returned HTTP {status}; response body withheld (may contain credentials)"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 1024 * 1024,
                "provider response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        let value: Value = serde_json::from_slice(&bytes).context("invalid provider JSON")?;
        ensure!(
            value.get("success") != Some(&Value::Bool(false)),
            "provider refused operation; inspect provider console"
        );
        Ok(value)
    }

    pub fn create_body(&self, spec: &Spec, env: BTreeMap<String, String>) -> Result<Value> {
        spec.validate()?;
        match (&self.kind, &spec.provider) {
            (
                CloudKind::Runpod,
                ProviderConfig::Runpod {
                    template_id,
                    gpu_type,
                    interruptible,
                    ..
                },
            ) => {
                let template_id = template_id
                    .as_deref()
                    .context("Runpod creation requires a template")?;
                validate_id(template_id)?;
                // Inherit image, disks, registry auth, ports and startup settings.
                // Cloning a template into an ad-hoc image request loses attribution.
                Ok(json!({
                    "name":spec.name, "templateId":template_id,
                    "computeType":"GPU", "cloudType":"SECURE",
                    "gpuTypeIds":[gpu_type], "gpuCount":1,
                    "interruptible":interruptible, "env":env
                }))
            }
            (CloudKind::Vast, ProviderConfig::Vast { disk_gb, .. }) => {
                // Values are generated hex only, never arbitrary shell fragments.
                ensure!(
                    env.iter().all(
                        |(k, v)| k.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
                            && v.bytes().all(|b| b.is_ascii_hexdigit())
                    ),
                    "invalid bootstrap environment"
                );
                Ok(
                    json!({"label":spec.name, "image":spec.image, "disk":disk_gb,
                    "runtype":"args", "args":[], "target_state":"running", "cancel_unavail":true,
                    "env":env.into_iter().map(|(k,v)|format!("-e {k}={v}")).collect::<Vec<_>>().join(" ")}),
                )
            }
            _ => bail!("provider/spec mismatch"),
        }
    }
}

#[async_trait]
impl Provider for Cloud {
    fn plan(&self, spec: &Spec) -> Result<Value> {
        self.create_body(spec, BTreeMap::new())
    }

    async fn prepare(&self, spec: &mut Spec) -> Result<()> {
        if let ProviderConfig::Runpod { template_id, .. } = &spec.provider {
            let id = template_id
                .as_deref()
                .context("Runpod creation requires a template")?;
            validate_id(id)?;
            let template = self
                .request(reqwest::Method::GET, &format!("/templates/{id}"), None)
                .await?;
            resolve_runpod_template(spec, &template)?;
        }
        spec.validate()
    }

    async fn verify(&self, spec: &Spec, id: &str) -> Result<()> {
        if let ProviderConfig::Runpod {
            template_id: Some(template_id),
            ..
        } = &spec.provider
        {
            let pod = self.inspect(id).await?;
            ensure!(
                pod["template_id"].as_str() == Some(template_id),
                "Runpod did not retain the requested template attribution"
            );
            ensure!(
                pod["image"].as_str() == Some(&spec.image),
                "Runpod image differs from the resolved template; template may have changed"
            );
        }
        Ok(())
    }

    async fn create(&self, spec: &Spec, credentials: &Credentials) -> Result<String> {
        let body = self.create_body(spec, credentials.env(spec)?)?;
        let (method, path) = match spec.provider {
            ProviderConfig::Runpod { .. } => (reqwest::Method::POST, "/pods".to_owned()),
            ProviderConfig::Vast { offer_id, .. } => {
                (reqwest::Method::PUT, format!("/asks/{offer_id}/"))
            }
            _ => bail!("provider/spec mismatch"),
        };
        let response = self.request(method, &path, Some(body)).await?;
        let id = match self.kind {
            CloudKind::Runpod => response["id"]
                .as_str()
                .context("missing pod ID; reconcile by name in provider console")?
                .to_owned(),
            CloudKind::Vast => response["new_contract"]
                .as_u64()
                .context("missing instance ID; reconcile by name in provider console")?
                .to_string(),
        };
        validate_id(&id)?;
        Ok(id)
    }

    async fn inspect(&self, id: &str) -> Result<Value> {
        validate_id(id)?;
        let path = match self.kind {
            CloudKind::Runpod => format!("/pods/{id}"),
            CloudKind::Vast => format!("/instances/{id}/"),
        };
        let value = self.request(reqwest::Method::GET, &path, None).await?;
        // Provider responses echo env; return only the fields we intend to show.
        Ok(match self.kind {
            CloudKind::Runpod => runpod_summary(&value),
            CloudKind::Vast => {
                json!({"id":id, "status":value["instances"]["actual_status"], "image":value["instances"]["image_uuid"]})
            }
        })
    }

    async fn destroy(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        let path = match self.kind {
            CloudKind::Runpod => format!("/pods/{id}"),
            CloudKind::Vast => format!("/instances/{id}/"),
        };
        self.request(reqwest::Method::DELETE, &path, None).await?;
        Ok(())
    }
}

fn resolve_runpod_template(spec: &mut Spec, template: &Value) -> Result<()> {
    let ProviderConfig::Runpod {
        template_id,
        disk_gb,
        volume_gb,
        ..
    } = &mut spec.provider
    else {
        bail!("template resolution requires Runpod");
    };
    ensure!(
        template["id"].as_str() == template_id.as_deref(),
        "unexpected Runpod template"
    );
    ensure!(
        template["isServerless"] != true,
        "Hellas requires a Pod template"
    );
    ensure!(
        template["volumeMountPath"] == "/var/lib/hellas",
        "template must mount persistent worker data at /var/lib/hellas"
    );
    let image = template["imageName"]
        .as_str()
        .context("template has no image")?;
    ensure!(
        spec.image.is_empty() || spec.image == image,
        "template image changed from the requested digest"
    );
    spec.image = image.to_owned();
    *disk_gb = template["containerDiskInGb"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .context("invalid template container disk size")?;
    *volume_gb = template["volumeInGb"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .context("invalid template volume size")?;
    // Only non-secret deployment metadata is copied into the receipt.
    spec.validate()
}

/// Provider responses also contain environment secrets: project an allowlist.
fn runpod_summary(value: &Value) -> Value {
    json!({"id":value["id"], "name":value["name"],
        "desired_status":value["desiredStatus"], "image":value.get("imageName").filter(|v| v.is_string()).unwrap_or(&value["image"]),
        "template_id":value["templateId"],
        "gpu_count":value["gpuCount"], "hourly_rate":value["costPerHr"],
        "interruptible":value["interruptible"],
        "disk_gb":value["containerDiskInGb"], "volume_gb":value["volumeInGb"]})
}

pub fn validate_id(id: &str) -> Result<()> {
    ensure!(
        !id.is_empty()
            && id.len() <= 128
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid provider resource ID"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn template_spec() -> Spec {
        Spec {
            name: "test-worker".into(),
            image: String::new(),
            provider: ProviderConfig::Runpod {
                account: None,
                template_id: Some("foundation-template".into()),
                gpu_type: "NVIDIA L4".into(),
                interruptible: true,
                disk_gb: 0,
                volume_gb: 0,
                container_registry_auth_id: None,
            },
            trust: crate::config::Trust::Token,
            serve_args: vec![],
        }
    }

    fn template() -> Value {
        json!({"id":"foundation-template", "imageName":format!("registry/image@sha256:{}", "a".repeat(64)),
            "containerDiskInGb":20, "volumeInGb":4, "volumeMountPath":"/var/lib/hellas",
            "env":{"UPSTREAM_KEY":"must-not-enter-receipt"}})
    }

    #[test]
    fn template_resolution_requires_pinned_image_and_preserves_only_metadata() {
        let mut spec = template_spec();
        resolve_runpod_template(&mut spec, &template()).unwrap();
        assert_eq!(spec.image, template()["imageName"]);
        assert!(
            !serde_json::to_string(&spec)
                .unwrap()
                .contains("must-not-enter-receipt")
        );
        for (field, value) in [
            ("id", json!("another-template")),
            ("imageName", json!("registry/image:latest")),
            ("volumeMountPath", json!("/workspace")),
            ("volumeInGb", json!(0)),
            ("isServerless", json!(true)),
        ] {
            let mut invalid = template();
            invalid[field] = value;
            assert!(resolve_runpod_template(&mut template_spec(), &invalid).is_err());
        }
    }

    #[tokio::test]
    async fn template_api_preserves_attribution_and_detects_missing_attribution() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for index in 0..4 {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    bytes.push(byte[0]);
                }
                let headers = String::from_utf8(bytes).unwrap();
                let response = match index {
                    0 => {
                        assert!(headers.starts_with("GET /templates/foundation-template "));
                        template()
                    }
                    1 => {
                        assert!(headers.starts_with("POST /pods "));
                        let length: usize = headers.lines().find_map(|line| line.to_lowercase()
                            .strip_prefix("content-length: ").map(str::parse)).unwrap().unwrap();
                        let mut body = vec![0; length];
                        socket.read_exact(&mut body).unwrap();
                        let body: Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(body["templateId"], "foundation-template");
                        assert_eq!(body["interruptible"], true);
                        assert!(body["env"]["HELLAS_REMOTE_TOKEN"].is_string());
                        assert!(body.get("imageName").is_none());
                        assert!(body.get("volumeMountPath").is_none());
                        json!({"id":"test-pod"})
                    }
                    _ => {
                        assert!(headers.starts_with("GET /pods/test-pod "));
                        // Live REST responses use `image`, not always `imageName`.
                        json!({"id":"test-pod", "templateId":if index == 2 { json!("foundation-template") } else { Value::Null },
                            "image":template()["imageName"], "env":{"secret":"do-not-leak"}})
                    }
                }.to_string();
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
            }
        });
        let mut cloud = Cloud::new(CloudKind::Runpod).unwrap();
        cloud.base = format!("http://{address}");
        cloud.credential =
            crate::accounts::CredentialSource::Command(vec!["printf".into(), "fixture".into()]);
        let mut spec = template_spec();
        cloud.prepare(&mut spec).await.unwrap();
        let id = cloud.create(&spec, &Credentials::generate()).await.unwrap();
        cloud.verify(&spec, &id).await.unwrap();
        assert!(
            cloud
                .verify(&spec, &id)
                .await
                .unwrap_err()
                .to_string()
                .contains("attribution")
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn concurrent_accounts_keep_their_own_tokens_and_redact_pod_environment() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    bytes.push(byte[0]);
                }
                let request = String::from_utf8(bytes).unwrap();
                let (id, list) = if request.starts_with("GET /pods ") {
                    assert!(
                        request
                            .to_lowercase()
                            .contains("authorization: bearer account-a")
                    );
                    ("pod-a", true)
                } else {
                    assert!(request.starts_with("GET /pods/pod-b "));
                    assert!(
                        request
                            .to_lowercase()
                            .contains("authorization: bearer account-b")
                    );
                    ("pod-b", false)
                };
                let pod = json!({"id":id, "desiredStatus":"RUNNING", "imageName":"pinned-image",
                    "env":{"HELLAS_REMOTE_TOKEN":"do-not-leak"}, "registryPassword":"do-not-leak"});
                let body = if list { json!([pod]) } else { pod }.to_string();
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
            }
        });
        let mut a = Cloud::new(CloudKind::Runpod).unwrap();
        let mut b = Cloud::new(CloudKind::Runpod).unwrap();
        for (client, token) in [(&mut a, "account-a"), (&mut b, "account-b")] {
            client.base = format!("http://{address}");
            client.credential =
                crate::accounts::CredentialSource::Command(vec!["printf".into(), token.into()]);
        }
        let (a, b) = tokio::join!(a.list(), b.inspect("pod-b"));
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!(a[0]["id"], "pod-a");
        assert_eq!(b["id"], "pod-b");
        assert_eq!(b["image"], "pinned-image");
        assert!(!format!("{a}{b}").contains("do-not-leak"));
        server.join().unwrap();
    }
}
