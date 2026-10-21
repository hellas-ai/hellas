use std::time::Duration;

use async_trait::async_trait;
use hellas_providers::{HttpSecret, HttpSecretConfig};
use reqwest::Method;
use serde_json::{Value, json};

use crate::{CreateMachine, Error, Machine, Provider, Result};

pub(crate) fn open(credential: HttpSecretConfig, config: Config) -> Result<Box<dyn Provider>> {
    Ok(Box::new(RunPod::new(credential, config)?))
}

/// RunPod settings; the generic machine request contains no template metadata.
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub template: Option<String>,
    #[cfg(feature = "test-support")]
    pub api_base: Option<String>,
}

impl Config {
    fn base(&self) -> Result<String> {
        #[cfg(feature = "test-support")]
        if let Some(base) = &self.api_base {
            let url = reqwest::Url::parse(base).map_err(|_| Error::Invalid("test API base"))?;
            if url.scheme() != "http"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || !url
                    .host_str()
                    .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                    .is_some_and(|ip| ip.is_loopback())
            {
                return Err(Error::Invalid(
                    "test API base must be a loopback HTTP endpoint",
                ));
            }
            return Ok(base.trim_end_matches('/').into());
        }
        Ok("https://rest.runpod.io/v1".into())
    }
}

struct RunPod {
    client: reqwest::Client,
    base: String,
    credential: HttpSecret,
    config: Config,
}

impl RunPod {
    fn new(credential: HttpSecretConfig, config: Config) -> Result<Self> {
        let credential = credential.into_secret().map_err(|_| Error::Credential)?;
        let client = reqwest::Client::builder()
            .user_agent(concat!("hellas-cloud/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(Error::Request)?;
        Ok(Self {
            client,
            base: config.base()?,
            credential,
            config,
        })
    }

    async fn request(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        let token = self
            .credential
            .resolve()
            .await
            .map_err(|_| Error::Credential)?;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        // Never retry allocation: a lost response can hide a billable machine.
        let mut response = request.send().await.map_err(Error::Request)?;
        if !response.status().is_success() {
            return Err(Error::HttpStatus(response.status()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(Error::Request)? {
            if bytes.len().saturating_add(chunk.len()) > 1024 * 1024 {
                return Err(Error::ResponseBound);
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::Response)
    }
}

#[async_trait]
impl Provider for RunPod {
    async fn create(&self, request: &CreateMachine) -> Result<Machine> {
        validate_request(request)?;
        let template_id = self
            .config
            .template
            .as_deref()
            .ok_or(Error::Invalid("provider template required for creation"))?;
        validate_id(template_id)?;
        let template = self
            .request(Method::GET, &format!("/templates/{template_id}"), None)
            .await?;
        validate_template(request, template_id, &template)?;
        // Preserve template attribution and its persistent storage settings.
        // No transport secret, owner, bootstrap token, or environment is supplied.
        let created = self
            .request(
                Method::POST,
                "/pods",
                Some(json!({
                    "name": request.name, "templateId": template_id,
                    "computeType": "GPU", "cloudType": "SECURE",
                    "gpuTypeIds": [request.accelerator], "gpuCount": request.accelerator_count,
                    "interruptible": request.interruptible
                })),
            )
            .await
            .map_err(|source| Error::CreationUnconfirmed {
                name: request.name.clone(),
                source: Box::new(source),
            })?;
        let id = field(&created, "id")
            .and_then(|id| {
                validate_id(id)?;
                Ok(id.to_owned())
            })
            .map_err(|source| Error::CreationUnconfirmed {
                name: request.name.clone(),
                source: Box::new(source),
            })?;
        let live = self
            .request(Method::GET, &format!("/pods/{id}"), None)
            .await
            .map_err(|_| Error::Allocated {
                id: id.clone(),
                reason: "could not read allocated machine",
            })?;
        if live["id"].as_str() != Some(&id)
            || live["templateId"].as_str() != Some(template_id)
            || image(&live) != Some(&request.image)
        {
            return Err(Error::Allocated {
                id,
                reason: "template attribution or pinned image changed",
            });
        }
        machine(&live).map_err(|_| Error::Allocated {
            id,
            reason: "invalid allocated machine metadata",
        })
    }

    async fn list(&self) -> Result<Vec<Machine>> {
        let value = self.request(Method::GET, "/pods", None).await?;
        value
            .as_array()
            .ok_or(Error::Response)?
            .iter()
            .map(machine)
            .collect()
    }

    async fn destroy(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        self.request(Method::DELETE, &format!("/pods/{id}"), None)
            .await?;
        Ok(())
    }
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or(Error::Response)
}

fn image(value: &Value) -> Option<&str> {
    value["image"]
        .as_str()
        .or_else(|| value["imageName"].as_str())
}

fn machine(value: &Value) -> Result<Machine> {
    let id = field(value, "id")?;
    validate_id(id)?;
    Ok(Machine {
        id: id.into(),
        name: field(value, "name")?.into(),
        status: field(value, "desiredStatus")?.into(),
        image: image(value).ok_or(Error::Response)?.into(),
        public_ip: value["publicIp"].as_str().map(str::to_owned),
        console_url: Some("https://console.runpod.io/pods".into()),
    })
}

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 128
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(Error::Invalid("resource ID"));
    }
    Ok(())
}

fn validate_request(request: &CreateMachine) -> Result<()> {
    validate_id(&request.name)?;
    if request.accelerator.is_empty()
        || request.accelerator.len() > 128
        || request.accelerator_count == 0
    {
        return Err(Error::Invalid("accelerator"));
    }
    let Some((repository, digest)) = request.image.rsplit_once("@sha256:") else {
        return Err(Error::Invalid("image must be pinned by sha256 digest"));
    };
    if repository.is_empty()
        || repository.starts_with('-')
        || !repository
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._:-".contains(&b))
        || digest.len() != 64
        || !digest.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::Invalid("pinned image"));
    }
    Ok(())
}

fn validate_template(request: &CreateMachine, template_id: &str, template: &Value) -> Result<()> {
    if template["id"].as_str() != Some(template_id)
        || template["imageName"].as_str() != Some(&request.image)
        || template["isServerless"] == true
        || template["volumeMountPath"] != "/var/lib/hellas"
        || !template["containerDiskInGb"]
            .as_u64()
            .is_some_and(|v| v > 0)
        || !template["volumeInGb"].as_u64().is_some_and(|v| v > 0)
    {
        return Err(Error::Invalid(
            "template must retain the pinned image and persistent Hellas data volume",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn spec() -> CreateMachine {
        CreateMachine {
            name: "worker".into(),
            image: format!("registry/hellas@sha256:{}", "a".repeat(64)),
            accelerator: "NVIDIA L4".into(),
            accelerator_count: 1,
            interruptible: false,
        }
    }

    fn template() -> Value {
        json!({"id":"template", "imageName":spec().image, "isServerless":false,
            "volumeMountPath":"/var/lib/hellas", "containerDiskInGb":20, "volumeInGb":5})
    }

    fn pod() -> Value {
        json!({"id":"pod1", "name":"worker", "desiredStatus":"RUNNING",
            "image":spec().image, "templateId":"template", "publicIp":"192.0.2.1",
            "env":{"SECRET":"never-project-this"}})
    }

    fn config() -> Config {
        Config {
            template: Some("template".into()),
            #[cfg(feature = "test-support")]
            api_base: None,
        }
    }

    #[test]
    fn provider_settings_do_not_enter_the_generic_request() {
        let request = json!({"name":"worker","image":spec().image,"accelerator":"NVIDIA L4",
            "accelerator_count":1,"template":"template"});
        assert!(serde_json::from_value::<CreateMachine>(request).is_err());
        let settings = json!({"template":"template","api_base":"http://127.0.0.1:1234"});
        #[cfg(not(feature = "test-support"))]
        assert!(serde_json::from_value::<Config>(settings).is_err());
        #[cfg(feature = "test-support")]
        assert_eq!(
            serde_json::from_value::<Config>(settings)
                .unwrap()
                .base()
                .unwrap(),
            "http://127.0.0.1:1234"
        );
    }

    fn source(path: &std::path::Path) -> HttpSecretConfig {
        serde_json::from_value(json!({"secret_file":path,"secret_field":"token"})).unwrap()
    }

    fn receive(socket: &mut std::net::TcpStream) -> (String, Value) {
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
        let length: usize = headers
            .lines()
            .find_map(|line| {
                line.to_lowercase()
                    .strip_prefix("content-length: ")
                    .map(|v| v.parse().unwrap())
            })
            .unwrap_or(0);
        let mut body = vec![0; length];
        socket.read_exact(&mut body).unwrap();
        let body = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        (headers, body)
    }

    fn respond(socket: &mut std::net::TcpStream, status: &str, body: &str) {
        write!(socket, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    }

    #[tokio::test]
    async fn create_list_destroy_use_one_source_and_never_send_bootstrap_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential.json");
        hellas_private::write_atomically(&path, ".tmp", br#"{"token":"first"}"#).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for step in 0..5 {
                let (mut socket, _) = listener.accept().unwrap();
                let (headers, body) = receive(&mut socket);
                assert!(headers.to_lowercase().contains(if step < 3 {
                    "authorization: bearer first"
                } else {
                    "authorization: bearer rotated"
                }));
                let response = match step {
                    0 => {
                        assert!(headers.starts_with("GET /templates/template "));
                        template()
                    }
                    1 => {
                        assert!(headers.starts_with("POST /pods "));
                        assert_eq!(
                            body,
                            json!({"name":"worker","templateId":"template","computeType":"GPU", "cloudType":"SECURE", "gpuTypeIds":["NVIDIA L4"],"gpuCount":1,"interruptible":false})
                        );
                        json!({"id":"pod1"})
                    }
                    2 => {
                        assert!(headers.starts_with("GET /pods/pod1 "));
                        pod()
                    }
                    3 => {
                        assert!(headers.starts_with("GET /pods "));
                        json!([pod()])
                    }
                    _ => {
                        assert!(headers.starts_with("DELETE /pods/pod1 "));
                        Value::Null
                    }
                };
                respond(&mut socket, "200 OK", &response.to_string());
            }
        });
        #[cfg(feature = "test-support")]
        let provider = crate::open(
            source(&path),
            crate::ProviderConfig::RunPod(Config {
                api_base: Some(format!("http://{address}")),
                ..config()
            }),
        )
        .unwrap();
        #[cfg(not(feature = "test-support"))]
        let provider = {
            let mut provider = RunPod::new(source(&path), config()).unwrap();
            provider.base = format!("http://{address}");
            provider
        };
        let created = provider.create(&spec()).await.unwrap();
        assert_eq!(created.id, "pod1");
        assert!(
            !serde_json::to_string(&created)
                .unwrap()
                .contains("never-project")
        );
        hellas_private::write_atomically(&path, ".tmp", br#"{"token":"rotated"}"#).unwrap();
        assert_eq!(provider.list().await.unwrap().len(), 1);
        provider.destroy(&created.id).await.unwrap();
        server.join().unwrap();
    }

    #[test]
    fn template_image_storage_and_identifiers_are_enforced_before_allocation() {
        for (field, value) in [
            ("id", json!("different")),
            ("imageName", json!("registry/image:latest")),
            ("volumeMountPath", json!("/workspace")),
            ("volumeInGb", json!(0)),
            ("containerDiskInGb", json!(0)),
            ("isServerless", json!(true)),
        ] {
            let mut invalid = template();
            invalid[field] = value;
            assert!(validate_template(&spec(), "template", &invalid).is_err());
        }
        for id in ["", "../pods", "one?two", "one/two"] {
            assert!(validate_id(id).is_err());
        }
        let mut invalid = spec();
        invalid.image = "image:latest".into();
        assert!(validate_request(&invalid).is_err());
    }

    #[tokio::test]
    async fn changed_template_after_allocation_returns_resource_id_for_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential.json");
        hellas_private::write_atomically(&path, ".tmp", br#"{"token":"key"}"#).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for step in 0..3 {
                let (mut socket, _) = listener.accept().unwrap();
                receive(&mut socket);
                let value = match step {
                    0 => template(),
                    1 => json!({"id":"pod1"}),
                    _ => {
                        let mut value = pod();
                        value["templateId"] = json!("changed");
                        value
                    }
                };
                respond(&mut socket, "200 OK", &value.to_string());
            }
        });
        let mut provider = RunPod::new(source(&path), config()).unwrap();
        provider.base = format!("http://{address}");
        assert!(
            matches!(provider.create(&spec()).await, Err(Error::Allocated { id, .. }) if id == "pod1")
        );
        server.join().unwrap();
    }

    #[tokio::test]
    async fn redirects_and_oversized_responses_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credential.json");
        hellas_private::write_atomically(&path, ".tmp", br#"{"token":"key"}"#).unwrap();
        for redirect in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                receive(&mut socket);
                if redirect {
                    write!(socket, "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                } else {
                    respond(&mut socket, "200 OK", &"x".repeat(1024 * 1024 + 1));
                }
            });
            let mut provider = RunPod::new(source(&path), config()).unwrap();
            provider.base = format!("http://{address}");
            let result = provider.list().await;
            if redirect {
                assert!(matches!(result, Err(Error::HttpStatus(_))));
            } else {
                assert!(matches!(result, Err(Error::ResponseBound)));
            }
            server.join().unwrap();
        }
    }
}
