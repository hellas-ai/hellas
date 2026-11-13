//! A stateless local gateway for model comparisons.
use super::*;

pub(super) struct LocalCompute {
    pub gateway: Process,
    pub http: reqwest::Client,
    pub address: String,
    pub provider: hellas_auth::PublicKey,
    _directory: tempfile::TempDir,
}
impl LocalCompute {
    pub async fn start(model: &Path) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        hellas_private::restrict_directory(root).unwrap();
        let owner = Cli::new(root, "owner", AGENT_PASSKEY);
        owner.run(&["identity", "init"]).await;
        let hellas_auth::authority::CredentialHolder::Node(holder) = owner.holder().await else {
            panic!("a device key")
        };
        let (gateway, address, token) = owner.gateway(&[string(model).into()], "local.log").await;
        let http = reqwest::Client::builder()
            .default_headers(
                [(
                    reqwest::header::AUTHORIZATION,
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
                )]
                .into_iter()
                .collect(),
            )
            .build()
            .unwrap();
        Self {
            gateway,
            http,
            address,
            provider: holder.public_key(),
            _directory: directory,
        }
    }
}
