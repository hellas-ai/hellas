//! Image companion. Allocation and operator commands live in the main Hellas CLI.
#[cfg(unix)]
use anyhow::{Context, Result, ensure};
#[cfg(unix)]
use clap::Parser;
#[cfg(unix)]
use hellas_cloud::{
    agent,
    config::{Credentials, read_json, validate_serve_args},
};
#[cfg(unix)]
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};

#[cfg(unix)]
#[derive(Parser)]
#[command(version, about = "Run an owner-bound Hellas worker")]
struct Args {
    #[arg(long, default_value = "/var/lib/hellas")]
    data: PathBuf,
    /// Private settings/credentials directory; defaults to --data.
    /// Use a filesystem supporting owner-only permissions.
    #[arg(long)]
    configuration_dir: Option<PathBuf>,
    /// Private environment map prepared by `hellas machines prepare`.
    #[arg(long)]
    bootstrap: Option<PathBuf>,
    #[arg(long, default_value = "/bin/hellas-cli")]
    cli: PathBuf,
    /// Original OCI entrypoint encoded as a JSON argv array.
    #[arg(long)]
    launcher: Option<PathBuf>,
    #[arg(long)]
    bind: Option<SocketAddr>,
    #[arg(long)]
    no_relay: bool,
    #[arg(last = true)]
    serve_args: Vec<String>,
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<()> {
    let Args {
        data,
        configuration_dir,
        bootstrap,
        cli,
        launcher,
        bind,
        no_relay,
        mut serve_args,
    } = Args::parse();
    let bootstrap: BTreeMap<String, String> = bootstrap
        .as_deref()
        .map(read_json)
        .transpose()?
        .unwrap_or_default();
    let setting = |name: &str| {
        bootstrap
            .get(name)
            .cloned()
            .or_else(|| std::env::var(name).ok())
    };
    let credentials = Credentials {
        admin_secret: setting("HELLAS_REMOTE_KEY").context("missing HELLAS_REMOTE_KEY")?,
        token: setting("HELLAS_REMOTE_TOKEN").context("missing HELLAS_REMOTE_TOKEN")?,
        owner: Some(setting("HELLAS_REMOTE_OWNER").context("missing HELLAS_REMOTE_OWNER")?),
    };
    if let Some(args) = setting("HELLAS_REMOTE_ARGS") {
        ensure!(
            serve_args.is_empty(),
            "serve args supplied both in env and argv"
        );
        serve_args = serde_json::from_slice(&hex::decode(args)?)?;
    }
    validate_serve_args(&serve_args)?;
    let launcher = launcher
        .as_deref()
        .map(read_json)
        .transpose()?
        .unwrap_or_else(|| vec![cli.to_string_lossy().into_owned(), "serve".into()]);
    agent::run(agent::AgentOptions {
        credentials,
        data,
        configuration_dir,
        cli,
        launcher,
        serve_args,
        bind,
        no_relay,
    })
    .await
}

#[cfg(not(unix))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("hellas-agent currently requires Unix")
}
