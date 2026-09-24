use crate::management::{Request, Service};
use anyhow::Result;
use clap::{Args, Subcommand};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Args)]
pub struct MachinesArgs {
    /// Call a running internal management service instead of running in-process.
    #[arg(long, global = true)]
    pub socket: Option<PathBuf>,
    #[command(subcommand)]
    pub command: MachineCommand,
}

#[derive(Subcommand)]
pub enum MachineCommand {
    /// Show this identity's machines. Last observations are not liveness guarantees.
    List,
    Status {
        name: String,
    },
    /// Authenticate the live machine and return its pinned execution route.
    Resolve {
        name: String,
    },
    Restart {
        name: String,
    },
    /// Install fetch routes and provider credentials over iroh, then restart Hellas.
    Configure {
        name: String,
        /// Local JSON route configuration, including its caller grants.
        #[arg(long)]
        fetch_config: PathBuf,
        /// Copy a credential from this local environment variable. Repeat as needed.
        #[arg(long = "env", value_name = "NAME")]
        env: Vec<String>,
        /// Upload a private JSON credential file, referenced in config as @files/NAME.
        #[arg(long = "file", value_name = "NAME=PATH")]
        files: Vec<String>,
    },
    Fetch {
        name: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        sha256: String,
        #[arg(long)]
        bytes: u64,
    },
    /// Prepare an owner-bound bare-metal agent bootstrap file (mode 0600).
    Prepare {
        name: String,
        #[arg(long)]
        bootstrap_file: PathBuf,
        #[arg(long)]
        admin_addr: Option<SocketAddr>,
        #[arg(last = true)]
        serve_args: Vec<String>,
    },
    Destroy {
        name: String,
    },
}

impl MachinesArgs {
    pub async fn run(self, service: Service) -> Result<()> {
        let request = match self.command {
            MachineCommand::List => Request::List,
            MachineCommand::Status { name } => Request::Status { name },
            MachineCommand::Resolve { name } => Request::Resolve { name },
            MachineCommand::Restart { name } => Request::Restart { name },
            MachineCommand::Configure {
                name,
                fetch_config,
                env,
                files,
            } => {
                let metadata = std::fs::metadata(&fetch_config)?;
                anyhow::ensure!(
                    metadata.is_file() && metadata.len() <= 48 * 1024,
                    "fetch configuration must be a regular file of at most 48 KiB"
                );
                let fetch_config = serde_json::from_slice(&std::fs::read(fetch_config)?)
                    .map_err(|_| anyhow::anyhow!("invalid fetch configuration JSON"))?;
                let env = env
                    .into_iter()
                    .map(|name| {
                        let value = std::env::var(&name).map_err(|_| {
                            anyhow::anyhow!("credential environment variable is unset or invalid")
                        })?;
                        Ok((name, value))
                    })
                    .collect::<Result<_>>()?;
                let files = files
                    .into_iter()
                    .map(|argument| {
                        let (name, path) = argument
                            .split_once('=')
                            .ok_or_else(|| anyhow::anyhow!("--file requires NAME=PATH"))?;
                        let metadata = std::fs::metadata(path)?;
                        anyhow::ensure!(
                            metadata.is_file() && metadata.len() <= 48 * 1024,
                            "credential file must be a regular file of at most 48 KiB"
                        );
                        let value =
                            serde_json::from_slice(&std::fs::read(path)?).map_err(|_| {
                                anyhow::anyhow!("invalid credential JSON; contents withheld")
                            })?;
                        Ok((name.to_owned(), value))
                    })
                    .collect::<Result<_>>()?;
                let configuration = crate::configuration::Configuration {
                    fetch_config,
                    env,
                    files,
                };
                configuration.validate()?;
                Request::Configure {
                    name,
                    configuration,
                }
            }
            MachineCommand::Fetch {
                name,
                url,
                sha256,
                bytes,
            } => Request::Fetch {
                name,
                url,
                sha256,
                bytes,
            },
            MachineCommand::Prepare {
                name,
                bootstrap_file,
                admin_addr,
                serve_args,
            } => Request::Prepare {
                name,
                bootstrap_file,
                admin_addr,
                serve_args,
            },
            MachineCommand::Destroy { name } => Request::Destroy { name },
        };
        let result = if let Some(socket) = self.socket {
            // A GUI uses the same methods. Reject a socket serving another loaded identity.
            let inventory = crate::internal_rpc::call(&socket, Request::List).await?;
            anyhow::ensure!(
                inventory["owner"] == service.owner(),
                "control socket serves another identity"
            );
            crate::internal_rpc::call(&socket, request).await?
        } else {
            service.execute(request).await?
        };
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

#[derive(Args)]
pub struct ControlArgs {
    #[command(subcommand)]
    pub command: ControlCommand,
}

#[derive(Subcommand)]
pub enum ControlCommand {
    /// Serve private JSON-RPC for local applications, using the selected identity.
    Serve {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}

impl ControlArgs {
    pub async fn run(self, service: Service) -> Result<()> {
        let ControlCommand::Serve { socket } = self.command;
        let socket = socket
            .map(Ok)
            .unwrap_or_else(|| crate::internal_rpc::default_socket(&service.owner()))?;
        eprintln!(
            "management owner: {}\nmanagement socket: {}",
            service.owner(),
            socket.display()
        );
        crate::internal_rpc::serve(service, &socket).await
    }
}
