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
