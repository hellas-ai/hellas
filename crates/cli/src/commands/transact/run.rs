//! `hellas run`: one call of a Catena program, written as a job folder and
//! transacted exactly as `hellas transact --job DIR`. Multi-step loops are
//! described in a hand-written job.toml.
use super::{ClientArgs, Context, TransactArgs};
use anyhow::Context as _;
use clap::Args;
use hellas_channel::content::{EphemeralContent, InvocationContent};
use hellas_rpc::protocol::invocation::{
    Artifact, MAX_INVOCATION_BYTES,
    compute::{self, Arg, Bind, Call, Declared, OutputKind, Plan, ValueKind},
};
use hellas_sdk::job::Job;
use std::path::PathBuf;

const BYTES_FORMAT: &str = "catena.bytes.v1";

#[derive(Debug, Args)]
pub struct RunArgs {
    #[command(flatten)]
    pub(super) client: ClientArgs,
    /// Catena source files, compiled in order.
    #[arg(long = "source", value_name = "FILE", num_args = 1.., required = true)]
    sources: Vec<PathBuf>,
    /// Function to call.
    #[arg(long)]
    entry: String,
    /// Call argument, in order: bool:B, u16:N, u32:N, u64:N, f32:X, input:NAME or zeroed:BYTES.
    #[arg(long = "arg", value_name = "KIND:VALUE", value_parser = parse_arg)]
    args: Vec<Arg>,
    /// Byte input named by its file name, passed as --arg input:NAME.
    #[arg(long = "input", value_name = "FILE")]
    inputs: Vec<PathBuf>,
    /// Kind of each returned value, in order: bool, u16, u32, u64, f32 or buffer:MAX_BYTES.
    #[arg(long = "returns", value_name = "KIND", value_parser = parse_returns)]
    returns: Vec<OutputKind>,
    /// Flat price the provider charges per job.
    #[arg(long)]
    payment: u64,
    /// Job folder to write (default: under the client state, by job digest).
    #[arg(long, value_name = "DIR")]
    save_job: Option<PathBuf>,
    /// Write the signed transcript and decoded outputs to this directory.
    #[arg(short = 'o', long = "output", value_name = "DIR")]
    output: Option<PathBuf>,
}

fn parse_arg(value: &str) -> Result<Arg, String> {
    let (kind, value) = value.split_once(':').ok_or("argument must be KIND:VALUE")?;
    let error = |e: &dyn std::fmt::Display| format!("invalid {kind} argument: {e}");
    Ok(match kind {
        "bool" => Arg::Bool(value.parse().map_err(|e| error(&e))?),
        "u16" => Arg::U16(value.parse().map_err(|e| error(&e))?),
        "u32" => Arg::U32(value.parse().map_err(|e| error(&e))?),
        "u64" => Arg::U64(value.parse().map_err(|e| error(&e))?),
        "f32" => Arg::F32Bits(value.parse::<f32>().map_err(|e| error(&e))?.to_bits()),
        "input" => Arg::Input {
            object: value.into(),
        },
        "zeroed" => Arg::Zeroed {
            bytes: value.parse().map_err(|e| error(&e))?,
        },
        _ => return Err(format!("unknown argument kind {kind}")),
    })
}

fn parse_returns(value: &str) -> Result<OutputKind, String> {
    Ok(OutputKind::Scalar(match value {
        "bool" => ValueKind::Bool,
        "u16" => ValueKind::U16,
        "u32" => ValueKind::U32,
        "u64" => ValueKind::U64,
        "f32" => ValueKind::F32,
        _ => {
            let max_bytes = value
                .strip_prefix("buffer:")
                .ok_or("returned kind must be bool, u16, u32, u64, f32 or buffer:MAX_BYTES")?
                .parse()
                .map_err(|e| format!("invalid buffer bound: {e}"))?;
            return Ok(OutputKind::Buffer { max_bytes });
        }
    }))
}

impl RunArgs {
    pub(super) fn job(&self) -> super::super::CliResult<Job> {
        let read = |path: &PathBuf, label, limit| {
            super::super::read_bounded_regular_file(path, label, limit)
        };
        let mut content = EphemeralContent::default();
        let sources = self
            .sources
            .iter()
            .map(|path| {
                Ok(content.insert(read(path, "source", compute::MAX_SOURCE_BYTES as usize)?))
            })
            .collect::<super::super::CliResult<_>>()?;
        let environment = compute::Environment {
            sources,
            assets: Vec::new(),
        };
        content.insert(environment.canonical_bytes()?);
        let inputs = self
            .inputs
            .iter()
            .map(|path| {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .with_context(|| format!("input {} needs a UTF-8 file name", path.display()))?;
                Ok(Artifact::new(
                    name,
                    BYTES_FORMAT,
                    read(path, "input", MAX_INVOCATION_BYTES)?,
                ))
            })
            .collect::<super::super::CliResult<_>>()?;
        let slot = |index: usize| format!("output-{index:04}");
        let plan = Plan {
            calls: vec![Call {
                entry: self.entry.clone(),
                args: self.args.clone(),
                bind: (0..self.returns.len())
                    .map(|i| Bind::Name(slot(i)))
                    .collect(),
            }],
            step: None,
            outputs: self
                .returns
                .iter()
                .enumerate()
                .map(|(i, kind)| Declared {
                    slot: slot(i),
                    kind: kind.clone(),
                })
                .collect(),
        };
        Ok(Job::compute(
            self.payment,
            environment,
            plan,
            inputs,
            InvocationContent::Ephemeral(content),
        )?)
    }
}

pub async fn run(args: RunArgs, context: Context) -> super::super::CliResult<()> {
    let job = args.job()?;
    let directory = args.save_job.clone().unwrap_or_else(|| {
        args.client
            .root(&context)
            .join("jobs")
            .join(job.digest().to_string())
    });
    job.save(&directory)?;
    eprintln!("job: {}", directory.display());
    super::run(
        TransactArgs {
            client: args.client,
            job: Some(directory),
            output: args.output,
        },
        context,
    )
    .await
}
