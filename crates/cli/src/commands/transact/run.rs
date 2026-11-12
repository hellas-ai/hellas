//! `hellas run`: one call of a Catena program, written as a job folder at the
//! price its target quotes and run like `hellas transact --job DIR`. Multi-step loops are
//! described in a hand-written job.toml.
use super::{ClientArgs, Context};
use anyhow::Context as _;
use clap::Args;
use hellas_rpc::protocol::invocation::{
    Artifact, MAX_INVOCATION_BYTES,
    compute::{self, Arg, Bind, Call, Declared, OutputKind, Plan, ValueKind},
};
use hellas_sdk::job::Job;
use hellas_store::content::{LocalStore, MemoryStore, Reservations, Scope};
use std::path::PathBuf;

const BYTES_FORMAT: &str = "catena.bytes.v1";

/// One call of a Catena program.
#[derive(Debug, Args)]
pub struct Program {
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
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[command(flatten)]
    pub(super) client: ClientArgs,
    #[command(flatten)]
    pub(super) program: Program,
    /// Pay the provider named by --provider its quoted price per job, at most MAX.
    #[arg(long, value_name = "MAX", requires = "provider", conflicts_with = "access", value_parser = clap::value_parser!(u64).range(1..))]
    pay: Option<u64>,
    #[command(flatten)]
    target: super::TargetArgs,
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

impl Program {
    pub(super) async fn job(&self, price: u64, evaluator: String) -> super::super::CliResult<Job> {
        let read = |path: &PathBuf, label, limit| {
            super::super::read_bounded_regular_file(path, label, limit)
        };
        let content = (
            LocalStore::Memory(MemoryStore::new(Reservations::ram(
                hellas_channel::content::DEFAULT_MAX_STAGING_BYTES,
            ))),
            Scope::Owner,
        );
        let mut sources = Vec::new();
        for path in &self.sources {
            sources.push(
                hellas_channel::content::upload_object(
                    &content.0,
                    &read(path, "source", compute::MAX_SOURCE_BYTES as usize)?,
                )
                .await?,
            );
        }
        let environment = compute::Environment {
            sources,
            assets: Vec::new(),
        };
        hellas_channel::content::upload_object(&content.0, &environment.canonical_bytes()?).await?;
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
        Ok(Job::compute(price, evaluator, environment, plan, inputs, content).await?)
    }
}

pub async fn run(args: RunArgs, context: Context) -> super::super::CliResult<()> {
    let evaluator = args.target.renderer()?;
    super::run_quoted(
        &args.client,
        args.target,
        &context,
        args.pay,
        args.save_job.clone(),
        async |price| args.program.job(price, evaluator).await,
        |_| args.output.clone(),
        |job, completed, provider| {
            super::present_job(job, completed, provider, args.output.as_deref())
        },
    )
    .await
}
