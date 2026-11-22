//! Direct checkpoint bindings for OmniVoice's setup and synthesis programs.
use super::{Audio, WAVEFORM, floats_f32};
use crate::model::{GpuDialect, native::Native, package::ComputeJob};
use anyhow::{Result, anyhow, ensure};
use catena_models::{omnivoice, spec::ModelConfig, weights::preparation::Binding};
use hellas_rpc::protocol::invocation::{Artifact, compute::*, output::InvocationOutput};
use hellas_store::content::{LocalStore, Scope};
use tokenizers::Tokenizer;

pub(super) struct OmniVoice {
    tokenizer: Tokenizer,
    config: ModelConfig,
    setup: Call,
    weights: Vec<Arg>,
}

impl OmniVoice {
    pub(super) fn open(source: &Native, dialect: GpuDialect) -> Result<(Self, String)> {
        let config = omnivoice::config(source.dir())?;
        let tokenizer = Tokenizer::from_file(source.dir().join("tokenizer.json"))
            .map_err(|err| anyhow!("loading OmniVoice tokenizer: {err}"))?;
        let program = omnivoice::setup::program(&config, false, dialect, |file, name, shape| {
            let tensor = source.tensor(file, name)?;
            ensure!(tensor.shape == shape, "unexpected shape for {file}/{name}");
            Ok((tensor.arg.clone(), tensor.dtype))
        })?;
        let slot = |i| format!("weight-{i}");
        let setup = Call {
            entry: "omnivoice.setup".into(),
            args: program.inputs,
            bind: (0..program.outputs).map(|i| Bind::Name(slot(i))).collect(),
        };
        let weights = program
            .weights
            .into_iter()
            .map(|weight| match weight {
                Binding::Asset(arg) => arg,
                Binding::Prepared(i) => Arg::Slot { name: slot(i) },
            })
            .collect();
        Ok((
            Self {
                tokenizer,
                config,
                setup,
                weights,
            },
            program.source,
        ))
    }

    pub(super) fn render_job(
        &self,
        environment: &Environment,
        content: &(LocalStore, Scope),
        text: &str,
        voice: &str,
        speed: f32,
    ) -> Result<ComputeJob> {
        ensure!(voice == "default", "OmniVoice uses the default voice");
        ensure!(speed == 1., "OmniVoice supports speed 1 only");
        let (ids, frames) = omnivoice::prepare(&self.tokenizer, &self.config, text, None)?;
        let mut args = vec![
            Arg::Input {
                object: "text".into(),
            },
            Arg::U64(ids.len() as u64),
            Arg::U64(frames as u64),
            Arg::U64(0),
        ];
        args.extend(self.weights.iter().cloned());
        let call = Call {
            entry: "omnivoice.synthesize".into(),
            args,
            bind: vec![Bind::Name(WAVEFORM.into())],
        };
        Ok(ComputeJob {
            environment: environment.clone(),
            content: content.clone(),
            inputs: vec![Artifact::new(
                "text",
                "catena.u64le.v1",
                ids.into_iter().flat_map(u64::to_le_bytes).collect(),
            )],
            plan: Plan {
                calls: vec![self.setup.clone(), call],
                step: None,
                outputs: vec![Declared {
                    slot: WAVEFORM.into(),
                    kind: OutputKind::Buffer {
                        max_bytes: 4 * omnivoice::waveform_samples(frames) as u64,
                    },
                }],
            },
        })
    }
}

pub(super) fn decode(output: &InvocationOutput) -> Result<Audio> {
    let [wave] = output.artifacts.as_slice() else {
        anyhow::bail!("expected one OmniVoice waveform")
    };
    ensure!(
        wave.name == WAVEFORM && wave.format == "catena.bytes.v1",
        "invalid OmniVoice waveform"
    );
    let samples = floats_f32(wave.bytes.as_bytes())?;
    ensure!(
        (omnivoice::waveform_samples(1)..=omnivoice::waveform_samples(omnivoice::MAX_FRAMES))
            .contains(&samples.len())
            && (samples.len() - omnivoice::waveform_samples(0))
                .is_multiple_of(omnivoice::FRAME_SAMPLES)
            && samples.iter().all(|x| x.is_finite()),
        "invalid OmniVoice sample count or value"
    );
    Ok(Audio {
        samples,
        sample_rate: omnivoice::SAMPLE_RATE,
    })
}
