//! Flux2 Klein stages share one program and pass their outputs through slots.
use super::native::Native;
use anyhow::{Context, Result, ensure};
use catena_models::{
    flux::{
        config, graph,
        preparation::{Setup, Stage, ordered},
        text, transformer, vae,
    },
    weights::preparation::Binding,
};
use hellas_rpc::protocol::invocation::{Artifact, compute::*, output::InvocationOutput};
use rand_chacha::rand_core::SeedableRng;
use rand_distr::{Distribution, StandardNormal};
use serde::Deserialize;
use std::{fs::File, io::Read, path::Path, sync::Arc};

pub const MAX_DIMENSION: usize = 512;
pub const MAX_STEPS: usize = 50;
pub const OUTPUT: &str = "image";
pub(super) const TEXT_INDEX: &str = "text_encoder/model.safetensors.index.json";
pub(super) const TRANSFORMER: &str = "transformer/diffusion_pytorch_model.safetensors";
pub(super) const TRANSFORMER_INDEX: &str =
    "transformer/diffusion_pytorch_model.safetensors.index.json";
pub(super) const VAE: &str = "vae/diffusion_pytorch_model.safetensors";
pub(super) const METADATA: [&str; 6] = [
    "model_index.json",
    "scheduler/scheduler_config.json",
    "text_encoder/config.json",
    "transformer/config.json",
    "vae/config.json",
    "tokenizer/tokenizer.json",
];

const VARIANTS_FILE: &str = "variants.json";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(deny_unknown_fields)]
struct Variant {
    width: usize,
    height: usize,
    steps: usize,
}
impl Variant {
    fn validate(self) -> Result<()> {
        dimensions(self.width, self.height)?;
        ensure!(
            (1..=MAX_STEPS).contains(&self.steps),
            "image steps must be between 1 and {MAX_STEPS}"
        );
        Ok(())
    }

    fn read(directory: &Path) -> Result<Vec<Self>> {
        use hellas_rpc::protocol::invocation::policy::MAX_COMPUTE_PROGRAMS;
        let file = match File::open(directory.join(VARIANTS_FILE)) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(vec![Self {
                    width: 512,
                    height: 512,
                    steps: 4,
                }]);
            }
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        file.take(8193).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 8192,
            "image variants document exceeds 8192 bytes"
        );
        let variants: Vec<Self> = serde_json::from_slice(&bytes)?;
        ensure!(
            (1..=MAX_COMPUTE_PROGRAMS).contains(&variants.len()),
            "image package requires 1 to {MAX_COMPUTE_PROGRAMS} variants"
        );
        let mut unique = std::collections::BTreeSet::new();
        for &variant in &variants {
            variant.validate()?;
            ensure!(
                unique.insert(variant),
                "duplicate image variant {variant:?}"
            );
        }
        Ok(variants)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ImageRequest<'a> {
    pub prompt: &'a str,
    pub seed: u64,
    pub width: usize,
    pub height: usize,
    pub steps: usize,
}
impl ImageRequest<'_> {
    fn variant(&self) -> Variant {
        Variant {
            width: self.width,
            height: self.height,
            steps: self.steps,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.variant().validate()?;
        ensure!(
            !self.prompt.trim().is_empty() && self.prompt.len() <= 16 << 10,
            "image prompt must contain 1 to 16384 bytes"
        );
        Ok(())
    }
}
fn dimensions(width: usize, height: usize) -> Result<()> {
    ensure!(
        width > 0
            && height > 0
            && width <= MAX_DIMENSION
            && height <= MAX_DIMENSION
            && width.is_multiple_of(16)
            && height.is_multiple_of(16),
        "image dimensions must be multiples of 16, between 16 and {MAX_DIMENSION}"
    );
    Ok(())
}

type StageShapes = (Stage, &'static str, Vec<(String, Vec<usize>)>);

struct Config {
    text: catena_models::spec::ModelConfig,
    transformer: config::TransformerConfig,
    vae: config::VaeConfig,
}
impl Config {
    fn read(dir: &Path) -> Result<Self> {
        catena_models::flux::pipeline::FluxPipeline::new(dir.to_owned())?;
        let text: config::TextConfig = config::read(dir.join("text_encoder/config.json"))?;
        let transformer: config::TransformerConfig =
            config::read(dir.join("transformer/config.json"))?;
        let vae: config::VaeConfig = config::read(dir.join("vae/config.json"))?;
        Ok(Self {
            text: text.qwen()?,
            transformer,
            vae,
        })
    }
    fn tensors(&self) -> Result<[StageShapes; 3]> {
        let denoise = graph::transformer(&self.transformer, 16, 16, 1, false)?;
        let vae = graph::vae(&self.vae, 16, 16, false)?;
        Ok([
            (
                Stage::Text,
                "text_encoder/",
                text::weight_shapes(&self.text),
            ),
            (
                Stage::Denoise,
                "transformer/",
                ordered(
                    &denoise.weights,
                    transformer::weight_shapes(&self.transformer),
                )?,
            ),
            (
                Stage::Vae,
                "vae/",
                ordered(&vae.weights, vae::weight_shapes())?,
            ),
        ])
    }
    fn source(&self, variant: Variant, setup: &[Setup<Arg>]) -> Result<String> {
        let Variant {
            width,
            height,
            steps,
        } = variant;
        let text = text::generated_source(&self.text)?;
        let denoise = graph::transformer(&self.transformer, height, width, steps, false)?;
        let vae = graph::vae(&self.vae, height, width, false)?;
        bundle_stages(
            [text.as_str(), &denoise.source, &vae.source]
                .into_iter()
                .chain(setup.iter().map(|s| s.source.as_str())),
        )
    }
}

fn bundle_stages<'a>(stages: impl IntoIterator<Item = &'a str>) -> Result<String> {
    let mut raw = metacat::theory::RawTheorySet::from_texts(stages)?;
    let mut shared = std::collections::BTreeMap::new();
    // Upstream stages each carry their WMMA helpers. Keep one definition,
    // but refuse a stage that gives a shared name a different meaning.
    for extension in &mut raw.extensions {
        for (name, arrow) in std::mem::take(&mut extension.arrows) {
            let definition = (arrow.type_maps.clone(), arrow.definition.clone());
            if let Some(previous) =
                shared.insert((extension.theory.clone(), name.clone()), definition.clone())
            {
                ensure!(previous == definition, "conflicting Flux definition {name}");
            } else {
                extension.arrows.insert(name, arrow);
            }
        }
    }
    Ok(graph::bundle(&raw.to_hexpr_text()))
}

pub(super) struct Flux {
    source: Arc<Native>,
    config: Config,
    stages: Vec<Setup<Arg>>,
    variants: Vec<Variant>,
    dialect: super::GpuDialect,
}
impl Flux {
    pub fn open(source: Arc<Native>, dialect: super::GpuDialect) -> Result<Self> {
        let directory = source.dir();
        let config = Config::read(directory)?;
        let mut stages = Vec::new();
        for (stage, prefix, shapes) in config.tensors()? {
            stages.push(stage.setup(shapes, |name, shape| {
                let tensor = source.tensor_in(prefix, name)?;
                ensure!(
                    tensor.shape == shape,
                    "{prefix}{name}: expected {shape:?}, got {:?}",
                    tensor.shape
                );
                Ok((tensor.dtype, tensor.arg.clone()))
            })?);
        }
        text::tokenize(directory, "check tokenizer")?;
        let variants = Variant::read(directory)?;
        Ok(Self {
            source,
            config,
            stages,
            variants,
            dialect,
        })
    }
    fn program(&self, variant: Variant) -> Result<String> {
        let source =
            super::program::render(&self.config.source(variant, &self.stages)?, self.dialect)?;
        ensure!(
            source.len() as u64 <= MAX_SOURCE_BYTES,
            "image program exceeds source limit"
        );
        Ok(source)
    }
    pub fn assets(&self) -> Vec<NamedAsset> {
        self.source.assets()
    }

    pub fn programs(&self, evaluator: &str) -> Result<Vec<hellas_rpc::ProgramManifest>> {
        self.variants
            .iter()
            .map(|&variant| {
                Ok(
                    super::program::describe(&self.program(variant)?, self.assets())
                        .manifest(evaluator)?,
                )
            })
            .collect()
    }

    /// The plan and inputs of one request, and the program they run.
    pub fn render_job(&self, request: &ImageRequest<'_>) -> Result<(Plan, Vec<Artifact>, String)> {
        request.validate()?;
        let variant = request.variant();
        ensure!(
            self.variants.contains(&variant),
            "image variant {}x{} with {} steps is not configured",
            variant.width,
            variant.height,
            variant.steps
        );
        let tokens = text::tokenize(self.source.dir(), request.prompt)?;
        ensure!(tokens.valid > 0, "empty tokenized prompt");
        ensure!(
            tokens
                .ids
                .iter()
                .all(|id| *id < self.config.text.vocabulary_size as u64),
            "image token exceeds vocabulary"
        );
        let source = self.program(variant)?;
        let input = |object: &str| Arg::Input {
            object: object.into(),
        };
        let slot = |name: &str| Arg::Slot { name: name.into() };
        let mut calls = Vec::new();
        let stages = [
            (
                "flux.encode-text",
                vec![input("tokens"), Arg::U64(tokens.valid as u64)],
                "conditioning",
            ),
            (
                "flux.denoise",
                vec![input("noise"), slot("conditioning")],
                "latents",
            ),
            ("flux.decode-image", vec![slot("latents")], OUTPUT),
        ];
        for ((entry, mut args, output), setup) in stages.into_iter().zip(&self.stages) {
            let prepared = |i: usize| format!("{}-{i}", setup.entry);
            if !setup.inputs.is_empty() {
                calls.push(Call {
                    entry: setup.entry.into(),
                    args: setup.inputs.clone(),
                    bind: (0..setup.inputs.len())
                        .map(|i| Bind::Name(prepared(i)))
                        .collect(),
                });
            }
            args.extend(setup.bindings.iter().map(|binding| match binding {
                Binding::Asset(view) => view.clone(),
                Binding::Prepared(i) => slot(&prepared(*i)),
            }));
            calls.push(Call {
                entry: entry.into(),
                args,
                bind: vec![Bind::Name(output.into())],
            });
        }
        let plan = Plan {
            calls,
            step: None,
            outputs: vec![Declared {
                slot: OUTPUT.into(),
                kind: OutputKind::Buffer {
                    max_bytes: (request.width * request.height * 3 * 4) as u64,
                },
            }],
        };
        let noise = noise(request.seed, request.width, request.height)?;
        let inputs = vec![
            Artifact::new(
                "noise",
                "catena.f32le.v1",
                noise.into_iter().flat_map(f32::to_le_bytes).collect(),
            ),
            Artifact::new(
                "tokens",
                "catena.u64le.v1",
                tokens.ids.into_iter().flat_map(u64::to_le_bytes).collect(),
            ),
        ];
        Ok((plan, inputs, source))
    }
}

/// Seeded noise matches catena-models; the reference digest guards RNG upgrades.
pub fn noise(seed: u64, width: usize, height: usize) -> Result<Vec<f32>> {
    dimensions(width, height)?;
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
    Ok((0..(width / 16 * (height / 16) * 128))
        .map(|_| StandardNormal.sample(&mut rng))
        .collect())
}

#[derive(Debug)]
pub struct Image {
    rgb: Vec<f32>,
}
impl Image {
    pub(super) fn decode(output: &InvocationOutput) -> Result<Self> {
        let image = output
            .artifacts
            .iter()
            .find(|a| a.name == OUTPUT)
            .context("missing image output")?;
        let bytes = image.bytes.as_bytes();
        ensure!(
            image.format == "catena.bytes.v1"
                && !bytes.is_empty()
                && bytes.len().is_multiple_of(12)
                && bytes.len() <= MAX_DIMENSION * MAX_DIMENSION * 12,
            "invalid RGB image artifact"
        );
        let rgb: Vec<_> = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .copied()
            .map(f32::from_le_bytes)
            .collect();
        ensure!(
            rgb.iter().all(|v| v.is_finite()),
            "image contains non-finite pixels"
        );
        Ok(Self { rgb })
    }
    pub fn png(&self, width: usize, height: usize) -> Result<Vec<u8>> {
        dimensions(width, height)?;
        ensure!(
            self.rgb.len() == width * height * 3,
            "image output has wrong dimensions"
        );
        let bytes: Vec<_> = self
            .rgb
            .iter()
            .map(|v| (v * 255.).round_ties_even() as u8)
            .collect();
        let mut output = Vec::new();
        let mut png = png::Encoder::new(&mut output, width.try_into()?, height.try_into()?);
        png.set_color(png::ColorType::Rgb);
        png.set_depth(png::BitDepth::Eight);
        png.write_header()?.write_image_data(&bytes)?;
        Ok(output)
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn fixture(directory: &Path, dialect: super::GpuDialect) -> Result<super::ModelPackage> {
    use super::native::Tensor;
    use hellas_rpc::ContentRef;
    use std::collections::BTreeMap;

    let mut files = BTreeMap::new();
    for (_, prefix, shapes) in Config::read(directory)?.tensors()? {
        let file = format!("{prefix}model.safetensors");
        let mut tensors = BTreeMap::new();
        let mut offset = 512;
        for (name, shape) in shapes {
            let bytes = shape.iter().product::<usize>() as u64 * 2;
            let arg = Arg::Asset {
                name: file.clone(),
                offset,
                bytes,
            };
            offset += bytes;
            tensors.insert(
                name,
                Tensor {
                    arg,
                    shape,
                    dtype: safetensors::Dtype::BF16,
                },
            );
        }
        let object = ContentRef::new(ContentRef::for_bytes(file.as_bytes()).id(), offset);
        files.insert(file, (object, tensors));
    }
    let native = Arc::new(Native::fixture(directory, files));
    Ok(super::ModelPackage::flux_fixture(
        Flux::open(native, dialect)?,
        dialect,
    ))
}
#[cfg(test)]
mod tests;
