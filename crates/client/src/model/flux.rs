//! Flux2 Klein stages share one program and pass their outputs through slots.
use super::package::ComputeJob;
use anyhow::{Context, Result, ensure};
use catena_models::flux::{config, graph, text};
use hellas_channel::content::EphemeralContent;
use hellas_rpc::{
    ContentId, ContentRef,
    protocol::invocation::{Artifact, compute::*, output::InvocationOutput},
};
use rand_chacha::rand_core::SeedableRng;
use rand_distr::{Distribution, StandardNormal};
use std::{
    fs::File,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

mod weights;

pub const MAX_DIMENSION: usize = 512;
pub const MAX_STEPS: usize = 50;
pub const OUTPUT: &str = "image";
const ASSETS: [&str; 3] = ["text", "denoise", "vae"];
const METADATA: [&str; 6] = [
    "model_index.json",
    "scheduler/scheduler_config.json",
    "text_encoder/config.json",
    "transformer/config.json",
    "vae/config.json",
    "tokenizer/tokenizer.json",
];

#[derive(Clone, Copy, Debug)]
pub struct ImageRequest<'a> {
    pub prompt: &'a str,
    pub seed: u64,
    pub width: usize,
    pub height: usize,
    pub steps: usize,
}
impl ImageRequest<'_> {
    pub fn validate(&self) -> Result<()> {
        dimensions(self.width, self.height)?;
        ensure!(
            (1..=MAX_STEPS).contains(&self.steps),
            "image steps must be between 1 and {MAX_STEPS}"
        );
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
        transformer.validate()?;
        vae.validate()?;
        Ok(Self {
            text: text.qwen()?,
            transformer,
            vae,
        })
    }
    fn tensors(&self) -> Result<[Vec<weights::Tensor>; 3]> {
        // Weight arguments do not depend on image dimensions or step count.
        let denoise = graph::transformer(&self.transformer, 16, 16, 1, false)?;
        let vae = graph::vae(&self.vae, 16, 16, false)?;
        Ok([
            weights::text(&self.text),
            weights::transformer(&denoise.weights)?,
            weights::vae(&vae.weights)?,
        ])
    }
    fn source(&self, width: usize, height: usize, steps: usize) -> Result<String> {
        let text = text::generated_source(&self.text)?;
        let denoise = graph::transformer(&self.transformer, height, width, steps, false)?;
        let vae = graph::vae(&self.vae, height, width, false)?;
        // The shared helpers must be added only once across the three stages.
        Ok(graph::bundle(&format!(
            "{text}\n{}\n{}",
            denoise.source, vae.source
        )))
    }
}

/// Convert a local distilled Klein 4B snapshot into immutable provider assets
/// and client metadata. Providers index the three `.bin` files; callers need
/// only the metadata and tokenizer after conversion.
pub fn convert_flux(checkpoint: &Path, destination: &Path) -> Result<Vec<NamedAsset>> {
    ensure!(!destination.exists(), "destination already exists");
    let config = Config::read(checkpoint)?;
    let tensors = config.tensors()?;
    text::tokenize(checkpoint, "check tokenizer")?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let staging = tempfile::Builder::new()
        .prefix(".flux-")
        .tempdir_in(parent)?;
    let mut assets = Vec::new();
    for ((name, tensors), source) in ASSETS.into_iter().zip(tensors).zip([
        "text_encoder/model.safetensors.index.json",
        "transformer/diffusion_pytorch_model.safetensors",
        "vae/diffusion_pytorch_model.safetensors",
    ]) {
        let checkpoint = catena_models::weights::Weights::open(&checkpoint.join(source))?;
        let path = staging.path().join(format!("{name}.bin"));
        let mut file = BufWriter::new(File::create(&path)?);
        for tensor in tensors {
            weights::write(&mut file, &checkpoint, &tensor)?;
        }
        file.flush()?;
        file.get_ref().sync_all()?;
        drop(file);
        let indexed = hellas_store::ContentStore::new().index(&path)?;
        assets.push(NamedAsset {
            name: name.into(),
            object: ContentRef::new(ContentId::from_bytes(*indexed.id.as_bytes()), indexed.len),
        });
    }
    for name in METADATA {
        let path = staging.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::copy(checkpoint.join(name), path)?;
    }
    std::fs::write(
        staging.path().join("assets.json"),
        serde_json::to_vec_pretty(&assets)?,
    )?;
    std::fs::rename(staging.path(), destination)?;
    Ok(assets)
}

pub(super) struct Flux {
    directory: PathBuf,
    config: Config,
    assets: Vec<NamedAsset>,
    args: [Vec<Arg>; 3],
}
impl Flux {
    pub fn open(directory: &Path) -> Result<Self> {
        let config = Config::read(directory)?;
        let tensors = config.tensors()?;
        let assets: Vec<NamedAsset> =
            serde_json::from_reader(File::open(directory.join("assets.json"))?)?;
        ensure!(
            assets.len() == ASSETS.len(),
            "Flux requires three weight assets"
        );
        let mut args = [Vec::new(), Vec::new(), Vec::new()];
        for (i, tensors) in tensors.into_iter().enumerate() {
            ensure!(assets[i].name == ASSETS[i], "incorrect Flux asset order");
            let mut offset = 0;
            for tensor in tensors {
                let bytes = tensor.bytes();
                args[i].push(Arg::Asset {
                    name: ASSETS[i].into(),
                    offset,
                    bytes,
                });
                offset += bytes;
            }
            ensure!(
                assets[i].object.bytes() == offset,
                "Flux weight asset has wrong length"
            );
        }
        text::tokenize(directory, "check tokenizer")?;
        Ok(Self {
            directory: directory.to_owned(),
            config,
            assets,
            args,
        })
    }
    pub fn render_job(&self, request: &ImageRequest<'_>) -> Result<ComputeJob> {
        request.validate()?;
        let tokens = text::tokenize(&self.directory, request.prompt)?;
        ensure!(tokens.valid > 0, "empty tokenized prompt");
        ensure!(
            tokens
                .ids
                .iter()
                .all(|id| *id < self.config.text.vocabulary_size as u64),
            "image token exceeds vocabulary"
        );
        let mut content = EphemeralContent::default();
        let source = super::program::render(&self.config.source(
            request.width,
            request.height,
            request.steps,
        )?)?;
        ensure!(
            source.len() as u64 <= MAX_SOURCE_BYTES,
            "image program exceeds source limit"
        );
        let environment = Environment {
            sources: vec![content.insert(source.into_bytes())],
            assets: self.assets.clone(),
        };
        content.insert(environment.canonical_bytes()?);
        let input = |object: &str| Arg::Input {
            object: object.into(),
        };
        let slot = |name: &str| Arg::Slot { name: name.into() };
        let call = |entry: &str, mut args: Vec<Arg>, weights: usize, output: &str| {
            args.extend(self.args[weights].iter().cloned());
            Call {
                entry: entry.into(),
                args,
                bind: vec![Bind::Name(output.into())],
            }
        };
        let plan = Plan {
            calls: vec![
                call(
                    "flux.encode-text",
                    vec![input("tokens"), Arg::U64(tokens.valid as u64)],
                    0,
                    "conditioning",
                ),
                call(
                    "flux.denoise",
                    vec![input("noise"), slot("conditioning")],
                    1,
                    "latents",
                ),
                call("flux.decode-image", vec![slot("latents")], 2, OUTPUT),
            ],
            step: None,
            outputs: vec![Declared {
                slot: OUTPUT.into(),
                kind: OutputKind::Buffer {
                    max_bytes: (request.width * request.height * 3 * 4) as u64,
                },
            }],
        };
        let noise = noise(request.seed, request.width, request.height)?;
        Ok(ComputeJob {
            environment,
            plan,
            content,
            inputs: vec![
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
            ],
        })
    }
}

/// The generator and distribution versions match catena-models' seeded noise.
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

#[cfg(test)]
mod tests;
