use super::*;
use catena_models::weights::Weights;
use std::collections::BTreeMap;

pub(super) struct Tensor {
    pub name: String,
    pub shape: Vec<usize>,
    pub f32: bool,
}
impl Tensor {
    pub fn bytes(&self) -> u64 {
        self.shape.iter().product::<usize>() as u64 * if self.f32 { 4 } else { 2 }
    }
}

// Storage matches Flux's TextEncoder, Transformer and VaeDecoder: text norms
// and the VAE are F32, everything else BF16.
pub(super) fn text(config: &catena_models::spec::ModelConfig) -> Vec<Tensor> {
    catena_models::flux::text::weight_shapes(config)
        .into_iter()
        .map(|(name, shape)| Tensor {
            f32: name.ends_with("norm.weight"),
            name,
            shape,
        })
        .collect()
}

/// The stage's checkpoint tensors in the argument order of its graph.
pub(super) fn ordered(
    names: &[String],
    shapes: Vec<(String, Vec<usize>)>,
    f32: bool,
) -> Result<Vec<Tensor>> {
    let mut shapes: BTreeMap<_, _> = shapes.into_iter().collect();
    let tensors = names
        .iter()
        .map(|name| {
            Ok(Tensor {
                name: name.clone(),
                shape: shapes
                    .remove(name)
                    .with_context(|| format!("unknown Flux weight {name}"))?,
                f32,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(shapes.is_empty(), "Flux graph omitted checkpoint weights");
    Ok(tensors)
}

pub(super) fn write(
    file: &mut impl std::io::Write,
    checkpoint: &Weights,
    tensor: &Tensor,
) -> Result<()> {
    checkpoint.validate(&tensor.name, &tensor.shape)?;
    let values = checkpoint.host_f32(&tensor.name)?;
    let bf16 = checkpoint.tensors[&tensor.name].dtype == safetensors::Dtype::BF16;
    for value in values {
        if tensor.f32 {
            file.write_all(&value.to_le_bytes())?;
        } else {
            let bits = if bf16 {
                (value.to_bits() >> 16) as u16
            } else {
                catena_models::weights::f32_to_bf16(value)
            };
            file.write_all(&bits.to_le_bytes())?;
        }
    }
    Ok(())
}
