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

// Argument order and storage match Flux's TextEncoder, Transformer and VaeDecoder.
pub(super) fn text(config: &catena_models::spec::ModelConfig) -> Vec<Tensor> {
    let h = config.hidden_size;
    let q = config.num_attention_heads * config.head_dim;
    let kv = config.num_key_value_heads * config.head_dim;
    let ff = config.intermediate_size;
    let mut result = vec![Tensor {
        name: "model.embed_tokens.weight".into(),
        shape: vec![config.vocabulary_size, h],
        f32: false,
    }];
    for layer in 0..27 {
        for (suffix, shape) in [
            ("input_layernorm.weight", vec![h]),
            ("self_attn.q_proj.weight", vec![q, h]),
            ("self_attn.k_proj.weight", vec![kv, h]),
            ("self_attn.v_proj.weight", vec![kv, h]),
            ("self_attn.o_proj.weight", vec![h, q]),
            ("self_attn.q_norm.weight", vec![config.head_dim]),
            ("self_attn.k_norm.weight", vec![config.head_dim]),
            ("post_attention_layernorm.weight", vec![h]),
            ("mlp.gate_proj.weight", vec![ff, h]),
            ("mlp.up_proj.weight", vec![ff, h]),
            ("mlp.down_proj.weight", vec![h, ff]),
        ] {
            result.push(Tensor {
                name: format!("model.layers.{layer}.{suffix}"),
                shape,
                f32: suffix.ends_with("norm.weight"),
            });
        }
    }
    result
}

pub(super) fn transformer(names: &[String]) -> Result<Vec<Tensor>> {
    let mut shapes = BTreeMap::<String, Vec<usize>>::new();
    for (name, shape) in [
        ("x_embedder.weight", vec![3072, 128]),
        ("context_embedder.weight", vec![3072, 7680]),
        (
            "time_guidance_embed.timestep_embedder.linear_1.weight",
            vec![3072, 256],
        ),
        (
            "time_guidance_embed.timestep_embedder.linear_2.weight",
            vec![3072, 3072],
        ),
        (
            "double_stream_modulation_img.linear.weight",
            vec![18432, 3072],
        ),
        (
            "double_stream_modulation_txt.linear.weight",
            vec![18432, 3072],
        ),
        ("single_stream_modulation.linear.weight", vec![9216, 3072]),
        ("norm_out.linear.weight", vec![6144, 3072]),
        ("proj_out.weight", vec![128, 3072]),
    ] {
        shapes.insert(name.into(), shape);
    }
    for layer in 0..5 {
        for suffix in [
            "attn.to_q.weight",
            "attn.to_k.weight",
            "attn.to_v.weight",
            "attn.to_out.0.weight",
            "attn.norm_q.weight",
            "attn.norm_k.weight",
            "attn.add_q_proj.weight",
            "attn.add_k_proj.weight",
            "attn.add_v_proj.weight",
            "attn.to_add_out.weight",
            "attn.norm_added_q.weight",
            "attn.norm_added_k.weight",
            "ff.linear_in.weight",
            "ff.linear_out.weight",
            "ff_context.linear_in.weight",
            "ff_context.linear_out.weight",
        ] {
            let shape = if suffix.contains("norm_") {
                vec![128]
            } else if suffix.ends_with("linear_in.weight") {
                vec![18432, 3072]
            } else if suffix.ends_with("linear_out.weight") {
                vec![3072, 9216]
            } else {
                vec![3072, 3072]
            };
            shapes.insert(format!("transformer_blocks.{layer}.{suffix}"), shape);
        }
    }
    for layer in 0..20 {
        for (suffix, shape) in [
            ("attn.to_qkv_mlp_proj.weight", vec![27648, 3072]),
            ("attn.to_out.weight", vec![3072, 12288]),
            ("attn.norm_q.weight", vec![128]),
            ("attn.norm_k.weight", vec![128]),
        ] {
            shapes.insert(format!("single_transformer_blocks.{layer}.{suffix}"), shape);
        }
    }
    ordered(names, shapes, false)
}

pub(super) fn vae(names: &[String]) -> Result<Vec<Tensor>> {
    let mut shapes = BTreeMap::new();
    for name in ["bn.running_mean", "bn.running_var"] {
        shapes.insert(name.into(), vec![128]);
    }
    for (name, ci, co, kernel) in [
        ("post_quant_conv", 32, 32, 1),
        ("decoder.conv_in", 32, 512, 3),
        ("decoder.conv_out", 128, 3, 3),
    ] {
        conv(&mut shapes, name, ci, co, kernel);
    }
    for layer in 0..2 {
        res(
            &mut shapes,
            &format!("decoder.mid_block.resnets.{layer}"),
            512,
            512,
        );
    }
    let mut ci = 512;
    for (block, co) in [512, 512, 256, 128].into_iter().enumerate() {
        for layer in 0..3 {
            res(
                &mut shapes,
                &format!("decoder.up_blocks.{block}.resnets.{layer}"),
                ci,
                co,
            );
            ci = co;
        }
        if block < 3 {
            conv(
                &mut shapes,
                &format!("decoder.up_blocks.{block}.upsamplers.0.conv"),
                co,
                co,
                3,
            );
        }
    }
    for suffix in ["weight", "bias"] {
        shapes.insert(format!("decoder.conv_norm_out.{suffix}"), vec![128]);
        shapes.insert(
            format!("decoder.mid_block.attentions.0.group_norm.{suffix}"),
            vec![512],
        );
    }
    for suffix in ["to_q", "to_k", "to_v", "to_out.0"] {
        shapes.insert(
            format!("decoder.mid_block.attentions.0.{suffix}.weight"),
            vec![512, 512],
        );
        shapes.insert(
            format!("decoder.mid_block.attentions.0.{suffix}.bias"),
            vec![512],
        );
    }
    ordered(names, shapes, true)
}
fn conv(
    shapes: &mut BTreeMap<String, Vec<usize>>,
    name: &str,
    ci: usize,
    co: usize,
    kernel: usize,
) {
    shapes.insert(format!("{name}.weight"), vec![co, ci, kernel, kernel]);
    shapes.insert(format!("{name}.bias"), vec![co]);
}
fn res(shapes: &mut BTreeMap<String, Vec<usize>>, name: &str, ci: usize, co: usize) {
    for (norm, channels) in [("norm1", ci), ("norm2", co)] {
        for suffix in ["weight", "bias"] {
            shapes.insert(format!("{name}.{norm}.{suffix}"), vec![channels]);
        }
    }
    conv(shapes, &format!("{name}.conv1"), ci, co, 3);
    conv(shapes, &format!("{name}.conv2"), co, co, 3);
    if ci != co {
        conv(shapes, &format!("{name}.conv_shortcut"), ci, co, 1);
    }
}
fn ordered(
    names: &[String],
    mut shapes: BTreeMap<String, Vec<usize>>,
    f32: bool,
) -> Result<Vec<Tensor>> {
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
