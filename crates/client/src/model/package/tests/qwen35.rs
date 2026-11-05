use super::*;
use catena_models::spec::{ModelConfig, WeightDtype, weight_specs};

// Include a recurrent layer and a full-attention layer, with zero weights.
fn fixture() -> tempfile::NamedTempFile {
    let mut config = ModelConfig::qwen35_0_8b();
    config.vocabulary_size = 4;
    config.hidden_size = 32;
    config.intermediate_size = 64;
    config.num_layers = 2;
    config.num_attention_heads = 1;
    config.num_key_value_heads = 1;
    config.head_dim = 128;
    config.max_position_embeddings = 128;
    config.full_attention_interval = Some(2);
    config.linear_group_count = Some(1);
    config.linear_time_step_rank = Some(1);
    config.linear_inner_size = Some(128);
    config.eos_token_id = Some(3);
    config.validate().unwrap();
    fn string(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u64).to_le_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    let mut metadata = Vec::new();
    string(&mut metadata, "general.architecture");
    metadata.extend_from_slice(&8u32.to_le_bytes());
    string(&mut metadata, "qwen35");
    let fields = [
        ("vocab_size", config.vocabulary_size),
        ("embedding_length", config.hidden_size),
        ("feed_forward_length", config.intermediate_size),
        ("block_count", config.num_layers),
        ("attention.head_count", config.num_attention_heads),
        ("attention.head_count_kv", config.num_key_value_heads),
        ("attention.key_length", config.head_dim),
        ("context_length", config.max_position_embeddings),
        ("rope.dimension_count", config.rope_dimension_count),
        ("full_attention_interval", 2),
        ("ssm.conv_kernel", 4),
        ("ssm.state_size", 128),
        ("ssm.group_count", 1),
        ("ssm.time_step_rank", 1),
        ("ssm.inner_size", 128),
    ];
    for (key, value) in fields {
        string(&mut metadata, &format!("qwen35.{key}"));
        metadata.extend_from_slice(&4u32.to_le_bytes());
        metadata.extend_from_slice(&(value as u32).to_le_bytes());
    }
    for (key, value) in [
        ("attention.layer_norm_rms_epsilon", config.rms_norm_eps),
        ("rope.freq_base", config.rope_theta),
    ] {
        string(&mut metadata, &format!("qwen35.{key}"));
        metadata.extend_from_slice(&6u32.to_le_bytes());
        metadata.extend_from_slice(&value.to_le_bytes());
    }
    string(&mut metadata, "tokenizer.ggml.eos_token_id");
    metadata.extend_from_slice(&4u32.to_le_bytes());
    metadata.extend_from_slice(&3u32.to_le_bytes());
    let mut tensors = std::collections::BTreeMap::new();
    for spec in weight_specs(&config).unwrap() {
        tensors.insert(spec.gguf_name.clone(), spec);
    }
    let mut bytes = b"GGUF".to_vec();
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&(tensors.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&((fields.len() + 4) as u64).to_le_bytes());
    bytes.extend(metadata);
    let mut payload = 0usize;
    for (name, spec) in tensors {
        string(&mut bytes, &name);
        bytes.extend_from_slice(&(spec.shape.len() as u32).to_le_bytes());
        for n in spec.shape.iter().rev() {
            bytes.extend_from_slice(&(*n as u64).to_le_bytes());
        }
        let (dtype, size) = match spec.dtype {
            WeightDtype::F32 => (0u32, 4),
            WeightDtype::Bf16 => (30u32, 2),
        };
        bytes.extend_from_slice(&dtype.to_le_bytes());
        payload = payload.next_multiple_of(32);
        bytes.extend_from_slice(&(payload as u64).to_le_bytes());
        payload += spec.shape.iter().product::<usize>() * size;
    }
    bytes.resize(bytes.len().next_multiple_of(32) + payload, 0);
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), bytes).unwrap();
    file
}

#[test]
fn dense_recurrent_model_renders_a_two_state_job() {
    let file = fixture();
    let job = ModelPackage::open(file.path())
        .unwrap()
        .text_job(&[2, 1], 2, &[])
        .unwrap();
    assert_eq!(
        job.plan.calls[0].bind,
        vec![Bind::Name("s0".into()), Bind::Name("s1".into())]
    );
    let step = job.plan.step.unwrap();
    assert_eq!(
        step.bind,
        vec![
            Bind::Name("s0".into()),
            Bind::Name("s1".into()),
            Bind::Discard,
            Bind::Name("next".into())
        ]
    );
    assert_eq!(step.stop.any_of, vec![3]);
    let config = catena_models::checkpoint::read_gguf_model_config(file.path()).unwrap();
    assert_eq!(step.args.len(), 5 + weight_specs(&config).unwrap().len());
}

#[test]
#[ignore = "compiles CUDA and HIP model programs; run check-model-programs"]
fn shipped_qwen35_program_matches_catena_models() {
    let file = fixture();
    let job = ModelPackage::open(file.path())
        .unwrap()
        .text_job(&[2, 1], 2, &[])
        .unwrap();
    let config = catena_models::checkpoint::read_gguf_model_config(file.path()).unwrap();
    let model = catena_models::catena::generated_model_source_for(&config).unwrap();
    crate::model::program::assert_shipped_module(&job, &model);
}
