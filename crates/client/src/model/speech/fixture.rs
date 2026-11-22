use super::*;
use std::{collections::BTreeMap, fs, io::Write};

/// Write an original MMS safetensors fixture with a sparse, zero-filled payload.
pub fn write_test_checkpoint(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    for (name, bytes) in [
        (
            "config.json",
            include_bytes!("fixture/config.json").as_slice(),
        ),
        (
            "tokenizer_config.json",
            include_bytes!("fixture/tokenizer_config.json").as_slice(),
        ),
        (
            "special_tokens_map.json",
            include_bytes!("fixture/special_tokens_map.json").as_slice(),
        ),
        (
            "vocab.json",
            include_bytes!("fixture/vocab.json").as_slice(),
        ),
    ] {
        fs::write(dir.join(name), bytes)?;
    }
    let mut tensors = BTreeMap::new();
    // A training-only tensor demonstrates that setup names only the inference subset.
    tensors.insert("discriminator.unused".to_owned(), vec![1]);
    for (name, binding) in tts::bindings() {
        if binding.normalized {
            let prefix = name.strip_suffix(".weight").unwrap();
            tensors.insert(format!("{prefix}.weight_g"), vec![binding.shape[0], 1, 1]);
            tensors.insert(format!("{prefix}.weight_v"), binding.shape);
        } else {
            tensors.insert(name, binding.shape);
        }
    }
    let mut offset = 0;
    let mut header = BTreeMap::new();
    for (name, shape) in tensors {
        let start = offset;
        offset += 4 * shape.iter().product::<usize>();
        header.insert(
            name,
            serde_json::json!({"dtype":"F32", "shape":shape, "data_offsets":[start,offset]}),
        );
    }
    let mut bytes = serde_json::to_vec(&header)?;
    bytes.resize(bytes.len().next_multiple_of(8), b' ');
    let mut file = fs::File::create(dir.join("model.safetensors"))?;
    file.write_all(&(bytes.len() as u64).to_le_bytes())?;
    file.write_all(&bytes)?;
    file.set_len((8 + bytes.len() + offset) as u64)?;
    Ok(())
}
