//! Standard Prost/Serde configuration for EdgeIndex's protobuf messages.
use prost_types::{FileDescriptorSet, field_descriptor_proto::Type};
use std::path::Path;

pub fn configure(config: &mut prost_build::Config, fds: &FileDescriptorSet, out: &Path) {
    let file = fds
        .file
        .iter()
        .find(|f| f.name() == "hellas/chain/v1/edge_index.proto")
        .expect("EdgeIndex schema");
    let mut aliases = String::new();
    for message in &file.message_type {
        let name = message.name();
        let path = format!(".hellas.chain.v1.{name}");
        let short = name.strip_prefix("EdgeIndex").expect("EdgeIndex prefix");
        aliases.push_str(&format!("pub use crate::pb::chain::{name} as {short};\n"));
        config.message_attribute(
            &path,
            "#[derive(::serde::Serialize, ::serde::Deserialize)] #[serde(deny_unknown_fields)]",
        );
        // Existing schema-1 proof routes retain numeric integers and byte arrays,
        // including when the same proof is embedded in an EdgeIndex response.
        if short == "ProofBundle" {
            continue;
        }
        for field in &message.field {
            if field.proto3_optional.unwrap_or(false) {
                config.field_attribute(
                    format!("{path}.{}", field.name()),
                    "#[serde(default, skip_serializing_if = \"Option::is_none\")]",
                );
            }
            let adapter = match field.r#type() {
                Type::Uint64 => Some("decimal_u64"),
                Type::Bytes if field.proto3_optional.unwrap_or(false) => {
                    Some("optional_base64_bytes")
                }
                Type::Bytes => Some("base64_bytes"),
                _ => None,
            };
            if let Some(adapter) = adapter {
                config.field_attribute(
                    format!("{path}.{}", field.name()),
                    format!("#[serde(with = \"crate::edge_index::{adapter}\")]"),
                );
            }
        }
        for oneof in &message.oneof_decl {
            if oneof.name().starts_with('_') {
                continue;
            }
            config.enum_attribute(format!("{path}.{}", oneof.name()), "#[derive(::serde::Serialize, ::serde::Deserialize)] #[serde(rename_all = \"kebab-case\")]");
        }
    }
    std::fs::write(out.join("hellas_edge_index_aliases.rs"), aliases)
        .expect("write EdgeIndex aliases");
}
